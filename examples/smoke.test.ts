import { afterAll, expect, test as bunTest } from "bun:test";
import * as Credentials from "@distilled.cloud/cloudflare/Credentials";
import { Retry } from "@distilled.cloud/cloudflare";
import * as GitHub from "alchemy/GitHub";
import * as Provider from "alchemy/Provider";
import * as Test from "alchemy/Test/Bun";
import { SopsFileProvider } from "effect-sops";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

import { fixtureAgeKey } from "./_shared/fixture.ts";
import { program as cloudflareSecrets } from "./cloudflare-secrets-store/app.ts";
import { readAppConfig } from "./config-provider/app.ts";
import { program as githubSecrets } from "./github-actions-secrets/app.ts";
import { program as jsonImport } from "./json-import/app.ts";
import { readSecrets } from "./schema-decoder/app.ts";
import { program as sopsFile } from "./sops-file/app.ts";

const { test: sopsTest } = Test.make({ providers: SopsFileProvider() });

sopsTest.provider("SopsFile stack deploys a real encrypted document", (stack) =>
  Effect.gen(function* () {
    const deployed = yield* stack.deploy(sopsFile(fixtureAgeKey));
    yield* stack.destroy();

    expect(deployed.topLevelKeys).toEqual(["api", "nested"]);
    expect(Redacted.value(deployed.apiToken)).toBe("native-token");
  }),
);

sopsTest.provider("JSON import keeps the decrypted document typed", (stack) =>
  Effect.gen(function* () {
    const deployed = yield* stack.deploy(jsonImport(fixtureAgeKey));
    yield* stack.destroy();

    expect(Redacted.value(deployed.apiToken)).toBe("native-token");
    expect(Redacted.value(deployed.enabled)).toBe("true");
  }),
);

bunTest("Schema decoder runs without Alchemy", async () => {
  const secrets = await Effect.runPromise(readSecrets(fixtureAgeKey));

  expect(Redacted.value(secrets.api.token)).toBe("native-token");
  expect(secrets.api.enabled).toBe(true);
  expect(secrets.nested.count).toBe(3);
});

bunTest("ConfigProvider resolves a SOPS-backed application config", async () => {
  const config = await Effect.runPromise(readAppConfig(fixtureAgeKey));

  expect(Redacted.value(config.apiToken)).toBe("native-token");
  expect(config.retryCount).toBe(3);
});

const github = createMockGitHub();
const gitHubProviders = Layer.effect(
  GitHub.Providers,
  Provider.collection([GitHub.Secret as any]),
).pipe(
  Layer.provide(GitHub.SecretProvider()),
  Layer.provideMerge(
    GitHub.fromToken("test-token", { baseUrl: github.baseUrl }),
  ),
);
const { test: githubTest } = Test.make({
  providers: Layer.mergeAll(SopsFileProvider(), gitHubProviders) as Layer.Layer<
    any,
    never,
    any
  >,
});

afterAll(() => github.stop());

githubTest.provider(
  "GitHub Actions demo encrypts and manages its selected secret",
  (stack) =>
    Effect.gen(function* () {
      github.reset();
      const deployed = yield* stack.deploy(
        githubSecrets({
          ageKey: fixtureAgeKey,
          baseUrl: github.baseUrl,
          owner: "darkmatter",
          repository: "example",
        }),
      );
      yield* stack.destroy();

      expect(deployed).toHaveLength(1);
      expect(github.requests.upsert).toBe(1);
      expect(github.secrets.has("DEPLOY_TOKEN")).toBe(false);
    }),
);

const cloudflare = createMockCloudflare();
const { test: cloudflareTest } = Test.make({
  providers: Layer.mergeAll(
    Credentials.fromApiToken({
      apiToken: "test-token",
      apiBaseUrl: cloudflare.baseUrl,
    }),
    Layer.succeed(Retry.Retry, { while: () => false }),
  ),
});

afterAll(() => cloudflare.stop());

cloudflareTest.provider(
  "Cloudflare Secrets Store demo imports its selected secret",
  (stack) =>
    Effect.gen(function* () {
      cloudflare.reset();
      const deployed = yield* stack.deploy(
        cloudflareSecrets({
          accountId: "account-id",
          ageKey: fixtureAgeKey,
          storeId: "store-id",
        }),
      );
      yield* stack.destroy();

      expect(deployed.imported).toHaveLength(1);
      expect(deployed.imported[0]!.name).toBe("API_TOKEN");
      expect(cloudflare.requests.seen).toEqual([
        "GET /accounts/account-id/secrets_store/stores/store-id/secrets",
        "POST /accounts/account-id/secrets_store/stores/store-id/secrets",
      ]);
      expect(cloudflare.requests.create).toBe(1);
      expect(cloudflare.requests.delete).toBe(0);
      expect(cloudflare.secrets.has("API_TOKEN")).toBe(true);
    }),
);

function createMockGitHub() {
  const secrets = new Map<string, { readonly encryptedValue: string }>();
  const requests = { upsert: 0 };
  const server = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const url = new URL(request.url);
      const publicKeyPath =
        "/api/v3/repos/darkmatter/example/actions/secrets/public-key";
      const secretPrefix = "/api/v3/repos/darkmatter/example/actions/secrets/";

      if (url.pathname === publicKeyPath && request.method === "GET") {
        return Response.json({
          key_id: "test-key",
          key: Buffer.alloc(32, 1).toString("base64"),
        });
      }

      if (url.pathname.startsWith(secretPrefix) && request.method === "PUT") {
        requests.upsert += 1;
        const name = decodeURIComponent(url.pathname.slice(secretPrefix.length));
        const body = (await request.json()) as {
          readonly encrypted_value: string;
          readonly key_id: string;
        };
        if (body.key_id !== "test-key" || body.encrypted_value === "") {
          return Response.json({ message: "invalid secret payload" }, { status: 400 });
        }
        secrets.set(name, { encryptedValue: body.encrypted_value });
        return new Response(null, { status: 201 });
      }

      if (url.pathname.startsWith(secretPrefix) && request.method === "DELETE") {
        secrets.delete(decodeURIComponent(url.pathname.slice(secretPrefix.length)));
        return new Response(null, { status: 204 });
      }

      return Response.json({ message: "not found" }, { status: 404 });
    },
  });

  return {
    baseUrl: server.url.origin,
    requests,
    secrets,
    reset: () => {
      secrets.clear();
      requests.upsert = 0;
    },
    stop: () => server.stop(true),
  };
}

function createMockCloudflare() {
  const secrets = new Map<string, { readonly id: string; readonly name: string }>();
  const requests = { create: 0, delete: 0, seen: [] as string[] };
  const server = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const url = new URL(request.url);
      requests.seen.push(`${request.method} ${url.pathname}`);
      const collection =
        "/accounts/account-id/secrets_store/stores/store-id/secrets";

      if (url.pathname === collection && request.method === "GET") {
        return Response.json({
          success: true,
          errors: [],
          messages: [],
          result: [],
          result_info: { count: 0, page: 1, per_page: 100, total_count: 0 },
        });
      }

      if (url.pathname === collection && request.method === "POST") {
        requests.create += 1;
        const entries = (await request.json()) as {
          readonly name: string;
          readonly value: string;
        }[];
        const result = entries.map((entry, index) => {
          const secret = { id: `secret-${index + 1}`, name: entry.name };
          secrets.set(secret.name, secret);
          return {
            id: secret.id,
            created: "2026-01-01T00:00:00Z",
            modified: "2026-01-01T00:00:00Z",
            name: secret.name,
            status: "active",
            store_id: "store-id",
          };
        });
        return Response.json({ success: true, errors: [], messages: [], result });
      }

      const match = url.pathname.match(
        /^\/accounts\/account-id\/secrets_store\/stores\/store-id\/secrets\/([^/]+)$/,
      );
      if (match && request.method === "DELETE") {
        requests.delete += 1;
        for (const [name, secret] of secrets) {
          if (secret.id === match[1]) secrets.delete(name);
        }
        return Response.json({ success: true, errors: [], messages: [], result: {} });
      }

      return Response.json({ message: "not found" }, { status: 404 });
    },
  });

  return {
    baseUrl: server.url.origin,
    requests,
    secrets,
    reset: () => {
      secrets.clear();
      requests.create = 0;
      requests.delete = 0;
      requests.seen.length = 0;
    },
    stop: () => server.stop(true),
  };
}
