import { expect, test as bunTest } from "bun:test";
import * as Credentials from "@distilled.cloud/cloudflare/Credentials";
import { Retry } from "@distilled.cloud/cloudflare";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import {
  CloudflareSopsSecrets,
  cloudflareSecretName,
  cloudflareSopsWorkerBindings,
  planCloudflareSecretImports,
} from "../src/index.ts";
import { materializeSecretDocument } from "../src/document.ts";
import { SopsInputError } from "../src/errors.ts";

const cloudflare = createMockCloudflare();

const providers = Layer.mergeAll(
  Credentials.fromApiToken({
    apiToken: "test-token",
    apiBaseUrl: cloudflare.baseUrl,
  }),
  Layer.succeed(Retry.Retry, { while: () => false }),
);

const { test, afterAll } = Test.make({ providers });

const { test: devTest } = Test.make({ stage: "dev", providers });

afterAll(Effect.sync(() => cloudflare.stop()));

bunTest("derives Cloudflare secret names from SOPS paths", () => {
  expect(cloudflareSecretName("api.token")).toBe("API_TOKEN");
  expect(cloudflareSecretName("oauth.clients[0].secret")).toBe(
    "OAUTH_CLIENTS_0_SECRET",
  );
  expect(cloudflareSecretName("1password.item")).toBe("_1PASSWORD_ITEM");
});

bunTest("plans explicit Cloudflare secret imports", () => {
  const document = materializeSecretDocument(
    '{"api":{"token":"secret"},"database":{"url":"postgres://db"}}',
    { format: "json" },
  );

  const imports = planCloudflareSecretImports(document.flat, {
    secrets: {
      API_TOKEN: "api.token",
      DATABASE_URL: "database.url",
    },
  });

  expect(imports.map(({ name, path }) => ({ name, path }))).toEqual([
    { name: "API_TOKEN", path: "api.token" },
    { name: "DATABASE_URL", path: "database.url" },
  ]);
  expect(Redacted.value(imports[0]!.value)).toBe("secret");
});

bunTest("plans generated Cloudflare secret names with a prefix", () => {
  const document = materializeSecretDocument(
    '{"api":{"token":"secret"},"enabled":true}',
    { format: "json" },
  );

  const imports = planCloudflareSecretImports(document.flat, {
    namePrefix: "WORKER_",
  });

  expect(imports.map(({ name, path }) => ({ name, path }))).toEqual([
    { name: "WORKER_API_TOKEN", path: "api.token" },
    { name: "WORKER_ENABLED", path: "enabled" },
  ]);
});

bunTest("builds Worker bindings for imported store secrets", () => {
  expect(
    cloudflareSopsWorkerBindings(
      { storeId: "store-id" },
      {
        API_TOKEN: "SOPS_API_TOKEN",
      },
    ),
  ).toEqual({
    bindings: [
      {
        type: "secrets_store_secret",
        name: "API_TOKEN",
        secretName: "SOPS_API_TOKEN",
        storeId: "store-id",
      },
    ],
  });
});

bunTest("fails when an explicit secret path is missing", () => {
  const document = materializeSecretDocument('{"api":{"token":"secret"}}', {
    format: "json",
  });

  expect(() =>
    planCloudflareSecretImports(document.flat, {
      secrets: { MISSING: "missing.path" },
    }),
  ).toThrow(SopsInputError);
});

test.provider(
  "create, noop, replace Cloudflare secrets through an Action",
  (stack) =>
    Effect.gen(function* () {
      cloudflare.reset();
      const fixture = yield* writeActionFixture("worker-secrets");

      const deploy = Effect.gen(function* () {
        const imported = yield* CloudflareSopsSecrets("WorkerSecrets", {
          path: fixture.encryptedPath,
          format: "json",
          backend: "cli",
          sopsBinary: fixture.sopsBinary,
          store: {
            accountId: "account-id",
            storeId: "store-id",
          },
          secrets: {
            API_TOKEN: "api.token",
          },
          comment: "imported by effect-sops",
        });

        return {
          imported,
        };
      });

      const created = yield* stack.deploy(deploy);
      const unchanged = yield* stack.deploy(deploy);
      yield* Effect.promise(() =>
        writeFile(fixture.encryptedPath, "ciphertext-v2"),
      );
      const updated = yield* stack.deploy(deploy);
      yield* stack.destroy();

      expect(created.imported.imported[0]!.name).toBe("API_TOKEN");
      expect(created.imported.topLevelKeys).toEqual(["api"]);
      expect(unchanged.imported.imported[0]!.secretId).toBe(
        created.imported.imported[0]!.secretId,
      );
      expect(updated.imported.imported[0]!.name).toBe("API_TOKEN");
      expect(cloudflare.requests.create).toBe(2);
      expect(cloudflare.requests.delete).toBe(1);
      expect(cloudflare.requests.patch).toBe(0);
      expect(cloudflare.secrets.get("API_TOKEN")?.value).toBe(
        "ciphertext-v2",
      );
    }),
);

test.provider(
  "imports secrets from ordered SOPS file arrays",
  (stack) =>
    Effect.gen(function* () {
      cloudflare.reset();
      const common = yield* writeActionFixture("worker-secrets-common");
      const stage = yield* writeActionFixture("worker-secrets-stage");
      yield* Effect.promise(() => writeFile(stage.encryptedPath, "ciphertext-stage"));

      const imported = yield* stack.deploy(
        Effect.gen(function* () {
          return yield* CloudflareSopsSecrets("WorkerSecretsArray", {
            path: [common.encryptedPath, stage.encryptedPath],
            format: "json",
            backend: "cli",
            sopsBinary: common.sopsBinary,
            store: {
              accountId: "account-id",
              storeId: "store-id",
            },
            secrets: {
              API_TOKEN: "api.token",
            },
          });
        }),
      );
      yield* stack.destroy();

      expect(imported.path).toBe([common.encryptedPath, stage.encryptedPath].join(","));
      expect(imported.topLevelKeys).toEqual(["api"]);
      expect(imported.imported[0]!.name).toBe("API_TOKEN");
      expect(cloudflare.secrets.get("API_TOKEN")?.value).toBe("ciphertext-stage");
    }),
);

test.provider(
  "uses a Cloudflare-valid page size when listing store secrets",
  (stack) =>
    Effect.gen(function* () {
      cloudflare.reset();
      cloudflare.rejectInvalidPerPage();
      const fixture = yield* writeActionFixture("worker-secrets-page-size");

      const deployed = yield* stack.deploy(
        Effect.gen(function* () {
          return yield* CloudflareSopsSecrets("WorkerSecretsPageSize", {
            path: fixture.encryptedPath,
            format: "json",
            backend: "cli",
            sopsBinary: fixture.sopsBinary,
            store: {
              accountId: "account-id",
              storeId: "store-id",
            },
            secrets: {
              API_TOKEN: "api.token",
            },
            comment: "imported by effect-sops",
          });
        }),
      );
      yield* stack.destroy();

      expect(deployed.imported[0]!.name).toBe("API_TOKEN");
      expect(cloudflare.requests.list).toBeGreaterThan(0);
    }),
);

devTest.provider(
  "skips the Cloudflare Secrets Store import in the dev stage",
  (stack) =>
    Effect.gen(function* () {
      cloudflare.reset();
      const fixture = yield* writeActionFixture("worker-secrets-dev");

      const imported = yield* stack.deploy(
        Effect.gen(function* () {
          return yield* CloudflareSopsSecrets("WorkerSecretsDev", {
            path: fixture.encryptedPath,
            format: "json",
            backend: "cli",
            sopsBinary: fixture.sopsBinary,
            store: {
              accountId: "account-id",
              storeId: "store-id",
            },
            secrets: {
              API_TOKEN: "api.token",
            },
            comment: "imported by effect-sops",
          });
        }),
      );
      yield* stack.destroy();

      expect(imported.accountId).toBe("account-id");
      expect(imported.storeId).toBe("store-id");
      expect(imported.path).toBe(fixture.encryptedPath);
      expect(imported.imported).toEqual([]);
      expect(imported.topLevelKeys).toEqual([]);
      expect(cloudflare.requests.list).toBe(0);
      expect(cloudflare.requests.create).toBe(0);
      expect(cloudflare.requests.delete).toBe(0);
      expect(cloudflare.requests.patch).toBe(0);
      expect(cloudflare.secrets.size).toBe(0);
    }),
);

interface MockSecret {
  readonly id: string;
  readonly name: string;
  readonly scopes: string[];
  readonly value: string;
  readonly status: "pending" | "active" | "deleted";
  readonly comment?: string;
  readonly storeId: string;
}

function createMockCloudflare() {
  const secrets = new Map<string, MockSecret>();
  const requests = {
    create: 0,
    delete: 0,
    list: 0,
    patch: 0,
  };
  let nextId = 1;
  let rejectInvalidPerPage = false;

  const server = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const url = new URL(request.url);
      const path = url.pathname;
      const secretsPath =
        "/accounts/account-id/secrets_store/stores/store-id/secrets";

      if (path === secretsPath && request.method === "GET") {
        requests.list += 1;
        const page = Number(url.searchParams.get("page") ?? "1");
        const perPage = Number(
          url.searchParams.get("per_page") ??
            url.searchParams.get("perPage") ??
            "50",
        );
        if (rejectInvalidPerPage && perPage > 100) {
          return Response.json(
            {
              success: false,
              errors: [{ code: 1000, message: "invalid_per_page_parameter" }],
              messages: [],
              result: null,
            },
            { status: 400 },
          );
        }

        const search = url.searchParams.get("search");
        const result =
          page > 1
            ? []
            : Array.from(secrets.values())
                .filter((secret) => !search || secret.name.includes(search))
                .map(toCloudflareSecret);

        return Response.json({
          success: true,
          errors: [],
          messages: [],
          result,
          result_info: {
            count: result.length,
            page,
            per_page: perPage,
            total_count: result.length,
          },
        });
      }

      if (path === secretsPath && request.method === "POST") {
        requests.create += 1;
        const body = await request.json();
        const entries = Array.isArray(body)
          ? body
          : ((body as { body?: unknown[] }).body ?? []);
        const created: MockSecret[] = [];

        for (const entry of entries as {
          name: string;
          scopes: string[];
          value: string;
          comment?: string;
        }[]) {
          const secret: MockSecret = {
            id: `secret-${nextId++}`,
            name: entry.name,
            scopes: entry.scopes,
            value: entry.value,
            status: "active",
            storeId: "store-id",
            ...(entry.comment !== undefined ? { comment: entry.comment } : {}),
          };
          secrets.set(secret.name, secret);
          created.push(secret);
        }

        return Response.json({
          success: true,
          errors: [],
          messages: [],
          result: created.map(toCloudflareSecret),
        });
      }

      const secretPathMatch = path.match(
        /^\/accounts\/account-id\/secrets_store\/stores\/store-id\/secrets\/([^/]+)$/,
      );
      if (secretPathMatch && request.method === "DELETE") {
        requests.delete += 1;
        const secretId = secretPathMatch[1]!;
        const secret = Array.from(secrets.values()).find(
          (item) => item.id === secretId,
        );
        if (secret) secrets.delete(secret.name);

        return Response.json({
          success: true,
          errors: [],
          messages: [],
          result: secret ? toCloudflareSecret(secret) : {},
        });
      }

      if (secretPathMatch && request.method === "PATCH") {
        requests.patch += 1;
        const secretId = secretPathMatch[1]!;
        const body = (await request.json()) as {
          scopes?: string[];
          comment?: string;
        };
        const secret = Array.from(secrets.values()).find(
          (item) => item.id === secretId,
        );
        if (!secret) return new Response("not found", { status: 404 });
        const patched: MockSecret = {
          ...secret,
          scopes: body.scopes ?? secret.scopes,
          ...(body.comment !== undefined ? { comment: body.comment } : {}),
        };
        secrets.set(patched.name, patched);

        return Response.json({
          success: true,
          errors: [],
          messages: [],
          result: toCloudflareSecret(patched),
        });
      }

      return new Response(`Unhandled ${request.method} ${path}`, {
        status: 404,
      });
    },
  });

  return {
    baseUrl: `http://127.0.0.1:${server.port}`,
    requests,
    secrets,
    reset: () => {
      secrets.clear();
      requests.create = 0;
      requests.delete = 0;
      requests.list = 0;
      requests.patch = 0;
      nextId = 1;
      rejectInvalidPerPage = false;
    },
    rejectInvalidPerPage: () => {
      rejectInvalidPerPage = true;
    },
    stop: () => server.stop(true),
  };
}

const toCloudflareSecret = (secret: MockSecret) => ({
  id: secret.id,
  created: "2026-01-01T00:00:00Z",
  modified: "2026-01-01T00:00:00Z",
  name: secret.name,
  status: secret.status,
  store_id: secret.storeId,
  ...(secret.comment !== undefined ? { comment: secret.comment } : {}),
});

const writeActionFixture = (name: string) =>
  Effect.promise(async () => {
    const dir = join(import.meta.dir, ".tmp", name);
    const encryptedPath = join(dir, "secrets.enc.json");
    const sopsBinary = join(dir, "sops-fake");
    await mkdir(dir, { recursive: true });
    await writeFile(encryptedPath, "ciphertext-v1");
    await writeFile(
      sopsBinary,
      [
        "#!/usr/bin/env bun",
        "const path = process.argv.at(-1);",
        "if (!path) process.exit(1);",
        "const value = (await Bun.file(path).text()).trim();",
        "process.stdout.write(JSON.stringify({ api: { token: value } }));",
      ].join("\n"),
    );
    await chmod(sopsBinary, 0o755);
    return { encryptedPath, sopsBinary };
  });
