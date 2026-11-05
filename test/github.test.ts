import { expect } from "bun:test";
import * as GitHub from "@alchemy.run/github";
import * as Provider from "alchemy/Provider";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import {
  GitHubSopsSecrets,
  SopsFileProvider,
  type SopsCommandRequest,
} from "../src/index.ts";

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

const { test, afterAll } = Test.make({
  providers: Layer.mergeAll(
    SopsFileProvider({
      decrypt: (request: SopsCommandRequest) =>
        Effect.sync(() =>
          JSON.stringify({ deploy: { token: request.content } }),
        ),
    }),
    gitHubProviders,
  ) as Layer.Layer<any, never, any>,
});

afterAll(Effect.sync(() => github.stop()));

test.provider(
  "imports SOPS values as GitHub Actions secrets through GitHub.Secret",
  (stack) =>
    Effect.gen(function* () {
      github.reset();
      let ciphertext = "ciphertext-v1";

      const deploy = Effect.gen(function* () {
        return yield* GitHubSopsSecrets("DeploySecrets", {
          content: ciphertext,
          format: "json",
          owner: "darkmatter",
          repository: "example",
          secrets: {
            DEPLOY_TOKEN: "deploy.token",
          },
        });
      });

      const created = yield* stack.deploy(deploy);
      ciphertext = "ciphertext-v2";
      const updated = yield* stack.deploy(deploy);

      expect(github.secrets.get("DEPLOY_TOKEN")?.encryptedValue).not.toBe(
        ciphertext,
      );
      yield* stack.destroy();

      expect(created).toHaveLength(1);
      expect(created[0]!.updatedAt).toEqual(expect.any(String));
      expect(updated).toHaveLength(1);
      expect(github.requests.repoPublicKey).toBeGreaterThanOrEqual(2);
      expect(github.requests.upsert).toBeGreaterThanOrEqual(2);
      expect(github.requests.delete).toBe(1);
      expect(github.secrets.has("DEPLOY_TOKEN")).toBe(false);
    }),
);

function createMockGitHub() {
  const secrets = new Map<string, { readonly encryptedValue: string }>();
  const requests = {
    delete: 0,
    repoPublicKey: 0,
    upsert: 0,
  };
  const server = Bun.serve({
    port: 0,
    fetch: async (request) => {
      const url = new URL(request.url);
      const publicKeyPath =
        "/api/v3/repos/darkmatter/example/actions/secrets/public-key";
      const secretPrefix = "/api/v3/repos/darkmatter/example/actions/secrets/";

      if (url.pathname === publicKeyPath && request.method === "GET") {
        requests.repoPublicKey += 1;
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
        requests.delete += 1;
        const name = decodeURIComponent(url.pathname.slice(secretPrefix.length));
        secrets.delete(name);
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
      requests.delete = 0;
      requests.repoPublicKey = 0;
      requests.upsert = 0;
    },
    stop: () => server.stop(true),
  };
}
