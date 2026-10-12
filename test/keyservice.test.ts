import { describe, expect, test } from "bun:test";
import {
  Client,
  credentials,
  Server,
  ServerCredentials,
  status,
  type ServerUnaryCall,
  type sendUnaryData,
} from "@grpc/grpc-js";
import { parse } from "protobufjs";
import { Decrypter, armor } from "age-encryption";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { join } from "node:path";
import { tmpdir } from "node:os";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Schema from "effect/Schema";
import * as Redacted from "effect/Redacted";
import * as AlchemyTest from "alchemy/Test/Bun";
import * as Output from "alchemy/Output";
import { SopsFile, SopsFileProvider } from "../src/resource.ts";
import { runSopsAge } from "../src/sops-age.ts";
import { runSopsAge as runEdge } from "../src/edge.ts";
import { decodeEffect } from "../src/Schema.ts";
import { defaultDecrypt } from "../src/backend.ts";
import {
  defaultSopsDecryptMemoizeKey,
  type SopsCommandRequest,
} from "../src/decrypt.ts";
import { keyServiceTarget } from "../src/keyservice-client.ts";
import * as SopsConfig from "../src/Config.ts";
import encrypted from "./fixtures/native.enc.json" with { type: "json" };

const identity =
  "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
const fixture = (name: string) =>
  readFile(join(import.meta.dir, "fixtures", name), "utf8");
const protocol = parse(`syntax = "proto3";
  message AgeKey { string recipient = 1; }
  message Key { AgeKey age_key = 6; }
  message DecryptRequest { Key key = 1; bytes ciphertext = 2; }
  message DecryptResponse { bytes plaintext = 1; }
`).root;
const Request = Schema.Struct({
  key: Schema.Struct({ ageKey: Schema.Struct({ recipient: Schema.String }) }),
  ciphertext: Schema.Uint8Array,
});
type Request = typeof Request.Type;
type Response = { plaintext: Uint8Array };
type Handler = (
  call: ServerUnaryCall<Request, Response>,
  reply: sendUnaryData<Response>,
) => void;

const startServer = async (handler?: Handler, unix = false) => {
  const dir = await mkdtemp(join(tmpdir(), "effect-sops-keyservice-"));
  const server = new Server();
  const target = unix ? `unix:${join(dir, "s.sock")}` : "127.0.0.1:0";
  server.addService(
    {
      decrypt: {
        path: "/KeyService/Decrypt",
        requestStream: false,
        responseStream: false,
        requestSerialize: (value: Request) =>
          Buffer.from(
            protocol.lookupType("DecryptRequest").encode(value).finish(),
          ),
        requestDeserialize: (bytes: Buffer) =>
          Schema.decodeUnknownSync(Request)(
            protocol.lookupType("DecryptRequest").decode(bytes),
          ),
        responseSerialize: (value: Response) =>
          Buffer.from(
            protocol.lookupType("DecryptResponse").encode(value).finish(),
          ),
        responseDeserialize: (bytes: Buffer) => ({
          plaintext: Schema.decodeUnknownSync(
            Schema.Struct({ plaintext: Schema.Uint8Array }),
          )(protocol.lookupType("DecryptResponse").decode(bytes)).plaintext,
        }),
      },
    },
    {
      decrypt:
        handler ??
        ((
          call: ServerUnaryCall<Request, Response>,
          reply: sendUnaryData<Response>,
        ) => {
          const decrypter = new Decrypter();
          decrypter.addIdentity(identity);
          void decrypter
            .decrypt(
              armor.decode(new TextDecoder().decode(call.request.ciphertext)),
              "uint8array",
            )
            .then(
              (plaintext) => reply(null, { plaintext }),
              () =>
                reply({
                  code: status.PERMISSION_DENIED,
                  message: "Cannot unwrap",
                }),
            );
        }),
    },
  );
  try {
    const port = await new Promise<number>((resolve, reject) =>
      server.bindAsync(
        target,
        ServerCredentials.createInsecure(),
        (error, port) => (error ? reject(error) : resolve(port)),
      ),
    );
    return {
      uri: unix ? `unix://${join(dir, "s.sock")}` : `tcp://127.0.0.1:${port}`,
      close: async () => {
        server.forceShutdown();
        await rm(dir, { recursive: true, force: true });
      },
    };
  } catch (cause) {
    server.forceShutdown();
    await rm(dir, { recursive: true, force: true });
    throw cause;
  }
};

const withServer = async (
  body: (uri: string) => Promise<void>,
  handler?: Handler,
  unix = false,
) => {
  const server = await startServer(handler, unix);
  try {
    await body(server.uri);
  } finally {
    await server.close();
  }
};

const request = (uri: string): SopsCommandRequest => ({
  content: JSON.stringify(encrypted),
  binary: "/no-sops-binary",
  inputType: "json",
  outputType: "json",
  keyServices: [uri],
  enableLocalKeyService: false,
  timeoutMs: 2_000,
});

test("native TCP keyservice decrypts and validates a real SOPS document", () =>
  withServer(async (uri) => {
    expect(
      JSON.parse(await Effect.runPromise(runSopsAge(request(uri)))),
    ).toEqual({
      api: { token: "native-token", enabled: true },
      nested: { count: 3 },
    });
  }));

test("native Unix socket keyservice supports local paths and cwd", () =>
  withServer(
    async (uri) => {
      const { content, ...options } = request(uri);
      const plaintext = await Effect.runPromise(
        runSopsAge({
          ...options,
          cwd: import.meta.dir,
          path: "fixtures/native.enc.json",
        }),
      );
      expect(JSON.parse(plaintext).api.token).toBe("native-token");
    },
    undefined,
    true,
  ));

test("Schema and Config use the same native keyservice options", () =>
  withServer(async (uri) => {
    const options = { keyServices: [uri], enableLocalKeyService: false };
    const value = await Effect.runPromise(
      decodeEffect(
        Schema.Struct({
          api: Schema.Struct({
            token: Schema.RedactedFromValue(Schema.String),
          }),
        }),
      )(encrypted, options),
    );
    expect(Redacted.value(value.api.token)).toBe("native-token");
    const provider = SopsConfig.make({
      json: encrypted,
      backend: "sops-age",
      ...options,
    });
    expect(
      await Effect.runPromise(
        Config.nested(Config.String("token"), "api").pipe(
          Effect.provide(ConfigProvider.layer(provider)),
        ),
      ),
    ).toBe("native-token");
  }));

test("per-request environment variables support redacted values", () =>
  withServer(async (uri) => {
    const { keyServices, enableLocalKeyService, ...options } = request(uri);
    const plaintext = await Effect.runPromise(
      runSopsAge({
        ...options,
        env: {
          SOPS_KEYSERVICE: Redacted.make(uri),
          SOPS_ENABLE_LOCAL_KEYSERVICE: "false",
        },
      }),
    );
    expect(JSON.parse(plaintext).api.token).toBe("native-token");
  }));

test("explicit options override environment and local-only settings avoid remote RPC", () =>
  withServer(
    async (uri) => {
      const plaintext = await Effect.runPromise(
        runSopsAge({
          ...request(uri),
          enableLocalKeyService: true,
          env: {
            SOPS_KEYSERVICE: "tcp://127.0.0.1:1",
            SOPS_ENABLE_LOCAL_KEYSERVICE: "false",
            SOPS_AGE_KEY: identity,
          },
        }),
      );
      expect(JSON.parse(plaintext).api.token).toBe("native-token");
    },
    () => {
      throw new Error("Local recovery must happen first");
    },
  ));

test("local key failure proceeds to the remote service", () =>
  withServer(async (uri) => {
    const plaintext = await Effect.runPromise(
      runSopsAge({
        ...request(uri),
        enableLocalKeyService: true,
        env: { SOPS_AGE_KEY: "invalid-test-identity" },
      }),
    );
    expect(JSON.parse(plaintext).api.token).toBe("native-token");
  }));

test("tries subsequent services after a denied unwrap", () =>
  withServer(async (working) => {
    await withServer(
      async (denied) => {
        const plaintext = await Effect.runPromise(
          runSopsAge({ ...request(working), keyServices: [denied, working] }),
        );
        expect(JSON.parse(plaintext).api.token).toBe("native-token");
      },
      (_, reply) =>
        reply({
          code: status.PERMISSION_DENIED,
          message: "private server detail",
        }),
    );
  }));

for (const [name, inputType] of [
  ["keyservice.enc.yaml", "yaml"],
  ["keyservice.enc.env", "dotenv"],
] as const) {
  test(`decrypts and checks MAC for ${inputType}, independently of output format`, () =>
    withServer(async (uri) => {
      const plaintext = await Effect.runPromise(
        runSopsAge({
          ...request(uri),
          content: await fixture(name),
          inputType,
          outputType: "json",
        }),
      );
      expect(plaintext).toContain("native-token");
    }));
}

test("URL input is fetched once before native decryption", () =>
  withServer(async (uri) => {
    let reads = 0;
    const http = Bun.serve({
      port: 0,
      hostname: "127.0.0.1",
      fetch: () => {
        reads++;
        return new Response(JSON.stringify(encrypted));
      },
    });
    try {
      const { content, ...options } = request(uri);
      expect(
        JSON.parse(
          await Effect.runPromise(
            runSopsAge({ ...options, url: `http://127.0.0.1:${http.port}` }),
          ),
        ).api.token,
      ).toBe("native-token");
      expect(reads).toBe(1);
    } finally {
      await http.stop(true);
    }
  }));

test("MAC-only-encrypted honors unencrypted values and extraction", () =>
  withServer(async (uri) => {
    const document = JSON.parse(await fixture("keyservice-mac-only.enc.json"));
    document.public_unencrypted = "changed";
    const result = await Effect.runPromise(
      runSopsAge({
        ...request(uri),
        content: JSON.stringify(document),
        extract: '["api"]["token"]',
      }),
    );
    expect(result).toBe("native-token");
  }));

for (const mutation of [
  "removed value",
  "changed MAC",
  "changed timestamp",
  "plaintext substitution",
] as const) {
  test(`rejects ${mutation} even when extracting a different field`, () =>
    withServer(async (uri) => {
      const document = structuredClone(encrypted);
      if (mutation === "plaintext substitution")
        document.api.token = "native-token";
      if (mutation === "removed value")
        Reflect.deleteProperty(document, "nested");
      if (mutation === "changed MAC")
        document.sops.mac = document.sops.mac.replace("data:j", "data:k");
      if (mutation === "changed timestamp")
        document.sops.lastmodified = "2020-01-01T00:00:00Z";
      await expect(
        Effect.runPromise(
          runSopsAge({
            ...request(uri),
            content: JSON.stringify(document),
            extract: '["api"]["token"]',
          }),
        ),
      ).rejects.toThrow();
    }));
}

test("rejects invalid data keys without exposing server details", () =>
  withServer(
    async (uri) => {
      await expect(Effect.runPromise(runSopsAge(request(uri)))).rejects.toThrow(
        "expected 32 bytes",
      );
    },
    (_, reply) => reply(null, { plaintext: new Uint8Array(31) }),
  ));

test("auto never invokes the CLI after a keyservice failure", () =>
  withServer(
    async (uri) => {
      await expect(
        Effect.runPromise(
          defaultDecrypt(
            "auto",
            "json",
          )({ ...request(uri), path: "unused.json" }),
        ),
      ).rejects.toThrow("gRPC status 7");
    },
    (_, reply) =>
      reply({
        code: status.PERMISSION_DENIED,
        message: "private server detail",
      }),
  ));

test("deadline cancels a stalled request", () =>
  withServer(
    async (uri) => {
      await expect(
        Effect.runPromise(runSopsAge({ ...request(uri), timeoutMs: 100 })),
      ).rejects.toThrow(/timed out|gRPC status 4/);
    },
    () => {},
  ));

test("Effect interruption cancels the in-flight RPC", async () => {
  const started = Promise.withResolvers<void>();
  const cancelled = Promise.withResolvers<void>();
  await withServer(
    async (uri) => {
      const fiber = Effect.runFork(runSopsAge(request(uri)));
      await started.promise;
      await Effect.runPromise(Fiber.interrupt(fiber));
      await cancelled.promise;
    },
    (call) => {
      call.on("cancelled", () => cancelled.resolve());
      started.resolve();
    },
  );
});

test("memoization separates endpoints and local-recovery policies", () => {
  const first = request("unix:///first.sock");
  expect(defaultSopsDecryptMemoizeKey(first)).not.toBe(
    defaultSopsDecryptMemoizeKey(request("unix:///second.sock")),
  );
  expect(defaultSopsDecryptMemoizeKey(first)).not.toBe(
    defaultSopsDecryptMemoizeKey({ ...first, enableLocalKeyService: true }),
  );
  const { keyServices, ...envRequest } = first;
  expect(
    defaultSopsDecryptMemoizeKey({
      ...envRequest,
      env: { SOPS_KEYSERVICE: "unix:///first.sock" },
    }),
  ).not.toBe(
    defaultSopsDecryptMemoizeKey({
      ...envRequest,
      env: { SOPS_KEYSERVICE: "unix:///second.sock" },
    }),
  );
});

test("rejects disabled recovery, malformed config, unsupported groups, and edge transport", async () => {
  await expect(
    Effect.runPromise(runSopsAge({ ...request(""), keyServices: [] })),
  ).rejects.toThrow("no remote");
  const { enableLocalKeyService, ...options } = request("tcp://127.0.0.1:1");
  await expect(
    Effect.runPromise(
      runSopsAge({
        ...options,
        env: { SOPS_ENABLE_LOCAL_KEYSERVICE: "maybe" },
      }),
    ),
  ).rejects.toThrow("must be a boolean");
  await expect(
    Effect.runPromise(
      runSopsAge({
        ...request("tcp://127.0.0.1:1"),
        content: JSON.stringify({
          ...encrypted,
          sops: { ...encrypted.sops, key_groups: [] },
        }),
      }),
    ),
  ).rejects.toThrow("key groups");
  await expect(
    Effect.runPromise(runEdge(request("tcp://127.0.0.1:1"))),
  ).rejects.toThrow("no gRPC transport");
  expect(() => keyServiceTarget("https://example.com")).toThrow();
  expect(() => keyServiceTarget("unix://host/path")).toThrow();
});

// Independent interoperability check: this server uses SOPS's Go protobuf
// implementation and key handling, not the TypeScript test server above.
describe.skipIf(!Bun.which("sops"))("real SOPS keyservice", () => {
  test("decrypts through SOPS in Bun and Node, including inherited environment", async () => {
    const binary = Bun.which("sops");
    if (!binary) throw new Error("sops missing");
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-real-keyservice-"));
    const socket = join(dir, "s.sock");
    const server = spawn(
      binary,
      ["keyservice", "--network", "unix", "--address", socket],
      { env: { SOPS_AGE_KEY: identity }, stdio: "ignore" },
    );
    const closed = new Promise((resolve) => server.once("close", resolve));
    const client = new Client(`unix:${socket}`, credentials.createInsecure());
    try {
      await new Promise<void>((resolve, reject) =>
        client.waitForReady(Date.now() + 3_000, (error) =>
          error ? reject(error) : resolve(),
        ),
      );
      const plaintext = await Effect.runPromise(
        runSopsAge(request(`unix://${socket}`)),
      );
      expect(JSON.parse(plaintext).api.token).toBe("native-token");
      const node = Bun.which("node");
      if (!node)
        throw new Error(
          "Node is required for the real keyservice integration test",
        );
      // Keep external package resolution rooted in this checkout, while testing
      // the TypeScript implementation in an independent Node runtime.
      const nodeDir = await mkdtemp(join(import.meta.dir, ".keyservice-node-"));
      try {
        const built = await Bun.build({
          entrypoints: [join(import.meta.dir, "../src/sops-age.ts")],
          target: "node",
          packages: "external",
        });
        expect(built.success).toBe(true);
        const bundle = built.outputs[0];
        if (!bundle) throw new Error("Missing Node bundle");
        const entry = join(nodeDir, "backend.mjs");
        await writeFile(entry, await bundle.text());
        const script = `
          import { runSopsAge } from ${JSON.stringify(entry)};
          import * as Effect from "effect/Effect";
          const request = { content: ${JSON.stringify(JSON.stringify(encrypted))}, binary: "/no-sops-binary", inputType: "json", timeoutMs: 2000 };
          const check = async (options) => {
            const result = JSON.parse(await Effect.runPromise(runSopsAge(options)));
            if (result.api.token !== "native-token") throw new Error("Wrong result");
          };
          await check(request);
          process.env.SOPS_KEYSERVICE = "tcp://127.0.0.1:1";
          await check({ ...request, env: { SOPS_KEYSERVICE: ${JSON.stringify(`unix://${socket}`)} } });
          await check({ ...request, keyServices: [], enableLocalKeyService: true, env: { SOPS_AGE_KEY: ${JSON.stringify(identity)} } });
          console.log("Node keyservice and environment precedence: PASS");
        `;
        const child = Bun.spawn(
          [node, "--input-type=module", "--eval", script],
          {
            cwd: join(import.meta.dir, ".."),
            env: {
              SOPS_KEYSERVICE: `unix://${socket}`,
              SOPS_ENABLE_LOCAL_KEYSERVICE: "false",
            },
            stdout: "pipe",
            stderr: "pipe",
          },
        );
        const [stdout, stderr, code] = await Promise.all([
          new Response(child.stdout).text(),
          new Response(child.stderr).text(),
          child.exited,
        ]);
        expect(stderr).toBe("");
        expect(code).toBe(0);
        expect(stdout).toContain(
          "Node keyservice and environment precedence: PASS",
        );
      } finally {
        await rm(nodeDir, { recursive: true, force: true });
      }
    } finally {
      client.close();
      server.kill();
      await closed;
      await rm(dir, { recursive: true, force: true });
    }
  });
});

const { test: providerTest } = AlchemyTest.make({
  providers: SopsFileProvider(),
});
providerTest.provider("SopsFile preserves native keyservice options", (stack) =>
  Effect.acquireUseRelease(
    Effect.promise(() => startServer()),
    ({ uri }) =>
      Effect.gen(function* () {
        const outputs = yield* stack.deploy(
          Effect.gen(function* () {
            const secrets = yield* SopsFile("RemoteAge", {
              json: encrypted,
              backend: "sops-age",
              sopsBinary: "/no-sops-binary",
              keyServices: [uri],
              enableLocalKeyService: false,
            });
            return {
              token: Output.map(secrets.data, (data) => data.api.token),
            };
          }),
        );
        expect(Redacted.value(outputs.token)).toBe("native-token");
        yield* stack.destroy();
      }),
    (server) => Effect.promise(() => server.close()),
  ),
);
