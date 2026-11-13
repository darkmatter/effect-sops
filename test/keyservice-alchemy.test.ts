import { expect, test } from "bun:test";
import * as net from "node:net";
import * as Output from "alchemy/Output";
import * as Test from "alchemy/Test/Bun";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Layer from "effect/Layer";
import * as Logger from "effect/Logger";
import * as Path from "effect/Path";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";
import { fixtureAgeKey } from "../examples/_shared/fixture.ts";
import { program as exampleProgram } from "../examples/keyservice/app.ts";
import {
  keyServiceProviders,
  SopsKeyService,
  SopsKeyServiceTunnel,
  type SopsKeyServiceProps,
} from "../src/keyservice/alchemy.ts";
import * as Listen from "../src/keyservice/listen.ts";
import { SopsFile, SopsFileProvider } from "../src/resource.ts";
import { runSopsAge } from "../src/sops-age.ts";
import encrypted from "./fixtures/native.enc.json" with { type: "json" };

test("the sidecar entry default-exports a Layer", async () => {
  const entry = await import("../src/keyservice/alchemy-local.ts");
  expect(Layer.isLayer(entry.default)).toBe(true);
});

const { test: keyServiceTest } = Test.make({
  providers: Layer.mergeAll(keyServiceProviders(), SopsFileProvider()),
});

const fixture = Effect.gen(function* () {
  const fs = yield* FileSystem.FileSystem;
  const path = yield* Path.Path;
  const directory = yield* fs.makeTempDirectoryScoped({ prefix: "sops-alchemy-" });
  const identityFile = path.join(directory, "fixture-age-identity");
  yield* fs.writeFileString(identityFile, Redacted.value(fixtureAgeKey), { mode: 0o600 });
  return {
    fs,
    identityFile,
    pidFile: path.join(directory, "ssh.pid"),
    ssh: path.join(import.meta.dir, "fixtures/ssh/ssh-fake"),
    document: path.join(import.meta.dir, "fixtures/native.enc.json"),
    props: {
      listen: [Listen.loopback(0)],
      age: { identityFiles: [identityFile], discover: false },
    },
  };
});

const decrypt = (uri: string) =>
  runSopsAge({
    content: JSON.stringify(encrypted),
    binary: "/unused-sops-binary",
    inputType: "json",
    outputType: "json",
    keyServices: [uri],
    enableLocalKeyService: false,
    timeoutMs: 2_000,
  });

const connectionStatus = (uri: string) =>
  Effect.callback<"connected" | "refused", Error>((resume) => {
    const address = new URL(uri);
    const socket = net.createConnection({ host: address.hostname, port: Number(address.port) });
    socket.once("connect", () => {
      socket.destroy();
      resume(Effect.succeed("connected"));
    });
    socket.once("error", (error: NodeJS.ErrnoException) =>
      resume(error.code === "ECONNREFUSED" ? Effect.succeed("refused") : Effect.fail(error)),
    );
    socket.setTimeout(1_000, () => {
      socket.destroy();
      resume(Effect.fail(new Error("Connection probe timed out")));
    });
    return Effect.sync(() => socket.destroy());
  });

const awaitRefused = (uri: string) =>
  connectionStatus(uri).pipe(
    Effect.repeat({
      schedule: Schedule.spaced("20 millis"),
      until: (status) => status === "refused",
      times: 100,
    }),
  );

keyServiceTest.provider("keyservice decrypts, preserves a noop, updates, and closes on destroy", (stack) =>
  Effect.gen(function* () {
    const { props } = yield* fixture;
    // Both ports are occupied before update, so the replacement cannot reuse the old URI.
    const program = SopsKeyService("KeyService", {
      ...props,
      listen: [Listen.loopback(0), Listen.loopback(0)],
    });
    const created = yield* stack.deploy(program);
    expect(created.uris).toHaveLength(2);
    expect(created.uris[0]).toBe(created.uri);
    expect(created.remoteUris).toEqual([]);
    expect(JSON.parse(yield* decrypt(created.uri)).api.token).toBe("native-token");

    const unchanged = yield* stack.deploy(program);
    expect(unchanged.uri).toBe(created.uri);
    expect(yield* connectionStatus(unchanged.uri)).toBe("connected");

    const updated = yield* stack.deploy(
      SopsKeyService("KeyService", {
        ...props,
        listen: [Listen.loopback(Number(new URL(created.uris[1]!).port))],
        requestTimeoutSeconds: 10,
      }),
    );
    expect(JSON.parse(yield* decrypt(updated.uri)).api.token).toBe("native-token");
    expect(yield* awaitRefused(created.uri)).toBe("refused");

    yield* stack.destroy();
    expect(yield* awaitRefused(updated.uri)).toBe("refused");
  }),
);

keyServiceTest.provider("SopsFile resolves a keyservice Output URI before decryption", (stack) =>
  Effect.gen(function* () {
    const { props, document } = yield* fixture;
    const deployed = yield* stack.deploy(Effect.gen(function* () {
      const service = yield* SopsKeyService("KeyService", props);
      const secrets = yield* SopsFile("Secrets", {
        path: document,
        backend: "sops-age",
        keyServices: [service.uri],
        enableLocalKeyService: false,
        secrets: { API_TOKEN: "api.token" },
      });
      return {
        uri: service.uri,
        token: Output.map(secrets.secrets, (values) => values.API_TOKEN!),
      };
    }));
    expect(Redacted.value(deployed.token)).toBe("native-token");
    yield* stack.destroy();
    expect(yield* awaitRefused(deployed.uri)).toBe("refused");
  }),
);

keyServiceTest.provider("SSH tunnel decrypts Output consumers and restarts after its child exits", (stack) =>
  Effect.gen(function* () {
    const { props, document, ssh, pidFile, fs } = yield* fixture;
    const program = Effect.gen(function* () {
      const service = yield* SopsKeyService("KeyService", props);
      const tunnel = yield* SopsKeyServiceTunnel("Tunnel", {
        destination: "fixture-host",
        remotePort: Output.map(service.uri, (uri) => Number(new URL(uri).port)),
        localPort: 0,
        ssh,
        sshArgs: ["-o", `FakePidFile=${pidFile}`],
        readyTimeoutSeconds: 3,
      });
      const secrets = yield* SopsFile("Secrets", {
        path: document,
        backend: "sops-age",
        keyServices: [tunnel.uri],
        enableLocalKeyService: false,
        secrets: { API_TOKEN: "api.token" },
      });
      return {
        uri: tunnel.uri,
        localPort: tunnel.localPort,
        serviceUri: service.uri,
        token: Output.map(secrets.secrets, (values) => values.API_TOKEN!),
      };
    });

    const created = yield* stack.deploy(program);
    expect(created.localPort).toBeGreaterThan(0);
    expect(created.uri).toBe(`tcp://127.0.0.1:${created.localPort}`);
    expect(Redacted.value(created.token)).toBe("native-token");
    const originalPid = Number(yield* fs.readFileString(pidFile));
    expect(Number.isSafeInteger(originalPid) && originalPid > 1).toBe(true);

    const unchanged = yield* stack.deploy(program);
    expect(unchanged.uri).toBe(created.uri);
    expect(Number(yield* fs.readFileString(pidFile))).toBe(originalPid);

    yield* Effect.sync(() => process.kill(originalPid, "SIGTERM"));
    expect(yield* awaitRefused(created.uri)).toBe("refused");
    const restarted = yield* Effect.gen(function* () {
      const deployed = yield* stack.deploy(program);
      return { deployed, pid: Number(yield* fs.readFileString(pidFile)) };
    }).pipe(Effect.repeat({
      schedule: Schedule.spaced("20 millis"),
      until: ({ pid }) => pid !== originalPid,
      times: 20,
    }));
    expect(restarted.pid).not.toBe(originalPid);
    expect(restarted.deployed.serviceUri).toBe(created.serviceUri);
    expect(JSON.parse(yield* decrypt(restarted.deployed.uri)).api.token).toBe("native-token");
    expect(Redacted.value(restarted.deployed.token)).toBe("native-token");

    yield* stack.destroy();
    expect(yield* awaitRefused(restarted.deployed.uri)).toBe("refused");
    expect(yield* awaitRefused(restarted.deployed.serviceUri)).toBe("refused");
    expect(() => process.kill(restarted.pid, 0)).toThrow();
  }),
  { timeout: 30_000 },
);

keyServiceTest.provider("keyservice example deploys and destroys using its explicit fixture identity file", (stack) =>
  Effect.gen(function* () {
    const { identityFile } = yield* fixture;
    const deployed = yield* stack.deploy(exampleProgram(identityFile));
    expect(Redacted.value(deployed.apiToken)).toBe("native-token");
    expect(deployed.topLevelKeys).toEqual(["api", "nested"]);
    yield* stack.destroy();
    expect(yield* awaitRefused(deployed.uri)).toBe("refused");
  }),
);

keyServiceTest.provider("a dead remote forward closes its keyservice instance before replacement", (stack) => {
  let warningCount = 0;
  const logger = Logger.make(({ logLevel, message }) => {
    if (
      logLevel === "Warn" && Array.isArray(message) &&
      message.some((value: unknown) =>
        typeof value === "string" && value.includes("SSH forward exited"))
    ) warningCount += 1;
  });
  return Effect.gen(function* () {
    const { props, ssh, pidFile, fs } = yield* fixture;
    const program = SopsKeyService("KeyService", {
      ...props,
      remoteForwards: [{
        destination: "fixture-host",
        remotePort: 0,
        ssh,
        sshArgs: ["-o", `FakePidFile=${pidFile}`],
      }],
    });
    const created = yield* stack.deploy(program);
    expect(created.remoteUris).toHaveLength(1);
    expect(JSON.parse(yield* decrypt(created.remoteUris[0]!)).api.token).toBe("native-token");
    const originalPid = Number(yield* fs.readFileString(pidFile));
    expect(Number.isSafeInteger(originalPid) && originalPid > 1).toBe(true);

    yield* Effect.sync(() => process.kill(originalPid, "SIGTERM"));
    expect(yield* awaitRefused(created.remoteUris[0]!)).toBe("refused");
    expect(yield* awaitRefused(created.uri)).toBe("refused");
    expect(warningCount).toBe(1);

    const restarted = yield* Effect.gen(function* () {
      const deployed = yield* stack.deploy(program);
      return { deployed, pid: Number(yield* fs.readFileString(pidFile)) };
    }).pipe(Effect.repeat({
      schedule: Schedule.spaced("20 millis"),
      until: ({ pid }) => pid !== originalPid,
      times: 20,
    }));
    expect(restarted.pid).not.toBe(originalPid);
    expect(JSON.parse(yield* decrypt(restarted.deployed.uri)).api.token).toBe("native-token");
    expect(JSON.parse(yield* decrypt(restarted.deployed.remoteUris[0]!)).api.token).toBe("native-token");

    yield* stack.destroy();
    expect(yield* awaitRefused(restarted.deployed.uri)).toBe("refused");
    expect(yield* awaitRefused(restarted.deployed.remoteUris[0]!)).toBe("refused");
    expect(() => process.kill(restarted.pid, 0)).toThrow();
    expect(warningCount).toBe(1);
  }).pipe(Effect.provide(Logger.layer([logger])));
},
  { timeout: 30_000 },
);

for (const [name, options] of [
  ["dialog without approval", { dialog: {} }],
  ["remember without approval", { rememberApprovalSeconds: 60 }],
  ["dialog with approval none", { approval: "none", dialog: {} }],
  ["remember with approval none", { approval: "none", rememberApprovalSeconds: 60 }],
] satisfies ReadonlyArray<readonly [string, SopsKeyServiceProps]>) {
  keyServiceTest.provider(`rejects ${name}`, (stack) => Effect.gen(function* () {
    const { props } = yield* fixture;
    const result = yield* stack.deploy(SopsKeyService("KeyService", { ...props, ...options })).pipe(
      Effect.match({
        onFailure: (error) => ({ failed: true, message: error instanceof Error ? error.message : "" }),
        onSuccess: () => ({ failed: false, message: "" }),
      }),
    );
    yield* stack.destroy();
    expect(result.failed).toBe(true);
    expect(result.message).toContain('require approval: "dialog"');
  }));
}

let cacheDecryptCalls = 0;
const { test: cacheTest } = Test.make({
  providers: SopsFileProvider({
    decrypt: () => Effect.sync(() => {
      cacheDecryptCalls += 1;
      return '{"fixture":"value"}';
    }),
  }),
});

cacheTest.provider("SopsFile ignores URI changes but preserves local-keyservice policy", (stack) =>
  Effect.gen(function* () {
    const program = (uri: string, enableLocalKeyService = false) => SopsFile("Secrets", {
      content: JSON.stringify(encrypted),
      format: "json",
      keyServices: [uri],
      enableLocalKeyService,
    });
    const before = cacheDecryptCalls;
    const created = yield* stack.deploy(program("tcp://127.0.0.1:5001"));
    const next = program("tcp://127.0.0.1:5002");
    const plan = yield* stack.plan(next);
    const updated = yield* stack.deploy(next);
    expect(cacheDecryptCalls - before).toBe(1);
    expect(updated.sourceHash).toBe(created.sourceHash);
    expect(Object.values(plan.resources).map((resource) => resource.action)).toEqual(["noop"]);
    const changed = yield* stack.deploy(program("tcp://127.0.0.1:5002", true));
    expect(cacheDecryptCalls - before).toBe(2);
    expect(changed.sourceHash).not.toBe(created.sourceHash);
    yield* stack.destroy();
  }),
);
