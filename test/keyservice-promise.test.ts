import { describe, expect, test } from "bun:test";
import * as net from "node:net";
import { lstat, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as BunServices from "@effect/platform-bun/BunServices";
import * as NodeServices from "@effect/platform-node/NodeServices";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Logger from "effect/Logger";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  Interaction,
  KeyServiceListenError,
  Listen,
  openKeyServiceTunnel,
  runKeyService,
  startKeyService,
} from "../src/KeyService.ts";
import { runSopsAge } from "../src/sops-age.ts";
import encrypted from "./fixtures/native.enc.json" with { type: "json" };

const identity = "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
const base = {
  address: "127.0.0.1:0",
  age: { identities: [identity] },
  logRequests: false,
} as const;
const fakeSsh = join(import.meta.dir, "fixtures/ssh/ssh-fake");
const nodeBinary = Bun.which("node");
const decrypt = (uri: string) =>
  Effect.runPromise(
    runSopsAge({
      binary: "/no-sops-binary",
      content: JSON.stringify(encrypted),
      inputType: "json",
      outputType: "json",
      keyServices: [uri],
      enableLocalKeyService: false,
      timeoutMs: 2_000,
    }),
  );

const reachable = (port: number): Promise<boolean> =>
  new Promise((resolve) => {
    const socket = net.createConnection({ host: "127.0.0.1", port });
    const finish = (connected: boolean) => {
      socket.destroy();
      resolve(connected);
    };
    socket.once("connect", () => finish(true));
    socket.once("error", () => finish(false));
    socket.setTimeout(500, () => finish(false));
  });

const freePort = async (): Promise<number> => {
  const server = net.createServer();
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  if (!address || typeof address === "string") throw new Error("Missing test listener");
  return address.port;
};

const waitUntil = async (condition: () => boolean | Promise<boolean>) => {
  for (let attempt = 0; attempt < 100; attempt++) {
    if (await condition()) return;
    await Bun.sleep(10);
  }
  throw new Error("Timed out waiting for test readiness");
};

describe("keyservice Promise facade", () => {
  test("decrypts through the public entry and closes idempotently", async () => {
    const handle = await startKeyService(base);
    const port = Number(new URL(handle.uri).port);
    try {
      expect(JSON.parse(await decrypt(handle.uri))).toEqual({
        api: { token: "native-token", enabled: true },
        nested: { count: 3 },
      });
      expect(handle.uris).toEqual([handle.uri]);
      expect(await reachable(port)).toBe(true);
      expect(handle.tunnels).toHaveLength(0);
    } finally {
      const closing = handle.close();
      expect(handle.close()).toBe(closing);
      await closing;
      await handle.close();
    }
    expect(await reachable(port)).toBe(false);
  });

  test("await using releases the listener", async () => {
    let port = 0;
    {
      await using handle = await startKeyService(base);
      port = Number(new URL(handle.uri).port);
      expect(await reachable(port)).toBe(true);
    }
    expect(await reachable(port)).toBe(false);
  });

  test("rejects conflicting UIs and invalid addresses with clear messages", async () => {
    for (const options of [
      { prompt: true, dialog: true },
      { prompt: true, interaction: Interaction.none },
      { dialog: {}, interaction: { approve: () => true } },
    ])
      await expect(startKeyService({ ...base, ...options })).rejects.toThrow(
        "Choose only one of prompt, dialog, or interaction",
      );
    await expect(startKeyService({ ...base, address: "invalid" })).rejects.toBeInstanceOf(
      KeyServiceListenError,
    );
  });

  test("explicit listeners reject conflicting convenience options", async () => {
    for (const convenience of [
      { address: "127.0.0.1:0" },
      { network: "tcp" as const },
      { tailscale: true },
      { tailscale: false },
    ])
      await expect(
        startKeyService({ age: base.age, listen: Listen.loopback(0), ...convenience }),
      ).rejects.toThrow("Choose listen or network, address, and tailscale");
  });

  test("explicit listeners serve each address", async () => {
    await using handle = await startKeyService({
      age: base.age,
      listen: [Listen.loopback(0), Listen.loopback(0)],
    });
    expect(handle.addresses).toHaveLength(2);
    for (const uri of handle.uris) expect(JSON.parse(await decrypt(uri)).nested.count).toBe(3);
  });

  test("network unix serves and removes its socket on close", async () => {
    const directory = await mkdtemp(join(tmpdir(), "promise-unix-"));
    const path = join(directory, "keyservice.sock");
    try {
      {
        await using handle = await startKeyService({ ...base, network: "unix", address: path });
        expect(handle.uri).toBe(`unix://${path}`);
        expect((await lstat(path)).isSocket()).toBe(true);
        expect(JSON.parse(await decrypt(handle.uri)).nested.count).toBe(3);
      }
      await expect(lstat(path)).rejects.toMatchObject({ code: "ENOENT" });
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("plain Promise callbacks and remembered approvals work", async () => {
    let approvals = 0;
    await using handle = await startKeyService({
      ...base,
      interaction: {
        approve: async () => {
          approvals++;
          return true;
        },
      },
      rememberApproval: "1 minute",
    });
    await decrypt(handle.uri);
    await decrypt(handle.uri);
    expect(approvals).toBe(1);
  });

  test("Effect callbacks can deny requests", async () => {
    await using handle = await startKeyService({
      ...base,
      interaction: { approve: () => Effect.succeed(false) },
    });
    await expect(decrypt(handle.uri)).rejects.toThrow("gRPC status 7");
  });

  test("maxPendingRequests limits waiting requests through the Promise facade", async () => {
    let approvals = 0;
    let release: ((approved: boolean) => void) | undefined;
    await using handle = await startKeyService({
      ...base,
      maxPendingRequests: 0,
      interaction: {
        approve: () => new Promise<boolean>((resolve) => {
          approvals++;
          release = resolve;
        }),
      },
    });
    const first = decrypt(handle.uri).then(() => true, () => false);
    try {
      await waitUntil(() => approvals === 1);
      await expect(decrypt(handle.uri)).rejects.toThrow("gRPC status 8");
      expect(approvals).toBe(1);
      release?.(true);
      expect(await first).toBe(true);
    } finally {
      release?.(false);
      await first;
    }
  });

  test("automatic custom interactions still warn with remembered approvals", async () => {
    const warnings: Array<string> = [];
    const logger = Logger.make<unknown, void>(({ logLevel, message }) => {
      if (logLevel === "Warn") warnings.push(JSON.stringify(message));
    });
    for (const interaction of [
      { displayMessage: () => undefined },
      Interaction.make({ displayMessage: () => undefined }),
      { ...Interaction.none },
    ]) {
      await using handle = await startKeyService({
        ...base,
        address: "0.0.0.0:0",
        interaction,
        rememberApproval: "1 minute",
        layer: Layer.merge(BunServices.layer, Logger.layer([logger])),
      });
      expect(handle.uris.length).toBe(1);
    }
    expect(warnings.length).toBe(3);
    expect(warnings.every((message) => message.includes("without approval"))).toBe(true);
  });

  test("supports an explicit Node platform layer", async () => {
    await using handle = await startKeyService({ ...base, layer: NodeServices.layer });
    expect(JSON.parse(await decrypt(handle.uri)).nested.count).toBe(3);
  });

  test.skipIf(!nodeBinary)("automatically loads Node services in the Node runtime", async () => {
    if (!nodeBinary) return;
    const build = await Bun.build({
      entrypoints: [join(import.meta.dir, "../src/KeyService.ts")],
      target: "node",
      format: "cjs",
      packages: "external",
    });
    expect(build.success).toBe(true);
    const bundle = build.outputs[0];
    if (!bundle) throw new Error("Missing Node smoke bundle");
    const code = `${await bundle.text()}
      (async () => {
        const handle = await module.exports.startKeyService({ address: "127.0.0.1:0", age: { discover: false } });
        if (!handle.uri.startsWith("tcp://127.0.0.1:")) throw new Error("Node listener unavailable");
        await handle.close();
        await handle.close();
        console.log("node-facade-ok");
      })().catch(() => { console.error("Node facade smoke failed"); process.exitCode = 1; });`;
    const result = await Effect.runPromise(
      Effect.gen(function* () {
        const spawner = yield* ChildProcessSpawner;
        const child = yield* spawner.spawn(
          ChildProcess.make(nodeBinary, ["--eval", code], {
            cwd: join(import.meta.dir, ".."),
            stdin: "ignore",
            stdout: "pipe",
            stderr: "ignore",
          }),
        );
        return yield* Effect.all(
          [child.exitCode, Stream.mkString(Stream.decodeText(child.stdout))],
          { concurrency: "unbounded" },
        );
      }).pipe(Effect.scoped, Effect.provide(BunServices.layer)),
    );
    expect(Number(result[0])).toBe(0);
    expect(result[1]).toContain("node-facade-ok");
  });

  test("failed startup releases already-bound listeners and platform resources", async () => {
    const port = await freePort();
    let released = 0;
    const layer = Layer.merge(
      BunServices.layer,
      Layer.effectDiscard(
        Effect.addFinalizer(() =>
          Effect.sync(() => {
            released++;
          }),
        ),
      ),
    );
    await expect(
      startKeyService({
        ...base,
        address: `127.0.0.1:${port}`,
        layer,
        ssh: { destination: "fixture", ssh: "/missing/ssh" },
      }),
    ).rejects.toThrow("Could not start the SSH executable");
    expect(await reachable(port)).toBe(false);
    expect(released).toBe(1);
  });

  test("platform construction failure rejects and disposes acquired resources", async () => {
    let released = false;
    const layer = Layer.merge(
      BunServices.layer,
      Layer.effectDiscard(
        Effect.gen(function* () {
          yield* Effect.addFinalizer(() =>
            Effect.sync(() => {
              released = true;
            }),
          );
          yield* Effect.die(new Error("test platform unavailable"));
        }),
      ),
    );
    await expect(startKeyService({ ...base, layer })).rejects.toThrow("test platform unavailable");
    expect(released).toBe(true);
  });

  test("run stops on abort and restores signal listeners", async () => {
    const port = await freePort();
    const controller = new AbortController();
    const before = [process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")];
    const running = runKeyService({
      ...base,
      address: `127.0.0.1:${port}`,
      signal: controller.signal,
    });
    try {
      await waitUntil(() => reachable(port));
    } finally {
      controller.abort();
      await running;
    }
    expect(await reachable(port)).toBe(false);
    expect([process.listenerCount("SIGINT"), process.listenerCount("SIGTERM")]).toEqual(before);
  });

  test("abort during platform startup disposes the partially built runtime", async () => {
    const controller = new AbortController();
    let started = false;
    let released = false;
    const layer = Layer.merge(
      BunServices.layer,
      Layer.effectDiscard(
        Effect.gen(function* () {
          yield* Effect.addFinalizer(() =>
            Effect.sync(() => {
              released = true;
            }),
          );
          started = true;
          yield* Effect.never;
        }),
      ),
    );
    const running = runKeyService({ ...base, layer, signal: controller.signal });
    try {
      await waitUntil(() => started);
    } finally {
      controller.abort();
      await running;
    }
    expect(released).toBe(true);
  });

  test("already-aborted run does not acquire platform services", async () => {
    const controller = new AbortController();
    controller.abort();
    let acquired = false;
    const layer = Layer.merge(
      BunServices.layer,
      Layer.effectDiscard(
        Effect.sync(() => {
          acquired = true;
        }),
      ),
    );
    await runKeyService({ ...base, layer, signal: controller.signal });
    expect(acquired).toBe(false);
  });

  test("SSH convenience forwards and tunnel handles decrypt and close", async () => {
    const handle = await startKeyService({
      ...base,
      ssh: [{ destination: "fixture", ssh: fakeSsh, remotePort: 0 }],
    });
    const remote = handle.tunnels[0];
    if (!remote) throw new Error("Missing remote forward");
    try {
      expect("awaitExit" in remote).toBe(false);
      expect(JSON.parse(await decrypt(remote.uri)).nested.count).toBe(3);
      const tunnel = await openKeyServiceTunnel({
        destination: "fixture",
        ssh: fakeSsh,
        remotePort: Number(new URL(handle.uri).port),
      });
      try {
        expect(JSON.parse(await decrypt(tunnel.uri)).nested.count).toBe(3);
      } finally {
        await Promise.all([tunnel.close(), tunnel.close()]);
      }
      await tunnel.exited;
      expect(await reachable(tunnel.bindPort)).toBe(false);
    } finally {
      await handle.close();
    }
    await remote.exited;
    expect(await reachable(remote.bindPort)).toBe(false);
  });

  test("each remote forward reports exit while normal service close stays quiet", async () => {
    const directory = await mkdtemp(join(tmpdir(), "promise-remote-exit-"));
    const warnings: Array<string> = [];
    const logger = Logger.make<unknown, void>(({ logLevel, message }) => {
      if (logLevel === "Warn") warnings.push(JSON.stringify(message));
    });
    try {
      const destinations = ["fixture-one", "fixture-two", "fixture-close"];
      const handle = await startKeyService({
        ...base,
        interaction: { approve: () => true },
        layer: Layer.merge(BunServices.layer, Logger.layer([logger])),
        ssh: destinations.map((destination) => ({
          destination,
          ssh: fakeSsh,
          remotePort: 0,
          sshArgs: ["-o", `FakePidFile=${join(directory, destination)}`],
        })),
      });
      try {
        for (const index of [0, 1]) {
          const tunnel = handle.tunnels[index];
          const destination = destinations[index];
          if (!tunnel || !destination) throw new Error("Missing remote forward");
          const pid = Number(await readFile(join(directory, destination), "utf8"));
          process.kill(pid, "SIGTERM");
          await tunnel.exited;
          await waitUntil(() => warnings.length === index + 1);
          expect(warnings[index]?.includes(destination)).toBe(true);
          expect(warnings[index]?.includes("remote forward exited")).toBe(true);
          expect(await reachable(tunnel.bindPort)).toBe(false);
          expect(JSON.parse(await decrypt(handle.uri)).nested.count).toBe(3);
        }
      } finally {
        await handle.close();
      }
      await Promise.all(handle.tunnels.map(({ exited }) => exited));
      expect(warnings.length).toBe(2);
      for (const tunnel of handle.tunnels) expect(await reachable(tunnel.bindPort)).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });

  test("tunnel exited observes process exit and async disposal remains safe", async () => {
    const directory = await mkdtemp(join(tmpdir(), "promise-tunnel-"));
    const pidFile = join(directory, "pid");
    try {
      await using service = await startKeyService(base);
      await using tunnel = await openKeyServiceTunnel({
        destination: "fixture",
        ssh: fakeSsh,
        sshArgs: ["-o", `FakePidFile=${pidFile}`],
        remotePort: Number(new URL(service.uri).port),
        layer: BunServices.layer,
      });
      const pid = Number(await readFile(pidFile, "utf8"));
      process.kill(pid, "SIGTERM");
      await tunnel.exited;
      expect(await reachable(tunnel.bindPort)).toBe(false);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
