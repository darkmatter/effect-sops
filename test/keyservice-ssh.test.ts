import { describe, expect, test } from "bun:test";
import * as net from "node:net";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as BunServices from "@effect/platform-bun/BunServices";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Schedule from "effect/Schedule";
import type * as Scope from "effect/Scope";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  localForward,
  localForwardArgs,
  remoteForward,
  remoteForwardArgs,
} from "../src/keyservice/ssh.ts";
import type { SshTunnel } from "../src/keyservice/model.ts";

const fake = join(import.meta.dir, "fixtures/ssh/ssh-fake");
const defaults = [
  "-N",
  "-T",
  "-o",
  "ExitOnForwardFailure=yes",
  "-o",
  "ServerAliveInterval=15",
  "-o",
  "ServerAliveCountMax=3",
  "-o",
  "BatchMode=yes",
  "-o",
  "ConnectTimeout=10",
  "-o",
  "ControlMaster=no",
  "-o",
  "ControlPath=none",
];
const options = {
  destination: "test-host",
  ssh: fake,
  readyTimeout: "3 seconds",
} as const;
const target = { _tag: "Tcp", host: "127.0.0.1", port: 5000 } as const;
const run = <A, E>(
  effect: Effect.Effect<A, E, Scope.Scope | ChildProcessSpawner>,
) =>
  Effect.runPromise(
    effect.pipe(Effect.scoped, Effect.provide(BunServices.layer)),
  );

async function mode<A>(value: string, work: () => Promise<A>): Promise<A> {
  const previous = process.env.FAKE_SSH_MODE;
  process.env.FAKE_SSH_MODE = value;
  try {
    return await work();
  } finally {
    if (previous === undefined) delete process.env.FAKE_SSH_MODE;
    else process.env.FAKE_SSH_MODE = previous;
  }
}

async function echo(path?: string) {
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("error", () => socket.destroy());
    socket.pipe(socket);
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    if (path) server.listen(path, resolve);
    else server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  return {
    port: address && typeof address !== "string" ? address.port : 0,
    close: () =>
      new Promise<void>((resolve, reject) => {
        for (const socket of sockets) socket.destroy();
        server.close((cause) => (cause ? reject(cause) : resolve()));
      }),
  };
}

const roundtrip = (port: number, host = "127.0.0.1") =>
  Effect.tryPromise(
    () =>
      new Promise<string>((resolve, reject) => {
        const socket = net.createConnection({ host, port });
        socket.once("connect", () => socket.write("keyservice forwarding"));
        socket.once("data", (value) => {
          socket.destroy();
          resolve(value.toString());
        });
        socket.once("error", reject);
        socket.setTimeout(2000, () => {
          socket.destroy();
          reject(new Error("echo timeout"));
        });
      }),
  );

const assertExited = (pid: number) => {
  expect(() => process.kill(pid, 0)).toThrow();
};

describe("SSH argument builders", () => {
  test("user overrides precede defaults, then forward and destination separator", () => {
    expect(
      localForwardArgs(
        { destination: "alice@host", sshArgs: ["-o", "BatchMode=no"] },
        1234,
      ),
    ).toEqual([
      "-o",
      "BatchMode=no",
      ...defaults,
      "-v",
      "-L",
      "127.0.0.1:1234:127.0.0.1:5000",
      "--",
      "alice@host",
    ]);
    expect(
      remoteForwardArgs({
        destination: "host",
        target,
        sshArgs: ["-p", "2222"],
      }),
    ).toEqual([
      "-p",
      "2222",
      ...defaults,
      "-v",
      "-R",
      "127.0.0.1:5000:127.0.0.1:5000",
      "--",
      "host",
    ]);
  });
  test("brackets IPv6 addresses and preserves Unix socket targets", () => {
    expect(
      localForwardArgs(
        {
          destination: "host",
          localHost: "::1",
          remoteHost: "2001:db8::1",
          remotePort: 42,
        },
        1234,
      ),
    ).toContain("[::1]:1234:[2001:db8::1]:42");
    expect(
      remoteForwardArgs({
        destination: "host",
        remoteHost: "::1",
        remotePort: 0,
        target: { _tag: "Tcp", host: "::1", port: 42 },
      }),
    ).toContain("[::1]:0:[::1]:42");
    expect(
      remoteForwardArgs({
        destination: "host",
        target: { _tag: "Unix", path: "/tmp/key service.sock" },
      }),
    ).toContain("127.0.0.1:5000:/tmp/key service.sock");
  });
  test("rejects malformed ports and hosts in pure builders", () => {
    for (const port of [-1, 65536, 0.1, NaN, Infinity]) {
      expect(() => localForwardArgs({ destination: "host" }, port)).toThrow();
      expect(() =>
        remoteForwardArgs({ destination: "host", remotePort: port, target }),
      ).toThrow();
    }
    expect(() =>
      localForwardArgs({ destination: "host", remoteHost: "bad:host" }, 42),
    ).toThrow();
    expect(() =>
      remoteForwardArgs({
        destination: "host",
        target: { _tag: "Unix", path: "relative.sock" },
      }),
    ).toThrow();
  });
});

describe("SSH forwards", () => {
  test("busy explicit local ports fail before spawning SSH", async () => {
    const server = await echo();
    const dir = await mkdtemp(join(tmpdir(), "ssh-busy-explicit-"));
    const pidFile = join(dir, "pid");
    try {
      const failure = await run(
        Effect.flip(
          localForward({
            ...options,
            localPort: server.port,
            sshArgs: ["-o", `FakePidFile=${pidFile}`],
          }),
        ),
      );
      expect(failure.reason).toBe("ForwardFailed");
      expect(failure.message).toBe(`local port ${server.port} is already in use`);
      expect(existsSync(pidFile)).toBe(false);
    } finally {
      await server.close();
      await rm(dir, { recursive: true });
    }
  });
  test("local SSH bind rejection includes its diagnostics", async () => {
    await mode("busy", async () => {
      const failure = await run(Effect.flip(localForward(options)));
      expect(failure.reason).toBe("ForwardFailed");
      expect(failure.stderr).toContain("Address already in use");
      expect(failure.stderr).toContain("Could not request local forwarding");
    });
  });
  test("a foreign listener taking the auto-selected port never becomes a tunnel or receives probes", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-busy-race-"));
    const pidFile = join(dir, "pid");
    const connectionsFile = join(dir, "connections");
    try {
      await mode("busy", () =>
        run(
          Effect.gen(function* () {
            const failure = yield* Effect.flip(
              localForward({
                ...options,
                sshArgs: [
                  "-o",
                  `FakePidFile=${pidFile}`,
                  "-o",
                  `FakeConnectionsFile=${connectionsFile}`,
                ],
              }),
            );
            expect(failure.reason).toBe("ForwardFailed");
            const connections = yield* Effect.promise(() =>
              readFile(connectionsFile, "utf8"),
            );
            expect(Number(connections)).toBe(0);
            const pid = yield* Effect.promise(() => readFile(pidFile, "utf8"));
            assertExited(Number(pid));
          }),
        ),
      );
    } finally {
      await rm(dir, { recursive: true });
    }
  });
  test("a local listening diagnostic alone never marks a tunnel ready", async () => {
    await mode("listening-only", async () => {
      const failure = await run(
        Effect.flip(
          localForward({ ...options, readyTimeout: "250 millis" }),
        ),
      );
      expect(failure.reason).toBe("TimedOut");
      expect(failure.stderr).toContain("Local forwarding listening on");
    });
  });
  test("a jump session becomes ready only when the final forward accepts connections", async () => {
    const server = await echo();
    try {
      await mode("jump", () =>
        run(
          Effect.gen(function* () {
            const tunnel = yield* localForward({
              ...options,
              remotePort: server.port,
            });
            expect(yield* roundtrip(tunnel.bindPort)).toBe(
              "keyservice forwarding",
            );
          }),
        ),
      );
    } finally {
      await server.close();
    }
  });
  test("a jump session without the final listener times out", async () => {
    await mode("jump-only", async () => {
      const failure = await run(
        Effect.flip(localForward({ ...options, readyTimeout: "250 millis" })),
      );
      expect(failure.reason).toBe("TimedOut");
      expect(failure.stderr).toContain("Entering interactive session");
    });
  });
  test("listening diagnostics for another host or port do not establish readiness", async () => {
    for (const value of ["wrong-host", "wrong-port"])
      await mode(value, async () => {
        const failure = await run(
          Effect.flip(localForward({ ...options, readyTimeout: "250 millis" })),
        );
        expect(failure.reason).toBe("TimedOut");
        expect(failure.stderr).toContain("Local forwarding listening on");
        expect(failure.stderr).toContain("Entering interactive session");
      });
  });
  test("IPv6 listening diagnostics accept either bracket style", async () => {
    const server = await echo();
    try {
      for (const value of ["normal", "bracketed"])
        await mode(value, () =>
          run(
            Effect.gen(function* () {
              const tunnel = yield* localForward({
                ...options,
                localHost: "::1",
                remotePort: server.port,
              });
              expect(yield* roundtrip(tunnel.bindPort, tunnel.bindHost)).toBe(
                "keyservice forwarding",
              );
            }),
          ),
        );
    } finally {
      await server.close();
    }
  });
  test("local readiness diagnostics may span chunks", async () => {
    await mode("split", () =>
      run(
        Effect.gen(function* () {
          const tunnel = yield* localForward(options);
          expect(tunnel.bindPort).toBeGreaterThan(0);
        }),
      ),
    );
  });
  test("validates destinations and ports before spawning", async () => {
    for (const destination of [
      "",
      "-oProxyCommand=bad",
      "host name",
      "host\nname",
      "host\u0080",
    ]) {
      expect(
        (await run(Effect.flip(localForward({ ...options, destination }))))
          .reason,
      ).toBe("InvalidOptions");
      expect(
        (
          await run(
            Effect.flip(remoteForward({ ...options, destination, target })),
          )
        ).reason,
      ).toBe("InvalidOptions");
    }
    expect(
      (await run(Effect.flip(localForward({ ...options, localPort: -1 }))))
        .reason,
    ).toBe("InvalidOptions");
    expect(
      (
        await run(
          Effect.flip(
            remoteForward({ ...options, target: { ...target, port: 65536 } }),
          ),
        )
      ).reason,
    ).toBe("InvalidOptions");
  });
  test("local ephemeral forwarding round-trips data, then scope close completes awaitExit", async () => {
    const server = await echo();
    let tunnel: SshTunnel | undefined;
    try {
      await run(
        Effect.gen(function* () {
          tunnel = yield* localForward({ ...options, remotePort: server.port });
          expect(tunnel.direction).toBe("local");
          expect(tunnel.bindPort).toBeGreaterThan(0);
          expect(tunnel.uri).toBe(`tcp://127.0.0.1:${tunnel.bindPort}`);
          expect(yield* roundtrip(tunnel.bindPort)).toBe(
            "keyservice forwarding",
          );
        }),
      );
      expect(tunnel).toBeDefined();
      if (tunnel)
        await Effect.runPromise(
          tunnel.awaitExit.pipe(Effect.timeout("1 second")),
        );
    } finally {
      await server.close();
    }
  });
  test("remote dynamic forwarding becomes ready and round-trips data", async () => {
    const server = await echo();
    try {
      await run(
        Effect.gen(function* () {
          const tunnel = yield* remoteForward({
            ...options,
            remotePort: 0,
            target: { ...target, port: server.port },
          });
          expect(tunnel.direction).toBe("remote");
          expect(tunnel.uri).toBe(`tcp://127.0.0.1:${tunnel.bindPort}`);
          expect(tunnel.bindPort).toBeGreaterThan(0);
          expect(yield* roundtrip(tunnel.bindPort)).toBe(
            "keyservice forwarding",
          );
        }),
      );
    } finally {
      await server.close();
    }
  });
  test("remote allocation may follow success, and readiness lines may span chunks", async () => {
    for (const value of ["allocation-after", "split"])
      await mode(value, () =>
        run(
          Effect.gen(function* () {
            const tunnel = yield* remoteForward({
              ...options,
              remotePort: 0,
              target,
            });
            expect(tunnel.bindPort).toBeGreaterThan(0);
          }),
        ),
      );
  });
  test("remote Unix targets work end to end", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-unix-"));
    const path = join(dir, "echo.sock");
    const server = await echo(path);
    try {
      await run(
        Effect.gen(function* () {
          const tunnel = yield* remoteForward({
            ...options,
            remotePort: 0,
            target: { _tag: "Unix", path },
          });
          expect(yield* roundtrip(tunnel.bindPort)).toBe(
            "keyservice forwarding",
          );
        }),
      );
    } finally {
      await server.close();
      await rm(dir, { recursive: true });
    }
  });
  test("early exit includes stderr and keeps diagnostics bounded", async () => {
    for (const value of ["fail", "noisy-fail"])
      await mode(value, async () => {
        for (const operation of [
          localForward(options),
          remoteForward({ ...options, target }),
        ]) {
          const failure = await run(Effect.flip(operation));
          expect(failure.reason).toBe("Exited");
          expect(failure.stderr).toContain("Permission denied (publickey).");
          expect(failure.stderr?.length).toBeLessThanOrEqual(8192);
        }
      });
  });
  test("remote forwarding rejection releases its process before returning the error", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-rejected-"));
    const pidFile = join(dir, "pid");
    try {
      await mode("forward-fail", () =>
        run(
          Effect.gen(function* () {
            const failure = yield* Effect.flip(
              remoteForward({
                ...options,
                remotePort: 0,
                target,
                sshArgs: ["-o", `FakePidFile=${pidFile}`],
              }),
            );
            expect(failure.reason).toBe("ForwardFailed");
            const pid = yield* Effect.promise(() => readFile(pidFile, "utf8"));
            assertExited(Number(pid));
          }),
        ),
      );
    } finally {
      await rm(dir, { recursive: true });
    }
  });
  test("timeouts release children while the calling scope remains open", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-timeout-"));
    const pidFile = join(dir, "pid");
    try {
      await mode("timeout", async () => {
        for (const operation of [
          localForward({
            ...options,
            readyTimeout: "250 millis",
            sshArgs: ["-o", `FakePidFile=${pidFile}`],
          }),
          remoteForward({
            ...options,
            target,
            readyTimeout: "250 millis",
            sshArgs: ["-o", `FakePidFile=${pidFile}`],
          }),
        ]) {
          await run(
            Effect.gen(function* () {
              expect((yield* Effect.flip(operation)).reason).toBe("TimedOut");
              const pid = yield* Effect.promise(() =>
                readFile(pidFile, "utf8"),
              );
              assertExited(Number(pid));
            }),
          );
        }
      });
    } finally {
      await rm(dir, { recursive: true });
    }
  });
  test("startup interruption releases its child", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-interrupt-"));
    const pidFile = join(dir, "pid");
    try {
      await mode("timeout", () =>
        run(
          Effect.gen(function* () {
            const fiber = yield* Effect.forkScoped(
              localForward({
                ...options,
                sshArgs: ["-o", `FakePidFile=${pidFile}`],
              }),
            );
            const pid = yield* Effect.tryPromise(() =>
              readFile(pidFile, "utf8"),
            ).pipe(
              Effect.retry({
                times: 20,
                schedule: Schedule.spaced("20 millis"),
              }),
            );
            yield* Fiber.interrupt(fiber);
            assertExited(Number(pid));
          }),
        ),
      );
    } finally {
      await rm(dir, { recursive: true });
    }
  });
  test("continues draining noisy stderr after readiness", async () => {
    // After readiness the fake writes ~4 MiB to stderr and then exits, which
    // it can only do while the tunnel keeps draining the pipe.
    const exited = await mode("noisy", () =>
      run(
        Effect.gen(function* () {
          const tunnel = yield* remoteForward({
            ...options,
            remotePort: 0,
            target,
          });
          return yield* tunnel.awaitExit.pipe(
            Effect.as(true),
            Effect.timeoutOrElse({
              duration: "3 seconds",
              orElse: () => Effect.succeed(false),
            }),
          );
        }),
      ),
    );
    expect(exited).toBe(true);
  });
  test("recognizes the alternate remote forwarding failure warning", async () => {
    await mode("forward-warning", async () => {
      expect(
        (
          await run(
            Effect.flip(remoteForward({ ...options, target, remotePort: 0 })),
          )
        ).reason,
      ).toBe("ForwardFailed");
    });
  });
  test("forces termination when the child ignores SIGTERM", async () => {
    const dir = await mkdtemp(join(tmpdir(), "ssh-force-kill-"));
    const pidFile = join(dir, "pid");
    try {
      await mode("ignore-term", () =>
        run(
          Effect.gen(function* () {
            const failure = yield* Effect.flip(
              localForward({
                ...options,
                readyTimeout: "250 millis",
                sshArgs: ["-o", `FakePidFile=${pidFile}`],
              }),
            );
            expect(failure.reason).toBe("TimedOut");
            const pid = yield* Effect.promise(() => readFile(pidFile, "utf8"));
            assertExited(Number(pid));
          }),
        ),
      );
    } finally {
      await rm(dir, { recursive: true });
    }
  });
  test("missing SSH executable fails with SpawnFailed", async () => {
    expect(
      (
        await run(
          Effect.flip(localForward({ ...options, ssh: "/nonexistent/ssh" })),
        )
      ).reason,
    ).toBe("SpawnFailed");
  });
  test.skipIf(process.env.EFFECT_SOPS_SSH_SMOKE !== "1")(
    "real localhost SSH round-trips data",
    async () => {
      const server = await echo();
      try {
        await run(
          Effect.gen(function* () {
            const tunnel = yield* localForward({
              destination: "localhost",
              remotePort: server.port,
            });
            expect(yield* roundtrip(tunnel.bindPort)).toBe(
              "keyservice forwarding",
            );
          }),
        );
      } finally {
        await server.close();
      }
    },
    20000,
  );
});
