import { expect, test } from "bun:test";
import {
  lstat,
  mkdtemp,
  readFile,
  rm,
  unlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as BunServices from "@effect/platform-bun/BunServices";
import { generateIdentity } from "age-encryption";
import * as Effect from "effect/Effect";
import * as Logger from "effect/Logger";
import type * as Scope from "effect/Scope";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import * as Interaction from "../src/keyservice/interaction.ts";
import * as Listen from "../src/keyservice/listen.ts";
import { serve, Ssh } from "../src/KeyService.ts";
import { runSopsAge } from "../src/sops-age.ts";
import encrypted from "./fixtures/native.enc.json" with { type: "json" };

// Public identity used only for the checked-in encrypted fixture.
const identity =
  "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
const age = { identities: [identity] };
const fixture = join(import.meta.dir, "fixtures/native.enc.json");
const fakeSsh = join(import.meta.dir, "fixtures/ssh/ssh-fake");
const sops = Bun.which("sops");
const sopsAvailable = sops !== null;
const expected = {
  api: { token: "native-token", enabled: true },
  nested: { count: 3 },
};
const run = <A, E>(
  effect: Effect.Effect<A, E, Scope.Scope | ChildProcessSpawner>,
) =>
  Effect.runPromise(
    effect.pipe(Effect.scoped, Effect.provide(BunServices.layer)),
  );
const temporaryDirectory = Effect.acquireRelease(
  Effect.promise(() => mkdtemp(join(tmpdir(), "ks-e2e-"))),
  (directory) =>
    Effect.promise(() => rm(directory, { recursive: true, force: true })),
);

// Replace the inherited environment entirely: even a future discovery fallback
// in the Go client must not reach workstation keys or configuration.
const cli = Effect.fn("Test.sops")(function* (args: ReadonlyArray<string>) {
  const directory = yield* temporaryDirectory;
  const spawner = yield* ChildProcessSpawner;
  const child = yield* spawner.spawn(
    ChildProcess.make(sops ?? "sops", args, {
      env: {
        PATH: process.env.PATH,
        HOME: directory,
        XDG_CONFIG_HOME: directory,
      },
      extendEnv: false,
      cwd: directory,
      stdin: "ignore",
      stdout: "pipe",
      stderr: "pipe",
    }),
  );
  const [stdout, stderr, code] = yield* Effect.all(
    [
      child.stdout.pipe(Stream.decodeText(), Stream.mkString),
      child.stderr.pipe(Stream.decodeText(), Stream.mkString),
      child.exitCode,
    ] as const,
    { concurrency: "unbounded" },
  );
  return { stdout, stderr, code };
});
const decryptArgs = (uri: string, path = fixture) => [
  "decrypt",
  "--enable-local-keyservice=false",
  "--keyservice",
  uri,
  path,
];
const nativeDecrypt = (uri: string) =>
  runSopsAge({
    binary: "/unused-native-backend",
    content: JSON.stringify(encrypted),
    inputType: "json",
    outputType: "json",
    keyServices: [uri],
    enableLocalKeyService: false,
    timeoutMs: 3000,
  });

test.skipIf(!sopsAvailable)(
  "Go SOPS decrypts through the scoped TCP keyservice",
  () =>
    run(
      Effect.gen(function* () {
        const server = yield* serve({ listen: Listen.loopback(0), age });
        const result = yield* cli(decryptArgs(server.uri));
        expect(Number(result.code)).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual(expected);
      }),
    ),
);

test.skipIf(!sopsAvailable)(
  "Go SOPS encrypts and decrypts through the keyservice",
  () =>
    run(
      Effect.gen(function* () {
        const server = yield* serve({ listen: Listen.loopback(0), age });
        const directory = yield* temporaryDirectory;
        const input = join(directory, "plain.json");
        const output = join(directory, "encrypted.json");
        yield* Effect.promise(() => writeFile(input, JSON.stringify(expected)));
        const result = yield* cli([
          "encrypt",
          "--enable-local-keyservice=false",
          "--keyservice",
          server.uri,
          "--age",
          encrypted.sops.age[0]!.recipient,
          "--input-type",
          "json",
          "--output-type",
          "json",
          input,
        ]);
        expect(Number(result.code)).toBe(0);
        yield* Effect.promise(() => writeFile(output, result.stdout));
        const plaintext = yield* cli(decryptArgs(server.uri, output));
        expect(Number(plaintext.code)).toBe(0);
        expect(JSON.parse(plaintext.stdout)).toEqual(expected);
      }),
    ),
);

test.skipIf(!sopsAvailable)("Go SOPS reports denied approval", () =>
  run(
    Effect.gen(function* () {
      const server = yield* serve({
        listen: Listen.loopback(0),
        age,
        interaction: Interaction.make({ approve: () => false }),
      });
      const result = yield* cli(decryptArgs(server.uri));
      expect(Number(result.code)).not.toBe(0);
      // SOPS wraps errors with newline-prefixed tree bars, even inside a phrase.
      expect(
        result.stderr
          .replace(/\n\s*\|/g, " ")
          .replace(/\s+/g, " ")
          .includes("Request rejected by user"),
      ).toBe(true);
    }),
  ),
);

test.skipIf(!sopsAvailable)("Go SOPS decrypts through a Unix listener", () =>
  run(
    Effect.gen(function* () {
      const directory = yield* temporaryDirectory;
      const server = yield* serve({
        listen: Listen.unix(join(directory, "s.sock")),
        age,
      });
      expect(server.uri.startsWith("unix:///")).toBe(true);
      const result = yield* cli(decryptArgs(server.uri));
      expect(Number(result.code)).toBe(0);
      expect(JSON.parse(result.stdout)).toEqual(expected);
    }),
  ),
);

test.skipIf(!sopsAvailable)(
  "An unknown recipient fails before asking for approval",
  () =>
    run(
      Effect.gen(function* () {
        let approvals = 0;
        const other = yield* Effect.promise(generateIdentity);
        const server = yield* serve({
          listen: Listen.loopback(0),
          age: { identities: [other] },
          interaction: Interaction.make({
            approve: () => {
              approvals++;
              return true;
            },
          }),
        });
        const result = yield* cli(decryptArgs(server.uri));
        expect(Number(result.code)).not.toBe(0);
        expect(approvals).toBe(0);
      }),
    ),
);

test("serve returns listeners in order and remote forwarding prefers TCP", () =>
  run(
    Effect.gen(function* () {
      const directory = yield* temporaryDirectory;
      const socket = join(directory, "s.sock");
      const server = yield* serve({
        listen: [Listen.unix(socket), Listen.loopback(0)],
        age,
        remoteForwards: [
          { destination: "test-host", ssh: fakeSsh, remotePort: 0 },
        ],
      });
      expect(server.uri).toBe(`unix://${socket}`);
      expect(server.uris.length).toBe(2);
      expect(server.addresses[1]?.address._tag).toBe("Tcp");
      expect(server.tunnels.length).toBe(1);
      // Removing the Unix endpoint proves the forward selected the later TCP one.
      yield* Effect.promise(() => unlink(socket));
      const plaintext = yield* nativeDecrypt(server.tunnels[0]!.uri);
      expect(JSON.parse(plaintext)).toEqual(expected);
    }),
  ));

test("remote forwarding falls back to the Unix listener", () =>
  run(
    Effect.gen(function* () {
      const directory = yield* temporaryDirectory;
      const server = yield* serve({
        listen: Listen.unix(join(directory, "s.sock")),
        age,
        remoteForwards: [
          { destination: "test-host", ssh: fakeSsh, remotePort: 0 },
        ],
      });
      const plaintext = yield* nativeDecrypt(server.tunnels[0]!.uri);
      expect(JSON.parse(plaintext)).toEqual(expected);
    }),
  ));

test("Ssh.localForward opens a usable local forward", () =>
  run(
    Effect.gen(function* () {
      const server = yield* serve({ listen: Listen.loopback(0), age });
      const address = server.addresses[0]!.address;
      if (address._tag !== "Tcp") throw new Error("Expected TCP listener");
      const tunnel = yield* Ssh.localForward({
        destination: "test-host",
        ssh: fakeSsh,
        remotePort: address.port,
      });
      expect(JSON.parse(yield* nativeDecrypt(tunnel.uri))).toEqual(expected);
    }),
  ));

test("remote forwarding honors an explicit target", () =>
  run(
    Effect.gen(function* () {
      const target = yield* serve({ listen: Listen.loopback(0), age });
      const server = yield* serve({
        listen: Listen.loopback(0),
        age: { identities: [] },
        remoteForwards: [
          {
            destination: "test-host",
            ssh: fakeSsh,
            remotePort: 0,
            target: target.addresses[0]!.address,
          },
        ],
      });
      expect(JSON.parse(yield* nativeDecrypt(server.tunnels[0]!.uri))).toEqual(
        expected,
      );
    }),
  ));

test("failed startup closes the listener and earlier tunnels before returning", () =>
  run(
    Effect.gen(function* () {
      const directory = yield* temporaryDirectory;
      const socket = join(directory, "s.sock");
      const pidFile = join(directory, "ssh.pid");
      const error = yield* serve({
        listen: Listen.unix(socket),
        age,
        remoteForwards: [
          {
            destination: "test-host",
            ssh: fakeSsh,
            sshArgs: ["-o", `FakePidFile=${pidFile}`],
            remotePort: 0,
          },
          { destination: "-invalid-destination", ssh: fakeSsh, remotePort: 0 },
        ],
      }).pipe(Effect.flip);
      expect(error._tag).toBe("SshTunnelError");
      const exists = yield* Effect.promise(() =>
        lstat(socket).then(
          () => true,
          (cause: unknown) => {
            if (
              cause instanceof Error &&
              "code" in cause &&
              cause.code === "ENOENT"
            )
              return false;
            throw cause;
          },
        ),
      );
      expect(exists).toBe(false);
      const pid = Number(
        yield* Effect.promise(() => readFile(pidFile, "utf8")),
      );
      expect(() => process.kill(pid, 0)).toThrow();
    }),
  ));

test("an empty listener list fails with InvalidAddress", () =>
  run(
    Effect.gen(function* () {
      const error = yield* serve({ listen: [], age }).pipe(Effect.flip);
      expect(error.reason).toBe("InvalidAddress");
    }),
  ));

test("serve logs bound URIs and warns only for unapproved network listeners", async () => {
  const logs: Array<{ level: string; message: string }> = [];
  const logger = Logger.make<unknown, void>(({ logLevel, message }) => {
    logs.push({ level: logLevel, message: JSON.stringify(message) });
  });
  await run(
    Effect.gen(function* () {
      const local = yield* serve({ listen: Listen.loopback(0), age });
      expect(logs.some(({ message }) => message.includes(local.uri))).toBe(
        true,
      );
      expect(logs.filter(({ level }) => level === "Warn").length).toBe(0);
      yield* serve({ listen: Listen.tcp("0.0.0.0", 0), age });
      const warnings = logs.filter(({ level }) => level === "Warn");
      expect(warnings.length).toBe(1);
      expect(warnings[0]?.message.includes("Interaction.terminal()")).toBe(
        true,
      );
      expect(warnings[0]?.message.includes("Interaction.dialog()")).toBe(true);
      yield* serve({
        listen: Listen.tcp("0.0.0.0", 0),
        age,
        interaction: Interaction.make({ approve: () => false }),
      });
      expect(logs.filter(({ level }) => level === "Warn").length).toBe(1);
    }).pipe(Effect.provideService(Logger.CurrentLoggers, new Set([logger]))),
  );
});

test("automatic callback defaults warn for network listeners and remote forwards", async () => {
  const warnings: Array<string> = [];
  const logger = Logger.make<unknown, void>(({ logLevel, message }) => {
    if (logLevel === "Warn") warnings.push(JSON.stringify(message));
  });
  await run(
    Effect.gen(function* () {
      yield* serve({
        listen: Listen.tcp("0.0.0.0", 0),
        age,
        interaction: Interaction.make({ displayMessage: () => undefined }),
      });
      expect(warnings.length).toBe(1);
      yield* serve({
        listen: Listen.loopback(0),
        age,
        remoteForwards: [{ destination: "fixture", ssh: fakeSsh, remotePort: 0 }],
      });
      expect(warnings.length).toBe(2);
    }).pipe(Effect.provideService(Logger.CurrentLoggers, new Set([logger]))),
  );
  expect(warnings.length).toBe(2);
});

test.skipIf(!sopsAvailable || process.env.EFFECT_SOPS_SSH_SMOKE !== "1")(
  "Go SOPS decrypts through real localhost SSH forwards",
  () =>
    run(
      Effect.gen(function* () {
        const server = yield* serve({
          listen: Listen.loopback(0),
          age,
          remoteForwards: [{ destination: "localhost", remotePort: 0 }],
        });
        const address = server.addresses[0]!.address;
        if (address._tag !== "Tcp") throw new Error("Expected TCP listener");
        const local = yield* Ssh.localForward({
          destination: "localhost",
          remotePort: address.port,
        });
        for (const uri of [local.uri, server.tunnels[0]!.uri]) {
          const result = yield* cli(decryptArgs(uri));
          expect(Number(result.code)).toBe(0);
          expect(JSON.parse(result.stdout)).toEqual(expected);
        }
      }),
    ),
  30000,
);

test.skipIf(!sopsAvailable || process.env.EFFECT_SOPS_TAILSCALE_SMOKE !== "1")(
  "Go SOPS decrypts through the Tailscale address",
  () =>
    run(
      Effect.gen(function* () {
        const server = yield* serve({ listen: Listen.tailscale(0), age });
        expect(server.uri.startsWith("tcp://100.")).toBe(true);
        const result = yield* cli(decryptArgs(server.uri));
        expect(Number(result.code)).toBe(0);
        expect(JSON.parse(result.stdout)).toEqual(expected);
      }),
    ),
  30000,
);
