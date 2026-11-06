import { describe, expect, test } from "bun:test";
import { Client, credentials, status, type MethodDefinition } from "@grpc/grpc-js";
import * as BunServices from "@effect/platform-bun/BunServices";
import { armor, Decrypter } from "age-encryption";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createConnection, createServer, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Logger from "effect/Logger";
import * as Redacted from "effect/Redacted";
import * as Scope from "effect/Scope";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import { keyServiceTarget, unwrapRemoteAgeKey } from "../src/keyservice-client.ts";
import {
  KeyServiceError,
  KeyServiceInteractionError,
  type KeyHandler,
  type KeyServiceErrorReason,
  type KeyServiceInteraction,
  type KeyServiceRequest,
  type KeyServiceServerOptions,
  type ResolvedListenAddress,
} from "../src/keyservice/model.ts";
import { keyServiceDefinition } from "../src/keyservice/protocol.ts";
import { makeServer } from "../src/keyservice/server.ts";

const age = { type: "age", recipient: "age1test-recipient" } as const;
const plaintext = () => new Uint8Array(32).fill(42);
const ciphertext = new Uint8Array([1, 2, 3]);
const tcp = { _tag: "Tcp", host: "127.0.0.1", port: 0 } as const;
const addresses = (...values: ReadonlyArray<ResolvedListenAddress>) =>
  values.map((address) => ({ requested: address, resolved: address }));
const keys: KeyHandler = {
  preflight: (_, key) =>
    key.type === "age"
      ? Effect.void
      : Effect.fail(
          new KeyServiceError({
            reason: "UnsupportedKey",
            message: "Unsupported key type",
          }),
        ),
  decrypt: () => Effect.sync(plaintext),
  encrypt: () => Effect.succeed(ciphertext),
};
const interaction = (
  approve: KeyServiceInteraction["approve"] = () => Effect.succeed(true),
): KeyServiceInteraction => ({
  approve,
  displayMessage: () => Effect.void,
  requestValue: () => Effect.succeed(Redacted.make("test-value")),
  confirm: () => Effect.succeed(true),
  waiting: () => Effect.void,
});

const start = async (
  options: Partial<KeyServiceServerOptions> = {},
  logger?: Logger.Logger<unknown, void>,
) => {
  const scope = Scope.makeUnsafe();
  const close = () => Effect.runPromise(Scope.close(scope, Exit.void));
  try {
    const program = makeServer({
      addresses: addresses(tcp),
      keys,
      interaction: interaction(),
      logRequests: false,
      ...options,
    }).pipe(Scope.provide(scope));
    const server = await Effect.runPromise(
      logger
        ? program.pipe(Effect.provideService(Logger.CurrentLoggers, new Set([logger])))
        : program,
    );
    return { ...server, close };
  } catch (cause) {
    await close();
    throw cause;
  }
};
const withServer = async (
  body: (uri: string) => Promise<void>,
  options: Partial<KeyServiceServerOptions> = {},
  logger?: Logger.Logger<unknown, void>,
) => {
  const server = await start(options, logger);
  try {
    const bound = server.addresses[0];
    if (!bound) throw new Error("Server did not bind an address");
    await body(bound.uri);
  } finally {
    await server.close();
  }
};
const rpc = <Request, Response>(
  uri: string,
  method: Pick<
    MethodDefinition<Request, Response>,
    "path" | "requestSerialize" | "responseDeserialize"
  >,
  request: Request,
  timeout = 2_000,
) => {
  const client = new Client(keyServiceTarget(uri), credentials.createInsecure());
  return new Promise<Response>((resolve, reject) => {
    client.makeUnaryRequest(
      method.path,
      method.requestSerialize,
      method.responseDeserialize,
      request,
      { deadline: Date.now() + timeout },
      (error, response) => {
        client.close();
        if (error) reject(error);
        else if (response === undefined) reject(new Error("Missing gRPC response"));
        else resolve(response);
      },
    );
  });
};
const decrypt = (uri: string, timeout?: number) =>
  rpc(uri, keyServiceDefinition.Decrypt, { key: age, ciphertext }, timeout);
const signal = () => {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
};
const temporary = async (body: (directory: string) => Promise<void>) => {
  // /tmp keeps Unix socket paths below macOS's 104-byte limit.
  const directory = await mkdtemp(
    join(process.platform === "darwin" ? "/tmp" : tmpdir(), "sops-server-"),
  );
  try {
    await body(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
};

describe("keyservice server requests", () => {
  test("serves the in-repo age client, records request metadata, and erases decrypted output", async () => {
    const seen: Array<KeyServiceRequest> = [];
    const output = plaintext();
    await withServer(
      async (uri) => {
        const actual = await Effect.runPromise(
          unwrapRemoteAgeKey(
            keyServiceTarget(uri),
            {
              recipient: "age1unsafe\nrecipient",
              enc: "test-ciphertext",
            },
            Date.now() + 2_000,
          ),
        );
        expect(actual).toEqual(plaintext());
        expect(output).toEqual(new Uint8Array(32));
        expect(seen[0]).toMatchObject({
          id: 1,
          operation: "decrypt",
          peerHost: "127.0.0.1",
          keyDescription: "age key with recipient age1unsafe?recipient",
        });
        expect(seen[0]?.receivedAt).toBeInstanceOf(Date);
        expect(seen[0]?.peer).toContain("127.0.0.1");
        await decrypt(uri);
        expect(seen.map((request) => request.id)).toEqual([1, 2]);
      },
      {
        keys: { ...keys, decrypt: () => Effect.succeed(output) },
        interaction: interaction((request) =>
          Effect.sync(() => {
            seen.push(request);
            return true;
          }),
        ),
      },
    );
  });

  test("denies requests with the upstream status and wording", async () => {
    let decrypted = false;
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({
          code: status.PERMISSION_DENIED,
          details: "Request rejected by user",
        });
        expect(decrypted).toBe(false);
      },
      {
        interaction: interaction(() => Effect.succeed(false)),
        keys: {
          ...keys,
          decrypt: () =>
            Effect.sync(() => {
              decrypted = true;
              return plaintext();
            }),
        },
      },
    );
  });

  test("missing and unsupported keys fail before approval", async () => {
    let approvals = 0;
    await withServer(
      async (uri) => {
        await expect(rpc(uri, keyServiceDefinition.Decrypt, { ciphertext })).rejects.toMatchObject({
          code: status.NOT_FOUND,
          details: "Must provide a key",
        });
        await expect(
          rpc(uri, keyServiceDefinition.Encrypt, { plaintext: plaintext() }),
        ).rejects.toMatchObject({ code: status.NOT_FOUND, details: "Must provide a key" });
        await expect(
          rpc(uri, keyServiceDefinition.Decrypt, {
            key: { type: "kms", arn: "test-arn", role: "", context: {}, awsProfile: "" },
            ciphertext,
          }),
        ).rejects.toMatchObject({ code: status.UNIMPLEMENTED });
        expect(approvals).toBe(0);
      },
      {
        interaction: interaction(() =>
          Effect.sync(() => {
            approvals++;
            return true;
          }),
        ),
      },
    );
  });

  const statuses: ReadonlyArray<readonly [KeyServiceErrorReason, number]> = [
    ["MissingKey", status.NOT_FOUND],
    ["UnsupportedKey", status.UNIMPLEMENTED],
    ["NoMatchingIdentity", status.FAILED_PRECONDITION],
    ["Denied", status.PERMISSION_DENIED],
    ["InteractionUnavailable", status.UNAVAILABLE],
    ["PluginFailed", status.ABORTED],
    ["InvalidRequest", status.INVALID_ARGUMENT],
    ["TimedOut", status.DEADLINE_EXCEEDED],
    ["Internal", status.INTERNAL],
  ];
  test.each(statuses)("maps handler failure %s to gRPC %s", async (reason, code) => {
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({ code, details: "Client-safe failure" });
      },
      {
        keys: {
          ...keys,
          decrypt: () =>
            Effect.fail(new KeyServiceError({ reason, message: "Client-safe failure" })),
        },
      },
    );
  });

  const interactionStatuses: ReadonlyArray<
    readonly [KeyServiceInteractionError["reason"], number]
  > = [
    ["Unavailable", status.UNAVAILABLE],
    ["Cancelled", status.PERMISSION_DENIED],
    ["TimedOut", status.PERMISSION_DENIED],
    ["Failed", status.INTERNAL],
  ];
  test.each(interactionStatuses)("maps approval failure %s to gRPC %s", async (reason, code) => {
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({ code });
      },
      {
        interaction: interaction(() =>
          Effect.fail(new KeyServiceInteractionError({ reason, message: "Approval unavailable" })),
        ),
      },
    );
  });

  test("defects produce a generic internal response", async () => {
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({
          code: status.INTERNAL,
          details: "internal keyservice error",
        });
      },
      { keys: { ...keys, decrypt: () => Effect.die(new Error("fixture defect")) } },
    );
  });

  test("request fibers retain the construction logger and log metadata without key bytes", async () => {
    const logs: Array<unknown> = [];
    const logger = Logger.make<unknown, void>(({ message }) => {
      logs.push(message);
    });
    await withServer(
      async (uri) => {
        await rpc(uri, keyServiceDefinition.Decrypt, {
          key: age,
          ciphertext: new TextEncoder().encode("ciphertext-sentinel"),
        });
      },
      { logRequests: true },
      logger,
    );
    const text = JSON.stringify(logs);
    for (const expected of ["decrypt", "age key with recipient", "127.0.0.1", "served"])
      expect(text).toContain(expected);
    expect(text).not.toContain("ciphertext-sentinel");
    expect(text).not.toContain("plaintext");
    expect(text).not.toContain("ciphertext");
    expect(text).toContain("duration");
    logs.length = 0;
    await withServer(
      async (uri) => {
        await decrypt(uri);
      },
      { logRequests: false },
      logger,
    );
    expect(logs).toHaveLength(0);
  });

  test("defect logs preserve the failure without exposing its payload", async () => {
    const logs: Array<unknown> = [];
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({
          code: status.INTERNAL,
          details: "internal keyservice error",
        });
      },
      { keys: { ...keys, decrypt: () => Effect.die(new Error("private-defect-sentinel")) } },
      Logger.make<unknown, void>(({ message, cause }) => {
        logs.push({ message, cause });
      }),
    );
    expect(JSON.stringify(logs)).toContain("internal keyservice error");
    expect(JSON.stringify(logs)).not.toContain("private-defect-sentinel");
  });

  test.each([false, true])(
    "encrypt wipes the handler's plaintext after completion (failure=%s)",
    async (fail) => {
      let received: Uint8Array | undefined;
      await withServer(
        async (uri) => {
          const pending = rpc(uri, keyServiceDefinition.Encrypt, {
            key: age,
            plaintext: plaintext(),
          });
          if (fail) await expect(pending).rejects.toMatchObject({ code: status.ABORTED });
          else expect((await pending).ciphertext).toEqual(ciphertext);
          expect(received).toEqual(new Uint8Array(32));
        },
        {
          keys: {
            ...keys,
            encrypt: (input) =>
              Effect.gen(function* () {
                received = input.plaintext;
                expect(received).toEqual(plaintext());
                expect(input.request.operation).toBe("encrypt");
                return fail
                  ? yield* Effect.fail(
                      new KeyServiceError({ reason: "PluginFailed", message: "Fixture failure" }),
                    )
                  : ciphertext;
              }),
          },
        },
      );
    },
  );

  test("serializes approval and key work across decrypt and encrypt", async () => {
    const events: Array<string> = [];
    await withServer(
      async (uri) => {
        await Promise.all([
          decrypt(uri),
          rpc(uri, keyServiceDefinition.Encrypt, { key: age, plaintext: plaintext() }),
        ]);
        expect(events).toEqual([
          "preflight",
          "approve-start",
          "approve-end",
          "key-start",
          "key-end",
          "preflight",
          "approve-start",
          "approve-end",
          "key-start",
          "key-end",
        ]);
      },
      {
        interaction: interaction(() =>
          Effect.gen(function* () {
            events.push("approve-start");
            yield* Effect.sleep("15 millis");
            events.push("approve-end");
            return true;
          }),
        ),
        keys: {
          preflight: () =>
            Effect.sync(() => {
              events.push("preflight");
            }),
          decrypt: () =>
            Effect.gen(function* () {
              events.push("key-start");
              yield* Effect.sleep("15 millis");
              events.push("key-end");
              return plaintext();
            }),
          encrypt: () =>
            Effect.gen(function* () {
              events.push("key-start");
              yield* Effect.sleep("15 millis");
              events.push("key-end");
              return ciphertext;
            }),
        },
      },
    );
  });

  test("client deadline interrupts pending approval and releases the permit", async () => {
    const entered = signal(),
      interrupted = signal();
    let count = 0;
    await withServer(
      async (uri) => {
        const pending = decrypt(uri, 150);
        const failure = expect(pending).rejects.toMatchObject({ code: status.DEADLINE_EXCEEDED });
        await entered.promise;
        await failure;
        await interrupted.promise;
        expect((await decrypt(uri)).plaintext).toEqual(plaintext());
      },
      {
        interaction: interaction(() =>
          ++count === 1
            ? Effect.gen(function* () {
                entered.resolve();
                return yield* Effect.never;
              }).pipe(Effect.onInterrupt(() => Effect.sync(interrupted.resolve)))
            : Effect.succeed(true),
        ),
      },
    );
  });

  test("request timeout interrupts approval", async () => {
    const interrupted = signal();
    await withServer(
      async (uri) => {
        await expect(decrypt(uri)).rejects.toMatchObject({ code: status.DEADLINE_EXCEEDED });
        await interrupted.promise;
      },
      {
        requestTimeout: "40 millis",
        interaction: interaction(() =>
          Effect.never.pipe(Effect.onInterrupt(() => Effect.sync(interrupted.resolve))),
        ),
      },
    );
  });

  test("request timeout includes waiting for the server-wide permit", async () => {
    const entered = signal();
    let count = 0;
    await withServer(
      async (uri) => {
        const first = decrypt(uri);
        await entered.promise;
        const second = decrypt(uri);
        const startTime = Date.now();
        const [firstResult, secondResult] = await Promise.allSettled([first, second]);
        expect(firstResult.status).toBe("fulfilled");
        expect(secondResult.status).toBe("rejected");
        if (secondResult.status === "rejected")
          expect(secondResult.reason).toMatchObject({
            code: status.DEADLINE_EXCEEDED,
            details: "Keyservice request timed out",
          });
        expect(Date.now() - startTime).toBeLessThan(300);
      },
      {
        requestTimeout: "200 millis",
        interaction: interaction(() =>
          Effect.gen(function* () {
            count++;
            if (count === 1) {
              entered.resolve();
              yield* Effect.sleep("140 millis");
            } else yield* Effect.never;
            return true;
          }),
        ),
      },
    );
  });

  test("closing the scope interrupts pending approval and stops the listener", async () => {
    const entered = signal(),
      interrupted = signal();
    const server = await start({
      interaction: interaction(() =>
        Effect.gen(function* () {
          entered.resolve();
          return yield* Effect.never;
        }).pipe(Effect.onInterrupt(() => Effect.sync(interrupted.resolve))),
      ),
    });
    const uri = server.addresses[0]!.uri;
    const pending = decrypt(uri).then(
      () => "served",
      (error: unknown) => error,
    );
    try {
      await entered.promise;
    } finally {
      await server.close();
    }
    await interrupted.promise;
    expect(await pending).toMatchObject({ code: status.CANCELLED });
    const address = server.addresses[0]!.address;
    if (address._tag !== "Tcp") throw new Error("Expected TCP listener");
    await expect(
      new Promise<void>((resolve, reject) => {
        const socket = createConnection({ host: address.host, port: address.port });
        socket.once("error", reject);
        socket.once("connect", () => {
          socket.destroy();
          resolve();
        });
      }),
    ).rejects.toMatchObject({ code: "ECONNREFUSED" });
  });
});

describe("keyservice server listeners", () => {
  test("binds every TCP address and reports real ephemeral ports", async () => {
    const server = await start({ addresses: addresses(tcp, { ...tcp, host: "localhost" }) });
    try {
      expect(server.addresses).toHaveLength(2);
      for (const bound of server.addresses) {
        expect(bound.requested).toMatchObject({ port: 0 });
        expect(bound.address._tag).toBe("Tcp");
        if (bound.address._tag === "Tcp") expect(bound.address.port).toBeGreaterThan(0);
        expect((await decrypt(bound.uri)).plaintext).toEqual(plaintext());
      }
    } finally {
      await server.close();
    }
  });

  test.each([0o600, 0o660])(
    "Unix socket uses mode %s and is removed at scope close",
    async (mode) => {
      await temporary(async (directory) => {
        const path = join(directory, "service.sock");
        const server = await start({
          addresses: addresses({ _tag: "Unix", path }),
          ...(mode === 0o600 ? {} : { socketMode: mode }),
        });
        const uri = server.addresses[0]!.uri;
        try {
          expect(uri).toBe(`unix://${path}`);
          expect((await stat(path)).mode & 0o777).toBe(mode);
          expect((await decrypt(uri)).plaintext).toEqual(plaintext());
        } finally {
          await server.close();
        }
        await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
        await expect(decrypt(uri, 100)).rejects.toMatchObject({ code: status.UNAVAILABLE });
      });
    },
  );

  test("rejects relative Unix paths", async () => {
    await expect(
      start({ addresses: addresses({ _tag: "Unix", path: "relative.sock" }) }),
    ).rejects.toMatchObject({ reason: "InvalidAddress" });
  });

  test("does not replace ordinary files or active sockets", async () => {
    await temporary(async (directory) => {
      const path = join(directory, "occupied");
      await writeFile(path, "keep this file");
      await expect(start({ addresses: addresses({ _tag: "Unix", path }) })).rejects.toMatchObject({
        reason: "BindFailed",
      });
      expect(await readFile(path, "utf8")).toBe("keep this file");
      await rm(path);
      const probeClosed = signal();
      const connections = new Set<Socket>();
      const listener = createServer((socket) => {
        connections.add(socket);
        socket.once("close", () => {
          connections.delete(socket);
          probeClosed.resolve();
        });
      });
      await new Promise<void>((resolve, reject) =>
        listener.once("error", reject).listen(path, resolve),
      );
      try {
        await expect(start({ addresses: addresses({ _tag: "Unix", path }) })).rejects.toMatchObject(
          { reason: "BindFailed" },
        );
        await Effect.runPromise(
          Effect.promise(() => probeClosed.promise).pipe(Effect.timeout("500 millis")),
        );
        expect(connections.size).toBe(0);
        expect((await stat(path)).isSocket()).toBe(true);
        await new Promise<void>((resolve, reject) => {
          const socket = createConnection(path, () => {
            socket.end();
            resolve();
          });
          socket.once("error", reject);
        });
      } finally {
        for (const socket of connections) socket.destroy();
        await new Promise<void>((resolve, reject) =>
          listener.close((error) => (error ? reject(error) : resolve())),
        );
      }
    });
  });

  test("replaces a stale Unix socket left by a terminated process", async () => {
    await temporary(async (directory) => {
      const path = join(directory, "stale.sock");
      await Effect.runPromise(
        Effect.gen(function* () {
          const spawner = yield* ChildProcessSpawner;
          const child = yield* spawner.spawn(
            ChildProcess.make(process.execPath, [
              "-e",
              'require("node:net").createServer().listen(process.argv[1], () => process.kill(process.pid, "SIGKILL"))',
              path,
            ]),
          );
          // SIGKILL intentionally leaves the socket inode and is reported as a typed failure.
          const exit = yield* Effect.result(child.exitCode);
          expect(exit._tag).toBe("Failure");
        }).pipe(Effect.scoped, Effect.provide(BunServices.layer)),
      );
      expect((await stat(path)).isSocket()).toBe(true);
      await withServer(
        async (uri) => {
          expect((await decrypt(uri)).plaintext).toEqual(plaintext());
        },
        { addresses: addresses({ _tag: "Unix", path }) },
      );
      await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
    });
  });

  test("cleans up earlier listeners when a later bind fails", async () => {
    await temporary(async (directory) => {
      const path = join(directory, "first.sock"),
        blocked = join(directory, "blocked");
      await writeFile(blocked, "keep");
      const scope = Scope.makeUnsafe();
      try {
        await expect(
          Effect.runPromise(
            makeServer({
              addresses: addresses({ _tag: "Unix", path }, { _tag: "Unix", path: blocked }),
              keys,
              interaction: interaction(),
              logRequests: false,
            }).pipe(Scope.provide(scope)),
          ),
        ).rejects.toMatchObject({ reason: "BindFailed" });
        // Acquisition failure must roll back without relying on the caller's scope closing.
        await expect(stat(path)).rejects.toMatchObject({ code: "ENOENT" });
        expect(await readFile(blocked, "utf8")).toBe("keep");
        await expect(decrypt(`unix://${path}`, 100)).rejects.toMatchObject({
          code: status.UNAVAILABLE,
        });
      } finally {
        await Effect.runPromise(Scope.close(scope, Exit.void));
      }
    });
  });

  test("a TCP bind collision releases the first listener before the caller closes its scope", async () => {
    const occupied = createServer((socket) => socket.end());
    const reservation = createServer();
    const scope = Scope.makeUnsafe();
    await new Promise<void>((resolve, reject) =>
      occupied.once("error", reject).listen(0, "127.0.0.1", resolve),
    );
    try {
      await new Promise<void>((resolve, reject) =>
        reservation.once("error", reject).listen(0, "127.0.0.1", resolve),
      );
      const firstAddress = reservation.address(),
        blockedAddress = occupied.address();
      if (
        !firstAddress ||
        typeof firstAddress === "string" ||
        !blockedAddress ||
        typeof blockedAddress === "string"
      )
        throw new Error("Expected TCP addresses");
      await new Promise<void>((resolve, reject) =>
        reservation.close((error) => (error ? reject(error) : resolve())),
      );
      const first = { ...tcp, port: firstAddress.port },
        blocked = { ...tcp, port: blockedAddress.port };
      await expect(
        Effect.runPromise(
          makeServer({
            addresses: addresses(first, blocked),
            keys,
            interaction: interaction(),
            logRequests: false,
          }).pipe(Scope.provide(scope)),
        ),
      ).rejects.toMatchObject({
        reason: "BindFailed",
        address: `127.0.0.1:${blocked.port}`,
      });
      // A fresh listener proves the earlier successful bind was released immediately.
      await new Promise<void>((resolve, reject) =>
        reservation.once("error", reject).listen(first.port, first.host, resolve),
      );
      expect(reservation.listening).toBe(true);
      expect(occupied.listening).toBe(true);
    } finally {
      await Effect.runPromise(Scope.close(scope, Exit.void));
      if (reservation.listening)
        await new Promise<void>((resolve, reject) =>
          reservation.close((error) => (error ? reject(error) : resolve())),
        );
      await new Promise<void>((resolve, reject) =>
        occupied.close((error) => (error ? reject(error) : resolve())),
      );
    }
  });
});

const sops = Bun.which("sops");
test.skipIf(sops === null)(
  "real Go sops decrypts the existing native fixture through this server",
  async () => {
    // This public test-only identity decrypts the repository's native.enc.json fixture.
    const identity = "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
    await withServer(
      async (uri) => {
        const result = await Effect.runPromise(
          Effect.gen(function* () {
            const spawner = yield* ChildProcessSpawner;
            const child = yield* spawner.spawn(
              ChildProcess.make(
                sops!,
                [
                  "decrypt",
                  "--enable-local-keyservice=false",
                  "--keyservice",
                  uri,
                  join(import.meta.dir, "fixtures/native.enc.json"),
                ],
                {
                  env: Object.fromEntries(
                    Object.entries(process.env).filter(([key]) => !key.startsWith("SOPS_AGE_KEY")),
                  ),
                  extendEnv: false,
                },
              ),
            );
            return yield* Effect.all(
              {
                stdout: child.stdout.pipe(Stream.decodeText(), Stream.runCollect),
                stderr: child.stderr.pipe(Stream.decodeText(), Stream.runCollect),
                exitCode: child.exitCode,
              },
              { concurrency: "unbounded" },
            );
          }).pipe(Effect.scoped, Effect.provide(BunServices.layer)),
        );
        expect(Number(result.exitCode)).toBe(0);
        expect(JSON.parse(result.stdout.join(""))).toMatchObject({
          api: { token: "native-token" },
        });
      },
      {
        keys: {
          ...keys,
          decrypt: ({ ciphertext: encrypted }) =>
            Effect.tryPromise({
              try: () => {
                const decrypter = new Decrypter();
                decrypter.addIdentity(identity);
                return decrypter.decrypt(
                  armor.decode(new TextDecoder().decode(encrypted)),
                  "uint8array",
                );
              },
              catch: () =>
                new KeyServiceError({
                  reason: "InvalidRequest",
                  message: "Invalid fixture ciphertext",
                }),
            }),
        },
      },
    );
  },
  10_000,
);
