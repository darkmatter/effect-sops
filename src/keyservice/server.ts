import { chmod, lstat, unlink } from "node:fs/promises";
import { createConnection } from "node:net";
import { isAbsolute } from "node:path";
import {
  Server,
  ServerCredentials,
  status,
  type sendUnaryData,
  type ServerUnaryCall,
} from "@grpc/grpc-js";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as FiberSet from "effect/FiberSet";
import * as Scope from "effect/Scope";
import * as Semaphore from "effect/Semaphore";
import { grpcBindTarget, keyServiceUri, peerHost } from "./address.js";
import {
  KeyServiceError,
  KeyServiceListenError,
  sanitizeForDisplay,
  type BoundAddress,
  type KeyServiceErrorReason,
  type KeyServiceOperation,
  type KeyServiceRequest,
  type KeyServiceServer,
  type KeyServiceServerOptions,
} from "./model.js";
import {
  describeKey,
  keyServiceDefinition,
  type DecryptRequestMessage,
  type DecryptResponseMessage,
  type EncryptRequestMessage,
  type EncryptResponseMessage,
} from "./protocol.js";

const grpcStatus: Record<KeyServiceErrorReason, status> = {
  MissingKey: status.NOT_FOUND,
  UnsupportedKey: status.UNIMPLEMENTED,
  NoMatchingIdentity: status.FAILED_PRECONDITION,
  Denied: status.PERMISSION_DENIED,
  InteractionUnavailable: status.UNAVAILABLE,
  PluginFailed: status.ABORTED,
  InvalidRequest: status.INVALID_ARGUMENT,
  TimedOut: status.DEADLINE_EXCEEDED,
  Internal: status.INTERNAL,
};

const hasCode = (error: unknown, code: string): boolean =>
  typeof error === "object" && error !== null && "code" in error && error.code === code;

const bindError = (address: string) => (cause: unknown) =>
  new KeyServiceListenError({
    reason: "BindFailed",
    address,
    message: `Could not bind ${sanitizeForDisplay(address)}`,
    cause,
  });

const prepareSocket = Effect.fn("KeyService.prepareSocket")(function* (path: string) {
  if (!isAbsolute(path)) {
    return yield* Effect.fail(
      new KeyServiceListenError({
        reason: "InvalidAddress",
        address: path,
        message: "Unix socket paths must be absolute",
      }),
    );
  }
  const existing = yield* Effect.tryPromise({
    try: () => lstat(path),
    catch: (cause) => cause,
  }).pipe(
    Effect.catch((cause) =>
      hasCode(cause, "ENOENT") ? Effect.succeed(undefined) : Effect.fail(bindError(path)(cause)),
    ),
  );
  if (!existing) return;
  const stale =
    existing.isSocket() &&
    (yield* Effect.callback<boolean>((resume) => {
      const socket = createConnection(path);
      const complete = (stale: boolean) => {
        socket.destroy();
        resume(Effect.succeed(stale));
      };
      socket.once("connect", () => complete(false));
      socket.once("error", (error) =>
        complete(hasCode(error, "ECONNREFUSED") || hasCode(error, "ENOENT")),
      );
      socket.setTimeout(500, () => complete(false));
      return Effect.sync(() => socket.destroy());
    }));
  if (!stale) {
    return yield* Effect.fail(
      new KeyServiceListenError({
        reason: "BindFailed",
        address: path,
        message: `Could not bind ${sanitizeForDisplay(path)}: address in use`,
      }),
    );
  }
  yield* Effect.tryPromise({
    try: async () => {
      // Do not remove a file that replaced the stale socket during the probe.
      const current = await lstat(path);
      if (current.ino !== existing.ino || current.dev !== existing.dev) {
        throw new Error("Socket path changed during stale socket check");
      }
      await unlink(path);
    },
    catch: bindError(path),
  });
});

/** Bind the upstream SOPS KeyService on every address and serve until the scope closes. */
export const makeServer: (
  options: KeyServiceServerOptions,
) => Effect.Effect<KeyServiceServer, KeyServiceListenError, Scope.Scope> = Effect.fn(
  "KeyService.makeServer",
)(function* (options) {
  const scope = yield* Scope.fork(yield* Effect.scope);
  return yield* Effect.gen(function* () {
    const context = yield* Effect.context<never>();
    const runFork = Effect.runForkWith(context);
    const fibers = yield* FiberSet.make();
    const semaphore = yield* Semaphore.make(1);
    const sockets = new Map<string, { ino: number; dev: number }>();
    let closing = false;
    let nextId = 1;
    const server = yield* Effect.acquireRelease(
      Effect.sync(() => new Server({ "grpc.max_receive_message_length": 1024 * 1024 })),
      (server) =>
        Effect.gen(function* () {
          closing = true;
          yield* FiberSet.clear(fibers);
          yield* Effect.callback<void>((resume) => {
            server.tryShutdown(() => resume(Effect.void));
          }).pipe(Effect.timeoutOrElse({ duration: "2 seconds", orElse: () => Effect.void }));
          server.forceShutdown();
          for (const [path, identity] of sockets) {
            yield* Effect.tryPromise({
              try: async () => {
                const current = await lstat(path);
                if (
                  current.ino === identity.ino &&
                  current.dev === identity.dev &&
                  current.isSocket()
                ) {
                  await unlink(path);
                }
              },
              catch: (cause) => cause,
            }).pipe(
              Effect.catch((cause) =>
                hasCode(cause, "ENOENT")
                  ? Effect.void
                  : Effect.logWarning(
                      "Could not remove keyservice socket",
                      sanitizeForDisplay(path),
                    ),
              ),
            );
          }
        }),
    );

    const serve = (
      operation: KeyServiceOperation,
      call: ServerUnaryCall<
        DecryptRequestMessage | EncryptRequestMessage,
        DecryptResponseMessage | EncryptResponseMessage
      >,
      callback: sendUnaryData<Uint8Array>,
    ): void => {
      const input = call.request;
      const wipeInput = () => {
        if ("plaintext" in input) input.plaintext.fill(0);
      };
      if (closing || !input.key) {
        wipeInput();
        callback({
          code: closing ? status.CANCELLED : status.NOT_FOUND,
          details: closing ? "keyservice is shutting down" : "Must provide a key",
        });
        return;
      }
      const started = Date.now();
      const peer = call.getPeer();
      const request: KeyServiceRequest = {
        id: nextId++,
        operation,
        key: input.key,
        keyDescription: describeKey(input.key),
        peer,
        peerHost: peerHost(peer),
        receivedAt: new Date(started),
      };
      const work = Effect.gen(function* () {
        yield* options.keys.preflight(operation, request.key);
        const approved = yield* options.interaction.approve(request).pipe(
          Effect.mapError(
            (error) =>
              new KeyServiceError({
                reason:
                  error.reason === "Unavailable"
                    ? "InteractionUnavailable"
                    : error.reason === "Failed"
                      ? "Internal"
                      : "Denied",
                message:
                  error.reason === "Unavailable"
                    ? "Request approval is unavailable"
                    : error.reason === "Failed"
                      ? "Request approval failed"
                      : "Request rejected by user",
              }),
          ),
        );
        if (!approved)
          return yield* Effect.fail(
            new KeyServiceError({
              reason: "Denied",
              message: "Request rejected by user",
            }),
          );
        return yield* "plaintext" in input
          ? options.keys.encrypt({
              request,
              plaintext: input.plaintext,
              interaction: options.interaction,
            })
          : options.keys.decrypt({
              request,
              ciphertext: input.ciphertext,
              interaction: options.interaction,
            });
      }).pipe(
        Semaphore.withPermit(semaphore),
        Effect.timeoutOrElse({
          duration: options.requestTimeout ?? "2 minutes",
          orElse: () =>
            Effect.fail(
              new KeyServiceError({
                reason: "TimedOut",
                message: "Keyservice request timed out",
              }),
            ),
        }),
        Effect.ensuring(Effect.sync(wipeInput)),
        Effect.onExit((exit) =>
          Effect.gen(function* () {
            let outcome = "served";
            if (Exit.isSuccess(exit)) {
              try {
                if (call.cancelled) outcome = "failed Cancelled";
                else callback(null, exit.value);
              } finally {
                // Cancellation can prevent grpc-js from invoking its wiping serializer.
                if (operation === "decrypt") exit.value.fill(0);
              }
            } else {
              const failure = exit.cause.reasons.find(Cause.isFailReason)?.error;
              const interrupted = Cause.hasInterruptsOnly(exit.cause);
              const defect = Cause.hasDies(exit.cause);
              const reason = defect
                ? "Internal"
                : (failure?.reason ?? (interrupted ? "Cancelled" : "Internal"));
              outcome = `${reason === "Denied" ? "denied" : "failed"} ${reason}`;
              callback({
                code: reason === "Cancelled" ? status.CANCELLED : grpcStatus[reason],
                details: defect
                  ? "internal keyservice error"
                  : (failure?.message ??
                    (interrupted ? "Request cancelled" : "internal keyservice error")),
              });
              if (defect) {
                // Defect payloads can contain secrets; retain only the cause's structure.
                yield* Effect.logError("internal keyservice error", {
                  id: request.id,
                  cause: exit.cause.reasons.map((reason) => reason._tag),
                });
              }
            }
            if (options.logRequests !== false)
              yield* Effect.logInfo("Keyservice request", {
                id: request.id,
                operation,
                keyDescription: request.keyDescription,
                peer: sanitizeForDisplay(peer, 80),
                outcome,
                durationMs: Date.now() - started,
              });
          }),
        ),
      );
      const fiber = runFork(work);
      FiberSet.addUnsafe(fibers, fiber);
      const cancel = () => fiber.interruptUnsafe();
      call.on("cancelled", cancel);
      fiber.addObserver(() => call.removeListener("cancelled", cancel));
      if (call.cancelled) cancel();
    };

    server.addService(keyServiceDefinition, {
      Decrypt: (
        call: ServerUnaryCall<DecryptRequestMessage, DecryptResponseMessage>,
        callback: sendUnaryData<DecryptResponseMessage>,
      ) =>
        serve("decrypt", call, (error, plaintext) =>
          callback(error, plaintext ? { plaintext } : undefined),
        ),
      Encrypt: (
        call: ServerUnaryCall<EncryptRequestMessage, EncryptResponseMessage>,
        callback: sendUnaryData<EncryptResponseMessage>,
      ) =>
        serve("encrypt", call, (error, ciphertext) =>
          callback(error, ciphertext ? { ciphertext } : undefined),
        ),
    });
    const addresses: BoundAddress[] = [];
    for (const { requested, resolved } of options.addresses) {
      if (resolved._tag === "Unix") yield* prepareSocket(resolved.path);
      const target = grpcBindTarget(resolved);
      // bindAsync has no cancellation handle. Finish acquisition before interruption
      // so even a late port-0 bind is registered before the scope shuts it down.
      const address = yield* Effect.uninterruptible(
        Effect.gen(function* () {
          const port = yield* Effect.callback<number, KeyServiceListenError>((resume) => {
            try {
              server.bindAsync(target, ServerCredentials.createInsecure(), (error, port) =>
                resume(error ? Effect.fail(bindError(target)(error)) : Effect.succeed(port)),
              );
            } catch (cause) {
              resume(Effect.fail(bindError(target)(cause)));
            }
          });
          if (resolved._tag === "Tcp") return { ...resolved, port };
          yield* Effect.tryPromise({
            try: async () => {
              const info = await lstat(resolved.path);
              sockets.set(resolved.path, { ino: info.ino, dev: info.dev });
              await chmod(resolved.path, options.socketMode ?? 0o600);
            },
            catch: bindError(target),
          });
          return resolved;
        }),
      );
      addresses.push({ requested, address, uri: keyServiceUri(address) });
    }
    return { addresses };
  }).pipe(
    Scope.provide(scope),
    Effect.onExit((exit) => (Exit.isFailure(exit) ? Scope.close(scope, exit) : Effect.void)),
  );
});
