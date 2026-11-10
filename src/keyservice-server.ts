import { Server, ServerCredentials } from "@grpc/grpc-js";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import type { Scope } from "effect/Scope";
import {
  createKeyServiceImplementation,
  KeyServiceIdentityError,
  resolveConfiguredIdentities,
} from "./keyservice-rpc.js";
import { keyServiceDefinition } from "./keyservice-wire.js";

export class KeyServiceBindError extends Data.TaggedError(
  "KeyServiceBindError",
)<{
  readonly address: string;
  readonly message: string;
}> {}

const acquireServer = (
  server: Server,
  address: string,
): Effect.Effect<number, KeyServiceBindError> =>
  Effect.tryPromise({
    try: async () => {
      const bound = Promise.withResolvers<number>();
      try {
        server.bindAsync(address, ServerCredentials.createInsecure(), (error, port) => {
          if (error) bound.reject(error);
          else bound.resolve(port);
        });
        return await bound.promise;
      } catch (cause) {
        server.forceShutdown();
        throw cause;
      }
    },
    catch: () =>
      new KeyServiceBindError({
        address,
        message: `Cannot bind the age keyservice at ${address}`,
      }),
  });

const releaseServer = async (server: Server): Promise<void> => {
  const stopped = Promise.withResolvers<void>();
  const timer = setTimeout(() => {
    server.forceShutdown();
    stopped.resolve();
  }, 2_000);
  server.tryShutdown(() => stopped.resolve());
  await stopped.promise;
  clearTimeout(timer);
};

const uriFor = (address: string, port: number): string => {
  if (address.startsWith("unix:")) {
    return `unix://${address.slice("unix:".length)}`;
  }
  const separator = address.lastIndexOf(":");
  const host = separator === -1 ? address : address.slice(0, separator);
  return `tcp://${host}:${port}`;
};

export interface KeyServiceConfig {
  readonly identities: readonly string[];
  /** gRPC target: `host:port` or `unix:/absolute/path`. */
  readonly address: string;
}

export interface KeyServiceHandle {
  readonly address: string;
  /** Ready-to-use SOPS_KEYSERVICE URI with the actual bound port. */
  readonly uri: string;
  readonly recipients: readonly string[];
}

export const startKeyService = (
  config: KeyServiceConfig,
): Effect.Effect<
  KeyServiceHandle,
  KeyServiceIdentityError | KeyServiceBindError,
  Scope
> =>
  Effect.gen(function* () {
    const identities = yield* resolveConfiguredIdentities(config.identities);
    const address = config.address.trim();
    if (address.length === 0) {
      return yield* Effect.fail(
        new KeyServiceBindError({ address, message: "A keyservice address is required" }),
      );
    }
    const server = new Server();
    server.addService(keyServiceDefinition, createKeyServiceImplementation(identities));
    const port = yield* Effect.acquireRelease(
      acquireServer(server, address),
      () => Effect.promise(() => releaseServer(server)),
    );
    return {
      address,
      uri: uriFor(address, port),
      recipients: identities.map((identity) => identity.recipient),
    };
  });
