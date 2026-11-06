import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Scope from "effect/Scope";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import { isLoopback } from "./address.js";
import { ageKeyHandler } from "./age.js";
import * as Interaction from "./interaction.js";
import * as Listen from "./listen.js";
import {
  KeyServiceListenError,
  sanitizeForDisplay,
  type AgeKeyServiceOptions,
  type BoundAddress,
  type KeyHandler,
  type KeyServiceInteraction,
  type ListenAddress,
  type SshRemoteForwardOptions,
  type SshTunnel,
  type SshTunnelError,
} from "./model.js";
import { makeServer } from "./server.js";
import * as Ssh from "./ssh.js";

/** Listener, approval, key, and forwarding options for a scoped keyservice. */
export interface ServeOptions {
  /** Default: 127.0.0.1:5000, matching `sops keyservice`. */
  readonly listen?: ListenAddress | ReadonlyArray<ListenAddress>;
  /** Default: approve without prompting, matching SOPS without `--prompt`. */
  readonly interaction?: KeyServiceInteraction;
  /** Defaults to the built-in age handler configured with `age`. */
  readonly keys?: KeyHandler;
  readonly age?: AgeKeyServiceOptions;
  /** Open after binding; target defaults to the first TCP listener, else Unix. */
  readonly remoteForwards?: ReadonlyArray<
    Omit<SshRemoteForwardOptions, "target"> & {
      readonly target?: SshRemoteForwardOptions["target"];
    }
  >;
  readonly requestTimeout?: Duration.Input;
  /** Requests allowed to wait for their turn. Default: 16. */
  readonly maxPendingRequests?: number;
  readonly logRequests?: boolean;
  readonly socketMode?: number;
  /** Tailscale discovery and executable overrides. */
  readonly resolve?: Listen.ResolveOptions;
}

/** Addresses and forwards that remain available for the enclosing scope. */
export interface RunningKeyService {
  /** The first listener's URI, suitable for SOPS_KEYSERVICE or --keyservice. */
  readonly uri: string;
  readonly uris: ReadonlyArray<string>;
  readonly addresses: ReadonlyArray<BoundAddress>;
  /** Each remote forward URI is usable on its destination host. */
  readonly tunnels: ReadonlyArray<SshTunnel>;
}

/** The equivalent of `sops keyservice`, owned by the caller's scope. */
export const serve: (
  options?: ServeOptions,
) => Effect.Effect<
  RunningKeyService,
  KeyServiceListenError | SshTunnelError,
  Scope.Scope | ChildProcessSpawner
> = Effect.fn("KeyService.serve")(function* (options = {}) {
  const scope = yield* Scope.fork(yield* Effect.scope);
  return yield* Effect.gen(function* () {
    const listeners: ReadonlyArray<ListenAddress> =
      options.listen === undefined
        ? [Listen.loopback()]
        : "_tag" in options.listen
          ? [options.listen]
          : options.listen;
    if (listeners.length === 0)
      return yield* Effect.fail(
        new KeyServiceListenError({
          reason: "InvalidAddress",
          message: "At least one keyservice listener is required",
        }),
      );
    const addresses = yield* Effect.forEach(listeners, (requested) =>
      Listen.resolve(requested, options.resolve).pipe(
        Effect.map((resolved) => ({ requested, resolved })),
      ),
    );
    const interaction = options.interaction ?? Interaction.none;
    if (
      Interaction.approvesAutomatically(interaction) &&
      (addresses.some(({ resolved }) => !isLoopback(resolved)) ||
        (options.remoteForwards?.length ?? 0) > 0)
    )
      yield* Effect.logWarning(
        "Keyservice is reachable from the network or an SSH remote host without approval; use Interaction.terminal() or Interaction.dialog() to approve requests",
      );
    const keys = options.keys ?? (yield* ageKeyHandler(options.age));
    const server = yield* makeServer({
      addresses,
      keys,
      interaction,
      ...(options.requestTimeout === undefined
        ? {}
        : { requestTimeout: options.requestTimeout }),
      ...(options.maxPendingRequests === undefined
        ? {}
        : { maxPendingRequests: options.maxPendingRequests }),
      ...(options.logRequests === undefined
        ? {}
        : { logRequests: options.logRequests }),
      ...(options.socketMode === undefined
        ? {}
        : { socketMode: options.socketMode }),
    });
    const first = server.addresses[0];
    if (!first)
      return yield* Effect.fail(
        new KeyServiceListenError({
          reason: "BindFailed",
          message: "Keyservice did not bind a listener",
        }),
      );
    const target =
      server.addresses.find(({ address }) => address._tag === "Tcp")?.address ??
      first.address;
    const tunnels = yield* Effect.forEach(
      options.remoteForwards ?? [],
      (forward) =>
        Ssh.remoteForward({ ...forward, target: forward.target ?? target }),
    );
    let running = true;
    for (const tunnel of tunnels)
      yield* tunnel.awaitExit.pipe(
        Effect.andThen(() =>
          running
            ? Effect.logWarning("Keyservice SSH remote forward exited", {
                destination: sanitizeForDisplay(tunnel.destination, 1024),
              })
            : Effect.void,
        ),
        Effect.forkScoped,
      );
    // Finalizers run in reverse order: mark shutdown before interrupting watchers.
    yield* Effect.addFinalizer(() =>
      Effect.sync(() => {
        running = false;
      }),
    );
    const uris = server.addresses.map(({ uri }) => uri);
    yield* Effect.logInfo("Keyservice listening", {
      uris: uris.map((uri) => sanitizeForDisplay(uri, 1024)),
    });
    return { uri: first.uri, uris, addresses: server.addresses, tunnels };
  }).pipe(
    Scope.provide(scope),
    // A caught startup error must not leave a partially started server running.
    Effect.onExit((exit) =>
      Exit.isFailure(exit) ? Scope.close(scope, exit) : Effect.void,
    ),
  );
});
