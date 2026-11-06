import * as LocalProvider from "alchemy/Local/LocalProvider";
import { Resource } from "alchemy/Resource";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as Scope from "effect/Scope";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  KeyServiceListenError,
  SshTunnelError,
  type ListenAddress,
  type SshTunnel,
} from "./model.js";

/** Serializable keyservice settings; identity contents must never enter Alchemy state. */
export interface SopsKeyServiceProps {
  readonly listen?: ReadonlyArray<ListenAddress>;
  readonly approval?: "none" | "dialog";
  readonly dialog?: {
    readonly title?: string;
    readonly timeoutSeconds?: number;
    readonly valueTimeoutSeconds?: number;
    readonly notifications?: boolean;
  };
  readonly rememberApprovalSeconds?: number;
  readonly age?: {
    readonly identityFiles?: ReadonlyArray<string>;
    readonly discover?: boolean;
    readonly encryptPlugins?: ReadonlyArray<string>;
  };
  readonly remoteForwards?: ReadonlyArray<{
    readonly destination: string;
    readonly remoteHost?: string;
    readonly remotePort?: number;
    readonly sshArgs?: ReadonlyArray<string>;
    readonly ssh?: string;
  }>;
  readonly requestTimeoutSeconds?: number;
}

/** Listener URIs on this machine and forwarding URIs on remote hosts. */
export interface SopsKeyServiceAttributes {
  readonly uri: string;
  readonly uris: ReadonlyArray<string>;
  readonly remoteUris: ReadonlyArray<string>;
}

/** A scoped local keyservice, hosted in the sidecar during `alchemy dev`. */
export interface SopsKeyService extends Resource<
  "Sops.KeyService",
  SopsKeyServiceProps,
  SopsKeyServiceAttributes
> {}

/** Serve until the deployment process or development session ends. */
export const SopsKeyService = Resource<SopsKeyService>("Sops.KeyService");

/** Serializable SSH forwarding settings for reaching a remote keyservice. */
export interface SopsKeyServiceTunnelProps {
  readonly destination: string;
  readonly localHost?: string;
  readonly localPort?: number;
  readonly remoteHost?: string;
  readonly remotePort?: number;
  readonly sshArgs?: ReadonlyArray<string>;
  readonly ssh?: string;
  readonly readyTimeoutSeconds?: number;
}

/** Local forwarding endpoint, including the allocated port when omitted in props. */
export interface SopsKeyServiceTunnelAttributes {
  readonly uri: string;
  readonly localPort: number;
}

/** A scoped SSH local forward, hosted in the sidecar during `alchemy dev`. */
export interface SopsKeyServiceTunnel extends Resource<
  "Sops.KeyServiceTunnel",
  SopsKeyServiceTunnelProps,
  SopsKeyServiceTunnelAttributes
> {}

/** Forward a local port to a remote keyservice for the Alchemy session. */
export const SopsKeyServiceTunnel = Resource<SopsKeyServiceTunnel>(
  "Sops.KeyServiceTunnel",
);

// The dev loader imports source modules, whereas published packages use JavaScript.
const localModule = import.meta.resolve(
  new URL(import.meta.url).pathname.endsWith(".ts")
    ? "./alchemy-local.ts"
    : "./alchemy-local.js",
);

/** Register the keyservice provider with platform services captured at construction. */
export const SopsKeyServiceProvider = () =>
  LocalProvider.make(
    SopsKeyService,
    localModule,
    Effect.gen(function* () {
      const spawner = yield* ChildProcessSpawner;
      return {
        start: Effect.fn("SopsKeyService.start")(function* ({ news, invalidate }) {
          const { serve, Interaction } = yield* Effect.tryPromise({
            try: async () => ({
              ...(await import("./serve.js")),
              Interaction: await import("./interaction.js"),
            }),
            catch: () =>
              new KeyServiceListenError({
                reason: "BindFailed",
                message: "Could not load the keyservice implementation",
              }),
          });
          for (const seconds of [
            news.dialog?.timeoutSeconds,
            news.dialog?.valueTimeoutSeconds,
            news.rememberApprovalSeconds,
            news.requestTimeoutSeconds,
          ]) {
            if (seconds !== undefined && (!Number.isFinite(seconds) || seconds <= 0))
              return yield* Effect.fail(
                new KeyServiceListenError({
                  reason: "InvalidAddress",
                  message: "Keyservice timeouts must be positive finite seconds",
                }),
              );
          }
          const dialog = news.dialog;
          let interaction = news.approval === "dialog"
            ? yield* Interaction.dialog({
                ...(dialog?.title === undefined ? {} : { title: dialog.title }),
                ...(dialog?.notifications === undefined
                  ? {}
                  : { notifications: dialog.notifications }),
                ...(dialog?.timeoutSeconds === undefined
                  ? {}
                  : { timeout: Duration.seconds(dialog.timeoutSeconds) }),
                ...(dialog?.valueTimeoutSeconds === undefined
                  ? {}
                  : { valueTimeout: Duration.seconds(dialog.valueTimeoutSeconds) }),
              }).pipe(Effect.provideService(ChildProcessSpawner, spawner))
            : Interaction.none;
          if (news.approval === "dialog" && news.rememberApprovalSeconds !== undefined)
            interaction = yield* Interaction.remember(interaction, {
              ttl: Duration.seconds(news.rememberApprovalSeconds),
            });
          const running = yield* acquireInstance(
            serve({
              interaction,
              ...(news.listen === undefined ? {} : { listen: news.listen }),
              ...(news.age === undefined ? {} : { age: news.age }),
              ...(news.remoteForwards === undefined
                ? {}
                : { remoteForwards: news.remoteForwards }),
              ...(news.requestTimeoutSeconds === undefined
                ? {}
                : { requestTimeout: Duration.seconds(news.requestTimeoutSeconds) }),
            }).pipe(Effect.provideService(ChildProcessSpawner, spawner)),
            (value) => value.tunnels,
            invalidate,
          );
          return {
            uri: running.uri,
            uris: running.uris,
            remoteUris: running.tunnels.map((tunnel) => tunnel.uri),
          };
        }),
      } satisfies LocalProvider.LocalProviderSpec<SopsKeyService>;
    }),
  );

/** Register the SSH tunnel provider with platform services captured at construction. */
export const SopsKeyServiceTunnelProvider = () =>
  LocalProvider.make(
    SopsKeyServiceTunnel,
    localModule,
    Effect.gen(function* () {
      const spawner = yield* ChildProcessSpawner;
      return {
        start: Effect.fn("SopsKeyServiceTunnel.start")(function* ({ news, invalidate }) {
          const { connect } = yield* Effect.tryPromise({
            try: () => import("./serve.js"),
            catch: () =>
              new SshTunnelError({
                reason: "SpawnFailed",
                destination: "<configured destination>",
                message: "Could not load the SSH tunnel implementation",
              }),
          });
          const { readyTimeoutSeconds, ...options } = news;
          if (
            readyTimeoutSeconds !== undefined &&
            (!Number.isFinite(readyTimeoutSeconds) || readyTimeoutSeconds <= 0)
          )
            return yield* Effect.fail(
              new SshTunnelError({
                reason: "InvalidOptions",
                destination: "<configured destination>",
                message: "SSH readiness timeout must be positive finite seconds",
              }),
            );
          const tunnel = yield* acquireInstance(
            connect({
              ...options,
              ...(readyTimeoutSeconds === undefined
                ? {}
                : { readyTimeout: Duration.seconds(readyTimeoutSeconds) }),
            }).pipe(Effect.provideService(ChildProcessSpawner, spawner)),
            (value) => [value],
            invalidate,
          );
          return { uri: tunnel.uri, localPort: tunnel.bindPort };
        }),
      } satisfies LocalProvider.LocalProviderSpec<SopsKeyServiceTunnel>;
    }),
  );

/** Register both scoped keyservice resources. */
export const keyServiceProviders = () =>
  Layer.merge(SopsKeyServiceProvider(), SopsKeyServiceTunnelProvider());

// LocalProvider.invalidate forgets the instance but does not close its scope.
// Release its listeners and sibling forwards before allowing a restart.
const acquireInstance = <A, E>(
  acquire: Effect.Effect<A, E, Scope.Scope>,
  tunnels: (value: A) => ReadonlyArray<SshTunnel>,
  invalidate: Effect.Effect<void>,
): Effect.Effect<A, E, Scope.Scope> =>
  Effect.gen(function* () {
    const scope = yield* Scope.fork(yield* Effect.scope);
    const value = yield* acquire.pipe(
      Scope.provide(scope),
      Effect.onExit((exit) =>
        Exit.isFailure(exit) ? Scope.close(scope, exit) : Effect.void,
      ),
    );
    const forwards = tunnels(value);
    if (forwards.length > 0)
      yield* Effect.raceAllFirst(forwards.map((tunnel) => tunnel.awaitExit)).pipe(
        Effect.exit,
        Effect.flatMap(() => Scope.close(scope, Exit.void)),
        Effect.andThen(invalidate),
        // The watcher belongs to the parent, so closing the child cannot interrupt cleanup.
        Effect.forkScoped,
      );
    return value;
  });
