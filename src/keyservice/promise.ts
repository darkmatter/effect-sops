import * as Cause from "effect/Cause";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Layer from "effect/Layer";
import * as ManagedRuntime from "effect/ManagedRuntime";
import * as References from "effect/References";
import * as Scope from "effect/Scope";
import type * as Terminal from "effect/Terminal";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import type { DialogOptions } from "./dialog.js";
import * as Interaction from "./interaction.js";
import type { InteractionHandlers } from "./interaction.js";
import * as Listen from "./listen.js";
import type {
  KeyServiceInteraction,
  ListenAddress,
  SshLocalForwardOptions,
  SshTunnel,
} from "./model.js";
import { serve, type RunningKeyService, type ServeOptions } from "./serve.js";
import * as Ssh from "./ssh.js";

/** A remote SSH forward with an optional target inferred from the server listeners. */
export type RemoteForwardInput = NonNullable<ServeOptions["remoteForwards"]>[number];

/** SOPS-compatible startup options for callers that do not use Effect. */
export interface StartKeyServiceOptions extends Omit<ServeOptions, "listen" | "interaction"> {
  /** SOPS --network; defaults to tcp. */
  readonly network?: "tcp" | "unix";
  /** SOPS --address; defaults to 127.0.0.1:5000. */
  readonly address?: string;
  /** Listen on this machine's Tailscale IP; true selects IPv4 and port 5000. */
  readonly tailscale?: boolean | { readonly port?: number; readonly family?: 4 | 6 };
  /** Explicit listeners cannot be combined with network, address, or tailscale. */
  readonly listen?: ListenAddress | ReadonlyArray<ListenAddress>;
  /** Confirm every request on the terminal. */
  readonly prompt?: boolean;
  /** Confirm requests and answer plugin prompts with macOS dialogs. */
  readonly dialog?: boolean | DialogOptions;
  /** Custom approval and plugin UI callbacks. */
  readonly interaction?: KeyServiceInteraction | InteractionHandlers;
  /** Cache approvals for the same peer, operation, and key. */
  readonly rememberApproval?: Duration.Input;
  /** Additional SSH remote forwards, using the server as their default target. */
  readonly ssh?: string | RemoteForwardInput | ReadonlyArray<string | RemoteForwardInput>;
  /** Enable debug logging. */
  readonly verbose?: boolean;
  /** Override the automatically selected Bun or Node platform services. */
  readonly layer?: Layer.Layer<ChildProcessSpawner | Terminal.Terminal>;
}

/** A running service whose close and async-dispose operations release all resources. */
export interface KeyServiceHandle extends Omit<RunningKeyService, "tunnels"> {
  /** Each exited promise completes on process exit or service close, without rejecting. */
  readonly tunnels: ReadonlyArray<
    Omit<SshTunnel, "awaitExit"> & { readonly exited: Promise<void> }
  >;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

/** A local SSH forward; exited completes on natural exit or close. */
export interface KeyServiceTunnelHandle {
  readonly uri: string;
  readonly bindHost: string;
  readonly bindPort: number;
  readonly destination: string;
  readonly exited: Promise<void>;
  close(): Promise<void>;
  [Symbol.asyncDispose](): Promise<void>;
}

const platformLayer: Layer.Layer<ChildProcessSpawner | Terminal.Terminal> = Layer.unwrap(
  Effect.promise(async () => {
    const bun = typeof Bun !== "undefined";
    try {
      return bun
        ? (await import("@effect/platform-bun/BunServices")).layer
        : (await import("@effect/platform-node/NodeServices")).layer;
    } catch {
      throw new Error(
        `Install ${bun ? "@effect/platform-bun" : "@effect/platform-node"}@^4.0.0 to run the keyservice on this platform, or supply a platform layer`,
      );
    }
  }),
);

// Both entry points own a service scope separately from the platform lifetime.
// Closing the scope must still work if platform construction itself failed.
const acquire = async <A, E, R>(
  layer: Layer.Layer<R>,
  effect: Effect.Effect<A, E, R | Scope.Scope>,
  signal?: AbortSignal,
) => {
  const runtime = ManagedRuntime.make(layer);
  const scope = Scope.makeUnsafe();
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closing ??= Effect.runPromise(Scope.close(scope, Exit.void)).finally(() => runtime.dispose()));
  const result = await runtime.runPromiseExit(Scope.provide(effect, scope), { signal });
  if (Exit.isFailure(result)) {
    await close();
    if (signal?.aborted && Cause.hasInterrupts(result.cause)) throw signal.reason;
    throw Cause.squash(result.cause);
  }
  return { value: result.value, runtime, close };
};

const start = async (
  options: StartKeyServiceOptions,
  signal?: AbortSignal,
): Promise<KeyServiceHandle> => {
  if (
    options.listen !== undefined &&
    (options.network !== undefined ||
      options.address !== undefined ||
      options.tailscale !== undefined)
  )
    throw new Error("Choose listen or network, address, and tailscale");
  if (
    (options.prompt && options.dialog) ||
    (options.interaction && (options.prompt || options.dialog))
  )
    throw new Error("Choose only one of prompt, dialog, or interaction");
  const program = Effect.gen(function* () {
    const listen =
      options.listen ??
      (options.tailscale
        ? Listen.tailscale(
            typeof options.tailscale === "object" ? options.tailscale.port : undefined,
            typeof options.tailscale === "object" ? options.tailscale : undefined,
          )
        : yield* Listen.fromSops(options.network ?? "tcp", options.address ?? "127.0.0.1:5000"));
    let interaction =
      options.interaction === Interaction.none
        ? Interaction.none
        : options.interaction
          ? Interaction.make(options.interaction)
          : options.prompt
            ? yield* Interaction.terminal()
            : options.dialog
              ? yield* Interaction.dialog(
                  typeof options.dialog === "object" ? options.dialog : undefined,
                )
              : Interaction.none;
    // Adapting an existing interaction must not disguise the default approval policy.
    if (options.interaction?.approve === Interaction.none.approve)
      interaction = { ...interaction, approve: Interaction.none.approve };
    if (
      options.rememberApproval !== undefined &&
      !Interaction.approvesAutomatically(interaction)
    )
      interaction = yield* Interaction.remember(interaction, { ttl: options.rememberApproval });
    const forwards =
      options.ssh === undefined
        ? []
        : typeof options.ssh === "string" || "destination" in options.ssh
          ? [options.ssh]
          : options.ssh;
    return yield* serve({
      ...options,
      listen,
      interaction,
      remoteForwards: [
        ...(options.remoteForwards ?? []),
        ...forwards.map((forward) =>
          typeof forward === "string" ? { destination: forward } : forward,
        ),
      ],
    });
  });
  const { value, runtime, close } = await acquire(
    options.layer ?? platformLayer,
    options.verbose ? Effect.provideService(program, References.MinimumLogLevel, "Debug") : program,
    signal,
  );
  return {
    ...value,
    tunnels: value.tunnels.map(({ awaitExit, ...tunnel }) => ({
      ...tunnel,
      exited: runtime.runPromiseExit(awaitExit).then(() => undefined, () => undefined),
    })),
    close,
    [Symbol.asyncDispose]: close,
  };
};

/** Start a keyservice until close or async disposal, rejecting startup with the typed error. */
export const startKeyService = (options: StartKeyServiceOptions = {}): Promise<KeyServiceHandle> =>
  start(options);

/** Serve until SIGINT, SIGTERM, or an AbortSignal, then release listeners, tunnels, and platform services. */
export const runKeyService = async (
  options: StartKeyServiceOptions & { readonly signal?: AbortSignal } = {},
): Promise<void> => {
  const controller = new AbortController();
  const stop = () => controller.abort();
  const stopped = new Promise<void>((resolve) =>
    controller.signal.addEventListener("abort", () => resolve(), { once: true }),
  );
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);
  options.signal?.addEventListener("abort", stop, { once: true });
  let handle: KeyServiceHandle | undefined;
  try {
    if (options.signal?.aborted) stop();
    if (controller.signal.aborted) return;
    handle = await start(options, controller.signal);
    await stopped;
  } catch (error) {
    if (!controller.signal.aborted || error !== controller.signal.reason) throw error;
  } finally {
    process.off("SIGINT", stop);
    process.off("SIGTERM", stop);
    options.signal?.removeEventListener("abort", stop);
    await handle?.close();
  }
};

/** Open a local SSH forward to a remote keyservice until close or async disposal. */
export const openKeyServiceTunnel = async (
  options: SshLocalForwardOptions & { readonly layer?: Layer.Layer<ChildProcessSpawner> },
): Promise<KeyServiceTunnelHandle> => {
  const { value, runtime, close } = await acquire(
    options.layer ?? platformLayer,
    Ssh.localForward(options),
  );
  return {
    uri: value.uri,
    bindHost: value.bindHost,
    bindPort: value.bindPort,
    destination: value.destination,
    exited: runtime.runPromiseExit(value.awaitExit).then(() => undefined, () => undefined),
    close,
    [Symbol.asyncDispose]: close,
  };
};
