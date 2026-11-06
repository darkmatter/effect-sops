/**
 * Shared contracts for the SOPS keyservice server: the request a user is asked
 * to approve, the interaction surface used for approval and age plugin
 * follow-ups (PIN, touch, confirmation), the key handler the gRPC layer calls,
 * listen addresses, SSH forwards, and typed failures.
 *
 * Nothing here carries key material. Data keys only exist inside a
 * {@link KeyHandler} call and the gRPC response serializer.
 */
import * as Data from "effect/Data";
import type * as Duration from "effect/Duration";
import type * as Effect from "effect/Effect";
import type * as Redacted from "effect/Redacted";

// ---------------------------------------------------------------------------
// Keys and requests
// ---------------------------------------------------------------------------

/**
 * The master key a request names (`Key` in upstream `keyservice.proto`).
 * Only `age` is served by this package; the other variants exist so prompts
 * and errors can describe what a client asked for.
 */
export type KeyServiceKey =
  | { readonly type: "age"; readonly recipient: string }
  | { readonly type: "pgp"; readonly fingerprint: string }
  | {
      readonly type: "kms";
      readonly arn: string;
      readonly role: string;
      readonly context: Readonly<Record<string, string>>;
      readonly awsProfile: string;
    }
  | { readonly type: "gcp-kms"; readonly resourceId: string }
  | {
      readonly type: "azure-keyvault";
      readonly vaultUrl: string;
      readonly name: string;
      readonly version: string;
    }
  | {
      readonly type: "vault";
      readonly vaultAddress: string;
      readonly enginePath: string;
      readonly keyName: string;
    }
  | { readonly type: "hckms"; readonly keyId: string };

export type KeyServiceOperation = "decrypt" | "encrypt";

/**
 * What approvers and UIs learn about one incoming RPC.
 *
 * `key` is exactly what the client sent, so its strings are untrusted. Show
 * users {@link KeyServiceRequest.keyDescription} or {@link describeRequest},
 * which are sanitized, never raw `key` fields.
 */
export interface KeyServiceRequest {
  /** Sequential per server, starting at 1. */
  readonly id: number;
  readonly operation: KeyServiceOperation;
  readonly key: KeyServiceKey;
  /** Sanitized human description, e.g. `age key with recipient age1…`. */
  readonly keyDescription: string;
  /** gRPC peer as reported by the transport, e.g. `127.0.0.1:53422`, `ipv4:100.64.1.2:53422`, or `unix:/tmp/sops.sock`. */
  readonly peer: string;
  /** Peer host without port when it can be parsed (`100.64.1.2`, `::1`); undefined for Unix sockets. */
  readonly peerHost: string | undefined;
  readonly receivedAt: Date;
}

// Control characters (C0, DEL, C1) and bidirectional overrides let a client
// rewrite a terminal prompt or reorder dialog text.
const unsafeDisplayCharacters =
  /[\u0000-\u001f\u007f-\u009f؜‎‏‪-‮⁦-⁩]/g;

/**
 * Make an untrusted string safe to show in a prompt: unsafe characters become
 * `?` and the result is truncated to `max` characters.
 */
export const sanitizeForDisplay = (text: string, max = 160): string => {
  const safe = text.replace(unsafeDisplayCharacters, "?");
  return safe.length > max ? `${safe.slice(0, max - 1)}…` : safe;
};

/** One line for prompts and logs, e.g. `decrypt request from 100.64.1.2 using age key with recipient age1…`. */
export const describeRequest = (request: KeyServiceRequest): string =>
  `${request.operation} request from ${sanitizeForDisplay(
    request.peerHost ?? request.peer,
    80,
  )} using ${request.keyDescription}`;

// ---------------------------------------------------------------------------
// Interaction: approval gate and age plugin follow-ups
// ---------------------------------------------------------------------------

/** Who is asking when an age plugin wants to talk to the user. */
export interface PluginPromptContext {
  /** Plugin name, e.g. `yubikey` for `age-plugin-yubikey`. */
  readonly plugin: string;
  /** The keyservice request the plugin is serving, when there is one. */
  readonly request: KeyServiceRequest | undefined;
}

/**
 * The user-facing side of the keyservice: `--prompt`-style approval plus the
 * age plugin client UI (`msg`, `request-secret`, `request-public`, `confirm`).
 *
 * Implementations close over whatever services they need when constructed
 * (a `Terminal`, a `ChildProcessSpawner`), so every method here is
 * requirement-free. The server serializes requests, so an implementation never
 * has to handle two prompts at once.
 */
export interface KeyServiceInteraction {
  /**
   * Decide whether to serve a request. Runs before any key material is
   * touched. `false` is reported to the client as `PERMISSION_DENIED`.
   */
  readonly approve: (
    request: KeyServiceRequest,
  ) => Effect.Effect<boolean, KeyServiceInteractionError>;
  /** age plugin `msg`: show a message; the plugin waits for acknowledgement. */
  readonly displayMessage: (
    context: PluginPromptContext,
    message: string,
  ) => Effect.Effect<void, KeyServiceInteractionError>;
  /** age plugin `request-secret` (e.g. a YubiKey PIN) or `request-public`. */
  readonly requestValue: (
    context: PluginPromptContext,
    prompt: string,
    secret: boolean,
  ) => Effect.Effect<Redacted.Redacted<string>, KeyServiceInteractionError>;
  /** age plugin `confirm`: `true` when the user chose `yes`. `no` may be absent. */
  readonly confirm: (
    context: PluginPromptContext,
    prompt: string,
    yes: string,
    no: string | undefined,
  ) => Effect.Effect<boolean, KeyServiceInteractionError>;
  /**
   * The plugin has been silent for a while (age clients use 5 seconds), which
   * usually means it is waiting for a hardware touch. Best effort; never fails.
   */
  readonly waiting: (context: PluginPromptContext) => Effect.Effect<void>;
}

// ---------------------------------------------------------------------------
// Key handling (what the gRPC layer calls)
// ---------------------------------------------------------------------------

export interface KeyHandlerInput {
  readonly request: KeyServiceRequest;
  /** The interaction for plugin follow-ups during this request. */
  readonly interaction: KeyServiceInteraction;
}

/**
 * Serves `KeyService.Decrypt` / `KeyService.Encrypt` for the keys it supports.
 * The server calls {@link KeyHandler.preflight} before asking for approval, so
 * users are never prompted for a key this service cannot use.
 */
export interface KeyHandler {
  /**
   * Fail fast with `UnsupportedKey` or `NoMatchingIdentity` when this handler
   * cannot serve `key` for `operation`. Must not touch key material or prompt.
   */
  readonly preflight: (
    operation: KeyServiceOperation,
    key: KeyServiceKey,
  ) => Effect.Effect<void, KeyServiceError>;
  /** Unwrap a SOPS data key. `ciphertext` is the master key's encrypted data key (armored age for age keys). */
  readonly decrypt: (
    input: KeyHandlerInput & { readonly ciphertext: Uint8Array },
  ) => Effect.Effect<Uint8Array, KeyServiceError>;
  /** Wrap a SOPS data key for the request's key. Returns the encrypted data key bytes. */
  readonly encrypt: (
    input: KeyHandlerInput & { readonly plaintext: Uint8Array },
  ) => Effect.Effect<Uint8Array, KeyServiceError>;
}

/** Options for the built-in age key handler. */
export interface AgeKeyServiceOptions {
  /** Identity strings: `AGE-SECRET-KEY-1…`, `AGE-SECRET-KEY-PQ-1…`, or plugin identities `AGE-PLUGIN-<NAME>-1…`. */
  readonly identities?: ReadonlyArray<string | Redacted.Redacted<string>>;
  /** keys.txt-format files, re-read on every request. */
  readonly identityFiles?: ReadonlyArray<string>;
  /**
   * Discover identities the way `sops` does, on every request:
   * `SOPS_AGE_KEY`, `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY_CMD`, then the user
   * `sops/age/keys.txt` (`$XDG_CONFIG_HOME` first on macOS).
   * Default: `true` unless `identities` or `identityFiles` is set.
   */
  readonly discover?: boolean;
  /** Environment used for discovery. Default: `process.env` when the handler is created. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /**
   * Plugins that may be spawned for Encrypt requests to plugin recipients
   * (`age1<name>1…`). Recipients come from the network, so this is an
   * allowlist. Default: the plugins named by the loaded identities.
   */
  readonly encryptPlugins?: ReadonlyArray<string>;
  /** Resolve a plugin name to its executable. Default: `age-plugin-<name>` on `PATH`. */
  readonly pluginBinary?: (name: string) => string;
}

// ---------------------------------------------------------------------------
// Listening and forwarding
// ---------------------------------------------------------------------------

/** Where to accept connections. `Tailscale` resolves to this machine's tailnet address. */
export type ListenAddress =
  | { readonly _tag: "Tcp"; readonly host: string; readonly port: number }
  | { readonly _tag: "Unix"; readonly path: string }
  | { readonly _tag: "Tailscale"; readonly port: number; readonly family: 4 | 6 };

/** A listen address after Tailscale resolution: what the gRPC server binds. */
export type ResolvedListenAddress =
  | { readonly _tag: "Tcp"; readonly host: string; readonly port: number }
  | { readonly _tag: "Unix"; readonly path: string };

/** One listener the server actually bound. */
export interface BoundAddress {
  readonly requested: ListenAddress;
  /** With the real port when `0` was requested. */
  readonly address: ResolvedListenAddress;
  /** SOPS keyservice URI for this listener: `tcp://host:port` or `unix:///abs/path`. */
  readonly uri: string;
}

export interface SshCommonOptions {
  /** ssh destination exactly as you would pass it to `ssh`: `user@host`, `host`, or a `~/.ssh/config` alias. */
  readonly destination: string;
  /** ssh executable. Default: `ssh` on `PATH`. */
  readonly ssh?: string;
  /** Extra ssh arguments placed before the destination, e.g. `["-p", "2222", "-i", key]`. */
  readonly sshArgs?: ReadonlyArray<string>;
  /** How long to wait for the forward to come up. Default: 15 seconds. */
  readonly readyTimeout?: Duration.Input;
}

/** `ssh -L localPort:remoteHost:remotePort destination`: reach a keyservice that runs on (or near) the remote host. */
export interface SshLocalForwardOptions extends SshCommonOptions {
  /** Default `127.0.0.1`. */
  readonly localHost?: string;
  /** Default: a free ephemeral port. */
  readonly localPort?: number;
  /** Host to connect to from the remote side. Default `127.0.0.1`. */
  readonly remoteHost?: string;
  /** Port to connect to from the remote side. Default `5000`. */
  readonly remotePort?: number;
}

/** `ssh -R remotePort:target destination`: expose a local keyservice on the remote host. */
export interface SshRemoteForwardOptions extends SshCommonOptions {
  /** Remote bind address. Default `127.0.0.1` (loopback on the remote host). */
  readonly remoteHost?: string;
  /** Remote port. Default `5000`; `0` lets sshd allocate one. */
  readonly remotePort?: number;
  /** Local target the remote side reaches: the keyservice listener. */
  readonly target:
    | { readonly _tag: "Tcp"; readonly host: string; readonly port: number }
    | { readonly _tag: "Unix"; readonly path: string };
}

/** A running SSH forward. Closing its scope stops `ssh`. */
export interface SshTunnel {
  readonly direction: "local" | "remote";
  readonly destination: string;
  /**
   * SOPS keyservice URI usable where the forward listens: on this machine for
   * `local`, on the remote host for `remote`.
   */
  readonly uri: string;
  readonly bindHost: string;
  readonly bindPort: number;
  /** Completes when `ssh` exits for any reason, including scope close. */
  readonly awaitExit: Effect.Effect<void>;
}

// ---------------------------------------------------------------------------
// Server core
// ---------------------------------------------------------------------------

/** Inputs for the gRPC server once addresses are resolved and handlers built. */
export interface KeyServiceServerOptions {
  readonly addresses: ReadonlyArray<{
    readonly requested: ListenAddress;
    readonly resolved: ResolvedListenAddress;
  }>;
  readonly keys: KeyHandler;
  readonly interaction: KeyServiceInteraction;
  /** Upper bound for one request, including approval and plugin interaction. Default: 2 minutes. */
  readonly requestTimeout?: Duration.Input;
  /** Log request metadata (never key material). Default: `true`. */
  readonly logRequests?: boolean;
  /** File mode applied to Unix sockets after binding. Default: `0o600`. */
  readonly socketMode?: number;
}

export interface KeyServiceServer {
  readonly addresses: ReadonlyArray<BoundAddress>;
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** An interaction could not complete. */
export class KeyServiceInteractionError extends Data.TaggedError(
  "KeyServiceInteractionError",
)<{
  readonly reason: "Unavailable" | "Cancelled" | "TimedOut" | "Failed";
  readonly message: string;
  readonly cause?: unknown;
}> {}

export type KeyServiceErrorReason =
  /** The request carried no key (`Must provide a key`). */
  | "MissingKey"
  /** The key type is not served here (e.g. AWS KMS). */
  | "UnsupportedKey"
  /** No configured identity can serve the key. */
  | "NoMatchingIdentity"
  /** The user declined, or cancelled a follow-up such as a PIN prompt. */
  | "Denied"
  /** The interaction cannot run (no TTY, no dialog support). */
  | "InteractionUnavailable"
  /** An age plugin failed or reported an error. */
  | "PluginFailed"
  /** Malformed ciphertext, recipient, or data key. */
  | "InvalidRequest"
  | "TimedOut"
  | "Internal";

/** A request failed. Messages are safe to return to clients: no key material, no file contents. */
export class KeyServiceError extends Data.TaggedError("KeyServiceError")<{
  readonly reason: KeyServiceErrorReason;
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** The age plugin client protocol failed. */
export class AgePluginError extends Data.TaggedError("AgePluginError")<{
  readonly plugin: string;
  readonly reason:
    | "InvalidName"
    | "NotFound"
    | "Protocol"
    | "PluginError"
    | "Interaction"
    | "Exited";
  readonly message: string;
  readonly cause?: unknown;
}> {}

/** A listen address could not be resolved or bound. */
export class KeyServiceListenError extends Data.TaggedError(
  "KeyServiceListenError",
)<{
  readonly reason: "InvalidAddress" | "TailscaleUnavailable" | "BindFailed";
  readonly message: string;
  readonly address?: string;
  readonly cause?: unknown;
}> {}

/** An SSH forward could not be started or died before it was ready. */
export class SshTunnelError extends Data.TaggedError("SshTunnelError")<{
  readonly reason:
    | "InvalidOptions"
    | "SpawnFailed"
    | "ForwardFailed"
    | "Exited"
    | "TimedOut";
  readonly message: string;
  readonly destination: string;
  /** Tail of ssh's stderr, when available. */
  readonly stderr?: string;
  readonly cause?: unknown;
}> {}
