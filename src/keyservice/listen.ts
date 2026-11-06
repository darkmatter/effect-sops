import { isIP } from "node:net";
import * as os from "node:os";
import { resolve as absolutePath } from "node:path";
import * as Effect from "effect/Effect";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import { hostPort } from "./address.js";
import {
  KeyServiceListenError,
  sanitizeForDisplay,
  type ListenAddress,
  type ResolvedListenAddress,
} from "./model.js";

/** A TCP listener; validation is performed by {@link resolve}. */
export const tcp = (host: string, port: number): ListenAddress => ({
  _tag: "Tcp",
  host,
  port,
});

/** 127.0.0.1:port, defaulting to the SOPS keyservice port 5000. */
export const loopback = (port = 5000): ListenAddress => tcp("127.0.0.1", port);

/** A Unix socket listener; relative paths are made absolute by {@link resolve}. */
export const unix = (path: string): ListenAddress => ({ _tag: "Unix", path });

/** This machine's Tailscale address, defaulting to IPv4 and port 5000. */
export const tailscale = (
  port = 5000,
  options?: { readonly family?: 4 | 6 },
): ListenAddress => ({ _tag: "Tailscale", port, family: options?.family ?? 4 });

const invalid = (message: string) =>
  new KeyServiceListenError({ reason: "InvalidAddress", message });

const validatePort = (port: number): void => {
  if (!Number.isInteger(port) || port < 0 || port > 65535)
    throw invalid("Listener port must be an integer between 0 and 65535");
};

const validate = (address: ListenAddress): void => {
  if (address._tag === "Unix") {
    if (!address.path || /[\u0000-\u001f\u007f]/.test(address.path))
      throw invalid(
        "Unix socket path must be non-empty and contain no control characters",
      );
    return;
  }
  validatePort(address.port);
  if (address._tag === "Tailscale") {
    if (address.family !== 4 && address.family !== 6)
      throw invalid("Tailscale address family must be 4 or 6");
    return;
  }
  const host = address.host;
  const hostname = host.endsWith(".") ? host.slice(0, -1) : host;
  if (isIP(host)) return;
  if (
    hostname.length === 0 ||
    hostname.length > 253 ||
    /^[\d.]+$/.test(hostname) ||
    !hostname
      .split(".")
      .every((label) => /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/i.test(label))
  )
    throw invalid(
      `Invalid TCP listener host: ${sanitizeForDisplay(hostPort(host, address.port))}`,
    );
};

const parseSops = (network: "tcp" | "unix", address: string): ListenAddress => {
  if (network === "unix") {
    const parsed = unix(address);
    validate(parsed);
    return parsed;
  }
  if (network !== "tcp") throw invalid("Listener network must be tcp or unix");
  const parts = /^(?:\[([^\]]+)\]|([^:]*)):(\d+)$/.exec(address);
  const host = parts?.[1] ?? parts?.[2];
  if (parts && !host)
    throw invalid(
      `an empty host would listen on every interface; pass 0.0.0.0:${parts[3]} or [::]:${parts[3]} explicitly`,
    );
  if (!parts || !host || (parts[1] && isIP(host) !== 6))
    throw invalid("TCP listener address must be host:port or [IPv6]:port");
  const parsed = tcp(host, Number(parts[3]));
  validate(parsed);
  return parsed;
};

/** Parse a SOPS tcp|unix address; wildcard TCP hosts must be explicit. */
export const fromSops = (
  network: "tcp" | "unix",
  address: string,
): Effect.Effect<ListenAddress, KeyServiceListenError> =>
  Effect.try({
    try: () => parseSops(network, address),
    catch: (cause) =>
      cause instanceof KeyServiceListenError
        ? cause
        : invalid("Invalid listener address"),
  });

/** Parse a `tcp://host:port` or `unix:///absolute/path` keyservice URI. */
export const fromUri = (
  uri: string,
): Effect.Effect<ListenAddress, KeyServiceListenError> =>
  Effect.try({
    try: () => {
      if (uri.startsWith("tcp://")) return parseSops("tcp", uri.slice(6));
      if (!uri.startsWith("unix:///"))
        throw invalid(
          "Keyservice URI must use tcp:// or unix:/// with an absolute path",
        );
      // A URI must not silently discard authority, query, or fragment components.
      if (/[?#]/.test(uri))
        throw invalid("Unix keyservice URI cannot include a query or fragment");
      return parseSops("unix", decodeURIComponent(uri.slice(7)));
    },
    catch: (cause) =>
      cause instanceof KeyServiceListenError
        ? cause
        : invalid("Invalid keyservice URI encoding"),
  });

/** Platform discovery overrides for resolving this machine's Tailscale address. */
export interface ResolveOptions {
  /** Executable used when interface discovery is ambiguous; default `tailscale`. */
  readonly tailscaleBinary?: string;
  /** Interface discovery override; default `os.networkInterfaces`. */
  readonly networkInterfaces?: () => NodeJS.Dict<
    ReadonlyArray<os.NetworkInterfaceInfo>
  >;
}

const isTailscaleAddress = (address: string, family: 4 | 6): boolean => {
  if (isIP(address) !== family) return false;
  if (family === 6) return /^fd7a:115c:a1e0:/i.test(address);
  const [first, second] = address.split(".").map(Number);
  return first === 100 && second !== undefined && second >= 64 && second <= 127;
};

/** Resolve this machine's Tailscale IP, scanning interfaces before invoking the CLI. */
export const tailscaleAddress: (
  options?: ResolveOptions & { readonly family?: 4 | 6 },
) => Effect.Effect<string, KeyServiceListenError, ChildProcessSpawner> =
  Effect.fn("KeyServiceListen.tailscaleAddress")(function* (options = {}) {
    const family = options.family ?? 4;
    if (family !== 4 && family !== 6)
      return yield* Effect.fail(
        invalid("Tailscale address family must be 4 or 6"),
      );
    const unavailable = (detail: string) =>
      new KeyServiceListenError({
        reason: "TailscaleUnavailable",
        message: `Is Tailscale running? \`tailscale ip -${family}\` ${detail}`,
      });
    const interfaces = yield* Effect.try({
      try: options.networkInterfaces ?? os.networkInterfaces,
      catch: () => unavailable("could not inspect network interfaces"),
    }).pipe(Effect.orElseSucceed(() => ({})));
    const candidates = new Set(
      Object.values(interfaces).flatMap((entries) => {
        // CGNAT alone is shared with carriers and other VPNs; qualify each interface.
        if (
          !entries?.some(
            (entry) => !entry.internal && isTailscaleAddress(entry.address, 6),
          )
        )
          return [];
        return entries
          .filter(
            (entry) =>
              !entry.internal && isTailscaleAddress(entry.address, family),
          )
          .map((entry) => entry.address);
      }),
    );
    if (candidates.size === 1) return candidates.values().next().value!;
    const spawner = yield* ChildProcessSpawner;
    return yield* Effect.gen(function* () {
      const child = yield* spawner.spawn(
        ChildProcess.make(
          options.tailscaleBinary ?? "tailscale",
          ["ip", `-${family}`],
          { stdin: "ignore", stdout: "pipe", stderr: "ignore" },
        ),
      );
      const [output, code] = yield* Effect.all(
        [
          child.stdout.pipe(Stream.decodeText(), Stream.mkString),
          child.exitCode,
        ],
        { concurrency: "unbounded" },
      );
      if (code !== 0)
        return yield* Effect.fail(unavailable(`exited with status ${code}`));
      const first = output
        .split(/\r?\n/)
        .map((line) => line.trim())
        .find((line) => line.length > 0);
      if (!first) return yield* Effect.fail(unavailable("printed nothing"));
      if (isIP(first) !== family)
        return yield* Effect.fail(
          unavailable(`did not print an IPv${family} address`),
        );
      return first;
    }).pipe(
      Effect.scoped,
      Effect.mapError((cause) =>
        cause instanceof KeyServiceListenError
          ? cause
          : unavailable("could not be executed"),
      ),
    );
  });

/** Validate a listener, resolve Tailscale, and make Unix socket paths absolute. */
export const resolve: (
  address: ListenAddress,
  options?: ResolveOptions,
) => Effect.Effect<
  ResolvedListenAddress,
  KeyServiceListenError,
  ChildProcessSpawner
> = Effect.fn("KeyServiceListen.resolve")(function* (address, options) {
  yield* Effect.try({
    try: () => validate(address),
    catch: (cause) =>
      cause instanceof KeyServiceListenError
        ? cause
        : invalid("Invalid listener address"),
  });
  if (address._tag === "Unix")
    return { _tag: "Unix", path: absolutePath(address.path) };
  if (address._tag === "Tcp") return address;
  const host = yield* tailscaleAddress({ ...options, family: address.family });
  return { _tag: "Tcp", host, port: address.port };
});
