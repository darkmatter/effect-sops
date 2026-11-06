/** Scoped OpenSSH forwards for reaching and sharing SOPS keyservices. */
import * as net from "node:net";
import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Scope from "effect/Scope";
import * as Exit from "effect/Exit";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import { hostPort, keyServiceUri } from "./address.js";
import {
  sanitizeForDisplay,
  SshTunnelError,
  type SshCommonOptions,
  type SshLocalForwardOptions,
  type SshRemoteForwardOptions,
  type SshTunnel,
} from "./model.js";

// ControlMaster/ControlPath: a host configured for multiplexing would hand the
// forward to an existing master, where it outlives this process and its
// readiness messages never reach our stderr. Each tunnel owns its connection.
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
const tailLimit = 8192;
const error = (
  options: SshCommonOptions,
  reason: SshTunnelError["reason"],
  message: string,
  stderr?: string,
) =>
  new SshTunnelError({
    reason,
    message,
    destination: sanitizeForDisplay(options.destination),
    ...(stderr === undefined
      ? {}
      : { stderr: sanitizeForDisplay(stderr, tailLimit) }),
  });

function validate(
  options: SshCommonOptions,
  hosts: ReadonlyArray<string>,
  ports: ReadonlyArray<number>,
) {
  if (
    !options.destination ||
    /^-/.test(options.destination) ||
    /[\s\u0000-\u001f\u007f-\u009f]/u.test(options.destination)
  )
    throw error(
      options,
      "InvalidOptions",
      "SSH destination must be non-empty, contain no whitespace or controls, and not start with '-'",
    );
  if (ports.some((port) => !Number.isInteger(port) || port < 0 || port > 65535))
    throw error(
      options,
      "InvalidOptions",
      "SSH ports must be integers between 0 and 65535",
    );
  if (
    hosts.some(
      (host) =>
        !host ||
        (net.isIP(host) === 0 && !/^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$/.test(host)),
    )
  )
    throw error(
      options,
      "InvalidOptions",
      "SSH hosts must be IP addresses or host names without delimiters",
    );
}

/** Build verbose `-L` arguments, preserving first-value precedence for user SSH options. Throws InvalidOptions for invalid inputs. */
export const localForwardArgs = (
  options: SshLocalForwardOptions,
  localPort: number,
): ReadonlyArray<string> => {
  const host = options.localHost ?? "127.0.0.1";
  const remoteHost = options.remoteHost ?? "127.0.0.1";
  const remotePort = options.remotePort ?? 5000;
  validate(
    options,
    [host, remoteHost],
    [localPort, remotePort, options.localPort ?? 0],
  );
  return [
    ...(options.sshArgs ?? []),
    ...defaults,
    "-v",
    "-L",
    `${hostPort(host, localPort)}:${hostPort(remoteHost, remotePort)}`,
    "--",
    options.destination,
  ];
};

/** Build verbose `-R` arguments for a TCP or Unix target. Throws InvalidOptions for invalid inputs. */
export const remoteForwardArgs = (
  options: SshRemoteForwardOptions,
): ReadonlyArray<string> => {
  const host = options.remoteHost ?? "127.0.0.1";
  const port = options.remotePort ?? 5000;
  const target = options.target;
  validate(
    options,
    [host, ...(target._tag === "Tcp" ? [target.host] : [])],
    [port, ...(target._tag === "Tcp" ? [target.port] : [])],
  );
  if (
    target._tag === "Unix" &&
    (!target.path.startsWith("/") ||
      /[\u0000-\u001f\u007f-\u009f]/u.test(target.path))
  )
    throw error(
      options,
      "InvalidOptions",
      "SSH Unix targets require an absolute path without control characters",
    );
  return [
    ...(options.sshArgs ?? []),
    ...defaults,
    "-v",
    "-R",
    `${hostPort(host, port)}:${
      target._tag === "Tcp" ? hostPort(target.host, target.port) : target.path
    }`,
    "--",
    options.destination,
  ];
};

const freePort = (host: string, port: number, options: SshCommonOptions) =>
  Effect.callback<number, SshTunnelError>((resume, signal) => {
    const server = net.createServer();
    server.once("error", (cause: NodeJS.ErrnoException) =>
      resume(
        Effect.fail(
          error(
            options,
            "ForwardFailed",
            port !== 0 && cause.code === "EADDRINUSE"
              ? `local port ${port} is already in use`
              : "Could not reserve a local SSH port",
          ),
        ),
      ),
    );
    server.listen({ port, host, signal }, () => {
      if (signal.aborted) {
        server.close();
        return;
      }
      const address = server.address();
      server.close(() => {
        if (address && typeof address !== "string")
          resume(Effect.succeed(address.port));
        else
          resume(
            Effect.fail(
              error(
                options,
                "ForwardFailed",
                "Could not determine the local SSH port",
              ),
            ),
          );
      });
    });
    return Effect.sync(() => {
      server.close();
    });
  });

const spawnForward = Effect.fn("Ssh.spawnForward")(function* (
  options: SshCommonOptions,
  args: ReadonlyArray<string>,
  direction: SshTunnel["direction"],
  host: string,
  port: number,
) {
  const spawner = yield* ChildProcessSpawner;
  const child = yield* spawner
    .spawn(
      ChildProcess.make(options.ssh ?? "ssh", args, {
        stdin: "ignore",
        stdout: "ignore",
        stderr: "pipe",
        forceKillAfter: "1 second",
      }),
    )
    .pipe(
      Effect.mapError(() =>
        error(options, "SpawnFailed", "Could not start the SSH executable"),
      ),
    );
  const ready = yield* Deferred.make<number, SshTunnelError>();
  const drained = yield* Deferred.make<void>();
  let tail = "";
  let pending = "";
  let allocated: number | undefined = port === 0 ? undefined : port;
  let succeeded = false;
  let localListening = false;
  const line = (value: string) =>
    Effect.gen(function* () {
      if (direction === "local") {
        if (
          /Could not request local forwarding|cannot listen to port|Address already in use/i.test(
            value,
          )
        )
          yield* Deferred.fail(
            ready,
            error(options, "ForwardFailed", "SSH local forwarding failed", tail),
          );
        else {
          const match = /Local forwarding listening on (\S+) port (\d+)\./.exec(
            value,
          );
          // Jump hops share stderr. Require our listener before session entry;
          // the listening message itself precedes bind and may still fail.
          if (
            match &&
            match[1]?.replace(/^\[|\]$/g, "") === host &&
            Number(match[2]) === port
          )
            localListening = true;
          else if (
            localListening && value.includes("Entering interactive session")
          )
            yield* Deferred.succeed(ready, port);
        }
        return;
      }
      if (
        /remote forward failure for: listen|Warning: remote port forwarding failed/i.test(
          value,
        )
      )
        yield* Deferred.fail(
          ready,
          error(options, "ForwardFailed", "SSH remote forwarding failed", tail),
        );
      const match = /Allocated port (\d+) for remote forward/.exec(value);
      if (match) {
        const parsed = Number(match[1]);
        if (Number.isInteger(parsed) && parsed > 0 && parsed <= 65535)
          allocated = parsed;
      }
      if (value.includes("remote forward success for: listen"))
        succeeded = true;
      if (succeeded && allocated !== undefined)
        yield* Deferred.succeed(ready, allocated);
    });
  // Both the retained diagnostics and unfinished line are bounded, even if ssh never emits a newline.
  const drain = child.stderr.pipe(
    Stream.decodeText(),
    Stream.runForEach((chunk) =>
      Effect.gen(function* () {
        tail = (tail + chunk).slice(-tailLimit);
        const lines = (pending + chunk).split("\n");
        pending = (lines.pop() ?? "").slice(-tailLimit);
        for (const value of lines) yield* line(value);
      }),
    ),
    Effect.andThen(Effect.suspend(() => line(pending))),
    Effect.catch(() =>
      Deferred.fail(
        ready,
        error(options, "Exited", "Could not read SSH diagnostics", tail),
      ),
    ),
    Effect.ensuring(Deferred.succeed(drained, undefined)),
  );
  yield* Effect.forkScoped(drain);
  const exited = Effect.gen(function* () {
    yield* Effect.exit(child.exitCode);
    yield* Deferred.await(drained);
    return yield* Effect.fail(
      error(options, "Exited", "SSH exited before the forward was ready", tail),
    );
  });
  const bindPort = yield* Effect.raceFirst(Deferred.await(ready), exited).pipe(
    Effect.timeoutOrElse({
      duration: options.readyTimeout ?? "15 seconds",
      orElse: () =>
        Effect.fail(
          error(
            options,
            "TimedOut",
            "SSH forward did not become ready before the timeout",
            tail,
          ),
        ),
    }),
  );
  return {
    direction,
    destination: options.destination,
    bindHost: host,
    bindPort,
    uri: keyServiceUri({ _tag: "Tcp", host, port: bindPort }),
    awaitExit: Effect.asVoid(Effect.exit(child.exitCode)),
  } satisfies SshTunnel;
});

const start = Effect.fn("Ssh.start")(function* (
  options: SshCommonOptions,
  args: ReadonlyArray<string>,
  direction: SshTunnel["direction"],
  host: string,
  port: number,
) {
  const scope = yield* Scope.fork(yield* Effect.scope);
  // Failed startup must release the child even when its caller catches the error inside a live scope.
  return yield* spawnForward(options, args, direction, host, port).pipe(
    Scope.provide(scope),
    Effect.onError((cause) => Scope.close(scope, Exit.failCause(cause))),
  );
});

/** Reach a remote keyservice through a scoped `ssh -L` tunnel. */
export const localForward: (
  options: SshLocalForwardOptions,
) => Effect.Effect<
  SshTunnel,
  SshTunnelError,
  Scope.Scope | ChildProcessSpawner
> = Effect.fn("Ssh.localForward")(function* (options) {
  yield* Effect.try({
    try: () => localForwardArgs(options, options.localPort ?? 0),
    catch: (cause) =>
      cause instanceof SshTunnelError
        ? cause
        : error(options, "InvalidOptions", "Invalid local SSH options"),
  });
  const host = options.localHost ?? "127.0.0.1";
  const port = yield* freePort(host, options.localPort ?? 0, options);
  return yield* start(
    options,
    localForwardArgs(options, port),
    "local",
    host,
    port,
  );
});

/** Expose a local TCP or Unix keyservice through a scoped `ssh -R` tunnel; its URI is for the remote host. */
export const remoteForward: (
  options: SshRemoteForwardOptions,
) => Effect.Effect<
  SshTunnel,
  SshTunnelError,
  Scope.Scope | ChildProcessSpawner
> = Effect.fn("Ssh.remoteForward")(function* (options) {
  const args = yield* Effect.try({
    try: () => remoteForwardArgs(options),
    catch: (cause) =>
      cause instanceof SshTunnelError
        ? cause
        : error(options, "InvalidOptions", "Invalid remote SSH options"),
  });
  return yield* start(
    options,
    args,
    "remote",
    options.remoteHost ?? "127.0.0.1",
    options.remotePort ?? 5000,
  );
});
