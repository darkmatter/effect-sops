#!/usr/bin/env bun
import * as Effect from "effect/Effect";
import { isIPv4 } from "node:net";
import { isAbsolute } from "node:path";
import {
  AgeIdentityConfigError,
  resolveAgeIdentities,
} from "./keyservice-identity.js";
import {
  KeyServiceBindError,
  startKeyService,
} from "./keyservice-server.js";
import { KeyServiceIdentityError } from "./keyservice-rpc.js";

export interface CliOptions {
  readonly network: "tcp" | "unix";
  readonly address: string;
  readonly warnNonLoopback: boolean;
}

export type CliArgs =
  | { readonly kind: "help" }
  | { readonly kind: "run"; readonly options: CliOptions }
  | { readonly kind: "error"; readonly message: string };

const usage = `Usage: effect-sops-keyservice [--network tcp|unix] [--address ADDRESS]

Serve the SOPS age keyservice over unauthenticated gRPC.

Options:
  --network tcp|unix   Transport to listen on (default: tcp)
  --address ADDRESS    TCP host:port (default: 127.0.0.1:5000), or an
                       absolute Unix socket path with --network unix
  -h, --help           Show this help and exit

Age identities are read from SOPS_AGE_KEY, then SOPS_AGE_KEY_FILE, then the
default sops/age key file. Private keys are never accepted as arguments.`;

interface TcpTarget {
  readonly host: string;
  readonly port: number;
}

const parseTcpTarget = (value: string): TcpTarget | undefined => {
  try {
    const url = new URL(`tcp://${value}`);
    if (
      !url.hostname ||
      !url.port ||
      url.username ||
      url.password ||
      url.search ||
      url.hash ||
      url.pathname !== ""
    ) {
      return undefined;
    }
    const port = Number(url.port);
    if (!Number.isInteger(port) || port < 0 || port > 65_535) return undefined;
    return { host: url.hostname.replace(/^\[|\]$/g, ""), port };
  } catch {
    return undefined;
  }
};

export const parseArgs = (argv: readonly string[]): CliArgs => {
  let network: string | undefined;
  let address: string | undefined;

  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index] ?? "";
    if (argument === "--help" || argument === "-h") return { kind: "help" };

    const equals = argument.indexOf("=");
    const flag = equals === -1 ? argument : argument.slice(0, equals);
    const inline = equals === -1 ? undefined : argument.slice(equals + 1);
    if (flag !== "--network" && flag !== "--address") {
      return { kind: "error", message: "Unknown argument; use --help for usage" };
    }
    const value = inline ?? argv[index + 1];
    if (value === undefined || value.startsWith("--")) {
      return { kind: "error", message: `Missing value for ${flag}` };
    }
    if (inline === undefined) index += 1;
    if (flag === "--network") network = value;
    else address = value;
  }

  const selected = network ?? "tcp";
  if (selected !== "tcp" && selected !== "unix") {
    return {
      kind: "error",
      message: "Unsupported network (expected tcp or unix)",
    };
  }

  if (selected === "unix") {
    if (address === undefined || !isAbsolute(address)) {
      return {
        kind: "error",
        message: "The unix network requires an absolute --address socket path",
      };
    }
    return {
      kind: "run",
      options: { network: "unix", address, warnNonLoopback: false },
    };
  }

  const tcpAddress = address ?? "127.0.0.1:5000";
  const target = parseTcpTarget(tcpAddress);
  if (target === undefined) {
    return {
      kind: "error",
      message: "Invalid TCP address (expected host:port)",
    };
  }
  const host = target.host;
  const loopback =
    host === "localhost" || host === "::1" || (isIPv4(host) && host.startsWith("127."));
  return {
    kind: "run",
    options: {
      network: "tcp",
      address: tcpAddress,
      warnNonLoopback: !loopback,
    },
  };
};

const waitForShutdownSignal = (onReady: () => void): Effect.Effect<void> =>
  Effect.callback<void>((resume) => {
    let signaled = false;
    const stop = () => {
      if (signaled) return;
      signaled = true;
      resume(Effect.void);
    };
    process.once("SIGINT", stop);
    process.once("SIGTERM", stop);
    onReady();
    return Effect.sync(() => {
      process.off("SIGINT", stop);
      process.off("SIGTERM", stop);
    });
  });

export const main = async (
  argv: readonly string[] = process.argv.slice(2),
): Promise<number> => {
  const parsed = parseArgs(argv);
  if (parsed.kind === "error") {
    process.stderr.write(`${parsed.message}\n\n${usage}\n`);
    return 1;
  }
  if (parsed.kind === "help") {
    process.stdout.write(`${usage}\n`);
    return 0;
  }

  const { network, address, warnNonLoopback } = parsed.options;
  const target = network === "unix" ? `unix:${address}` : address;
  try {
    await Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const identities = yield* resolveAgeIdentities({ env: process.env });
          const handle = yield* startKeyService({ identities, address: target });
          yield* waitForShutdownSignal(() => {
            if (warnNonLoopback) {
              process.stderr.write(
                "effect-sops-keyservice: warning: listening on a non-loopback address without authentication or TLS\n",
              );
            }
            process.stderr.write(
              `effect-sops-keyservice listening on ${handle.uri}\n`,
            );
          });
        }),
      ),
    );
    return 0;
  } catch (cause) {
    const message =
      cause instanceof AgeIdentityConfigError ||
      cause instanceof KeyServiceIdentityError ||
      cause instanceof KeyServiceBindError
        ? cause.message
        : "Unexpected keyservice failure";
    process.stderr.write(`effect-sops-keyservice: ${message}\n`);
    return 1;
  }
};

if (import.meta.main) {
  process.exitCode = await main();
}
