import * as Deferred from "effect/Deferred";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

import { keyServiceSettings, type SopsKeyServiceOptions } from "./keyservice-options.js";

import { SopsDecryptError } from "./errors.js";

export type SopsCliFormat = "json" | "yaml" | "dotenv" | "binary";
export type SopsBackend = "auto" | "cli" | "sops-age";

export interface SopsCommandRequest extends SopsKeyServiceOptions {
  readonly path?: string;
  readonly content?: string | Redacted.Redacted<string>;
  readonly url?: string | Redacted.Redacted<string>;
  readonly cwd?: string;
  readonly binary: string;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly extract?: string;
  readonly args?: readonly string[];
  readonly env?: Record<string, string | Redacted.Redacted<string>>;
  readonly timeoutMs?: number;
}

export type SopsDecrypt = (
  request: SopsCommandRequest,
) => Effect.Effect<string, SopsDecryptError>;

export interface SopsDecryptMemoizeOptions {
  readonly key?: (request: SopsCommandRequest) => string;
}

export const memoizeDecrypt = (
  decrypt: SopsDecrypt,
  options: SopsDecryptMemoizeOptions = {},
): SopsDecrypt => {
  const keyFor = options.key ?? defaultSopsDecryptMemoizeKey;
  const cache = new Map<string, Deferred.Deferred<string, SopsDecryptError>>();

  return (request) =>
    Effect.suspend(() => {
      const key = keyFor(request);
      const existing = cache.get(key);
      if (existing) return Deferred.await(existing);

      return Effect.gen(function* () {
        const deferred = yield* Deferred.make<string, SopsDecryptError>();
        cache.set(key, deferred);

        const exit = yield* Effect.exit(decrypt(request));
        yield* Deferred.done(deferred, exit);

        if (exit._tag === "Failure") {
          cache.delete(key);
        }

        return yield* exit;
      });
    });
};

export const defaultSopsDecryptMemoizeKey = (
  request: SopsCommandRequest,
): string =>
  stableStringify({
    path: request.path,
    content: request.content
      ? revealSecretString(request.content)
      : undefined,
    url: request.url ? revealSecretString(request.url) : undefined,
    cwd: request.cwd,
    binary: request.binary,
    inputType: request.inputType,
    outputType: request.outputType,
    extract: request.extract,
    args: request.args,
    envKeys: Object.keys(request.env ?? {}).sort(),
    keyService: keyServiceSettings(request),
    timeoutMs: request.timeoutMs,
  });

export const buildSopsArgs = (request: SopsCommandRequest): string[] => {
  const path = requirePath(request);
  const args = ["--decrypt"];

  if (request.inputType) {
    args.push("--input-type", request.inputType);
  }
  if (request.outputType) {
    args.push("--output-type", request.outputType);
  }
  if (request.extract) {
    args.push("--extract", request.extract);
  }
  for (const uri of request.keyServices ?? []) args.push("--keyservice", uri);
  if (request.enableLocalKeyService !== undefined) {
    args.push(`--enable-local-keyservice=${request.enableLocalKeyService}`);
  }
  args.push(...(request.args ?? []));
  args.push(path);

  return args;
};

export const requirePath = (request: SopsCommandRequest): string => {
  if (request.path) return request.path;

  throw new SopsDecryptError({
    message: "The sops CLI backend requires a local path source",
    path: requestLabel(request),
  });
};

export const requestLabel = (request: SopsCommandRequest): string => {
  if (request.path) return request.path;
  if (request.url) return revealSecretString(request.url);
  return "<inline>";
};

export const revealSecretString = (
  value: string | Redacted.Redacted<string>,
): string => (Redacted.isRedacted(value) ? Redacted.value(value) : value);

export const revealEnv = (
  env: Record<string, string | Redacted.Redacted<string>> | undefined,
) =>
  Object.fromEntries(
    Object.entries(env ?? {}).map(([key, value]) => [
      key,
      revealSecretString(value),
    ]),
  );

const stableStringify = (value: unknown): string =>
  JSON.stringify(sortForStableStringify(value));

const sortForStableStringify = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(sortForStableStringify);

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([, child]) => child !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, child]) => [key, sortForStableStringify(child)]),
    );
  }

  return value;
};
