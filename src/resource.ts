import { keyServiceSettings, type SopsKeyServiceOptions } from "./keyservice-options.js";
import type { Resource as AlchemyResource } from "alchemy";
import { Resource } from "alchemy";
import * as Diff from "alchemy/Diff";
import * as Provider from "alchemy/Provider";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schedule from "effect/Schedule";
import * as Schema from "effect/Schema";

import { defaultDecrypt } from "./backend.js";
import {
  type GenerateSecretTypesOptions,
  type MaterializedSecretDocument,
  type ResolvedSopsDocumentFormat,
  type SecretRecord,
  type SecretTree,
  type SopsDocumentFormat,
  generateSecretTypes,
  materializeSecretValue,
  parseSecretDocument,
} from "./document.js";
import {
  SopsDecryptError,
  SopsFileReadError,
  SopsInputError,
  SopsParseError,
  SopsSchemaError,
  SopsSecretPathError,
  type SopsError,
} from "./errors.js";
import { withErrorDetail } from "./error-detail.js";
import {
  type MaybeRedactedString,
  type SecretStringInput,
  resolveOptionalSecretStringInput,
  resolveSecretStringInput,
  resolveSecretStringInputs,
  resolveSecretStringRecord,
  revealString,
} from "./input.js";
import { buildSopsCommandRequest } from "./source.js";
import {
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
  type SopsDecryptMemoizeOptions,
  memoizeDecrypt,
} from "./sops.js";

const PROVIDER_VERSION = 1;
const registeredSchemas = new Map<string, SopsFileSchema>();

export interface SopsRetryOptions {
  readonly times?: number;
  readonly delay?: Duration.Input;
}

export type SopsGeneratedTypesOptions = GenerateSecretTypesOptions;
export type SopsGeneratedTypesInput = true | SopsGeneratedTypesOptions;
export type SopsFileSchema = Schema.Struct<Schema.Struct.Fields> &
  Schema.Decoder<unknown>;

/**
 * Removes the top-level SOPS metadata key from a JSON-imported document type.
 * Encrypted SOPS JSON keeps its plaintext key structure and only adds a `sops`
 * metadata object; the decrypted document never contains that key.
 */
export type OmitSopsMetadata<T> = T extends object ? Omit<T, "sops"> : T;

/**
 * Maps every scalar leaf of a JSON-imported document type to
 * `Redacted<string>`, mirroring the runtime `data` output where decrypted
 * scalars are stringified and wrapped in `Redacted`. Object and array structure
 * is preserved.
 */
export type RedactSecretLeaves<T> = T extends ReadonlyArray<infer U>
  ? ReadonlyArray<RedactSecretLeaves<U>>
  : T extends object
    ? { readonly [K in keyof T]: RedactSecretLeaves<T[K]> }
    : Redacted.Redacted<string>;

/**
 * The typed `data` shape returned by {@link SopsFile} when an imported JSON
 * document drives the types: SOPS metadata removed and every scalar leaf
 * redacted. TypeScript infers the source type from the JSON import itself, so
 * no schema or key declarations are required.
 */
export type SopsRedactedDocument<T> = RedactSecretLeaves<OmitSopsMetadata<T>>;

export interface SopsFileOptions<R = never> extends SopsKeyServiceOptions {
  readonly path?: SecretStringInput<R> | readonly SecretStringInput<R>[];
  readonly content?: SecretStringInput<R>;
  readonly url?: SecretStringInput<R>;
  /**
   * An imported (encrypted) SOPS JSON document, e.g.
   * `import secrets from "./secrets.enc.json" with { type: "json" }`.
   *
   * At runtime the object is serialized to JSON and decrypted as `content`. At
   * the type level its inferred shape drives a fully typed, redacted `data`
   * output via {@link SopsRedactedDocument} — no `schema` or `secrets` keys
   * required.
   */
  readonly json?: object;
  readonly cwd?: SecretStringInput<R>;
  readonly format?: SopsDocumentFormat | SecretStringInput<R>;
  readonly inputType?: SopsCliFormat | SecretStringInput<R>;
  readonly outputType?: SopsCliFormat | SecretStringInput<R>;
  readonly backend?: SopsBackend | SecretStringInput<R>;
  readonly sopsBinary?: SecretStringInput<R>;
  readonly sopsArgs?: readonly SecretStringInput<R>[];
  readonly extract?: SecretStringInput<R>;
  readonly env?: Record<string, SecretStringInput<R>>;
  readonly ageKey?: SecretStringInput<R>;
  readonly ageKeyFile?: SecretStringInput<R>;
  readonly schema?: SopsFileSchema;
  readonly secrets?: Record<string, string>;
  readonly cache?: boolean;
  readonly types?: SopsGeneratedTypesInput;
  readonly timeoutMs?: number;
  readonly retry?: SopsRetryOptions;
}

export interface SopsFileProps extends SopsKeyServiceOptions {
  readonly path?: MaybeRedactedString | readonly MaybeRedactedString[];
  readonly content?: MaybeRedactedString;
  readonly url?: MaybeRedactedString;
  readonly cwd?: MaybeRedactedString;
  readonly format: SopsDocumentFormat;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly backend: SopsBackend;
  readonly sopsBinary: MaybeRedactedString;
  readonly sopsArgs: readonly MaybeRedactedString[];
  readonly extract?: MaybeRedactedString;
  readonly env: Record<string, MaybeRedactedString>;
  readonly ageKey?: MaybeRedactedString;
  readonly ageKeyFile?: MaybeRedactedString;
  readonly schemaKey?: string;
  readonly secrets?: Record<string, string>;
  readonly cache: boolean;
  readonly types?: SopsGeneratedTypesOptions;
  readonly timeoutMs: number;
  readonly retry: Required<SopsRetryOptions>;
}

export type SopsFileAttributes<Value = never, Data = SecretTree> = {
  readonly path: string;
  readonly format: Exclude<SopsDocumentFormat, "auto">;
  readonly sourceHash: string;
  readonly data: Data;
  readonly flat: SecretRecord;
  readonly secrets: SecretRecord;
  readonly topLevelKeys: readonly string[];
  readonly types?: string;
  readonly version: number;
} & ([Value] extends [never] ? {} : { readonly value: Value });

export type SopsFileResource<Value = never, Data = SecretTree> = AlchemyResource<
  "Sops.File",
  SopsFileProps,
  SopsFileAttributes<Value, Data>
>;

export interface SopsFileProviderOptions {
  readonly decrypt?: SopsDecrypt;
  readonly memoize?: boolean | SopsDecryptMemoizeOptions;
}

export const SopsFileResource = Resource<SopsFileResource>("Sops.File");

// Schema-driven typing: an explicit `effect/Schema` validates and types `value`.
export function SopsFile<S extends SopsFileSchema, R = never>(
  id: string,
  options: SopsFileOptions<R> & { readonly schema: S },
): Effect.Effect<
  SopsFileResource<S["Type"]>,
  never,
  R | Provider.Provider<SopsFileResource>
>;
// JSON-import typing: TypeScript infers the document shape from the imported
// `json` object and propagates it to a redacted `data` output. No `schema` or
// `secrets` declarations are required.
export function SopsFile<const Shape extends object, R = never>(
  id: string,
  options: SopsFileOptions<R> & { readonly json: Shape },
): Effect.Effect<
  SopsFileResource<never, SopsRedactedDocument<Shape>>,
  never,
  R | Provider.Provider<SopsFileResource>
>;
export function SopsFile<R = never>(
  id: string,
  options: SopsFileOptions<R>,
): Effect.Effect<
  SopsFileResource,
  never,
  R | Provider.Provider<SopsFileResource>
>;
// The implementation signature is not visible to callers, so it stays loose:
// `SopsFileAttributes` only carries `value` when a schema is present, so no
// single concrete type is compatible with every overload above.
export function SopsFile(
  id: string,
  options: SopsFileOptions<any>,
): Effect.Effect<any, never, any> {
  return SopsFileResource(id, normalizeOptions(options)) as Effect.Effect<
    any,
    never,
    any
  >;
}

export const SopsFileProvider = (options: SopsFileProviderOptions = {}) => {
  const decrypts = new Map<string, SopsDecrypt>();
  const decryptFor = (backend: SopsBackend, format: SopsDocumentFormat) => {
    const base = options.decrypt ?? defaultDecrypt(backend, format);
    if (!options.memoize) return base;

    const key = options.decrypt ? "custom" : `${backend}:${format}`;
    const existing = decrypts.get(key);
    if (existing) return existing;

    const memoized = memoizeDecrypt(
      base,
      options.memoize === true ? undefined : options.memoize,
    );
    decrypts.set(key, memoized);
    return memoized;
  };

  return Provider.succeed(SopsFileResource, {
    version: PROVIDER_VERSION,
    list: Effect.fn(function* () {
      return [];
    }),
    read: Effect.fn(function* ({ output }) {
      return output;
    }),
    diff: Effect.fn(function* ({ news, olds, output }) {
      if (!Diff.isResolved(news)) return undefined;
      if (!output) return undefined;
      if (!sameProps(olds, news)) return { action: "update" as const };
      if (!news.cache) return { action: "update" as const };

      const sourceHash = yield* hashSource(news);
      return output.sourceHash === sourceHash &&
        output.version === PROVIDER_VERSION
        ? { action: "noop" as const }
        : { action: "update" as const };
    }),
    reconcile: Effect.fn(function* ({ news, output, session }) {
      const source = yield* loadEncryptedSource(news);
      const sourceHash = yield* hashLoadedSource(news, source);
      if (
        news.cache &&
        output?.sourceHash === sourceHash &&
        output.version === PROVIDER_VERSION
      ) {
        return output;
      }

      yield* session.note(`Decrypting ${source.label}`);

      const decryptOne = (item: LoadedEncryptedSource) => {
        const request = buildSopsCommandRequest({
          source: {
            content: item.content,
            ...(item.path ? { path: item.path } : {}),
            ...(item.url ? { url: item.url } : {}),
          },
          options: news,
        });
        return decryptWithRetry(
          decryptFor(news.backend, news.format),
          request,
          news.retry,
        );
      };
      const plaintexts = Array.isArray(source.sources)
        ? yield* Effect.all(source.sources.map(decryptOne))
        : [yield* decryptOne(source)];

      const materialized =
        plaintexts.length === 1
          ? yield* parseDecryptedDocument(plaintexts[0]!, news, source.label)
          : yield* parseMergedDecryptedDocuments(plaintexts, news, source.label);
      yield* session.note(
        `Decrypted ${source.label}: top-level keys ${formatTopLevelKeys(
          materialized.topLevelKeys,
        )}`,
      );

      const generatedTypes = news.types
        ? generateSecretTypes(materialized.data, news.types)
        : undefined;

      return {
        path: source.label,
        format: materialized.format,
        sourceHash,
        data: materialized.data,
        flat: materialized.flat,
        secrets: materialized.secrets,
        topLevelKeys: materialized.topLevelKeys,
        ...(news.schemaKey ? { value: materialized.value } : {}),
        ...(generatedTypes ? { types: generatedTypes } : {}),
        version: PROVIDER_VERSION,
      };
    }),
    delete: Effect.fn(function* () {
      return undefined;
    }),
  });
};

export const providers = SopsFileProvider;

const normalizeOptions = <R>(
  options: SopsFileOptions<R>,
): Effect.Effect<SopsFileProps, never, R> =>
  Effect.gen(function* () {
    const path = yield* resolveOptionalPathInput(options.path);
    const content = yield* resolveOptionalSecretStringInput(options.content);
    const url = yield* resolveOptionalSecretStringInput(options.url);
    // An imported JSON document is serialized back to its ciphertext form and
    // decrypted as inline `content`. Values and key order are preserved, so the
    // SOPS MAC still verifies.
    const jsonContent =
      options.json !== undefined ? JSON.stringify(options.json) : undefined;
    validateSourceOptions({
      ...(path !== undefined ? { path } : {}),
      ...(content !== undefined ? { content } : {}),
      ...(url !== undefined ? { url } : {}),
      ...(jsonContent !== undefined ? { json: jsonContent } : {}),
    });

    const cwd = yield* resolveOptionalSecretStringInput(options.cwd);
    const format = normalizeDocumentFormat(
      yield* resolveSecretStringInput(
        options.format ?? (jsonContent !== undefined ? "json" : "auto"),
      ),
      "format",
    );
    const inputType = normalizeOptionalCliFormat(
      yield* resolveOptionalSecretStringInput(options.inputType),
      "inputType",
    );
    const outputType = normalizeOptionalCliFormat(
      yield* resolveOptionalSecretStringInput(options.outputType),
      "outputType",
    );
    const backend = normalizeBackend(
      yield* resolveSecretStringInput(options.backend ?? "auto"),
    );
    const extract = yield* resolveOptionalSecretStringInput(options.extract);
    const ageKey = yield* resolveOptionalSecretStringInput(options.ageKey);
    const ageKeyFile = yield* resolveOptionalSecretStringInput(
      options.ageKeyFile,
    );

    return {
      format,
      backend,
      sopsBinary: yield* resolveSecretStringInput(options.sopsBinary ?? "sops"),
      sopsArgs: yield* resolveSecretStringInputs(options.sopsArgs),
      env: yield* resolveSecretStringRecord(options.env),
      cache: options.cache ?? true,
      ...(options.schema ? { schemaKey: registerSchema(options.schema) } : {}),
      ...(options.types ? { types: normalizeGeneratedTypes(options.types) } : {}),
      timeoutMs: options.timeoutMs ?? 30_000,
      retry: {
        times: options.retry?.times ?? 2,
        delay: options.retry?.delay ?? "250 millis",
      },
      ...(path !== undefined ? { path } : {}),
      ...(content !== undefined
        ? { content }
        : jsonContent !== undefined
          ? { content: jsonContent }
          : {}),
      ...(url !== undefined ? { url } : {}),
      ...(cwd ? { cwd } : {}),
      ...(inputType ? { inputType } : {}),
      ...(outputType ? { outputType } : {}),
      ...(extract ? { extract } : {}),
      ...(ageKey ? { ageKey } : {}),
      ...(ageKeyFile ? { ageKeyFile } : {}),
      ...(options.keyServices !== undefined ? { keyServices: [...options.keyServices] } : {}),
      ...(options.enableLocalKeyService !== undefined ? { enableLocalKeyService: options.enableLocalKeyService } : {}),
      ...(options.secrets ? { secrets: options.secrets } : {}),
    };
  }).pipe(Effect.orDie);

const normalizeDocumentFormat = (
  value: MaybeRedactedString,
  field: string,
): SopsDocumentFormat => {
  const raw = revealString(value);
  if (
    raw === "auto" ||
    raw === "json" ||
    raw === "yaml" ||
    raw === "dotenv" ||
    raw === "text" ||
    raw === "binary"
  ) {
    return raw;
  }
  throw new SopsInputError({
    message: `Invalid ${field}: ${raw}`,
    field,
  });
};

const normalizeBackend = (value: MaybeRedactedString): SopsBackend => {
  const raw = revealString(value);
  if (raw === "auto" || raw === "cli" || raw === "sops-age") return raw;

  throw new SopsInputError({
    message: `Invalid backend: ${raw}`,
    field: "backend",
  });
};

const validateSourceOptions = (source: {
  readonly path?: MaybeRedactedString | readonly MaybeRedactedString[];
  readonly content?: MaybeRedactedString;
  readonly url?: MaybeRedactedString;
  readonly json?: MaybeRedactedString;
}): void => {
  const provided = [source.path, source.content, source.url, source.json].filter(
    (value) => value !== undefined,
  );

  if (provided.length === 1) return;

  throw new SopsInputError({
    message:
      "Exactly one SOPS source must be provided: path, content, url, or json",
    field: "path",
  });
};

const normalizeOptionalCliFormat = (
  value: MaybeRedactedString | undefined,
  field: string,
): SopsCliFormat | undefined => {
  if (value === undefined) return undefined;
  const raw = revealString(value);
  if (raw === "json" || raw === "yaml" || raw === "dotenv" || raw === "binary") {
    return raw;
  }
  throw new SopsInputError({
    message: `Invalid ${field}: ${raw}`,
    field,
  });
};

const decryptWithRetry = (
  decrypt: SopsDecrypt,
  request: SopsCommandRequest,
  retry: Required<SopsRetryOptions>,
) =>
  decrypt(request).pipe(
    Effect.retry({
      schedule: Schedule.spaced(retry.delay).pipe(
        Schedule.upTo({ times: retry.times }),
      ),
    }),
  );

const parseDecryptedDocument = (
  plaintext: string,
  props: SopsFileProps,
  sourceLabel: string,
): Effect.Effect<
  MaterializedSecretDocument<unknown>,
  SopsParseError | SopsError
> =>
  Effect.gen(function* () {
    // Parse/materialize/schema failures below stay generic on purpose: they
    // run against decrypted content and their causes can quote secret values.
    const parsed = yield* Effect.try({
      try: () =>
        parseSecretDocument(plaintext, {
          format: props.format,
          path: sourceLabel,
        }),
      catch: (cause) =>
        cause instanceof SopsParseError
          ? cause
          : new SopsParseError({
              message: "Failed to parse decrypted SOPS content",
              format: props.format,
              cause,
            }),
    });

    const value = props.schemaKey
      ? yield* decodeSchema(props.schemaKey, parsed.value, sourceLabel)
      : parsed.value;

    return yield* Effect.try({
      try: () =>
        materializeSecretValue(value, {
          format: parsed.format,
          ...(props.secrets ? { secrets: props.secrets } : {}),
        }),
      catch: (cause) =>
        cause instanceof SopsSecretPathError
          ? cause
          : new SopsParseError({
              message: "Failed to materialize decrypted SOPS content",
              format: props.format,
              cause,
            }),
    });
  });

const parseMergedDecryptedDocuments = (
  plaintexts: readonly string[],
  props: SopsFileProps,
  sourceLabel: string,
): Effect.Effect<
  MaterializedSecretDocument<unknown>,
  SopsParseError | SopsError
> =>
  Effect.gen(function* () {
    const parsedValues: unknown[] = [];
    let resolvedFormat: Exclude<SopsDocumentFormat, "auto"> | undefined;
    for (const plaintext of plaintexts) {
      const parsed = yield* Effect.try({
        try: () =>
          parseSecretDocument(plaintext, {
            format: props.format,
            path: sourceLabel,
          }),
        catch: (cause) =>
          cause instanceof SopsParseError
            ? cause
            : new SopsParseError({
                message: "Failed to parse decrypted SOPS content",
                format: props.format,
                cause,
              }),
      });
      resolvedFormat = parsed.format;
      parsedValues.push(parsed.value);
    }

    const merged = mergeSecretValues(parsedValues, sourceLabel);
    const value = props.schemaKey
      ? yield* decodeSchema(props.schemaKey, merged, sourceLabel)
      : merged;

    return yield* Effect.try({
      try: () =>
        materializeSecretValue(value, {
          format: resolvedFormat ?? resolveFallbackFormat(props.format),
          ...(props.secrets ? { secrets: props.secrets } : {}),
        }),
      catch: (cause) =>
        cause instanceof SopsSecretPathError
          ? cause
          : new SopsParseError({
              message: "Failed to materialize decrypted SOPS content",
              format: props.format,
              cause,
            }),
    });
  });

const mergeSecretValues = (
  values: readonly unknown[],
  sourceLabel: string,
): Record<string, unknown> => {
  const merged: Record<string, unknown> = {};
  for (const value of values) {
    if (!isPlainObject(value)) {
      throw new SopsParseError({
        message: `Cannot merge non-object SOPS content from ${sourceLabel}`,
        format: "json",
      });
    }
    deepMerge(merged, value);
  }
  return merged;
};

const deepMerge = (
  target: Record<string, unknown>,
  source: Record<string, unknown>,
): void => {
  for (const [key, value] of Object.entries(source)) {
    if (isPlainObject(value) && isPlainObject(target[key])) {
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
};

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);

interface LoadedEncryptedSource {
  readonly label: string;
  readonly content: string;
  readonly bytes: Uint8Array;
  readonly path?: string;
  readonly url?: string;
  readonly sources?: readonly LoadedEncryptedSource[];
}

const hashSource = (props: SopsFileProps) =>
  Effect.flatMap(loadEncryptedSource(props), (source) =>
    hashLoadedSource(props, source),
  );

const loadEncryptedSource = (
  props: SopsFileProps,
): Effect.Effect<LoadedEncryptedSource, SopsFileReadError> =>
  Effect.tryPromise({
    try: async () => {
      if (props.content !== undefined) {
        const content = revealString(props.content);
        return {
          label: "<inline>",
          content,
          bytes: new TextEncoder().encode(content),
        };
      }

      if (props.url !== undefined) {
        const url = revealString(props.url);
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`HTTP ${response.status} while reading ${url}`);
        }
        const content = await response.text();
        return {
          label: url,
          url,
          content,
          bytes: new TextEncoder().encode(content),
        };
      }

      if (Array.isArray(props.path)) {
        const sources: LoadedEncryptedSource[] = [];
        for (const path of await resolveResourcePaths(props)) {
          const bytes = await readPathBytes(path);
          sources.push({
            label: path,
            path,
            content: new TextDecoder().decode(bytes),
            bytes,
          });
        }
        return {
          label: sources.map((source) => source.label).join(","),
          sources,
          content: sources.map((source) => source.content).join("\n"),
          bytes: concatBytes(
            sources.flatMap((source) => [
              source.bytes,
              new TextEncoder().encode("\0"),
            ]),
          ),
        };
      }

      const path = await resolveResourcePath(props);
      const bytes = await readPathBytes(path);
      return {
        label: path,
        path,
        content: new TextDecoder().decode(bytes),
        bytes,
      };
    },
    catch: (cause) =>
      new SopsFileReadError({
        message: withErrorDetail(
          `Failed to read encrypted SOPS source: ${sourceLabel(props)}`,
          cause,
        ),
        path: sourceLabel(props),
        cause,
      }),
  });

const hashLoadedSource = (
  props: SopsFileProps,
  source: LoadedEncryptedSource,
): Effect.Effect<string, SopsFileReadError> =>
  Effect.tryPromise({
    try: () =>
      sha256Hex([
        source.bytes,
        new TextEncoder().encode("\0"),
        new TextEncoder().encode(
          JSON.stringify({
            source: source.label,
            format: props.format,
            inputType: props.inputType,
            outputType: props.outputType,
            backend: props.backend,
            extract: props.extract ? revealString(props.extract) : undefined,
            sopsArgs: props.sopsArgs.map(revealString),
            secrets: props.secrets,
            schemaKey: props.schemaKey,
            providerVersion: PROVIDER_VERSION,
            keyService: keyServiceSettings(buildSopsCommandRequest({ source: {}, options: props })),
            types: props.types,
          }),
        ),
      ]),
    catch: (cause) =>
      new SopsFileReadError({
        message: withErrorDetail(
          `Failed to hash encrypted SOPS source: ${source.label}`,
          cause,
        ),
        path: source.label,
        cause,
      }),
  });

const sourceLabel = (props: SopsFileProps): string => {
  const { path } = props;
  if (path !== undefined) {
    return isReadonlyRedactedStringArray(path)
      ? path.map(revealString).join(",")
      : revealString(path);
  }
  if (props.url !== undefined) return revealString(props.url);
  return "<inline>";
};

const resolveResourcePaths = async (
  props: SopsFileProps,
): Promise<readonly string[]> => {
  if (!isReadonlyRedactedStringArray(props.path)) return [await resolveResourcePath(props)];

  const cwd = props.cwd ? revealString(props.cwd) : undefined;
  const paths: string[] = [];
  for (const item of props.path) {
    const rawPath = revealString(item);
    if (isAbsolutePath(rawPath)) {
      paths.push(rawPath);
    } else if (typeof process !== "undefined" && process.cwd) {
      const { resolve } = await import("node:path");
      paths.push(resolve(cwd ?? process.cwd(), rawPath));
    } else if (cwd) {
      paths.push(new URL(rawPath, cwd).toString());
    } else {
      paths.push(rawPath);
    }
  }
  return paths;
};

const resolveResourcePath = async (props: SopsFileProps): Promise<string> => {
  if (props.path === undefined) {
    throw new Error("path source is missing");
  }

  if (isReadonlyRedactedStringArray(props.path)) {
    throw new Error("path source must be a single path");
  }

  const rawPath = revealString(props.path);
  const cwd = props.cwd ? revealString(props.cwd) : undefined;

  if (isAbsolutePath(rawPath)) return rawPath;

  if (typeof process !== "undefined" && process.cwd) {
    const { resolve } = await import("node:path");
    return resolve(cwd ?? process.cwd(), rawPath);
  }

  if (cwd) {
    return new URL(rawPath, cwd).toString();
  }

  return rawPath;
};

const isAbsolutePath = (path: string): boolean =>
  path.startsWith("/") || /^[A-Za-z]:[\\/]/.test(path);

const readPathBytes = async (path: string): Promise<Uint8Array> => {
  const runtime = globalThis as typeof globalThis & {
    Bun?: {
      file: (path: string) => { arrayBuffer: () => Promise<ArrayBuffer> };
    };
    Deno?: {
      readFile: (path: string) => Promise<Uint8Array>;
    };
  };

  if (runtime.Bun) {
    return new Uint8Array(await runtime.Bun.file(path).arrayBuffer());
  }

  if (runtime.Deno) {
    return runtime.Deno.readFile(path);
  }

  if (typeof process !== "undefined" && process.versions?.node) {
    const { readFile } = await import("node:fs/promises");
    return readFile(path);
  }

  throw new Error(`Unable to read local file source "${path}"`);
};

const concatBytes = (parts: readonly Uint8Array[]): Uint8Array => {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }
  return bytes;
};

const sha256Hex = async (parts: readonly Uint8Array[]): Promise<string> => {
  const length = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    bytes.set(part, offset);
    offset += part.byteLength;
  }

  if (globalThis.crypto?.subtle) {
    const digest = await globalThis.crypto.subtle.digest("SHA-256", bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  const { createHash } = await import("node:crypto");
  const hash = createHash("sha256");
  hash.update(bytes);
  return hash.digest("hex");
};

const bytesToHex = (bytes: Uint8Array): string =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

const sameProps = (
  olds: SopsFileProps | undefined,
  news: SopsFileProps,
): boolean => JSON.stringify(olds ?? {}) === JSON.stringify(news);

const normalizeGeneratedTypes = (
  options: SopsGeneratedTypesInput,
): SopsGeneratedTypesOptions =>
  options === true ? {} : options;

const registerSchema = (schema: SopsFileSchema): string => {
  const key = stableStringify(schema.ast);
  registeredSchemas.set(key, schema);
  return key;
};

const decodeSchema = (
  schemaKey: string,
  value: unknown,
  sourceLabel: string,
): Effect.Effect<unknown, SopsSchemaError> =>
  Effect.try({
    try: () => {
      const schema = registeredSchemas.get(schemaKey);
      if (!schema) {
        throw new Error(
          "Schema was not registered in the current process before decrypting",
        );
      }
      return Schema.decodeUnknownSync(schema)(value);
    },
    catch: (cause) =>
      new SopsSchemaError({
        message: `Failed to validate decrypted SOPS content from ${sourceLabel}`,
        path: sourceLabel,
        cause,
      }),
  });

const stableStringify = (value: unknown): string =>
  JSON.stringify(stableValue(value));

const stableValue = (value: unknown): unknown => {
  if (
    value === null ||
    value === undefined ||
    typeof value === "string" ||
    typeof value === "number" ||
    typeof value === "boolean"
  ) {
    return value;
  }

  if (typeof value === "function") {
    return `[Function:${value.name}]`;
  }

  if (Array.isArray(value)) return value.map(stableValue);

  if (typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([key, child]) => [key, stableValue(child)]),
    );
  }

  return String(value);
};

const formatTopLevelKeys = (keys: readonly string[]): string =>
  keys.length === 0 ? "(none)" : keys.join(", ");

const resolveOptionalPathInput = <R>(
  input: SopsFileOptions<R>["path"],
): Effect.Effect<MaybeRedactedString | readonly MaybeRedactedString[] | undefined, any, R> =>
  Effect.gen(function* () {
    if (input === undefined) return undefined;
    if (isReadonlySecretStringInputArray(input)) {
      return yield* resolveSecretStringInputs(input);
    }
    return yield* resolveSecretStringInput(input);
  });

const isReadonlyRedactedStringArray = (
  value: unknown,
): value is readonly MaybeRedactedString[] => Array.isArray(value);

const isReadonlySecretStringInputArray = <R>(
  value: SopsFileOptions<R>["path"],
): value is readonly SecretStringInput<R>[] => Array.isArray(value);

const resolveFallbackFormat = (
  format: SopsDocumentFormat,
): ResolvedSopsDocumentFormat => (format === "auto" ? "json" : format);
