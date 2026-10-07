import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

import { defaultDecrypt } from "./backend.js";
import {
  materializeSecretDocument,
  resolveDocumentFormat,
  type SecretTree,
  type SopsDocumentFormat,
} from "./document.js";
import {
  memoizeDecrypt,
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./sops.js";
import { buildSopsCommandRequest } from "./source.js";

/**
 * Describes the SOPS document backing a `ConfigProvider`.
 *
 * These mirror the source options of {@link SopsFile}, minus everything that
 * only makes sense inside the Alchemy resource graph. Values are plain rather
 * than `SecretStringInput` because a config provider is consulted before any
 * Effect services exist.
 */
export interface SopsConfigOptions {
  readonly path?: string;
  readonly content?: string | Redacted.Redacted<string>;
  readonly url?: string | Redacted.Redacted<string>;
  /**
   * An imported encrypted SOPS JSON document, e.g.
   * `import secrets from "./secrets.enc.json" with { type: "json" }`.
   */
  readonly json?: object;
  readonly cwd?: string;
  readonly format?: SopsDocumentFormat;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly backend?: SopsBackend;
  readonly sopsBinary?: string;
  readonly sopsArgs?: readonly string[];
  readonly extract?: string;
  readonly env?: Record<string, string | Redacted.Redacted<string>>;
  readonly ageKey?: string | Redacted.Redacted<string>;
  readonly ageKeyFile?: string;
  readonly timeoutMs?: number;
  /**
   * Maps config names to dotted paths within the document, so a nested
   * document can answer flat lookups:
   *
   * ```ts
   * secrets: { CLOUDFLARE_API_TOKEN: "secrets.CLOUDFLARE_API_TOKEN" }
   * ```
   *
   * When omitted, the decrypted document is exposed as-is and nested lookups
   * address it by path segments.
   */
  readonly secrets?: Record<string, string>;
  /** Overrides the decrypt implementation, primarily for tests. */
  readonly decrypt?: SopsDecrypt;
}

/**
 * A `ConfigProvider` backed by a SOPS document.
 *
 * Alchemy resolves provider credentials with `Config.Redacted`/`Config.String`,
 * which read the ambient `ConfigProvider` rather than `process.env`, so this is
 * enough to authenticate a deploy with no secrets in the environment.
 *
 * Decryption is lazy and runs at most once: the document is only read when a
 * lookup reaches this provider, so registering it as a fallback behind the
 * environment costs nothing when the value is already set.
 */
export const make = (options: SopsConfigOptions): ConfigProvider.ConfigProvider => {
  const format = resolveDocumentFormat(options.format ?? "auto", options.path);
  const request = buildRequest(options, format);
  const decrypt = memoizeDecrypt(
    options.decrypt ?? defaultDecrypt(options.backend ?? "auto", format),
  );

  let cached: ConfigProvider.ConfigProvider | undefined;

  const provider = Effect.suspend(() => {
    if (cached) return Effect.succeed(cached);

    return decrypt(request).pipe(
      Effect.map((plaintext) => {
        const document = materializeSecretDocument(plaintext, {
          format,
          ...(options.path !== undefined ? { path: options.path } : {}),
          ...(options.secrets ? { secrets: options.secrets } : {}),
        });

        const root = options.secrets ? reveal(document.secrets) : reveal(document.data);

        cached = ConfigProvider.fromUnknown(root);
        return cached;
      }),
      // The failure carries the source label but never decrypted content, so a
      // config error cannot leak secret material into logs.
      Effect.mapError(
        (cause) =>
          new ConfigProvider.SourceError({
            message: `Failed to read SOPS config from ${sourceLabel(options)}`,
            cause,
          }),
      ),
    );
  });

  return ConfigProvider.make((path) => Effect.flatMap(provider, (source) => source.load(path)));
};

/** Replaces the ambient `ConfigProvider` with a SOPS-backed one. */
export const layer = (options: SopsConfigOptions): Layer.Layer<never> =>
  ConfigProvider.layer(make(options));

/**
 * Adds a SOPS-backed provider to the ambient chain.
 *
 * The default appends it behind the existing provider, so an ambient
 * environment variable still wins and the document is only decrypted on a miss.
 * Pass `asPrimary` to consult SOPS first.
 */
export const layerAdd = (
  options: SopsConfigOptions,
  addOptions?: { readonly asPrimary?: boolean },
): Layer.Layer<never> => ConfigProvider.layerAdd(make(options), addOptions);

/**
 * Supplies SOPS credentials to both layers of an Alchemy stack.
 *
 * A stack's `state` store initializes before its `providers` and resolves
 * credentials independently, so providing the config layer to only one of them
 * fails during state initialization. This wires both from a single provider:
 *
 * ```ts
 * export default Alchemy.Stack(
 *   "MyApp",
 *   SopsConfig.provideCredentials(
 *     { path: "secrets.sops.json" },
 *     { providers: Cloudflare.providers(), state: Cloudflare.state() },
 *   ),
 *   body,
 * );
 * ```
 */
export const provideCredentials = <
  ProvidersOut,
  ProvidersError,
  ProvidersIn,
  StateOut,
  StateError,
  StateIn,
>(
  options: SopsConfigOptions,
  stack: {
    readonly providers: Layer.Layer<ProvidersOut, ProvidersError, ProvidersIn>;
    readonly state: Layer.Layer<StateOut, StateError, StateIn>;
  },
) => {
  const credentials = ConfigProvider.layerAdd(make(options));
  return {
    providers: stack.providers.pipe(Layer.provide(credentials)),
    state: stack.state.pipe(Layer.provide(credentials)),
  };
};

const buildRequest = (
  options: SopsConfigOptions,
  format: SopsDocumentFormat,
): SopsCommandRequest =>
  buildSopsCommandRequest({
    source: {
      ...(options.path !== undefined ? { path: options.path } : {}),
      ...(options.content !== undefined ? { content: options.content } : {}),
      ...(options.json !== undefined
        ? { content: JSON.stringify(options.json) }
        : {}),
      ...(options.url !== undefined ? { url: options.url } : {}),
    },
    options: { ...options, format },
    inferInputType: true,
  });

const sourceLabel = (options: SopsConfigOptions): string => {
  if (options.path) return options.path;
  if (options.url) return "<url>";
  return "<inline>";
};

const reveal = (tree: SecretTree): unknown => {
  if (Redacted.isRedacted(tree)) return Redacted.value(tree);
  if (Array.isArray(tree)) return tree.map(reveal);
  return Object.fromEntries(
    Object.entries(tree as { readonly [key: string]: SecretTree }).map(([key, value]) => [
      key,
      reveal(value),
    ]),
  );
};
