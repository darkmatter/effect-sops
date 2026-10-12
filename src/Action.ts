import { defaultDecrypt } from "./backend.js";
import type { SopsKeyServiceOptions } from "./keyservice-options.js";
import * as secretsStore from "@distilled.cloud/cloudflare/secrets-store";
import { Action, Stage } from "alchemy";
import type * as Output from "alchemy/Output";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Stream from "effect/Stream";

import {
  type SecretRecord,
  type SecretTree,
  type ResolvedSopsDocumentFormat,
  type SopsDocumentFormat,
  materializeSecretDocument,
  type MaterializedSecretDocument,
} from "./document.js";
import { SopsInputError } from "./errors.js";
import { type MaybeRedactedString } from "./input.js";
import { buildSopsCommandRequest } from "./source.js";
import {
  type SopsBackend,
  type SopsCliFormat,
} from "./sops.js";

const CLOUDFLARE_SECRETS_STORE_PAGE_SIZE = 100;

export interface CloudflareSecretsStoreRef {
  readonly accountId: string;
  readonly storeId: string;
}

export interface CloudflareSecretsStoreInput {
  readonly accountId: string | Output.Output<string, any>;
  readonly storeId: string | Output.Output<string, any>;
}

export interface CloudflareSopsSecretsOptions extends SopsKeyServiceOptions {
  /** Local SOPS file read at plan time. Ciphertext is stored in Action state. */
  readonly path: string | readonly string[];
  /** Optional working directory for relative paths and CLI execution. */
  readonly cwd?: string;
  /** Cloudflare Secrets Store resource or attrs returned by `Cloudflare.SecretsStore`. */
  readonly store: CloudflareSecretsStoreInput;
  /** Decrypted document format. Defaults to `auto`, using `path` for inference. */
  readonly format?: SopsDocumentFormat;
  /** SOPS encrypted input type hint for the decrypt backend. */
  readonly inputType?: SopsCliFormat;
  /** Decrypted output type hint for the decrypt backend. */
  readonly outputType?: SopsCliFormat;
  /** Decrypt backend. `auto` tries the native age path before the CLI. */
  readonly backend?: SopsBackend;
  /** `sops` binary name or path when the CLI backend is used. */
  readonly sopsBinary?: string;
  /** Extra CLI args. Forces CLI fallback when the native backend cannot honor them. */
  readonly sopsArgs?: readonly string[];
  /** Optional SOPS extract expression. */
  readonly extract?: string;
  /** Environment passed to decrypt backends. */
  readonly env?: Record<string, MaybeRedactedString>;
  /** Age identity. Stored as redacted Action input when wrapped with `Redacted.make`. */
  readonly ageKey?: MaybeRedactedString;
  /** Age identity file path for the CLI backend. */
  readonly ageKeyFile?: MaybeRedactedString;
  /** Map Cloudflare secret names to decrypted dot-path selectors. */
  readonly secrets?: Record<string, string>;
  /** Prefix for generated secret names when `secrets` is omitted. */
  readonly namePrefix?: string;
  /** Cloudflare Secrets Store scopes. Defaults to `["workers"]`. */
  readonly scopes?: readonly string[];
  /** Free-form comment attached to imported secrets. */
  readonly comment?: string;
  /**
   * Cloudflare cannot patch a Secrets Store secret value. When true, an existing
   * matching name is deleted and recreated so the value converges.
   *
   * @default true
   */
  readonly replaceExisting?: boolean;
  readonly timeoutMs?: number;
}

export interface CloudflareSopsSecretsActionInput
  extends Omit<CloudflareSopsSecretsOptions, "path" | "store"> {
  readonly path: string | readonly string[];
  readonly content: string | readonly string[];
  readonly store: CloudflareSecretsStoreRef;
}

export interface CloudflareSecretImport {
  readonly name: string;
  readonly path: string;
  readonly value: Redacted.Redacted<string>;
}

export interface CloudflareSopsSecretsOutput {
  readonly accountId: string;
  readonly storeId: string;
  readonly path: string;
  readonly topLevelKeys: readonly string[];
  readonly imported: {
    readonly name: string;
    readonly path: string;
    readonly secretId: string;
    /**
     * Cloudflare's documented statuses, kept open because the API returns the
     * status verbatim and may add values without a breaking change here.
     */
    readonly status: "pending" | "active" | "deleted" | (string & {});
  }[];
}

export interface CloudflareSopsWorkerBindingSource {
  readonly storeId: string | Output.Output<string, any>;
}

export interface CloudflareSopsWorkerSecretBinding {
  readonly type: "secrets_store_secret";
  readonly name: string;
  readonly secretName: string;
  readonly storeId: string | Output.Output<string, any>;
}

export interface CloudflareSopsWorkerBindingSet {
  readonly bindings: CloudflareSopsWorkerSecretBinding[];
}

export function CloudflareSopsSecrets(
  input: CloudflareSopsSecretsOptions,
): Effect.Effect<Output.ToOutput<CloudflareSopsSecretsOutput>, never, any>;
export function CloudflareSopsSecrets(
  id: string,
  input: CloudflareSopsSecretsOptions,
): Effect.Effect<Output.ToOutput<CloudflareSopsSecretsOutput>, never, any>;
/**
 * Import decrypted SOPS values into Cloudflare Secrets Store at deploy time.
 *
 * The wrapper reads the encrypted file before registering the Action and passes
 * the ciphertext as Action input. That keeps plaintext out of state while still
 * making Alchemy rerun the Action when the SOPS file changes.
 */
export function CloudflareSopsSecrets(
  ...args:
    | [input: CloudflareSopsSecretsOptions]
    | [id: string, input: CloudflareSopsSecretsOptions]
): Effect.Effect<Output.ToOutput<CloudflareSopsSecretsOutput>, never, any> {
  const [id, input] =
    args.length === 1
      ? ["CloudflareSopsSecrets", args[0]]
      : (args as [string, CloudflareSopsSecretsOptions]);

  return Effect.gen(function* () {
    const content = yield* readEncryptedFile(input.path, input.cwd);
    return yield* CloudflareSopsSecretsAction(id, {
      ...input,
      content,
    });
  });
}

export const CloudflareSopsSecretsAction = Action(
  "Sops.CloudflareSecrets",
  Effect.gen(function* () {
    const createSecret = yield* secretsStore.createStoreSecret;
    const deleteSecret = yield* secretsStore.deleteStoreSecret;
    const patchSecret = yield* secretsStore.patchStoreSecret;

    return Effect.fn(function* (input: CloudflareSopsSecretsActionInput) {
      // `alchemy dev` runs the Worker locally and forwards Secrets Store
      // bindings as redacted values, so in the dev stage we skip the remote
      // import entirely: return the store coordinates so Worker bindings still
      // resolve, but write nothing to Cloudflare.
      const stage = yield* Stage;
      if (stage === "dev") {
        yield* Effect.logInfo(
          `Skipping Cloudflare Secrets Store import for ${formatPath(
            input.path,
          )} in the dev stage; secrets are forwarded as redacted values locally`,
        );
        return {
          accountId: input.store.accountId,
          storeId: input.store.storeId,
          path: formatPath(input.path),
          topLevelKeys: [],
          imported: [],
        } satisfies CloudflareSopsSecretsOutput;
      }
      const plaintext = yield* decryptForAction(input);
      const materialized = isReadonlyStringArray(plaintext)
        ? materializeMergedSecretDocuments(plaintext, {
            format: input.format ?? "auto",
            path: formatPath(input.path),
            ...(input.secrets ? { secrets: input.secrets } : {}),
          })
        : materializeSecretDocument(plaintext, {
            format: input.format ?? "auto",
            path: formatPath(input.path),
            ...(input.secrets ? { secrets: input.secrets } : {}),
          });
      yield* Effect.logInfo(
        `Decrypted ${formatPath(input.path)}: top-level keys ${formatTopLevelKeys(
          materialized.topLevelKeys,
        )}`,
      );
      const imports = planCloudflareSecretImports(materialized.flat, input);
      const scopes = [...(input.scopes ?? ["workers"])];
      const listed = yield* secretsStore.listStoreSecrets
        .items({
          accountId: input.store.accountId,
          storeId: input.store.storeId,
          perPage: CLOUDFLARE_SECRETS_STORE_PAGE_SIZE,
        })
        .pipe(Stream.runCollect);
      const existing = new Map(
        Array.from(listed, (secret) => [secret.name, secret] as const),
      );

      const createBody = (item: CloudflareSecretImport) => ({
        name: item.name,
        scopes,
        value: Redacted.value(item.value),
        ...(input.comment !== undefined ? { comment: input.comment } : {}),
      });

      const create = (item: CloudflareSecretImport) =>
        createSecret({
          accountId: input.store.accountId,
          storeId: input.store.storeId,
          body: [createBody(item)],
        });

      const findByName = (name: string) =>
        secretsStore.listStoreSecrets
          .items({
            accountId: input.store.accountId,
            storeId: input.store.storeId,
            search: name,
            perPage: CLOUDFLARE_SECRETS_STORE_PAGE_SIZE,
          })
          .pipe(
            Stream.runCollect,
            Effect.map((matches) =>
              Array.from(matches).find((secret) => secret.name === name),
            ),
          );

      const importSecret = (item: CloudflareSecretImport) =>
        Effect.gen(function* () {
          const created = yield* create(item).pipe(
            Effect.catchTag("SecretNameAlreadyExists", () =>
              Effect.succeed(undefined),
            ),
          );
          const secret = created?.result[0] ?? (yield* findByName(item.name));
          if (!secret) {
            return yield* Effect.die(
              new Error(
                `Secret "${item.name}" already exists but could not be found in store ${input.store.storeId}`,
              ),
            );
          }
          return {
            name: item.name,
            path: item.path,
            secretId: secret.id,
            status: secret.status,
          };
        });

      const patchExisting = (
        item: CloudflareSecretImport,
        secretId: string,
      ) =>
        patchSecret({
          accountId: input.store.accountId,
          storeId: input.store.storeId,
          secretId,
          scopes,
          ...(input.comment !== undefined ? { comment: input.comment } : {}),
        }).pipe(
          Effect.map((patched) => ({
            name: item.name,
            path: item.path,
            secretId: patched.id,
            status: patched.status,
          })),
        );

      const imported = yield* Effect.all(
        imports.map((item) =>
          Effect.gen(function* () {
            const current = existing.get(item.name);
            if (current && input.replaceExisting !== false) {
              yield* deleteSecret({
                accountId: input.store.accountId,
                storeId: input.store.storeId,
                secretId: current.id,
              }).pipe(
                Effect.catchTag("SecretNotFound", () => Effect.void),
                Effect.catchTag("StoreNotFound", () => Effect.void),
                Effect.catchTag("NotFound", () => Effect.void),
              );
            } else if (current) {
              return yield* patchExisting(item, current.id).pipe(
                Effect.catchTag("SecretNotFound", () => importSecret(item)),
              );
            }

            return yield* importSecret(item);
          }),
        ),
        { concurrency: "unbounded" },
      );

      return {
        accountId: input.store.accountId,
        storeId: input.store.storeId,
        path: formatPath(input.path),
        topLevelKeys: materialized.topLevelKeys,
        imported,
      };
    });
  }),
);

/**
 * Build Worker metadata bindings for secrets imported by
 * `CloudflareSopsSecrets`.
 *
 * Pass the Action output as `source` so the Worker depends on the import before
 * Cloudflare validates the `secrets_store_secret` bindings.
 */
export const cloudflareSopsWorkerBindings = (
  source: CloudflareSopsWorkerBindingSource,
  names: readonly string[] | Record<string, string>,
): CloudflareSopsWorkerBindingSet => {
  const entries = Array.isArray(names)
    ? names.map((name) => [name, name] as const)
    : Object.entries(names);

  return {
    bindings: entries.map(([name, secretName]) => ({
      type: "secrets_store_secret",
      name,
      secretName,
      storeId: source.storeId,
    })),
  };
};

export const planCloudflareSecretImports = (
  secrets: SecretRecord,
  input: Pick<CloudflareSopsSecretsActionInput, "namePrefix" | "secrets">,
): readonly CloudflareSecretImport[] => {
  const entries = input.secrets
    ? Object.keys(input.secrets).map(
        (name) => [name, input.secrets![name]!] as const,
      )
    : Object.keys(secrets).map((path) => [
        `${input.namePrefix ?? ""}${cloudflareSecretName(path)}`,
        path,
      ] as const);

  return entries.map(([name, path]) => {
    const value = secrets[path];
    if (!value) {
      throw new SopsInputError({
        message: `Secret path "${path}" was not found in decrypted SOPS content`,
        field: "secrets",
      });
    }
    return { name, path, value };
  });
};

export const cloudflareSecretName = (path: string): string => {
  const name = path
    .replace(/\[(\d+)\]/g, "_$1")
    .replace(/[^A-Za-z0-9_]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .replace(/_+/g, "_")
    .toUpperCase();

  if (name === "") {
    throw new SopsInputError({
      message: `Cannot derive Cloudflare secret name from path "${path}"`,
      field: "secrets",
    });
  }

  return /^[A-Za-z_]/.test(name) ? name : `_${name}`;
};

const decryptForAction = (
  input: CloudflareSopsSecretsActionInput,
): Effect.Effect<string | readonly string[], unknown> => {
  const decryptOne = (path: string, content: string) => {
    const request = buildSopsCommandRequest({
      source: { path, content },
      options: {
        ...input,
        sopsArgs: input.sopsArgs ?? [],
        env: input.env ?? {},
        timeoutMs: input.timeoutMs ?? 30_000,
      },
    });

    return defaultDecrypt(input.backend ?? "auto", input.format ?? "auto")(
      request,
    );
  };

  if (isReadonlyStringArray(input.path) || isReadonlyStringArray(input.content)) {
    const paths = isReadonlyStringArray(input.path) ? input.path : [input.path];
    const contents = isReadonlyStringArray(input.content) ? input.content : [input.content];
    return Effect.all(
      contents.map((content, index) =>
        decryptOne(paths[index] ?? formatPath(input.path), content),
      ),
    );
  }

  return decryptOne(input.path, input.content);
};

const readEncryptedFile = (
  path: string | readonly string[],
  cwd: string | undefined,
): Effect.Effect<string | readonly string[]> =>
  Effect.tryPromise(async () => {
    const { readFile } = await import("node:fs/promises");
    const { isAbsolute, resolve } = await import("node:path");
    const readOne = (item: string) =>
      readFile(isAbsolute(item) ? item : resolve(cwd ?? process.cwd(), item), "utf8");
    return isReadonlyStringArray(path) ? Promise.all(path.map(readOne)) : readOne(path);
  }).pipe(Effect.orDie);

const materializeMergedSecretDocuments = (
  plaintexts: readonly string[],
  options: {
    readonly format: SopsDocumentFormat;
    readonly path: string;
    readonly secrets?: Record<string, string>;
  },
): Omit<MaterializedSecretDocument<unknown>, "value"> => {
  const values = plaintexts.map((plaintext) =>
    materializeSecretDocument(plaintext, options),
  );
  const mergedFlat = Object.assign({}, ...values.map((value) => value.flat));
  const mergedData = deepMergeAll(values.map((value) => value.data));
  return {
    format: values[0]?.format ?? resolveFallbackFormat(options.format),
    data: mergedData,
    flat: mergedFlat,
    secrets: selectSecrets(mergedFlat, options.secrets),
    topLevelKeys: Object.keys(mergedData),
  };
};

const selectSecrets = (
  flat: SecretRecord,
  selectors: Record<string, string> | undefined,
): SecretRecord => {
  if (!selectors) return flat;
  return Object.fromEntries(
    Object.entries(selectors).map(([name, path]) => {
      const value = flat[path];
      if (!value) {
        throw new SopsInputError({
          message: `Secret path "${path}" was not found in decrypted SOPS content`,
          field: "secrets",
        });
      }
      return [name, value];
    }),
  );
};

const deepMergeAll = (values: readonly SecretTree[]): SecretTree => {
  const merged: Record<string, SecretTree> = {};
  for (const value of values) {
    if (isPlainObject(value)) deepMerge(merged, value);
  }
  return merged;
};

const deepMerge = (
  target: Record<string, SecretTree>,
  source: Record<string, SecretTree>,
): void => {
  for (const [key, value] of Object.entries(source)) {
    if (isPlainObject(value) && isPlainObject(target[key])) {
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
};

const isPlainObject = (value: unknown): value is Record<string, SecretTree> =>
  value !== null &&
  typeof value === "object" &&
  !Array.isArray(value) &&
  !Redacted.isRedacted(value);

const formatPath = (path: string | readonly string[]): string =>
  isReadonlyStringArray(path) ? path.join(",") : path;

const isReadonlyStringArray = (value: unknown): value is readonly string[] =>
  Array.isArray(value);

const resolveFallbackFormat = (
  format: SopsDocumentFormat,
): ResolvedSopsDocumentFormat => (format === "auto" ? "json" : format);

const formatTopLevelKeys = (keys: readonly string[]): string =>
  keys.length === 0 ? "(none)" : keys.join(", ");
