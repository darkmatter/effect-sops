import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import type * as SchemaAST from "effect/SchemaAST";

import { SopsDecryptError } from "./errors.js";
import { runSopsAge } from "./sops-age.js";

/** A scalar value that can occur at a leaf in an imported SOPS JSON file. */
export type EncryptedScalar = string | number | boolean | null;

/** The top-level metadata object required by SOPS JSON documents. */
export type SopsMetadata = Readonly<Record<string, unknown>>;

type EncryptLeaves<T> = T extends EncryptedScalar | undefined
  ? EncryptedScalar
  : T extends readonly unknown[]
    ? { [K in keyof T]: EncryptLeaves<T[K]> }
    : T extends object
      ? { [K in keyof T]: EncryptLeaves<T[K]> }
      : EncryptedScalar;

/**
 * The imported SOPS JSON shape accepted for a struct schema.
 *
 * Encoded keys, nesting, arrays, and property optionality are retained while
 * scalar leaves accept encrypted JSON scalars. SOPS metadata is required at the
 * document root and is removed by decryption before schema decoding.
 */
export type EncryptedFor<
  S extends Schema.Struct<Schema.Struct.Fields>,
> = EncryptLeaves<Schema.Codec.Encoded<S>> & {
  readonly sops: SopsMetadata;
};

/** Options that do not alter the statically known imported JSON shape. */
export interface DecryptOptions {
  /**
   * An explicit age identity. When omitted, `sops-age` uses its normal identity
   * discovery mechanism.
   */
  readonly ageKey?: string | Redacted.Redacted<string>;
}

/**
 * Decrypts an imported SOPS JSON document and decodes its plaintext with an
 * Effect Schema struct.
 *
 * @example
 * ```ts
 * import * as Schema from "effect-sops/Schema";
 * import * as EffectSchema from "effect/Schema";
 * import encrypted from "./secrets.enc.json" with { type: "json" };
 *
 * const AppSecrets = EffectSchema.Struct({ token: EffectSchema.String });
 * const program = Schema.decodeEffect(AppSecrets)(encrypted);
 * ```
 */
export const decodeEffect = <
  S extends Schema.Struct<Schema.Struct.Fields>,
>(
  schema: S,
  parseOptions?: SchemaAST.ParseOptions,
): ((
  encryptedJson: EncryptedFor<S>,
  decryptOptions?: DecryptOptions,
) => Effect.Effect<
  S["Type"],
  SopsDecryptError | Schema.SchemaError,
  S["DecodingServices"]
>) => {
  const decode = Schema.decodeUnknownEffect(
    Schema.fromJsonString(schema),
    parseOptions,
  );

  return (encryptedJson, decryptOptions) =>
    stringifyEncryptedJson(encryptedJson).pipe(
      Effect.flatMap((content) =>
        runSopsAge({
          content,
          binary: "sops",
          inputType: "json",
          outputType: "json",
          ...(decryptOptions?.ageKey !== undefined
            ? { env: { SOPS_AGE_KEY: decryptOptions.ageKey } }
            : {}),
        }),
      ),
      Effect.flatMap((decrypted) => decode(decrypted)),
    );
};

const stringifyEncryptedJson = (
  encryptedJson: object,
): Effect.Effect<string, SopsDecryptError> =>
  Effect.try({
    try: () => {
      const content = JSON.stringify(encryptedJson);
      if (content === undefined) {
        throw new Error("Encrypted SOPS JSON serialization returned no value");
      }
      return content;
    },
    catch: () =>
      new SopsDecryptError({
        message: "Failed to serialize encrypted SOPS JSON",
        path: "<inline>",
      }),
  });
