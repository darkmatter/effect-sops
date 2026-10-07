/**
 * KMS-wrapped SOPS decryption for runtimes that hold AWS credentials but no
 * age key and no `sops` binary — Cloudflare Workers assuming an IAM role
 * through OIDC, Lambda, ECS tasks.
 *
 * SOPS encrypts every leaf with AES-256-GCM under one random data key and
 * stores that key wrapped once per master key under `sops.kms[]` (for KMS)
 * or `sops.age[]` (for age). This backend asks the caller to unwrap one of
 * the `sops.kms[]` entries — via `kms:Decrypt` with whatever credentials the
 * runtime has — and hands the data key to `sops-age`, which performs the
 * same leaf decryption it does after an age unwrap.
 *
 * Not verified: the document-level `sops.mac` (same as the age backend).
 * Each leaf is still authenticated by its GCM tag and its path.
 */
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import { decryptSops } from "@drkmttr/sops-age";
import { parse as parseYaml } from "yaml";

import {
  requestLabel,
  revealSecretString,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";
import { encodeDecryptedValue, normalizeSopsExtract } from "./sops-age.js";

/** One `sops.kms[]` entry: the data key wrapped by one KMS key. */
export interface SopsKmsEntry {
  readonly arn: string;
  /** Base64 KMS ciphertext of the 32-byte data key. */
  readonly enc: string;
  readonly created_at?: string;
  readonly aws_profile?: string;
  readonly role?: string;
  readonly context?: Readonly<Record<string, string>>;
}

export interface SopsKmsOptions {
  /**
   * Unwrap a data key: typically `kms:Decrypt` of `entry.enc` against
   * `entry.arn` with the runtime's credentials. Tried for each candidate
   * entry in document order until one succeeds.
   */
  readonly unwrapDataKey: (entry: SopsKmsEntry) => Effect.Effect<Uint8Array, unknown>;
  /** Only try entries whose `arn` matches (a role usually can decrypt with one key). */
  readonly keyArn?: string;
}

type KmsFormat = "json" | "yaml";

const documentFormat = (request: SopsCommandRequest): KmsFormat | undefined => {
  const format = request.inputType ?? request.outputType ?? "json";
  return format === "json" || format === "yaml" ? format : undefined;
};

/** Just enough parsing to read `sops.kms[]`; sops-age parses the document itself. */
const kmsEntries = (
  request: SopsCommandRequest,
  format: KmsFormat,
  keyArn: string | undefined,
): Effect.Effect<ReadonlyArray<SopsKmsEntry>, SopsDecryptError> =>
  Effect.try({
    try: () => {
      if (request.content === undefined) {
        throw new Error("The kms backend requires inline `content`; read the file first");
      }
      const text = revealSecretString(request.content);
      const document: unknown = format === "json" ? JSON.parse(text) : parseYaml(text);
      const metadata = (document as { sops?: { kms?: unknown } } | null)?.sops;
      const entries = Array.isArray(metadata?.kms) ? (metadata.kms as SopsKmsEntry[]) : [];
      return entries.filter(
        (entry) =>
          typeof entry?.arn === "string" && typeof entry?.enc === "string" && (!keyArn || entry.arn === keyArn),
      );
    },
    catch: (cause) =>
      new SopsDecryptError({
        message: cause instanceof Error ? cause.message : "Failed to parse SOPS document",
        path: requestLabel(request),
        cause,
      }),
  });

/**
 * A `SopsDecrypt` whose master key is AWS KMS. Plug it in wherever a
 * `decrypt` is accepted (`SopsFile`, `effect-sops/Config`) or call it
 * directly at the edge.
 */
export const runSopsKms =
  (options: SopsKmsOptions): SopsDecrypt =>
  (request) =>
    Effect.gen(function* () {
      const label = requestLabel(request);
      const format = documentFormat(request);
      if (!format) {
        return yield* new SopsDecryptError({
          message: `The kms backend supports json and yaml documents, not ${request.inputType ?? request.outputType}`,
          path: label,
        });
      }
      const entries = yield* kmsEntries(request, format, options.keyArn);
      if (entries.length === 0) {
        return yield* new SopsDecryptError({
          message: options.keyArn
            ? `No sops.kms entry for ${options.keyArn}; the file is not encrypted to that key`
            : "No sops.kms entries; the file is not encrypted to any KMS key",
          path: label,
        });
      }

      const failures: unknown[] = [];
      let dataKey: Uint8Array | undefined;
      for (const entry of entries) {
        const attempt = yield* Effect.exit(options.unwrapDataKey(entry));
        if (Exit.isSuccess(attempt)) {
          dataKey = attempt.value;
          break;
        }
        failures.push({ arn: entry.arn, cause: attempt.cause });
      }
      if (!dataKey) {
        return yield* new SopsDecryptError({
          message: `Could not unwrap the SOPS data key with any of ${entries.length} KMS key(s)`,
          path: label,
          cause: failures,
        });
      }

      const decrypted = yield* Effect.tryPromise({
        try: () =>
          decryptSops(revealSecretString(request.content!), {
            dataKey,
            fileType: format,
            ...(request.extract ? { keyPath: normalizeSopsExtract(request.extract) } : {}),
          }),
        catch: (cause) =>
          new SopsDecryptError({
            message: "Failed to decrypt SOPS values with the unwrapped data key",
            path: label,
            cause,
          }),
      });
      return yield* Effect.try({
        try: () => encodeDecryptedValue(decrypted, request.outputType ?? request.inputType),
        catch: (cause) =>
          cause instanceof SopsDecryptError
            ? cause
            : new SopsDecryptError({ message: "Failed to encode decrypted value", path: label, cause }),
      });
    });
