import { parse as parseDotenv } from "dotenv";
import { parse as parseYaml } from "yaml";
import * as Schema from "effect/Schema";
import * as Option from "effect/Option";
import * as Result from "effect/Result";
import * as Base64 from "effect/encoding/Base64";
import * as Hex from "effect/encoding/Hex";
import { gcm } from "@noble/ciphers/aes";
import { sha512 } from "@noble/hashes/sha2";
import type { SopsCliFormat } from "./decrypt.js";

const Metadata = Schema.Struct({
  age: Schema.Array(
    Schema.Struct({ recipient: Schema.String, enc: Schema.String }),
  ),
  mac: Schema.String,
  lastmodified: Schema.String,
  mac_only_encrypted: Schema.optionalKey(Schema.Boolean),
  unencrypted_suffix: Schema.optionalKey(Schema.String),
  encrypted_suffix: Schema.optionalKey(Schema.String),
  unencrypted_regex: Schema.optionalKey(Schema.String),
  encrypted_regex: Schema.optionalKey(Schema.String),
});
const Document = Schema.Record(Schema.String, Schema.Unknown);
const encoder = new TextEncoder();

export const parseKeyServiceDocument = (
  content: string,
  format?: SopsCliFormat,
) => {
  let document: unknown;
  if (format === "binary")
    throw new Error("Keyservice decryption supports JSON, YAML, and dotenv");
  try {
    if (format === "dotenv") document = dotenvDocument(content);
    else if (format === "json") document = JSON.parse(content);
    else if (format === "yaml") document = parseYaml(content);
    else {
      try {
        document = JSON.parse(content);
      } catch {
        const yaml: unknown = parseYaml(content);
        document =
          typeof yaml === "object" && yaml !== null
            ? yaml
            : dotenvDocument(content);
      }
    }
  } catch {
    throw new Error("Could not parse the SOPS keyservice document");
  }
  const root = decodeRecord(document);
  const rawMetadata = decodeRecord(root.sops);
  if (
    rawMetadata.key_groups !== undefined ||
    Number(rawMetadata.shamir_threshold ?? 0) > 1
  ) {
    throw new Error(
      "Native keyservice decryption does not support SOPS key groups or Shamir shares",
    );
  }
  if (
    rawMetadata.encrypted_comment_regex ||
    rawMetadata.unencrypted_comment_regex
  ) {
    throw new Error(
      "Native keyservice decryption does not support comment-based encryption rules",
    );
  }
  const decoded = Schema.decodeUnknownOption(Metadata)(rawMetadata);
  if (Option.isNone(decoded))
    throw new Error(
      "Invalid SOPS metadata: age recipients, MAC, and lastmodified are required",
    );
  const metadata = decoded.value;
  if (metadata.age.length === 0)
    throw new Error("Native keyservice decryption requires age recipients");
  return { root, metadata };
};

const decodeRecord = (value: unknown): Record<string, unknown> => {
  const decoded = Schema.decodeUnknownOption(Document)(value);
  if (Option.isNone(decoded))
    throw new Error("Expected a SOPS document and metadata object");
  return decoded.value;
};

const dotenvDocument = (content: string): Record<string, unknown> => {
  const values = parseDotenv(content);
  const root: Record<string, unknown> = {};
  const metadata: Record<string, unknown> = {};
  const age: Record<string, string>[] = [];
  for (const [key, value] of Object.entries(values)) {
    if (!key.startsWith("sops_")) {
      root[key] = value;
      continue;
    }
    const field = key.slice(5);
    const match = /^age__list_(\d+)__map_(enc|recipient)$/.exec(field);
    if (match) {
      const index = Number(match[1]);
      const name = match[2];
      if (name) (age[index] ??= {})[name] = value.replaceAll("\\n", "\n");
    } else
      metadata[field] =
        field === "mac_only_encrypted" ? value === "true" : value;
  }
  if (Object.keys(metadata).some((key) => key.startsWith("key_groups"))) {
    throw new Error(
      "Native keyservice decryption does not support SOPS key groups",
    );
  }
  return { ...root, sops: { ...metadata, age } };
};

const decodeBase64 = (value: string): Uint8Array =>
  Result.getOrThrowWith(
    Base64.decode(value),
    () => new Error("Invalid Base64 in SOPS encrypted scalar"),
  );

const decryptScalar = (value: string, key: Uint8Array, aad: string) => {
  const match =
    /^ENC\[AES256_GCM,data:([^,]+),iv:([^,]+),tag:([^,]+),type:([^\]]+)\]$/.exec(
      value,
    );
  const [, data, iv, tag, type] = match ?? [];
  if (!data || !iv || !tag || !type)
    throw new Error("Invalid SOPS encrypted scalar");
  const ciphertext = decodeBase64(data);
  const authTag = decodeBase64(tag);
  const combined = new Uint8Array(ciphertext.length + authTag.length);
  combined.set(ciphertext);
  combined.set(authTag, ciphertext.length);
  return {
    type,
    bytes: gcm(key, decodeBase64(iv), encoder.encode(aad)).decrypt(combined),
  };
};

// SOPS hashes scalar values in document order, skips nulls and comments, and
// uses capitalized booleans. Keys are authenticated by each scalar's GCM AAD.
export const verifyKeyServiceMac = (
  document: ReturnType<typeof parseKeyServiceDocument>,
  dataKey: Uint8Array,
): void => {
  const { root, metadata } = document;
  const unencryptedRegex = metadata.unencrypted_regex
    ? new RegExp(metadata.unencrypted_regex)
    : undefined;
  const encryptedRegex = metadata.encrypted_regex
    ? new RegExp(metadata.encrypted_regex)
    : undefined;
  const shouldEncrypt = (path: readonly string[]): boolean => {
    let encrypted = true;
    if (
      metadata.unencrypted_suffix &&
      path.some((key) => key.endsWith(metadata.unencrypted_suffix ?? ""))
    )
      encrypted = false;
    if (metadata.encrypted_suffix)
      encrypted = path.some((key) =>
        key.endsWith(metadata.encrypted_suffix ?? ""),
      );
    if (unencryptedRegex && path.some((key) => unencryptedRegex.test(key)))
      encrypted = false;
    if (encryptedRegex)
      encrypted = path.some((key) => encryptedRegex.test(key));
    return encrypted;
  };
  const hash = sha512.create();
  if (metadata.mac_only_encrypted)
    hash.update(
      Uint8Array.from([
        0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52, 0x7b, 0x10, 0x34, 0xf3,
        0xd1, 0x47, 0xbe, 0x0b, 0x0b, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6,
        0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69,
      ]),
    );
  const walk = (value: unknown, path: readonly string[]): void => {
    if (value === null) return;
    if (Array.isArray(value)) {
      for (const item of value) walk(item, path);
      return;
    }
    if (typeof value === "object") {
      for (const [key, child] of Object.entries(value))
        walk(child, [...path, key]);
      return;
    }
    const encrypted = shouldEncrypt(path);
    if (
      encrypted &&
      value !== "" &&
      (typeof value !== "string" || !value.startsWith("ENC["))
    ) {
      throw new Error("Expected an encrypted SOPS scalar");
    }
    if (!encrypted && typeof value === "string" && value.startsWith("ENC[")) {
      throw new Error(
        "Native keyservice decryption cannot preserve an unencrypted ENC scalar",
      );
    }
    if (encrypted && typeof value === "string" && value.startsWith("ENC[")) {
      const { type, bytes } = decryptScalar(
        value,
        dataKey,
        `${path.join(":")}:`,
      );
      if (type === "comment") return;
      hash.update(
        type === "bool"
          ? encoder.encode(
              new TextDecoder().decode(bytes).toLowerCase() === "true"
                ? "True"
                : "False",
            )
          : bytes,
      );
    } else if (!metadata.mac_only_encrypted) {
      if (typeof value === "boolean")
        hash.update(encoder.encode(value ? "True" : "False"));
      else if (typeof value === "string") hash.update(encoder.encode(value));
      else if (typeof value === "number" && Number.isFinite(value))
        hash.update(encoder.encode(decimal(value)));
      else throw new Error("Unsupported SOPS value for MAC verification");
    }
  };
  for (const [key, value] of Object.entries(root))
    if (key !== "sops") walk(value, [key]);
  const computed = Hex.encode(hash.digest()).toUpperCase();
  const stored = decryptScalar(metadata.mac, dataKey, metadata.lastmodified);
  if (
    stored.type !== "str" ||
    new TextDecoder().decode(stored.bytes) !== computed
  ) {
    throw new Error("SOPS document MAC verification failed");
  }
};

/** Go's strconv.FormatFloat(f, 'f', -1, 64), for unencrypted numeric leaves. */
const decimal = (value: number): string => {
  if (Object.is(value, -0)) return "-0";
  const text = String(value);
  if (!/[eE]/.test(text)) return text;
  const [coefficient = "", exponent = "0"] = text.split(/[eE]/);
  const negative = coefficient.startsWith("-");
  const unsigned = negative ? coefficient.slice(1) : coefficient;
  const dot = unsigned.indexOf(".");
  const digits = unsigned.replace(".", "");
  const position = (dot === -1 ? unsigned.length : dot) + Number(exponent);
  const expanded =
    position <= 0
      ? `0.${"0".repeat(-position)}${digits}`
      : position >= digits.length
        ? digits + "0".repeat(position - digits.length)
        : `${digits.slice(0, position)}.${digits.slice(position)}`;
  return (negative ? "-" : "") + expanded;
};
