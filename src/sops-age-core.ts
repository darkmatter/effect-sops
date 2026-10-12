import * as Effect from "effect/Effect";
import { decryptSops, type DecryptSopsOptions } from "@drkmttr/sops-age";
import { stringify as stringifyYaml } from "yaml";

import {
  requestLabel,
  revealEnv,
  revealSecretString,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";

type SopsAgeFileType = NonNullable<DecryptSopsOptions["fileType"]>;

export const runSopsAge: SopsDecrypt = (request) =>
  Effect.tryPromise({
    try: () => runSopsAgePromise(request),
    catch: (cause) =>
      cause instanceof SopsDecryptError
        ? cause
        : new SopsDecryptError({
            message: "Failed to decrypt SOPS content with sops-age",
            path: requestLabel(request),
            cause,
          }),
  });

const runSopsAgePromise = async (
  request: SopsCommandRequest,
): Promise<string> => {
  assertNativeCompatible(request);

  const options: DecryptSopsOptions = {
    ...nativeDecryptOptions(request),
  };
  const decrypted = await decryptSopsWithSource(request, options);

  return encodeDecryptedValue(decrypted, request.outputType);
};

const assertNativeCompatible = (request: SopsCommandRequest): void => {
  if (request.inputType === "binary" || request.outputType === "binary") {
    throw new SopsDecryptError({
      message:
        'The sops-age backend supports json, yaml, and dotenv files only; use backend: "cli" for binary SOPS files',
      path: requestLabel(request),
    });
  }

  if (request.args?.length) {
    throw new SopsDecryptError({
      message:
        'sopsArgs are only supported by the CLI backend; use backend: "cli" for custom sops flags',
      path: requestLabel(request),
    });
  }
};

const nativeDecryptOptions = (
  request: SopsCommandRequest,
): DecryptSopsOptions => {
  const env = revealEnv(request.env);
  const fileType = toSopsAgeFileType(request.inputType ?? request.outputType);
  const secretKey = env.SOPS_AGE_KEY;
  const extract = request.extract
    ? normalizeSopsExtract(request.extract)
    : undefined;

  return {
    ...(fileType ? { fileType } : {}),
    ...(secretKey ? { secretKey } : {}),
    ...(extract ? { keyPath: extract } : {}),
  };
};

const decryptSopsWithSource = (
  request: SopsCommandRequest,
  options: DecryptSopsOptions,
) => {
  if (request.content !== undefined) {
    return decryptSops(revealSecretString(request.content), options);
  }

  if (request.url !== undefined) {
    return decryptSops({
      url: revealSecretString(request.url),
      ...options,
    });
  }

  if (request.path) {
    return decryptSops({
      path: request.path,
      ...options,
    });
  }

  throw new SopsDecryptError({
    message: "The sops-age backend requires a path, url, or content source",
    path: requestLabel(request),
  });
};

const toSopsAgeFileType = (
  format: SopsCliFormat | undefined,
): SopsAgeFileType | undefined => {
  switch (format) {
    case undefined:
      return undefined;
    case "dotenv":
      return "env";
    case "json":
    case "yaml":
      return format;
    case "binary":
      throw new SopsDecryptError({
        message: "The sops-age backend does not support binary input",
        path: "<inline>",
      });
  }
};

/** `["a"]["b"]` (sops --extract syntax) or dotted → `a.b`. */
export const normalizeSopsExtract = (extract: string): string => {
  const trimmed = extract.trim();
  const bracketPath = [...trimmed.matchAll(/\[['"]([^'"]+)['"]\]/g)].map(
    (match) => match[1],
  );

  return bracketPath.length > 0 ? bracketPath.join(".") : trimmed;
};

/** Serialize a decrypted value in the requested SOPS output format. */
export const encodeDecryptedValue = (
  value: unknown,
  outputType: SopsCliFormat | undefined,
): string => {
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);

  switch (outputType) {
    case "yaml":
      return stringifyYaml(value);
    case "dotenv":
      return encodeDotenv(value);
    case "binary":
      throw new SopsDecryptError({
        message: "The sops-age backend does not support binary output",
        path: "<inline>",
      });
    case "json":
    case undefined:
      return JSON.stringify(value);
  }
};

const encodeDotenv = (value: unknown): string => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new SopsDecryptError({
      message: "dotenv output requires a decrypted object",
      path: "<inline>",
    });
  }

  return `${Object.entries(value as Record<string, unknown>)
    .map(([key, item]) => `${key}=${quoteDotenvValue(item)}`)
    .join("\n")}\n`;
};

const quoteDotenvValue = (value: unknown): string => {
  const stringValue = value === undefined ? "" : String(value);
  if (/^[A-Za-z0-9_./:-]*$/.test(stringValue)) return stringValue;
  return JSON.stringify(stringValue);
};
