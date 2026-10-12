import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import * as Effect from "effect/Effect";
import { decryptSops, findAllAgeKeys } from "@drkmttr/sops-age";
import { armor, Decrypter } from "age-encryption";
import {
  requestLabel,
  revealEnv,
  revealSecretString,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";
import { keyServiceSettings } from "./keyservice-options.js";
import { keyServiceTarget, unwrapRemoteAgeKey } from "./keyservice-client.js";
import {
  parseKeyServiceDocument,
  verifyKeyServiceMac,
} from "./keyservice-document.js";
import { encodeDecryptedValue, normalizeSopsExtract } from "./sops-age-core.js";

export const runSopsKeyService: SopsDecrypt = Effect.fn(
  "SopsKeyService.decrypt",
)((request: SopsCommandRequest) =>
  Effect.tryPromise({
    try: (signal) => decryptWithKeyService(request, signal),
    catch: (cause) =>
      new SopsDecryptError({
        message:
          cause instanceof Error
            ? cause.message
            : "Native keyservice decryption failed",
        path: requestLabel(request),
      }),
  }),
);

const decryptWithKeyService = async (
  request: SopsCommandRequest,
  interrupted: AbortSignal,
): Promise<string> => {
  if (request.args?.length)
    throw new Error(
      "Custom sopsArgs are not supported by native keyservice decryption",
    );
  if (request.inputType === "binary" || request.outputType === "binary")
    throw new Error(
      "Native keyservice decryption supports JSON, YAML, and dotenv",
    );
  const settings = keyServiceSettings(request);
  const enabled = settings.enableLocalKeyService;
  const local =
    enabled === true ||
    enabled === "true" ||
    enabled === "1" ||
    enabled === "TRUE" ||
    enabled === "True";
  if (
    !local &&
    enabled !== false &&
    enabled !== "false" &&
    enabled !== "0" &&
    enabled !== "FALSE" &&
    enabled !== "False"
  ) {
    throw new Error("SOPS_ENABLE_LOCAL_KEYSERVICE must be a boolean");
  }
  const targets = settings.keyServices.map(keyServiceTarget);
  if (!local && targets.length === 0)
    throw new Error(
      "Local keyservice is disabled and no remote keyservices are configured",
    );
  const timeoutMs = request.timeoutMs ?? 30_000;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0)
    throw new Error("Keyservice timeoutMs must be positive");
  const timeout = new AbortController();
  const timer = setTimeout(() => timeout.abort(), timeoutMs);
  const signal = AbortSignal.any([interrupted, timeout.signal]);
  const deadline = Date.now() + timeoutMs;
  let dataKey: Uint8Array | undefined;
  try {
    const content = await loadContent(request, signal);
    // Input and output formats are independent. Let the parser detect the input
    // when the request only specifies an output format (usual resource path).
    const document = parseKeyServiceDocument(content, request.inputType);
    if (local) {
      let keys: string[] = [];
      try {
        keys = await localKeys(request, signal);
      } catch {
        /* remote recovery may still succeed */
      }
      for (const entry of document.metadata.age) {
        signal.throwIfAborted();
        try {
          const decrypter = new Decrypter();
          for (const key of keys) {
            try {
              decrypter.addIdentity(key);
            } catch {
              /* Another identity may be usable. */
            }
          }
          const candidate = await decrypter.decrypt(
            armor.decode(entry.enc),
            "uint8array",
          );
          if (candidate.length === 32) {
            dataKey = candidate;
            break;
          }
        } catch {
          /* Try the next recipient without exposing identity errors. */
        }
      }
    }
    const failures: string[] = [];
    if (!dataKey) {
      for (const entry of document.metadata.age) {
        for (const target of targets) {
          signal.throwIfAborted();
          try {
            dataKey = await unwrapRemoteAgeKey(target, entry, signal, deadline);
            break;
          } catch (cause) {
            failures.push(
              cause instanceof Error ? cause.message : "Keyservice RPC failed",
            );
          }
        }
        if (dataKey) break;
      }
    }
    signal.throwIfAborted();
    if (!dataKey)
      throw new Error(
        `Could not recover the SOPS data key${failures.length ? `: ${[...new Set(failures)].join("; ")}` : " with local age identities"}`,
      );
    verifyKeyServiceMac(document, dataKey);
    // Normalize metadata once; preserves mac_only_encrypted for verification,
    // including dotenv metadata that the dependency otherwise drops.
    const decrypted: unknown = await decryptSops(document.root, {
      dataKey,
      ...(request.extract
        ? { keyPath: normalizeSopsExtract(request.extract) }
        : {}),
    });
    signal.throwIfAborted();
    return encodeDecryptedValue(decrypted, request.outputType);
  } catch (cause) {
    if (timeout.signal.aborted)
      throw new Error(
        `Native keyservice decryption timed out after ${timeoutMs}ms`,
      );
    throw cause;
  } finally {
    clearTimeout(timer);
    dataKey?.fill(0);
  }
};

const loadContent = async (
  request: SopsCommandRequest,
  signal: AbortSignal,
): Promise<string> => {
  if (request.content !== undefined) return revealSecretString(request.content);
  if (request.url !== undefined) {
    const response = await fetch(revealSecretString(request.url), { signal });
    if (!response.ok)
      throw new Error(
        `Could not fetch SOPS document (HTTP ${response.status})`,
      );
    return response.text();
  }
  if (request.path)
    return readFile(resolve(request.cwd ?? process.cwd(), request.path), {
      encoding: "utf8",
      signal,
    });
  throw new Error(
    "Native keyservice decryption requires content, a path, or a URL",
  );
};

const localKeys = async (
  request: SopsCommandRequest,
  signal: AbortSignal,
): Promise<string[]> => {
  const env = revealEnv(request.env);
  if (env.SOPS_AGE_KEY !== undefined) return splitKeys(env.SOPS_AGE_KEY);
  if (env.SOPS_AGE_KEY_FILE !== undefined)
    return splitKeys(
      await readFile(
        resolve(request.cwd ?? process.cwd(), env.SOPS_AGE_KEY_FILE),
        { encoding: "utf8", signal },
      ),
    );
  return findAllAgeKeys();
};

const splitKeys = (text: string): string[] =>
  text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"));
