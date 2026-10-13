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
import {
  keyServiceTarget,
  unwrapRemoteAgeKey,
  type AgeRecipient,
} from "./keyservice-client.js";
import {
  parseKeyServiceDocument,
  verifyKeyServiceMac,
} from "./keyservice-document.js";
import { encodeDecryptedValue, normalizeSopsExtract } from "./sops-age-core.js";

const asError = (cause: unknown): Error =>
  cause instanceof Error
    ? cause
    : new Error("Native keyservice decryption failed");

export const runSopsKeyService: SopsDecrypt = Effect.fn(
  "SopsKeyService.decrypt",
)(
  function* (request: SopsCommandRequest) {
    const settings = yield* Effect.try({
      try: () => validateRequest(request),
      catch: asError,
    });
    return yield* decryptWithKeyService(request, settings).pipe(
      Effect.timeoutOrElse({
        duration: settings.timeoutMs,
        orElse: () =>
          Effect.fail(
            new Error(
              `Native keyservice decryption timed out after ${settings.timeoutMs}ms`,
            ),
          ),
      }),
    );
  },
  (effect, request) =>
    effect.pipe(
      Effect.mapError(
        (cause) =>
          new SopsDecryptError({
            message: cause.message,
            path: requestLabel(request),
          }),
      ),
    ),
);

const validateRequest = (request: SopsCommandRequest) => {
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
  return { local, targets, timeoutMs };
};

const decryptWithKeyService = Effect.fn("SopsKeyService.decryptDocument")(
  function* (
    request: SopsCommandRequest,
    settings: ReturnType<typeof validateRequest>,
  ) {
    // gRPC deadlines use wall time; Effect owns the overall operation timeout.
    const deadline = Date.now() + settings.timeoutMs;
    const content = yield* Effect.tryPromise({
      try: (signal) => loadContent(request, signal),
      catch: asError,
    });
    // Input and output formats are independent. Let the parser detect the input
    // when the request only specifies an output format (usual resource path).
    const document = yield* Effect.try({
      try: () => parseKeyServiceDocument(content, request.inputType),
      catch: asError,
    });
    const dataKey = yield* Effect.acquireRelease(
      recoverDataKey(request, document.metadata.age, settings, deadline),
      (key) => Effect.sync(() => key.fill(0)),
      // Key recovery performs I/O and must remain interruptible during acquisition.
      { interruptible: true },
    );
    yield* Effect.try({
      try: () => verifyKeyServiceMac(document, dataKey),
      catch: asError,
    });
    // Normalize metadata once; preserves mac_only_encrypted for verification,
    // including dotenv metadata that the dependency otherwise drops.
    const decrypted: unknown = yield* Effect.tryPromise({
      try: () =>
        decryptSops(document.root, {
          dataKey,
          ...(request.extract
            ? { keyPath: normalizeSopsExtract(request.extract) }
            : {}),
        }),
      catch: asError,
    });
    return yield* Effect.try({
      try: () => encodeDecryptedValue(decrypted, request.outputType),
      catch: asError,
    });
  },
  Effect.scoped,
);

const recoverDataKey = Effect.fn("SopsKeyService.recoverDataKey")(function* (
  request: SopsCommandRequest,
  recipients: readonly AgeRecipient[],
  settings: ReturnType<typeof validateRequest>,
  deadline: number,
) {
  if (settings.local) {
    const keys = yield* Effect.tryPromise({
      try: (signal) => localKeys(request, signal),
      catch: asError,
    }).pipe(Effect.orElseSucceed((): string[] => []));
    for (const entry of recipients) {
      const key = yield* unwrapLocalAgeKey(entry, keys).pipe(
        Effect.orElseSucceed(() => undefined),
      );
      if (key) return key;
    }
  }
  const failures: string[] = [];
  for (const entry of recipients) {
    for (const target of settings.targets) {
      const key = yield* unwrapRemoteAgeKey(target, entry, deadline).pipe(
        Effect.orElseSucceed((error) => {
          failures.push(error.message);
          return undefined;
        }),
      );
      if (key) return key;
    }
  }
  return yield* Effect.fail(
    new Error(
      `Could not recover the SOPS data key${failures.length ? `: ${[...new Set(failures)].join("; ")}` : " with local age identities"}`,
    ),
  );
});

const unwrapLocalAgeKey = (entry: AgeRecipient, keys: readonly string[]) =>
  Effect.tryPromise({
    try: async (signal) => {
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
      // The age library cannot cancel crypto work. Erase any result arriving
      // after interruption, before it can escape the Promise adapter.
      if (signal.aborted || candidate.length !== 32) {
        candidate.fill(0);
        throw new Error("Local age identity did not recover a valid data key");
      }
      return candidate;
    },
    catch: asError,
  });

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
