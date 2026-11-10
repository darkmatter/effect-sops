import {
  status,
  type ServerUnaryCall,
  type UntypedServiceImplementation,
  type sendUnaryData,
} from "@grpc/grpc-js";
import {
  Decrypter,
  Encrypter,
  armor,
  identityToRecipient,
} from "age-encryption";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";
import type { Type } from "protobufjs";
import {
  decryptRequestType,
  encryptRequestType,
  WireDecryptRequest,
  type WireDecryptResponse,
  WireEncryptRequest,
  type WireEncryptResponse,
  type WireKey,
} from "./keyservice-wire.js";

export interface ConfiguredIdentity {
  readonly identity: string;
  readonly recipient: string;
}

export class KeyServiceIdentityError extends Data.TaggedError(
  "KeyServiceIdentityError",
)<{
  readonly message: string;
}> {}

class KeyServiceRpcError extends Data.TaggedError("KeyServiceRpcError")<{
  readonly code: number;
  readonly message: string;
}> {}

const malformed = new KeyServiceRpcError({
  code: status.INVALID_ARGUMENT,
  message: "Malformed keyservice request",
});

const denied = new KeyServiceRpcError({
  code: status.PERMISSION_DENIED,
  message: "The requested recipient cannot decrypt this ciphertext",
});

const invalid = (message: string): KeyServiceRpcError =>
  new KeyServiceRpcError({ code: status.INVALID_ARGUMENT, message });

const decodeRequest = <Value>(
  type: Type,
  decode: (value: unknown) => Value,
  bytes: Buffer,
): Effect.Effect<Value, KeyServiceRpcError> =>
  Effect.try({
    // Plain objects omit protobuf's inherited null defaults for absent messages.
    try: () => decode(type.toObject(type.decode(bytes))),
    catch: () => malformed,
  });

const recipientFromKey = (
  key: WireKey | undefined,
): Effect.Effect<string, KeyServiceRpcError> => {
  if (key === undefined) return Effect.fail(invalid("A key is required"));
  const unsupported =
    key.kmsKey !== undefined ||
    key.pgpKey !== undefined ||
    key.gcpKmsKey !== undefined ||
    key.azureKeyVaultKey !== undefined ||
    key.vaultKey !== undefined;
  if (unsupported) {
    return Effect.fail(
      new KeyServiceRpcError({
        code: status.UNIMPLEMENTED,
        message: "Only age keys are supported",
      }),
    );
  }
  const recipient = key.ageKey?.recipient?.trim() ?? "";
  if (recipient.length === 0) {
    return Effect.fail(
      invalid(
        key.ageKey === undefined
          ? "A key is required"
          : "An age recipient is required",
      ),
    );
  }
  return Effect.try({
    try: () => {
      const encrypter = new Encrypter();
      encrypter.addRecipient(recipient);
      return recipient;
    },
    catch: () => invalid("Invalid age recipient"),
  });
};

const encryptRequest = (
  bytes: Buffer,
): Effect.Effect<WireEncryptResponse, KeyServiceRpcError> =>
  Effect.gen(function* () {
    const request = yield* decodeRequest(
      encryptRequestType,
      Schema.decodeUnknownSync(WireEncryptRequest),
      bytes,
    );
    const recipient = yield* recipientFromKey(request.key);
    const plaintext = request.plaintext;
    if (plaintext === undefined || plaintext.length === 0) {
      return yield* Effect.fail(invalid("Plaintext is required"));
    }
    const encrypted = yield* Effect.tryPromise({
      try: async () => {
        const encrypter = new Encrypter();
        encrypter.addRecipient(recipient);
        return encrypter.encrypt(plaintext);
      },
      catch: () =>
        new KeyServiceRpcError({
          code: status.INTERNAL,
          message: "Age encryption failed",
        }),
    });
    return { ciphertext: new TextEncoder().encode(armor.encode(encrypted)) };
  });

const decryptRequest = (
  bytes: Buffer,
  identities: readonly ConfiguredIdentity[],
): Effect.Effect<WireDecryptResponse, KeyServiceRpcError> =>
  Effect.gen(function* () {
    const request = yield* decodeRequest(
      decryptRequestType,
      Schema.decodeUnknownSync(WireDecryptRequest),
      bytes,
    );
    const recipient = yield* recipientFromKey(request.key);
    const identity = identities.find(
      (candidate) => candidate.recipient === recipient,
    );
    if (identity === undefined) return yield* Effect.fail(denied);
    const ciphertext = request.ciphertext;
    if (ciphertext === undefined || ciphertext.length === 0) {
      return yield* Effect.fail(invalid("Ciphertext is required"));
    }
    const encrypted = yield* Effect.try({
      try: () => armor.decode(new TextDecoder().decode(ciphertext)),
      catch: () => invalid("Malformed age ciphertext"),
    });
    const plaintext = yield* Effect.tryPromise({
      try: async () => {
        const decrypter = new Decrypter();
        decrypter.addIdentity(identity.identity);
        return decrypter.decrypt(encrypted, "uint8array");
      },
      catch: () => denied,
    });
    return { plaintext };
  });

const respond = <Response>(
  reply: sendUnaryData<Response>,
  effect: Effect.Effect<Response, KeyServiceRpcError>,
): void => {
  Effect.runPromise(effect).then(
    (value) => reply(null, value),
    (cause: unknown) => {
      if (cause instanceof KeyServiceRpcError) {
        reply({ code: cause.code, message: cause.message });
      } else {
        reply({
          code: status.INTERNAL,
          message: "Keyservice request failed",
        });
      }
    },
  );
};

export const createKeyServiceImplementation = (
  identities: readonly ConfiguredIdentity[],
): UntypedServiceImplementation => ({
  encrypt: (
    call: ServerUnaryCall<Buffer, WireEncryptResponse>,
    reply: sendUnaryData<WireEncryptResponse>,
  ) => {
    respond(reply, encryptRequest(call.request));
  },
  decrypt: (
    call: ServerUnaryCall<Buffer, WireDecryptResponse>,
    reply: sendUnaryData<WireDecryptResponse>,
  ) => {
    respond(reply, decryptRequest(call.request, identities));
  },
});

export const resolveConfiguredIdentities = (
  values: readonly string[],
): Effect.Effect<readonly ConfiguredIdentity[], KeyServiceIdentityError> => {
  const unique = [
    ...new Set(
      values.map((value) => value.trim()).filter((value) => value.length > 0),
    ),
  ];
  if (unique.length === 0) {
    return Effect.fail(
      new KeyServiceIdentityError({
        message: "No age identities are configured",
      }),
    );
  }
  return Effect.tryPromise({
    try: async () => {
      const resolved = await Promise.all(
        unique.map(async (identity) => ({
          identity,
          recipient: await identityToRecipient(identity),
        })),
      );
      const byRecipient = new Map<string, string>();
      for (const entry of resolved) {
        if (!byRecipient.has(entry.recipient)) {
          byRecipient.set(entry.recipient, entry.identity);
        }
      }
      return [...byRecipient].map(([recipient, identity]) => ({
        identity,
        recipient,
      }));
    },
    catch: () =>
      new KeyServiceIdentityError({
        message: "The configured age identities are invalid",
      }),
  });
};
