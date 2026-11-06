/**
 * Wire contract of the SOPS keyservice: upstream `keyservice/keyservice.proto`
 * (getsops/sops v3.13) and the unqualified `/KeyService/Encrypt` and
 * `/KeyService/Decrypt` gRPC methods, as a `@grpc/grpc-js` service definition.
 */
import type { ServiceDefinition } from "@grpc/grpc-js";
import { parse } from "protobufjs";
import { sanitizeForDisplay, type KeyServiceKey } from "./model.js";

const root = parse(`syntax = "proto3";
  message Key {
    oneof key_type {
      KmsKey kms_key = 1;
      PgpKey pgp_key = 2;
      GcpKmsKey gcp_kms_key = 3;
      AzureKeyVaultKey azure_keyvault_key = 4;
      VaultKey vault_key = 5;
      AgeKey age_key = 6;
      HckmsKey hckms_key = 7;
    }
  }
  message PgpKey { string fingerprint = 1; }
  message KmsKey {
    string arn = 1;
    string role = 2;
    map<string, string> context = 3;
    string aws_profile = 4;
  }
  message GcpKmsKey { string resource_id = 1; }
  message VaultKey {
    string vault_address = 1;
    string engine_path = 2;
    string key_name = 3;
  }
  message AzureKeyVaultKey {
    string vault_url = 1;
    string name = 2;
    string version = 3;
  }
  message AgeKey { string recipient = 1; }
  message HckmsKey { string key_id = 1; }
  message EncryptRequest { Key key = 1; bytes plaintext = 2; }
  message EncryptResponse { bytes ciphertext = 1; }
  message DecryptRequest { Key key = 1; bytes ciphertext = 2; }
  message DecryptResponse { bytes plaintext = 1; }
`).root;

const types = {
  EncryptRequest: root.lookupType("EncryptRequest"),
  EncryptResponse: root.lookupType("EncryptResponse"),
  DecryptRequest: root.lookupType("DecryptRequest"),
  DecryptResponse: root.lookupType("DecryptResponse"),
};

/** A decoded `DecryptRequest`. `key` is undefined when the client sent none. */
export interface DecryptRequestMessage {
  readonly key: KeyServiceKey | undefined;
  readonly ciphertext: Uint8Array;
}

/** A decoded `EncryptRequest`. `key` is undefined when the client sent none. */
export interface EncryptRequestMessage {
  readonly key: KeyServiceKey | undefined;
  readonly plaintext: Uint8Array;
}

export interface DecryptResponseMessage {
  readonly plaintext: Uint8Array;
}

export interface EncryptResponseMessage {
  readonly ciphertext: Uint8Array;
}

type Fields = Record<string, unknown>;

const record = (value: unknown): Fields | undefined =>
  typeof value === "object" && value !== null ? (value as Fields) : undefined;

const text = (value: unknown): string =>
  typeof value === "string" ? value : "";

const bytes = (value: unknown): Uint8Array =>
  value instanceof Uint8Array ? value : new Uint8Array();

const stringMap = (value: unknown): Readonly<Record<string, string>> =>
  Object.fromEntries(
    Object.entries(record(value) ?? {}).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );

/** Map a decoded protobuf `Key` to {@link KeyServiceKey}; undefined when no variant is set. */
export const decodeKey = (value: unknown): KeyServiceKey | undefined => {
  const key = record(value);
  if (!key) return undefined;
  const age = record(key.ageKey);
  if (age) return { type: "age", recipient: text(age.recipient) };
  const pgp = record(key.pgpKey);
  if (pgp) return { type: "pgp", fingerprint: text(pgp.fingerprint) };
  const kms = record(key.kmsKey);
  if (kms)
    return {
      type: "kms",
      arn: text(kms.arn),
      role: text(kms.role),
      context: stringMap(kms.context),
      awsProfile: text(kms.awsProfile),
    };
  const gcp = record(key.gcpKmsKey);
  if (gcp) return { type: "gcp-kms", resourceId: text(gcp.resourceId) };
  const azure = record(key.azureKeyvaultKey);
  if (azure)
    return {
      type: "azure-keyvault",
      vaultUrl: text(azure.vaultUrl),
      name: text(azure.name),
      version: text(azure.version),
    };
  const vault = record(key.vaultKey);
  if (vault)
    return {
      type: "vault",
      vaultAddress: text(vault.vaultAddress),
      enginePath: text(vault.enginePath),
      keyName: text(vault.keyName),
    };
  const hckms = record(key.hckmsKey);
  if (hckms) return { type: "hckms", keyId: text(hckms.keyId) };
  return undefined;
};

/** Map {@link KeyServiceKey} back to protobuf `Key` fields (for clients and tests). */
export const encodeKey = (key: KeyServiceKey): Fields => {
  switch (key.type) {
    case "age":
      return { ageKey: { recipient: key.recipient } };
    case "pgp":
      return { pgpKey: { fingerprint: key.fingerprint } };
    case "kms":
      return {
        kmsKey: {
          arn: key.arn,
          role: key.role,
          context: key.context,
          awsProfile: key.awsProfile,
        },
      };
    case "gcp-kms":
      return { gcpKmsKey: { resourceId: key.resourceId } };
    case "azure-keyvault":
      return {
        azureKeyvaultKey: {
          vaultUrl: key.vaultUrl,
          name: key.name,
          version: key.version,
        },
      };
    case "vault":
      return {
        vaultKey: {
          vaultAddress: key.vaultAddress,
          enginePath: key.enginePath,
          keyName: key.keyName,
        },
      };
    case "hckms":
      return { hckmsKey: { keyId: key.keyId } };
  }
};

/**
 * Describe a key for prompts and logs, following upstream `keyToString`
 * (which has no age case and prints "Unknown key type" for it). Fields come
 * from the client, so the result is sanitized for display.
 */
export const describeKey = (key: KeyServiceKey): string => {
  const safe = (value: string) => sanitizeForDisplay(value, 120);
  switch (key.type) {
    case "age":
      return `age key with recipient ${safe(key.recipient)}`;
    case "pgp":
      return `PGP key with fingerprint ${safe(key.fingerprint)}`;
    case "kms":
      return `AWS KMS key with ARN ${safe(key.arn)}`;
    case "gcp-kms":
      return `GCP KMS key with resource ID ${safe(key.resourceId)}`;
    case "azure-keyvault":
      return `Azure Key Vault key with URL ${safe(`${key.vaultUrl}/keys/${key.name}/${key.version}`)}`;
    case "vault":
      return `Hashicorp Vault key with URI ${safe(`${key.vaultAddress}/v1/${key.enginePath}/keys/${key.keyName}`)}`;
    case "hckms":
      return `HuaweiCloud KMS key with ID ${safe(key.keyId)}`;
  }
};

export const decodeDecryptRequest = (buffer: Uint8Array): DecryptRequestMessage => {
  const message = record(types.DecryptRequest.decode(buffer)) ?? {};
  return { key: decodeKey(message.key), ciphertext: bytes(message.ciphertext) };
};

export const decodeEncryptRequest = (buffer: Uint8Array): EncryptRequestMessage => {
  const message = record(types.EncryptRequest.decode(buffer)) ?? {};
  return { key: decodeKey(message.key), plaintext: bytes(message.plaintext) };
};

export const encodeDecryptRequest = (value: {
  readonly key?: KeyServiceKey;
  readonly ciphertext: Uint8Array;
}): Buffer =>
  Buffer.from(
    types.DecryptRequest.encode({
      ...(value.key ? { key: encodeKey(value.key) } : {}),
      ciphertext: value.ciphertext,
    }).finish(),
  );

export const encodeEncryptRequest = (value: {
  readonly key?: KeyServiceKey;
  readonly plaintext: Uint8Array;
}): Buffer =>
  Buffer.from(
    types.EncryptRequest.encode({
      ...(value.key ? { key: encodeKey(value.key) } : {}),
      plaintext: value.plaintext,
    }).finish(),
  );

/**
 * Serialize a decrypt response, then erase the data key from the response
 * object: the serialized buffer is the only copy left once gRPC sends it.
 */
export const encodeDecryptResponse = (value: DecryptResponseMessage): Buffer => {
  const encoded = Buffer.from(
    types.DecryptResponse.encode({ plaintext: value.plaintext }).finish(),
  );
  value.plaintext.fill(0);
  return encoded;
};

export const decodeDecryptResponse = (buffer: Uint8Array): DecryptResponseMessage => ({
  plaintext: bytes(record(types.DecryptResponse.decode(buffer))?.plaintext),
});

export const encodeEncryptResponse = (value: EncryptResponseMessage): Buffer =>
  Buffer.from(
    types.EncryptResponse.encode({ ciphertext: value.ciphertext }).finish(),
  );

export const decodeEncryptResponse = (buffer: Uint8Array): EncryptResponseMessage => ({
  ciphertext: bytes(record(types.EncryptResponse.decode(buffer))?.ciphertext),
});

/** Request shapes the server receives (decoded) and clients send. */
export type DecryptRequestInput = Parameters<typeof encodeDecryptRequest>[0];
export type EncryptRequestInput = Parameters<typeof encodeEncryptRequest>[0];

/** `@grpc/grpc-js` definition of the upstream `KeyService` (server and client sides). */
export const keyServiceDefinition = {
  Decrypt: {
    path: "/KeyService/Decrypt",
    requestStream: false,
    responseStream: false,
    originalName: "decrypt",
    requestSerialize: encodeDecryptRequest,
    requestDeserialize: decodeDecryptRequest,
    responseSerialize: encodeDecryptResponse,
    responseDeserialize: decodeDecryptResponse,
  },
  Encrypt: {
    path: "/KeyService/Encrypt",
    requestStream: false,
    responseStream: false,
    originalName: "encrypt",
    requestSerialize: encodeEncryptRequest,
    requestDeserialize: decodeEncryptRequest,
    responseSerialize: encodeEncryptResponse,
    responseDeserialize: decodeEncryptResponse,
  },
} satisfies ServiceDefinition;
