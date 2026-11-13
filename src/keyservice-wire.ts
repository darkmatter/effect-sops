import type { ServiceDefinition } from "@grpc/grpc-js";
import { parse } from "protobufjs";
import * as Schema from "effect/Schema";

// Age-only subset of getsops/sops/keyservice/keyservice.proto. Field numbers
// and the unqualified /KeyService/* method names are the upstream wire
// contract; the other Key variants are modeled only so they can be rejected
// explicitly instead of silently ignored.
const protocol = parse(`syntax = "proto3";
  message AgeKey { string recipient = 1; }
  message KmsKey {}
  message PgpKey {}
  message GcpKmsKey {}
  message AzureKeyVaultKey {}
  message VaultKey {}
  message Key {
    oneof key_type {
      KmsKey kms_key = 1;
      PgpKey pgp_key = 2;
      GcpKmsKey gcp_kms_key = 3;
      AzureKeyVaultKey azure_key_vault_key = 4;
      VaultKey vault_key = 5;
      AgeKey age_key = 6;
    }
  }
  message EncryptRequest { Key key = 1; bytes plaintext = 2; }
  message EncryptResponse { bytes ciphertext = 1; }
  message DecryptRequest { Key key = 1; bytes ciphertext = 2; }
  message DecryptResponse { bytes plaintext = 1; }
`).root;

export const encryptRequestType = protocol.lookupType("EncryptRequest");
export const decryptRequestType = protocol.lookupType("DecryptRequest");
const encryptResponseType = protocol.lookupType("EncryptResponse");
const decryptResponseType = protocol.lookupType("DecryptResponse");

const WireAgeKey = Schema.Struct({
  recipient: Schema.optionalKey(Schema.String),
});

export const WireKey = Schema.Struct({
  ageKey: Schema.optionalKey(WireAgeKey),
  kmsKey: Schema.optionalKey(Schema.Unknown),
  pgpKey: Schema.optionalKey(Schema.Unknown),
  gcpKmsKey: Schema.optionalKey(Schema.Unknown),
  azureKeyVaultKey: Schema.optionalKey(Schema.Unknown),
  vaultKey: Schema.optionalKey(Schema.Unknown),
});
export type WireKey = typeof WireKey.Type;

export const WireEncryptRequest = Schema.Struct({
  key: Schema.optionalKey(WireKey),
  plaintext: Schema.optionalKey(Schema.Uint8Array),
});
export type WireEncryptRequest = typeof WireEncryptRequest.Type;

export const WireEncryptResponse = Schema.Struct({
  ciphertext: Schema.Uint8Array,
});
export type WireEncryptResponse = typeof WireEncryptResponse.Type;

export const WireDecryptRequest = Schema.Struct({
  key: Schema.optionalKey(WireKey),
  ciphertext: Schema.optionalKey(Schema.Uint8Array),
});
export type WireDecryptRequest = typeof WireDecryptRequest.Type;

export const WireDecryptResponse = Schema.Struct({
  plaintext: Schema.Uint8Array,
});
export type WireDecryptResponse = typeof WireDecryptResponse.Type;

export const keyServiceDefinition: ServiceDefinition = {
  encrypt: {
    path: "/KeyService/Encrypt",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: Buffer) => value,
    requestDeserialize: (value: Buffer) => value,
    responseSerialize: (value: WireEncryptResponse) =>
      Buffer.from(encryptResponseType.encode(value).finish()),
    responseDeserialize: (value: Buffer) =>
      Schema.decodeUnknownSync(WireEncryptResponse)(
        encryptResponseType.toObject(encryptResponseType.decode(value)),
      ),
  },
  decrypt: {
    path: "/KeyService/Decrypt",
    requestStream: false,
    responseStream: false,
    requestSerialize: (value: Buffer) => value,
    requestDeserialize: (value: Buffer) => value,
    responseSerialize: (value: WireDecryptResponse) =>
      Buffer.from(decryptResponseType.encode(value).finish()),
    responseDeserialize: (value: Buffer) =>
      Schema.decodeUnknownSync(WireDecryptResponse)(
        decryptResponseType.toObject(decryptResponseType.decode(value)),
      ),
  },
};
