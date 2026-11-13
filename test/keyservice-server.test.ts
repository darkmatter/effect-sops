import { describe, expect, test } from "bun:test";
import {
  Client,
  credentials,
  status,
  type ServiceError,
} from "@grpc/grpc-js";
import {
  Decrypter,
  armor,
  generateX25519Identity,
  identityToRecipient,
} from "age-encryption";
import * as Effect from "effect/Effect";
import { existsSync } from "node:fs";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parse } from "protobufjs";
import { keyServiceTarget } from "../src/keyservice-client.ts";
import {
  KeyServiceBindError,
  type KeyServiceHandle,
  startKeyService,
} from "../src/keyservice-server.ts";

interface EncryptResponse {
  readonly ciphertext: Uint8Array;
}

interface DecryptResponse {
  readonly plaintext: Uint8Array;
}

// Client-side view of the upstream age-only wire contract. The server owns its
// own definition; this keeps the test independent of server internals.
const protocol = parse(`syntax = "proto3";
  message AgeKey { string recipient = 1; }
  message KmsKey {}
  message Key { oneof key_type { KmsKey kms_key = 1; AgeKey age_key = 6; } }
  message EncryptRequest { Key key = 1; bytes plaintext = 2; }
  message EncryptResponse { bytes ciphertext = 1; }
  message DecryptRequest { Key key = 1; bytes ciphertext = 2; }
  message DecryptResponse { bytes plaintext = 1; }
`).root;

const encryptRequestType = protocol.lookupType("EncryptRequest");
const encryptResponseType = protocol.lookupType("EncryptResponse");
const decryptRequestType = protocol.lookupType("DecryptRequest");
const decryptResponseType = protocol.lookupType("DecryptResponse");

const call = <Response>(
  target: string,
  method: "encrypt" | "decrypt",
  request: object,
): Promise<Response> => {
  const client = new Client(target, credentials.createInsecure());
  const response = Promise.withResolvers<Response>();
  const [path, requestType, responseType] =
    method === "encrypt"
      ? [
          "/KeyService/Encrypt",
          encryptRequestType,
          encryptResponseType,
        ] as const
      : [
          "/KeyService/Decrypt",
          decryptRequestType,
          decryptResponseType,
        ] as const;
  client.makeUnaryRequest(
    path,
    (value: object) => Buffer.from(requestType.encode(value).finish()),
    (bytes: Uint8Array) => responseType.decode(bytes) as unknown as Response,
    request,
    {},
    (error, value) => {
      client.close();
      if (error) response.reject(error);
      else if (value === undefined) response.reject(new Error("No response"));
      else response.resolve(value);
    },
  );
  return response.promise;
};

const rawCall = (target: string, bytes: Buffer): Promise<ServiceError | null> => {
  const client = new Client(target, credentials.createInsecure());
  const failure = Promise.withResolvers<ServiceError | null>();
  client.makeUnaryRequest(
    "/KeyService/Decrypt",
    (value: Buffer) => value,
    (value: Uint8Array) => value,
    bytes,
    {},
    (error) => {
      client.close();
      failure.resolve(error);
    },
  );
  return failure.promise;
};

const rpcFailure = async (promise: Promise<unknown>): Promise<ServiceError> => {
  try {
    await promise;
  } catch (cause) {
    return cause as ServiceError;
  }
  throw new Error("Expected the keyservice RPC to fail");
};

const withServer = async (
  identities: readonly string[],
  address: string,
  body: (handle: KeyServiceHandle) => Promise<void>,
): Promise<void> => {
  await Effect.runPromise(
    Effect.scoped(
      Effect.gen(function* () {
        const handle = yield* startKeyService({ identities, address });
        yield* Effect.promise(() => body(handle));
      }),
    ),
  );
};

const newDataKey = (): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(32));

describe("effect-sops-keyservice server", () => {
  test("Encrypt and Decrypt roundtrip real SOPS age armor over TCP", async () => {
    const identity = await generateX25519Identity();
    const recipient = await identityToRecipient(identity);
    const dataKey = newDataKey();
    await withServer([identity], "127.0.0.1:0", async (handle) => {
      expect(handle.uri).toMatch(/^tcp:\/\/127\.0\.0\.1:\d+$/);
      const target = keyServiceTarget(handle.uri);
      const encrypted = await call<EncryptResponse>(target, "encrypt", {
        key: { ageKey: { recipient } },
        plaintext: dataKey,
      });
      const armored = new TextDecoder().decode(encrypted.ciphertext);
      expect(armored.startsWith("-----BEGIN AGE ENCRYPTED FILE-----")).toBe(
        true,
      );

      const direct = new Decrypter();
      direct.addIdentity(identity);
      expect(await direct.decrypt(armor.decode(armored), "uint8array")).toEqual(
        dataKey,
      );

      const decrypted = await call<DecryptResponse>(target, "decrypt", {
        key: { ageKey: { recipient } },
        ciphertext: new TextEncoder().encode(armored),
      });
      expect(decrypted.plaintext).toEqual(dataKey);
    });
  });

  test("rejects missing, unsupported, and invalid age key requests", async () => {
    const identity = await generateX25519Identity();
    const recipient = await identityToRecipient(identity);
    await withServer([identity], "127.0.0.1:0", async (handle) => {
      const target = keyServiceTarget(handle.uri);
      const missing = await rpcFailure(
        call(target, "encrypt", { plaintext: newDataKey() }),
      );
      expect(missing.code).toBe(status.INVALID_ARGUMENT);

      const unsupported = await rpcFailure(
        call(target, "encrypt", {
          key: { kmsKey: {} },
          plaintext: newDataKey(),
        }),
      );
      expect(unsupported.code).toBe(status.UNIMPLEMENTED);

      const invalidRecipient = await rpcFailure(
        call(target, "encrypt", {
          key: { ageKey: { recipient: "age1not-a-recipient" } },
          plaintext: newDataKey(),
        }),
      );
      expect(invalidRecipient.code).toBe(status.INVALID_ARGUMENT);
    });
  });

  test("Decrypt only uses the identity matching the requested recipient", async () => {
    const identity = await generateX25519Identity();
    const otherIdentity = await generateX25519Identity();
    const recipient = await identityToRecipient(identity);
    const otherRecipient = await identityToRecipient(otherIdentity);
    const dataKey = newDataKey();
    await withServer(
      [identity, otherIdentity],
      "127.0.0.1:0",
      async (handle) => {
        const target = keyServiceTarget(handle.uri);
        const encrypted = await call<EncryptResponse>(target, "encrypt", {
          key: { ageKey: { recipient } },
          plaintext: dataKey,
        });
        const mismatch = await rpcFailure(
          call(target, "decrypt", {
            key: { ageKey: { recipient: otherRecipient } },
            ciphertext: encrypted.ciphertext,
          }),
        );
        expect(mismatch.code).toBe(status.PERMISSION_DENIED);
        expect(mismatch.details.includes(identity)).toBe(false);
        expect(mismatch.details).not.toContain(recipient);
      },
    );
  });

  test("malformed ciphertext and wire input fail without leaking input", async () => {
    const identity = await generateX25519Identity();
    const recipient = await identityToRecipient(identity);
    const malformedText = "this is not an age file";
    await withServer([identity], "127.0.0.1:0", async (handle) => {
      const target = keyServiceTarget(handle.uri);
      const malformed = await rpcFailure(
        call(target, "decrypt", {
          key: { ageKey: { recipient } },
          ciphertext: new TextEncoder().encode(malformedText),
        }),
      );
      expect(malformed.code).toBe(status.INVALID_ARGUMENT);
      expect(malformed.details).not.toContain(malformedText);

      const missing = await rpcFailure(
        call(target, "decrypt", { key: { ageKey: { recipient } } }),
      );
      expect(missing.code).toBe(status.INVALID_ARGUMENT);

      const wire = await rawCall(target, Buffer.from([0xff, 0xff, 0xff]));
      expect(wire?.code).toBe(status.INVALID_ARGUMENT);
    });
  });
});

describe("listener lifecycle", () => {
  test("TCP reports the assigned port and releases it on close", async () => {
    const identity = await generateX25519Identity();
    let uri = "";
    await withServer([identity], "127.0.0.1:0", async (handle) => {
      uri = handle.uri;
    });
    const port = Number(new URL(uri).port);
    expect(port).toBeGreaterThan(0);
    await withServer([identity], `127.0.0.1:${port}`, async (handle) => {
      expect(handle.uri).toBe(`tcp://127.0.0.1:${port}`);
    });
  });

  test("Unix sockets serve RPC, are cleaned up, and pre-existing files survive", async () => {
    const identity = await generateX25519Identity();
    const recipient = await identityToRecipient(identity);
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-socket-"));
    try {
      const socketPath = join(dir, "service.sock");
      await withServer([identity], `unix:${socketPath}`, async (handle) => {
        expect(handle.uri).toBe(`unix://${socketPath}`);
        expect(existsSync(socketPath)).toBe(true);
        const before = await lstat(socketPath, { bigint: true });
        const second = await Effect.runPromise(Effect.scoped(Effect.result(
          startKeyService({ identities: [identity], address: `unix:${socketPath}` }),
        )));
        expect(second).toMatchObject({
          _tag: "Failure", failure: { _tag: "KeyServiceBindError" },
        });
        const after = await lstat(socketPath, { bigint: true });
        expect(after.dev).toBe(before.dev);
        expect(after.ino).toBe(before.ino);
        const dataKey = newDataKey();
        const target = keyServiceTarget(handle.uri);
        const encrypted = await call<EncryptResponse>(target, "encrypt", {
          key: { ageKey: { recipient } },
          plaintext: dataKey,
        });
        const decrypted = await call<DecryptResponse>(target, "decrypt", {
          key: { ageKey: { recipient } },
          ciphertext: encrypted.ciphertext,
        });
        expect(decrypted.plaintext).toEqual(dataKey);
      });
      expect(existsSync(socketPath)).toBe(false);

      await writeFile(socketPath, "keep");
      await expect(
        withServer([identity], `unix:${socketPath}`, async () => {}),
      ).rejects.toBeInstanceOf(KeyServiceBindError);
      expect(await readFile(socketPath, "utf8")).toBe("keep");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
