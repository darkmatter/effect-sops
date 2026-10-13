import { Client, credentials } from "@grpc/grpc-js";
import { parse } from "protobufjs";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

// Age-only subset of getsops/sops/keyservice/keyservice.proto. Field numbers
// and the unqualified /KeyService/Decrypt method are the upstream wire contract.
const protocol = parse(`syntax = "proto3";
  message AgeKey { string recipient = 1; }
  message Key { oneof key_type { AgeKey age_key = 6; } }
  message DecryptRequest { Key key = 1; bytes ciphertext = 2; }
  message DecryptResponse { bytes plaintext = 1; }
`).root;
const requestType = protocol.lookupType("DecryptRequest");
const responseType = protocol.lookupType("DecryptResponse");
const Response = Schema.Struct({ plaintext: Schema.Uint8Array });

export interface AgeRecipient {
  readonly recipient: string;
  readonly enc: string;
}

export const keyServiceTarget = (uri: string): string => {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    throw new Error(
      "Expected a keyservice URI of unix:///absolute/path or tcp://host:port",
    );
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error(
      "Keyservice URIs cannot contain credentials, queries, or fragments",
    );
  }
  if (
    url.protocol === "unix:" &&
    !url.host &&
    url.pathname.startsWith("/") &&
    url.pathname !== "/"
  ) {
    return `unix:${decodeURIComponent(url.pathname)}`;
  }
  if (
    url.protocol === "tcp:" &&
    url.hostname &&
    url.port &&
    (!url.pathname || url.pathname === "/")
  ) {
    return url.host;
  }
  throw new Error(
    "Expected a keyservice URI of unix:///absolute/path or tcp://host:port",
  );
};

export const unwrapRemoteAgeKey = Effect.fn(
  "SopsKeyService.unwrapRemoteAgeKey",
)(function* (target: string, entry: AgeRecipient, deadline: number) {
  const client = yield* Effect.acquireRelease(
    Effect.sync(() => new Client(target, credentials.createInsecure())),
    (client) => Effect.sync(() => client.close()),
  );
  return yield* Effect.callback<Uint8Array, Error>((resume, signal) => {
    const call = client.makeUnaryRequest(
      "/KeyService/Decrypt",
      (value: AgeRecipient) =>
        Buffer.from(
          requestType
            .encode({
              key: { ageKey: { recipient: value.recipient } },
              ciphertext: Buffer.from(value.enc, "utf8"),
            })
            .finish(),
        ),
      (bytes) => Schema.decodeUnknownSync(Response)(responseType.decode(bytes)),
      entry,
      { deadline },
      (error, response) => {
        // A response arriving after cancellation must not retain key material.
        if (signal.aborted) {
          response?.plaintext.fill(0);
          return;
        }
        if (error)
          resume(
            Effect.fail(
              new Error(`Keyservice RPC failed (gRPC status ${error.code})`),
            ),
          );
        else if (!response || response.plaintext.length !== 32) {
          response?.plaintext.fill(0);
          resume(
            Effect.fail(
              new Error(
                "Keyservice returned an invalid data key; expected 32 bytes",
              ),
            ),
          );
        } else resume(Effect.succeed(response.plaintext));
      },
    );
    return Effect.sync(() => call.cancel());
  });
}, Effect.scoped);
