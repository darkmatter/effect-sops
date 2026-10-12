import * as Effect from "effect/Effect";
import { requestLabel, type SopsDecrypt } from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";
import { usesKeyServices } from "./keyservice-options.js";
import { runSopsAge as runLocalAge } from "./sops-age-core.js";

export { encodeDecryptedValue, normalizeSopsExtract } from "./sops-age-core.js";

/** Native age decryption, including SOPS keyservices when configured. */
export const runSopsAge: SopsDecrypt = (request) =>
  Effect.suspend(() => {
    if (!usesKeyServices(request)) return runLocalAge(request);
    return Effect.flatMap(
      Effect.tryPromise({
        try: () => import("./sops-keyservice.js"),
        catch: () =>
          new SopsDecryptError({
            message: "Could not load the native keyservice transport",
            path: requestLabel(request),
          }),
      }),
      ({ runSopsKeyService }) => runSopsKeyService(request),
    );
  });
