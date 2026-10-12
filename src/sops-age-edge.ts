import * as Effect from "effect/Effect";
import { requestLabel, type SopsDecrypt } from "./decrypt.js";
import { SopsDecryptError } from "./errors.js";
import { usesKeyServices } from "./keyservice-options.js";
import { runSopsAge as runLocalAge } from "./sops-age-core.js";

export const runSopsAge: SopsDecrypt = (request) =>
  Effect.suspend(() =>
    usesKeyServices(request)
      ? Effect.fail(
          new SopsDecryptError({
            message:
              "SOPS keyservices require the Node/Bun entry point; the edge entry point has no gRPC transport",
            path: requestLabel(request),
          }),
        )
      : runLocalAge(request),
  );
