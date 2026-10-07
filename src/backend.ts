import * as Effect from "effect/Effect";

import type { SopsDocumentFormat } from "./document.js";
import { SopsDecryptError } from "./errors.js";
import { runSopsAge, runSopsCli, type SopsBackend, type SopsDecrypt } from "./sops.js";

/**
 * Selects the decrypt implementation for a backend.
 *
 * `auto` prefers the in-process `sops-age` backend and falls back to the CLI,
 * except for formats the native backend cannot represent.
 *
 * This lives outside `resource.ts` so entry points that must not depend on
 * Alchemy — such as `effect-sops/Config` — can share the same selection.
 */
export const defaultDecrypt = (backend: SopsBackend, format: SopsDocumentFormat): SopsDecrypt => {
  switch (backend) {
    case "cli":
      return runSopsCli;
    case "sops-age":
      return runSopsAge;
    case "auto":
      return format === "binary" || format === "text" ? runSopsCli : runSopsAgeWithCliFallback;
  }
};

export const runSopsAgeWithCliFallback: SopsDecrypt = (request) =>
  runSopsAge(request).pipe(
    Effect.catchIf(
      () => true,
      (nativeError) => {
        if (!request.path) return Effect.fail(nativeError);

        return runSopsCli(request).pipe(
          Effect.catchIf(
            () => true,
            (cliError) =>
              Effect.fail(
                new SopsDecryptError({
                  message: "Both sops-age and the sops CLI failed to decrypt",
                  path: request.path ?? "<inline>",
                  cause: { nativeError, cliError },
                }),
              ),
          ),
        );
      },
    ),
  );
