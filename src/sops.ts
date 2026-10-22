import * as Effect from "effect/Effect";

import { withErrorDetail } from "./error-detail.js";
import { SopsDecryptError } from "./errors.js";
import { requestLabel, type SopsDecrypt } from "./decrypt.js";

export {
  buildSopsArgs,
  defaultSopsDecryptMemoizeKey,
  memoizeDecrypt,
  revealEnv,
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
  type SopsDecryptMemoizeOptions,
} from "./decrypt.js";

export const runSopsCli: SopsDecrypt = (request) =>
  Effect.flatMap(
    Effect.tryPromise({
      try: () => import("./sops-cli.js"),
      catch: (cause) =>
        new SopsDecryptError({
          message: withErrorDetail("Failed to load the sops CLI backend", cause),
          path: requestLabel(request),
          cause,
        }),
    }),
    ({ runSopsCli }) => runSopsCli(request),
  );

export { runSopsAge } from "./sops-age.js";
export {
  runSopsKms,
  type SopsKmsEntry,
  type SopsKmsOptions,
} from "./sops-kms.js";
