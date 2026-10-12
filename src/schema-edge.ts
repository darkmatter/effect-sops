import { makeDecodeEffect } from "./schema-decode.js";
import { runSopsAge } from "./sops-age-edge.js";

export type {
  DecryptOptions,
  EncryptedFor,
  EncryptedScalar,
  SopsMetadata,
} from "./schema-decode.js";
export const decodeEffect = makeDecodeEffect(runSopsAge);
