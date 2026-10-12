export {
  decodeEffect,
  type DecryptOptions,
  type EncryptedFor,
  type EncryptedScalar,
  type SopsMetadata,
} from "./schema-edge.js";
export {
  runSopsAge,
} from "./sops-age-edge.js";
export {
  runSopsKms,
  type SopsKmsEntry,
  type SopsKmsOptions,
} from "./sops-kms.js";
export {
  buildSopsArgs,
  defaultSopsDecryptMemoizeKey,
  memoizeDecrypt,
  type SopsBackend,
  type SopsCliFormat,
  type SopsCommandRequest,
  type SopsDecrypt,
  type SopsDecryptMemoizeOptions,
} from "./decrypt.js";
export {
  generateSecretTypes,
  materializeSecretDocument,
  resolveDocumentFormat,
  topLevelSecretKeys,
  type GenerateSecretTypesOptions,
  type MaterializedSecretDocument,
  type ResolvedSopsDocumentFormat,
  type SecretRecord,
  type SecretTree,
  type SopsDocumentFormat,
} from "./document.js";
export {
  type MaybeRedactedString,
  type SecretStringInput,
  resolveSecretStringInput,
} from "./input.js";
export * from "./errors.js";

export type { SopsKeyServiceOptions } from "./keyservice-options.js";
