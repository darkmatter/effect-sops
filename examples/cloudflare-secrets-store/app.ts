import {
  CloudflareSopsSecrets,
  type MaybeRedactedString,
} from "effect-sops";

const secretsPath = new URL("../_shared/secrets.sops.json", import.meta.url)
  .pathname;

export interface CloudflareSecretsDemoOptions {
  readonly accountId: string;
  readonly ageKey: MaybeRedactedString;
  readonly storeId: string;
}

export const program = (options: CloudflareSecretsDemoOptions) =>
  CloudflareSopsSecrets("WorkerSecrets", {
    path: secretsPath,
    format: "json",
    ageKey: options.ageKey,
    store: {
      accountId: options.accountId,
      storeId: options.storeId,
    },
    comment: "managed by the effect-sops example",
    secrets: { API_TOKEN: "api.token" },
  });
