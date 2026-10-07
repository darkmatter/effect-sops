import {
  GitHubSopsSecrets,
  type SecretStringInput,
} from "effect-sops";

const secretsPath = new URL("../_shared/secrets.sops.json", import.meta.url)
  .pathname;

export interface GitHubSecretsDemoOptions {
  readonly ageKey: SecretStringInput;
  readonly baseUrl?: string;
  readonly environment?: string;
  readonly owner: string;
  readonly repository: string;
}

export const program = (options: GitHubSecretsDemoOptions) =>
  GitHubSopsSecrets("GitHubActionsSecrets", {
    path: secretsPath,
    format: "json",
    ageKey: options.ageKey,
    owner: options.owner,
    repository: options.repository,
    ...(options.environment === undefined
      ? {}
      : { environment: options.environment }),
    ...(options.baseUrl === undefined ? {} : { baseUrl: options.baseUrl }),
    secrets: { DEPLOY_TOKEN: "api.token" },
  });
