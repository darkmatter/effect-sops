import * as GitHub from "@alchemy.run/github";
import * as Output from "alchemy/Output";
import type * as Provider from "alchemy/Provider";
import * as Effect from "effect/Effect";

import {
  SopsFile,
  type SopsFileOptions,
  type SopsFileResource,
} from "./resource.js";

/**
 * Options for importing selected SOPS values as GitHub Actions secrets.
 *
 * Secret names must be supplied explicitly because Alchemy registers one
 * `GitHub.Secret` resource per name while composing the stack. The map values
 * are dot-path selectors in the decrypted SOPS document.
 */
export interface GitHubSopsSecretsOptions<R = never>
  extends
    Omit<SopsFileOptions<R>, "secrets">,
    Omit<GitHub.SecretProps, "name" | "value"> {
  /** Maps GitHub Actions secret names to decrypted SOPS dot-path selectors. */
  readonly secrets: Record<string, string>;
}

export type GitHubSopsSecretsOutput = readonly GitHub.Secret[];

export function GitHubSopsSecrets<R = never>(
  input: GitHubSopsSecretsOptions<R>,
): Effect.Effect<
  GitHubSopsSecretsOutput,
  never,
  R | Provider.Provider<SopsFileResource> | GitHub.Providers
>;
export function GitHubSopsSecrets<R = never>(
  id: string,
  input: GitHubSopsSecretsOptions<R>,
): Effect.Effect<
  GitHubSopsSecretsOutput,
  never,
  R | Provider.Provider<SopsFileResource> | GitHub.Providers
>;
/**
 * Decrypt a SOPS document through {@link SopsFile} and manage the selected
 * values as repository or environment secrets with Alchemy's
 * {@link GitHub.Secret} resource.
 *
 * The SOPS resource keeps the selected values redacted. Each value remains an
 * Alchemy output, so the corresponding GitHub secret is updated whenever its
 * encrypted SOPS source changes.
 */
export function GitHubSopsSecrets<R = never>(
  ...args:
    | [input: GitHubSopsSecretsOptions<R>]
    | [id: string, input: GitHubSopsSecretsOptions<R>]
): Effect.Effect<
  GitHubSopsSecretsOutput,
  never,
  R | Provider.Provider<SopsFileResource> | GitHub.Providers
> {
  const [id, input] =
    args.length === 1
      ? ["GitHubSopsSecrets", args[0]]
      : (args as [string, GitHubSopsSecretsOptions<R>]);
  const { baseUrl, environment, owner, repository, secrets, ...sopsOptions } =
    input;

  return Effect.gen(function* () {
    const source = yield* SopsFile(`${id}Source`, {
      ...sopsOptions,
      secrets,
    });

    return yield* Effect.all(
      Object.keys(secrets).map((name) =>
        GitHub.Secret(`${id}-${name}`, {
          owner,
          repository,
          name,
          value: source.secrets.pipe(
            Output.map((values) => values[name]!),
          ),
          ...(environment === undefined ? {} : { environment }),
          ...(baseUrl === undefined ? {} : { baseUrl }),
        }),
      ),
    );
  });
}
