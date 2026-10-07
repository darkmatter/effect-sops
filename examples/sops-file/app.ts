import * as Output from "alchemy/Output";
import {
  SopsFile,
  type SecretStringInput,
} from "effect-sops";
import * as Effect from "effect/Effect";

const secretsPath = new URL("../_shared/secrets.sops.json", import.meta.url)
  .pathname;

export const program = (ageKey: SecretStringInput) =>
  Effect.gen(function* () {
    const secrets = yield* SopsFile("AppSecrets", {
      path: secretsPath,
      format: "json",
      ageKey,
      secrets: { API_TOKEN: "api.token" },
    });

    return {
      apiToken: Output.map(secrets.secrets, (values) => values.API_TOKEN!),
      sourceHash: secrets.sourceHash,
      topLevelKeys: secrets.topLevelKeys,
    };
  });
