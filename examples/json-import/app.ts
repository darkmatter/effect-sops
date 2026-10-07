import * as Output from "alchemy/Output";
import {
  SopsFile,
  type SecretStringInput,
} from "effect-sops";
import * as Effect from "effect/Effect";
import encrypted from "../_shared/secrets.sops.json" with { type: "json" };

export const program = (ageKey: SecretStringInput) =>
  Effect.gen(function* () {
    const secrets = yield* SopsFile("ImportedSecrets", {
      json: encrypted,
      ageKey,
    });

    return {
      apiToken: Output.map(secrets.data, (data) => data.api.token),
      enabled: Output.map(secrets.data, (data) => data.api.enabled),
      topLevelKeys: secrets.topLevelKeys,
    };
  });
