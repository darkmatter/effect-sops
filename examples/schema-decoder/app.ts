import * as SopsSchema from "effect-sops/Schema";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import encrypted from "../_shared/secrets.sops.json" with { type: "json" };

const AppSecrets = Schema.Struct({
  api: Schema.Struct({
    token: Schema.RedactedFromValue(Schema.String),
    enabled: Schema.Boolean,
  }),
  nested: Schema.Struct({ count: Schema.Number }),
});

export const readSecrets = (ageKey: string | Redacted.Redacted<string>) =>
  SopsSchema.decodeEffect(AppSecrets)(encrypted, { ageKey });
