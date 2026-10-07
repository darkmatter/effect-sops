import * as SopsConfig from "effect-sops/Config";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

const secretsPath = new URL("../_shared/secrets.sops.json", import.meta.url)
  .pathname;

export const readAppConfig = (ageKey: string | Redacted.Redacted<string>) =>
  Effect.all({
    apiToken: Config.nested(Config.Redacted("token"), "api"),
    retryCount: Config.nested(Config.Int("count"), "nested"),
  }).pipe(
    Effect.provide(
      ConfigProvider.layer(
        SopsConfig.make({ path: secretsPath, ageKey, format: "json" }),
      ),
    ),
  );
