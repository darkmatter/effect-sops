import { describe, expect, test } from "bun:test";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

import { resolveSecretStringInput } from "../src/input.ts";

describe("resolveSecretStringInput", () => {
  test("accepts a literal string", async () => {
    const value = await Effect.runPromise(resolveSecretStringInput("literal"));

    expect(value).toBe("literal");
  });

  test("preserves an existing Redacted string", async () => {
    const secret = Redacted.make("from-redacted");
    const value = await Effect.runPromise(resolveSecretStringInput(secret));

    expect(Redacted.isRedacted(value)).toBe(true);
    expect(Redacted.value(value as Redacted.Redacted<string>)).toBe(
      "from-redacted",
    );
  });

  test("accepts an Effect that resolves to a string", async () => {
    const value = await Effect.runPromise(
      resolveSecretStringInput(Effect.succeed("from-effect")),
    );

    expect(value).toBe("from-effect");
  });

  test("accepts an Effect Config value", async () => {
    const provider = ConfigProvider.fromUnknown({
      SOPS_FILE: "./secrets.enc.yaml",
    });

    const value = await Effect.runPromise(
      resolveSecretStringInput(Config.String("SOPS_FILE")).pipe(
        Effect.provideService(ConfigProvider.ConfigProvider, provider),
      ),
    );

    expect(value).toBe("./secrets.enc.yaml");
  });
});
