import { expect, test } from "bun:test";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

import * as SopsConfig from "../src/Config.ts";
import { SopsDecryptError } from "../src/errors.ts";
import type { SopsDecrypt } from "../src/sops.ts";
import nativeEncrypted from "./fixtures/native.enc.json" with { type: "json" };

const AGE_SECRET_KEY = "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";

const source = {
  json: nativeEncrypted,
  ageKey: Redacted.make(AGE_SECRET_KEY),
} as const;

// A `Config` is itself an `Effect`, so supplying the provider is all a lookup
// needs.
const resolve = <A>(config: Config.Config<A>, provider: ConfigProvider.ConfigProvider) =>
  Effect.provide(config, ConfigProvider.layer(provider));

const apiToken = Config.nested(Config.String("token"), "api");

test("resolves a nested path from the decrypted document", async () => {
  const token = await Effect.runPromise(resolve(apiToken, SopsConfig.make(source)));

  expect(token).toBe("native-token");
});

test("resolves a redacted config without revealing it", async () => {
  const token = await Effect.runPromise(
    resolve(Config.nested(Config.Redacted("token"), "api"), SopsConfig.make(source)),
  );

  expect(Redacted.isRedacted(token)).toBe(true);
  expect(Redacted.value(token)).toBe("native-token");
  expect(String(token)).not.toContain("native-token");
});

test("non-string leaves are readable as their config type", async () => {
  const count = await Effect.runPromise(
    resolve(Config.nested(Config.Int("count"), "nested"), SopsConfig.make(source)),
  );

  expect(count).toBe(3);
});

test("selectors flatten a nested document to single-segment lookups", async () => {
  const token = await Effect.runPromise(
    resolve(
      Config.String("API_TOKEN"),
      SopsConfig.make({ ...source, secrets: { API_TOKEN: "api.token" } }),
    ),
  );

  expect(token).toBe("native-token");
});

test("a missing path is absent rather than a failure, so fallbacks apply", async () => {
  const provider = SopsConfig.make(source).pipe(
    ConfigProvider.orElse(ConfigProvider.fromUnknown({ ABSENT: "fallback" })),
  );

  const value = await Effect.runPromise(resolve(Config.String("ABSENT"), provider));

  expect(value).toBe("fallback");
});

test("decrypts once across many lookups", async () => {
  let decryptions = 0;
  const counting: SopsDecrypt = () => {
    decryptions += 1;
    return Effect.succeed(JSON.stringify({ api: { token: "counted" } }));
  };

  const provider = SopsConfig.make({ ...source, decrypt: counting });

  for (let i = 0; i < 3; i += 1) {
    expect(await Effect.runPromise(resolve(apiToken, provider))).toBe("counted");
  }

  expect(decryptions).toBe(1);
});

test("never decrypts when an earlier provider supplies the value", async () => {
  let decryptions = 0;
  const failing: SopsDecrypt = () => {
    decryptions += 1;
    return Effect.fail(new SopsDecryptError({ message: "should not run", path: "<inline>" }));
  };

  const provider = ConfigProvider.fromUnknown({ TOKEN: "from-env" }).pipe(
    ConfigProvider.orElse(SopsConfig.make({ ...source, decrypt: failing })),
  );

  const value = await Effect.runPromise(resolve(Config.String("TOKEN"), provider));

  expect(value).toBe("from-env");
  expect(decryptions).toBe(0);
});

test("a decrypt failure surfaces the source label without leaking content", async () => {
  const failing: SopsDecrypt = () =>
    Effect.fail(
      new SopsDecryptError({
        message: "no identity matched",
        path: "secrets.sops.json",
      }),
    );

  const result = await Effect.runPromise(
    Effect.flip(
      resolve(apiToken, SopsConfig.make({ path: "secrets.sops.json", decrypt: failing })),
    ),
  );

  expect(String(result)).toContain("secrets.sops.json");
  expect(String(result)).not.toContain("native-token");
});

test("layerAdd resolves through the document when the environment misses", async () => {
  const token = await Effect.runPromise(Effect.provide(apiToken, SopsConfig.layerAdd(source)));

  expect(token).toBe("native-token");
});

test("provideCredentials wires both stack layers without eager decryption", async () => {
  let decryptions = 0;
  const counting: SopsDecrypt = () => {
    decryptions += 1;
    return Effect.succeed(JSON.stringify({ api: { token: "counted" } }));
  };

  const stack = SopsConfig.provideCredentials(
    { ...source, decrypt: counting },
    {
      providers: ConfigProvider.layer(ConfigProvider.fromUnknown({})),
      state: ConfigProvider.layer(ConfigProvider.fromUnknown({})),
    },
  );

  expect(stack.providers).toBeDefined();
  expect(stack.state).toBeDefined();
  expect(decryptions).toBe(0);
});
