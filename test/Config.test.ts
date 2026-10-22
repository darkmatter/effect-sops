import { expect, test } from "bun:test";
import * as Config from "effect/Config";
import * as ConfigProvider from "effect/ConfigProvider";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Redacted from "effect/Redacted";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import * as SopsConfig from "../src/Config.ts";
import { SopsDecryptError } from "../src/errors.ts";
import type { SopsDecrypt } from "../src/sops.ts";
import nativeEncrypted from "./fixtures/native.enc.json" with { type: "json" };

const AGE_SECRET_KEY = "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";

const source = {
  json: nativeEncrypted,
  ageKey: Redacted.make(AGE_SECRET_KEY),
} as const;
// A throwaway identity that is not a recipient of the fixture.
const WRONG_AGE_SECRET_KEY =
  "AGE-SECRET-KEY-1Y9DUG8247C74EHHWK2242TTHR7JMNWHX2E4LTQ4XD6548T7AW05QDEG6JV";

const fixturePath = join(import.meta.dir, "fixtures/native.enc.json");

const STDERR = "Failed to get the data key required to decrypt the SOPS file.";

const makeFailingSops = async (name: string): Promise<string> => {
  const dir = join(import.meta.dir, ".tmp", name);
  const binary = join(dir, "sops-fake");
  await mkdir(dir, { recursive: true });
  await writeFile(
    binary,
    [
      "#!/usr/bin/env bun",
      `process.stderr.write(${JSON.stringify(`${STDERR}\n`)});`,
      "process.exit(128);",
    ].join("\n"),
  );
  await chmod(binary, 0o755);
  return binary;
};

const failureMessage = async (provider: ConfigProvider.ConfigProvider): Promise<string> => {
  const exit = await Effect.runPromiseExit(resolve(apiToken, provider));
  expect(Exit.isFailure(exit)).toBe(true);
  if (!Exit.isFailure(exit)) return "";
  const error: unknown = Cause.squash(exit.cause);
  return error instanceof Error ? error.message : String(error);
};

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
  expect(String(result)).toContain("no identity matched");
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

test("a failing sops CLI surfaces its stderr in the config error message", async () => {
  const sopsBinary = await makeFailingSops("config-cli-failure");

  const message = await failureMessage(
    SopsConfig.make({ path: fixturePath, backend: "cli", sopsBinary, keyServices: [] }),
  );

  expect(message).toContain(
    `Failed to read SOPS config from ${fixturePath}: sops exited with code 128: ${STDERR}`,
  );
  expect(message).not.toContain("\n");
  expect(message).not.toContain("native-token");
});

test("the auto fallback message names both backends and their reasons", async () => {
  const sopsBinary = await makeFailingSops("config-fallback-failure");

  const message = await failureMessage(
    SopsConfig.make({
      path: fixturePath,
      sopsBinary,
      keyServices: [],
      ageKey: Redacted.make(WRONG_AGE_SECRET_KEY),
    }),
  );

  expect(message).toContain(
    "Both sops-age and the sops CLI failed to decrypt (sops-age: Failed to decrypt SOPS content with sops-age:",
  );
  expect(message).toContain(`; sops CLI: sops exited with code 128: ${STDERR})`);
  expect(message).not.toContain("native-token");
  expect(message).not.toContain(WRONG_AGE_SECRET_KEY);
});
