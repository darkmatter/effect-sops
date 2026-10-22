import { expect, test } from "bun:test";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { runSopsKms, type SopsKmsEntry } from "../src/index.ts";
import { runSopsKms as runSopsKmsEdge } from "../src/edge.ts";

// Fixtures were produced by `sops encrypt --kms <sops-dev key>` (sops 3.13.3).
// Their data keys were unwrapped once with kms:Decrypt so the tests can run
// without AWS; the plaintexts are dummies.
const KEY_ARN = "arn:aws:kms:us-west-2:950224716579:key/71e3cd26-ace6-41a0-8ab1-ed51a941443a";
const JSON_DATA_KEY = "dPWCsU2WoMxkt638wv7gCNNQriCEZWn/Tzb5O0NLC3o=";
const YAML_DATA_KEY = "ejyHXlyzQISuSIoQ5+gTu2v7B0AhIWwhC5GJeuccmwU=";

const fromBase64 = (value: string) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
const fixture = (name: string) => readFile(join(import.meta.dir, "fixtures", name), "utf8");

const fakeKms = (dataKey: string) => {
  const seen: SopsKmsEntry[] = [];
  const unwrapDataKey = (entry: SopsKmsEntry) => {
    seen.push(entry);
    return Effect.succeed(fromBase64(dataKey));
  };
  return { unwrapDataKey, seen };
};

test("decrypts a KMS-encrypted JSON document produced by the sops CLI", async () => {
  const { unwrapDataKey, seen } = fakeKms(JSON_DATA_KEY);
  const plaintext = await Effect.runPromise(
    runSopsKms({ unwrapDataKey })({
      content: await fixture("kms.enc.json"),
      binary: "sops",
      inputType: "json",
      outputType: "json",
    }),
  );
  expect(JSON.parse(plaintext)).toEqual({
    api: { token: "kms-token", enabled: true, retries: 3, ratio: 0.5 },
    hosts: ["alpha", "beta"],
    nested: { deep: { value: "leaf" } },
    empty: "",
  });
  expect(seen).toHaveLength(1);
  expect(seen[0]?.arn).toBe(KEY_ARN);
  expect(seen[0]?.enc).toMatch(/^AQICAH/);
});

test("decrypts a KMS-encrypted YAML document and re-emits YAML", async () => {
  const { unwrapDataKey } = fakeKms(YAML_DATA_KEY);
  const plaintext = await Effect.runPromise(
    runSopsKms({ unwrapDataKey })({
      content: await fixture("kms.enc.yaml"),
      binary: "sops",
      inputType: "yaml",
      outputType: "yaml",
    }),
  );
  expect(plaintext).toContain("token: kms-token");
  expect(plaintext).toContain("enabled: true");
  expect(plaintext).toContain("retries: 3");
  expect(plaintext).toContain("- alpha");
  expect(plaintext).not.toContain("ENC[");
  expect(plaintext).not.toContain("sops:");
});

test("extract selects one value (sops --extract syntax) and returns it bare", async () => {
  const { unwrapDataKey } = fakeKms(JSON_DATA_KEY);
  const value = await Effect.runPromise(
    runSopsKms({ unwrapDataKey })({
      content: await fixture("kms.enc.json"),
      binary: "sops",
      inputType: "json",
      extract: '["nested"]["deep"]["value"]',
    }),
  );
  expect(value).toBe("leaf");
});

test("a wrong data key fails as SopsDecryptError, not a defect", async () => {
  const { unwrapDataKey } = fakeKms(YAML_DATA_KEY); // yaml fixture's key against the json fixture
  const exit = await Effect.runPromiseExit(
    runSopsKms({ unwrapDataKey })({
      content: await fixture("kms.enc.json"),
      binary: "sops",
      inputType: "json",
    }),
  );
  expect(Exit.isFailure(exit)).toBe(true);
  if (Exit.isFailure(exit)) expect(String(exit.cause)).toContain("SopsDecryptError");
});

test("keyArn filters entries; a file not encrypted to that key is a clear error", async () => {
  const { unwrapDataKey, seen } = fakeKms(JSON_DATA_KEY);
  const exit = await Effect.runPromiseExit(
    runSopsKms({ unwrapDataKey, keyArn: "arn:aws:kms:us-east-1:000000000000:key/other" })({
      content: await fixture("kms.enc.json"),
      binary: "sops",
      inputType: "json",
    }),
  );
  expect(Exit.isFailure(exit)).toBe(true);
  if (Exit.isFailure(exit)) expect(String(exit.cause)).toContain("not encrypted to that key");
  expect(seen).toHaveLength(0);
});

test("unwrap failures are aggregated and surfaced", async () => {
  const exit = await Effect.runPromiseExit(
    runSopsKms({ unwrapDataKey: () => Effect.fail(new Error("AccessDeniedException")) })({
      content: await fixture("kms.enc.json"),
      binary: "sops",
      inputType: "json",
    }),
  );
  expect(Exit.isFailure(exit)).toBe(true);
  if (Exit.isFailure(exit)) {
    const text = String(exit.cause);
    expect(text).toContain("Could not unwrap the SOPS data key");
    expect(text).toContain("AccessDeniedException");
  }
});

test("an age-only document has no KMS entries", async () => {
  const exit = await Effect.runPromiseExit(
    runSopsKmsEdge({ unwrapDataKey: () => Effect.succeed(fromBase64(JSON_DATA_KEY)) })({
      content: await fixture("native.enc.json"),
      binary: "sops",
      inputType: "json",
    }),
  );
  expect(Exit.isFailure(exit)).toBe(true);
  if (Exit.isFailure(exit)) expect(String(exit.cause)).toContain("not encrypted to any KMS key");
});
