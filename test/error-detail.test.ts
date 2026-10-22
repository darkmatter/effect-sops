import { expect, test } from "bun:test";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import { chmod, mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { errorDetail, withErrorDetail } from "../src/error-detail.ts";
import { SopsDecryptError, SopsParseError } from "../src/errors.ts";
import { runSopsCli } from "../src/index.ts";

const makeFakeSops = async (name: string, lines: readonly string[]): Promise<string> => {
  const dir = join(import.meta.dir, ".tmp", name);
  const binary = join(dir, "sops-fake");
  await mkdir(dir, { recursive: true });
  await writeFile(binary, ["#!/usr/bin/env bun", ...lines].join("\n"));
  await chmod(binary, 0o755);
  return binary;
};

const decryptFailure = async (
  request: Parameters<typeof runSopsCli>[0],
): Promise<SopsDecryptError> => {
  const exit = await Effect.runPromiseExit(runSopsCli(request));
  expect(Exit.isFailure(exit)).toBe(true);
  if (!Exit.isFailure(exit)) throw new Error("expected decrypt to fail");
  const error: unknown = Cause.squash(exit.cause);
  if (!(error instanceof SopsDecryptError)) throw new Error("expected SopsDecryptError");
  return error;
};

test("collapses whitespace and caps the detail at ~500 chars", () => {
  expect(errorDetail("line one\n\n  line\ttwo")).toBe("line one line two");

  const capped = errorDetail("x".repeat(600));
  expect(capped).toHaveLength(500);
  expect(capped.endsWith("...")).toBe(true);
});

test("a SopsDecryptError renders message plus stderr, without duplicating it", () => {
  const withStderr = new SopsDecryptError({
    message: "sops exited with code 128",
    path: "secrets.sops.json",
    exitCode: 128,
    stderr: "Failed to get the data key.\nTry again.",
  });
  expect(errorDetail(withStderr)).toBe(
    "sops exited with code 128: Failed to get the data key. Try again.",
  );

  const alreadyEnriched = new SopsDecryptError({
    message: "sops exited with code 128: Failed to get the data key.",
    path: "secrets.sops.json",
    stderr: "Failed to get the data key.",
  });
  expect(errorDetail(alreadyEnriched)).toBe(
    "sops exited with code 128: Failed to get the data key.",
  );
});

test("the fallback cause names both backends", () => {
  const detail = errorDetail({
    nativeError: new Error("no identity matched"),
    cliError: new SopsDecryptError({
      message: "sops exited with code 1",
      path: "secrets.sops.json",
      stderr: "boom",
    }),
  });
  expect(detail).toBe("sops-age: no identity matched; sops CLI: sops exited with code 1: boom");
});

test("parse errors stay content-free: their cause is never surfaced", () => {
  const parseError = new SopsParseError({
    message: "Failed to parse decrypted SOPS content as json",
    format: "json",
    cause: new Error('Unexpected token near "native-token"'),
  });
  const detail = errorDetail(parseError);
  expect(detail).toBe("Failed to parse decrypted SOPS content as json");
  expect(detail).not.toContain("native-token");
  expect(withErrorDetail("Failed to read config", parseError)).not.toContain("native-token");
});

test("age secret keys echoed by a backend are redacted", () => {
  const key = "AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQSY96KRD";
  const detail = errorDetail(new Error(`Invalid checksum in ${key}: expected "ltwj43"`));
  expect(detail).not.toContain(key);
  expect(detail).toContain("AGE-SECRET-KEY-<redacted>");
});

test("runSopsCli exit failures carry stderr in the message and keep the fields", async () => {
  const binary = await makeFakeSops("cli-exit-failure", [
    'process.stderr.write("Failed to get the data key.\\nsecond line\\n");',
    "process.exit(128);",
  ]);

  const error = await decryptFailure({
    path: join(import.meta.dir, "fixtures/native.enc.json"),
    binary,
    keyServices: [],
  });

  expect(error.message).toBe(
    "sops exited with code 128: Failed to get the data key. second line",
  );
  expect(error.exitCode).toBe(128);
  expect(error.stderr).toBe("Failed to get the data key.\nsecond line");
});

// Real clock on purpose: this exercises runSopsCli's own timeout timer
// killing a live child process, which fake timers cannot drive across the
// process boundary. The child's timer only keeps it alive until killed.
test("runSopsCli timeouts carry stderr in the message and keep the fields", async () => {
  const binary = await makeFakeSops("cli-timeout", [
    'process.stderr.write("still working\\n");',
    "setTimeout(() => {}, 5_000);",
  ]);

  const error = await decryptFailure({
    path: join(import.meta.dir, "fixtures/native.enc.json"),
    binary,
    keyServices: [],
    timeoutMs: 100,
  });

  expect(error.message).toBe("sops timed out after 100ms: still working");
  expect(error.stderr).toBe("still working");
});
