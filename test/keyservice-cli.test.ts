import { describe, expect, test } from "bun:test";
import { generateX25519Identity } from "age-encryption";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseArgs } from "../src/keyservice-cli.ts";

const cliPath = join(import.meta.dir, "../src/keyservice-cli.ts");

const cliEnv = (overrides: Record<string, string> = {}) => ({
  PATH: process.env.PATH ?? "",
  HOME: join(tmpdir(), `effect-sops-cli-${crypto.randomUUID()}`),
  ...overrides,
});

const runCli = (
  args: readonly string[],
  env: Record<string, string> = {},
) =>
  Bun.spawnSync([process.execPath, cliPath, ...args], {
    env: cliEnv(env),
    stdin: "ignore",
    stdout: "pipe",
    stderr: "pipe",
  });

const readReadyUri = async (
  stderr: ReadableStream<Uint8Array>,
): Promise<string> => {
  const reader = stderr.getReader();
  const decoder = new TextDecoder();
  let output = "";
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    output += decoder.decode(chunk.value, { stream: true });
    const uri = output.match(/listening on (tcp:\/\/\S+|unix:\/\/\/\S+)/)?.[1];
    if (uri !== undefined) return uri;
  }
  throw new Error(`CLI did not become ready: ${output}`);
};

describe("keyservice CLI", () => {
  test("--help works without identities", () => {
    const help = runCli(["--help"]);
    expect(help.exitCode).toBe(0);
    const stdout = help.stdout.toString();
    expect(stdout).toContain("--network");
    expect(stdout).toContain("--address");
    expect(help.stderr.toString()).toBe("");
  });

  test("only actual loopback addresses suppress the plaintext transport warning", () => {
    for (const [address, warnNonLoopback] of [
      ["127.0.0.1:5000", false],
      ["127.12.34.56:5000", false],
      ["localhost:5000", false],
      ["[::1]:5000", false],
      ["127.example.com:5000", true],
      ["0.0.0.0:5000", true],
      ["[::]:5000", true],
    ] as const) {
      expect(parseArgs(["--address", address])).toMatchObject({
        kind: "run", options: { warnNonLoopback },
      });
    }
  });

  test("rejects private-key arguments without echoing their values", async () => {
    const identity = await generateX25519Identity();
    for (const args of [
      [`--private-key=${identity}`],
      ["--network", identity],
      ["--address", identity],
      [identity],
    ]) {
      const result = runCli(args);
      expect(result.exitCode).toBe(1);
      const output = result.stdout.toString() + result.stderr.toString();
      expect(output.includes(identity)).toBe(false);
    }
  });

  test("fails before listening when no identities are configured", () => {
    const missing = runCli(
      ["--network", "tcp", "--address", "127.0.0.1:0"],
      {
        XDG_CONFIG_HOME: join(
          tmpdir(),
          `effect-sops-missing-${crypto.randomUUID()}`,
        ),
      },
    );
    expect(missing.exitCode).toBe(1);
    expect(missing.stderr.toString()).not.toContain("listening on");
  });

  test("serves with SOPS_AGE_KEY and exits cleanly on SIGTERM", async () => {
    const identity = await generateX25519Identity();
    const child = Bun.spawn(
      [
        process.execPath,
        cliPath,
        "--network",
        "tcp",
        "--address",
        "127.0.0.1:0",
      ],
      {
        env: cliEnv({ SOPS_AGE_KEY: identity }),
        stdin: "ignore",
        stdout: "pipe",
        stderr: "pipe",
      },
    );
    try {
      const uri = await readReadyUri(child.stderr);
      expect(uri).toMatch(/^tcp:\/\/127\.0\.0\.1:\d+$/);
      expect(Number(new URL(uri).port)).toBeGreaterThan(0);
    } finally {
      child.kill("SIGTERM");
    }
    expect(await child.exited).toBe(0);
  });

  test("Unix CLI creates and removes only its own socket", async () => {
    const identity = await generateX25519Identity();
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-cli-socket-"));
    const socketPath = join(dir, "service.sock");
    try {
      const child = Bun.spawn(
        [
          process.execPath,
          cliPath,
          "--network",
          "unix",
          "--address",
          socketPath,
        ],
        {
          env: cliEnv({ SOPS_AGE_KEY: identity }),
          stdin: "ignore",
          stdout: "pipe",
          stderr: "pipe",
        },
      );
      try {
        expect(await readReadyUri(child.stderr)).toBe(
          `unix://${socketPath}`,
        );
        expect(existsSync(socketPath)).toBe(true);
      } finally {
        child.kill("SIGTERM");
      }
      expect(await child.exited).toBe(0);
      expect(existsSync(socketPath)).toBe(false);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
