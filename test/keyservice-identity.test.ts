import { describe, expect, test } from "bun:test";
import { generateX25519Identity } from "age-encryption";
import * as Effect from "effect/Effect";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AgeIdentityConfigError,
  resolveAgeIdentities,
  type AgeIdentityOptions,
} from "../src/keyservice-identity.ts";

const failure = (
  options: AgeIdentityOptions,
): Promise<AgeIdentityConfigError> =>
  Effect.runPromise(Effect.flip(resolveAgeIdentities(options)));

describe("identity configuration", () => {
  test("follows SOPS_AGE_KEY, then file, then discovery without fallback", async () => {
    const inline = await generateX25519Identity();
    const fromFile = await generateX25519Identity();
    const discovered = await generateX25519Identity();
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-identity-"));
    try {
      const keyFile = join(dir, "keys.txt");
      await writeFile(keyFile, `# comment\n${fromFile}\n`);
      const configHome = join(dir, "config");
      await mkdir(join(configHome, "sops/age"), { recursive: true });
      await writeFile(join(configHome, "sops/age/keys.txt"), `${discovered}\n`);

      expect(
        await Effect.runPromise(
          resolveAgeIdentities({
            env: { SOPS_AGE_KEY: inline, SOPS_AGE_KEY_FILE: keyFile },
            homeDir: dir,
            configHome,
          }),
        ),
      ).toEqual([inline]);
      expect(
        await Effect.runPromise(
          resolveAgeIdentities({
            env: { SOPS_AGE_KEY_FILE: keyFile },
            homeDir: dir,
            configHome,
          }),
        ),
      ).toEqual([fromFile]);
      expect(
        await Effect.runPromise(
          resolveAgeIdentities({ env: {}, homeDir: dir, configHome }),
        ),
      ).toEqual([discovered]);

      const invalid = await failure({
        env: { SOPS_AGE_KEY: "not-a-key", SOPS_AGE_KEY_FILE: keyFile },
        homeDir: dir,
        configHome,
      });
      expect(invalid).toBeInstanceOf(AgeIdentityConfigError);
      expect(invalid.reason).toBe("invalid");
      expect(invalid.message).not.toContain("not-a-key");
      expect(invalid.message).not.toContain(fromFile);
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("discovers the SOPS key file using each platform's config directory", async () => {
    const identity = await generateX25519Identity();
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-platform-"));
    try {
      const xdg = join(dir, "xdg");
      const appData = join(dir, "roaming");
      const cases = [
        { platform: "linux", env: {}, config: join(dir, ".config") },
        { platform: "linux", env: { XDG_CONFIG_HOME: xdg }, config: xdg },
        { platform: "darwin", env: {}, config: join(dir, "Library/Application Support") },
        { platform: "darwin", env: { XDG_CONFIG_HOME: xdg }, config: xdg },
        { platform: "win32", env: { APPDATA: appData, XDG_CONFIG_HOME: xdg }, config: appData },
      ] as const;
      for (const entry of cases) {
        await mkdir(join(entry.config, "sops/age"), { recursive: true });
        await writeFile(join(entry.config, "sops/age/keys.txt"), identity, { mode: 0o600 });
        const resolved = await Effect.runPromise(resolveAgeIdentities({
          platform: entry.platform, env: entry.env, homeDir: dir,
        }));
        expect(resolved.length === 1 && resolved[0] === identity).toBe(true);
      }
      const missingAppData = await failure({ platform: "win32", env: {}, homeDir: dir });
      expect(missingAppData.reason).toBe("missing");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("empty explicit identity sources cannot fall back to a default key", async () => {
    const identity = await generateX25519Identity();
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-empty-source-"));
    try {
      await mkdir(join(dir, "sops/age"), { recursive: true });
      await writeFile(join(dir, "sops/age/keys.txt"), identity, { mode: 0o600 });
      for (const env of [{ SOPS_AGE_KEY: "" }, { SOPS_AGE_KEY_FILE: "" }]) {
        const result = await failure({ env, homeDir: dir, configHome: dir });
        expect(result.reason).toBe("invalid");
      }
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });

  test("fails when the configured file is absent or no source exists", async () => {
    const dir = await mkdtemp(join(tmpdir(), "effect-sops-identity-"));
    try {
      const absent = await failure({
        env: { SOPS_AGE_KEY_FILE: join(dir, "absent.txt") },
        homeDir: dir,
        configHome: join(dir, "config"),
      });
      expect(absent.reason).toBe("missing");

      const empty = await failure({
        env: {},
        homeDir: dir,
        configHome: join(dir, "config"),
      });
      expect(empty.reason).toBe("missing");
      expect(empty.message).toContain("SOPS_AGE_KEY");
    } finally {
      await rm(dir, { recursive: true, force: true });
    }
  });
});
