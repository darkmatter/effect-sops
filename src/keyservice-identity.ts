import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";

export interface AgeIdentityOptions {
  /**
   * Environment to read. Defaults to `process.env`. Passed explicitly so tests
   * never fall back to the caller's real default age identity files.
   */
  readonly env?: Readonly<Record<string, string | undefined>>;
  readonly homeDir?: string;
  readonly platform?: NodeJS.Platform;
  /** Overrides `XDG_CONFIG_HOME` from the supplied environment. */
  readonly configHome?: string;
}

export type AgeIdentityErrorReason = "missing" | "unreadable" | "invalid";

export class AgeIdentityConfigError extends Data.TaggedError(
  "AgeIdentityConfigError",
)<{
  readonly reason: AgeIdentityErrorReason;
  readonly message: string;
}> {}

// SOPS_AGE_KEY and key files contain one age secret key per entry. Comments
// and blank lines are ignored by the upstream age/sops loaders.
const ageSecretKey = /^AGE-SECRET-KEY-(?:PQ-)?1[0-9A-Z]+$/;

const parseIdentities = (text: string): readonly string[] | undefined => {
  const entries = text
    .split(/[\r\n,]+/)
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0 && !entry.startsWith("#"));
  if (entries.length === 0 || !entries.every((entry) => ageSecretKey.test(entry)))
    return undefined;
  return [...new Set(entries)];
};

const identitiesFrom = (
  text: string,
  source: string,
): Effect.Effect<readonly string[], AgeIdentityConfigError> => {
  const identities = parseIdentities(text);
  return identities
    ? Effect.succeed(identities)
    : Effect.fail(
        new AgeIdentityConfigError({
          reason: "invalid",
          message: `No usable age secret keys in ${source}`,
        }),
      );
};

const readIdentityFile = (
  path: string,
): Effect.Effect<string, AgeIdentityConfigError> =>
  Effect.try({
    try: () => readFileSync(path, "utf8"),
    catch: (cause) => {
      const missing =
        typeof cause === "object" &&
        cause !== null &&
        "code" in cause &&
        cause.code === "ENOENT";
      return new AgeIdentityConfigError({
        reason: missing ? "missing" : "unreadable",
        message: `Cannot read age key file ${path}`,
      });
    },
  });

/**
 * Resolve age identities in SOPS precedence order: `SOPS_AGE_KEY`, then
 * `SOPS_AGE_KEY_FILE`, then the default sops/age key file.
 *
 * An explicitly configured source is strict: an invalid or unreadable value
 * fails instead of silently loading a different identity.
 */
export const resolveAgeIdentities = (
  options: AgeIdentityOptions = {},
): Effect.Effect<readonly string[], AgeIdentityConfigError> =>
  Effect.gen(function* () {
    const env = options.env ?? process.env;
    if (env.SOPS_AGE_KEY !== undefined) {
      return yield* identitiesFrom(env.SOPS_AGE_KEY.trim(), "SOPS_AGE_KEY");
    }

    if (env.SOPS_AGE_KEY_FILE !== undefined) {
      const keyFile = env.SOPS_AGE_KEY_FILE.trim();
      if (!keyFile) {
        return yield* Effect.fail(
          new AgeIdentityConfigError({
            reason: "invalid",
            message: "SOPS_AGE_KEY_FILE must name an age identity file",
          }),
        );
      }
      const text = yield* readIdentityFile(keyFile);
      return yield* identitiesFrom(text, keyFile);
    }

    const home = options.homeDir ?? env.HOME ?? env.USERPROFILE ?? homedir();
    const platform = options.platform ?? process.platform;
    // Match SOPS getUserConfigDir: XDG overrides macOS, but not Windows.
    const configHome =
      options.configHome?.trim() ||
      (platform === "win32"
        ? env.APPDATA?.trim()
        : env.XDG_CONFIG_HOME?.trim() ||
          join(home, platform === "darwin" ? "Library/Application Support" : ".config"));
    if (configHome) {
      const candidate = join(configHome, "sops/age/keys.txt");
      const loaded = yield* Effect.result(readIdentityFile(candidate));
      if (loaded._tag === "Success") {
        return yield* identitiesFrom(loaded.success, candidate);
      }
      if (loaded.failure.reason !== "missing") {
        return yield* Effect.fail(loaded.failure);
      }
    }

    return yield* Effect.fail(
      new AgeIdentityConfigError({
        reason: "missing",
        message:
          "No age identities found; set SOPS_AGE_KEY or SOPS_AGE_KEY_FILE",
      }),
    );
  });
