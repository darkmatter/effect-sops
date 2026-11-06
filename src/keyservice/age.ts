import { readFile } from "node:fs/promises";
import { join } from "node:path";
import {
  armor,
  Decrypter,
  Encrypter,
  identityToRecipient,
  Stanza,
} from "age-encryption";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  pluginNameFromIdentity,
  pluginNameFromRecipient,
  unwrapFileKey,
  wrapFileKey,
} from "./age-plugin.js";
import {
  AgePluginError,
  type AgeKeyServiceOptions,
  type KeyHandler,
  KeyServiceError,
  KeyServiceInteractionError,
  type KeyServiceKey,
  type KeyServiceOperation,
  sanitizeForDisplay,
} from "./model.js";
import { describeKey } from "./protocol.js";

/** Identities in source order, with native recipients available for preflight. */
export interface AgeIdentities {
  readonly native: ReadonlyArray<Redacted.Redacted<string>>;
  readonly plugins: ReadonlyMap<
    string,
    ReadonlyArray<Redacted.Redacted<string>>
  >;
  readonly nativeRecipients: ReadonlySet<string>;
}

const keyCommand = Effect.fn("Age.keyCommand")(function* (
  command: string,
  env: Readonly<Record<string, string | undefined>>,
  recipient: string | undefined,
) {
  const child = yield* ChildProcess.make(command, [], {
    shell: true,
    env: { ...env, SOPS_AGE_RECIPIENT: recipient ?? "" },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "ignore",
    forceKillAfter: "1 second",
  });
  const output = yield* child.stdout.pipe(Stream.decodeText(), Stream.mkString);
  const code = yield* child.exitCode;
  if (code !== 0)
    return yield* Effect.fail(new Error("Identity command failed"));
  return output;
}, Effect.scoped);

const discovers = (options: AgeKeyServiceOptions): boolean =>
  options.discover ??
  (options.identities === undefined && options.identityFiles === undefined);

/**
 * Whether identities can come from `SOPS_AGE_KEY_CMD`. Such a command may
 * prompt (e.g. a password manager), so it only runs after approval.
 */
const usesKeyCommand = (options: AgeKeyServiceOptions): boolean =>
  discovers(options) && Boolean((options.env ?? process.env).SOPS_AGE_KEY_CMD);

/** Load identities on demand using SOPS discovery; commands receive SOPS_AGE_RECIPIENT. */
export const loadAgeIdentities = (
  options: AgeKeyServiceOptions,
  recipient?: string,
): Effect.Effect<AgeIdentities, KeyServiceError, ChildProcessSpawner> =>
  collectIdentities(options, recipient, true).pipe(
    Effect.flatMap(({ identities, sources }) =>
      identities.native.length === 0 && identities.plugins.size === 0
        ? Effect.fail(
            new KeyServiceError({
              reason: "NoMatchingIdentity",
              message: `No age identities found; sources tried: ${sources.map((source) => sanitizeForDisplay(source)).join(", ") || "none (discovery disabled)"}`,
            }),
          )
        : Effect.succeed(identities),
    ),
  );

const collectIdentities = Effect.fn("Age.collectIdentities")(
  function* (
    options: AgeKeyServiceOptions,
    recipient: string | undefined,
    runKeyCommand: boolean,
  ) {
    const env = { ...(options.env ?? process.env) };
    const native: Redacted.Redacted<string>[] = [];
    const plugins = new Map<string, Redacted.Redacted<string>[]>();
    const nativeRecipients = new Set<string>();
    const sources: string[] = [];
    const add = Effect.fn("Age.addIdentity")(function* (text: string) {
      const line = text.trim();
      if (!line || line.startsWith("#")) return;
      if (line.startsWith("AGE-PLUGIN-")) {
        const name = yield* pluginNameFromIdentity(line).pipe(
          Effect.orElseSucceed(() => undefined),
        );
        if (name) {
          const group = plugins.get(name) ?? [];
          group.push(Redacted.make(line));
          plugins.set(name, group);
          return;
        }
      } else if (/^AGE-SECRET-KEY-(?:PQ-)?1/.test(line)) {
        const address = yield* Effect.tryPromise({
          try: () => identityToRecipient(line),
          catch: () => undefined,
        }).pipe(Effect.orElseSucceed(() => undefined));
        if (address) {
          native.push(Redacted.make(line));
          nativeRecipients.add(address.toLowerCase());
          return;
        }
      } else if (
        /^(?:ssh-|-----BEGIN (?:OPENSSH|RSA|EC) PRIVATE KEY-----)/.test(line)
      ) {
        yield* Effect.logDebug("Skipping unsupported SSH age identity");
        return;
      }
      yield* Effect.logWarning("Skipping unrecognized or invalid age identity");
    });
    const addLines = Effect.fn("Age.addIdentityLines")(function* (
      text: string,
    ) {
      for (const line of text.split(/\r?\n/)) yield* add(line);
    });
    const file = Effect.fn("Age.readIdentityFile")(function* (
      path: string,
      optional = false,
    ) {
      sources.push(path);
      const content = yield* Effect.tryPromise({
        try: (signal) => readFile(path, { encoding: "utf8", signal }),
        catch: (error) =>
          optional &&
          error instanceof Error &&
          "code" in error &&
          error.code === "ENOENT",
      }).pipe(
        Effect.matchEffect({
          onSuccess: Effect.succeed,
          onFailure: (missing) =>
            missing
              ? Effect.succeed("")
              : Effect.logWarning(
                  `Could not load age identities from ${sanitizeForDisplay(path)}`,
                ).pipe(Effect.as("")),
        }),
      );
      yield* addLines(content);
    });
    if (options.identities !== undefined) {
      sources.push("explicit identities");
      for (const identity of options.identities) {
        yield* add(
          typeof identity === "string" ? identity : Redacted.value(identity),
        );
      }
    }
    for (const path of options.identityFiles ?? []) yield* file(path);
    if (discovers(options)) {
      sources.push("SOPS_AGE_KEY");
      // Preserve comment semantics before splitting this source's whitespace-separated words.
      for (const line of (env.SOPS_AGE_KEY ?? "").split(/\r?\n/)) {
        if (!line.trim().startsWith("#"))
          for (const word of line.split(/\s+/)) yield* add(word);
      }
      sources.push("SOPS_AGE_KEY_FILE");
      if (env.SOPS_AGE_KEY_FILE) yield* file(env.SOPS_AGE_KEY_FILE);
      sources.push("SOPS_AGE_KEY_CMD");
      if (env.SOPS_AGE_KEY_CMD && runKeyCommand) {
        const output = yield* keyCommand(
          env.SOPS_AGE_KEY_CMD,
          env,
          recipient,
        ).pipe(
          Effect.matchEffect({
            onSuccess: Effect.succeed,
            onFailure: () =>
              Effect.logWarning(
                "Could not load age identities from SOPS_AGE_KEY_CMD",
              ).pipe(Effect.as("")),
          }),
        );
        yield* addLines(output);
      }
      // Like sops (Go's os.UserConfigDir), the default file comes from the
      // given environment's XDG_CONFIG_HOME or HOME. Never fall back to the
      // process home: an explicit `env` must not reach the real keys.txt.
      const home = env.HOME;
      const config =
        env.XDG_CONFIG_HOME ||
        (home &&
          join(
            home,
            process.platform === "darwin"
              ? "Library/Application Support"
              : ".config",
          ));
      if (config) yield* file(join(config, "sops", "age", "keys.txt"), true);
    }
    const identities: AgeIdentities = { native, plugins, nativeRecipients };
    return { identities, sources };
  },
);

const ageError = (error: unknown): KeyServiceError => {
  if (error instanceof KeyServiceError) return error;
  if (error instanceof AgePluginError) {
    const interaction =
      error.reason === "Interaction" &&
      error.cause instanceof KeyServiceInteractionError
        ? error.cause
        : undefined;
    if (
      interaction?.reason === "Cancelled" ||
      interaction?.reason === "TimedOut"
    ) {
      return new KeyServiceError({
        reason: "Denied",
        message: "Age plugin interaction was cancelled or timed out",
      });
    }
    if (interaction?.reason === "Unavailable") {
      return new KeyServiceError({
        reason: "InteractionUnavailable",
        message: "Age plugin interaction is unavailable",
      });
    }
    return new KeyServiceError({
      reason: "PluginFailed",
      message:
        error.reason === "NotFound"
          ? `age-plugin-${sanitizeForDisplay(error.plugin)} is not installed`
          : sanitizeForDisplay(error.message),
    });
  }
  return new KeyServiceError({
    reason:
      error instanceof Error &&
      error.message === "no identity matched any of the file's recipients"
        ? "NoMatchingIdentity"
        : "InvalidRequest",
    message:
      error instanceof Error &&
      error.message === "no identity matched any of the file's recipients"
        ? "No age identity matched any of the file's recipients"
        : "Invalid age ciphertext or recipient",
  });
};

const recipientInfo = Effect.fn("Age.recipientInfo")(function* (
  operation: KeyServiceOperation,
  key: KeyServiceKey,
) {
  if (key.type !== "age")
    return yield* Effect.fail(
      new KeyServiceError({
        reason: "UnsupportedKey",
        message: `${describeKey(key)} is not supported by this keyservice (age only)`,
      }),
    );
  const recipient = key.recipient.toLowerCase();
  if (
    /^ssh-(?:ed25519|rsa) [A-Za-z0-9+/]+={0,2}(?: [^\r\n]*)?$/.test(
      key.recipient,
    )
  ) {
    return yield* Effect.fail(
      new KeyServiceError({
        reason:
          operation === "encrypt" ? "UnsupportedKey" : "NoMatchingIdentity",
        message:
          operation === "encrypt"
            ? "SSH age recipients are not supported by this keyservice"
            : `no age identity on this keyservice matches recipient ${sanitizeForDisplay(key.recipient)}`,
      }),
    );
  }
  const separator = recipient.lastIndexOf("1");
  if (
    !recipient.startsWith("age1") ||
    separator < 3 ||
    (key.recipient !== recipient &&
      key.recipient !== key.recipient.toUpperCase()) ||
    !/^[qpzry9x8gf2tvdw0s3jn54khce6mua7l]+$/.test(
      recipient.slice(separator + 1),
    )
  ) {
    return yield* Effect.fail(
      new KeyServiceError({
        reason: "InvalidRequest",
        message: "Invalid age recipient",
      }),
    );
  }
  const plugin = yield* pluginNameFromRecipient(recipient).pipe(
    Effect.mapError(
      () =>
        new KeyServiceError({
          reason: "InvalidRequest",
          message: "Invalid age recipient",
        }),
    ),
  );
  return { recipient, plugin };
});

/** The built-in age handler; identity sources are reloaded for every request. */
export const ageKeyHandler: (
  options?: AgeKeyServiceOptions,
) => Effect.Effect<KeyHandler, never, ChildProcessSpawner> = Effect.fn(
  "Age.keyHandler",
)(function* (input = {}) {
  const options: AgeKeyServiceOptions = {
    ...input,
    env: { ...(input.env ?? process.env) },
  };
  const context = yield* Effect.context<ChildProcessSpawner>();
  const run = Effect.runPromiseWith(context);
  const identitiesFor = (recipient: string, runKeyCommand: boolean) =>
    collectIdentities(options, recipient, runKeyCommand).pipe(
      Effect.map(({ identities }) => identities),
      Effect.provide(context),
    );
  const matches = (
    identities: AgeIdentities,
    info: { readonly recipient: string; readonly plugin: string | undefined },
  ) =>
    identities.nativeRecipients.has(info.recipient) ||
    (info.plugin !== undefined && identities.plugins.has(info.plugin));
  const noMatch = (recipient: string) =>
    new KeyServiceError({
      reason: "NoMatchingIdentity",
      message: `no age identity on this keyservice matches recipient ${sanitizeForDisplay(recipient)}`,
    });
  // Runs before approval, so it must stay free of side effects: it never runs
  // SOPS_AGE_KEY_CMD and never spawns a plugin.
  const check = Effect.fn("Age.check")(function* (
    operation: KeyServiceOperation,
    key: KeyServiceKey,
  ) {
    const info = yield* recipientInfo(operation, key);
    if (operation === "encrypt") {
      if (info.plugin === undefined) return info;
      const allowed =
        options.encryptPlugins ??
        [...(yield* identitiesFor(info.recipient, false)).plugins.keys()];
      if (!allowed.includes(info.plugin))
        return yield* Effect.fail(
          new KeyServiceError({
            reason: "UnsupportedKey",
            message: `Age plugin ${sanitizeForDisplay(info.plugin)} is not allowed for encryption`,
          }),
        );
      return info;
    }
    // A key command could still supply the identity; it runs after approval.
    if (usesKeyCommand(options)) return info;
    if (!matches(yield* identitiesFor(info.recipient, false), info))
      return yield* Effect.fail(noMatch(info.recipient));
    return info;
  });
  return {
    preflight: (operation, key) => check(operation, key).pipe(Effect.asVoid),
    decrypt: Effect.fn("Age.decrypt")(function* ({
      request,
      ciphertext,
      interaction,
    }) {
      const info = yield* check("decrypt", request.key);
      const identities = yield* identitiesFor(info.recipient, true);
      if (!matches(identities, info))
        return yield* Effect.fail(noMatch(info.recipient));
      const plugin = info.plugin;
      return yield* Effect.tryPromise({
        try: async (signal) => {
          const decrypter = new Decrypter();
          for (const identity of identities.native)
            decrypter.addIdentity(Redacted.value(identity));
          const groups = [...identities.plugins];
          groups.sort(
            ([left], [right]) =>
              Number(right === plugin) - Number(left === plugin),
          );
          for (const [name, group] of groups)
            decrypter.addIdentity({
              unwrapFileKey: async (stanzas) =>
                (await run(
                  unwrapFileKey(
                    name,
                    group.map(Redacted.value),
                    stanzas.map((stanza) => ({
                      type: stanza.args[0] ?? "",
                      args: stanza.args.slice(1),
                      body: stanza.body,
                    })),
                    { interaction, request, binary: options.pluginBinary },
                  ),
                  { signal },
                )) ?? null,
            });
          const binaryHeader = "age-encryption.org/v1\n";
          const binary =
            new TextDecoder().decode(
              ciphertext.subarray(0, binaryHeader.length),
            ) === binaryHeader
              ? ciphertext
              : armor.decode(
                  new TextDecoder("utf-8", { fatal: true }).decode(ciphertext),
                );
          const plaintext = await decrypter.decrypt(binary);
          // Crypto itself is not cancellable; erase a late result after its caller has gone.
          if (signal.aborted) {
            plaintext.fill(0);
            signal.throwIfAborted();
          }
          return plaintext;
        },
        catch: ageError,
      });
    }),
    encrypt: Effect.fn("Age.encrypt")(function* ({
      request,
      plaintext,
      interaction,
    }) {
      const { recipient, plugin } = yield* check("encrypt", request.key);
      return yield* Effect.tryPromise({
        try: async (signal) => {
          const encrypter = new Encrypter();
          if (plugin)
            encrypter.addRecipient({
              wrapFileKey: async (fileKey) =>
                (
                  await run(
                    wrapFileKey(plugin, recipient, fileKey, {
                      interaction,
                      request,
                      binary: options.pluginBinary,
                    }),
                    { signal },
                  )
                ).map(
                  (stanza) =>
                    new Stanza([stanza.type, ...stanza.args], stanza.body),
                ),
            });
          else encrypter.addRecipient(recipient);
          return new TextEncoder().encode(
            armor.encode(await encrypter.encrypt(plaintext)),
          );
        },
        catch: ageError,
      });
    }),
  } satisfies KeyHandler;
});
