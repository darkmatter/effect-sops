import { expect, test } from "bun:test";
import { decryptSops } from "@drkmttr/sops-age";
import {
  armor,
  Encrypter,
  generateHybridIdentity,
  generateX25519Identity,
  identityToRecipient,
} from "age-encryption";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Redacted from "effect/Redacted";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ageKeyHandler, loadAgeIdentities } from "../src/keyservice/age.ts";
import {
  KeyServiceInteractionError,
  type KeyServiceKey,
  type KeyServiceErrorReason,
} from "../src/keyservice/model.ts";
import {
  binary,
  identity as pluginIdentity,
  recipient as pluginRecipient,
  request,
  run,
  scripted,
} from "./fixtures/age-plugin/test-context.ts";
import document from "./fixtures/native.enc.json" with { type: "json" };

// This public identity belongs only to the checked-in native SOPS fixture.
const identity =
  "AGE-SECRET-KEY-1VSZHK96PS9NYD8C3U8WJRQVCAK6TMFSJD42U5LKCKAFRPYW0U5ZSM0T9RH";
const recipient =
  "age1nl7pqyavfmpmye88eyll3tg3xvvms9j3uvqdjf7sl03dwdzyf5hspee6sm";
const nativeKey: KeyServiceKey = { type: "age", recipient };
const pluginKey: KeyServiceKey = { type: "age", recipient: pluginRecipient };
const nativeRequest = { ...request, key: nativeKey };
const plaintext = new TextEncoder().encode("Unit B round-trip data key");
const ciphertext = new TextEncoder().encode(document.sops.age[0]!.enc);

const temporary = async <A>(body: (directory: string) => Promise<A>) => {
  const directory = await mkdtemp(join(tmpdir(), "keyservice-age-"));
  try {
    return await body(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
};
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`;
const plugin = async (directory: string, mode: string, pidFile?: string) => {
  const path = join(directory, `plugin-${mode}`);
  await writeFile(
    path,
    `#!/bin/sh\nexport FAKE_PLUGIN_MODE=${quote(mode)}\n${pidFile ? `echo "$$" > ${quote(pidFile)}\n` : ""}exec ${quote(binary)} "$@"\n`,
  );
  await chmod(path, 0o700);
  return () => path;
};

test("fixture data key decrypts the SOPS document through the public handler", async () => {
  const handler = await run(
    ageKeyHandler({ identities: [Redacted.make(identity)], env: {} }),
  );
  const dataKey = await run(
    handler.decrypt({
      request: nativeRequest,
      ciphertext,
      interaction: scripted().interaction,
    }),
  );
  expect(dataKey.length).toBe(32);
  const decrypted: unknown = await decryptSops(document, { dataKey });
  expect(decrypted).toMatchObject({ api: { token: "native-token" } });
});

test("loads each discovery source in order, retains plugin groups and skips comments and junk", () =>
  temporary(async (directory) => {
    const explicitFile = join(directory, "explicit.txt");
    const envFile = join(directory, "environment.txt");
    const commandFile = join(directory, "command.txt");
    const defaultFile = join(directory, "sops", "age", "keys.txt");
    await mkdir(join(directory, "sops", "age"), { recursive: true });
    await writeFile(
      explicitFile,
      "# comment\n  AGE-PLUGIN-FAKE-1pppp  \n\njunk\nssh-ed25519 AAAA\n",
    );
    await writeFile(envFile, "AGE-PLUGIN-OTHER-1qqqq\n");
    await writeFile(commandFile, "AGE-PLUGIN-FAKE-1rrrr\n");
    await writeFile(defaultFile, "AGE-PLUGIN-FAKE-1tttt\n");
    const loaded = await run(
      loadAgeIdentities(
        {
          identities: [identity, pluginIdentity],
          identityFiles: [explicitFile],
          discover: true,
          env: {
            HOME: directory,
            XDG_CONFIG_HOME: directory,
            SOPS_AGE_KEY: "AGE-PLUGIN-FAKE-1ssss\tAGE-PLUGIN-OTHER-1pppp",
            SOPS_AGE_KEY_FILE: envFile,
            SOPS_AGE_KEY_CMD: `[ "$SOPS_AGE_RECIPIENT" = ${quote(recipient)} ] && cat ${quote(commandFile)}`,
          },
        },
        recipient,
      ),
    );
    expect(loaded.native.length).toBe(1);
    expect([...loaded.nativeRecipients.keys()]).toEqual([recipient]);
    expect([...loaded.plugins.keys()]).toEqual(["fake", "other"]);
    expect(loaded.plugins.get("fake")?.length).toBe(5);
    expect(loaded.plugins.get("other")?.length).toBe(2);
  }));

test("loads native whitespace-separated environment identities and hybrid native recipients", () =>
  temporary(async (directory) => {
    const hybrid = await generateHybridIdentity();
    const loaded = await run(
      loadAgeIdentities({
        env: {
          HOME: directory,
          XDG_CONFIG_HOME: directory,
          SOPS_AGE_KEY: `\n${identity}\t${hybrid}\n`,
        },
      }),
    );
    expect(loaded.native.length).toBe(2);
    expect([...loaded.nativeRecipients.keys()]).toEqual([
      recipient,
      await identityToRecipient(hybrid),
    ]);
  }));

test("uses the platform default config directory when XDG_CONFIG_HOME is absent", () =>
  temporary(async (directory) => {
    const base =
      process.platform === "darwin"
        ? join(directory, "Library", "Application Support")
        : join(directory, ".config");
    await mkdir(join(base, "sops", "age"), { recursive: true });
    await writeFile(join(base, "sops", "age", "keys.txt"), identity);
    expect(
      (await run(loadAgeIdentities({ env: { HOME: directory } }))).native
        .length,
    ).toBe(1);
  }));

test("an explicit env without HOME never reads the process home's keys.txt", async () => {
  // The test preload points the process HOME at an empty temp dir; plant a
  // different identity there and prove discovery ignores it.
  const processHome = process.env.HOME;
  if (!processHome) throw new Error("test preload must set HOME");
  const configs = [
    join(processHome, "Library", "Application Support"),
    join(processHome, ".config"),
  ];
  for (const config of configs) {
    await mkdir(join(config, "sops", "age"), { recursive: true });
    await writeFile(
      join(config, "sops", "age", "keys.txt"),
      await generateX25519Identity(),
    );
  }
  try {
    const loaded = await run(
      loadAgeIdentities({ env: { SOPS_AGE_KEY: identity } }),
    );
    // Compare recipients, never identities, so a failure cannot print keys.
    expect([...loaded.nativeRecipients.keys()]).toEqual([recipient]);
  } finally {
    for (const config of configs)
      await rm(join(config, "sops"), { recursive: true, force: true });
  }
});

test("preflight never runs the key command; decrypt reloads it once per request", () =>
  temporary(async (directory) => {
    const runs = join(directory, "command-runs");
    const handler = await run(
      ageKeyHandler({
        env: {
          SOPS_AGE_KEY_CMD: `echo run >> ${quote(runs)} && echo ${quote(identity)}`,
        },
      }),
    );
    const count = async () =>
      (await Bun.file(runs).exists())
        ? (await readFile(runs, "utf8")).split("\n").filter(Boolean).length
        : 0;
    await run(handler.preflight("decrypt", nativeKey));
    await run(
      handler.preflight("decrypt", {
        type: "age",
        recipient: await identityToRecipient(await generateX25519Identity()),
      }),
    );
    expect(await count()).toBe(0);
    // Reusing the same request object must not reuse command output.
    for (let calls = 1; calls <= 2; calls++) {
      const dataKey = await run(
        handler.decrypt({
          request: nativeRequest,
          ciphertext,
          interaction: scripted().interaction,
        }),
      );
      expect(dataKey.length).toBe(32);
      expect(await count()).toBe(calls);
    }
  }));

test("decrypt uses only the native identity named by the request", async () => {
  const otherIdentity = await generateX25519Identity();
  const otherRecipient = await identityToRecipient(otherIdentity);
  let pluginCalls = 0;
  const handler = await run(
    ageKeyHandler({
      identities: [otherIdentity, identity, pluginIdentity],
      env: {},
      pluginBinary: () => {
        pluginCalls++;
        return binary;
      },
    }),
  );
  const otherKey: KeyServiceKey = { type: "age", recipient: otherRecipient };
  await run(handler.preflight("decrypt", otherKey));
  const result = await run(
    handler
      .decrypt({
        request: { ...nativeRequest, key: otherKey },
        ciphertext,
        interaction: scripted().interaction,
      })
      .pipe(
        Effect.match({
          onSuccess: () => "decrypted",
          onFailure: (error) => error.reason,
        }),
      ),
  );
  expect(result).toBe("NoMatchingIdentity");
  const dataKey = await run(
    handler.decrypt({
      request: nativeRequest,
      ciphertext,
      interaction: scripted().interaction,
    }),
  );
  expect(dataKey.length).toBe(32);
  expect(pluginCalls).toBe(0);
});

test("plugin requests never fall back to loaded native identities or another group", () =>
  temporary(async (directory) => {
    const names: string[] = [];
    const fake = await plugin(directory, "plain");
    const handler = await run(
      ageKeyHandler({
        identities: [identity, pluginIdentity, "AGE-PLUGIN-OTHER-1qqqq"],
        env: {},
        pluginBinary: (name) => {
          names.push(name);
          return name === "fake" ? fake() : "/never-run-other-plugin";
        },
      }),
    );
    const result = await run(
      handler
        .decrypt({
          request,
          ciphertext,
          interaction: scripted().interaction,
        })
        .pipe(
          Effect.match({
            onSuccess: () => "decrypted",
            onFailure: (error) => error.reason,
          }),
        ),
    );
    expect(result).toBe("NoMatchingIdentity");
    expect(names).toEqual(["fake"]);
  }));

test("plugin errors do not try other plugin groups", () =>
  temporary(async (directory) => {
    const names: string[] = [];
    const fake = await plugin(directory, "crash");
    const handler = await run(
      ageKeyHandler({
        identities: [pluginIdentity, "AGE-PLUGIN-OTHER-1qqqq"],
        env: {},
        pluginBinary: (name) => {
          names.push(name);
          return name === "fake" ? fake() : "/never-run-other-plugin";
        },
      }),
    );
    const result = await run(
      handler
        .decrypt({
          request,
          ciphertext,
          interaction: scripted().interaction,
        })
        .pipe(
          Effect.match({
            onSuccess: () => "decrypted",
            onFailure: (error) => error.reason,
          }),
        ),
    );
    expect(result).toBe("PluginFailed");
    expect(names).toEqual(["fake"]);
  }));

test("plugin encrypt derives its allowlist without running the key command", () =>
  temporary(async (directory) => {
    const marker = join(directory, "command-ran");
    const env = {
      SOPS_AGE_KEY_CMD: `touch ${quote(marker)} && echo ${quote(pluginIdentity)}`,
    };
    const denied = await run(ageKeyHandler({ env }));
    expect(
      (await run(Effect.flip(denied.preflight("encrypt", pluginKey)))).reason,
    ).toBe("UnsupportedKey");
    const deniedEncrypt = await run(
      denied
        .encrypt({
          request: { ...request, operation: "encrypt" },
          plaintext,
          interaction: scripted().interaction,
        })
        .pipe(
          Effect.match({
            onSuccess: () => "encrypted",
            onFailure: (error) => error.reason,
          }),
        ),
    );
    expect(deniedEncrypt).toBe("UnsupportedKey");
    const allowed = await run(
      ageKeyHandler({
        identities: [pluginIdentity],
        discover: true,
        pluginBinary: await plugin(directory, "plain"),
        env,
      }),
    );
    await run(allowed.preflight("encrypt", pluginKey));
    const encrypted = await run(
      allowed.encrypt({
        request: { ...request, operation: "encrypt" },
        plaintext,
        interaction: scripted().interaction,
      }),
    );
    expect(encrypted.length).toBeGreaterThan(0);
    expect(await Bun.file(marker).exists()).toBe(false);
  }));

test.each([{ discover: false }, { identities: [] }, { identityFiles: [] }])(
  "disabled discovery refuses unknown recipients without running commands: %j",
  (options) =>
    temporary(async (directory) => {
      const marker = join(directory, "command-ran");
      const handler = await run(
        ageKeyHandler({
          ...options,
          env: {
            SOPS_AGE_KEY_CMD: `touch ${quote(marker)} && echo ${quote(identity)}`,
          },
        }),
      );
      expect(
        (await run(Effect.flip(handler.preflight("decrypt", nativeKey))))
          .reason,
      ).toBe("NoMatchingIdentity");
      const result = await run(
        handler
          .decrypt({
            request: nativeRequest,
            ciphertext,
            interaction: scripted().interaction,
          })
          .pipe(
            Effect.match({
              onSuccess: () => "decrypted",
              onFailure: (error) => error.reason,
            }),
          ),
      );
      expect(result).toBe("NoMatchingIdentity");
      expect(await Bun.file(marker).exists()).toBe(false);
    }),
);

test("native encrypt never loads identities", () =>
  temporary(async (directory) => {
    const marker = join(directory, "command-ran");
    const handler = await run(
      ageKeyHandler({ env: { SOPS_AGE_KEY_CMD: `touch ${quote(marker)}` } }),
    );
    const encrypted = await run(
      handler.encrypt({
        request: { ...request, operation: "encrypt", key: nativeKey },
        plaintext: plaintext.slice(),
        interaction: scripted().interaction,
      }),
    );
    expect(new TextDecoder().decode(encrypted)).toStartWith(
      "-----BEGIN AGE ENCRYPTED FILE-----",
    );
    expect(await Bun.file(marker).exists()).toBe(false);
  }));

test.each(["identities", "identityFiles"] as const)(
  "explicit %s disables discovery even when empty",
  (source) =>
    temporary(async (directory) => {
      const failure = await run(
        Effect.flip(
          loadAgeIdentities({
            [source]: [],
            env: {
              HOME: directory,
              XDG_CONFIG_HOME: directory,
              SOPS_AGE_KEY: identity,
            },
          }),
        ),
      );
      expect(failure.reason).toBe("NoMatchingIdentity");
    }),
);

test("failing sources do not discard usable identities", () =>
  temporary(async (directory) => {
    const loaded = await run(
      loadAgeIdentities({
        identities: [identity],
        identityFiles: [join(directory, "missing")],
        discover: true,
        env: {
          HOME: directory,
          XDG_CONFIG_HOME: directory,
          SOPS_AGE_KEY_CMD: "exit 17",
          SOPS_AGE_KEY_FILE: directory,
        },
      }),
    );
    expect(loaded.native.length).toBe(1);
  }));

test("empty discovery reports source names and paths without source contents", () =>
  temporary(async (directory) => {
    const missing = join(directory, "missing.txt");
    const failure = await run(
      Effect.flip(
        loadAgeIdentities({
          identityFiles: [missing],
          discover: true,
          env: {
            HOME: directory,
            XDG_CONFIG_HOME: directory,
            SOPS_AGE_KEY: "not-an-identity-private-text",
            SOPS_AGE_KEY_FILE: missing,
            SOPS_AGE_KEY_CMD: "printf 'private-command-output'; exit 9",
          },
        }),
      ),
    );
    expect(failure.reason).toBe("NoMatchingIdentity");
    for (const source of [
      "SOPS_AGE_KEY",
      "SOPS_AGE_KEY_FILE",
      "SOPS_AGE_KEY_CMD",
      missing,
      join(directory, "sops", "age", "keys.txt"),
    ])
      expect(failure.message).toContain(source);
    expect(JSON.stringify(failure)).not.toContain("private-command-output");
    expect(JSON.stringify(failure)).not.toContain(
      "not-an-identity-private-text",
    );
  }));

test("handler snapshots its environment and rereads identity files on every request", () =>
  temporary(async (directory) => {
    const path = join(directory, "keys.txt");
    await writeFile(path, identity);
    const env = {
      SOPS_AGE_KEY_FILE: path,
      HOME: directory,
      XDG_CONFIG_HOME: directory,
    };
    const handler = await run(ageKeyHandler({ env }));
    env.SOPS_AGE_KEY_FILE = join(directory, "wrong.txt");
    await run(handler.preflight("decrypt", nativeKey));
    await writeFile(path, pluginIdentity);
    expect(
      (await run(Effect.flip(handler.preflight("decrypt", nativeKey)))).reason,
    ).toBe("NoMatchingIdentity");
    await run(handler.preflight("decrypt", pluginKey));
    await writeFile(path, identity);
    expect(
      (
        await run(
          handler.decrypt({
            request: nativeRequest,
            ciphertext,
            interaction: scripted().interaction,
          }),
        )
      ).length,
    ).toBe(32);
  }));

test("preflight distinguishes supported keys, missing identities and malformed recipients", async () => {
  const handler = await run(
    ageKeyHandler({ identities: [identity, pluginIdentity], env: {} }),
  );
  await run(handler.preflight("decrypt", nativeKey));
  await run(
    handler.preflight("decrypt", {
      type: "age",
      recipient: recipient.toUpperCase(),
    }),
  );
  await run(handler.preflight("decrypt", pluginKey));
  await run(handler.preflight("encrypt", pluginKey));
  const cases: ReadonlyArray<
    readonly [KeyServiceKey, "encrypt" | "decrypt", KeyServiceErrorReason]
  > = [
    [
      {
        type: "kms",
        arn: "arn:aws:kms:test",
        role: "",
        context: {},
        awsProfile: "",
      },
      "decrypt",
      "UnsupportedKey",
    ],
    [{ type: "age", recipient: "age1qqqq" }, "decrypt", "NoMatchingIdentity"],
    [
      { type: "age", recipient: "ssh-ed25519 AAAA" },
      "encrypt",
      "UnsupportedKey",
    ],
    [{ type: "age", recipient: "ssh-rsa AAAA" }, "encrypt", "UnsupportedKey"],
    [
      { type: "age", recipient: "ssh-ed25519 AAAA" },
      "decrypt",
      "NoMatchingIdentity",
    ],
    [{ type: "age", recipient: "age1other1qqqq" }, "encrypt", "UnsupportedKey"],
    [
      { type: "age", recipient: "garbage\u001b[2J" },
      "decrypt",
      "InvalidRequest",
    ],
    [
      { type: "age", recipient: "age1fake1INVALID" },
      "decrypt",
      "InvalidRequest",
    ],
  ];
  for (const [key, operation, reason] of cases)
    expect(
      (await run(Effect.flip(handler.preflight(operation, key)))).reason,
    ).toBe(reason);
});

test("explicit plugin allowlist replaces the default from loaded identities", async () => {
  const denied = await run(
    ageKeyHandler({
      identities: [pluginIdentity],
      encryptPlugins: [],
      env: {},
    }),
  );
  expect(
    (await run(Effect.flip(denied.preflight("encrypt", pluginKey)))).reason,
  ).toBe("UnsupportedKey");
  const allowed = await run(
    ageKeyHandler({ identities: [], encryptPlugins: ["fake"], env: {} }),
  );
  await run(allowed.preflight("encrypt", pluginKey));
});

test.each(["age1qqqq", "age1pq1qqqq", "age1tag1qqqq", "age1tagpq1qqqq"])(
  "native recipient shape %s does not require encrypt identities",
  async (value) => {
    const handler = await run(ageKeyHandler({ identities: [], env: {} }));
    await run(handler.preflight("encrypt", { type: "age", recipient: value }));
  },
);

test("native encrypt returns armor and decrypt accepts both armored and binary files", async () => {
  const encryptor = await run(ageKeyHandler({ identities: [], env: {} }));
  const decryptor = await run(
    ageKeyHandler({ identities: [identity], env: {} }),
  );
  const interaction = scripted().interaction;
  const encrypted = await run(
    encryptor.encrypt({
      request: { ...nativeRequest, operation: "encrypt" },
      plaintext,
      interaction,
    }),
  );
  const armored = new TextDecoder().decode(encrypted);
  expect(armored.startsWith("-----BEGIN AGE ENCRYPTED FILE-----")).toBe(true);
  for (const value of [encrypted, armor.decode(armored)])
    expect(
      Buffer.from(
        await run(
          decryptor.decrypt({
            request: nativeRequest,
            ciphertext: value,
            interaction,
          }),
        ),
      ).equals(Buffer.from(plaintext)),
    ).toBe(true);
});

test("bad armor, invalid headers and invalid header HMAC are InvalidRequest", async () => {
  const handler = await run(ageKeyHandler({ identities: [identity], env: {} }));
  const bytes = armor.decode(document.sops.age[0]!.enc);
  const marker = new TextEncoder().encode("--- ");
  const offset = Buffer.from(bytes).indexOf(marker) + marker.length;
  expect(offset).toBeGreaterThan(marker.length);
  bytes[offset] = bytes[offset] === 65 ? 66 : 65;
  for (const value of [
    new TextEncoder().encode("not age"),
    new TextEncoder().encode(
      "-----BEGIN AGE ENCRYPTED FILE-----\nINVALID\n-----END AGE ENCRYPTED FILE-----",
    ),
    new TextEncoder().encode("age-encryption.org/v1\nbad header"),
    bytes,
  ]) {
    expect(
      (
        await run(
          Effect.flip(
            handler.decrypt({
              request: nativeRequest,
              ciphertext: value,
              interaction: scripted().interaction,
            }),
          ),
        )
      ).reason,
    ).toBe("InvalidRequest");
  }
});

test("valid age files with no matching identity return NoMatchingIdentity", async () => {
  const other = new Encrypter();
  other.addRecipient(await identityToRecipient(await generateHybridIdentity()));
  const handler = await run(ageKeyHandler({ identities: [identity], env: {} }));
  expect(
    (
      await run(
        Effect.flip(
          handler.decrypt({
            request: nativeRequest,
            ciphertext: await other.encrypt(plaintext),
            interaction: scripted().interaction,
          }),
        ),
      )
    ).reason,
  ).toBe("NoMatchingIdentity");
});

test("plugin encrypt and PIN decrypt round trip with secret request context", () =>
  temporary(async (directory) => {
    const handler = await run(
      ageKeyHandler({
        identities: [pluginIdentity],
        pluginBinary: await plugin(directory, "pin"),
        env: {},
      }),
    );
    const { interaction, calls } = scripted();
    const encrypted = await run(
      handler.encrypt({
        request: { ...request, operation: "encrypt" },
        plaintext,
        interaction,
      }),
    );
    expect(
      Buffer.from(
        await run(
          handler.decrypt({ request, ciphertext: encrypted, interaction }),
        ),
      ).equals(Buffer.from(plaintext)),
    ).toBe(true);
    expect(calls).toEqual([
      {
        kind: "value",
        context: { plugin: "fake", request },
        message: "Enter PIN for fake",
        secret: true,
      },
    ]);
  }));

test.each([
  ["Cancelled", "Denied"],
  ["TimedOut", "Denied"],
  ["Unavailable", "InteractionUnavailable"],
] as const)("plugin PIN %s maps to %s", (reason, mapped) =>
  temporary(async (directory) => {
    const handler = await run(
      ageKeyHandler({
        identities: [pluginIdentity],
        pluginBinary: await plugin(directory, "pin"),
        env: {},
      }),
    );
    const encrypted = await run(
      handler.encrypt({
        request: { ...request, operation: "encrypt" },
        plaintext,
        interaction: scripted().interaction,
      }),
    );
    const { interaction } = scripted({
      requestValue: () =>
        Effect.fail(
          new KeyServiceInteractionError({
            reason,
            message: "Fixture prompt unavailable",
          }),
        ),
    });
    expect(
      (
        await run(
          Effect.flip(
            handler.decrypt({ request, ciphertext: encrypted, interaction }),
          ),
        )
      ).reason,
    ).toBe(mapped);
  }),
);

test.each(["crash", "bad-index", "error-control"])(
  "plugin %s is PluginFailed with safe diagnostics",
  (mode) =>
    temporary(async (directory) => {
      const handler = await run(
        ageKeyHandler({
          identities: [pluginIdentity],
          pluginBinary: await plugin(directory, mode),
          env: {},
        }),
      );
      const failure = await run(
        Effect.flip(
          handler.encrypt({
            request: { ...request, operation: "encrypt" },
            plaintext,
            interaction: scripted().interaction,
          }),
        ),
      );
      expect(failure.reason).toBe("PluginFailed");
      expect(failure.message).not.toMatch(/[\u0000-\u001f\u202e]/);
    }),
);

test("missing plugin executable has an actionable PluginFailed error", async () => {
  const handler = await run(
    ageKeyHandler({
      identities: [pluginIdentity],
      pluginBinary: () => "/no-such-unit-b-age-plugin",
      env: {},
    }),
  );
  const failure = await run(
    Effect.flip(
      handler.encrypt({
        request: { ...request, operation: "encrypt" },
        plaintext,
        interaction: scripted().interaction,
      }),
    ),
  );
  expect(failure.reason).toBe("PluginFailed");
  expect(failure.message).toBe("age-plugin-fake is not installed");
});

test("a matching native identity prevents spawning plugins even when listed later", async () => {
  let resolved = false;
  const handler = await run(
    ageKeyHandler({
      identities: [pluginIdentity, identity],
      env: {},
      pluginBinary: () => {
        resolved = true;
        return "/never-run-plugin";
      },
    }),
  );
  expect(
    (
      await run(
        handler.decrypt({
          request: nativeRequest,
          ciphertext,
          interaction: scripted().interaction,
        }),
      )
    ).length,
  ).toBe(32);
  expect(resolved).toBe(false);
});

test("the request's plugin group is the only group used for successful decryption", () =>
  temporary(async (directory) => {
    const fake = await plugin(directory, "plain");
    const names: string[] = [];
    const handler = await run(
      ageKeyHandler({
        identities: ["AGE-PLUGIN-OTHER-1qqqq", pluginIdentity],
        env: {},
        pluginBinary: (name) => {
          names.push(name);
          return name === "fake" ? fake() : "/never-run-other-plugin";
        },
      }),
    );
    const interaction = scripted().interaction;
    const encrypted = await run(
      handler.encrypt({
        request: { ...request, operation: "encrypt" },
        plaintext,
        interaction,
      }),
    );
    names.length = 0;
    expect(
      Buffer.from(
        await run(
          handler.decrypt({ request, ciphertext: encrypted, interaction }),
        ),
      ).equals(Buffer.from(plaintext)),
    ).toBe(true);
    expect(names).toEqual(["fake"]);
  }));

test(
  "interrupting slow plugin decryption terminates the spawned process",
  () =>
    temporary(async (directory) => {
      const waiting = Promise.withResolvers<void>();
      const interaction = scripted({
        waiting: () => Effect.sync(() => waiting.resolve()),
      }).interaction;
      const encryptor = await run(
        ageKeyHandler({
          identities: [pluginIdentity],
          pluginBinary: await plugin(directory, "plain"),
          env: {},
        }),
      );
      const encrypted = await run(
        encryptor.encrypt({
          request: { ...request, operation: "encrypt" },
          plaintext,
          interaction,
        }),
      );
      const pidFile = join(directory, "pid");
      const handler = await run(
        ageKeyHandler({
          identities: [pluginIdentity],
          pluginBinary: await plugin(directory, "slow", pidFile),
          env: {},
        }),
      );
      const fiber = Effect.runFork(
        handler.decrypt({ request, ciphertext: encrypted, interaction }),
      );
      try {
        let pid = 0;
        for (let attempt = 0; attempt < 100 && pid === 0; attempt++) {
          const text = await readFile(pidFile, "utf8").catch(
            (cause: unknown) => {
              if (
                typeof cause === "object" &&
                cause !== null &&
                "code" in cause &&
                cause.code === "ENOENT"
              )
                return "";
              throw cause;
            },
          );
          pid = Number(text);
          if (!pid) await Bun.sleep(20);
        }
        expect(pid).toBeGreaterThan(0);
        let timeout: ReturnType<typeof setTimeout> | undefined;
        try {
          await Promise.race([
            waiting.promise,
            new Promise<never>((_resolve, reject) => {
              timeout = setTimeout(
                () =>
                  reject(new Error("Plugin did not enter its waiting state")),
                7_000,
              );
            }),
          ]);
        } finally {
          clearTimeout(timeout);
        }
        expect(() => process.kill(pid, 0)).not.toThrow();
        await Effect.runPromise(Fiber.interrupt(fiber));
        // Promise cancellation signals the plugin's own Effect runtime asynchronously.
        for (let attempt = 0; attempt < 100; attempt++) {
          try {
            process.kill(pid, 0);
          } catch (cause) {
            if (
              typeof cause === "object" &&
              cause !== null &&
              "code" in cause &&
              cause.code === "ESRCH"
            )
              break;
            throw cause;
          }
          await Bun.sleep(20);
        }
        expect(() => process.kill(pid, 0)).toThrow();
      } finally {
        await Effect.runPromise(Fiber.interrupt(fiber));
      }
    }),
  10_000,
);
