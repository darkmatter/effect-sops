import { expect, test } from "bun:test";
import { Decrypter, Encrypter, Stanza } from "age-encryption";
import * as BunServices from "@effect/platform-bun/BunServices";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Redacted from "effect/Redacted";
import {
  encodeStanza,
  parseStanzas,
  pluginNameFromIdentity,
  pluginNameFromRecipient,
  unwrapFileKey,
  wrapFileKey,
  type AgeStanza,
} from "../src/keyservice/age-plugin.ts";
import { KeyServiceInteractionError } from "../src/keyservice/model.ts";

import {
  binary,
  identity,
  recipient,
  key,
  wrapped,
  request,
  scripted,
  run,
  options,
  unwrap,
  withMode,
} from "./fixtures/age-plugin/test-context.ts";

test.each([0, 1, 47, 48, 49, 96, 100])(
  "wire codec round-trips %i bytes with age line framing",
  async (size) => {
    const stanza = {
      type: "test",
      args: ["first", "second"],
      body: Uint8Array.from({ length: size }, (_, index) => index),
    };
    const encoded = encodeStanza(stanza);
    const lines = encoded.split("\n");
    expect(lines.shift()).toBe("-> test first second");
    expect(lines.pop()).toBe("");
    const final = lines.pop();
    expect(final?.length).toBeLessThan(64);
    expect(lines.every((line) => line.length === 64)).toBe(true);
    if (size % 48 === 0) expect(final).toBe("");
    expect(encoded).not.toContain("=");
    expect(await run(parseStanzas(encoded))).toEqual([stanza]);
  },
);

test.each([
  `-> test\n${"A".repeat(65)}\n`,
  "-> test\nZg==\n",
  "-> test\n%%\n",
  "-> test\nZh\n",
  "-> test\nA\n",
  "-> test\n_w\n",
  "-> test  double\n\n",
  "-> test\tbad\n\n",
  "-> test\nAAAA",
  `-> test\n${"A".repeat(64)}\n`,
])("wire codec rejects malformed input %#", async (input) => {
  expect((await run(Effect.flip(parseStanzas(input)))).reason).toBe("Protocol");
});

test("wire parser reads multiple consecutive stanzas", async () => {
  const next = { type: "done", args: [], body: new Uint8Array() };
  expect(
    await run(parseStanzas(encodeStanza(wrapped) + encodeStanza(next))),
  ).toEqual([wrapped, next]);
});

test("derives safe plugin names and distinguishes every native recipient", async () => {
  expect(await run(pluginNameFromIdentity("AGE-PLUGIN-YUBIKEY-1qqqq"))).toBe(
    "yubikey",
  );
  expect(await run(pluginNameFromRecipient("age1yubikey1qqqq"))).toBe(
    "yubikey",
  );
  for (const name of [
    "age1qqqq",
    "age1pq1qqqq",
    "age1tag1qqqq",
    "age1tagpq1qqqq",
  ])
    expect(await run(pluginNameFromRecipient(name))).toBeUndefined();
  expect(await run(pluginNameFromRecipient("age1a_b.c+d-e1qqqq"))).toBe(
    "a_b.c+d-e",
  );
});

test("rejects unsafe identity and recipient names", async () => {
  for (const value of [
    "AGE-PLUGIN-FAKE-x",
    "AGE-PLUGIN-../../BIN-1qqqq",
    "AGE-PLUGIN-A..B-1qqqq",
    `AGE-PLUGIN-${"A".repeat(65)}-1qqqq`,
  ])
    expect((await run(Effect.flip(pluginNameFromIdentity(value)))).reason).toBe(
      "InvalidName",
    );
  for (const value of [
    "age1../x1qqqq",
    "age1a..b1qqqq",
    "age1-bad1qqqq",
    `age1${"a".repeat(65)}1qqqq`,
  ])
    expect(
      (await run(Effect.flip(pluginNameFromRecipient(value)))).reason,
    ).toBe("InvalidName");
});

test("validates explicit plugin names before resolving executables", async () => {
  let resolved = false;
  const bad = {
    ...options(),
    binary: () => {
      resolved = true;
      return binary;
    },
  };
  expect(
    (
      await run(
        Effect.flip(unwrapFileKey("../fake", [identity], [wrapped], bad)),
      )
    ).reason,
  ).toBe("InvalidName");
  expect(
    (await run(Effect.flip(wrapFileKey("a..b", recipient, key, bad)))).reason,
  ).toBe("InvalidName");
  expect(resolved).toBe(false);
});

test("custom typage recipient and identity round-trip a real age file", () =>
  withMode("plain", async () => {
    const encrypter = new Encrypter();
    encrypter.addRecipient({
      wrapFileKey: async (fileKey) =>
        (await run(wrapFileKey("fake", recipient, fileKey, options()))).map(
          (stanza) => new Stanza([stanza.type, ...stanza.args], stanza.body),
        ),
    });
    const decrypter = new Decrypter();
    decrypter.addIdentity({
      unwrapFileKey: async (stanzas) => {
        const converted = stanzas.map((stanza): AgeStanza => {
          const [type, ...args] = stanza.args;
          if (!type) throw new Error("Age stanza missing type");
          return { type, args, body: stanza.body };
        });
        return (
          (await run(
            unwrapFileKey("fake", [identity], converted, options()),
          )) ?? null
        );
      },
    });
    const plaintext = new TextEncoder().encode(
      "An actual age file through a fake hardware plugin.",
    );
    const encrypted = await encrypter.encrypt(plaintext);
    expect(
      new TextDecoder().decode(encrypted).startsWith("age-encryption.org/v1\n"),
    ).toBe(true);
    expect(await decrypter.decrypt(encrypted)).toEqual(plaintext);
  }));

test("plain unwrap returns a matching key and undefined for no matching stanza", () =>
  withMode("plain", async () => {
    expect(await run(unwrap())).toEqual(key);
    expect(
      await run(unwrapFileKey("fake", [identity], [], options())),
    ).toBeUndefined();
  }));

test("correct PIN is requested as a secret with its request context", () =>
  withMode("pin", async () => {
    const { interaction, calls } = scripted();
    expect(await run(unwrap(interaction))).toEqual(key);
    expect(calls).toEqual([
      {
        kind: "value",
        context: { plugin: "fake", request },
        message: "Enter PIN for fake",
        secret: true,
      },
    ]);
  }));

test.each(["pin", "cancel-done"])(
  "cancelled PIN remains Interaction in %s mode",
  (mode) =>
    withMode(mode, async () => {
      const cause = new KeyServiceInteractionError({
        reason: "Cancelled",
        message: "Cancelled test prompt",
      });
      const { interaction } = scripted({
        requestValue: () => Effect.fail(cause),
      });
      const failure = await run(Effect.flip(unwrap(interaction)));
      expect(failure.reason).toBe("Interaction");
      expect(failure.cause).toBe(cause);
    }),
);

test("wrong PIN returns the plugin failure", () =>
  withMode("pin", async () => {
    const { interaction } = scripted({
      requestValue: () => Effect.succeed(Redacted.make("654321")),
    });
    const failure = await run(Effect.flip(unwrap(interaction)));
    expect(failure.reason).toBe("PluginError");
    expect(failure.message).toContain("wrong PIN");
  }));

test("chatty interactions preserve order, labels, public response and context", () =>
  withMode("chatty", async () => {
    const { interaction, calls } = scripted();
    expect(await run(unwrap(interaction))).toEqual(key);
    expect(calls).toEqual([
      {
        kind: "message",
        context: { plugin: "fake", request },
        message: "Touch fake token",
      },
      {
        kind: "confirm",
        context: { plugin: "fake", request },
        message: "Continue?",
        yes: "Yes, continue",
        no: "No, stop",
      },
      {
        kind: "value",
        context: { plugin: "fake", request },
        message: "Token label",
        secret: false,
      },
    ]);
  }));

test("one-label confirmation accepts a negative response", () =>
  withMode("confirm-no", async () => {
    const { interaction } = scripted({
      confirm: (_context, _prompt, yes, no) => {
        expect(yes).toBe("Yes");
        expect(no).toBeUndefined();
        return Effect.succeed(false);
      },
    });
    expect(await run(unwrap(interaction))).toEqual(key);
  }));

test("unknown plugin commands are acknowledged as unsupported", () =>
  withMode("unsupported", async () => {
    expect(await run(unwrap())).toEqual(key);
  }));

test.each([
  "duplicate-key",
  "bad-index",
  "short-key",
  "bad-confirm",
  "bad-label",
])("identity rejects %s", (mode) =>
  withMode(mode, async () => {
    expect((await run(Effect.flip(unwrap()))).reason).toBe("Protocol");
  }),
);

test.each(["duplicate-labels", "empty-wrap", "bad-index"])(
  "recipient rejects %s",
  (mode) =>
    withMode(mode, async () => {
      expect(
        (await run(Effect.flip(wrapFileKey("fake", recipient, key, options()))))
          .reason,
      ).toBe("Protocol");
    }),
);

test("sanitizes text reported by plugin errors", () =>
  withMode("error-control", async () => {
    const failure = await run(Effect.flip(unwrap()));
    expect(failure.reason).toBe("PluginError");
    expect(failure.message).toContain("bad?[2J?detail");
  }));

test(
  "waiting runs once and cannot block a late plugin response",
  () =>
    withMode("slow", async () => {
      let waits = 0;
      const { interaction } = scripted({
        waiting: () =>
          Effect.gen(function* () {
            waits++;
            yield* Effect.never;
          }),
      });
      const started = Date.now();
      expect(
        await run(
          unwrapFileKey("fake", [identity], [wrapped], {
            ...options(interaction),
            waitTimer: 100,
          }),
        ),
      ).toEqual(key);
      expect(waits).toBe(1);
      expect(Date.now() - started).toBeLessThan(9_000);
    }),
  10_000,
);

test("premature plugin exit includes exit code and diagnostic cause", () =>
  withMode("crash", async () => {
    const failure = await run(Effect.flip(unwrap()));
    expect(failure.reason).toBe("Exited");
    expect(`${failure.message} ${JSON.stringify(failure.cause)}`).toContain(
      "3",
    );
    expect(JSON.stringify(failure.cause)).toContain(
      "fake process exited deliberately",
    );
  }));

test("missing executable is NotFound", async () => {
  const failure = await run(
    Effect.flip(
      unwrapFileKey("fake", [identity], [wrapped], {
        ...options(),
        binary: () => "/no-such-age-plugin-test-binary",
      }),
    ),
  );
  expect(failure.reason).toBe("NotFound");
});

test.each(["hold", "hold-ignore-term"])(
  "interruption reaps the %s plugin",
  (mode) =>
    withMode(mode, async () => {
      const started = Promise.withResolvers<number>();
      const { interaction } = scripted({
        displayMessage: (_context, message) =>
          Effect.sync(() => {
            if (!/^pid:\d+$/.test(message))
              throw new Error("Expected fixture PID");
            started.resolve(Number(message.slice(4)));
          }),
      });
      const fiber = Effect.runFork(
        unwrap(interaction).pipe(Effect.provide(BunServices.layer)),
      );
      try {
        const pid = await started.promise;
        expect(() => process.kill(pid, 0)).not.toThrow();
        await Effect.runPromise(Fiber.interrupt(fiber));
        expect(() => process.kill(pid, 0)).toThrow();
      } finally {
        await Effect.runPromise(Fiber.interrupt(fiber));
      }
    }),
  8_000,
);

test(
  "done gives a hanging plugin a bounded exit grace and reaps it",
  () =>
    withMode("post-done-hold", async () => {
      let pid = 0;
      const { interaction } = scripted({
        displayMessage: (_context, message) =>
          Effect.sync(() => {
            if (!/^pid:\d+$/.test(message))
              throw new Error("Expected fixture PID");
            pid = Number(message.slice(4));
          }),
      });
      const started = Date.now();
      expect(await run(unwrap(interaction))).toEqual(key);
      expect(pid).toBeGreaterThan(0);
      expect(() => process.kill(pid, 0)).toThrow();
      expect(Date.now() - started).toBeLessThan(5_000);
    }),
  6_000,
);

test(
  "pending uninterruptible waiting cleanup never blocks the next message",
  () =>
    withMode("waiting-gate", async () => {
      const gate = Promise.withResolvers<void>();
      let waits = 0;
      let fallback = false;
      const timer = setTimeout(() => {
        fallback = true;
        gate.resolve();
      }, 2_000);
      const { interaction } = scripted({
        waiting: () =>
          Effect.uninterruptible(
            Effect.gen(function* () {
              waits++;
              yield* Effect.promise(() => gate.promise);
            }),
          ),
        displayMessage: (_context, message) =>
          Effect.sync(() => {
            expect(message).toBe("release waiting callback");
            gate.resolve();
          }),
      });
      try {
        expect(
          await run(
            unwrapFileKey("fake", [identity], [wrapped], {
              ...options(interaction),
              waitTimer: 50,
            }),
          ),
        ).toEqual(key);
        expect(waits).toBe(1);
        expect(fallback).toBe(false);
      } finally {
        clearTimeout(timer);
        gate.resolve();
      }
    }),
  4_000,
);

test("plugin diagnostics redact identities and entered secrets in common encodings", () =>
  withMode("diagnostic-secret", async () => {
    const failure = await run(Effect.flip(unwrap()));
    expect(failure.reason).toBe("PluginError");
    const diagnostic = JSON.stringify({
      message: failure.message,
      cause: failure.cause,
    });
    expect(diagnostic).toContain("[redacted]");
    for (const value of [identity, "123456"]) {
      const bytes = Buffer.from(value);
      for (const encoded of [
        value,
        bytes.toString("base64"),
        bytes.toString("base64").replace(/=+$/, ""),
        bytes.toString("hex"),
      ])
        expect(diagnostic).not.toContain(encoded);
    }
  }));
