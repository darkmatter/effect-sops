import { describe, expect, test } from "bun:test";
import * as BunServices from "@effect/platform-bun/BunServices";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runInNewContext } from "node:vm";
import * as Cause from "effect/Cause";
import * as Effect from "effect/Effect";
import * as Exit from "effect/Exit";
import * as Fiber from "effect/Fiber";
import * as Layer from "effect/Layer";
import * as Option from "effect/Option";
import * as Queue from "effect/Queue";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Terminal from "effect/Terminal";
import * as TestClock from "effect/testing/TestClock";
import * as Interaction from "../src/keyservice/interaction.ts";
import {
  describeRequest,
  KeyServiceInteractionError,
  sanitizeForDisplay,
  type KeyServiceKey,
  type KeyServiceRequest,
  type PluginPromptContext,
} from "../src/keyservice/model.ts";
import { describeKey } from "../src/keyservice/protocol.ts";

const request = (
  changes: Partial<KeyServiceRequest> = {},
): KeyServiceRequest => {
  const key = changes.key ?? { type: "age", recipient: "age1synthetic" };
  return {
    id: 1,
    operation: "decrypt",
    key,
    keyDescription: describeKey(key),
    peer: "127.0.0.1:12345",
    peerHost: "127.0.0.1",
    receivedAt: new Date(0),
    ...changes,
  };
};
const context: PluginPromptContext = { plugin: "yubikey", request: undefined };
const failure = <E>(effect: Effect.Effect<unknown, E>) =>
  Effect.runPromise(Effect.flip(effect));

describe("custom interactions", () => {
  test("none approves, displays messages, and rejects interactive follow-ups", async () => {
    expect(await Effect.runPromise(Interaction.none.approve(request()))).toBe(true);
    await Effect.runPromise(Interaction.none.displayMessage(context, "Touch key"));
    await Effect.runPromise(Interaction.none.waiting(context));
    for (const effect of [
      Interaction.none.requestValue(context, "PIN", true),
      Interaction.none.confirm(context, "Continue?", "Yes", "No"),
    ]) {
      const error = await failure(effect);
      expect(error.reason).toBe("Unavailable");
      expect(error.message).toContain("start the keyservice with prompt or dialog");
    }
  });

  test("make accepts values, Promises, Effects, and both value representations", async () => {
    const seen: string[] = [];
    const custom = Interaction.make({
      approve: (incoming) => incoming.operation === "decrypt",
      displayMessage: async (_context, message) => { seen.push(message); },
      requestValue: () => "synthetic-value",
      confirm: () => Effect.succeed(false),
      waiting: () => { seen.push("waiting"); },
    });
    expect(await Effect.runPromise(custom.approve(request()))).toBe(true);
    expect(await Effect.runPromise(custom.confirm(context, "Continue?", "Yes", "No"))).toBe(false);
    expect(Redacted.value(await Effect.runPromise(custom.requestValue(context, "Value", false)))).toBe("synthetic-value");
    await Effect.runPromise(custom.displayMessage(context, "message"));
    await Effect.runPromise(custom.waiting(context));
    expect(seen).toEqual(["message", "waiting"]);
    const redacted = Redacted.make("synthetic-value");
    expect(await Effect.runPromise(Interaction.make({ requestValue: () => Promise.resolve(redacted) }).requestValue(context, "Value", true))).toBe(redacted);
    expect(await Effect.runPromise(Interaction.make({}).approve(request()))).toBe(true);
    expect((await failure(Interaction.make({}).requestValue(context, "PIN", true))).reason).toBe("Unavailable");
  });

  test("make converts thrown, rejected, and failed handlers without exposing their details", async () => {
    const typed = new KeyServiceInteractionError({ reason: "Cancelled", message: "synthetic-sensitive-detail" });
    for (const approve of [
      () => { throw new Error("synthetic-sensitive-detail"); },
      () => Promise.reject(new Error("synthetic-sensitive-detail")),
      () => Effect.fail("synthetic-sensitive-detail"),
      () => Effect.die("synthetic-sensitive-detail"),
      () => { throw typed; },
      () => Promise.reject(typed),
      () => Effect.die(typed),
    ]) {
      const error = await failure(Interaction.make({ approve }).approve(request()));
      expect(error.reason).toBe("Failed");
      expect(error.message).not.toContain("synthetic-sensitive-detail");
    }
    await Effect.runPromise(Interaction.make({ waiting: () => Promise.reject("synthetic-sensitive-detail") }).waiting(context));
  });

  test.each(["Cancelled", "TimedOut", "Unavailable"] as const)("make preserves typed %s failures", async (reason) => {
    const error = new KeyServiceInteractionError({ reason, message: "Interaction unavailable" });
    const custom = Interaction.make({
      approve: () => Effect.fail(error),
      requestValue: () => Effect.fail(error),
      confirm: () => Effect.fail(error),
    });
    expect(await failure(custom.approve(request()))).toBe(error);
    expect(await failure(custom.requestValue(context, "Value", false))).toBe(error);
    expect(await failure(custom.confirm(context, "Continue?", "Yes", "No"))).toBe(error);
  });

  test("make preserves interruption", async () => {
    const exit = await Effect.runPromiseExit(Interaction.make({ approve: () => Effect.interrupt }).approve(request()));
    expect(Exit.isFailure(exit)).toBe(true);
    if (Exit.isFailure(exit)) expect(Cause.hasInterruptsOnly(exit.cause)).toBe(true);
  });

  test("identifies default automatic approval without invoking custom handlers", () => {
    let calls = 0;
    expect(Interaction.approvesAutomatically(Interaction.none)).toBe(true);
    expect(Interaction.approvesAutomatically(Interaction.make({}))).toBe(true);
    expect(Interaction.approvesAutomatically(Interaction.make({ requestValue: () => "value" }))).toBe(true);
    expect(Interaction.approvesAutomatically(Interaction.make({ approve: () => { calls++; return true; } }))).toBe(false);
    expect(calls).toBe(0);
  });

  test("remembering an automatic approval keeps it detectable", async () => {
    const remembered = await Effect.runPromise(
      Interaction.remember(Interaction.none, { ttl: "5 minutes" }),
    );
    expect(Interaction.approvesAutomatically(remembered)).toBe(true);
  });
});

const promptOrigins: ReadonlyArray<{ label: string; context: PluginPromptContext; suffix: string }> = [
  {
    label: "decryption peer host",
    context: { plugin: "yubikey", request: request({ peerHost: "100.64.1.2\n\u202e" }) },
    suffix: "\nFor a decryption request from 100.64.1.2??.",
  },
  {
    label: "encryption peer fallback",
    context: { plugin: "yubikey", request: request({ operation: "encrypt", peerHost: undefined, peer: "unix:/synthetic\u001b\u202e" }) },
    suffix: "\nFor an encryption request from unix:/synthetic??.",
  },
  { label: "no request", context, suffix: "" },
];

describe("remembered approvals", () => {
  test("approvalCovers compares complete keys and peer hosts, with exact expiry", () => {
    const base = request();
    const grant = { request: base, grantedAt: 10, expiresAt: 100 };
    expect(Interaction.approvalCovers(grant, request({ id: 2, peer: "127.0.0.1:22222" }), 99)).toBe(true);
    expect(Interaction.approvalCovers(grant, base, 100)).toBe(false);
    expect(Interaction.approvalCovers(grant, request({ operation: "encrypt" }), 20)).toBe(false);
    expect(Interaction.approvalCovers(grant, request({ peerHost: "127.0.0.2" }), 20)).toBe(false);
    expect(Interaction.approvalCovers(grant, request({ key: { type: "age", recipient: "age1different" } }), 20)).toBe(false);
    const unsafe = request({ key: { type: "age", recipient: "age1\n" } });
    const otherUnsafe = request({ key: { type: "age", recipient: "age1\r" } });
    expect(unsafe.keyDescription).toBe(otherUnsafe.keyDescription);
    expect(Interaction.approvalCovers({ ...grant, request: unsafe }, otherUnsafe, 20)).toBe(false);
    const local = request({ peerHost: undefined, peer: "unix:/first" });
    expect(Interaction.approvalCovers({ ...grant, request: local }, request({ peerHost: undefined, peer: "unix:/second" }), 20)).toBe(true);
    expect(Interaction.approvalCovers({ ...grant, request: local }, base, 20)).toBe(false);
    const keys: KeyServiceKey[] = [
      { type: "age", recipient: "recipient" },
      { type: "pgp", fingerprint: "fingerprint" },
      { type: "kms", arn: "arn", role: "role", context: { first: "1", second: "2" }, awsProfile: "profile" },
      { type: "gcp-kms", resourceId: "resource" },
      { type: "azure-keyvault", vaultUrl: "url", name: "name", version: "version" },
      { type: "vault", vaultAddress: "address", enginePath: "path", keyName: "key" },
      { type: "hckms", keyId: "id" },
    ];
    for (const key of keys) {
      const keyGrant = { ...grant, request: request({ key }) };
      expect(Interaction.approvalCovers(keyGrant, request({ key: { ...key } }), 20)).toBe(true);
      for (const [field, value] of Object.entries(key)) {
        if (field === "type") continue;
        const changed = { ...key, [field]: typeof value === "string" ? `${value}-changed` : { first: "changed" } };
        expect(Interaction.approvalCovers(keyGrant, request({ key: changed }), 20)).toBe(false);
      }
    }
    const kms = keys[2];
    if (kms?.type !== "kms") throw new Error("Missing KMS fixture");
    expect(Interaction.approvalCovers({ ...grant, request: request({ key: kms }) }, request({ key: { ...kms, context: { second: "2", first: "1" } } }), 20)).toBe(true);
  });

  test("reuses approval only for the same peer, key, and operation until expiry", async () => {
    let calls = 0;
    await Effect.runPromise(Effect.gen(function* () {
      const remembered = yield* Interaction.remember(Interaction.make({ approve: () => { calls++; return true; } }), { ttl: "1 second" });
      expect(yield* remembered.approve(request())).toBe(true);
      expect(yield* remembered.approve(request({ id: 2 }))).toBe(true);
      expect(calls).toBe(1);
      yield* remembered.approve(request({ peerHost: "127.0.0.2" }));
      yield* remembered.approve(request({ operation: "encrypt" }));
      yield* remembered.approve(request({ key: { type: "age", recipient: "age1other" } }));
      expect(calls).toBe(4);
      yield* TestClock.adjust("1 second");
      yield* remembered.approve(request());
      expect(calls).toBe(5);
    }).pipe(Effect.provide(TestClock.layer())));
  });

  test("does not remember denials and always delegates plugin follow-ups", async () => {
    let calls = 0;
    const events: string[] = [];
    const remembered = await Effect.runPromise(Interaction.remember(Interaction.make({
      approve: () => ++calls > 1,
      displayMessage: () => { events.push("message"); },
      requestValue: () => { events.push("value"); return "synthetic"; },
      confirm: () => { events.push("confirm"); return true; },
      waiting: () => { events.push("waiting"); },
    }), { ttl: "1 minute" }));
    expect(await Effect.runPromise(remembered.approve(request()))).toBe(false);
    expect(await Effect.runPromise(remembered.approve(request()))).toBe(true);
    expect(await Effect.runPromise(remembered.approve(request()))).toBe(true);
    expect(calls).toBe(2);
    for (let n = 0; n < 2; n++) {
      await Effect.runPromise(remembered.displayMessage(context, "Touch"));
      await Effect.runPromise(remembered.requestValue(context, "PIN", true));
      await Effect.runPromise(remembered.confirm(context, "Continue?", "Yes", "No"));
      await Effect.runPromise(remembered.waiting(context));
    }
    expect(events).toEqual(["message", "value", "confirm", "waiting", "message", "value", "confirm", "waiting"]);
  });

  test("custom coverage receives clock time but expired grants are removed first", async () => {
    let calls = 0;
    const checked: number[] = [];
    await Effect.runPromise(Effect.gen(function* () {
      const remembered = yield* Interaction.remember(Interaction.make({ approve: () => { calls++; return true; } }), {
        ttl: 100,
        covers: (_grant, _request, now) => { checked.push(now); return true; },
      });
      yield* remembered.approve(request());
      yield* TestClock.adjust(50);
      yield* remembered.approve(request({ peerHost: "other" }));
      expect(calls).toBe(1);
      expect(checked).toEqual([50]);
      yield* TestClock.adjust(50);
      yield* remembered.approve(request());
      expect(calls).toBe(2);
      expect(checked).toEqual([50]);
    }).pipe(Effect.provide(TestClock.layer())));
  });
});

const key = (name: string, input?: string, ctrl = false): Terminal.UserInput => ({
  input: input === undefined ? Option.none() : Option.some(input),
  key: { name, ctrl, meta: false, shift: false },
});

const fakeTerminal = (lines: readonly string[] = [], keys: readonly Terminal.UserInput[] = []) => {
  let position = 0;
  const output: string[] = [];
  const service = Terminal.make({
    columns: Effect.succeed(80),
    rows: Effect.succeed(24),
    readLine: Effect.suspend(() => {
      const line = lines[position++];
      return line === undefined ? Effect.fail(new Terminal.QuitError({})) : Effect.succeed(line);
    }),
    readInput: Effect.gen(function* () {
      const queue = yield* Queue.make<Terminal.UserInput, Cause.Done>();
      yield* Queue.offerAll(queue, keys);
      yield* Queue.end(queue);
      return queue;
    }),
    display: (text) => Effect.sync(() => { output.push(text); }),
  });
  return { output, layer: Layer.succeed(Terminal.Terminal, service) };
};

describe("terminal interaction", () => {
  test.each([...promptOrigins])("plugin prompts include sanitized origin: $label", async ({ context, suffix }) => {
    const fake = fakeTerminal(["public-value", "yes"]);
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    await Effect.runPromise(terminal.requestValue(context, "Value\nplease\u202e", false));
    await Effect.runPromise(terminal.confirm(context, "Continue\nnow\u202e", "Yes", "No"));
    expect(fake.output).toEqual([
      `[age-plugin-yubikey] Value?please?${suffix} `,
      `Continue?now?${suffix} [Yes/No] `,
    ]);
  });

  test("repeats the upstream prompt, accepts yes/no ignoring case, and sanitizes recipients", async () => {
    const fake = fakeTerminal(["maybe", "YES", "nO"]);
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    const incoming = request({ key: { type: "age", recipient: 'age1\u001b[31m\n\u202e"unsafe' } });
    expect(await Effect.runPromise(terminal.approve(incoming))).toBe(true);
    expect(await Effect.runPromise(terminal.approve(incoming))).toBe(false);
    expect(fake.output.join("")).toBe(`\nReceived ${describeRequest(incoming)}. Respond to request? (y/n): `.repeat(3));
    expect(fake.output.join("")).not.toContain("\u001b");
    expect(fake.output.join("")).not.toContain("\u202e");
  });

  test("maps QuitError to Cancelled for line reads", async () => {
    const fake = fakeTerminal();
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    expect((await failure(terminal.approve(request()))).reason).toBe("Cancelled");
    expect((await failure(terminal.requestValue(context, "Value", false))).reason).toBe("Cancelled");
    expect((await failure(terminal.confirm(context, "Continue?", "Yes", "No"))).reason).toBe("Cancelled");
  });

  test("reads a hidden synthetic PIN without echo and supports backspace", async () => {
    const fake = fakeTerminal([], [key("1", "1"), key("2", "2"), key("backspace"), key("3", "3"), key("return")]);
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    const value = await Effect.runPromise(terminal.requestValue(context, "Enter\nPIN\u202e", true));
    expect(Redacted.value(value)).toBe("13");
    expect(fake.output.join("")).not.toContain("13");
    expect(fake.output.join("")).toContain("Enter?PIN?");
  });

  test.each([{ keys: [] }, { keys: [key("c", undefined, true)] }, { keys: [key("d", undefined, true)] }])("hidden EOF and control cancellation return Cancelled (%j)", async ({ keys }) => {
    const fake = fakeTerminal([], keys);
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    expect((await failure(terminal.requestValue(context, "PIN", true))).reason).toBe("Cancelled");
  });

  test("handles public values, confirmation labels, messages, and waiting", async () => {
    const fake = fakeTerminal(["public-value", "invalid", "Proceed", "n", "y"]);
    const terminal = await Effect.runPromise(Interaction.terminal().pipe(Effect.provide(fake.layer)));
    expect(Redacted.value(await Effect.runPromise(terminal.requestValue(context, "Label", false)))).toBe("public-value");
    expect(await Effect.runPromise(terminal.confirm(context, "Continue?", "Proceed", "Stop"))).toBe(true);
    expect(await Effect.runPromise(terminal.confirm(context, "Continue?", "Proceed", "Stop"))).toBe(false);
    expect(await Effect.runPromise(terminal.confirm(context, "Ready?", "Ready", undefined))).toBe(true);
    await Effect.runPromise(terminal.displayMessage(context, "Touch\nkey\u202e"));
    await Effect.runPromise(terminal.waiting(context));
    expect(fake.output.join("")).toContain("Continue? [Proceed/Stop]");
    expect(fake.output.join("")).toContain("Ready? [Ready]");
    expect(fake.output.join("")).toContain("[age-plugin-yubikey] Touch?key?\n");
    expect(fake.output.join("")).toContain("[age-plugin-yubikey] waiting for the plugin (touch your security key if it is blinking)\n");
  });
});

const executable = join(import.meta.dir, "fixtures/osascript/osascript-fake");
const withDialog = async <A>(
  response: string,
  run: (log: string, dir: string) => Promise<A>,
  extra: Readonly<Record<string, string>> = {},
) => {
  const dir = await mkdtemp(join(tmpdir(), "effect-sops-dialog-"));
  const log = join(dir, "argv.json");
  const env = {
    FAKE_OSASCRIPT_LOG: log,
    FAKE_OSASCRIPT_RESPONSE: response,
    FAKE_OSASCRIPT_WAIT: "",
    FAKE_OSASCRIPT_EXIT: "0",
    FAKE_OSASCRIPT_PID: "",
    ...extra,
  };
  const previous = new Map(Object.keys(env).map((name) => [name, process.env[name]]));
  try {
    Object.assign(process.env, env);
    return await run(log, dir);
  } finally {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    await rm(dir, { recursive: true, force: true });
  }
};
const makeDialog = (options: Interaction.DialogOptions = {}) => Effect.runPromise(
  Interaction.dialog({ osascript: executable, ...options }).pipe(Effect.provide(BunServices.layer)),
);
const readArguments = async (path: string) => {
  const argv = Schema.decodeUnknownSync(Schema.Array(Schema.String))(JSON.parse(await readFile(path, "utf8")));
  expect(argv).toHaveLength(6);
  expect(argv.slice(0, 3)).toEqual(["-l", "JavaScript", "-e"]);
  expect(argv[4]).toBe("--");
  const script = argv[3];
  const json = argv[5];
  if (script === undefined || json === undefined) throw new Error("Missing dialog arguments");
  const payload = Schema.decodeUnknownSync(Schema.Record(Schema.String, Schema.Unknown))(JSON.parse(json));
  return { argv, script, payload };
};

const executeJxa = (
  script: string,
  payload: Readonly<Record<string, unknown>>,
  response: Readonly<Record<string, unknown>> | number,
) => {
  let activated = false;
  let dialogOptions: Readonly<Record<string, unknown>> | undefined;
  let notification: { message: string; options: Readonly<Record<string, unknown>> } | undefined;
  const application = {
    includeStandardAdditions: false,
    activate: () => { activated = true; },
    displayDialog: (_message: string, options: Readonly<Record<string, unknown>>) => {
      dialogOptions = options;
      if (typeof response === "number") throw { errorNumber: response };
      return response;
    },
    displayNotification: (message: string, options: Readonly<Record<string, unknown>>) => {
      notification = { message, options };
    },
  };
  const output: unknown = runInNewContext(`${script}\nrun(argv)`, {
    argv: [JSON.stringify(payload)],
    Application: { currentApplication: () => application },
  });
  expect(application.includeStandardAdditions).toBe(true);
  const json = Schema.decodeUnknownSync(Schema.String)(output);
  return { activated, dialogOptions, notification, result: JSON.parse(json) as unknown };
};

describe("dialog interaction", () => {
  test.each([...promptOrigins])("plugin prompts include sanitized origin: $label", ({ context, suffix }) => withDialog('{"button":"OK","text":"public-value"}', async (log) => {
    const dialog = await makeDialog();
    await Effect.runPromise(dialog.requestValue(context, "Value\nplease\u202e", false));
    expect((await readArguments(log)).payload.message).toBe(`Value?please?${suffix}`);
    await Effect.runPromise(dialog.confirm(context, "Continue\nnow\u202e", "OK", "Cancel"));
    expect((await readArguments(log)).payload.message).toBe(`Continue?now?${suffix}`);
  }));

  test("passes hostile recipients only as sanitized JSON data with safe approval defaults", () => withDialog('{"button":"Accept","gaveUp":false}', async (log) => {
    const recipient = 'age1" & do shell script "bad"\n\u202e';
    const incoming = request({ key: { type: "age", recipient } });
    const dialog = await makeDialog();
    expect(await Effect.runPromise(dialog.approve(incoming))).toBe(true);
    const { argv, script, payload } = await readArguments(log);
    expect(script).toContain("JSON.parse(argv[0])");
    expect(script).toContain("Application.currentApplication()");
    expect(script).toContain("activate()");
    expect(argv.slice(0, 5).join(" ")).not.toContain("do shell script");
    expect(payload.message).toBe(`Decryption request from ${incoming.peerHost}\n\n${incoming.keyDescription}\n\nAccept or decline this request.`);
    expect(payload.title).toBe("SOPS keyservice");
    expect(payload.buttons).toEqual(["Decline", "Accept"]);
    expect(payload.defaultButton).toBeUndefined();
    expect(payload.cancelButton).toBe("Decline");
    expect(payload.timeoutSeconds).toBe(60);
    expect(payload.icon).toBe("caution");
    expect(payload.message).not.toContain("\u202e");
    const execution = executeJxa(script, payload, { buttonReturned: "Accept", gaveUp: false });
    expect(execution.activated).toBe(true);
    expect(execution.dialogOptions?.defaultButton).toBeUndefined();
    expect(execution.dialogOptions?.withIcon).toBe("caution");
    expect(execution.dialogOptions?.givingUpAfter).toBe(60);
    expect(execution.result).toEqual({ button: "Accept", gaveUp: false });
    expect(executeJxa(script, payload, -128).result).toEqual({ cancelled: true });
    expect(executeJxa(script, payload, -1).result).toEqual({ failed: true });
  }));

  test.each(['{"button":"Decline"}', '{"gaveUp":true}', '{"cancelled":true}'])("approval declines %s", (response) => withDialog(response, async () => {
    expect(await Effect.runPromise((await makeDialog()).approve(request()))).toBe(false);
  }));

  test("keeps hidden answers out of argv and returns Redacted", () => withDialog('{"button":"OK","text":"synthetic-pin-123"}', async (log) => {
    const dialog = await makeDialog({ title: "Private approval", valueTimeout: "3 seconds" });
    const value = await Effect.runPromise(dialog.requestValue(context, "PIN\nplease\u202e", true));
    expect(Redacted.value(value)).toBe("synthetic-pin-123");
    const { argv, script, payload } = await readArguments(log);
    expect(argv.join(" ")).not.toContain("synthetic-pin-123");
    expect(payload.hidden).toBe(true);
    expect(payload.defaultAnswer).toBe("");
    expect(payload.buttons).toEqual(["Cancel", "OK"]);
    expect(payload.defaultButton).toBe("OK");
    expect(payload.cancelButton).toBe("Cancel");
    expect(payload.title).toContain("yubikey");
    expect(payload.message).toBe(sanitizeForDisplay("PIN\nplease\u202e", 400));
    expect(payload.timeoutSeconds).toBe(3);
    const execution = executeJxa(script, payload, { buttonReturned: "OK", textReturned: "synthetic-pin-123" });
    expect(execution.dialogOptions?.hiddenAnswer).toBe(true);
    expect(execution.dialogOptions?.defaultAnswer).toBe("");
    expect(execution.dialogOptions?.defaultButton).toBe("OK");
    expect(execution.result).toEqual({ button: "OK", text: "synthetic-pin-123", gaveUp: false });
  }));

  test.each([
    ['{"cancelled":true}', "Cancelled"],
    ['{"gaveUp":true}', "TimedOut"],
    ["not-json", "Failed"],
    ['{"button":"OK","text":42}', "Failed"],
  ] as const)("value response %s maps to %s", (response, reason) => withDialog(response, async () => {
    expect((await failure((await makeDialog()).requestValue(context, "PIN", true))).reason).toBe(reason);
  }));

  test.each(['{"button":"Proceed"}', '{"button":"Stop"}', '{"cancelled":true}'])("confirmation handles %s", (response) => withDialog(response, async (log) => {
    const dialog = await makeDialog({ timeout: "2 seconds" });
    expect(await Effect.runPromise(dialog.confirm(context, "Continue\nnow", "Proceed", "Stop"))).toBe(response.includes("Proceed"));
    const { payload } = await readArguments(log);
    expect(payload.buttons).toEqual(["Stop", "Proceed"]);
    expect(payload.defaultButton).toBe("Proceed");
    expect(payload.message).toBe("Continue?now");
    expect(payload.timeoutSeconds).toBe(2);
  }));

  test("notifications sanitize plugin messages and can be disabled", () => withDialog('{"notified":true}', async (log) => {
    const dialog = await makeDialog();
    await Effect.runPromise(dialog.displayMessage(context, "Touch\nkey"));
    const { script, payload } = await readArguments(log);
    expect(payload.message).toBe("Touch?key");
    const execution = executeJxa(script, payload, {});
    expect(execution.activated).toBe(false);
    expect(execution.notification).toEqual({ message: "Touch?key", options: { withTitle: "SOPS keyservice", subtitle: "age-plugin-yubikey" } });
    expect(execution.result).toEqual({ notified: true });
    await Effect.runPromise(dialog.waiting(context));
    expect((await readArguments(log)).payload.kind).toBe("notification");
    const disabled = await makeDialog({ notifications: false, osascript: "/missing/osascript" });
    await Effect.runPromise(disabled.displayMessage(context, "Touch key"));
    await Effect.runPromise(disabled.waiting(context));
  }));

  test("a missing executable fails at call time", async () => {
    const dialog = await makeDialog({ osascript: "/missing/osascript" });
    expect((await failure(dialog.approve(request()))).reason).toBe("Unavailable");
  });

  test("a nonzero child exit fails without returning stdout details", () => withDialog("synthetic-sensitive-detail", async () => {
    const error = await failure((await makeDialog()).approve(request()));
    expect(error.reason).toBe("Failed");
    expect(error.message).not.toContain("synthetic-sensitive-detail");
  }, { FAKE_OSASCRIPT_EXIT: "1" }));

  test("interruption terminates a pending dialog process", () => withDialog("{}", async (_log, dir) => {
    const pidPath = join(dir, "pid");
    process.env.FAKE_OSASCRIPT_PID = pidPath;
    const fiber = Effect.runFork((await makeDialog()).approve(request()));
    try {
      const deadline = Date.now() + 3_000;
      while (!(await Bun.file(pidPath).exists()) && Date.now() < deadline) await Bun.sleep(10);
      const pid = Number(await readFile(pidPath, "utf8"));
      expect(Number.isInteger(pid)).toBe(true);
      expect(pid).toBeGreaterThan(0);
      process.kill(pid, 0);
      await Effect.runPromise(Fiber.interrupt(fiber));
      expect(() => process.kill(pid, 0)).toThrow();
    } finally {
      await Effect.runPromise(Fiber.interrupt(fiber));
    }
  }, { FAKE_OSASCRIPT_WAIT: "1", FAKE_OSASCRIPT_PID: "" }));

  test.skipIf(process.platform === "darwin")("default executable is unavailable outside macOS", async () => {
    const dialog = await Effect.runPromise(Interaction.dialog().pipe(Effect.provide(BunServices.layer)));
    expect((await failure(dialog.approve(request()))).reason).toBe("Unavailable");
  });

  test.skipIf(process.env.EFFECT_SOPS_DIALOG_SMOKE !== "1")("real osascript compiles and times out without approval", async () => {
    const dialog = await Effect.runPromise(Interaction.dialog({ timeout: "1 second" }).pipe(Effect.provide(BunServices.layer)));
    expect(await Effect.runPromise(dialog.approve(request()))).toBe(false);
  }, 10_000);
});
