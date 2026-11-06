import { Buffer } from "node:buffer";
import { tmpdir } from "node:os";
import type * as Cause from "effect/Cause";
import type * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Fiber from "effect/Fiber";
import * as Queue from "effect/Queue";
import * as Redacted from "effect/Redacted";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  AgePluginError,
  type KeyServiceInteraction,
  type KeyServiceInteractionError,
  type KeyServiceRequest,
  sanitizeForDisplay,
} from "./model.js";

/** One age header or plugin protocol stanza. */
export interface AgeStanza {
  readonly type: string;
  readonly args: ReadonlyArray<string>;
  readonly body: Uint8Array;
}

/** Interaction and process options for one age plugin exchange. */
export interface AgePluginClientOptions {
  readonly interaction: KeyServiceInteraction;
  /** The keyservice request this plugin exchange serves, passed to interactions. */
  readonly request?: KeyServiceRequest | undefined;
  /** Executable for a plugin name; defaults to `age-plugin-${name}` on PATH. */
  readonly binary?: ((name: string) => string) | undefined;
  /** Silence before the waiting notification; defaults to 5 seconds. */
  readonly waitTimer?: Duration.Input | undefined;
}

const empty = new Uint8Array();
const token = /^[\x21-\x7e]+$/;
const protocolError = (plugin: string, message: string) =>
  new AgePluginError({ plugin, reason: "Protocol", message });
const validName = (name: string): boolean =>
  /^[a-z0-9][a-z0-9._+-]{0,63}$/.test(name) && !name.includes("..");
const invalidName = () =>
  new AgePluginError({
    plugin: "",
    reason: "InvalidName",
    message: "Invalid age plugin name",
  });

/** Derive a safe executable name from an age plugin identity. */
export const pluginNameFromIdentity = (
  identity: string,
): Effect.Effect<string, AgePluginError> =>
  Effect.try({
    try: () => {
      const separator = identity.lastIndexOf("1");
      if (separator < 0) throw invalidName();
      const hrp = identity.slice(0, separator);
      const match = /^AGE-PLUGIN-(.+)-$/i.exec(hrp);
      const name = match?.[1]?.toLowerCase();
      if (!name || !validName(name)) throw invalidName();
      return name;
    },
    catch: () => invalidName(),
  });

/** Derive a plugin name, leaving native age recipients to the native implementation. */
export const pluginNameFromRecipient = (
  recipient: string,
): Effect.Effect<string | undefined, AgePluginError> =>
  Effect.try({
    try: () => {
      const separator = recipient.lastIndexOf("1");
      if (separator === 3 && recipient.startsWith("age1")) return undefined;
      const hrp = recipient.slice(0, separator);
      if (["age1pq", "age1tag", "age1tagpq"].includes(hrp)) return undefined;
      const name = hrp.startsWith("age1") ? hrp.slice(4) : "";
      if (!validName(name)) throw invalidName();
      return name;
    },
    catch: () => invalidName(),
  });

const decodeBody = (text: string, plugin: string): Uint8Array => {
  if (!/^[A-Za-z0-9+/]*$/.test(text))
    throw protocolError(plugin, "Invalid stanza base64");
  const bytes = Buffer.from(text, "base64");
  if (bytes.toString("base64").replace(/=+$/, "") !== text) {
    bytes.fill(0);
    throw protocolError(plugin, "Non-canonical stanza base64");
  }
  return bytes;
};

/** Encode an age stanza with canonical unpadded base64 and a short final body line. */
export const encodeStanza = (stanza: AgeStanza): string => {
  const header = [stanza.type, ...stanza.args];
  if (!header.every((value) => token.test(value)))
    throw protocolError("", "Invalid stanza header");
  const body = Buffer.from(stanza.body).toString("base64").replace(/=+$/, "");
  const lines: string[] = [];
  for (let offset = 0; offset < body.length; offset += 64)
    lines.push(body.slice(offset, offset + 64));
  if (body.length % 64 === 0) lines.push("");
  return `-> ${header.join(" ")}\n${lines.join("\n")}\n`;
};

// Both complete-input and live-process parsing share the same wire validation.
const stanzaDecoder = (plugin: string) => {
  let header: string[] | undefined;
  let body = "";
  return {
    get pending() {
      return header !== undefined;
    },
    push(line: string): AgeStanza | undefined {
      if (!header) {
        if (!line.startsWith("-> "))
          throw protocolError(plugin, "Invalid stanza header");
        header = line.slice(3).split(" ");
        if (!header.every((value) => token.test(value)))
          throw protocolError(plugin, "Invalid stanza header");
        return undefined;
      }
      if (line.length > 64)
        throw protocolError(plugin, "Stanza body line exceeds 64 characters");
      body += line;
      if (line.length === 64) return undefined;
      const type = header[0];
      if (type === undefined)
        throw protocolError(plugin, "Missing stanza type");
      const result = {
        type,
        args: header.slice(1),
        body: decodeBody(body, plugin),
      };
      header = undefined;
      body = "";
      return result;
    },
  };
};

/** Parse complete stanza wire input, rejecting incomplete and noncanonical encodings. */
export const parseStanzas = (
  input: string,
): Effect.Effect<ReadonlyArray<AgeStanza>, AgePluginError> =>
  Effect.try({
    try: () => {
      if (input === "") return [];
      if (!input.endsWith("\n"))
        throw protocolError("", "Unterminated stanza line");
      const decoder = stanzaDecoder("");
      const result: AgeStanza[] = [];
      for (const line of input.slice(0, -1).split("\n")) {
        const stanza = decoder.push(line);
        if (stanza) result.push(stanza);
      }
      if (decoder.pending) throw protocolError("", "Incomplete stanza body");
      return result;
    },
    catch: (cause) =>
      cause instanceof AgePluginError
        ? cause
        : protocolError("", "Invalid stanza"),
  });

type ExchangeInput =
  | {
      readonly mode: "identity-v1";
      readonly identities: ReadonlyArray<string>;
      readonly stanzas: ReadonlyArray<AgeStanza>;
    }
  | {
      readonly mode: "recipient-v1";
      readonly recipient: string;
      readonly fileKey: Uint8Array;
    };

const exchange = Effect.fn("AgePlugin.exchange")(function* (
  plugin: string,
  input: ExchangeInput,
  options: AgePluginClientOptions,
) {
  if (!validName(plugin)) return yield* Effect.fail(invalidName());
  if (input.mode === "recipient-v1" && input.fileKey.length !== 16) {
    return yield* Effect.fail(
      protocolError(plugin, "File key must be 16 bytes"),
    );
  }
  const context = { plugin, request: options.request };
  const secrets: Redacted.Redacted<string>[] =
    input.mode === "identity-v1"
      ? input.identities.map((identity) => Redacted.make(identity))
      : [];
  const keyBytes: Uint8Array[] =
    input.mode === "recipient-v1" ? [input.fileKey] : [];
  const scrub = (text: string): string => {
    let safe = text;
    const values = secrets.flatMap((value) => {
      const text = Redacted.value(value);
      const bytes = Buffer.from(text);
      const encoded = bytes.toString("base64");
      const hexadecimal = bytes.toString("hex");
      bytes.fill(0);
      return [text, encoded, encoded.replace(/=+$/, ""), hexadecimal];
    });
    for (const bytes of keyBytes) {
      values.push(
        new TextDecoder().decode(bytes),
        Buffer.from(bytes).toString("base64"),
        Buffer.from(bytes).toString("base64").replace(/=+$/, ""),
        Buffer.from(bytes).toString("hex"),
      );
    }
    for (const value of values) {
      if (value) safe = safe.split(value).join("[redacted]");
    }
    return sanitizeForDisplay(safe, 4096);
  };
  const outgoing = yield* Queue.make<Uint8Array, Cause.Done>();
  const pendingBytes = new Set<Uint8Array>();
  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      for (const bytes of pendingBytes) bytes.fill(0);
      for (const secret of secrets) Redacted.wipeUnsafe(secret);
    }),
  );
  const process = yield* ChildProcess.make(
    options.binary?.(plugin) ?? `age-plugin-${plugin}`,
    [`--age-plugin=${input.mode}`],
    {
      cwd: tmpdir(),
      stdin: Stream.fromQueue(outgoing),
      stdout: "pipe",
      stderr: "pipe",
      forceKillAfter: "1 second",
    },
  ).pipe(
    Effect.mapError(
      (cause) =>
        new AgePluginError({
          plugin,
          reason: cause.reason._tag === "NotFound" ? "NotFound" : "Exited",
          message:
            cause.reason._tag === "NotFound"
              ? `age-plugin-${plugin} not found on PATH`
              : `Could not start age-plugin-${plugin}`,
        }),
    ),
  );
  let stderr = "";
  yield* process.stderr.pipe(
    Stream.decodeText(),
    Stream.runForEach((chunk) =>
      Effect.sync(() => {
        stderr = (stderr + chunk).slice(-4096);
      }),
    ),
    Effect.orElseSucceed(() => undefined),
    Effect.forkScoped,
  );
  const finish = Queue.end(outgoing).pipe(
    Effect.andThen(
      process.exitCode.pipe(
        Effect.timeoutOption("2 seconds"),
        Effect.orElseSucceed(() => undefined),
      ),
    ),
  );
  const exited = Effect.gen(function* () {
    const code = yield* process.exitCode.pipe(
      Effect.orElseSucceed(() => undefined),
      Effect.timeoutOption("2 seconds"),
    );
    return new AgePluginError({
      plugin,
      reason: "Exited",
      message: `age-plugin-${plugin} exited before done${code._tag === "Some" && code.value !== undefined ? ` (exit ${code.value})` : ""}`,
      cause: { stderr: scrub(stderr) },
    });
  });
  const send = (
    type: string,
    args: ReadonlyArray<string> = [],
    body: Uint8Array = empty,
  ) =>
    Effect.gen(function* () {
      const wire = yield* Effect.try({
        try: () => encodeStanza({ type, args, body }),
        catch: () => protocolError(plugin, "Invalid outbound stanza"),
      });
      const bytes = new TextEncoder().encode(wire);
      pendingBytes.add(bytes);
      yield* Queue.offer(outgoing, bytes);
    });
  if (input.mode === "identity-v1") {
    for (const identity of input.identities)
      yield* send("add-identity", [identity]);
    for (const stanza of input.stanzas)
      yield* send(
        "recipient-stanza",
        ["0", stanza.type, ...stanza.args],
        stanza.body,
      );
  } else {
    yield* send("add-recipient", [input.recipient]);
    yield* send("wrap-file-key", [], input.fileKey);
    yield* send("extension-labels");
  }
  yield* send("done");
  const pull = yield* Stream.toPull(process.stdout.pipe(Stream.decodeText()));
  let remaining = "";
  const decoder = stanzaDecoder(plugin);
  const next = Effect.gen(function* () {
    while (true) {
      const newline = remaining.indexOf("\n");
      if (newline < 0) {
        const chunk = yield* pull.pipe(
          Effect.catch(() => exited.pipe(Effect.flatMap(Effect.fail))),
        );
        remaining += chunk.join("");
        continue;
      }
      const line = remaining.slice(0, newline);
      remaining = remaining.slice(newline + 1);
      const stanza = yield* Effect.try({
        try: () => decoder.push(line),
        catch: (cause) =>
          cause instanceof AgePluginError
            ? cause
            : protocolError(plugin, "Invalid stanza"),
      });
      if (stanza) return stanza;
    }
  });
  let fileKey: Uint8Array | undefined;
  let returned = false;
  yield* Effect.addFinalizer(() =>
    Effect.sync(() => {
      if (!returned) fileKey?.fill(0);
    }),
  );
  const stanzas: AgeStanza[] = [];
  let labels = false;
  let interactionFailure: KeyServiceInteractionError | undefined;
  const interactionError = () =>
    new AgePluginError({
      plugin,
      reason: "Interaction",
      message: "Age plugin interaction failed",
      cause: interactionFailure,
    });
  const interact = <A>(
    effect: Effect.Effect<A, KeyServiceInteractionError>,
    reply: (value: A) => Effect.Effect<void, AgePluginError>,
  ) =>
    effect.pipe(
      Effect.matchEffect({
        onFailure: (cause) => {
          interactionFailure ??= cause;
          return send("fail");
        },
        onSuccess: reply,
      }),
    );
  while (true) {
    const timer = yield* Effect.sleep(options.waitTimer ?? "5 seconds").pipe(
      Effect.andThen(() => options.interaction.waiting(context)),
      Effect.forkScoped,
    );
    const stanza = yield* next.pipe(
      Effect.ensuring(Effect.forkScoped(Fiber.interrupt(timer))),
    );
    const text = () => scrub(new TextDecoder().decode(stanza.body));
    if (stanza.type === "done") break;
    if (stanza.type === "file-key" && input.mode === "identity-v1") {
      if (
        stanza.args.length !== 1 ||
        stanza.args[0] !== "0" ||
        stanza.body.length !== 16 ||
        fileKey
      ) {
        stanza.body.fill(0);
        return yield* Effect.fail(
          protocolError(plugin, "Invalid or duplicate file-key stanza"),
        );
      }
      fileKey = stanza.body;
      keyBytes.push(fileKey);
      yield* send("ok");
    } else if (
      stanza.type === "recipient-stanza" &&
      input.mode === "recipient-v1"
    ) {
      const type = stanza.args[1];
      if (stanza.args[0] !== "0" || !type)
        return yield* Effect.fail(
          protocolError(plugin, "Invalid recipient-stanza index or type"),
        );
      stanzas.push({ type, args: stanza.args.slice(2), body: stanza.body });
      yield* send("ok");
    } else if (stanza.type === "labels" && input.mode === "recipient-v1") {
      if (labels)
        return yield* Effect.fail(
          protocolError(plugin, "Duplicate labels stanza"),
        );
      labels = true;
      yield* send("ok");
    } else if (stanza.type === "error") {
      yield* send("ok");
      yield* finish;
      return yield* Effect.fail(
        interactionFailure
          ? interactionError()
          : new AgePluginError({
              plugin,
              reason: "PluginError",
              message: text(),
              cause: { stderr: scrub(stderr) },
            }),
      );
    } else if (stanza.type === "msg") {
      yield* interact(options.interaction.displayMessage(context, text()), () =>
        send("ok"),
      );
    } else if (stanza.type === "confirm") {
      if (stanza.args.length < 1 || stanza.args.length > 2)
        return yield* Effect.fail(
          protocolError(plugin, "Invalid confirm labels"),
        );
      const decoded = yield* Effect.try({
        try: () =>
          stanza.args.map((label) =>
            scrub(new TextDecoder().decode(decodeBody(label, plugin))),
          ),
        catch: () => protocolError(plugin, "Invalid confirm labels"),
      });
      yield* interact(
        options.interaction.confirm(
          context,
          text(),
          decoded[0] ?? "",
          decoded[1],
        ),
        (yes) => send("ok", [yes ? "yes" : "no"]),
      );
    } else if (
      stanza.type === "request-secret" ||
      stanza.type === "request-public"
    ) {
      yield* interact(
        options.interaction.requestValue(
          context,
          text(),
          stanza.type === "request-secret",
        ),
        (value) =>
          Effect.gen(function* () {
            secrets.push(Redacted.make(Redacted.value(value)));
            const bytes = new TextEncoder().encode(Redacted.value(value));
            yield* send("ok", [], bytes).pipe(
              Effect.ensuring(Effect.sync(() => bytes.fill(0))),
            );
          }),
      );
    } else {
      yield* send("unsupported");
    }
  }
  yield* finish;
  if (input.mode === "identity-v1" && !fileKey && interactionFailure)
    return yield* Effect.fail(interactionError());
  if (input.mode === "recipient-v1" && stanzas.length === 0)
    return yield* Effect.fail(
      interactionFailure
        ? interactionError()
        : protocolError(plugin, "Plugin returned no recipient stanzas"),
    );
  returned = true;
  return { fileKey, stanzas };
}, Effect.scoped);

/** Recover a 16-byte file key through identity-v1, or undefined when no identity matches. */
export const unwrapFileKey = (
  plugin: string,
  identities: ReadonlyArray<string>,
  stanzas: ReadonlyArray<AgeStanza>,
  options: AgePluginClientOptions,
): Effect.Effect<Uint8Array | undefined, AgePluginError, ChildProcessSpawner> =>
  exchange(plugin, { mode: "identity-v1", identities, stanzas }, options).pipe(
    Effect.map((result) => result.fileKey),
  );

/** Wrap a 16-byte file key through recipient-v1 and return at least one recipient stanza. */
export const wrapFileKey = (
  plugin: string,
  recipient: string,
  fileKey: Uint8Array,
  options: AgePluginClientOptions,
): Effect.Effect<
  ReadonlyArray<AgeStanza>,
  AgePluginError,
  ChildProcessSpawner
> =>
  exchange(plugin, { mode: "recipient-v1", recipient, fileKey }, options).pipe(
    Effect.map((result) => result.stanzas),
  );
