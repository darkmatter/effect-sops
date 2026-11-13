import * as BunServices from "@effect/platform-bun/BunServices";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  unwrapFileKey,
  type AgeStanza,
} from "../../../src/keyservice/age-plugin.ts";
import type {
  KeyServiceInteraction,
  KeyServiceRequest,
  PluginPromptContext,
} from "../../../src/keyservice/model.ts";

export const binary = `${import.meta.dir}/age-plugin-fake`;
export const identity = "AGE-PLUGIN-FAKE-1qqqq";
export const recipient = "age1fake1qqqq";
export const key = Uint8Array.from({ length: 16 }, (_, index) => index);
export const wrapped: AgeStanza = {
  type: "fake-wrap",
  args: ["aabbccdd"],
  body: key.map((byte) => byte ^ 0x5a),
};
export const request: KeyServiceRequest = {
  id: 1,
  operation: "decrypt",
  key: { type: "age", recipient },
  keyDescription: "fake test recipient",
  peer: "127.0.0.1:1234",
  peerHost: "127.0.0.1",
  receivedAt: new Date(0),
};
interface InteractionCall {
  readonly kind: string;
  readonly context: PluginPromptContext;
  readonly message?: string;
  readonly secret?: boolean;
  readonly yes?: string;
  readonly no?: string | undefined;
}
export const scripted = (overrides: Partial<KeyServiceInteraction> = {}) => {
  const calls: InteractionCall[] = [];
  const interaction: KeyServiceInteraction = {
    approve: () => Effect.succeed(true),
    displayMessage: (context, message) =>
      Effect.sync(() => {
        calls.push({ kind: "message", context, message });
      }),
    confirm: (context, message, yes, no) =>
      Effect.sync(() => {
        calls.push({ kind: "confirm", context, message, yes, no });
        return true;
      }),
    requestValue: (context, message, secret) =>
      Effect.sync(() => {
        calls.push({ kind: "value", context, message, secret });
        return Redacted.make(secret ? "123456" : "fixture label");
      }),
    waiting: (context) =>
      Effect.sync(() => {
        calls.push({ kind: "waiting", context });
      }),
    ...overrides,
  };
  return { calls, interaction };
};
export const run = <A, E>(effect: Effect.Effect<A, E, ChildProcessSpawner>) =>
  Effect.runPromise(effect.pipe(Effect.provide(BunServices.layer)));
export const options = (interaction = scripted().interaction) => ({
  binary: () => binary,
  interaction,
  request,
});
export const unwrap = (interaction?: KeyServiceInteraction) =>
  unwrapFileKey("fake", [identity], [wrapped], options(interaction));
export const withMode = async <A>(
  mode: string,
  body: () => Promise<A>,
): Promise<A> => {
  const previous = process.env.FAKE_PLUGIN_MODE;
  process.env.FAKE_PLUGIN_MODE = mode;
  try {
    return await body();
  } finally {
    if (previous === undefined) delete process.env.FAKE_PLUGIN_MODE;
    else process.env.FAKE_PLUGIN_MODE = previous;
  }
};
