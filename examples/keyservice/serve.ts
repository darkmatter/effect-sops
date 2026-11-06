import * as BunRuntime from "@effect/platform-bun/BunRuntime";
import * as BunServices from "@effect/platform-bun/BunServices";
import { Interaction, Listen, serve, type ServeOptions } from "effect-sops/KeyService";
import * as Config from "effect/Config";
import * as Data from "effect/Data";
import * as Effect from "effect/Effect";
import * as Option from "effect/Option";
import * as Prompt from "effect/cli/Prompt";

/** Complete named setups; replace the example SSH destination before using devbox. */
export const namedConfigurations = {
  local: {
    listen: Listen.loopback(5000),
    approval: "terminal",
    remember: false,
    remoteForwards: [],
  },
  tailscale: {
    listen: Listen.tailscale(5000),
    approval: "dialog",
    remember: true,
    remoteForwards: [],
  },
  devbox: {
    listen: Listen.loopback(5000),
    approval: "terminal",
    remember: false,
    remoteForwards: [{ destination: "user@devbox.example.com" }],
  },
} as const;

/** Name selected from the committed example configurations. */
export type ConfigurationName = keyof typeof namedConfigurations;

class ConfigurationError extends Data.TaggedError("ConfigurationError")<{
  readonly message: string;
}> {}

/** Pick interactively, or require KEYSERVICE_CONFIG when stdin is not a terminal. */
export const chooseConfiguration = Effect.fn("Example.chooseConfiguration")(
  function* (options: { readonly interactive?: boolean } = {}) {
    const names = Object.keys(namedConfigurations) as ConfigurationName[];
    if (options.interactive ?? Boolean(process.stdin.isTTY)) {
      return yield* Prompt.Select({
        message: "Keyservice configuration",
        choices: names.map((name) => ({ title: name, value: name })),
      });
    }
    const selected = yield* Config.String("KEYSERVICE_CONFIG").pipe(Config.option);
    const name = Option.getOrUndefined(selected);
    const match = names.find((candidate) => candidate === name);
    if (match) return match;
    return yield* Effect.fail(new ConfigurationError({
      message: `Set KEYSERVICE_CONFIG to one of: ${names.join(", ")}`,
    }));
  },
);

/** Start a named setup in the caller's scope; overrides also support hermetic examples tests. */
export const startConfiguredKeyService = Effect.fn("Example.startConfiguredKeyService")(
  function* (name: ConfigurationName, options: ServeOptions = {}) {
    const configuration = namedConfigurations[name];
    let interaction = options.interaction ?? (configuration.approval === "dialog"
      ? yield* Interaction.dialog()
      : yield* Interaction.terminal());
    if (configuration.remember) {
      interaction = yield* Interaction.remember(interaction, { ttl: "5 minutes" });
    }
    return yield* serve({
      listen: configuration.listen,
      remoteForwards: configuration.remoteForwards,
      ...options,
      interaction,
    });
  },
);

if (import.meta.main) {
  BunRuntime.runMain(Effect.gen(function* () {
    const name = yield* chooseConfiguration();
    yield* startConfiguredKeyService(name);
    yield* Effect.never;
  }).pipe(Effect.scoped, Effect.provide(BunServices.layer)));
}
