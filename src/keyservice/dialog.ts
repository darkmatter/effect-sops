import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";
import * as Schema from "effect/Schema";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import {
  KeyServiceInteractionError,
  sanitizeForDisplay,
  type KeyServiceInteraction,
  type PluginPromptContext,
} from "./model.js";

/** Configure native macOS approval and age plugin dialogs. */
export interface DialogOptions {
  /** Window title. Default "SOPS keyservice". */
  readonly title?: string;
  /** Approval timeout. Default 60 seconds. */
  readonly timeout?: Duration.Input;
  /** Value prompt timeout. Default 120 seconds. */
  readonly valueTimeout?: Duration.Input;
  /** Executable on PATH, or an absolute path. Default "osascript". */
  readonly osascript?: string;
  /** Display plugin notifications. Default true; false logs instead. */
  readonly notifications?: boolean;
}

// Only JSON argv contains caller text; the executable script is constant.
const script = `function run(argv) {
  const input = JSON.parse(argv[0]);
  const app = Application.currentApplication();
  app.includeStandardAdditions = true;
  try {
    if (input.kind === "notification") {
      app.displayNotification(input.message, {
        withTitle: input.title, subtitle: input.subtitle
      });
      return JSON.stringify({ notified: true });
    }
    app.activate();
    const options = {
      withTitle: input.title,
      buttons: input.buttons,
      cancelButton: input.cancelButton,
      givingUpAfter: input.timeoutSeconds
    };
    if (input.defaultButton !== undefined) options.defaultButton = input.defaultButton;
    if (input.icon !== undefined) options.withIcon = input.icon;
    if (input.kind === "value") {
      options.defaultAnswer = input.defaultAnswer;
      options.hiddenAnswer = input.hidden;
    }
    const result = app.displayDialog(input.message, options);
    return JSON.stringify({
      button: result.buttonReturned,
      gaveUp: result.gaveUp === true,
      text: result.textReturned
    });
  } catch (error) {
    return JSON.stringify(error.errorNumber === -128
      ? { cancelled: true } : { failed: true });
  }
}`;

const resultSchema = Schema.fromJsonString(
  Schema.Struct({
    button: Schema.optionalKey(Schema.String),
    gaveUp: Schema.optionalKey(Schema.Boolean),
    text: Schema.optionalKey(Schema.String),
    cancelled: Schema.optionalKey(Schema.Boolean),
    notified: Schema.optionalKey(Schema.Boolean),
  }),
);

interface DialogInput {
  readonly kind: "approve" | "value" | "confirm" | "notification";
  readonly message: string;
  readonly title: string;
  readonly buttons?: ReadonlyArray<string>;
  readonly timeoutSeconds?: number;
  readonly hidden?: boolean;
  readonly defaultAnswer?: string;
  readonly defaultButton?: string;
  readonly cancelButton?: string;
  readonly icon?: "caution";
  readonly subtitle?: string;
}

const failed = () =>
  new KeyServiceInteractionError({
    reason: "Failed",
    message: "The macOS dialog could not complete",
  });

const timeoutSeconds = (duration: Duration.Input): number => {
  const seconds = Duration.toSeconds(duration);
  if (!Number.isFinite(seconds) || seconds <= 0)
    throw new Error("Dialog timeout must be positive and finite");
  return Math.ceil(seconds);
};

/** Capture the spawner and create scoped macOS approval and plugin dialogs. */
export const dialog: (
  options?: DialogOptions,
) => Effect.Effect<KeyServiceInteraction, never, ChildProcessSpawner> = Effect.fn(
  "KeyServiceInteraction.dialog",
)(function* (options = {}) {
  const spawner = yield* ChildProcessSpawner;
  const title = sanitizeForDisplay(options.title ?? "SOPS keyservice");
  const executable = options.osascript ?? "osascript";
  const pluginTitle = (context: PluginPromptContext) =>
    `${title} — age-plugin-${sanitizeForDisplay(context.plugin, 80)}`;

  const run = Effect.fn("KeyServiceInteraction.dialog.run")(
    function* (input: DialogInput) {
      if (process.platform !== "darwin" && executable === "osascript")
        return yield* Effect.fail(
          new KeyServiceInteractionError({
            reason: "Unavailable",
            message: "macOS dialogs require osascript on macOS",
          }),
        );
      const child = yield* spawner
        .spawn(
          ChildProcess.make(
            executable,
            ["-l", "JavaScript", "-e", script, "--", JSON.stringify(input)],
            {
              stdin: "ignore",
              stdout: "pipe",
              // Neither diagnostics nor parser errors may expose a returned PIN.
              stderr: "ignore",
              forceKillAfter: "1 second",
            },
          ),
        )
        .pipe(
          Effect.mapError((error) =>
            error.reason._tag === "NotFound"
              ? new KeyServiceInteractionError({
                  reason: "Unavailable",
                  message: "The osascript executable is unavailable",
                })
              : failed(),
          ),
        );
      const output = yield* Stream.mkString(Stream.decodeText(child.stdout)).pipe(
        Effect.mapError(failed),
      );
      const exitCode = yield* child.exitCode.pipe(Effect.mapError(failed));
      if (exitCode !== 0) return yield* Effect.fail(failed());
      const result = yield* Schema.decodeUnknownEffect(resultSchema)(output).pipe(
        Effect.mapError(failed),
      );
      if (
        result.cancelled !== true &&
        result.gaveUp !== true &&
        (input.kind === "notification"
          ? result.notified !== true
          : result.button === undefined ||
            !input.buttons?.includes(result.button))
      )
        return yield* Effect.fail(failed());
      return result;
    },
    Effect.scoped,
  );

  const notify = Effect.fn("KeyServiceInteraction.dialog.notify")(function* (
    context: PluginPromptContext,
    message: string,
  ) {
    const subtitle = `age-plugin-${sanitizeForDisplay(context.plugin, 80)}`;
    const safeMessage = sanitizeForDisplay(message, 400);
    if (options.notifications === false) {
      yield* Effect.logInfo(`[${subtitle}] ${safeMessage}`);
      return;
    }
    yield* run({ kind: "notification", title, subtitle, message: safeMessage });
  });

  return {
    approve: Effect.fn("KeyServiceInteraction.dialog.approve")(function* (
      request,
    ) {
      const seconds = yield* Effect.try({
        try: () => timeoutSeconds(options.timeout ?? "60 seconds"),
        catch: failed,
      });
      const peer = sanitizeForDisplay(request.peerHost ?? request.peer, 80);
      const result = yield* run({
        kind: "approve",
        title,
        message: `${request.operation === "decrypt" ? "Decryption" : "Encryption"} request from ${peer}\n\n${request.keyDescription}\n\nAccept or decline this request.`,
        buttons: ["Decline", "Accept"],
        cancelButton: "Decline",
        timeoutSeconds: seconds,
        icon: "caution",
      });
      if (result.gaveUp)
        yield* Effect.logInfo("Keyservice approval dialog timed out");
      return !result.cancelled && !result.gaveUp && result.button === "Accept";
    }),
    requestValue: Effect.fn("KeyServiceInteraction.dialog.requestValue")(function* (
      context,
      prompt,
      secret,
    ) {
      const seconds = yield* Effect.try({
        try: () => timeoutSeconds(options.valueTimeout ?? "120 seconds"),
        catch: failed,
      });
      const result = yield* run({
        kind: "value",
        title: pluginTitle(context),
        message: sanitizeForDisplay(prompt, 400),
        hidden: secret,
        defaultAnswer: "",
        buttons: ["Cancel", "OK"],
        defaultButton: "OK",
        cancelButton: "Cancel",
        timeoutSeconds: seconds,
      });
      if (result.gaveUp)
        return yield* Effect.fail(
          new KeyServiceInteractionError({
            reason: "TimedOut",
            message: "The value dialog timed out",
          }),
        );
      if (result.cancelled || result.button === "Cancel")
        return yield* Effect.fail(
          new KeyServiceInteractionError({
            reason: "Cancelled",
            message: "The value dialog was cancelled",
          }),
        );
      if (result.text === undefined) return yield* Effect.fail(failed());
      return Redacted.make(result.text);
    }),
    confirm: Effect.fn("KeyServiceInteraction.dialog.confirm")(function* (
      context,
      prompt,
      yes,
      no,
    ) {
      const seconds = yield* Effect.try({
        try: () => timeoutSeconds(options.timeout ?? "60 seconds"),
        catch: failed,
      });
      const yesLabel = sanitizeForDisplay(yes);
      const noLabel = sanitizeForDisplay(no ?? "Cancel");
      if (yesLabel === noLabel) return yield* Effect.fail(failed());
      const result = yield* run({
        kind: "confirm",
        title: pluginTitle(context),
        message: sanitizeForDisplay(prompt, 400),
        buttons: [noLabel, yesLabel],
        defaultButton: yesLabel,
        cancelButton: noLabel,
        timeoutSeconds: seconds,
      });
      return !result.cancelled && !result.gaveUp && result.button === yesLabel;
    }),
    displayMessage: notify,
    waiting: (context) =>
      notify(
        context,
        "waiting for the plugin (touch your security key if it is blinking)",
      ).pipe(
        Effect.catch(() =>
          Effect.logWarning("Keyservice notification unavailable"),
        ),
      ),
  } satisfies KeyServiceInteraction;
});
