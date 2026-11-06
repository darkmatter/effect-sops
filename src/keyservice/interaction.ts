import * as Cause from "effect/Cause";
import * as Clock from "effect/Clock";
import * as Duration from "effect/Duration";
import * as Effect from "effect/Effect";
import * as Equal from "effect/Equal";
import * as Option from "effect/Option";
import * as Predicate from "effect/Predicate";
import * as Queue from "effect/Queue";
import * as Redacted from "effect/Redacted";
import * as Ref from "effect/Ref";
import * as Terminal from "effect/Terminal";
import {
  describeRequest,
  KeyServiceInteractionError,
  sanitizeForDisplay,
  type KeyServiceInteraction,
  type KeyServiceRequest,
  type PluginPromptContext,
} from "./model.js";

export { dialog, type DialogOptions } from "./dialog.js";

const unavailable = new KeyServiceInteractionError({
  reason: "Unavailable",
  message:
    "start the keyservice with prompt or dialog to answer age plugin prompts",
});

const pluginLabel = (context: PluginPromptContext): string =>
  `[age-plugin-${sanitizeForDisplay(context.plugin)}]`;

const waitingMessage = (context: PluginPromptContext): string =>
  `${pluginLabel(context)} waiting for the plugin (touch your security key if it is blinking)\n`;

/** Approve requests without prompting; plugin follow-ups require an interactive implementation. */
export const none: KeyServiceInteraction = {
  approve: () => Effect.succeed(true),
  displayMessage: (context, message) =>
    Effect.log(`${pluginLabel(context)} ${sanitizeForDisplay(message, 400)}`),
  requestValue: () => Effect.fail(unavailable),
  confirm: () => Effect.fail(unavailable),
  waiting: (context) => Effect.log(waitingMessage(context)),
};

type HandlerResult<A> = A | Promise<A> | Effect.Effect<A, unknown>;

/** Custom callbacks are lazy, may be asynchronous, and need no platform services. */
export interface InteractionHandlers {
  readonly approve?: (request: KeyServiceRequest) => HandlerResult<boolean>;
  readonly displayMessage?: (
    context: PluginPromptContext,
    message: string,
  ) => HandlerResult<void>;
  readonly requestValue?: (
    context: PluginPromptContext,
    prompt: string,
    secret: boolean,
  ) => HandlerResult<string | Redacted.Redacted<string>>;
  readonly confirm?: (
    context: PluginPromptContext,
    prompt: string,
    yes: string,
    no: string | undefined,
  ) => HandlerResult<boolean>;
  readonly waiting?: (context: PluginPromptContext) => HandlerResult<void>;
}

const invoke = <A>(
  handler: () => HandlerResult<A>,
): Effect.Effect<A, KeyServiceInteractionError> =>
  Effect.suspend(() => {
    const value = handler();
    if (Effect.isEffect(value)) return value;
    return Predicate.isPromise(value)
      ? Effect.tryPromise({ try: () => value, catch: () => undefined })
      : Effect.succeed(value);
  }).pipe(
    Effect.catchCause((cause) =>
      Cause.hasInterrupts(cause)
        ? Effect.interrupt
        : Effect.fail(
            new KeyServiceInteractionError({
              reason: "Failed",
              message: "Interaction handler failed",
            }),
          ),
    ),
  );

const bestEffort = <E>(effect: Effect.Effect<void, E>): Effect.Effect<void> =>
  Effect.catchCause(effect, (cause) =>
    Cause.hasInterrupts(cause) ? Effect.interrupt : Effect.void,
  );

/** Adapt plain, Promise, and Effect callbacks; omitted callbacks use {@link none}. */
export const make = ({
  approve,
  displayMessage,
  requestValue,
  confirm,
  waiting,
}: InteractionHandlers): KeyServiceInteraction => ({
  approve: approve ? (request) => invoke(() => approve(request)) : none.approve,
  displayMessage: displayMessage
    ? (context, message) => invoke(() => displayMessage(context, message))
    : none.displayMessage,
  requestValue: requestValue
    ? (context, prompt, secret) =>
        invoke(() => requestValue(context, prompt, secret)).pipe(
          Effect.map((value) =>
            typeof value === "string" ? Redacted.make(value) : value,
          ),
        )
    : none.requestValue,
  confirm: confirm
    ? (context, prompt, yes, no) =>
        invoke(() => confirm(context, prompt, yes, no))
    : none.confirm,
  waiting: waiting
    ? (context) => bestEffort(invoke(() => waiting(context)))
    : none.waiting,
});

/** One approved request and its validity window, measured by the Effect clock. */
export interface ApprovalGrant {
  readonly request: KeyServiceRequest;
  readonly grantedAt: number;
  readonly expiresAt: number;
}

/** Reuse an unexpired approval only for the same operation, peer host, and complete key. */
export const approvalCovers = (
  grant: ApprovalGrant,
  request: KeyServiceRequest,
  now: number,
): boolean =>
  now < grant.expiresAt &&
  grant.request.operation === request.operation &&
  grant.request.peerHost === request.peerHost &&
  Equal.equals(grant.request.key, request.key);

/** Cache approvals for a limited time; denials and plugin follow-ups are never cached. */
export const remember: (
  base: KeyServiceInteraction,
  options: {
    readonly ttl: Duration.Input;
    readonly covers?: (
      grant: ApprovalGrant,
      request: KeyServiceRequest,
      now: number,
    ) => boolean;
  },
) => Effect.Effect<KeyServiceInteraction> = Effect.fn(
  "KeyServiceInteraction.remember",
)(function* (base, options) {
  const grants = yield* Ref.make<ReadonlyArray<ApprovalGrant>>([]);
  const clock = yield* Clock.Clock;
  const now = Clock.currentTimeMillis.pipe(
    Effect.provideService(Clock.Clock, clock),
  );
  const ttl = Duration.toMillis(options.ttl);
  const covers = options.covers ?? approvalCovers;
  return {
    ...base,
    approve: Effect.fn("KeyServiceInteraction.remember.approve")(
      function* (request) {
        const checkedAt = yield* now;
        const current = yield* Ref.updateAndGet(grants, (saved) =>
          saved.filter((grant) => checkedAt < grant.expiresAt),
        );
        if (current.some((grant) => covers(grant, request, checkedAt)))
          return true;
        if (!(yield* base.approve(request))) return false;
        const grantedAt = yield* now;
        yield* Ref.update(grants, (saved) => [
          ...saved.filter((grant) => grantedAt < grant.expiresAt),
          { request, grantedAt, expiresAt: grantedAt + ttl },
        ]);
        return true;
      },
    ),
  };
});

/** Terminal prompts currently require no configuration beyond the supplied Terminal service. */
export type TerminalOptions = Readonly<Record<string, never>>;

/** Construct terminal approval and plugin prompts, capturing the provided terminal service. */
export const terminal: (
  options?: TerminalOptions,
) => Effect.Effect<KeyServiceInteraction, never, Terminal.Terminal> = Effect.fn(
  "KeyServiceInteraction.terminal",
)(function* (_options = {}) {
  const terminal = yield* Terminal.Terminal;
  const sanitize = (text: string) => sanitizeForDisplay(text, 400);
  const cancelled = new KeyServiceInteractionError({
    reason: "Cancelled",
    message: "Terminal prompt cancelled",
  });
  const display = (text: string) =>
    terminal
      .display(text)
      .pipe(
        Effect.mapError(
          () =>
            new KeyServiceInteractionError({
              reason: "Failed",
              message: "Could not display terminal prompt",
            }),
        ),
      );
  const readLine = terminal.readLine.pipe(Effect.mapError(() => cancelled));
  const choose = Effect.fn("KeyServiceInteraction.terminal.choose")(function* (
    prompt: string,
    yes: string,
    no?: string,
  ) {
    while (true) {
      yield* display(prompt);
      const answer = (yield* readLine).trim().toLowerCase();
      if (answer === yes.toLowerCase() || answer === "y" || answer === "yes")
        return true;
      if (
        (no !== undefined && answer === no.toLowerCase()) ||
        answer === "n" ||
        answer === "no"
      )
        return false;
    }
  });
  const readSecret = Effect.gen(function* () {
    const input = yield* terminal.readInput;
    const characters: Array<string> = [];
    while (true) {
      const event = yield* Queue.take(input).pipe(
        Effect.mapError(() => cancelled),
      );
      if (
        (event.key.ctrl &&
          (event.key.name === "c" || event.key.name === "d")) ||
        event.key.name === "escape"
      ) {
        return yield* Effect.fail(cancelled);
      }
      if (event.key.name === "return" || event.key.name === "enter") {
        yield* display("\n");
        return Redacted.make(characters.join(""));
      }
      if (event.key.name === "backspace") characters.pop();
      else if (
        !event.key.ctrl &&
        !event.key.meta &&
        Option.isSome(event.input)
      ) {
        characters.push(
          ...event.input.value.replace(/[\u0000-\u001f\u007f-\u009f]/g, ""),
        );
      }
    }
  }).pipe(Effect.scoped);
  return {
    approve: (request) =>
      choose(
        `\nReceived ${describeRequest(request)}. Respond to request? (y/n): `,
        "y",
        "n",
      ),
    displayMessage: (context, message) =>
      display(`${pluginLabel(context)} ${sanitize(message)}\n`),
    requestValue: Effect.fn("KeyServiceInteraction.terminal.requestValue")(
      function* (context, prompt, secret) {
        yield* display(`${pluginLabel(context)} ${sanitize(prompt)} `);
        return secret ? yield* readSecret : Redacted.make(yield* readLine);
      },
    ),
    confirm: (_context, prompt, yes, no) => {
      const yesLabel = sanitize(yes);
      const noLabel = no === undefined ? undefined : sanitize(no);
      return choose(
        `${sanitize(prompt)} [${yesLabel}${noLabel === undefined ? "" : `/${noLabel}`}] `,
        yesLabel,
        noLabel,
      );
    },
    waiting: (context) => bestEffort(display(waitingMessage(context))),
  };
});
