import type { SopsKeyServiceOptions } from "./keyservice-options.js";
import type { SopsDocumentFormat } from "./document.js";
import { type MaybeRedactedString, revealString } from "./input.js";
import type { SopsCliFormat, SopsCommandRequest } from "./sops.js";

type SopsCommandSource = Pick<
  SopsCommandRequest,
  "path" | "content" | "url"
>;

interface SopsCommandOptions extends SopsKeyServiceOptions {
  readonly cwd?: MaybeRedactedString;
  readonly format?: SopsDocumentFormat;
  readonly inputType?: SopsCliFormat;
  readonly outputType?: SopsCliFormat;
  readonly sopsBinary?: MaybeRedactedString;
  readonly sopsArgs?: readonly MaybeRedactedString[];
  readonly extract?: MaybeRedactedString;
  readonly env?: Record<string, MaybeRedactedString>;
  readonly ageKey?: MaybeRedactedString;
  readonly ageKeyFile?: MaybeRedactedString;
  readonly timeoutMs?: number;
}

export const buildSopsCommandRequest = ({
  source,
  options,
  inferInputType = false,
}: {
  readonly source: SopsCommandSource;
  readonly options: SopsCommandOptions;
  readonly inferInputType?: boolean;
}): SopsCommandRequest => {
  const format = options.format ?? "auto";
  const inputType =
    options.inputType ??
    (inferInputType ? explicitCliFormat(format) : undefined);
  const outputType =
    options.outputType ??
    (format === "auto" ? "json" : explicitCliFormat(format));
  const env = sopsCommandEnv(options);

  return {
    ...(source.path !== undefined ? { path: source.path } : {}),
    ...(source.content !== undefined ? { content: source.content } : {}),
    ...(source.url !== undefined ? { url: source.url } : {}),
    binary: revealString(options.sopsBinary ?? "sops"),
    ...(inputType !== undefined ? { inputType } : {}),
    ...(outputType !== undefined ? { outputType } : {}),
    ...(options.cwd !== undefined ? { cwd: revealString(options.cwd) } : {}),
    ...(options.extract !== undefined
      ? { extract: revealString(options.extract) }
      : {}),
    ...(options.sopsArgs !== undefined
      ? { args: options.sopsArgs.map(revealString) }
      : {}),
    ...(options.env !== undefined ||
    options.ageKey !== undefined ||
    options.ageKeyFile !== undefined
      ? { env }
      : {}),
    ...(options.keyServices !== undefined ? { keyServices: options.keyServices } : {}),
    ...(options.enableLocalKeyService !== undefined ? { enableLocalKeyService: options.enableLocalKeyService } : {}),
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
  };
};

const explicitCliFormat = (
  format: SopsDocumentFormat,
): SopsCliFormat | undefined =>
  format === "auto" || format === "text" ? undefined : format;

const sopsCommandEnv = (
  options: SopsCommandOptions,
): Record<string, MaybeRedactedString> => {
  const env: Record<string, MaybeRedactedString> = { ...(options.env ?? {}) };

  if (options.ageKey !== undefined) env.SOPS_AGE_KEY = options.ageKey;
  if (options.ageKeyFile !== undefined) {
    env.SOPS_AGE_KEY_FILE = options.ageKeyFile;
  }

  return env;
};
