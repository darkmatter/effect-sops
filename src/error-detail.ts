import { SopsDecryptError } from "./errors.js";

/**
 * Renders a one-line, secret-free detail for a failure so the reason is
 * visible in an error `message` (which is all `Cause.pretty`-style loggers
 * show) instead of being buried in `cause`/`stderr` fields.
 *
 * Only backend-produced text is surfaced: sops stderr and decrypt-backend
 * error messages, which never contain decrypted plaintext. Callers must not
 * pass parser/schema errors raised against decrypted content — those can
 * quote the input and stay generic by design. For any other `Error` only its
 * own `message` is used; arbitrary `cause` chains are not excavated, so a
 * deliberately generic wrapper cannot be un-gagged downstream.
 */
export const errorDetail = (cause: unknown): string => {
  if (cause === undefined || cause === null) return "";
  if (typeof cause === "string") return oneLine(cause);

  if (cause instanceof SopsDecryptError) {
    const parts = [oneLine(cause.message)];
    const stderr = cause.stderr ? oneLine(cause.stderr) : "";
    if (stderr && !parts[0]!.includes(stderr)) parts.push(stderr);
    if (isFallbackCause(cause.cause)) {
      const fallback = fallbackDetail(cause.cause);
      if (fallback && !parts.join(": ").includes(fallback)) parts.push(fallback);
    }
    return oneLine(parts.filter((part) => part.length > 0).join(": "));
  }

  if (isFallbackCause(cause)) return fallbackDetail(cause);
  if (cause instanceof Error) return oneLine(cause.message);
  return oneLine(String(cause));
};

/** `message` suffixed with `: <detail>` when the cause adds any detail. */
export const withErrorDetail = (message: string, cause: unknown): string => {
  const detail = errorDetail(cause);
  return detail && !message.includes(detail) ? oneLine(`${message}: ${detail}`) : oneLine(message);
};

interface FallbackCause {
  readonly nativeError: unknown;
  readonly cliError: unknown;
}

const isFallbackCause = (cause: unknown): cause is FallbackCause =>
  typeof cause === "object" &&
  cause !== null &&
  "nativeError" in cause &&
  "cliError" in cause;

const fallbackDetail = (cause: FallbackCause): string =>
  oneLine(
    `sops-age: ${errorDetail(cause.nativeError)}; sops CLI: ${errorDetail(cause.cliError)}`,
  );

const MAX_DETAIL_LENGTH = 500;

const oneLine = (text: string): string => {
  // Backend errors can echo a malformed age identity back at the caller
  // (e.g. checksum errors quote the full key); never let key material
  // ride along into a log-facing message.
  const collapsed = text
    .replace(/\s+/g, " ")
    .trim()
    .replace(/AGE-SECRET-KEY-[A-Z0-9]+/gi, "AGE-SECRET-KEY-<redacted>");
  return collapsed.length > MAX_DETAIL_LENGTH
    ? `${collapsed.slice(0, MAX_DETAIL_LENGTH - 3)}...`
    : collapsed;
};
