import * as Redacted from "effect/Redacted";
import type { SopsCommandRequest } from "./decrypt.js";

export interface SopsKeyServiceOptions {
  /** Ordered SOPS keyservice URIs. Overrides SOPS_KEYSERVICE, including with []. */
  readonly keyServices?: readonly string[];
  /** Try local age identities before remote services. Defaults to true. */
  readonly enableLocalKeyService?: boolean;
}

/** Read at the boundary, independent of a possibly SOPS-backed ConfigProvider. */
export const keyServiceSettings = (request: SopsCommandRequest) => {
  const ambient = typeof process === "undefined" ? {} : process.env;
  const read = (name: string) => {
    const value = request.env?.[name] ?? ambient[name];
    return Redacted.isRedacted(value) ? Redacted.value(value) : value;
  };
  return {
    keyServices:
      request.keyServices ??
      (read("SOPS_KEYSERVICE") ?? "")
        .split(",")
        .map((uri) => uri.trim())
        .filter(Boolean),
    enableLocalKeyService:
      request.enableLocalKeyService ??
      read("SOPS_ENABLE_LOCAL_KEYSERVICE") ??
      true,
  };
};

export const usesKeyServices = (request: SopsCommandRequest): boolean => {
  const settings = keyServiceSettings(request);
  return (
    settings.keyServices.length > 0 ||
    (settings.enableLocalKeyService !== true &&
      settings.enableLocalKeyService !== "true")
  );
};
