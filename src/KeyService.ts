/**
 * Native SOPS gRPC keyservice serving age keys, with terminal or macOS approval,
 * Tailscale listeners, and SSH forwards. The Effect API owns resources through
 * Scope; the Promise API exposes closeable handles and SOPS-compatible options.
 * Like `sops keyservice`, the default listener is TCP 127.0.0.1:5000 and requests
 * are approved automatically unless an interaction is configured.
 */
export * as Listen from "./keyservice/listen.js";
export * as Ssh from "./keyservice/ssh.js";
export * as Interaction from "./keyservice/interaction.js";
export * as Protocol from "./keyservice/protocol.js";
export { serve, connect, type ServeOptions, type RunningKeyService } from "./keyservice/serve.js";
export { makeServer } from "./keyservice/server.js";
export { ageKeyHandler, loadAgeIdentities, type AgeIdentities } from "./keyservice/age.js";
export * from "./keyservice/promise.js";
export * from "./keyservice/model.js";
export * from "./keyservice/address.js";
export type { InteractionHandlers } from "./keyservice/interaction.js";
export type { DialogOptions } from "./keyservice/dialog.js";
