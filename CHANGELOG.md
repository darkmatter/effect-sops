# Changelog

## Unreleased

### Changed

- Updated the Effect and Alchemy dependencies to their stable-compatible
  versions. The Config constructors used in examples and tests now use the
  Effect 4 names (`Config.String`, `Config.Int`, and `Config.Redacted`).
- Alchemy's Cloudflare adapter is now an optional peer dependency so the
  application provides one shared adapter instance alongside Alchemy.


## 0.10.0 - 2026-10-06

### Changed

- Renamed the package from `alchemy-sops` to `effect-sops`, and the repository
  to `darkmatter/effect-sops`. Replace `alchemy-sops` with `effect-sops` in
  dependencies and import paths (`effect-sops/Config`, `effect-sops/edge`,
  and so on); the API is unchanged.

## 0.9.0 - 2026-09-22

### Added

- Added `runSopsKms`, a `SopsDecrypt` for documents whose master key is AWS
  KMS: the caller unwraps a `sops.kms[]` entry (`kms:Decrypt`) and `sops-age`
  decrypts the leaves with its new `dataKey` option, so Workers and Lambdas
  with only AWS credentials can read SOPS files. Exported from the root and
  `alchemy-sops/edge`.

### Changed

- The native backend now uses `@drkmttr/sops-age`, darkmatter's published
  fork of `sops-age` with the `dataKey` option and nullable `sops.age`
  (offered upstream as humphd/sops-age#22).

## 0.8.1 - 2026-08-20

### Changed

- Normalized SOPS command construction across `SopsFile`, `ConfigProvider`, and
  Cloudflare secret actions. Command defaults, source formats, SOPS age
  credentials, and redacted command options now resolve consistently.

## 0.8.0 - 2026-08-12

### Added

- Added `GitHubSopsSecrets`, which maps explicitly named SOPS selectors to
  repository or environment GitHub Actions secrets through Alchemy's
  `GitHub.Secret` resource.
- Added runnable examples for `SopsFile`, JSON-import typing, Schema decoding,
  ConfigProvider, Cloudflare Secrets Store, and GitHub Actions secrets. CI now
  smoke-tests all examples with native SOPS decryption and local provider mocks.

## 0.7.0 - 2026-08-09

### Added

- Added the Alchemy-free `alchemy-sops/Config` entrypoint, which exposes a SOPS
  document as an Effect `ConfigProvider`. Alchemy resolves provider credentials
  through `Config.redacted`/`Config.string`, so a deploy can authenticate from an
  encrypted document with nothing in the environment and no `sops exec-env`
  wrapper.
- Added `provideCredentials`, which supplies the provider to both a stack's
  `providers` and `state` layers. The state store initializes first and resolves
  credentials independently, so wiring only `providers` fails during state
  initialization.

```ts
import * as SopsConfig from "alchemy-sops/Config";

export default Alchemy.Stack(
  "MyApp",
  SopsConfig.provideCredentials(
    { path: "secrets.sops.json" },
    { providers: Cloudflare.providers(), state: Cloudflare.state() },
  ),
  body,
);
```

Decryption is lazy and memoized, and `layerAdd` registers the document behind
the environment, so an ambient credential still wins and the document is never
decrypted on that path. A path the document lacks is reported as absent rather
than as a failure, so `ConfigProvider.orElse` composition behaves normally.

### Changed

- Moved backend selection into `src/backend.ts` so the Alchemy-free entrypoints
  share the same `auto`/`cli`/`sops-age` resolution as `SopsFile`.

### Fixed

- Pinned the `effect` dev dependency to `4.0.0-beta.102`. `beta.105` removed
  `Schema.TaggedErrorClass`, which the `@distilled.cloud/core` bundled with
  `alchemy@2.0.0-beta.70` still calls, so the suite failed to load Alchemy at
  all. The peer range is unchanged, so this does not constrain consumers.
- Restored the typecheck against `@distilled.cloud/cloudflare@0.30.3`, which
  widened a secret's `status` to an open union and tightened `Output` variance.
  `CloudflareSopsSecretsOutput` now declares the same open union.

## 0.6.0 - 2026-08-07

### Added

- Added the Alchemy-free `alchemy-sops/Schema` entrypoint for decrypting imported
  SOPS JSON and decoding it with Effect Schema.
- Added `EncryptedFor<S>` so TypeScript checks encrypted document keys, nesting,
  optionality, and required SOPS metadata against the schema encoded type.
- Re-exported the Schema decoder from `alchemy-sops/edge`.

```ts
import * as Schema from "alchemy-sops/Schema";
import * as EffectSchema from "effect/Schema";
import encrypted from "./secrets.enc.json" with { type: "json" };

const AppSecrets = EffectSchema.Struct({
  token: EffectSchema.RedactedFromValue(EffectSchema.String),
});

const secrets = yield * Schema.decodeEffect(AppSecrets)(encrypted);
```

### Changed

- Made `alchemy` an optional peer so Effect applications can use the Schema and
  edge entrypoints without installing or resolving Alchemy.
- Kept `effect` as a required peer and removed unused Effect platform packages
  from runtime dependencies.
- Updated retry scheduling for the current Effect 4 Schedule API.
