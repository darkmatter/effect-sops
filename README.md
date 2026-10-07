# effect-sops

Effect-native SOPS decoding and optional Alchemy resources with redacted
secret outputs.

`effect-sops` decrypts SOPS files with a native `sops-age` backend (via `@drkmttr/sops-age`, our fork with KMS data-key support). It keeps
decrypted scalar values redacted while they move through Effect and Alchemy.
The `sops` CLI backend remains available for binary files, custom SOPS flags,
and non-age backends.

## Contents

- [Install](#install)
- [Changelog](./CHANGELOG.md)
- [Choose a lifecycle](#choose-a-lifecycle)
- [Inside an Alchemy stack](#inside-an-alchemy-stack)
  - [Read a SOPS document](#read-a-sops-document)
  - [Type a JSON import](#type-a-json-import)
- [Without an Alchemy stack](#without-an-alchemy-stack)
  - [Decode an imported JSON document](#decode-an-imported-json-document)
  - [Edge usage](#edge-usage)
- [Before an Alchemy stack](#before-an-alchemy-stack)
- [At a deployment target](#at-a-deployment-target)
  - [Cloudflare Secrets Store](#cloudflare-secrets-store)
  - [GitHub Actions secrets](#github-actions-secrets)
- [Examples](./examples/README.md)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Security note](#security-note)
- [Troubleshooting](#troubleshooting)

## Install

```sh
bun add effect-sops effect
```

`effect` is a required peer. `alchemy` is optional and is only needed when you
import the package root for `SopsFile` or the Cloudflare Secrets Store API:

```sh
bun add alchemy
```

The native backend does not require a `sops` binary. Install `sops` only when
you need `backend: "cli"` or automatic fallback for SOPS features not supported
by `sops-age`. See [CHANGELOG.md](./CHANGELOG.md) for release notes.

## Choose a lifecycle

There is one SOPS document pipeline—decrypt, parse, select, and redact. Choose
the integration by **when the decrypted value is needed**, not by its source
format or TypeScript typing technique:

| When the value is needed | Start with | What varies within this route |
| --- | --- | --- |
| Inside an Alchemy stack | [`SopsFile`](#read-a-sops-document) | `path`, `content`, `url`, or JSON import; schema or inferred typing |
| Before the stack initializes | [`effect-sops/Config`](#before-an-alchemy-stack) | Config lookup shape and credential mapping |
| At a deployment target | [Cloudflare](#cloudflare-secrets-store) or [GitHub](#github-actions-secrets) import | Target provider and target-secret names |

If you are not using Alchemy at all, use the focused
[Effect Schema decoder](#decode-an-imported-json-document) or the
[low-level edge entry point](#edge-usage). Those are runtime choices, not extra
ways to configure an Alchemy stack.

See the runnable [examples](./examples/README.md), organized using the same
lifecycle model.

## Inside an Alchemy stack

### Read a SOPS document

```ts
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import { SopsFile, SopsFileProvider } from "effect-sops";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Schema from "effect/Schema";

const AppSecrets = Schema.Struct({
  database: Schema.Struct({
    url: Schema.RedactedFromValue(Schema.String),
  }),
  api: Schema.Struct({
    token: Schema.RedactedFromValue(Schema.String),
  }),
});

export default Alchemy.Stack(
  "App",
  {
    providers: SopsFileProvider({ memoize: true }),
    state: Alchemy.localState(),
  },
  Effect.gen(function* () {
    const secrets = yield* SopsFile("Secrets", {
      path: "./secrets.enc.yaml",
      format: "yaml",
      ageKey: Config.Redacted("SOPS_AGE_KEY"),
      schema: AppSecrets,
    });

    return {
      sourceHash: secrets.sourceHash,
      topLevelKeys: secrets.topLevelKeys,
      databaseUrl: Output.map(secrets.value, (s) => s.database.url),
    };
  }),
);
```

For local files, `backend: "auto"` is the default. It tries `sops-age` first for
structured age-encrypted files, then falls back to the CLI when a local `path`
source is available. Use `backend: "sops-age"` to require the native backend or
`backend: "cli"` to force the binary.

`path` can also be an ordered array of local SOPS files. Each file is decrypted
independently and object documents are deep-merged in order, so later files
override earlier ones. This is useful for `common.sops.json` plus stage-specific
overrides without materializing plaintext between files.

`SopsFileProvider({ memoize: true })` memoizes decrypt calls in the current
process. This is useful when multiple lazy resource paths request the same
encrypted source during one deploy. It does not replace resource `cache`; `cache`
controls persisted Alchemy output reuse across deploys.

Successful decrypts log the top-level keys without logging values. Pass a
service-free `Schema.Struct` from `effect/Schema` as `schema` to validate the
decrypted document and return a typed `secrets.value` output. Use
`Schema.RedactedFromValue(...)` for fields that should remain redacted in the
typed output.

The older `secrets` selector map is still supported when you need a flat
dot-path selection, and `types: true` or `types: { exportName: "AppSecrets" }`
still returns generated TypeScript definitions in `secrets.types`; no files are
written.

### Type a JSON import

TypeScript types JSON imports natively. Pass the imported encrypted SOPS
document as `json`, and that inferred type flows through to `secrets.data` —
with no `schema` and no `secrets` keys to declare:

```ts
import * as Alchemy from "alchemy";
import * as Output from "alchemy/Output";
import { SopsFile, SopsFileProvider } from "effect-sops";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import encrypted from "./secrets.enc.json" with { type: "json" };

export default Alchemy.Stack(
  "App",
  {
    providers: SopsFileProvider(),
    state: Alchemy.localState(),
  },
  Effect.gen(function* () {
    const secrets = yield* SopsFile("Secrets", {
      json: encrypted,
      ageKey: Config.Redacted("SOPS_AGE_KEY"),
    });

    // secrets.data is fully typed from the import: scalar leaves are
    // Redacted<string> and the top-level `sops` metadata key is removed.
    return {
      databaseUrl: Output.map(secrets.data, (data) => data.database.url),
    };
  }),
);
```

The encrypted SOPS JSON keeps its plaintext key structure, so importing it
gives TypeScript the document shape for free. At runtime the object is
re-serialized and decrypted as inline `content`; values and key order are
preserved, so the SOPS MAC still verifies. Every scalar leaf is mapped to
`Redacted<string>` via the exported `SopsRedactedDocument<T>` type, matching
the redacted `data` output. Reach for `schema` instead when you also want
runtime validation or non-redacted leaf types.

## Without an Alchemy stack

### Decode an imported JSON document

Use `effect-sops/Schema` to decrypt an imported SOPS JSON document and decode
it with an Effect 4 `Schema.Struct` without configuring an Alchemy Stack. The
curried API defines the schema once, then decodes each encrypted import with
`Schema.decodeEffect(AppSecrets)(encrypted)`:

```ts
import * as Schema from "effect-sops/Schema";
import * as Effect from "effect/Effect";
import * as EffectSchema from "effect/Schema";
import encrypted from "./secrets.enc.json" with { type: "json" };

const AppSecrets = EffectSchema.Struct({
  database: EffectSchema.Struct({
    url: EffectSchema.RedactedFromValue(EffectSchema.String),
  }),
  api: EffectSchema.Struct({
    token: EffectSchema.RedactedFromValue(EffectSchema.String),
  }),
});

const loadSecrets = Effect.gen(function* () {
  return yield* Schema.decodeEffect(AppSecrets)(encrypted);
});
```

This subpath and `effect-sops/edge` are Alchemy-free. The package root remains
the Alchemy resource API and therefore requires the optional `alchemy` peer at
runtime.

At compile time, `EncryptedFor<S>` derives required keys, nesting, and property
optionality from `Schema.Codec.Encoded<S>`. TypeScript checks that structure
against the inferred JSON import shape and requires the top-level `sops`
metadata object. Encrypted scalar leaves accept JSON scalar values, so
TypeScript cannot prove that a ciphertext decrypts to the expected plaintext
value or satisfies a refinement.

At runtime, `decodeEffect` serializes the imported document, decrypts it with the
native `sops-age` backend, then decodes the decrypted JSON with
`Schema.decodeUnknownEffect` through `Schema.fromJsonString`. Missing required
fields, invalid decoded types, failed transformations, and failed refinements
produce a `Schema.SchemaError` in the Effect error channel. Decryption failures
produce `SopsDecryptError`.

Pass Effect parse options when stricter document validation is required:

```ts
const loadStrictSecrets = Effect.gen(function* () {
  return yield* Schema.decodeEffect(AppSecrets, {
    errors: "all",
    onExcessProperty: "error",
  })(encrypted);
});
```

Identity discovery follows `sops-age` defaults. To supply an age identity
explicitly, keep it redacted and load the real value from secret configuration:

```ts
import * as Redacted from "effect/Redacted";

const ageKey = Redacted.make("<age-secret-key>");

const loadWithKey = Effect.gen(function* () {
  return yield* Schema.decodeEffect(AppSecrets)(encrypted, { ageKey });
});
```

Treat the decoded object as secret material. Never log it or reveal decoded
`Redacted` values for inspection; reveal them only at the provider boundary
that must consume the plaintext.

This API intentionally accepts imported JSON only so the encrypted document
shape remains available to TypeScript. Use `SopsFile` or the low-level edge APIs
for path, URL, extract, and ordered merge workflows; those sources cannot carry
a static JSON import shape.

### Edge usage

Alchemy programs can avoid local filesystem and process APIs by using inline
encrypted content or a URL source with the native backend:

```ts
import { SopsFile } from "effect-sops";

const secrets =
  yield *
  SopsFile("WorkerSecrets", {
    content: encryptedSopsJson,
    format: "json",
    backend: "sops-age",
    ageKey: workerEnv.SOPS_AGE_KEY,
  });
```

The Alchemy resource entrypoint still imports Alchemy. For code that is bundled
directly into an edge runtime, use the low-level `effect-sops/edge` subpath:

```ts
import { runSopsAge } from "effect-sops/edge";
```

### KMS-encrypted documents (no age key, no `sops` binary)

For a runtime that holds AWS credentials but nothing else — a Cloudflare Worker
assuming an IAM role through OIDC, a Lambda, an ECS task — `runSopsKms` is a
`SopsDecrypt` whose master key is AWS KMS. You supply the one AWS call it
needs: unwrap a `sops.kms[]` entry with `kms:Decrypt`.

```ts
import * as Effect from "effect/Effect";
import { runSopsKms } from "effect-sops/edge";

const decrypt = runSopsKms({
  // entry = { arn, enc, ... } from the document's sops.kms[] list.
  unwrapDataKey: (entry) => kmsDecrypt({ keyId: entry.arn, ciphertext: fromBase64(entry.enc) }),
  // optional: only try the key this role can use
  keyArn: "arn:aws:kms:us-west-2:123456789012:key/…",
});

const json = yield* decrypt({ content: encryptedJson, binary: "sops", inputType: "json", outputType: "json" });
```

The `decrypt` from `runSopsKms` plugs into anything that accepts `decrypt`, so `SopsFile` and
`effect-sops/Config` work unchanged with a KMS-only document.

Leaf decryption is `sops-age`'s own (its `dataKey` option), so the two native
backends share one implementation; like the `sops-age` backend, the
document-level `sops.mac` is not verified. JSON and YAML only; the document
must be passed as `content`.

## Before an Alchemy stack

`SopsFile` decrypts secrets _inside_ a stack, which is too late for the
credentials the stack itself needs to authenticate. `effect-sops/Config` covers
that earlier moment: it turns a SOPS document into an Effect `ConfigProvider`,
and because Alchemy resolves provider credentials through `Config.Redacted` /
`Config.String` rather than reading `process.env` directly, a deploy can
authenticate with nothing in the environment — no `sops exec-env` wrapper and no
exported variables.

```ts
import * as SopsConfig from "effect-sops/Config";
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";

export default Alchemy.Stack(
  "MyApp",
  SopsConfig.provideCredentials(
    {
      path: "secrets.sops.json",
      secrets: {
        CLOUDFLARE_API_TOKEN: "secrets.CLOUDFLARE_API_TOKEN",
        CLOUDFLARE_ACCOUNT_ID: "secrets.CLOUDFLARE_ACCOUNT_ID",
      },
    },
    { providers: Cloudflare.providers(), state: Cloudflare.state() },
  ),
  body,
);
```

Use `provideCredentials` rather than wiring the layer yourself: a stack's state
store initializes _before_ its providers and resolves credentials
independently, so supplying the layer to only `providers` fails during state
initialization with a missing-credential error that points nowhere near the
cause.

The `secrets` map is optional. Without it the decrypted document is exposed as
it is, and nested values are addressed with `Config.nested`. With it, a nested
document answers flat lookups, which is what provider credentials expect — so
there is no need to flatten the document on disk.

Decryption is lazy and happens at most once. `layerAdd` registers the provider
_behind_ the environment, so an ambient `CLOUDFLARE_API_TOKEN=… bun run deploy`
still wins and the document is never decrypted on that path:

```ts
import * as SopsConfig from "effect-sops/Config";

const credentials = SopsConfig.layerAdd({ path: "secrets.sops.json" });
// or SopsConfig.layerAdd({ ... }, { asPrimary: true }) to consult SOPS first,
// or SopsConfig.layer({ ... }) to replace the ambient provider outright.
```

A path the document does not contain is reported as _absent_ rather than as a
failure, so composing with `ConfigProvider.orElse` and other providers behaves
the way Effect expects. Only an unreadable or undecryptable document fails, as a
`ConfigProvider.SourceError` that names the source but never includes decrypted
content.

This entry point does not import `alchemy`, so it is usable from non-Alchemy
programs that just want SOPS-backed configuration.

> **Alchemy only consults environment-style credentials non-interactively when
> `CI=1`.** Otherwise it requires a configured profile and refuses to continue,
> which means the `ConfigProvider` is never reached. Set `CI=1` in automation,
> or run `alchemy login` for interactive use.

## At a deployment target

### Cloudflare Secrets Store

Use `CloudflareSopsSecrets` when Cloudflare Workers should receive secrets from
Cloudflare Secrets Store instead of Alchemy state. It is the high-level wrapper
around the exported `CloudflareSopsSecretsAction`.

The wrapper reads a local encrypted SOPS file before registering the Action,
passes ciphertext into Action state, decrypts during deploy, and imports selected
values into the target store. Plaintext is sent to Cloudflare Secrets Store but
is not persisted as Action input.

A stack using the Action needs:

- Cloudflare providers and state configured in the Alchemy stack
- A `Cloudflare.SecretsStore` resource or `{ accountId, storeId }` reference
- A deploy-time SOPS identity, preferably passed as `Redacted<string>`
- A `secrets` map from Cloudflare secret names to decrypted dot-path selectors,
  or no `secrets` map when all scalar leaves should be imported

```ts
import * as Alchemy from "alchemy";
import * as Cloudflare from "alchemy/Cloudflare";
import { CloudflareSopsSecrets, cloudflareSopsWorkerBindings } from "effect-sops";
import * as Effect from "effect/Effect";
import * as Redacted from "effect/Redacted";

export default Alchemy.Stack(
  "Worker",
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  Effect.gen(function* () {
    const store = yield* Cloudflare.SecretsStore("Secrets");

    const imported = yield* CloudflareSopsSecrets("WorkerSecrets", {
      path: "./secrets.enc.yaml",
      format: "yaml",
      backend: "sops-age",
      store,
      ageKey: Redacted.make(process.env.SOPS_AGE_KEY!),
      scopes: ["workers"],
      comment: "imported by effect-sops",
      secrets: {
        API_TOKEN: "api.token",
        DATABASE_URL: "database.url",
      },
    });

    const worker = yield* Cloudflare.Worker("Api", {
      main: "./src/worker.ts",
    });
    yield* worker.bind(
      "sops-secrets",
      cloudflareSopsWorkerBindings(imported, ["API_TOKEN", "DATABASE_URL"]),
    );

    return {
      url: worker.url,
    };
  }),
);
```

`secrets` maps Cloudflare secret names to paths in the decrypted document. Omit
it to import every scalar leaf; generated names are derived from dot paths, and
`namePrefix` can add a prefix to every generated name.

`cloudflareSopsWorkerBindings(imported, ["API_TOKEN"])` binds a Worker variable
to the Secrets Store secret with the same name. Pass an object when the Worker
binding name should differ from the stored secret name:

```ts
yield *
  worker.bind(
    "sops-secrets",
    cloudflareSopsWorkerBindings(imported, {
      API_TOKEN: "WORKER_API_TOKEN",
    }),
  );
```

Run the stack with your normal Alchemy deploy command. The Action runs when its
input changes, including the encrypted file content, backend options, selected
secret paths, scopes, comments, and target store.

Existing Secrets Store entries are replaced by default because Cloudflare does
not allow patching a secret value. Set `replaceExisting: false` when you only
want to converge scopes and comments for an existing secret name. The Cloudflare
credentials used by the stack must be allowed to manage the target Secrets
Store, and Worker deploy permissions are also needed when the same stack binds
those secrets to a Worker.

Most stacks should call `CloudflareSopsSecrets`. Use
`CloudflareSopsSecretsAction` directly only when the encrypted content is
already available and you want to pass the Action input yourself:

```ts
import { CloudflareSopsSecretsAction } from "effect-sops";
import * as Redacted from "effect/Redacted";

const imported =
  yield *
  CloudflareSopsSecretsAction("WorkerSecrets", {
    path: "secrets.enc.yaml",
    content: encryptedSopsYaml,
    format: "yaml",
    backend: "sops-age",
    store: {
      accountId: "account-id",
      storeId: "store-id",
    },
    ageKey: Redacted.make(process.env.SOPS_AGE_KEY!),
    secrets: {
      API_TOKEN: "api.token",
    },
  });
```

### GitHub Actions secrets

Use `GitHubSopsSecrets` to materialize selected SOPS values as repository or
environment secrets through Alchemy's `GitHub.Secret` resource. It requires a
static map of GitHub secret names to SOPS dot paths so that Alchemy can register
one managed resource for each secret.

The stack needs both `GitHub.providers()` and `SopsFileProvider()`. GitHub
credentials are resolved by Alchemy; a token needs `repo` scope for private
repositories or `public_repo` for public repositories.

```ts
import * as Alchemy from "alchemy";
import * as GitHub from "alchemy/GitHub";
import { GitHubSopsSecrets, SopsFileProvider } from "effect-sops";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

export default Alchemy.Stack(
  "GitHubActions",
  {
    providers: Layer.mergeAll(
      GitHub.providers(),
      SopsFileProvider(),
    ),
  },
  Effect.gen(function* () {
    yield* GitHubSopsSecrets("DeploySecrets", {
      path: "./secrets.enc.yaml",
      format: "yaml",
      owner: "my-org",
      repository: "my-repo",
      environment: "production", // omit for repository-wide secrets
      ageKey: Redacted.make(process.env.SOPS_AGE_KEY!),
      secrets: {
        DEPLOY_TOKEN: "github.deployToken",
        DATABASE_URL: "database.url",
      },
    });
  }),
);
```

Each secret remains redacted while it flows from `SopsFile` to `GitHub.Secret`.
Changing the encrypted SOPS source updates the corresponding GitHub Actions
secret. As with `SopsFile`, use an Alchemy state store you trust because state
must retain redacted values to reconcile resources.

## Inputs

Every string-like option accepts the same shapes as Alchemy `SecretInput`:

- `string`
- `Redacted<string>`
- `Effect<string | Redacted<string>>`
- `Config<string | Redacted<string>>`

Supported options:

- `path`, `content`, `url`, or `json`: exactly one encrypted source is
  required. `path` may be an ordered array of local files, merged left to right
  after decryption. `json` accepts an imported (encrypted) SOPS JSON document,
  drives the typed `data` output, and defaults `format` to `json`.
- `cwd`, `sopsBinary`
- `backend`: `auto`, `sops-age`, or `cli`
- `format`: `auto`, `json`, `yaml`, `dotenv`, `text`, or `binary`
- `inputType`, `outputType`: input/output format hints
- `extract`: passed to `sops --extract` for CLI and as a key path for `sops-age`
- `sopsArgs`: extra CLI args; requires `backend: "cli"` or CLI fallback
- `env`, `ageKey`, `ageKeyFile`: SOPS environment inputs; `sops-age` uses
  direct `ageKey` / `SOPS_AGE_KEY`
- `schema`: service-free `Schema.Struct` from `effect/Schema`; validates the
  decrypted document and enables the typed `value` output
- `secrets`: output-name to dot-path selectors; optional legacy flat selection
- `types`: return generated TypeScript definitions for the redacted data shape;
  use `true` or `{ exportName: "AppSecrets" }`
- `cache`, `timeoutMs`, `retry`

Provider options:

- `decrypt`: custom decrypt backend (e.g. `runSopsKms({ unwrapDataKey })` for KMS-encrypted documents)
- `memoize`: `true` to share in-flight and completed decrypts by request in the
  current process, or `{ key }` to provide a custom memoization key

`CloudflareSopsSecrets` shares the decrypt options above and adds:

- `store`: Cloudflare Secrets Store resource or `{ accountId, storeId }`
- `namePrefix`: prefix for generated Cloudflare secret names when `secrets` is
  omitted
- `scopes`: Cloudflare Secrets Store scopes; defaults to `["workers"]`
- `comment`: free-form Cloudflare Secrets Store comment
- `replaceExisting`: delete and recreate matching existing secrets so values
  converge; defaults to `true`

`CloudflareSopsSecretsAction` also accepts `content`, the encrypted SOPS
ciphertext to use as Action input. The `CloudflareSopsSecrets` wrapper fills
that field by reading `path`.

`GitHubSopsSecrets` accepts the `SopsFile` source and decrypt options plus:

- `owner`, `repository`, `environment`, and `baseUrl`: forwarded to every
  `GitHub.Secret`; omit `environment` for repository-wide secrets
- `secrets`: required map from GitHub Actions secret names to decrypted SOPS
  dot-path selectors

## Outputs

The resource returns:

- `data`: nested document with scalar leaves redacted, typed from the imported
  document when `json` is used
- `flat`: dot-path map of all redacted leaves
- `secrets`: selected redacted leaves, or all leaves when `secrets` is omitted
- `value`: schema-validated typed document when `schema` was provided
- `topLevelKeys`: top-level keys from the decrypted document
- `types`: generated TypeScript definitions when `types` was requested
- `sourceHash`: SHA-256 digest of the encrypted source plus non-secret options
- `path`, `format`, `version`

`cache` defaults to `true`. If the encrypted source digest and resource version
are unchanged, the provider returns the previous redacted output without
decrypting again. Set `cache: false` to force decryption on every deploy.

The Cloudflare Action returns `accountId`, `storeId`, `path`, and an `imported`
array containing each Cloudflare secret name, source dot path, secret id, and
status.

## Security note

`Redacted<string>` prevents accidental printing and logging, but Alchemy state
stores still persist values so they can be revived later. Use a state store you
trust for decrypted secrets.

## Troubleshooting

### `TypeError: undefined is not an object (evaluating 'impl.base.get')` when providing a ConfigProvider

**Symptom:** A stack using `effect-sops/Config` dies immediately with a
`TypeError` inside `effect/Context.js` at `lookup`, with no mention of SOPS or
configuration. Stack frames reference two different `effect` paths, for example
`effect@4.0.0-beta.102` and `effect@4.0.0-beta.105`.

**Cause:** Two copies of `effect` are installed. `ConfigProvider` is a
`Context.Reference`, so its identity is per-instance: a provider built by one
copy of `effect` cannot be read by a stack running another. This surfaces most
often when the layer is constructed in a shared workspace package that resolves
a different `effect` than the app.

**Fix:** Align `effect` to a single version across the workspace and reinstall.
For Bun, `ls node_modules/.bun | grep '^effect@'` should show one version for
application code. `effect` is a peer dependency of `effect-sops` for exactly
this reason — let the app own the version rather than nesting a second copy.

If a shared package must expose credentials, have it return plain data and let
each stack build the provider with its own `effect` import.

### `Output` type errors when passing `secrets.value` into `Cloudflare.Vite` / `Worker` env

**Symptom:** TypeScript reports that `Output<…>` from `secrets.value` is not
assignable to the `Output<…>` expected by `alchemy/Output` helpers (for example
`Output.map`), often with a long path mentioning two different
`node_modules/alchemy` versions and incompatible `bind(...)` return types
(`RuntimeContext` vs `ExecutionContext`).

**Cause:** Two copies of `alchemy` are installed. `effect-sops` decrypts via one
instance (for example the version pulled in as its dependency), while your stack
imports `alchemy`, `alchemy/Cloudflare`, and `alchemy/Output` from another.
`Output` is not portable across versions — even patch differences in the Effect
runtime context break assignability.

**Fix:**

1. **Use one `alchemy` version everywhere.** Pin the same release in your root /
   catalog (for example `2.0.0-beta.43` or newer) and ensure every workspace
   package that imports `alchemy` uses that pin, not an older catalog entry.
2. **Deduplicate installs.** After aligning versions, run `bun install` (or your
   package manager’s equivalent) and confirm only one `alchemy` appears under
   `node_modules` (for Bun: `ls node_modules/.bun | grep '^alchemy@'` should
   show a single version for app code).
3. **Prefer `alchemy` as a peer, not a nested dependency.** `effect-sops` lists
   `alchemy` as a `peerDependency` with a semver range so your project’s
   `alchemy` is the one both the stack and `SopsFile` use. Avoid relying on a
   nested copy bundled inside another package.

**Example (monorepo catalog):**

```json
{
  "catalog": {
    "alchemy": "2.0.0-beta.57"
  }
}
```

Ensure `apps/*` and `packages/*` use `"alchemy": "catalog:"` (or the same exact
version), then reinstall.

If you still see two versions, check overrides / patched dependencies and any
package that pins an older `alchemy` directly.
