# Examples

Every directory is a runnable, focused example. Start with **when the
decrypted value is needed**; the directories below are variations within that
lifecycle.

The shared encrypted fixture uses a public test-only age identity so the smoke
suite can prove decryption. Copy the code, but always encrypt your own document
and use your own identity.

## Inside an Alchemy stack

Use `SopsFile` when your stack needs redacted values. The encrypted source and
typing choice are variations of this one route.

| Example | Variation | Run it locally |
| --- | --- | --- |
| [`sops-file`](./sops-file) | Read selected, schema-validated values from a SOPS file. | `SOPS_AGE_KEY=... bun alchemy deploy examples/sops-file/alchemy.run.ts` |
| [`json-import`](./json-import) | Use an encrypted JSON import to infer `secrets.data` types. | `SOPS_AGE_KEY=... bun alchemy deploy examples/json-import/alchemy.run.ts` |

## Before an Alchemy stack

Use a SOPS-backed `ConfigProvider` when configuration or provider credentials
must be available before the stack's providers and state initialize.

| Example | Run it locally |
| --- | --- |
| [`config-provider`](./config-provider) | `SOPS_AGE_KEY=... bun examples/config-provider/main.ts` |

## At a deployment target

Use a target adapter when SOPS values must be synchronized into another secret
system rather than returned to your program.

| Example | Target | Run it locally |
| --- | --- | --- |
| [`cloudflare-secrets-store`](./cloudflare-secrets-store) | Cloudflare Secrets Store for Worker bindings. | `CLOUDFLARE_ACCOUNT_ID=... CLOUDFLARE_SECRETS_STORE_ID=... SOPS_AGE_KEY=... bun alchemy deploy examples/cloudflare-secrets-store/alchemy.run.ts` |
| [`github-actions-secrets`](./github-actions-secrets) | Repository or environment GitHub Actions secrets. | `GITHUB_OWNER=... GITHUB_REPOSITORY=... SOPS_AGE_KEY=... bun alchemy deploy examples/github-actions-secrets/alchemy.run.ts` |

The Cloudflare and GitHub examples require their usual Alchemy credentials. The
GitHub token needs `repo` for private repositories or `public_repo` for public
ones. Set `GITHUB_ENVIRONMENT` to scope the GitHub secret to an Actions
environment; omit it for a repository secret.

## Without an Alchemy stack

Use [`schema-decoder`](./schema-decoder) when a standalone Effect program needs
validated imported SOPS JSON:

```sh
SOPS_AGE_KEY=... bun examples/schema-decoder/main.ts
```

When another program needs access to an age identity, use a keyservice:

| Example | Variation | Run it locally |
| --- | --- | --- |
| [`keyservice`](./keyservice) | Named server configurations, SSH client, Alchemy resources, and a manual YubiKey check. | `KEYSERVICE_CONFIG=local bun examples/keyservice/serve.ts` |

## Smoke checks

```sh
bun run build
bun run smoke:examples
```

`examples/smoke.test.ts` runs in CI after the package build. It decrypts the
shared fixture for every SOPS entry point and uses local mock APIs to prove the
Cloudflare and GitHub examples make the expected secret-management requests.
It also starts the keyservice example on a random loopback port and decrypts
through it. The script runs from `test/` so its hermetic preload isolates
identity discovery from workstation credentials. The manual YubiKey example is never part of the
smoke suite.
