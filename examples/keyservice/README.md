# Keyservice

```sh
bun run build
bun examples/keyservice/serve.ts
```

Choose a committed configuration from the terminal picker. The server stays
running until Ctrl+C. It serves age keys through the upstream SOPS gRPC API;
clients need no copy of the private identity. Bun and its Effect platform
package are required for these examples.

| Name | Listener | Approval | Forwarding |
| --- | --- | --- | --- |
| `local` | `127.0.0.1:5000` | Terminal, every request | None |
| `tailscale` | This machine's Tailscale IPv4 address, port 5000 | macOS dialog, remembered for five minutes | None |
| `devbox` | `127.0.0.1:5000` | Terminal, every request | SSH remote forward to `user@devbox.example.com` |

Edit the `devbox` destination in [serve.ts](./serve.ts) before using it. It
exposes the local service on the remote machine's loopback port 5000. SSH
needs working noninteractive authentication. Tailscale must already be
running; dialogs require macOS.

When stdin is not a terminal, select a name with `KEYSERVICE_CONFIG`:

```sh
KEYSERVICE_CONFIG=tailscale bun examples/keyservice/serve.ts < /dev/null
```

The interactive picker takes precedence over the environment. There is no
selector flag. `local` and `devbox` still need a terminal to approve requests;
selecting a name noninteractively does not make terminal approval headless.
The `tailscale` configuration can show dialogs without terminal stdin, but
still needs an interactive macOS desktop.

Identity discovery uses SOPS environment sources and the platform's SOPS
`keys.txt`. It happens on requests, not when this example is imported.
Native identities run before plugin identities during decryption after
recipient preflight succeeds. Configure `AGE-PLUGIN-…` identities and install
the corresponding `age-plugin-*` executable for hardware-backed keys.

Requests are serialized. Preflight may read identity sources to find a
matching recipient before prompting. Approval comes before cryptographic key
operations, key commands, and plugin interactions. Unsupported keys and
known missing identities fail without a prompt. Remembered approval covers
the same peer host, operation, and key; it never skips plugin PIN or touch
requests.

The protocol has no authentication or encryption. Prefer loopback or Unix
sockets; use SSH or a Tailscale tailnet with ACLs for remote access. Keep
approval enabled on network listeners. The server warns if a network listener
uses the default interaction without approval. See the root
[API examples and command parity table](../../README.md#serve-a-sops-keyservice).

## Reach a remote service

```sh
bun examples/keyservice/client.ts user@keyhost ./secrets.enc.json
```

Start a keyservice on `keyhost` first. [client.ts](./client.ts) opens an SSH
local forward to its loopback port 5000, decrypts the supplied file with
`runSopsAge`, and closes the tunnel. Local identity discovery is disabled.
The command prints success only; it never prints the decrypted document.
When embedding it, `decryptThroughTunnel(destination, path)` returns
`Promise<string>` containing plaintext. Pass it directly to its consumer.
`decryptThroughKeyService(uri, path)` provides the same native decrypt as an
Effect when a service URI is already available.

When a service is listening locally, the SOPS CLI can use it too:

```sh
sops decrypt --enable-local-keyservice=false \
  --keyservice tcp://127.0.0.1:5000 ./secrets.enc.json > /dev/null
```

## Inside an Alchemy stack

[alchemy.run.ts](./alchemy.run.ts) registers `keyServiceProviders()` with
`SopsFileProvider()`. [app.ts](./app.ts) starts a random loopback listener and
passes its `uri` to `SopsFile({ keyServices: [keyService.uri],
enableLocalKeyService: false })`. Supply `SOPS_AGE_KEY_FILE` as the path to an
identity file matching the encrypted shared document. The shared document is
a public test fixture; replace it with your own encrypted source for real use.

Use `SopsKeyServiceTunnel` when the stack should reach an existing remote
service. Both Alchemy resources live for the deployment process; `alchemy dev`
keeps them in its local sidecar across hot reloads. Identity file paths may be
resource props; identity contents must never enter Alchemy state.

## Manual YubiKey check

```sh
bun examples/keyservice/yubikey.ts
```

Run [yubikey.ts](./yubikey.ts) manually on macOS with `sops` and
`age-plugin-yubikey` on PATH and the YubiKey attached. This program deliberately
uses your configured identities. **It is never run by automated tests.**
Your identity file must contain the plugin identity. The public recipient
comes from `AGE_YUBIKEY_RECIPIENT` or a `# Recipient: age1yubikey1…` comment
in `SOPS_AGE_KEY_FILE` or the default SOPS identity file. Never put an identity
or PIN in the recipient variable.

The program starts a random loopback listener with dialog approval, then
runs real SOPS encryption and decryption of a small temporary JSON document.
Accept the approval dialog for each operation. For decryption, answer the
plugin's PIN dialog and touch the YubiKey when required. It checks the round
trip without printing plaintext, identities, PINs, or data keys, then closes
the listener and removes the temporary directory. PIN and touch behavior
depends on the key's configured policy and plugin state.

## Hermetic smoke checks

```sh
bun run build
cd test && bun test ../examples/smoke.test.ts
```

The smoke suite imports `startConfiguredKeyService` from the server example,
uses the public shared fixture identity on a random loopback port, and
decrypts the shared document through the client helper. It also checks named
configuration selection and SSH tunnel lifetime. The `test/` working directory
enables the hermetic preload, which isolates identity discovery from real
workstation credentials. SSH and plugin protocol tests use fake executables;
the smoke suite never starts the manual hardware check.
