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

Every client arriving through `ssh -R` appears to the service as `127.0.0.1`.
Remembered approvals cover every user of that remote host who can reach the
forward, plus local clients with the same peer host, operation, and key. The
`devbox` configuration asks on every request for this reason.

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
Decryption uses only the native identity for the approved recipient, or its
matching plugin group. A plugin group may contain multiple identities; the
approval does not select an individual identity within that group. Configure
`AGE-PLUGIN-…` identities and install the corresponding `age-plugin-*`
executable for hardware-backed keys. Unlike upstream SOPS, SSH age recipients
(`ssh-ed25519` and `ssh-rsa`) and SSH private-key identity discovery are not
supported. This restriction does not affect SSH transport forwards.

Requests are serialized. Preflight may read identity sources to find a
matching recipient before prompting. Approval comes before cryptographic key
operations, key commands, and plugin interactions. Unsupported keys and
known missing identities fail without a prompt. `SOPS_AGE_KEY_CMD` runs only
after approval, so preflight cannot refuse a recipient as missing when only
that command can supply its identity. The command may prompt separately after
approval. Remembered approval covers
the same peer host, operation, and key; it never skips plugin PIN or touch
requests.

`requestTimeout` defaults to five minutes from the start of a request's turn,
excluding queue time. At most `maxPendingRequests` requests wait (default: 16);
additional requests fail with `RESOURCE_EXHAUSTED`. Client deadlines can
expire sooner, including while waiting for a turn.

The protocol has no authentication or encryption. Prefer loopback or Unix
sockets; use SSH or a Tailscale tailnet with ACLs for remote access. Keep
approval enabled on network listeners. The server warns when requests are
approved without asking and either a non-loopback listener or any SSH remote
forward is configured. TCP addresses require a host: use `127.0.0.1:5000` for
loopback or `0.0.0.0:5000` for all IPv4 interfaces; SOPS's `--address :5000`
shorthand is not supported. See the root
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

For a scoped Effect client, use `Ssh.localForward` from
`effect-sops/KeyService`. Promise tunnel handles expose `exited: Promise<void>`;
server handles expose the same signal on each `service.tunnels[i]`. A dropped
remote forward logs its destination. Standalone servers keep their local
listeners running and do not reconnect automatically.

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

If any `SopsKeyService` remote forward exits, the resource logs a warning and
closes its whole instance, including local listeners and the other forwards.
The next Alchemy plan or deploy starts a replacement. There is no automatic
restart between plans.

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
