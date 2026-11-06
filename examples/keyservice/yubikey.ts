import { join } from "node:path";
import * as BunRuntime from "@effect/platform-bun/BunRuntime";
import * as BunServices from "@effect/platform-bun/BunServices";
import { Interaction, Listen, serve } from "effect-sops/KeyService";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as FileSystem from "effect/FileSystem";
import * as Option from "effect/Option";
import * as Stream from "effect/Stream";
import * as ChildProcess from "effect/process/ChildProcess";
import { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";

// Manual hardware check only. Importing this module never discovers identities.
const recipient = Effect.gen(function* () {
  const supplied = yield* Config.String("AGE_YUBIKEY_RECIPIENT").pipe(Config.option);
  if (Option.isSome(supplied)) return supplied.value;
  const fs = yield* FileSystem.FileSystem;
  const explicitFile = yield* Config.String("SOPS_AGE_KEY_FILE").pipe(Config.option);
  const xdg = yield* Config.String("XDG_CONFIG_HOME").pipe(Config.option);
  const home = yield* Config.String("HOME");
  const config = Option.getOrElse(xdg, () => join(home, "Library/Application Support"));
  const path = Option.getOrElse(explicitFile, () => join(config, "sops/age/keys.txt"));
  const text = yield* fs.readFileString(path);
  const match = /^\s*#\s*Recipient:\s*(age1yubikey1[a-z0-9]+)\s*$/im.exec(text);
  if (!match?.[1]) {
    return yield* Effect.fail(new Error(
      "Set AGE_YUBIKEY_RECIPIENT or add a YubiKey Recipient comment to the identity file.",
    ));
  }
  return match[1];
});

const runSops = Effect.fn("Example.yubikey.sops")(function* (
  args: ReadonlyArray<string>,
  directory: string,
) {
  const spawner = yield* ChildProcessSpawner;
  const child = yield* spawner.spawn(ChildProcess.make("sops", args, {
    cwd: directory,
    // The Go client must use the service even if its own discovery policy changes.
    env: { PATH: process.env.PATH, HOME: directory, XDG_CONFIG_HOME: directory },
    stdin: "ignore",
    stdout: "pipe",
    stderr: "ignore",
  }));
  const [output, code] = yield* Effect.all([
    child.stdout.pipe(Stream.decodeText(), Stream.mkString),
    child.exitCode,
  ], { concurrency: "unbounded" });
  if (code !== 0) return yield* Effect.fail(new Error("SOPS hardware check failed."));
  return output;
}, Effect.scoped);

const manualCheck = Effect.gen(function* () {
  if (process.platform !== "darwin") {
    return yield* Effect.fail(new Error("The manual dialog check requires macOS."));
  }
  yield* Effect.logInfo("1. Resolve the YubiKey recipient without displaying identity material.");
  const address = yield* recipient;
  if (!/^age1yubikey1[a-z0-9]+$/.test(address)) {
    return yield* Effect.fail(new Error("AGE_YUBIKEY_RECIPIENT must be a YubiKey recipient."));
  }
  const fs = yield* FileSystem.FileSystem;
  const directory = yield* fs.makeTempDirectoryScoped({ prefix: "effect-sops-yubikey-" });
  const input = join(directory, "plain.json");
  const encrypted = join(directory, "encrypted.json");
  const document = '{"check":"manual-yubikey-roundtrip"}';
  yield* fs.writeFileString(input, document, { mode: 0o600 });
  yield* Effect.logInfo("2. Start a random loopback listener with dialog approval and identity discovery.");
  const service = yield* serve({
    listen: Listen.loopback(0),
    interaction: yield* Interaction.dialog(),
    age: { discover: true },
  });
  yield* Effect.logInfo("3. Encrypt with SOPS through the service. Accept the approval dialog.");
  const output = yield* runSops([
    "encrypt", "--enable-local-keyservice=false", "--keyservice", service.uri,
    "--age", address, "--input-type", "json", "--output-type", "json", input,
  ], directory);
  yield* fs.writeFileString(encrypted, output, { mode: 0o600 });
  yield* Effect.logInfo("4. Decrypt: approve the request, enter the PIN in the dialog, then touch the YubiKey when it blinks.");
  const plaintext = yield* runSops([
    "decrypt", "--enable-local-keyservice=false", "--keyservice", service.uri, encrypted,
  ], directory);
  const verified = yield* Effect.try({
    try: () => {
      const value: unknown = JSON.parse(plaintext);
      return typeof value === "object" && value !== null && "check" in value &&
        value.check === "manual-yubikey-roundtrip";
    },
    catch: () => new Error("SOPS returned an invalid JSON document."),
  });
  if (!verified) return yield* Effect.fail(new Error("YubiKey roundtrip did not match."));
  yield* Effect.logInfo("5. YubiKey roundtrip verified. Closing the service and removing temporary files.");
});

if (import.meta.main) {
  BunRuntime.runMain(manualCheck.pipe(
    Effect.scoped,
    Effect.provide(BunServices.layer),
    // Dependency errors can contain subprocess output; never display that material.
    Effect.catchCause(() => Effect.sync(() => {
      console.error("Manual YubiKey check failed. Check macOS, sops, age-plugin-yubikey, the recipient, and identity configuration.");
      process.exitCode = 1;
    })),
  ));
}
