/**
 * Preloaded before every test file (see bunfig.toml). Tests run on machines
 * that hold real age identities, and identity discovery reads `SOPS_AGE_*`,
 * `XDG_CONFIG_HOME`, and `HOME`. A failing assertion that prints discovered
 * identities would leak them into logs, so tests only ever see empty
 * directories. OpenSSH resolves `~/.ssh` from the passwd entry rather than
 * `HOME`, so opt-in SSH smoke tests still use the developer's SSH setup.
 */
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

for (const name of Object.keys(process.env)) {
  if (name.startsWith("SOPS_AGE_") || name === "SOPS_KEYSERVICE")
    delete process.env[name];
}
process.env.HOME = mkdtempSync(join(tmpdir(), "effect-sops-test-home-"));
process.env.XDG_CONFIG_HOME = mkdtempSync(
  join(tmpdir(), "effect-sops-test-config-"),
);
