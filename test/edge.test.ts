import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

test("edge entrypoint bundles without the CLI process backend", async () => {
  const outdir = await mkdtemp(join(tmpdir(), "effect-sops-edge-"));

  try {
    const result = await Bun.build({
      entrypoints: [join(import.meta.dir, "../src/edge.ts")],
      format: "esm",
      outdir,
      target: "browser",
    });

    expect(
      result.logs.map((log) => log.message).join("\n"),
    ).toBe("");
    expect(result.success).toBe(true);

    const bundled = await readFile(join(outdir, "edge.js"), "utf8");
    expect(bundled).not.toContain("node:child_process");
    expect(bundled).not.toContain("child_process");
  } finally {
    await rm(outdir, { recursive: true, force: true });
  }
});
