import { runSopsAge } from "effect-sops";
import { openKeyServiceTunnel, type SshLocalForwardOptions } from "effect-sops/KeyService";
import * as Effect from "effect/Effect";

/** Decrypt only through the supplied service; local identity discovery is disabled. */
export const decryptThroughKeyService = (uri: string, path: string) =>
  runSopsAge({
    binary: "sops",
    path,
    keyServices: [uri],
    enableLocalKeyService: false,
    outputType: "json",
  });

/** Reach a remote loopback keyservice over SSH and close the tunnel after decryption. */
export const decryptThroughTunnel = async (
  destination: string,
  path: string,
  options: Omit<SshLocalForwardOptions, "destination"> = {},
): Promise<string> => {
  await using tunnel = await openKeyServiceTunnel({ ...options, destination });
  return await Effect.runPromise(decryptThroughKeyService(tunnel.uri, path));
};

if (import.meta.main) {
  const [destination, path] = process.argv.slice(2);
  if (!destination || !path) {
    console.error("Usage: bun examples/keyservice/client.ts user@host secrets.sops.json");
    process.exitCode = 1;
  } else {
    try {
      // Pass the returned document to your application instead of printing secrets.
      await decryptThroughTunnel(destination, path);
      console.log("Decrypted the document through the SSH keyservice.");
    } catch {
      console.error("Keyservice decryption failed. Check the SSH destination and encrypted file.");
      process.exitCode = 1;
    }
  }
}
