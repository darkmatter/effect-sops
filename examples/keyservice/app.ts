import * as Output from "alchemy/Output";
import { SopsFile, SopsKeyService } from "effect-sops";
import { Listen } from "effect-sops/KeyService";
import * as Effect from "effect/Effect";

const secretsPath = new URL("../_shared/secrets.sops.json", import.meta.url)
  .pathname;

/** Decrypt the example document using only the explicitly supplied identity file. */
export const program = (identityFile: string) =>
  Effect.gen(function* () {
    const keyService = yield* SopsKeyService("KeyService", {
      listen: [Listen.loopback(0)],
      // For a trusted Tailscale network on macOS, use:
      // listen: [Listen.tailscale(5000)], approval: "dialog",
      // dialog: { title: "Approve SOPS decryption" },
      age: { identityFiles: [identityFile], discover: false },
    });
    const secrets = yield* SopsFile("AppSecrets", {
      path: secretsPath,
      format: "json",
      keyServices: [keyService.uri],
      enableLocalKeyService: false,
      secrets: { API_TOKEN: "api.token" },
    });

    return {
      uri: keyService.uri,
      apiToken: Output.map(secrets.secrets, (values) => values.API_TOKEN!),
      topLevelKeys: secrets.topLevelKeys,
    };
  });
