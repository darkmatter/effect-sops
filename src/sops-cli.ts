import { spawn } from "node:child_process";
import * as Effect from "effect/Effect";

import { SopsDecryptError } from "./errors.js";
import {
  buildSopsArgs,
  requestLabel,
  revealEnv,
  type SopsCommandRequest,
  type SopsDecrypt,
} from "./decrypt.js";

export const runSopsCli: SopsDecrypt = (request) =>
  Effect.tryPromise({
    try: () => runSopsCliPromise(request),
    catch: (cause) =>
      cause instanceof SopsDecryptError
        ? cause
        : new SopsDecryptError({
            message: "Failed to run sops",
            path: requestLabel(request),
            cause,
          }),
  });

const runSopsCliPromise = (request: SopsCommandRequest): Promise<string> =>
  new Promise((resolve, reject) => {
    const args = buildSopsArgs(request);
    const env = {
      ...process.env,
      ...revealEnv(request.env),
      // Explicit endpoint lists override inherited services, including [].
      ...(request.keyServices !== undefined ? { SOPS_KEYSERVICE: "" } : {}),
    };

    const child = spawn(request.binary, args, {
      cwd: request.cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";
    let timedOut = false;

    const timeout =
      request.timeoutMs === undefined
        ? undefined
        : setTimeout(() => {
            timedOut = true;
            child.kill("SIGTERM");
          }, request.timeoutMs);

    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", (cause) => {
      if (timeout) clearTimeout(timeout);
      reject(
        new SopsDecryptError({
          message: `Failed to start sops binary "${request.binary}"`,
          path: requestLabel(request),
          cause,
        }),
      );
    });
    child.on("close", (exitCode) => {
      if (timeout) clearTimeout(timeout);
      if (timedOut) {
        const error = {
          message: `sops timed out after ${request.timeoutMs}ms`,
          path: requestLabel(request),
          ...(exitCode === null ? {} : { exitCode }),
          ...(stderr.trim() ? { stderr: stderr.trim() } : {}),
        };
        reject(new SopsDecryptError(error));
        return;
      }
      if (exitCode === 0) {
        resolve(stdout);
        return;
      }
      const error = {
        message: `sops exited with code ${exitCode}`,
        path: requestLabel(request),
        ...(exitCode === null ? {} : { exitCode }),
        ...(stderr.trim() ? { stderr: stderr.trim() } : {}),
      };
      reject(new SopsDecryptError(error));
    });
  });
