import * as Alchemy from "alchemy";
import * as GitHub from "alchemy/GitHub";
import * as Layer from "effect/Layer";
import * as Redacted from "effect/Redacted";

import { SopsFileProvider } from "effect-sops";
import { requiredEnvironment } from "../_shared/env.ts";
import { program } from "./app.ts";

export default Alchemy.Stack(
  "GitHubActionsSecretsDemo",
  {
    providers: Layer.mergeAll(SopsFileProvider(), GitHub.providers()),
    state: Alchemy.localState(),
  },
  program({
    ageKey: Redacted.make(requiredEnvironment("SOPS_AGE_KEY")),
    owner: requiredEnvironment("GITHUB_OWNER"),
    repository: requiredEnvironment("GITHUB_REPOSITORY"),
    ...(process.env.GITHUB_ENVIRONMENT === undefined
      ? {}
      : { environment: process.env.GITHUB_ENVIRONMENT }),
  }),
);
