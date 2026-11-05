import * as Alchemy from "alchemy";
import * as Cloudflare from "@alchemy.run/cloudflare";
import * as Redacted from "effect/Redacted";

import { requiredEnvironment } from "../_shared/env.ts";
import { program } from "./app.ts";

export default Alchemy.Stack(
  "CloudflareSecretsStoreDemo",
  {
    providers: Cloudflare.providers(),
    state: Cloudflare.state(),
  },
  program({
    accountId: requiredEnvironment("CLOUDFLARE_ACCOUNT_ID"),
    ageKey: Redacted.make(requiredEnvironment("SOPS_AGE_KEY")),
    storeId: requiredEnvironment("CLOUDFLARE_SECRETS_STORE_ID"),
  }),
);
