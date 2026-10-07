import * as Alchemy from "alchemy";
import { SopsFileProvider } from "effect-sops";
import * as Config from "effect/Config";

import { program } from "./app.ts";

export default Alchemy.Stack(
  "JsonImportDemo",
  {
    providers: SopsFileProvider(),
    state: Alchemy.localState(),
  },
  program(Config.Redacted("SOPS_AGE_KEY")),
);
