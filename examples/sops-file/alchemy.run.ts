import * as Alchemy from "alchemy";
import { SopsFileProvider } from "effect-sops";
import * as Config from "effect/Config";

import { program } from "./app.ts";

export default Alchemy.Stack(
  "SopsFileDemo",
  {
    providers: SopsFileProvider({ memoize: true }),
    state: Alchemy.localState(),
  },
  program(Config.Redacted("SOPS_AGE_KEY")),
);
