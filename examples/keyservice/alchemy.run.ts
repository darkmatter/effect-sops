import * as Alchemy from "alchemy";
import { keyServiceProviders, SopsFileProvider } from "effect-sops";
import * as Config from "effect/Config";
import * as Effect from "effect/Effect";
import * as Layer from "effect/Layer";

import { program } from "./app.ts";

export default Alchemy.Stack(
  "SopsKeyServiceDemo",
  {
    providers: Layer.mergeAll(keyServiceProviders(), SopsFileProvider()),
    state: Alchemy.localState(),
  },
  Effect.gen(function* () {
    // Configure the path to an identity file matching the encrypted example.
    const identityFile = yield* Config.String("SOPS_AGE_KEY_FILE");
    return yield* program(identityFile);
  }),
);
