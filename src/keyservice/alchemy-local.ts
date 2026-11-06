import type * as RpcServer from "alchemy/Local/RpcServer";
import { keyServiceProviders } from "./alchemy.js";

/** Sidecar provider group keeps listeners and SSH forwards alive across hot reloads. */
export default keyServiceProviders() satisfies RpcServer.ProviderLayer;
