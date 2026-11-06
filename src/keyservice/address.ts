/**
 * Pure address formatting shared by the server, listen resolution, and SSH
 * forwards: SOPS keyservice URIs, `@grpc/grpc-js` bind targets, and peers.
 */
import type { ResolvedListenAddress } from "./model.js";

/** `host:port`, bracketing IPv6 literals. */
export const hostPort = (host: string, port: number): string =>
  host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;

/**
 * The URI a SOPS client passes to `--keyservice` / `SOPS_KEYSERVICE`:
 * `tcp://host:port` or `unix:///absolute/path`.
 */
export const keyServiceUri = (address: ResolvedListenAddress): string =>
  address._tag === "Unix"
    ? `unix://${address.path.split("/").map(encodeURIComponent).join("/")}`
    : `tcp://${hostPort(address.host, address.port)}`;

/** Target for `Server.bindAsync`: `host:port` or `unix:///absolute/path`. */
export const grpcBindTarget = (address: ResolvedListenAddress): string =>
  address._tag === "Unix"
    ? `unix://${address.path}`
    : hostPort(address.host, address.port);

/**
 * Host part of a gRPC peer string. Node reports `ipv4:1.2.3.4:5` /
 * `ipv6:[::1]:5`; Bun reports `1.2.3.4:5` / `[::1]:5`. Unix peers have no host.
 */
export const peerHost = (peer: string): string | undefined => {
  if (peer.startsWith("unix:")) return undefined;
  const address = peer.replace(/^ipv[46]:/, "");
  const bracketed = /^\[([^\]]+)\](?::\d+)?$/.exec(address);
  if (bracketed) return bracketed[1];
  const hostAndPort = /^([^:]+):\d+$/.exec(address);
  if (hostAndPort) return hostAndPort[1];
  return address.length > 0 ? address : undefined;
};

/** Whether only this machine can reach the listener (Unix socket or loopback TCP). */
export const isLoopback = (address: ResolvedListenAddress): boolean => {
  if (address._tag === "Unix") return true;
  const host = address.host.toLowerCase();
  return (
    host === "localhost" ||
    host === "::1" ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host)
  );
};
