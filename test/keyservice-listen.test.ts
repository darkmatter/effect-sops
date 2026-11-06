import { expect, test } from "bun:test";
import type * as os from "node:os";
import { resolve as absolutePath } from "node:path";
import * as BunServices from "@effect/platform-bun/BunServices";
import * as Effect from "effect/Effect";
import type { ChildProcessSpawner } from "effect/process/ChildProcessSpawner";
import * as Listen from "../src/keyservice/listen.ts";
import { grpcBindTarget, keyServiceUri } from "../src/keyservice/address.ts";
import { keyServiceTarget } from "../src/keyservice-client.ts";
import type { ListenAddress } from "../src/keyservice/model.ts";

const fake = `${import.meta.dir}/fixtures/ssh/tailscale-fake`;
const noInterfaces = () => ({});
const run = <A, E>(effect: Effect.Effect<A, E, ChildProcessSpawner>) =>
  Effect.runPromise(effect.pipe(Effect.provide(BunServices.layer)));

const addressInfo = (
  address: string,
  internal = false,
): os.NetworkInterfaceInfo => ({
  address,
  internal,
  netmask: address.includes(":") ? "ffff:ffff:ffff:ffff::" : "255.255.255.255",
  mac: "00:00:00:00:00:00",
  cidr: null,
  ...(address.includes(":")
    ? { family: "IPv6", scopeid: 0 }
    : { family: "IPv4" }),
});

const withMode = async <A>(
  mode: string,
  body: () => Promise<A>,
): Promise<A> => {
  const previous = process.env.FAKE_TAILSCALE_MODE;
  process.env.FAKE_TAILSCALE_MODE = mode;
  try {
    return await body();
  } finally {
    if (previous === undefined) delete process.env.FAKE_TAILSCALE_MODE;
    else process.env.FAKE_TAILSCALE_MODE = previous;
  }
};

test("constructors preserve addresses and use explicit loopback and Tailscale defaults", () => {
  expect(Listen.tcp("localhost", 0)).toEqual({
    _tag: "Tcp",
    host: "localhost",
    port: 0,
  });
  expect(Listen.loopback()).toEqual({
    _tag: "Tcp",
    host: "127.0.0.1",
    port: 5000,
  });
  expect(Listen.loopback(42)).toEqual(Listen.tcp("127.0.0.1", 42));
  expect(Listen.unix("relative.sock")).toEqual({
    _tag: "Unix",
    path: "relative.sock",
  });
  expect(Listen.tailscale()).toEqual({
    _tag: "Tailscale",
    port: 5000,
    family: 4,
  });
  expect(Listen.tailscale(7, { family: 6 })).toEqual({
    _tag: "Tailscale",
    port: 7,
    family: 6,
  });
});

test.each([
  ["127.0.0.1:5000", Listen.loopback()],
  ["localhost:0", Listen.tcp("localhost", 0)],
  ["0.0.0.0:5000", Listen.tcp("0.0.0.0", 5000)],
  ["[::]:5000", Listen.tcp("::", 5000)],
  ["[::1]:65535", Listen.tcp("::1", 65535)],
  ["[fd7a:115c:a1e0::1]:5000", Listen.tcp("fd7a:115c:a1e0::1", 5000)],
] as const)("fromSops parses TCP %s", async (address, expected) => {
  expect(await Effect.runPromise(Listen.fromSops("tcp", address))).toEqual(
    expected,
  );
});

test("fromSops explains why an empty TCP host requires an explicit wildcard", async () => {
  const error = await Effect.runPromise(
    Listen.fromSops("tcp", ":5000").pipe(Effect.flip),
  );
  expect(error.reason).toBe("InvalidAddress");
  expect(error.message).toBe(
    "an empty host would listen on every interface; pass 0.0.0.0:5000 or [::]:5000 explicitly",
  );
});

test("fromSops accepts relative Unix paths and resolve makes them absolute", async () => {
  const address = await Effect.runPromise(
    Listen.fromSops("unix", "./keyservice.sock"),
  );
  expect(address).toEqual(Listen.unix("./keyservice.sock"));
  expect<ListenAddress>(await run(Listen.resolve(address))).toEqual(
    Listen.unix(absolutePath("./keyservice.sock")),
  );
  expect<ListenAddress>(
    await run(Listen.resolve(Listen.unix("/tmp/keyservice.sock"))),
  ).toEqual(Listen.unix("/tmp/keyservice.sock"));
});

test.each([
  ["tcp://127.0.0.1:5000", Listen.loopback()],
  ["tcp://[::1]:0", Listen.tcp("::1", 0)],
  ["unix:///tmp/sops.sock", Listen.unix("/tmp/sops.sock")],
  ["unix:///tmp/a%20b.sock", Listen.unix("/tmp/a b.sock")],
] as const)("fromUri parses %s", async (uri, expected) => {
  expect(await Effect.runPromise(Listen.fromUri(uri))).toEqual(expected);
});

test("Unix client URIs encode path segments while gRPC bind targets stay raw", async () => {
  const address = { _tag: "Unix", path: "/tmp/a%20b #?/key service.sock" } as const;
  const uri = keyServiceUri(address);
  expect(uri).toBe("unix:///tmp/a%2520b%20%23%3F/key%20service.sock");
  expect(await Effect.runPromise(Listen.fromUri(uri))).toEqual(address);
  expect(keyServiceTarget(uri)).toBe(`unix:${address.path}`);
  expect(grpcBindTarget(address)).toBe(`unix://${address.path}`);
});

test.each([
  "",
  "127.0.0.1",
  ":5000",
  "::1:5000",
  "[localhost]:5000",
  "host:-1",
  "host:65536",
  "host:1.5",
  "host:NaN",
  "host:1e3",
  "host:",
  "bad host:1",
  "host:1/path",
  "host:1?x",
  "user@host:1",
  "host:1\n",
  "999.999.999.999:1",
  "-host:1",
  "a..b:1",
])("fromSops rejects malformed TCP address %j", async (address) => {
  const error = await Effect.runPromise(
    Listen.fromSops("tcp", address).pipe(Effect.flip),
  );
  expect(error.reason).toBe("InvalidAddress");
});

test.each([
  "http://localhost:5000",
  "tcp://host",
  "tcp://host:1/",
  "tcp://host:1#part",
  "tcp://user@host:1",
  "unix://host/tmp/sops.sock",
  "unix://relative.sock",
  "unix:///tmp/a?b",
  "unix:///tmp/a#b",
  "unix:///tmp/%00.sock",
  "unix:///tmp/%ZZ.sock",
])("fromUri rejects malformed URI %j", async (uri) => {
  expect(
    (await Effect.runPromise(Listen.fromUri(uri).pipe(Effect.flip))).reason,
  ).toBe("InvalidAddress");
});

test.each([-1, 65536, 1.5, NaN, Infinity])(
  "resolve rejects invalid port %s for TCP and Tailscale",
  async (port) => {
    for (const address of [
      Listen.tcp("localhost", port),
      Listen.tailscale(port),
    ]) {
      expect(
        (await run(Listen.resolve(address).pipe(Effect.flip))).reason,
      ).toBe("InvalidAddress");
    }
  },
);

test.each(["", "bad host", "[::1]", "host/path", "host\n", "a".repeat(64)])(
  "resolve rejects invalid host %j",
  async (host) => {
    expect(
      (await run(Listen.resolve(Listen.tcp(host, 5000)).pipe(Effect.flip)))
        .reason,
    ).toBe("InvalidAddress");
  },
);

test.each(["", "a\u0000b", "a\nb"])(
  "resolve and fromSops reject invalid Unix path %j",
  async (path) => {
    expect(
      (await run(Listen.resolve(Listen.unix(path)).pipe(Effect.flip))).reason,
    ).toBe("InvalidAddress");
    expect(
      (await Effect.runPromise(Listen.fromSops("unix", path).pipe(Effect.flip)))
        .reason,
    ).toBe("InvalidAddress");
  },
);

test("resolve preserves explicit TCP binding including wildcard, IPv6, and port zero", async () => {
  for (const address of [
    Listen.loopback(0),
    Listen.tcp("0.0.0.0", 65535),
    Listen.tcp("::1", 5000),
  ]) {
    expect<ListenAddress>(await run(Listen.resolve(address))).toEqual(address);
  }
});

test("a Tailscale IPv6 address qualifies only its own interface's IPv4 address", async () => {
  const options = {
    tailscaleBinary: "/missing-tailscale",
    networkInterfaces: () => ({
      lo: [addressInfo("100.64.1.1", true)],
      wlan: [
        addressInfo("192.168.1.1"),
        addressInfo("100.64.1.2"),
        addressInfo("100.63.255.255"),
        addressInfo("100.128.0.0"),
      ],
      utun7: [addressInfo("100.64.0.10"), addressInfo("fd7a:115c:a1e0::1")],
    }),
  };
  expect(await run(Listen.tailscaleAddress(options))).toBe("100.64.0.10");
  const resolved = await run(Listen.resolve(Listen.tailscale(42), options));
  expect<ListenAddress>(resolved).toEqual(Listen.tcp("100.64.0.10", 42));
  expect(keyServiceUri(resolved)).toBe("tcp://100.64.0.10:42");
});

test.each(["100.64.0.0", "100.127.255.255"])(
  "interface scanning includes CGNAT boundary %s",
  async (address) => {
    expect(
      await run(
        Listen.tailscaleAddress({
          tailscaleBinary: "/missing-tailscale",
          networkInterfaces: () => ({
            utun: [addressInfo(address), addressInfo("fd7a:115c:a1e0::1")],
          }),
        }),
      ),
    ).toBe(address);
  },
);

test.each([
  ["CGNAT only", { en0: [addressInfo("100.64.1.1")] }],
  [
    "Tailscale IPv6 on another interface",
    {
      en0: [addressInfo("100.64.1.1")],
      utun: [addressInfo("fd7a:115c:a1e0::1")],
    },
  ],
  [
    "internal Tailscale IPv6",
    {
      utun: [addressInfo("100.64.1.1"), addressInfo("fd7a:115c:a1e0::1", true)],
    },
  ],
] as const)("%s requires CLI confirmation for IPv4", async (_name, interfaces) => {
  const options = { tailscaleBinary: fake, networkInterfaces: () => interfaces };
  await withMode("ok", async () => {
    expect(await run(Listen.tailscaleAddress(options))).toBe("100.64.0.10");
  });
  await withMode("fail", async () => {
    const error = await run(Listen.tailscaleAddress(options).pipe(Effect.flip));
    expect(error.reason).toBe("TailscaleUnavailable");
    expect(error.message).toContain("exited with status 1");
  });
});

test("IPv6 discovery selects only the Tailscale /48 prefix", async () => {
  const options = {
    family: 6 as const,
    tailscaleBinary: "/missing-tailscale",
    networkInterfaces: () => ({
      utun: [
        addressInfo("fd7a:115c:a1e1::1"),
        addressInfo("fd7a:115c:a1e0::2", true),
        addressInfo("100.64.0.10"),
        addressInfo("FD7A:115C:A1E0::ABCD"),
      ],
    }),
  };
  expect(await run(Listen.tailscaleAddress(options))).toBe(
    "FD7A:115C:A1E0::ABCD",
  );
  expect<ListenAddress>(
    await run(Listen.resolve(Listen.tailscale(9, { family: 6 }), options)),
  ).toEqual(Listen.tcp("FD7A:115C:A1E0::ABCD", 9));
});

test.each([0, 2])(
  "%i candidates use CLI fallback and select the first non-empty line",
  async (count) => {
    await withMode("ok", async () => {
      const options = {
        tailscaleBinary: fake,
        networkInterfaces: () => ({
          utun: [
            addressInfo("fd7a:115c:a1e0::1"),
            ...[addressInfo("100.64.1.1"), addressInfo("100.64.1.2")].slice(
              0,
              count,
            ),
          ],
        }),
      };
      expect(await run(Listen.tailscaleAddress(options))).toBe("100.64.0.10");
    });
  },
);

test("IPv6 CLI fallback passes ip -6", () =>
  withMode("ok", async () => {
    expect(
      await run(
        Listen.tailscaleAddress({
          tailscaleBinary: fake,
          networkInterfaces: noInterfaces,
          family: 6,
        }),
      ),
    ).toBe("fd7a:115c:a1e0::1234");
  }));

test("interface discovery failure falls back to the CLI", () =>
  withMode("ok", async () => {
    expect(
      await run(
        Listen.tailscaleAddress({
          tailscaleBinary: fake,
          networkInterfaces: () => {
            throw new Error("scan failed");
          },
        }),
      ),
    ).toBe("100.64.0.10");
  }));

test.each([
  ["empty", "printed nothing"],
  ["fail", "exited with status 1"],
  ["invalid", "did not print an IPv4 address"],
  ["wrong-family", "did not print an IPv4 address"],
])("CLI %s yields helpful TailscaleUnavailable", (mode, detail) =>
  withMode(mode, async () => {
    const error = await run(
      Listen.tailscaleAddress({
        tailscaleBinary: fake,
        networkInterfaces: noInterfaces,
      }).pipe(Effect.flip),
    );
    expect(error.reason).toBe("TailscaleUnavailable");
    expect(error.message).toContain("Is Tailscale running?");
    expect(error.message).toContain(detail);
  }),
);

test("missing tailscale executable yields TailscaleUnavailable", async () => {
  const error = await run(
    Listen.tailscaleAddress({
      tailscaleBinary: "/missing-tailscale",
      networkInterfaces: noInterfaces,
    }).pipe(Effect.flip),
  );
  expect(error.reason).toBe("TailscaleUnavailable");
  expect(error.message).toContain("could not be executed");
});
