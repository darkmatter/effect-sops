import { createInterface } from "node:readline";

export interface Stanza {
  readonly type: string;
  readonly args: ReadonlyArray<string>;
  readonly body: Uint8Array;
}

// An independent fixture codec catches mistakes shared by client reads/writes.
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity })[
  Symbol.asyncIterator
]();

export const read = async (): Promise<Stanza> => {
  const header = await lines.next();
  if (header.done || !/^-> [!-~]+(?: [!-~]+)*$/.test(header.value))
    throw new Error("Invalid fixture input header");
  const [type, ...args] = header.value.slice(3).split(" ");
  if (!type) throw new Error("Missing fixture input type");
  let encoded = "";
  for (;;) {
    const line = await lines.next();
    if (
      line.done ||
      line.value.length > 64 ||
      !/^[A-Za-z0-9+/]*$/.test(line.value)
    )
      throw new Error("Invalid fixture input body");
    encoded += line.value;
    if (line.value.length < 64) break;
  }
  const body = Buffer.from(encoded, "base64");
  if (body.toString("base64").replace(/=+$/, "") !== encoded)
    throw new Error("Non-canonical fixture input body");
  return { type, args, body };
};

export const write = (
  type: string,
  args: ReadonlyArray<string> = [],
  body: Uint8Array | string = new Uint8Array(),
): void => {
  const encoded = Buffer.from(body).toString("base64").replace(/=+$/, "");
  const chunks: string[] = [];
  for (let offset = 0; offset < encoded.length; offset += 64)
    chunks.push(encoded.slice(offset, offset + 64));
  if (encoded.length % 64 === 0) chunks.push("");
  process.stdout.write(
    `-> ${[type, ...args].join(" ")}\n${chunks.join("\n")}\n`,
  );
};

export const exchange = async (
  type: string,
  args: ReadonlyArray<string> = [],
  body: Uint8Array | string = new Uint8Array(),
): Promise<Stanza> => {
  write(type, args, body);
  return read();
};

export const expectReply = (reply: Stanza, type: string, args = ""): void => {
  if (reply.type !== type || reply.args.join(" ") !== args)
    throw new Error("Unexpected client acknowledgement");
};

export const waitForEof = async (): Promise<void> => {
  for await (const _line of { [Symbol.asyncIterator]: () => lines }) {
    throw new Error("Unexpected input after done");
  }
};
