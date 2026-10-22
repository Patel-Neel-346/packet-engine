// M4-a tests: loopback tap synthesis + pcapng writer roundtrip.
// Unit-level (pure math) + one real in-process loopback scenario (fast, no
// elevation, no external traffic).

import test from "node:test";
import assert from "node:assert/strict";
import { LoopbackTap } from "../src/loopbacktap.ts";
import { writePcapng, type PcapngChunk } from "../src/pcapngwrite.ts";
import { parsePcapng, packetTimestampSeconds } from "../src/pcapng.ts";

test("pcapng writer: SHB+IDB+EPBs roundtrip through parsePcapng", () => {
  const mkFrame = (len: number, fill: number): Buffer => {
    const b = Buffer.alloc(len, fill);
    b[0] = 0xff; b[1] = 0x02; // dst mac prefix (realistic-ish)
    b[12] = 0x08; b[13] = 0x00; // ethertype IPv4
    return b;
  };
  const chunks: PcapngChunk[] = [
    { data: mkFrame(60, 0x11), origLen: 60, ts: 1792800000 + 0.001 },
    { data: mkFrame(1514, 0x22), origLen: 1514, ts: 1792800000 + 0.0025 },
    { data: mkFrame(65, 0x33), origLen: 65, ts: 1792800000 + 1 },
  ];
  const buf = writePcapng(chunks, { linkType: 1, userAppl: "m4a test" });
  assert.ok(buf.length > 70, "must produce a nontrivial buffer");
  const parsed = parsePcapng(buf);
  assert.equal(parsed.interfaces.length, 1, "exactly one IDB");
  assert.equal(parsed.interfaces[0].linkType, 1);
  assert.equal(parsed.interfaces[0].tsResolRaw, 6, "if_tsresol=6 (us)");
  assert.equal(parsed.packets.length, 3);
  parsed.packets.forEach((p, i) => {
    assert.equal(p.data.length, chunks[i].data.length, "caplen preserved");
    assert.equal(p.origLen, chunks[i].origLen, "origLen preserved");
    assert.ok(p.data.equals(chunks[i].data), "payload verbatim");
    const ts = packetTimestampSeconds(p, parsed.interfaces);
    assert.ok(Math.abs(ts - chunks[i].ts) < 2e-6, "us-precision timestamp");
  });
});

test("tap: real in-process loopback TCP echo is observed verbatim and synthesizes consistent frames", async () => {
  // IMPORTANT: use the default import (the module.exports object) — that is
  // what the tap patches; the namespace named exports are static snapshots.
  const netModule = await import("node:net");
  const net = netModule.default as typeof netModule;
  const tap = new LoopbackTap();
  tap.arm();
  const port = 47888 + Math.floor(Math.random() * 2000);
  const server = net.createServer((sock) => {
    sock.on("data", (c: Buffer) => {
      sock.write(Buffer.concat([Buffer.from("echo:"), c]));
      sock.end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve());
  });

  const reply: string = await new Promise((resolve) => {
    const s = net.createConnection({ host: "127.0.0.1", port });
    s.on("connect", () => s.write("unit-test-payload"));
    let buf = Buffer.alloc(0);
    s.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
    });
    s.on("close", () => resolve(buf.toString("utf8")));
    s.on("error", () => resolve("error"));
    setTimeout(() => resolve("timeout"), 4000);
  });
  assert.ok(reply.startsWith("echo:unit-test-payload"), "echo app-level roundtrip");
  await new Promise<void>((r) => server.close(() => r()));
  tap.disarm();

  const tales = tap.tcpTales;
  assert.equal(tales.length, 1, "one connection observed");
  const story = tales[0];
  assert.equal(story.c2sPayload.toString("utf8"), "unit-test-payload", "c2s bytes verbatim");
  assert.equal(story.s2cPayload.toString("utf8"), "echo:unit-test-payload", "s2c bytes verbatim");

  // synthesize + write + parse
  const built = tap.synthesizeAll();
  assert.equal(built.chunks.length >= 6, true, "SYN + SYN-ACK + data + acks + FIN pairs");
  const buf2 = writePcapng(built.chunks, { linkType: 1, userAppl: "m4a unit" });
  const parsed = parsePcapng(buf2);
  assert.equal(parsed.packets.length, built.chunks.length);
  // first frame is the SYN: ethertype=IPv4 and IPv4 proto=TCP at byte 14+9
  const f0 = parsed.packets[0].data;
  assert.equal(f0.readUInt16BE(12), 0x0800);
  assert.equal(f0[14], 0x45);
  assert.equal(f0[23], 6, "IPv4 protocol = TCP");
  // all frames carry a valid IPv4 header checksum (recomputable with 0 at sum)
  for (const chunk of built.chunks) {
    const ip = chunk.data.subarray(14, 34);
    const stored = ip.readUInt16BE(10);
    ip.writeUInt16BE(0, 10);
    let sum = 0;
    for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    const computed = ~sum & 0xffff;
    ip.writeUInt16BE(stored, 10);
    assert.equal(stored, computed, "IPv4 checksum correct");
  }
  // timestamps strictly increasing
  for (let i = 1; i < built.chunks.length; i++) {
    assert.ok(built.chunks[i].ts >= built.chunks[i - 1].ts, "stable frame order");
  }
});

test("tap: synthesis seq/ack math is internally consistent", () => {
  // Manual connection story (same shape the tap records), synthesized directly.
  const c = {
    id: 1,
    proto4: true,
    t0: 1000, // us
    t1: 1200, // us (SYN-ACK)
    clientIp: "127.0.0.1",
    clientPort: 11000,
    serverIp: "127.0.0.1",
    serverPort: 41000,
    events: [
      { k: "tx", ts: 1500, dir: "c2s", payload: Buffer.from("ab") },
      { k: "ackObs", ts: 1600, dir: "s2c" },
      { k: "tx", ts: 1700, dir: "s2c", payload: Buffer.from("xy") },
      { k: "ackObs", ts: 1800, dir: "c2s" },
      { k: "fin", ts: 1900, dir: "c2s" },
    ],
    c2sData: Buffer.from("ab"),
    s2cData: Buffer.from("xy"),
    ends: [{ dir: "c2s", ts: 1900 }],
    resets: 0,
    finalized: true,
  };
  const synthTap = new LoopbackTap() as unknown as {
    synthesizeTcpFrames(c: unknown): {
      chunks: Array<{
        data: Buffer;
        ts: number;
      }>;
      story: { frames: number; c2sPayload: Buffer; s2cPayload: Buffer };
    };
  };
  const { chunks, story } = synthTap.synthesizeTcpFrames(c);
  // SYN, SYN-ACK, data(2B), ack, data(2B), ack, FIN|ACK, fin-ACK
  assert.equal(chunks.length, 8);
  assert.equal(story.frames, chunks.length);
  assert.equal(story.c2sPayload.toString(), "ab");
  assert.equal(story.s2cPayload.toString(), "xy");
  // sizes: SYN/SYN-ACK carry MSS: 14+20+(20+4)=58; data frames 56; FIN pair 54
  assert.equal(chunks[0].data.length, 58);
  assert.equal(chunks[1].data.length, 58);
  assert.equal(chunks[2].data.length, 56, "first data frame carries verbatim 2B");
  assert.equal(chunks[2].data.subarray(-2).toString(), "ab", "c2s payload positioned at tail");
  assert.equal(chunks[3].data.length, 54, "pure ACK");
  // timestamps: SYN at t0, SYN-ACK at t1, then events in order
  assert.equal(chunks[0].ts, 1e-3);
  assert.equal(chunks[1].ts, 1.2e-3);
  assert.equal(chunks[2].ts, 1.5e-3);
  assert.ok(chunks[7].ts >= chunks[6].ts, "fin then counter-ACK in order");
});
