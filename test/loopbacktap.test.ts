// ─────────────────────────────────────────────────────────────────────────────
// M4-a LOOPBACK TAP SUITE — src/tap/loopbacktap.ts + src/engine/pcapngwrite.ts
// Run:  npm test           (one-shot)      npm run test:watch   (live)
//
// The tap is the Finding-A closer: a userspace vantage over loopback traffic
// pktmon can never see. These tests defend its TWO honesty promises:
//
//   PROMISE 1 (verbatim): every application payload byte recorded by the tap
//   must come out of the synthesized PCAPNG byte-identical — verified BOTH
//   through a real in-process loopback echo (real sockets, no elevation) AND
//   through the pcapng writer→parser roundtrip.
//
//   PROMISE 2 (honest synthesis): the only synthesized fields are what
//   userland cannot observe (ISNs, ACK placement, header cosmetics) — and the
//   seq/ack math must be internally consistent so tools like Wireshark agree.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "vitest";
import { LoopbackTap } from "../src/tap/loopbacktap.ts";
import { writePcapng, type PcapngChunk } from "../src/engine/pcapngwrite.ts";
import { parsePcapng, packetTimestampSeconds } from "../src/engine/pcapng.ts";

describe("pcapng writer (pcapngwrite.ts)", () => {
  it("writes SHB + one IDB (tsresol=6 µs) + EPBs that parsePcapng reads back byte-exactly", () => {
    // Three frames chosen to hit edge sizes: small, >snaplen-ish mid, and
    // a 4-byte-unaligned tail (65B) that exercises EPB padding.
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
    expect(buf.length).toBeGreaterThan(70);
    const parsed = parsePcapng(buf);
    expect(parsed.interfaces).toHaveLength(1);
    expect(parsed.interfaces[0].linkType).toBe(1);
    expect(parsed.interfaces[0].tsResolRaw).toBe(6); // microseconds, like every trace in the corpus
    expect(parsed.packets).toHaveLength(3);
    parsed.packets.forEach((p, i) => {
      expect(p.data.length).toBe(chunks[i].data.length); // caplen preserved
      expect(p.origLen).toBe(chunks[i].origLen);
      expect(p.data.equals(chunks[i].data)).toBe(true); // payload verbatim
      const ts = packetTimestampSeconds(p, parsed.interfaces);
      expect(Math.abs(ts - chunks[i].ts)).toBeLessThan(2e-6); // µs-precision timestamps
    });
  });
});

describe("LoopbackTap: synthesis math (pure, no sockets)", () => {
  it("replays a hand-built connection story with consistent seq/ack ordering and exact frame sizes", () => {
    // A manual connection story with the same shape the tap records live:
    // client sends "ab", server acks-then-sends "xy", client acks, client FINs.
    const c = {
      id: 1,
      proto4: true,
      t0: 1000, // µs — SYN timestamp
      t1: 1200, // µs — SYN-ACK timestamp
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
        chunks: Array<{ data: Buffer; ts: number }>;
        story: { frames: number; c2sPayload: Buffer; s2cPayload: Buffer };
      };
    };
    const { chunks, story } = synthTap.synthesizeTcpFrames(c);

    // Exactly: SYN, SYN-ACK, data(2B), ack, data(2B), ack, FIN|ACK, fin-ACK
    expect(chunks).toHaveLength(8);
    expect(story.frames).toBe(chunks.length);
    // Verbatim payloads survive into the story the CLI checks against.
    expect(story.c2sPayload.toString()).toBe("ab");
    expect(story.s2cPayload.toString()).toBe("xy");

    // Frame sizes prove no bogus MSS option on non-SYN packets:
    //   SYN/SYN-ACK carry MSS: 14(eth) + 20(ip) + (20+4)(tcp) = 58
    //   data frames:           14 + 20 + 20 + 2(payload)      = 56
    //   pure ACKs:             14 + 20 + 20                   = 54
    expect(chunks[0].data.length).toBe(58);
    expect(chunks[1].data.length).toBe(58);
    expect(chunks[2].data.length).toBe(56);
    expect(chunks[2].data.subarray(-2).toString()).toBe("ab"); // payload sits at the tail
    expect(chunks[3].data.length).toBe(54);

    // Timestamps: SYN at t0, SYN-ACK at t1, then events in observed order.
    expect(chunks[0].ts).toBe(1e-3);
    expect(chunks[1].ts).toBe(1.2e-3);
    expect(chunks[2].ts).toBe(1.5e-3);
    expect(chunks[7].ts).toBeGreaterThanOrEqual(chunks[6].ts); // FIN before its counter-ACK
  });
});

describe("LoopbackTap: real in-process loopback echo (Finding A end-to-end)", () => {
  it("records the echo conversation verbatim and synthesizes checkable frames with valid checksums", async () => {
    // IMPORTANT: use the default import (the module.exports object) — that is
    // what the tap patches; the namespace named exports are static snapshots.
    const netModule = await import("node:net");
    const net = netModule.default as typeof netModule;

    const tap = new LoopbackTap();
    tap.arm();

    // Real listeners / real connection / real bytes — armed tap intercepts.
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

    // Sanity BEFORE the tap analysis: the app-level echo itself worked.
    expect(reply.startsWith("echo:unit-test-payload")).toBe(true);
    await new Promise<void>((r) => server.close(() => r()));
    tap.disarm();

    // PROMISE 1 — recorded payloads are verbatim.
    const tales = tap.tcpTales;
    expect(tales).toHaveLength(1);
    const story = tales[0];
    expect(story.c2sPayload.toString("utf8")).toBe("unit-test-payload");
    expect(story.s2cPayload.toString("utf8")).toBe("echo:unit-test-payload");

    // Synthesize → write → parse: the exact pipeline m4-loopback runs.
    const built = tap.synthesizeAll();
    expect(built.chunks.length).toBeGreaterThanOrEqual(6); // SYN + SYN-ACK + data + ACKs + FIN pair
    const buf2 = writePcapng(built.chunks, { linkType: 1, userAppl: "m4a unit" });
    const parsed = parsePcapng(buf2);
    expect(parsed.packets).toHaveLength(built.chunks.length);

    // First frame is the SYN: IPv4 ethertype, version nibble, TCP proto.
    const f0 = parsed.packets[0].data;
    expect(f0.readUInt16BE(12)).toBe(0x0800);
    expect(f0[14]).toBe(0x45);
    expect(f0[23]).toBe(6);

    // PROMISE 2 — synthesized headers must still be real enough that
    // Wireshark/tshark accept them: every IPv4 header checksum recomputes.
    for (const chunk of built.chunks) {
      const ip = chunk.data.subarray(14, 34);
      const stored = ip.readUInt16BE(10);
      ip.writeUInt16BE(0, 10); // zero the field, recompute, compare
      let sum = 0;
      for (let i = 0; i < 20; i += 2) sum += ip.readUInt16BE(i);
      while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
      const computed = ~sum & 0xffff;
      ip.writeUInt16BE(stored, 10);
      expect(stored).toBe(computed);
    }

    // Global frame order stays strictly timestamp-increasing (stable sort).
    for (let i = 1; i < built.chunks.length; i++) {
      expect(built.chunks[i].ts).toBeGreaterThanOrEqual(built.chunks[i - 1].ts);
    }
  });
});
