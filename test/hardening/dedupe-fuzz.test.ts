// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — dedupe/ipHash (catalog section J — feasible subset; legacy
// flows.test.ts covers tolerance in/out edges) + section K (bounded fuzz)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { decode, eth, ip4, tcp, udp } from "./helpers.ts";
import { ethHdr, ip4Hdr, makePcap, tcpPkt, PSH, ACK } from "./pcap-helpers.ts";
import { dedupePackets, decodeAllPackets, ipHash } from "../../src/engine/dedupe.ts";
import { buildFlows } from "../../src/engine/flows.ts";

// ── J: ipHash framing tolerance + representative semantics ──────────────────

describe("dedupe catalog (J)", () => {
  it("dedupe J1: the same IP packet as bare-IP and ethernet copies -> IDENTICAL ipHash (framing tolerance)", () => {
    // full ethernet frame
    const ethFrame = [tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("z"))].map(
      (f) => f,
    )[0];
    // bare-IP copy = the same bytes minus the 14-byte ethernet header
    const bare = ethFrame.subarray(14);
    const a = decode(1, ethFrame);
    const b = decode(1, Buffer.concat([Buffer.from("deadb00f1234", "hex"), bare])); // fake ethlabel
    (b as unknown as { __bytes: Buffer }).__bytes = Buffer.concat([
      Buffer.from("deadb00f1234", "hex"),
      bare,
    ]);
    (b as unknown as { __frame: number }).__frame = 1;
    (a as unknown as { __bytes: Buffer }).__bytes = ethFrame;
    void eth;
    expect(ipHash(a)).toBe(ipHash(b)); // hash starts at ipOffset → framing-neutral
  });

  it("dedupe J2: representative = FIRST member (reprIdx stable), every EPB index survives in members", () => {
    const f1 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("z"));
    const f2 = Buffer.from(f1);
    const parsed = makePcap([f1, f2], 100); // 100µs apart — inside tolerance
    const out = dedupePackets(parsed, decodeAllPackets(parsed));
    expect(out.groups).toHaveLength(1);
    expect(out.duplicatesMerged).toBe(1);
    expect(out.groups[0].reprIdx).toBe(0); // first EPB is the representative
    expect(out.groups[0].members).toEqual([0, 1]);
  });

  it("dedupe J3: a non-IP packet (arp etc.) has ipHash null and forms its OWN group", () => {
    const parsed = makePcap([
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("z")),
    ]);
    const decoded = decodeAllPackets(parsed);
    const d = decoded[0];
    (d as unknown as { __bytes: Buffer }).__bytes = parsed.packets[0].data;
    // ARP frame: ethertype 0x0806 -> no IP -> null hash
    const arpFrame = Buffer.concat([ethHdr(0x0806), ip4Hdr("10.0.0.1", "10.0.0.2", 1, 0)]);
    const arpParsed = makePcap([arpFrame]);
    const arpDecoded = decodeAllPackets(arpParsed);
    expect(ipHash(arpDecoded[0])).toBeNull();
    const out = dedupePackets(arpParsed, arpDecoded);
    expect(out.groups).toHaveLength(1); // member of a group, just never hash-merged
  });

  it("dedupe J4: tolerance compares against the REPRESENTATIVE (first) ts — chains beyond the window do NOT merge", () => {
    // t0=0, +1800µs (merge), +3600µs (outside 2000 of FIRST → new group)
    const f1 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("z"));
    const parsed = makePcap([f1, Buffer.from(f1), Buffer.from(f1)], 1800);
    const out = dedupePackets(parsed, decodeAllPackets(parsed));
    expect(out.groups).toHaveLength(2);
    expect(out.groups[0].members).toEqual([0, 1]); // 1800 ≤ 2000 after first
    expect(out.groups[1].members).toEqual([2]); // 3600 > 2000 from the rep
  });

  it("dedupe J5: tolerance edge — copies 1999µs and 2001µs apart -> merged and not merged respectively (M2 dedupe rule)", () => {
    const f = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("edge"));
    const p1999 = makePcap([f, Buffer.from(f)], 1999);
    const d1999 = dedupePackets(p1999, decodeAllPackets(p1999));
    expect(d1999.groups).toHaveLength(1);
    expect(d1999.duplicatesMerged).toBe(1);

    const p2001 = makePcap([f, Buffer.from(f)], 2001);
    const d2001 = dedupePackets(p2001, decodeAllPackets(p2001));
    expect(d2001.groups).toHaveLength(2);
    expect(d2001.duplicatesMerged).toBe(0);
  });

  it("dedupe J6: genuine retransmission (200ms apart) -> NOT merged (catalog J2)", () => {
    const f = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("retrans"));
    const p = makePcap([f, Buffer.from(f)], 200000); // 200 ms
    const out = dedupePackets(p, decodeAllPackets(p));
    expect(out.groups).toHaveLength(2);
    expect(out.duplicatesMerged).toBe(0);
  });

  it("dedupe J7: different IP payloads with identical timestamp -> distinct groups (content-based hashing)", () => {
    const f1 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("packet1"));
    const f2 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("packet2"));
    const p = makePcap([f1, f2], 0);
    const out = dedupePackets(p, decodeAllPackets(p));
    expect(out.groups).toHaveLength(2);
    expect(out.duplicatesMerged).toBe(0);
  });
});

// ── K: bounded fuzz (mulberry32 PRNG; 50k draws; prefix cuts + bit flips) ────

/** mulberry32 — deterministic PRNG from the fixture spec (no Math.random). */
function mulberry32(seed: number): () => number {
  let t = seed >>> 0;
  return () => {
    t += 0x6d2b79f5;
    let r = Math.imul(t ^ (t >>> 15), 1 | t);
    r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) >>> 0;
    return ((r ^ (r >>> 14)) >>> 0) / 0x10000 / 2 + (((r ^ (r >>> 14)) >>> 0) / 4294967296) * 0; // normalized below
  };
}

describe("fuzz catalog (K) — bounded random-input battery", () => {
  it("fuzz K1: 25k fully-random buffers (len 0..150) never throw and always return an errors ARRAY", () => {
    let t = 0xc0ffee00 >> 0;
    const rnd = (): number => {
      t += 0x6d2b79f5;
      let r = Math.imul(t ^ (t >>> 15), 1 | t);
      r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) >>> 0;
      return r / 0x100000000;
    };
    for (let i = 0; i < 25000; i++) {
      const n = Math.floor(rnd() * 151);
      const buf = Buffer.alloc(n);
      for (let j = 0; j < n; j++) buf[j] = Math.floor(rnd() * 256);
      const r = decode(1, buf);
      expect(Array.isArray(r.errors)).toBe(true);
    }
  });

  it("fuzz K2: every prefix truncation of structured frames decodes without throwing (partial state honest)", () => {
    let t = 0xfeed1234 >>> 0;
    const rnd = (): number => {
      t += 0x6d2b79f5;
      let r = Math.imul(t ^ (t >>> 15), 1 | t);
      r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) >>> 0;
      return r / 0x100000000;
    };
    const frames = [
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("payload-data")),
      Buffer.concat([
        ethHdr(0x86dd),
        (() => {
          const ip6 = Buffer.alloc(48);
          ip6[0] = 0x60;
          ip6[7] = 17;
          ip6.write('"20010db8".start', 8); // garbage-y src (never read as text)
          ip6[20 + 0] = 0x11;
          ip6[20 + 2] = 0x00;
          ip6[20 + 3] = 0x01;
          return ip6;
        })(),
      ]),
      Buffer.concat([ethHdr(0x0806), ip4Hdr("1.2.3.4", "5.6.7.8", 1, 28)]), // ARP
    ];
    let count = 0;
    for (const f of frames) {
      for (let cut = 0; cut <= f.length; cut++) {
        const r = decode(1, f.subarray(0, cut));
        expect(Array.isArray(r.errors)).toBe(true);
        count++;
      }
    }
    // plus randomized prefix cuts
    for (let i = 0; i < 5000; i++) {
      const f = frames[Math.floor(rnd() * frames.length)];
      const r = decode(1, f.subarray(0, Math.floor(rnd() * (f.length + 1))));
      expect(Array.isArray(r.errors)).toBe(true);
      count++;
    }
    expect(count).toBeGreaterThanOrEqual(3);
  });

  it("fuzz K3: single-bit flips across 5k variants never throw (decode continues or names the failure)", () => {
    const frame = tcpPkt(
      "10.0.0.1",
      1000,
      "10.0.0.2",
      443,
      PSH,
      1,
      1,
      Buffer.from("\x16\x03\x03\x00\x10" + "1".repeat(16), "latin1"),
    );
    for (let i = 0; i < 5000; i++) {
      const b = Buffer.from(frame);
      const bit = Math.floor(Math.abs(Math.sin(i) * 1e6)) % (b.length * 8);
      b[Math.floor(bit / 8)] ^= (1 << (bit % 8)) & 0xff;
      const r = decode(1, b);
      expect(Array.isArray(r.errors)).toBe(true);
    }
  });

  it("fuzz K4: deterministic — the same seed replays the identical error sequence (mulberry32 replay, catalog K)", () => {
    const run = (seed: number): string[] => {
      let t = seed >>> 0;
      const rnd = (): number => {
        t += 0x6d2b79f5;
        let r = Math.imul(t ^ (t >>> 15), 1 | t);
        r = (r + Math.imul(r ^ (r >>> 7), 61 | r)) >>> 0;
        return r / 0x100000000;
      };
      const out: string[] = [];
      for (let i = 0; i < 3000; i++) {
        const n = Math.floor(rnd() * 100);
        const buf = Buffer.alloc(n);
        for (let j = 0; j < n; j++) buf[j] = Math.floor(rnd() * 256);
        out.push(decode(1, buf).errors.join("|"));
      }
      return out;
    };
    const a = run(0xabcdef01);
    const b = run(0xabcdef01);
    expect(a).toEqual(b);
    expect(a.length).toBe(3000);
  });

  it("fuzz K5: valid packet with each length field set to 0, 1, max, max-1 -> bounded errors, never throws (catalog K5)", () => {
    const base = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH, 1, 1, Buffer.from("test"));
    const extremes = [0, 1, 65534, 65535];
    for (const val of extremes) {
      const bIp = Buffer.from(base);
      bIp.writeUInt16BE(val, 16);
      const rIp = decode(1, bIp);
      expect(Array.isArray(rIp.errors)).toBe(true);

      const uFrame = Buffer.concat([
        ethHdr(0x0800),
        ip4Hdr("10.0.0.1", "10.0.0.2", 17, 12),
        Buffer.alloc(12),
      ]);
      uFrame.writeUInt16BE(val, 14 + 20 + 4);
      const rUdp = decode(1, uFrame);
      expect(Array.isArray(rUdp.errors)).toBe(true);
    }
  });

  it("fuzz K6: round-trip property test — generated valid packets decode back to identical input fields (500 cases, catalog K6)", () => {
    let seed = 0x12345678;
    const rnd = () => {
      seed = (seed * 1664525 + 1013904223) >>> 0;
      return seed;
    };
    for (let i = 0; i < 500; i++) {
      const sport = 1024 + (rnd() % 60000);
      const dport = 1 + (rnd() % 65534);
      const seq = rnd();
      const ack = rnd();
      const ip4a = `10.${(rnd() % 254) + 1}.${(rnd() % 254) + 1}.${(rnd() % 254) + 1}`;
      const ip4b = `192.168.${(rnd() % 254) + 1}.${(rnd() % 254) + 1}`;
      const payload = Buffer.from(`data_${i}`);
      const f = tcpPkt(ip4a, sport, ip4b, dport, PSH, seq, ack, payload);
      const r = decode(1, f);
      expect(r.ip?.src).toBe(ip4a);
      expect(r.ip?.dst).toBe(ip4b);
      expect(r.transport?.sport).toBe(sport);
      expect(r.transport?.dport).toBe(dport);
      expect(r.transport?.seq).toBe(seq);
      expect(r.transport?.ack).toBe(ack);
      expect(r.errors).toHaveLength(0);
    }
  });

  it("fuzz K7: flow tracker fed a random shuffle of segments -> never throws, totals invariant (catalog K7)", () => {
    const pkts: Buffer[] = [];
    for (let i = 0; i < 10; i++) {
      pkts.push(
        tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, i * 10, 1, Buffer.alloc(10, i)),
      );
    }
    const orderly = buildFlows(makePcap(pkts), "t");
    const totalBytesOrdered = orderly.flows[0].bytes.a2b;

    let seed = 42;
    const shuffled = [...pkts].sort(() => Math.sin(seed++) - 0.5);
    const shuffledAnalysis = buildFlows(makePcap(shuffled), "t");
    expect(shuffledAnalysis.flows[0].bytes.a2b).toBe(totalBytesOrdered);
    expect(shuffledAnalysis.flows[0].uniquePackets).toBe(orderly.flows[0].uniquePackets);
  });

  it("fuzz K8: DNS parser fed random cyclic pointer graphs -> always terminates in bounded time (<100ms, catalog K8)", () => {
    let seed = 0x99999999;
    const rnd = () => {
      seed = (seed * 1103515245 + 12345) >>> 0;
      return seed;
    };
    for (let i = 0; i < 50; i++) {
      const msg = Buffer.alloc(40);
      msg.writeUInt16BE(0x1234, 0);
      msg.writeUInt16BE(0x0100, 2);
      msg.writeUInt16BE(1, 4);
      for (let j = 12; j < 38; j += 2) {
        msg[j] = 0xc0;
        msg[j + 1] = 12 + (rnd() % 26);
      }
      const t0 = Date.now();
      const r = decode(
        1,
        eth(ip4(udp(msg, { sport: 50000, dport: 53 }), { proto: 17 }), { ethertype: 0x0800 }),
      );
      const elapsed = Date.now() - t0;
      expect(elapsed).toBeLessThan(100);
      expect(Array.isArray(r.errors)).toBe(true);
    }
  });
});
