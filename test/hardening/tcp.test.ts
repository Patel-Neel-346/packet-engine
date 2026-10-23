// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — TCP header (catalog section D, cases 1–12)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { eth, ip4, ip6, tcp, tcpOptionMss, tcpOptionWs, tcpOptionSackPermitted, tcpOptionTimestamps, decode, hasError } from "./helpers.ts";

describe("tcp catalog (D)", () => {
  it("tcp D1: ports, seq, ack, window, urgent pointer decode (RFC 9293 §3.3.1)", () => {
    const t = tcp({ sport: 51000, dport: 443, seq: 0xdeadbeef, ack: 0xcafebabe, window: 64240, urgent: 7777, flags: 0x18 });
    const r = decode(228, ip4(t));
    expect(r.transport?.sport).toBe(51000);
    expect(r.transport?.dport).toBe(443);
    expect(r.transport?.seq).toBe(0xdeadbeef);
    expect(r.transport?.ack).toBe(0xcafebabe);
    expect(r.transport?.window).toBe(64240);
    expect(r.transport?.urgentPtr).toBe(7777);
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D2: each flag alone -> exactly that flag bitmask; all 8 together -> full byte (RFC 9293 §3.3.1.1)", () => {
    const kinds: Array<[string, number]> = [
      ["CWR", 0x80], ["ECE", 0x40], ["URG", 0x20], ["ACK", 0x10],
      ["PSH", 0x08], ["RST", 0x04], ["SYN", 0x02], ["FIN", 0x01],
    ];
    for (const [name, bit] of kinds) {
      const r = decode(228, ip4(tcp({ flags: bit, sport: 9, dport: 90 })));
      expect(r.transport?.tcpFlags).toBe(bit);
      void name;
    }
    const all = decode(228, ip4(tcp({ flags: 0xff, sport: 9, dport: 90 })));
    expect(all.transport?.tcpFlags).toBe(0xff);
  });

  it("tcp D3: data offset 5 and 15 -> payload offset correct (RFC 9293 §3.3.1)", () => {
    const a = decode(228, ip4(tcp({ dataOffsetUnits: 5 }, Buffer.alloc(6, 1))));
    expect(a.transport?.payloadLen).toBe(6);
    const opts = Buffer.concat([tcpOptionMss(1460), tcpOptionWs(7), tcpOptionSackPermitted(), tcpOptionTimestamps(5, 0)]);
    const b = decode(228, ip4(tcp({ dataOffsetUnits: 15, rawOptions: opts }, Buffer.alloc(8, 2))));
    expect(b.transport?.payloadLen).toBe(8);
    expect(b.transport?.headerLen).toBe(60);
    expect(b.transport?.options?.mss).toBe(1460);
  });

  it("tcp D4a: data offset < 5 -> error 'tcp: bad data offset', ports still returned (RFC 9293 §3.3.1)", () => {
    // full 20-byte header present, but the data-offset nibble claims 16 bytes
    const t = Buffer.from(tcp({ sport: 33, dport: 330 }));
    t[12] = 0x40;
    const r = decode(228, ip4(t));
    expect(hasError(r, "tcp: bad data offset")).toBe(true);
    expect(r.transport?.sport).toBe(33); // partial decode kept
    expect(r.transport?.dport).toBe(330);
  });

  it("tcp D4b: data offset beyond captured -> error 'tcp: bad data offset', ports still returned", () => {
    // data-offset nibble claims 60 bytes with only 20 captured
    const t = Buffer.from(tcp({ sport: 34, dport: 340 }));
    t[12] = 0xf0;
    const r = decode(228, ip4(t));
    expect(hasError(r, "tcp: bad data offset")).toBe(true);
    expect(r.transport?.sport).toBe(34);
    expect(r.transport?.dport).toBe(340);
  });

  it("tcp D5a: SAS/timestamp options parsed to metadata; unknown option kind skipped by its length (RFC 9293 §3.3.1)", () => {
    const unknown = Buffer.from([0xff, 0x04, 0x00, 0x00]); // unknown kind, len 4 → skipped
    const opts = Buffer.concat([tcpOptionMss(1400), tcpOptionWs(9), tcpOptionSackPermitted(), unknown, tcpOptionTimestamps(0x1234, 0x5678)]);
    const r = decode(228, ip4(tcp({ dataOffsetUnits: 15, rawOptions: opts }, Buffer.alloc(4, 9))));
    const o = r.transport?.options;
    expect(o?.mss).toBe(1400);
    expect(o?.windowScale).toBe(9);
    expect(o?.sackPermitted).toBe(true);
    expect(o?.timestamps?.val).toBe(0x1234);
    expect(o?.timestamps?.echo).toBe(0x5678);
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D5b: option length 1 (malformed, would loop) -> error 'tcp.bad-options', bounded walk stops (RFC 793 §3.1 minimum)", () => {
    const bad = Buffer.from([2, 1]); // MSS kind with length 1 → malformed
    const r = decode(228, ip4(tcp({ dataOffsetUnits: 6, rawOptions: bad, sport: 5, dport: 55 })));
    expect(hasError(r, "tcp.bad-options")).toBe(true);
    expect(r.transport?.sport).toBe(5); // header itself still decoded
    const opt = r.transport?.options;
    expect(opt?.mss).toBeUndefined();
  });

  it("tcp D5c: option overruns the data-offset boundary -> error 'tcp.bad-options', no crash", () => {
    const bad = Buffer.from([2, 40, 1, 1]); // declared length 40 way past boundary
    const r = decode(228, ip4(tcp({ dataOffsetUnits: 6, rawOptions: bad, sport: 6, dport: 66 })));
    expect(hasError(r, "tcp.bad-options")).toBe(true);
    expect(r.errors).toHaveLength(1);
  });

  it("tcp D6: payload length derives from IP total length, NOT captured bytes, when Ethernet padding exists", () => {
    const ipPart = ip4(tcp({ sport: 21, dport: 210 }, Buffer.alloc(10, 3)));
    const padded = Buffer.concat([eth(ipPart, { ethertype: 0x0800 }), Buffer.alloc(8, 0)]);
    ipPart.writeUInt16BE(50, 2); // announce only 30 bytes of segment
    const r = decode(1, padded);
    expect(r.transport?.payloadLen).toBe(10); // from ip.totalLen(50) - 20 - 20
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D7: zero-length payload with ACK-only -> decoded, payloadLen 0 (RFC 9293 §3.3.1)", () => {
    const r = decode(228, ip4(tcp({ flags: 0x10, sport: 30, dport: 300 }, Buffer.alloc(0))));
    expect(r.transport?.kind).toBe("tcp");
    expect(r.transport?.payloadLen).toBe(0);
    expect((r.transport?.tcpFlags ?? 0) & 0x10).toBe(0x10);
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D8: checksum valid -> flag true (IPv4 + IPv6 pseudo-header); corrupted -> false, and decode continues (RFC 9293 §2.2)", () => {
    const recompute = (seg: Buffer, srcBytes: Buffer, dstBytes: Buffer, proto: number, plen: number): number => {
      let sum = 0;
      for (let i = 0; i < srcBytes.length; i += 2) sum += srcBytes.readUInt16BE(i) + dstBytes.readUInt16BE(i);
      sum += proto + (plen > 0xffff ? 0xffff : plen) + (plen > 0xffff ? 0xffff >>> 16 : 0); // hmm keep simple: plen <= 0xffff here
      for (let i = 0; i < seg.length; i += 2) sum += i + 1 < seg.length ? seg.readUInt16BE(i) : seg[i] << 8;
      while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
      return (~sum & 0xffff) >>> 0;
    };
    // IPv4 positive case
    const t4 = tcp({ sport: 40, dport: 404 }, Buffer.from("data", "ascii"));
    const ip4src = Buffer.from("0a000001", "hex"), ip4dst = Buffer.from("0a000002", "hex");
    t4.writeUInt16BE(recompute(t4, ip4src, ip4dst, 6, t4.length), 16); // TCP checksum field is at +16
    const good = decode(228, ip4(t4));
    expect(good.transport?.checksumValid).toBe(true);
    // IPv4 corrupted case: flip one payload bit → invalid, decode continues
    const badBuf = ip4(Buffer.from(t4));
    badBuf[badBuf.length - 1] ^= 1;
    const corrupt = decode(228, badBuf);
    expect(corrupt.transport?.checksumValid).toBe(false);
    expect(corrupt.transport?.sport).toBe(40);
    // IPv6 positive case (pseudo-header = src16+dst16+len32+zero24+NH)
    const t6 = tcp({ sport: 42, dport: 424 }, Buffer.from("data", "ascii"));
    const src6 = Buffer.from("20010db8000000000000000000000001", "hex");
    const dst6 = Buffer.from("20010db8000000000000000000000002", "hex");
    let s6 = 0;
    for (let i = 0; i < 16; i += 2) s6 += src6.readUInt16BE(i) + dst6.readUInt16BE(i);
    s6 += t6.length + 6; // upper-layer length (high word 0) + NH=6
    for (let i = 0; i < t6.length; i += 2) s6 += i + 1 < t6.length ? t6.readUInt16BE(i) : t6[i] << 8;
    while (s6 > 0xffff) s6 = (s6 & 0xffff) + (s6 >>> 16);
    t6.writeUInt16BE((~s6 & 0xffff) >>> 0, 16); // TCP checksum field is at +16
    const good6 = decode(228, ip6(t6, { nh: 6 }));
    expect(good6.transport?.checksumValid).toBe(true);
  });

  it("tcp D8b: UDP-style checksum 0 remains mandatory for TCP — stored 0 never counts as valid (RFC 9293 §2.2)", () => {
    // tcp() helper emits checksum 0 → verifyTransportChecksum must report invalid
    const r = decode(228, ip4(tcp({ sport: 41, dport: 414 }, Buffer.alloc(4, 7))));
    expect(r.transport?.checksumValid).toBe(false);
  });

  it("tcp D9a: header split at exactly 19 captured bytes -> error, no throw (truncation boundary)", () => {
    const r = decode(228, ip4(tcp({ sport: 50, dport: 500 }).subarray(0, 19)));
    expect(hasError(r, "tcp: header truncated")).toBe(true);
    expect(r.transport?.sport).toBeUndefined(); // header incomplete: ports not fabricated
  });

  it("tcp D9b: header split at exactly 20 captured bytes -> complete header, decoded", () => {
    const r = decode(228, ip4(tcp({ sport: 51, dport: 510 }).subarray(0, 20)));
    expect(r.transport?.sport).toBe(51);
    expect(r.transport?.payloadLen).toBe(0); // from IP-totalLength math (23→0)
    // NOTE: the IP totalLen announced by ip4() here equals 20+0 = 40? No: 20-byte TCP
    // ⇒ totalLen 40; captured 40. payloadLen = 0.
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D10: port 0 -> decodes cleanly with no error and no warning-side-effect (documented rule)", () => {
    const r = decode(228, ip4(tcp({ sport: 0, dport: 0, flags: 0x10, seq: 5 })));
    expect(r.transport?.sport).toBe(0);
    expect(r.transport?.dport).toBe(0); // ports recorded as-is, no fabrication
    expect(r.errors).toHaveLength(0);
  });

  it("tcp D11: seq and ack 0xFFFFFFFF decode as unsigned (no negatives) (RFC 9293 §3.3.3)", () => {
    const r = decode(228, ip4(tcp({ seq: 0xffffffff, ack: 0xffffffff, sport: 60, dport: 600 })));
    expect(r.transport?.seq).toBe(4294967295);
    expect(r.transport?.ack).toBe(4294967295);
    expect(r.transport?.seq).toBeGreaterThan(0);
  });

  it("tcp D12: segment inside the FIRST fragment of a fragmented datagram -> decoded AND flagged fragmented (RFC 791 §3.2)", () => {
    const r = decode(1, eth(ip4(tcp({ sport: 70, dport: 700 }) as Buffer, { id: 55, flags: 1, frag: 0 }), { ethertype: 0x0800 }));
    expect(r.ip?.fragment?.moreFragments).toBe(true);
    expect(r.ip?.fragment?.id).toBe(55);
    expect(r.transport?.sport).toBe(70); // first fragment carries the header
  });
});
