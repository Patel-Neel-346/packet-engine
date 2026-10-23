// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — UDP + ICMP/ICMPv6 (catalog section E, cases 1–6)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { eth, ip4, ip6, udp, decode, hasError } from "./helpers.ts";

/** Recompute a UDP checksum over the v4 or v6 pseudo-header and store it. */
function setUdpChecksum(seg: Buffer, version: 4 | 6, srcHex: string, dstHex: string, proto: number): void {
  let sum = 0;
  const src = Buffer.from(srcHex, "hex");
  const dst = Buffer.from(dstHex, "hex");
  if (version === 4) {
    for (let i = 0; i < 4; i += 2) sum += src.readUInt16BE(i) + dst.readUInt16BE(i);
    sum += proto + seg.length;
  } else {
    for (let i = 0; i < 16; i += 2) sum += src.readUInt16BE(i) + dst.readUInt16BE(i);
    sum += seg.length + proto; // upper-layer length high word = 0 (≤ 0xffff)
  }
  for (let i = 0; i < seg.length; i += 2) sum += i + 1 < seg.length ? seg.readUInt16BE(i) : seg[i] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  seg.writeUInt16BE((~sum & 0xffff) >>> 0, 6); // UDP checksum field is at +6
}

describe("udp catalog (E1, E2)", () => {
  it("udp E1a: ports + declared datagram length decode; payload length = len - 8 (RFC 768 §3)", () => {
    const u = udp(Buffer.from("hello", "ascii"), { sport: 51000, dport: 51001 }); // len 13
    const r = decode(228, ip4(u, { proto: 17 }));
    expect(r.transport?.sport).toBe(51000);
    expect(r.transport?.dport).toBe(51001);
    expect(r.transport?.payloadLen).toBe(5);
    expect(r.errors).toHaveLength(0);
  });

  it("udp E1b: declared length 1-7 -> error 'udp.bad-length' (RFC 768 minimum is 8)", () => {
    const u = udp(Buffer.alloc(6, 7), { sport: 60, dport: 610, lenOverride: 5 });
    const r = decode(228, ip4(u, { proto: 17 }));
    expect(hasError(r, "udp.bad-length")).toBe(true);
    expect(r.transport?.sport).toBe(60); // partial decode kept
    expect(r.transport?.dport).toBe(610);
  });

  it("udp E1c: declared length beyond captured -> error 'udp.truncated', partial fields kept", () => {
    const u = udp(Buffer.alloc(4), { sport: 61, dport: 611, lenOverride: 300 });
    const r = decode(228, ip4(u, { proto: 17 }));
    expect(hasError(r, "udp.truncated")).toBe(true);
    expect(r.transport?.sport).toBe(61);
    expect(r.transport?.payloadLen).toBe(4); // capped to captured, never invented
  });

  it("udp E1d: declared length 0 -> tolerated as the IPv6 jumbogram convention (RFC 2675 §3.1, documented)", () => {
    const a = decode(228, ip4(udp(Buffer.alloc(4), { lenOverride: 0, sport: 62, dport: 612 }), { proto: 17 }));
    expect(a.transport?.payloadLen).toBe(0);
    expect(a.errors).toHaveLength(0); // documented leniency on IPv4
    const b = decode(228, ip6(udp(Buffer.alloc(4), { lenOverride: 0, sport: 63, dport: 613 }), { nh: 17 }));
    expect(b.transport?.payloadLen).toBe(0);
    expect(b.errors).toHaveLength(0);
  });

  it("udp E2a: correct checksum over IPv4 pseudo-header -> checksumValid true (RFC 768 §4)", () => {
    const u = udp(Buffer.from("abcd", "ascii"), { sport: 7, dport: 70 });
    setUdpChecksum(u, 4, "0a000001", "0a000002", 17);
    const r = decode(228, ip4(u, { proto: 17 }));
    expect(r.transport?.checksumValid).toBe(true);
    expect(r.transport?.checksumZero ?? false).toBe(false);
  });

  it("udp E2b: checksum 0 over IPv4 -> ALLOWED (RFC 768), flagged via checksumZero (catalog E2)", () => {
    const u = udp(Buffer.from("abcd", "ascii"), { sport: 8, dport: 80 });
    u.writeUInt16BE(0, 6);
    const r = decode(228, ip4(u, { proto: 17 }));
    expect(r.transport?.checksumZero).toBe(true);
    expect(r.transport?.checksumValid).toBe(true); // RFC 768 allows 0 on IPv4
  });

  it("udp E2c: checksum 0 over IPv6 -> flagged as a DEFECT (RFC 8200 §8.1 requires the checksum)", () => {
    const u = udp(Buffer.from("abcd", "ascii"), { sport: 9, dport: 90 });
    u.writeUInt16BE(0, 6);
    const r = decode(228, ip6(u, { nh: 17 }));
    expect(r.transport?.checksumZero).toBe(true);
    expect(r.transport?.checksumValid).toBe(false);
  });

  it("udp E2d: corrupted checksum over IPv6 -> checksumValid false, decode continues", () => {
    const u = udp(Buffer.from("abcd", "ascii"), { sport: 10, dport: 100 });
    setUdpChecksum(u, 6, "20010db8000000000000000000000001", "20010db8000000000000000000000002", 17);
    u[u.length - 1] ^= 1; // flip a payload bit
    const r = decode(228, ip6(u, { nh: 17 }));
    expect(r.transport?.checksumValid).toBe(false);
    expect(r.transport?.sport).toBe(10); // decode not blocked
  });
});

describe("icmp catalog (E3–E6)", () => {
  const icmp = (body: Buffer): Buffer => {
    const b = Buffer.concat([Buffer.alloc(0), body]);
    return b;
  };
  const frame4 = (body: Buffer) => decode(228, ip4(body, { proto: 1 }));
  const frame6 = (body: Buffer) => decode(228, ip6(body, { nh: 58 }));

  it("icmp E3a: echo request (type 8 code 0) -> type/code/id/seq decoded as metadata (RFC 792)", () => {
    const body = Buffer.alloc(8 + 12);
    body[0] = 8; body[1] = 0;
    body.writeUInt16BE(0x9abc, 4); // echo id
    body.writeUInt16BE(0x0100, 6); // seq
    const r = frame4(icmp(body));
    expect(r.transport?.kind).toBe("icmp");
    expect(r.transport?.icmpType).toBe(8);
    expect(r.transport?.icmpCode).toBe(0);
    expect(r.transport?.icmpEchoId).toBe(0x9abc);
    expect(r.transport?.icmpEchoSeq).toBe(0x0100);
    expect(r.errors).toHaveLength(0);
  });

  it("icmp E3b: echo reply (type 0) -> id/seq decoded (RFC 792)", () => {
    const body = Buffer.alloc(10);
    body[0] = 0; body[1] = 0;
    body.writeUInt16BE(0x55aa, 4);
    body.writeUInt16BE(2, 6);
    const r = frame4(icmp(body));
    expect(r.transport?.icmpType).toBe(0);
    expect(r.transport?.icmpEchoId).toBe(0x55aa);
    expect(r.transport?.icmpEchoSeq).toBe(2);
  });

  it("icmp E3c: destination unreachable (type 3) -> type/code decoded; embedded original header stays UNDECODED (documented v1 limit)", () => {
    const body = Buffer.alloc(4 + 28);
    body[0] = 3; body[1] = 3; // port unreachable
    // embedded "original datagram" follows — deliberately not dissected in v1
    body[12] = 0x45; // an embedded IPv4 header pattern
    const r = frame4(icmp(body));
    expect(r.transport?.icmpType).toBe(3);
    expect(r.transport?.icmpCode).toBe(3);
    expect(r.transport?.icmpEchoId).toBeUndefined(); // not an echo class
    expect(Array.isArray(r.errors)).toBe(true); // no throw; no phantom fields
  });

  it("icmp E4: ICMPv6 echo request/reply (128/129) -> type/code + echo id/seq (RFC 4443 §4.1)", () => {
    for (const ty of [128, 129]) {
      const body = Buffer.alloc(10);
      body[0] = ty; body[1] = 0;
      body.writeUInt16BE(0x77, 4);
      body.writeUInt16BE(9, 6);
      const r = frame6(icmp(body));
      expect(r.transport?.kind).toBe("icmpv6");
      expect(r.transport?.icmpType).toBe(ty);
      expect(r.transport?.icmpEchoId).toBe(0x77);
      expect(r.transport?.icmpEchoSeq).toBe(9);
    }
  });

  it("icmp E5a: ICMP truncated below type+code -> error 'icmp.truncated', no throw (RFC 792 §2)", () => {
    const r = frame4(icmp(Buffer.from([8, 0]))); // 2 bytes: no code pair
    expect(hasError(r, "icmp.truncated")).toBe(true);
    expect(r.transport?.icmpType).toBe(8); // the one byte we did get
    expect(r.transport?.icmpCode).toBeUndefined();
  });

  it("icmp E5b: ICMPv6 truncated below type+code -> error 'icmpv6.truncated' (RFC 4443 §2.1)", () => {
    const r = frame6(icmp(Buffer.alloc(2)));
    expect(hasError(r, "icmpv6.truncated")).toBe(true);
    expect(Array.isArray(r.errors)).toBe(true);
  });

  it("icmp E6: ICMP inside the fragment stream (first fragment) -> decoded and pair-consistent (design note, s8 parity rule)", () => {
    // First ICMP fragment (offset 0, MF set) decodes normally: ICMP is not
    // subject to the TCP/UDP non-first-fragment rule (its flow pairing is
    // port-free — documented engine design verified against the s8 corpus).
    const ipPart = ip4(icmp(Buffer.alloc(8, 1)), { proto: 1, id: 5, flags: 1, frag: 0 });
    const r = decode(1, eth(ipPart, { ethertype: 0x0800 }));
    expect(r.transport?.kind).toBe("icmp");
    expect(r.ip?.fragment?.moreFragments).toBe(true);
  });
});
