// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — IPv4 (catalog section B, cases 1–14)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import {
  eth, ip4, tcp, udp, decode, hasError, hasError as hasCode,
} from "./helpers.ts";

describe("ipv4 catalog (B)", () => {
  it("ipv4 B1: valid header -> addresses, TTL, protocol, total length, identification, checksum flag (RFC 791 §3.1)", () => {
    const r = decode(1, eth(ip4(tcp({ sport: 77, dport: 7700 })), { ethertype: 0x0800 }));
    expect(r.ip?.src).toBe("10.0.0.1");
    expect(r.ip?.dst).toBe("10.0.0.2");
    expect(r.ip?.ttlHop).toBe(64);
    expect(r.ip?.proto).toBe(6);
    expect(r.ip?.totalLen).toBe(40);
    expect(r.ip?.id).toBe(0x1234);
    expect(r.ip?.checksumValid).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv4 B2a: IHL=4 (<20 bytes) -> error 'ipv4: bad IHL', no throw, no IP fields returned (RFC 791 §3.1)", () => {
    const r = decode(228, ip4(tcp(), { ihl: 16 }));
    expect(hasError(r, "ipv4: bad IHL")).toBe(true);
    expect(r.ip).toBeUndefined(); // header length is unusable
  });

  it("ipv4 B2b: IHL=5 -> OK; IHL=15 (60B header with options) -> OK with options length 40", () => {
    const ok5 = decode(228, ip4(Buffer.alloc(0)));
    expect(ok5.ip?.headerLen).toBe(20);
    const big = ip4(tcp({ sport: 5, dport: 50 }), { ihl: 60 });
    const ok15 = decode(228, big);
    expect(ok15.ip?.headerLen).toBe(60);
    expect(ok15.transport?.sport).toBe(5); // payload offset after 60-byte header
    expect(ok15.errors).toHaveLength(0);
  });

  it("ipv4 B3: options present -> payload (L4) starts after the options block (RFC 791 §3.1.2)", () => {
    // 24-byte header (IHL 6): 20 base + 4 option bytes (EOL pad)
    const r = decode(228, ip4(Buffer.alloc(20), { ihl: 24 }));
    expect(r.ip?.headerLen).toBe(24);
    const r2 = decode(228, Buffer.concat([
      Buffer.from([0x46, 0x00, 0x00, 0x2a, 0, 0, 0x40, 0x00, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 9, 0, 0, 0]),
      tcp({ sport: 8, dport: 80 }),
      Buffer.alloc(0),
    ]));
    expect(r2.ip?.headerLen).toBe(24);
    expect(r2.transport?.sport).toBe(8);
    expect(hasError(r2, "ipv4: bad IHL")).toBe(false);
  });

  it("ipv4 B4: total length > captured bytes -> error 'ipv4.truncated', partial L3 fields kept (RFC 791 §3.1)", () => {
    // build with proper bytes, then lie about totalLen via a direct buffer patch
    const buf = ip4(tcp({ sport: 31, dport: 3100 }));
    buf.writeUInt16BE(9999, 2);
    const r = decode(1, eth(buf, { ethertype: 0x0800 }));
    expect(hasCode(r, "ipv4.truncated")).toBe(true);
    // partial decode retained
    expect(r.ip?.src).toBe("10.0.0.1");
    expect(r.transport?.sport).toBe(31);
    expect(Array.isArray(r.errors)).toBe(true);
  });

  it("ipv4 B5: total length < IHL*4 (nonzero) -> error 'ipv4.bad-total-length' (RFC 791 §3.1)", () => {
    const buf = ip4(tcp({ sport: 9, dport: 90 }));
    buf.writeUInt16BE(10, 2); // bogus but nonzero
    const r = decode(1, eth(buf, { ethertype: 0x0800 }));
    expect(hasCode(r, "ipv4.bad-total-length")).toBe(true);
    expect(r.ip?.payloadLen).toBeLessThan(1);
  });

  it("ipv4 B6: total length < captured (Ethernet padding) -> trailing pad NOT counted as payload (RFC 894 §3.2.1)", () => {
    // eth + ip(42B) + tcp(22B: header 20 + 2 payload) + 6 pad bytes; IP
    // announces only 42 → the 6 trailing pad bytes must be ignored.
    const ip = ip4(Buffer.concat([
      tcp({ sport: 2000, dport: 80, flags: 0x18 }, Buffer.alloc(2, 9)),
    ])); // total 20+22=42
    const padded = Buffer.concat([eth(ip, { ethertype: 0x0800 }), Buffer.alloc(6, 0x00)]);
    ip.writeUInt16BE(42, 2); // re-assert: announce only 42 bytes
    const r = decode(1, padded);
    expect(r.ip?.totalLen).toBe(42);
    expect(r.transport?.payloadLen).toBe(2); // exactly ip.totalLen-derived, pad excluded
    expect(r.errors).toHaveLength(0);
  });

  it("ipv4 B7: version nibble not 4 (0x55) on a bare frame -> error, no throw (RFC 791 §3.1)", () => {
    const r = decode(228, Buffer.from([0x55, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2]));
    expect(r.ip).toBeUndefined();
    expect(r.errors.length).toBeGreaterThan(0);
  });

  it("ipv4 B8: checksum valid -> flag true; one flipped bit -> flag false but decode CONTINUES (RFC 791)", () => {
    const good = decode(228, ip4(tcp({ sport: 3, dport: 30 })));
    expect(good.ip?.checksumValid).toBe(true);
    const buf = ip4(tcp({ sport: 3, dport: 30 }), { corruptChecksum: true });
    const bad = decode(1, eth(buf, { ethertype: 0x0800 }));
    expect(bad.ip?.checksumValid).toBe(false);
    expect(bad.transport?.sport).toBe(3); // decode not blocked by a checksum lie
  });

  it("ipv4 B9a: first fragment (MF=1, offset 0) -> transport decoded AND fragment metadata present (RFC 791 §3.2)", () => {
    const frame = eth(ip4(
      tcp({ sport: 60, dport: 600, flags: 0x18 }, Buffer.alloc(8, 0xaa)),
      { id: 99, flags: 1, frag: 0 },
    ), { ethertype: 0x0800 });
    const r = decode(1, frame);
    expect(r.ip?.fragment?.moreFragments).toBe(true);
    expect(r.ip?.fragment?.offsetBytes).toBe(0);
    expect(r.transport?.sport).toBe(60); // the L4 header IS inside this fragment
  });

  it("ipv4 B9b: middle fragment (MF=1, offset > 0) -> NO L4 decode (metadata only); tcp ports absent (no reassembly in v1)", () => {
    // 24 bytes of data-blob at fragment offset 0x10*8=128 — no L4 header exists here
    const ipFrag = ip4(Buffer.alloc(24, 0x5a), { proto: 6, id: 77, flags: 1, frag: 16 });
    const frame = eth(ipFrag, { ethertype: 0x0800 });
    const r = decode(1, frame);
    expect(r.ip?.fragment?.offsetBytes).toBe(128);
    expect(r.ip?.fragment?.moreFragments).toBe(true);
    expect(r.transport?.sport).toBeUndefined(); // ports never fabricated
    expect(r.transport?.kind).toBe("other");
  });

  it("ipv4 B9c: last fragment (MF=0, offset > 0) -> metadata only, unique-host bytes intact", () => {
    const r = decode(1, eth(ip4(Buffer.alloc(16, 0xbb), { proto: 17, id: 78, flags: 0, frag: 4 }), { ethertype: 0x0800 }));
    expect(r.ip?.fragment?.moreFragments).toBe(false);
    expect(r.ip?.fragment?.offsetBytes).toBe(32);
    expect(r.transport?.kind).toBe("other");
  });

  it("ipv4 B10: DF flag set -> recorded; reserved bit set -> still decoded, metadata kept (RFC 791/9293 note)", () => {
    const df = decode(228, ip4(tcp({ sport: 5, dport: 50 }), { flags: 2 })); // DF bit
    expect(df.ip?.fragment?.dontFragment).toBe(true);
    const resv = decode(228, ip4(tcp({ sport: 6, dport: 60 }), { flags: 4 })); // reserved EVIL bit
    expect(resv.ip?.src).toBe("10.0.0.1"); // reserved bit never blocks decode
    expect(resv.errors).toHaveLength(0);
  });

  it("ipv4 B11: fragment offset + length overflow past 65535 -> fragment byte-offset recorded as-is, no throw (RFC 791)", () => {
    const r = decode(228, ip4(Buffer.alloc(20), { flags: 0, frag: 8181 }), 20);
    expect(r.ip?.fragment?.offsetBytes).toBe(8181 * 8); // 65448 (decoder records truth, never reassembles)
    expect(Array.isArray(r.errors)).toBe(true);
  });

  it("ipv4 B12: fragments out of order -> each fragment described independently, no silent reassembly (v1 documented limit)", () => {
    const last = decode(228, ip4(Buffer.alloc(12, 1), { id: 5, proto: 17, flags: 0, frag: 20 }));
    const first = decode(228, ip4(udp(Buffer.alloc(4)), { id: 5, proto: 17, flags: 1, frag: 0 }));
    expect(last.ip?.fragment?.offsetBytes).toBe(160);
    expect(first.ip?.fragment?.moreFragments).toBe(true);
    // v1 never reassembles: the LAST fragment carries no L4 header at all…
    expect(last.transport?.sport).toBeUndefined();
    expect(last.transport?.kind).toBe("other");
    // …while the FIRST fragment legitimately contains the UDP header (B9a).
    expect(first.transport?.kind).toBe("udp");
    expect(first.transport?.sport).toBe(4000);
  });

  it("ipv4 B13a: TTL=0 -> decodes with TTL recorded (RFC 791)", () => {
    const r = decode(228, ip4(tcp({ sport: 4, dport: 40 }), { ttl: 0 }));
    expect(r.ip?.ttlHop).toBe(0);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv4 B13b: TTL=255 -> decodes with TTL recorded (RFC 791)", () => {
    const r = decode(228, ip4(tcp({ sport: 4, dport: 40 }), { ttl: 255 }));
    expect(r.ip?.ttlHop).toBe(255);
  });

  it("ipv4 B14: protocol numbers 1/6/17/47/50/89 -> kind mapped, others carry the proto number (RFC 790)", () => {
    const l4 = (p: number): Buffer => p === 6 ? tcp({ sport: 3, dport: 33 }) : p === 17 ? udp(Buffer.alloc(2)) : Buffer.alloc(8);
    const proto = (p: number) => decode(228, ip4(l4(p), { proto: p })).transport;
    expect(proto(1)?.kind).toBe("icmp");
    expect(proto(6)?.kind).toBe("tcp");
    expect(proto(17)?.kind).toBe("udp");
    const gre = proto(47); // GRE
    expect(gre?.kind).toBe("other");
    expect(gre?.proto).toBe(47);
    expect(proto(50)?.proto).toBe(50); // ESP
    expect(proto(89)?.proto).toBe(89); // OSPF
  });
});
