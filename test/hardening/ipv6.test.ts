// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — IPv6 (catalog section C, cases 1–14)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { ip6, tcp, decode, hasError, type ExtSpec } from "./helpers.ts";

describe("ipv6 catalog (C)", () => {
  it("ipv6 C1: valid header -> addresses, hop limit, next header, traffic class, flow label (RFC 8200 §3)", () => {
    const b = ip6(tcp({ sport: 9, dport: 90 }), {
      hopLimit: 255,
      src: "fe800000000000000000000000000005",
    });
    b[1] = 0x30;
    b.writeUInt16BE(0x04d2, 2); // TC nibble 3, flow label 0x04d2
    const r = decode(228, b);
    expect(r.ip?.version).toBe(6);
    expect(r.ip?.src).toBe("fe80::5");
    expect(r.ip?.ttlHop).toBe(255);
    expect(r.ip?.proto).toBe(6);
    expect(r.ip?.trafficClass).toBe(3);
    expect(r.ip?.flowLabel).toBe(0x04d2);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C2: payload length > captured -> truncation error, partial IP fields kept (RFC 8200 §3.5)", () => {
    const b = ip6(tcp({ sport: 7, dport: 79 }), { payloadLenOverride: 9999 });
    const r = decode(228, b);
    expect(hasError(r, "ipv6.truncated")).toBe(true);
    expect(r.ip?.src).toBe("2001:db8::1");
    expect(r.transport?.sport).toBe(7); // partial decode retained
  });

  it("ipv6 C3: payload length 0 with hop-by-hop (jumbogram convention) -> documented v1 limit: L3+L4 decoded, payloadLen stays 0 (RFC 2675 §3)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 8, dport: 80 }), {
        exts: [{ kind: "hbh", units: 1, nhAfter: 6 }],
        payloadLenOverride: 0,
      }),
    );
    expect(r.ip?.proto).toBe(6); // chain walked to TCP
    expect(r.ip?.extHeaders?.[0].type).toBe(0);
    expect(r.ip?.payloadLen).toBe(0); // no jumbogram reconstruction (documented limit)
    expect(r.transport?.kind).toBe("tcp");
    expect(r.transport?.sport).toBe(8);
  });

  it("ipv6 C4a: hop-by-hop header alone (0) -> chain walked, TCP found (RFC 8200 §4.3)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 12, dport: 120 }), { exts: [{ kind: "hbh", units: 0, nhAfter: 6 }] }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([0]);
    expect(r.transport?.sport).toBe(12);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C4b: routing header alone (43) -> chain walked, TCP found (RFC 8200 §4.4)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 13, dport: 130 }), { exts: [{ kind: "routing", units: 0, nhAfter: 6 }] }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([43]);
    expect(r.transport?.sport).toBe(13);
  });

  it("ipv6 C4c: fragment header alone (44) -> walked, TCP at the right offset (RFC 8200 §4.5)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 14, dport: 140 }), {
        exts: [{ kind: "frag", nhAfter: 6, offUnits: 0, mf: false, id: 42 }],
      }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([44]);
    expect(r.transport?.sport).toBe(14);
  });

  it("ipv6 C4d: destination-options alone (60) -> chain walked, TCP found (RFC 8200 §4.6)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 15, dport: 150 }), { exts: [{ kind: "dstopt", units: 0, nhAfter: 6 }] }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([60]);
    expect(r.transport?.sport).toBe(15);
  });

  it("ipv6 C4e: AH alone (51) -> walked per RFC 4302 (NEXT HEADER IS AH BYTE 0; engine bug fixed here)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 16, dport: 160 }), { exts: [{ kind: "ah", pl: 1, nhAfter: 6 }] }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([51]);
    expect(r.ip?.extHeaders?.[0].lenBytes).toBe(12); // (1 + 2) * 4 per RFC 4302
    expect(r.ip?.proto).toBe(6); // the NEXT HEADER byte 0 pointed at TCP
    expect(r.transport?.sport).toBe(16);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C5: chain of 3 mixed extension headers -> TCP found at the correct offset (RFC 8200 §4)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 17, dport: 170 }), {
        exts: [
          { kind: "hbh", units: 0, nhAfter: 43 },
          { kind: "frag", nhAfter: 60, offUnits: 0, mf: false, id: 7 },
          { kind: "dstopt", units: 0, nhAfter: 6 },
        ],
      }),
    );
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([0, 44, 60]);
    expect(r.ip?.proto).toBe(6);
    expect(r.transport?.sport).toBe(17);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C6: extension header length field points past end -> error, no throw (RFC 8200 §4)", () => {
    const b = ip6(tcp({ sport: 18, dport: 180 }), {
      exts: [{ kind: "dstopt", units: 4, nhAfter: 6 }],
    });
    const cut = b.subarray(0, 48); // 40 header + only 8 of 40 declared ext bytes
    const r = decode(228, cut);
    expect(r.errors.length).toBeGreaterThan(0);
    expect(r.ip).toBeUndefined();
  });

  it("ipv6 C7: chain of MORE than 8 extension headers -> error 'ipv6: chain too long' (documented limit)", () => {
    const chain: ExtSpec[] = [];
    for (let i = 0; i < 9; i++) chain.push({ kind: "hbh", units: 0, nhAfter: 0 });
    const r = decode(228, ip6(tcp({ sport: 19, dport: 190 }), { exts: chain }));
    expect(r.errors.some((e) => e.startsWith("ipv6.chain-too-long"))).toBe(true);
    expect(r.ip).toBeUndefined();
  });

  it("ipv6 C8: exactly 8 ext headers then TCP -> walks fully (bounded, at the documented limit); completes well under 250ms", () => {
    const t0 = Date.now();
    const chain: ExtSpec[] = [];
    for (let i = 0; i < 8; i++) chain.push({ kind: "hbh", units: 0, nhAfter: 0 });
    const r = decode(228, ip6(tcp({ sport: 20, dport: 200 }), { exts: chain }));
    const ms = Date.now() - t0;
    expect(ms).toBeLessThan(250); // bounded-time assertion (catalog C8)
    expect(r.ip?.extHeaders).toHaveLength(8);
    expect(r.ip?.proto).toBe(6);
    expect(r.transport?.sport).toBe(20);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C9a: fragment header -> offset, M flag and identification recorded on ip (RFC 8200 §4.5)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 21, dport: 210 }), {
        exts: [{ kind: "frag", nhAfter: 6, offUnits: 5, mf: true, id: 0xdeadbeef }],
      }),
    );
    expect(r.ip?.fragment?.offsetBytes).toBe(40);
    expect(r.ip?.fragment?.moreFragments).toBe(true);
    expect(r.ip?.fragment?.id).toBe(0xdeadbeef);
  });

  it("ipv6 C9b: non-first fragment (offset > 0) -> NO L4 decode, metadata only (same rule as IPv4)", () => {
    const r = decode(
      228,
      ip6(Buffer.alloc(24, 0x77), {
        exts: [{ kind: "frag", nhAfter: 6, offUnits: 9, mf: true, id: 3 }],
      }),
    );
    expect(r.ip?.fragment?.offsetBytes).toBe(72);
    expect(r.ip?.fragment?.moreFragments).toBe(true);
    expect(r.transport?.sport).toBeUndefined();
    expect(r.transport?.kind).toBe("other");
  });

  it("ipv6 C10: atomic fragment (offset 0, M=0) -> L4 decoded (RFC 8200 §4.5)", () => {
    const r = decode(
      228,
      ip6(tcp({ sport: 22, dport: 220 }), {
        exts: [{ kind: "frag", nhAfter: 6, offUnits: 0, mf: false, id: 5 }],
      }),
    );
    expect(r.transport?.sport).toBe(22);
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C11: next header 59 (No Next Header) -> payload absent, transport 'other', no error (RFC 8200 §4.7)", () => {
    const r = decode(228, ip6(Buffer.alloc(0), { nh: 59 }));
    expect(r.ip?.proto).toBe(59);
    expect(r.transport?.kind).toBe("other");
    expect(r.errors).toHaveLength(0);
  });

  it("ipv6 C12: version nibble not 6 (0x75) -> error, no throw (RFC 8200 §3.1)", () => {
    const r = decode(228, Buffer.from([0x75, 0, 0, 0, 0, 0, 6, 64, 0xfe, 0x80]));
    expect(r.ip).toBeUndefined();
    expect(r.errors.length).toBeGreaterThan(0);
  });

  it("ipv6 C13: link-local, loopback(::1), v4-mapped ::= text form per RFC 5952 (lowercase, longest zero run)", () => {
    const mk = (src: string) => decode(228, ip6(Buffer.alloc(0), { src, nh: 59 })).ip?.src;
    expect(mk("fe800000000000000000000000000005")).toBe("fe80::5");
    expect(mk("00000000000000000000000000000001")).toBe("::1");
    expect(mk("20010db8000000000000000000000001")).toBe("2001:db8::1");
    // EXACT v4-mapped (::ffff:0:0/96): 10 zero bytes + 0xffff + the v4 bytes
    expect(mk("00000000000000000000ffff0a000001")).toBe("::ffff:10.0.0.1");
    // NEAR-mapped (0001:fffe after the zero run) does NOT get a dotted tail
    expect(mk("00000000000000000001fffe0a000001")).toBe("::1:fffe:a00:1");
  });

  it("ipv6 C14: format roundtrip — parse(format(addr)) == addr for 20 seeded random addresses (RFC 5952 §2.1)", () => {
    // text-side mini-parser mirroring RFC 5952 rules (compression + hex groups)
    const parseV6 = (s: string): Buffer => {
      const b = Buffer.alloc(16);
      const hexp = (g: string, off: number) => {
        g.split(":")
          .filter((x) => x !== "")
          .forEach((grp, i) => {
            const v = parseInt(grp, 16);
            b[off + i * 2] = v >> 8;
            b[off + i * 2 + 1] = v & 0xff;
          });
      };
      const hiLo = s.split("::");
      if (hiLo.length === 1) {
        hexp(hiLo[0], 0);
        return b;
      }
      hexp(hiLo[0], 0);
      if (/^:ffff:/.test(hiLo[1])) {
        // dotted-quad tail (v4-mapped)
        const parts = hiLo[1].slice(":ffff:".length).split(".").map(Number);
        b[10] = 0xff;
        b[11] = 0xff;
        for (let i = 0; i < 4; i++) b[12 + i] = parts[i];
      } else {
        const comps = hiLo[1].split(":").filter((x) => x !== "");
        for (let i = 0; i < comps.length; i++) {
          const v = parseInt(comps[comps.length - 1 - i], 16);
          b[15 - i * 2] = v & 0xff;
          b[14 - i * 2] = (v >> 8) & 0xff;
        }
      }
      return b;
    };
    // seeded PRNG (mulberry32, seed printed here for reproduction)
    const SEED = 0xc0ffee;
    let a = SEED >>> 0;
    const rnd = () => {
      a = (a + 0x6d2b79f5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return (t ^ (t >>> 14)) >>> 0;
    };
    for (let i = 0; i < 20; i++) {
      const bytes = Buffer.from(Array.from({ length: 16 }, () => rnd() & 0xff));
      // format via the ENGINE on a synthetic packet, then parse the text back
      const hexSrc = bytes.toString("hex");
      const text = decode(228, ip6(Buffer.alloc(0), { src: hexSrc, nh: 59 })).ip?.src ?? "";
      const back = parseV6(text);
      expect(text).not.toHaveLength(0);
      expect(back.equals(bytes)).toBe(true);
    }
  });
});
