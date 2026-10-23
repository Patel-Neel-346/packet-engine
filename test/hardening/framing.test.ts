// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — Framing (catalog section A, cases 1–14)
//
// Naming: "<area>: <input condition> -> <expected result> (<why>)."
// Each test asserts (1) no throw, (2) the expected fields / named error code,
// (3) partial decode retention where the catalog demands it.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { decodePacket, flowIdOf } from "../../src/engine/decoder.ts";
import { eth, ip4, ip6, tcp, decode, hasError } from "./helpers.ts";

describe("framing (catalog A)", () => {
  it("framing A1: plain Ethernet II + IPv4 -> EtherType 0x0800 detected, MACs decoded (RFC 894)", () => {
    const frame = eth(ip4(tcp({ sport: 77, dport: 7700 })), { ethertype: 0x0800 });
    const r = decode(1, frame);
    expect(r.framing).toBe("ethernet");
    expect(r.ethertype).toBe(0x0800);
    expect(r.dstMac).toBe("02:02:03:04:05:06");
    expect(r.srcMac).toBe("02:02:03:04:05:07");
    expect(r.errors).toHaveLength(0);
  });

  it("framing A2: Ethernet II + IPv6 -> EtherType 0x86DD detected, IPv6 parsed (RFC 8200)", () => {
    const frame = eth(ip6(tcp({ sport: 7, dport: 70 })), { ethertype: 0x86dd });
    const r = decode(1, frame);
    expect(r.ethertype).toBe(0x86dd);
    expect(r.ip?.version).toBe(6);
    expect(r.errors).toHaveLength(0);
  });

  it("framing A3: single 802.1Q tag (0x8100) -> VLAN id + PCP decoded, inner EtherType used (IEEE 802.1Q)", () => {
    const frame = eth(ip4(Buffer.alloc(4)), { vlans: [0x0050] }); // TCI 0x0050: PCP=0, id=80
    const r = decode(1, frame);
    expect(r.framing).toBe("vlan");
    expect(r.vlanIds).toEqual([80]);
    // inner EtherType regardless of VLAN
    expect(r.ipOffset).toBe(18);
    expect(r.ip?.version).toBe(4);
  });

  it("framing A4: double tag 802.1ad 0x88A8 + 0x8100 -> both tags recorded (IEEE 802.1ad Q-in-Q)", () => {
    const frame = eth(ip4(tcp({ sport: 10, dport: 100 })), {
      vlans: [100, 200],
      tpids: [0x88a8, 0x8100],
    });
    const r = decode(1, frame);
    expect(r.framing).toBe("vlan");
    expect(r.vlanIds).toEqual([100, 200]);
    expect(r.ip?.version).toBe(4); // decoded THROUGH both tags
    expect(r.errors).toHaveLength(0);
  });

  it("framing A5: triple-stacked VLAN -> decoded up to the documented 4-tag limit (decoder guard=4)", () => {
    const frame = eth(ip4(tcp({ sport: 11, dport: 110 })), { vlans: [111, 222, 333] });
    const r = decode(1, frame);
    expect(r.vlanIds).toEqual([111, 222, 333]);
    expect(r.ip?.version).toBe(4);
    expect(r.errors).toHaveLength(0);
  });

  it("framing A6: VLAN tag truncated after TPID (no TCI bytes) -> error 'ethernet:', no throw (802.1Q)", () => {
    // 14-byte header + only 2 bytes of the 0x8100 tag (TPID present, TCI cut)
    const frame = eth(ip4(Buffer.alloc(4)), { vlans: [1], cutTo: 16 });
    const r = decode(1, frame);
    expect(hasError(r, "ethernet: truncated VLAN tag")).toBe(true);
    expect(r.ip).toBeUndefined(); // cannot continue past a cut tag
  });

  it("framing A7: ARP request -> kind 'arp', opcode recorded, no flow created (RFC 826)", () => {
    const arpReq = Buffer.concat([
      Buffer.from([0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01]),
      Buffer.from("aabbccddeeff", "hex"),
      Buffer.from([10, 0, 0, 1]),
      Buffer.alloc(6),
      Buffer.from([10, 0, 0, 2]),
    ]);
    const r = decode(1, eth(arpReq, { ethertype: 0x0806 }));
    expect(r.transport?.kind).toBe("arp");
    expect(r.transport?.arpOpcode).toBe(1);
    expect(flowIdOf(r)).toBeNull(); // ARP creates no flow
    expect(Array.isArray(r.errors)).toBe(true); // did not throw
  });

  it("framing A7b: ARP reply -> opcode 2 decoded (RFC 826)", () => {
    const arpRep = Buffer.concat([
      Buffer.from([0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02]),
      Buffer.from("001122334455", "hex"),
      Buffer.from([10, 0, 0, 2]),
      Buffer.from("aabbccddeeff", "hex"),
      Buffer.from([10, 0, 0, 1]),
    ]);
    const r = decode(1, eth(arpRep, { ethertype: 0x0806 }));
    expect(r.transport?.kind).toBe("arp");
    expect(r.transport?.arpOpcode).toBe(2);
  });

  it("framing A8: bare IPv4 with no Ethernet header (non-Ethernet linkType) -> framing 'bareIP'", () => {
    const r = decode(101, ip4(tcp())); // linktype 101: Raw IP
    expect(r.framing).toBe("bareIP");
    expect(r.transport?.kind).toBe("tcp");
    expect(r.errors).toHaveLength(0);
  });

  it("framing A9: bare IPv6 (no L2) -> framing 'bareIP', IPv6 fields decoded", () => {
    const r = decode(229, ip6(tcp())); // linktype 229: IPv6 raw
    expect(r.framing).toBe("bareIP");
    expect(r.ip?.version).toBe(6);
    expect(r.transport?.sport).toBeDefined();
  });

  it("framing A10: raw 802.11 data frame, non-QoS (LLC/SNAP at offset 24) -> IP decoded (IEEE 802.11)", () => {
    // FC byte0 0x08 = v0/type2(data)/subtype0 (non-QoS data)
    const l2 = Buffer.alloc(24);
    l2[0] = 0x08;
    l2[1] = 0x01;
    const llc = Buffer.from("aaaa030000000800", "hex");
    const frame = Buffer.concat([l2, llc, ip4(tcp({ sport: 9, dport: 90 }))]);
    const r = decode(1, frame);
    expect(r.framing).toBe("raw80211");
    expect(r.transport?.sport).toBe(9);
    expect(r.errors).toHaveLength(0);
  });

  it("framing A10b: raw 802.11 QoS data frame (LLC/SNAP at offset 26) -> IP decoded", () => {
    // FC byte0 0x48 = v0/type2(data)/subtype8 (QoS data)
    const l2 = Buffer.alloc(26);
    l2[0] = 0x48;
    l2[1] = 0x01;
    const llc = Buffer.from("aaaa030000000800", "hex");
    const frame = Buffer.concat([l2, llc, ip4(tcp({ sport: 9, dport: 90 }))]);
    const r = decode(1, frame);
    expect(r.framing).toBe("raw80211");
    expect(r.transport?.sport).toBe(9);
  });

  it("framing A11: unknown EtherType 0x4dba WITH a consistent IP payload -> engine recovers (documented rule)", () => {
    // Documented engine rule (M1-verified vs tshark): unknown ethertype that
    // still carries a len-consistent IP payload is RECOVERED and the oddity
    // is recorded as an error-level note — we assert the rule THAT EXISTS.
    const frame = eth(ip4(tcp({ sport: 7, dport: 70 })), { ethertype: 0x4dba });
    const r = decode(1, frame);
    expect(r.ethertype).toBe(0x4dba);
    expect(r.errors.some((e) => e.includes("0x4dba"))).toBe(true);
    // Recovery is real: IP + TCP decode
    expect(r.transport?.sport).toBe(7);
    expect(Array.isArray(r.errors)).toBe(true);
  });

  it("framing A11b: unknown EtherType with NO IP payload -> L2 fields kept, framing 'ethernet', counted unsupported (error recorded)", () => {
    // Engine rule (M1-verified): the Ethernet header is still real even when
    // the ethertype neither carries IP nor recovers — L2 fields survive, the
    // odd ethertype is recorded as an error (parity counts this unsupported),
    // and no IP structure is invented.
    const garbage = Buffer.alloc(20, 0xab);
    const r = decode(1, eth(garbage, { ethertype: 0x4dba }));
    expect(r.framing).toBe("ethernet");
    expect(r.dstMac).toBe("02:02:03:04:05:06");
    expect(r.ip).toBeUndefined();
    expect(r.errors.some((e) => e.includes("0x4dba"))).toBe(true);
  });

  it("framing A12: frame shorter than 14 bytes -> error 'ethernet: frame too short', no throw", () => {
    const r = decode(1, eth(ip4(Buffer.alloc(0)), { cutTo: 13 }));
    expect(hasError(r, "ethernet: frame too short")).toBe(true);
    expect(r.framing).toBe("unknown");
  });

  it("framing A13: empty and 1-byte buffers -> error recorded, no throw", () => {
    const r0 = decodePacket(1, Buffer.alloc(0), 0);
    expect(r0.errors.length).toBeGreaterThan(0);
    // 0x45 is a plausible IPv4 IHL byte: bare-IP detection assigns framing
    // (documented rule) and the 20-byte header requirement then errors out.
    const r1 = decodePacket(1, Buffer.from([0x45]), 1);
    expect(Array.isArray(r1.errors)).toBe(true);
    expect(r1.framing).toBe("bareIP");
    expect(r1.errors.some((e) => e.includes("truncated"))).toBe(true);
  });

  it("framing A14: ambiguous first nibble 0x5 -> neither bare-IP nor recovered, framing 'unknown' (detection rule)", () => {
    // nibble 5: not 4 (IPv4) and not 6 (IPv6); findBareIpStart accepts only
    // consistency-checked starts, so garbage stays unknown.
    const b = Buffer.from([0x55, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const r = decode(101, b);
    expect(r.framing).toBe("unknown");
    expect(r.ip).toBeUndefined();
    expect(r.errors.length).toBeGreaterThan(0);
  });
});
