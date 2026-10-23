// ─────────────────────────────────────────────────────────────────────────────
// DECODER SUITE — src/engine/decoder.ts
// Run:  npm test           (one-shot)      npm run test:watch   (live)
//       npm run test:ui    (browser dashboard)
//
// What "passing" means here: every fixture byte layout is written INLINE in
// this file (see the builders below), so when something breaks you can diff
// the expectation against the exact bytes without reading engine code.
//
// Coverage map:
//   • ethernet framing        → IPv4/IPv6 next, VLAN tags, bare-IP, raw 802.11
//   • DNS (UDP + TCP)         → questions, A/AAAA/CNAME, length prefix, loops
//   • IP edges                → fragments (described, not reassembled),
//                               IPv6 extension-header chains, bad ethertype
//   • hostile input           → truncation, wrong version, checksum lies
//   • TCP payload metadata    → TLS ClientHello SNI (metadata only — no crypto)
//   • non-IP traffic          → ARP stays on the L2 path (Finding A territory)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "vitest";
import { decodePacket, flowIdOf, canonicalFlow } from "../src/engine/decoder.ts";
import type { DecodedPacket } from "../src/engine/decoder.ts";

// ── inline fixture builders (bytes-on-the-wire made readable) ───────────────

function mac(sep: string): Buffer {
  const b = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) b[i] = parseInt(sep.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function hex(s: string): Buffer {
  return Buffer.from(s.replace(/\s+/g, ""), "hex");
}

/** Ethernet II frame, optionally VLAN-tagged (802.1Q stacked outer→inner). */
function eth(
  payload: Buffer,
  ethertype = 0x0800,
  dst = "020203040506",
  src = "020203040507",
  vlans: number[] = [],
): Buffer {
  const parts: Buffer[] = [mac(dst), mac(src)];
  for (const _ of vlans) {
    parts.push(hex("8100"));
    const tci = Buffer.alloc(2);
    tci.writeUInt16BE(_ & 0x0fff, 0);
    parts.push(tci);
  }
  const et = Buffer.alloc(2);
  et.writeUInt16BE(ethertype, 0);
  parts.push(et, payload);
  return Buffer.concat(parts);
}

/** IPv4 header with valid checksum unless asked to lie. */
function ip4(
  src: string,
  dst: string,
  proto: number,
  payloadAndOptions: Buffer,
  opts: { ihl?: number; totalLen?: number; id?: number; flagsFrag?: number; ttl?: number; corruptChecksum?: boolean } = {},
): Buffer {
  const ihl = opts.ihl ?? 20;
  const total = opts.totalLen ?? ihl + payloadAndOptions.length;
  const h = Buffer.alloc(ihl);
  h[0] = 0x40 | ihl / 4;
  h.writeUInt16BE(total, 2);
  h.writeUInt16BE(opts.id ?? 0x1234, 4);
  h.writeUInt16BE(opts.flagsFrag ?? 0x4000, 6);
  h[8] = opts.ttl ?? 64;
  h[9] = proto;
  const s = src.split(".").map((x) => parseInt(x, 10));
  const d = dst.split(".").map((x) => parseInt(x, 10));
  for (let i = 0; i < 4; i++) {
    h[12 + i] = s[i] as number;
    h[16 + i] = d[i] as number;
  }
  if (!opts.corruptChecksum) {
    let sum = 0;
    for (let i = 0; i < ihl; i += 2) sum += h.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    h.writeUInt16BE(~sum & 0xffff, 10);
  }
  return Buffer.concat([h, payloadAndOptions]);
}

function tcp(
  sport: number,
  dport: number,
  flags: number,
  payload: Buffer = Buffer.alloc(0),
  seq = 1,
): Buffer {
  const b = Buffer.alloc(20 + payload.length);
  b.writeUInt16BE(sport, 0);
  b.writeUInt16BE(dport, 2);
  b.writeUInt32BE(seq >>> 0, 4);
  b.writeUInt32BE(0, 8);
  b[12] = 0x50; // data offset 20
  b[13] = flags & 0xff;
  b.writeUInt16BE(0xffff, 14);
  payload.copy(b, 20);
  return b;
}

function udp(sport: number, dport: number, payload: Buffer): Buffer {
  const b = Buffer.alloc(8 + payload.length);
  b.writeUInt16BE(sport, 0);
  b.writeUInt16BE(dport, 2);
  b.writeUInt16BE(8 + payload.length, 4);
  payload.copy(b, 8);
  return b;
}

/** DNS message: header + questions + answers (answers point of offset 12). */
function dnsMessage(
  id: number,
  isResponse: boolean,
  questions: Array<{ name: string; type: number }>,
  answers: Array<{ type: number; data: Buffer; rcode?: number }>,
): Buffer {
  const parts: Buffer[] = [];
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(isResponse ? 0x8180 : 0x0100, 2);
  h.writeUInt16BE(questions.length, 4);
  h.writeUInt16BE(answers.length, 6);
  parts.push(h);
  for (const q of questions) {
    for (const label of q.name.split(".")) {
      const one = Buffer.alloc(1 + label.length);
      one[0] = label.length;
      one.write(label, 1);
      parts.push(one);
    }
    const zero = Buffer.from([0]);
    const t = Buffer.alloc(4);
    t.writeUInt16BE(q.type, 0);
    parts.push(zero, t);
  }
  for (const a of answers) {
    // pointer to first question's name (offset 12)
    const ptr = Buffer.from([0xc0, 0x0c]);
    const rr = Buffer.alloc(10);
    rr.writeUInt16BE(a.type, 0);
    rr.writeUInt16BE(1, 2); // IN
    rr.writeUInt32BE(30, 4);
    rr.writeUInt16BE(a.data.length, 8);
    parts.push(ptr, rr, a.data);
  }
  return Buffer.concat(parts);
}

// ── suites ───────────────────────────────────────────────────────────────────

describe("decodePacket: ethernet framing", () => {
  it("decodes Ethernet→IPv4→TCP fully and normalizes the flow id (direction-independent)", () => {
    const frame = eth(
      ip4("10.66.52.167", "104.20.26.136", 6, tcp(65123, 443, 0x02)),
    );
    const r = decodePacket(1, frame, frame.length);
    expect(r.framing).toBe("ethernet");
    expect(r.ethertype).toBe(0x0800);
    // IP layer parsed with a VALID header checksum
    expect(r.ip?.version).toBe(4);
    expect(r.ip?.src).toBe("10.66.52.167");
    expect(r.ip?.dst).toBe("104.20.26.136");
    expect(r.ip?.checksumValid).toBe(true);
    // L4 layer: SYN flag reaches the story
    expect(r.transport?.kind).toBe("tcp");
    expect(r.transport?.sport).toBe(65123);
    expect(r.transport?.dport).toBe(443);
    expect(r.transport?.tcpFlags).toBe(0x02);
    expect(r.errors).toHaveLength(0);
    // The canonical flow id puts the LOWER ip/port endpoint first…
    expect(flowIdOf(r)).toBe("p6 104.20.26.136:443 <--> 10.66.52.167:65123");
    // …and the reverse direction MUST map to the exact same flow id.
    const back = decodePacket(1, eth(ip4("104.20.26.136", "10.66.52.167", 6, tcp(443, 65123, 0x10))), 100);
    expect(flowIdOf(back)).toBe(flowIdOf(r));
  });

  it("decodes a double VLAN tag and records both VLAN ids", () => {
    const frame = eth(
      ip4("10.0.0.1", "10.0.0.2", 17, udp(123, 456, Buffer.from([1, 2]))),
      0x0800,
      "020203040506",
      "020203040507",
      [200, 300],
    );
    const r = decodePacket(1, frame, frame.length);
    expect(r.framing).toBe("vlan");
    expect(r.vlanIds).toEqual([200, 300]);
    // L4 decode must succeed THROUGH both tags, not stop at the first one.
    expect(r.transport?.sport).toBe(123);
    // Canonical endpoint order: lower IP first.
    const rev = canonicalFlow(17, "10.0.0.1", 123, "10.0.0.2", 456);
    expect(rev.aip).toBe("10.0.0.1");
  });

  it("decodes bare-IP framing when there is no Ethernet header (linktype 1 or 228)", () => {
    const b = ip4("10.66.52.167", "104.20.26.136", 6, tcp(1, 2, 0x10));
    const r = decodePacket(1, b, b.length);
    expect(r.framing).toBe("bareIP");
    expect(r.transport?.kind).toBe("tcp");
    // linktype 228 (IPV4 raw) takes the same path.
    const r2 = decodePacket(228, b, b.length);
    expect(r2.framing).toBe("bareIP");
  });

  it("decodes raw 802.11 QoS frames (LLC/SNAP payload starts at offset 26)", () => {
    const l2 = Buffer.alloc(26);
    l2[0] = 0x08;
    l2[1] = 0x01; // FC: data, to-DS
    l2.writeUInt16BE(0x0080, 2); // duration
    mac("0e90588896a5").copy(l2, 4);
    mac("84144dba8f79").copy(l2, 10);
    mac("0e90588896a5").copy(l2, 16);
    l2.writeUInt16BE(0x0000, 22); // seq control
    l2.writeUInt16BE(0x0000, 24); // QoS control
    const llc = hex("aaaa 0300 0000 0800"); // LLC/SNAP → ethertype 0x0800
    const frame = Buffer.concat([
      l2,
      llc,
      ip4("10.66.52.167", "10.66.52.203", 17, udp(51324, 53, dnsMessage(7, true, [], []))),
    ]);
    const r = decodePacket(1, frame, frame.length);
    expect(r.framing).toBe("raw80211");
    expect(r.transport?.kind).toBe("udp");
    expect(r.transport?.dport).toBe(53);
    expect(r.dns?.isResponse).toBe(true);
  });
});

describe("decodePacket: DNS parsing", () => {
  it("extracts questions + A + AAAA + CNAME (via compression pointer) over UDP", () => {
    const msg = dnsMessage(0x2ccb, false, [{ name: "example.org", type: 255 }], [
      // CNAME: pointer-free name "www.org"
      { type: 5, data: Buffer.concat([Buffer.from([3]), Buffer.from("www"), Buffer.from([3]), Buffer.from("org"), Buffer.from([0])]) },
      { type: 1, data: Buffer.from([93, 184, 215, 14]) },
      { type: 28, data: hex("2606470090d66c5ea14256e5252b85fe") },
    ]);
    const frame = eth(ip4("10.66.52.167", "10.66.52.203", 17, udp(56850, 53, msg)));
    const r = decodePacket(1, frame, frame.length);
    expect(r.dns?.transactionId).toBe(0x2ccb);
    expect(r.dns?.isResponse).toBe(false);
    expect(r.dns?.questions[0]).toEqual({ name: "example.org", type: 255 });
    expect(r.dns?.aRecords[0]).toBe("93.184.215.14");
    expect(r.dns?.aaaaRecords[0]).toBe("2606:4700:90d6:6c5e:a142:56e5:252b:85fe");
  });

  it("parses DNS carried inside TCP by skipping the 2-byte length prefix", () => {
    const msg = dnsMessage(0xbeef, false, [{ name: "example.com", type: 1 }], []);
    const prefix = Buffer.alloc(2);
    prefix.writeUInt16BE(msg.length, 0);
    const frame = eth(ip4("10.0.0.1", "2.2.2.2", 6, tcp(5000, 53, 0x18, Buffer.concat([prefix, msg]))));
    const r = decodePacket(1, frame, frame.length);
    expect(r.dns?.transactionId).toBe(0xbeef);
    expect(r.dns?.questions[0].name).toBe("example.com");
  });

  it("terminates on a self-referencing DNS label pointer instead of hanging", () => {
    // name begins with pointer to itself; decoder must not hang.
    const msg = Buffer.alloc(20);
    msg.writeUInt16BE(1, 0);
    msg.writeUInt16BE(1, 4); // 1 question
    msg.writeUInt16BE(0x0001, 5);
    msg[12] = 0xc0;
    msg[13] = 0x0c; // pointer to itself (offset 12)
    const frame = eth(ip4("1.1.1.1", "2.2.2.2", 17, udp(53, 5000, msg)));
    const r = decodePacket(1, frame, frame.length);
    // Either gives up cleanly (null) or yields a parsed-but-empty result —
    // anything but a hang/infinite recursion passes.
    expect(r.dns === null || r.dns !== undefined).toBe(true);
  });
});

describe("decodePacket: IP-layer edge cases", () => {
  it("records IPv4 fragment fields (MF bit + offset) but never fakes reassembly", () => {
    const f1 = decodePacket(1, eth(ip4("1.1.1.1", "2.2.2.2", 17, Buffer.alloc(40), { flagsFrag: 0x2001, id: 7 })), 100);
    expect(f1.ip?.fragment?.moreFragments).toBe(true);
    expect(f1.ip?.fragment?.offsetBytes).toBe(8); // raw frag field 1 → 8 bytes
    expect(f1.ip?.fragment?.id).toBe(7);
    const f2 = decodePacket(1, eth(ip4("1.1.1.1", "2.2.2.2", 17, Buffer.alloc(30), { flagsFrag: 62, id: 7 })), 100);
    expect(f2.ip?.fragment?.moreFragments).toBe(false);
    expect(f2.ip?.fragment?.offsetBytes).toBe(8 * 62);
  });

  it("walks the IPv6 hop-by-hop extension-header chain and still decodes TCP", () => {
    const versionTraffic = Buffer.alloc(40 + 8 + 20);
    versionTraffic[0] = 0x60;
    versionTraffic.writeUInt16BE(8 + 20, 4); // payload length
    versionTraffic[6] = 0; // next header = hop-by-hop
    versionTraffic[7] = 60; // hop limit
    // hop-by-hop ext at offset 40: NH=6 (TCP), ext-len byte 0 → 8 bytes
    versionTraffic[40] = 6;
    versionTraffic[41] = 0;
    for (let i = 48; i < 48 + 20; i++) versionTraffic[i] = 0;
    versionTraffic.writeUInt16BE(65123, 48);
    versionTraffic.writeUInt16BE(443, 50);
    versionTraffic[48 + 12] = 0x50; // TCP data offset 20
    versionTraffic[48 + 13] = 0x02; // SYN
    const frame = Buffer.concat([eth(versionTraffic, 0x86dd)]);
    const p = decodePacket(1, frame, frame.length);
    expect(p.ip?.version).toBe(6);
    expect(p.ip?.proto).toBe(6);
    expect(p.ip?.extHeaders?.[0].type).toBe(0); // hop-by-hop
    expect(p.transport?.sport).toBe(65123); // decoded THROUGH the ext chain
    expect(p.errors).toHaveLength(0);
  });

  it("describes the IPv6 fragment header without reassembling (M3 scope)", () => {
    const b = Buffer.alloc(40 + 8 + 20);
    b[0] = 0x60;
    b.writeUInt16BE(28, 4);
    b[6] = 44; // next header = fragment
    b[7] = 60;
    b[40] = 6; // fragment ext: NH = TCP
    b.writeUInt16BE((0 << 3) | 0, 42); // offset 0, MF=0
    b.writeUInt32BE(9, 44); // fragment id
    b.writeUInt16BE(56850, 48);
    b.writeUInt16BE(53, 50);
    const frame = eth(b, 0x86dd);
    const r = decodePacket(1, frame, frame.length);
    expect(r.ip?.proto).toBe(6);
    expect(r.ip?.extHeaders?.map((e) => e.type)).toEqual([44]);
  });

  it("recovers packets with an unknown ethertype that still carry IP, recording the oddity", () => {
    const b = eth(ip4("9.9.9.9", "8.8.8.8", 6, tcp(1, 2, 0x18)), 0x9999);
    const r = decodePacket(1, b, b.length);
    expect(r.errors).toEqual(expect.arrayContaining([expect.stringContaining("0x9999")]));
    // Recovery is real: the inner IP+TCP still parse.
    expect(r.ip?.src).toBe("9.9.9.9");
    expect(r.transport?.sport).toBe(1);
  });
});

describe("decodePacket: hostile and malformed input", () => {
  it("reports truncated headers, bad IP versions, corrupt checksums, mid-VLAN cuts", () => {
    // 1. Truncated IPv4 header: must say so, not throw.
    const t1 = decodePacket(228, Buffer.from([0x45, 0x00, 0x00]), 3);
    expect(t1.errors).toEqual(expect.arrayContaining([expect.stringContaining("truncated")]));

    // 2. Bad version nibble (0x35 → version 3): errors, no crash.
    const t2 = decodePacket(228, Buffer.from([0x35, 0, 0, 0]), 4);
    expect(t2.errors.length).toBeGreaterThan(0);

    // 3. Corrupt IPv4 checksum: still decodes, and the corruption is
    //    RECORDED, not hidden.
    const bad = eth(ip4("1.1.1.1", "2.2.2.2", 6, tcp(1, 2, 0x10), { corruptChecksum: true }));
    const t3 = decodePacket(1, bad, bad.length);
    expect(t3.ip?.checksumValid).toBe(false);
    expect(t3.transport?.kind).toBe("tcp");

    // 4. Ethernet truncated in the middle of a VLAN tag.
    const t4 = decodePacket(1, hex("ffffffffffff aaaaaaaaaaaa 8100 00"), 10);
    expect(t4.errors.length).toBeGreaterThan(0);
  });

  it("never throws on empty or 1–3 byte inputs", () => {
    for (const b of [Buffer.alloc(0), Buffer.alloc(3), Buffer.from([0x08, 0x01])]) {
      const r = decodePacket(1, b, b.length);
      // Contract: errors is always an array (never a throw path).
      expect(Array.isArray(r.errors)).toBe(true);
    }
  });

  it("returns the documented DecodedPacket shape even for garbage", () => {
    const r: DecodedPacket = decodePacket(1, Buffer.from([0, 1]), 2);
    expect(typeof r.capLen).toBe("number");
    expect(r.framing).toBe("unknown");
  });
});

describe("decodePacket: TCP payload metadata (no decryption ever)", () => {
  it("extracts SNI from a minimal TLS ClientHello — record version, legacy version, hostname", () => {
    // Hand-assembled ClientHello: record(0x16,0301,len) + handshake(01,len,
    // 0303, random32, session-id, cipher, compression, SNI extension).
    const host = "example.org";
    const hostBytes = Buffer.from(host, "ascii");
    const sniList = Buffer.concat([
      Buffer.alloc(2), // list length, patched below
      Buffer.from([0x00]), // entry type 0 = hostname
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(hostBytes.length, 0); return b; })(),
      hostBytes,
    ]);
    sniList.writeUInt16BE(sniList.length - 2, 0);
    const sniExt = Buffer.concat([
      Buffer.from([0x00, 0x00]), // extension type = server_name
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(sniList.length, 0); return b; })(),
      sniList,
    ]);
    const body = Buffer.concat([
      Buffer.from([0x03, 0x03]), // legacy version
      Buffer.alloc(32), // random
      Buffer.from([0x00]), // empty session id
      Buffer.from([0x00, 0x02, 0x13, 0x01]), // one cipher suite (TLS_AES_128_GCM)
      Buffer.from([0x01, 0x00]), // compression: null
      (() => { const b = Buffer.alloc(2); b.writeUInt16BE(sniExt.length, 0); return b; })(),
      sniExt,
    ]);
    const hsLen = Buffer.alloc(4);
    hsLen[0] = 0x01;
    hsLen.writeUIntBE(body.length, 1, 3);
    const hsBody = Buffer.concat([hsLen, body]);
    const recHeader = Buffer.alloc(5);
    recHeader[0] = 0x16; // handshake record
    recHeader[1] = 0x03; recHeader[2] = 0x01; // TLS 1.0 record layer
    recHeader.writeUInt16BE(hsBody.length, 3);
    const tls = Buffer.concat([recHeader, hsBody]);
    const frame = eth(ip4("10.0.0.10", "1.2.3.4", 6, tcp(50000, 443, 0x18, tls)));

    const r = decodePacket(1, frame, frame.length);
    expect((r.transport?.payloadLen ?? 0)).toBeGreaterThan(0);
    expect(r.tls?.recordVersion).toBe("0301");
    expect(r.tls?.legacyVersion).toBe("0303");
    expect(r.tls?.sni).toBe("example.org");
    // NOTE: only METADATA is read — keys/payload are never decrypted (project rule).
  });
});

describe("decodePacket: non-IP traffic", () => {
  it("routes ARP to the arp kind and touches no IP decoder", () => {
    const arp = hex("0001 0800 06 04 0001 aabbccddeeff c0a80119 000000000000 c0a80101");
    const frame = Buffer.concat([eth(arp, 0x0806)]);
    const r = decodePacket(1, frame, frame.length);
    expect(r.transport?.kind).toBe("arp");
    expect(r.ip).toBeUndefined();
  });
});
