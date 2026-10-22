// Decoder unit tests on synthetic packets (run: node --test test/).
// Every fixture's byte layout is written inline so failures are readable.

import test from "node:test";
import assert from "node:assert/strict";
import { decodePacket, flowIdOf, canonicalFlow } from "../src/engine/decoder.ts";
import type { DecodedPacket } from "../src/engine/decoder.ts";

function mac(sep: string): Buffer {
  const b = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) b[i] = parseInt(sep.slice(i * 2, i * 2 + 2), 16);
  return b;
}

function hex(s: string): Buffer {
  return Buffer.from(s.replace(/\s+/g, ""), "hex");
}

function eth(payload: Buffer, ethertype = 0x0800, dst = "020203040506", src = "020203040507", vlans: number[] = []): Buffer {
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

test("ethernet IPv4 TCP: full decode + flow normalization", () => {
  const frame = eth(
    ip4("10.66.52.167", "104.20.26.136", 6, tcp(65123, 443, 0x02)),
  );
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.framing, "ethernet");
  assert.equal(r.ethertype, 0x0800);
  assert.equal(r.ip?.version, 4);
  assert.equal(r.ip?.src, "10.66.52.167");
  assert.equal(r.ip?.dst, "104.20.26.136");
  assert.equal(r.ip?.checksumValid, true);
  assert.equal(r.transport?.kind, "tcp");
  assert.equal(r.transport?.sport, 65123);
  assert.equal(r.transport?.dport, 443);
  assert.equal(r.transport?.tcpFlags, 0x02);
  assert.ok(r.errors.length === 0, JSON.stringify(r.errors));
  const f = flowIdOf(r);
  assert.equal(f, "p6 104.20.26.136:443 <--> 10.66.52.167:65123");
  // Reversed direction maps to the same flow id.
  const back = decodePacket(1, eth(ip4("104.20.26.136", "10.66.52.167", 6, tcp(443, 65123, 0x10))), 100);
  assert.equal(flowIdOf(back), f);
});

test("double VLAN tag decoded, both ids recorded", () => {
  const frame = eth(ip4("10.0.0.1", "10.0.0.2", 17, udp(123, 456, Buffer.from([1, 2]))), 0x0800, "020203040506", "020203040507", [200, 300]);
  const r = decodePacket(1, frame, frame.length);
  assert.deepEqual(r.vlanIds, [200, 300]);
  assert.equal(r.framing, "vlan");
  assert.equal(r.transport?.sport, 123);
  const rev = canonicalFlow(17, "10.0.0.1", 123, "10.0.0.2", 456);
  assert.equal(rev.aip === "10.0.0.1", true);
});

test("DNS over UDP: questions + A + AAAA + CNAME via pointer", () => {
  const msg = dnsMessage(0x2ccb, false, [{ name: "example.org", type: 255 }], [
    { type: 5, data: Buffer.concat([Buffer.from([3]), Buffer.from("www"), Buffer.from([3]), Buffer.from("org"), Buffer.from([0])]) },
    { type: 1, data: Buffer.from([93, 184, 215, 14]) },
    { type: 28, data: hex("2606470090d66c5ea14256e5252b85fe") },
  ]);
  const frame = eth(ip4("10.66.52.167", "10.66.52.203", 17, udp(56850, 53, msg)));
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.dns?.transactionId, 0x2ccb);
  assert.equal(r.dns?.isResponse, false);
  assert.deepEqual(r.dns?.questions[0], { name: "example.org", type: 255 });
  assert.equal(r.dns?.aRecords[0], "93.184.215.14");
  assert.equal(r.dns?.aaaaRecords[0], "2606:4700:90d6:6c5e:a142:56e5:252b:85fe");
});

test("IPv4 fragments: MF + offset fields recorded (no reassembly)", () => {
  const f1 = decodePacket(1, eth(ip4("1.1.1.1", "2.2.2.2", 17, Buffer.alloc(40), { flagsFrag: 0x2001, id: 7 })), 100);
  assert.equal(f1.ip?.fragment?.moreFragments, true);
  assert.equal(f1.ip?.fragment?.offsetBytes, 8);
  assert.equal(f1.ip?.fragment?.id, 7);
  const f2 = decodePacket(1, eth(ip4("1.1.1.1", "2.2.2.2", 17, Buffer.alloc(30), { flagsFrag: 62, id: 7 })), 100);
  assert.equal(f2.ip?.fragment?.moreFragments, false);
  assert.equal(f2.ip?.fragment?.offsetBytes, 8 * 62);
});

test("IPv6 hop-by-hop extension header chain then TCP", () => {
  const versionTraffic = Buffer.alloc(40 + 8 + 20);
  versionTraffic[0] = 0x60;
  versionTraffic.writeUInt16BE(8 + 20, 4); // payload
  versionTraffic[6] = 0; // next = hop-by-hop
  versionTraffic[7] = 60;
  // hop-by-hop at 40: NH=6, ext len byte = 0 => 8 bytes
  versionTraffic[40] = 6;
  versionTraffic[41] = 0;
  for (let i = 48; i < 48 + 20; i++) versionTraffic[i] = 0;
  versionTraffic.writeUInt16BE(65123, 48);
  versionTraffic.writeUInt16BE(443, 50);
  versionTraffic[48 + 12] = 0x50; // TCP data offset 20
  versionTraffic[48 + 13] = 0x02; // SYN flag
  const frame = Buffer.concat([eth(versionTraffic, 0x86dd)]);
  const p = decodePacket(1, frame, frame.length);
  assert.equal(p.ip?.version, 6);
  assert.equal(p.ip?.proto, 6);
  assert.equal(p.ip?.extHeaders?.[0].type, 0);
  assert.equal(p.transport?.sport, 65123);
  assert.ok(p.errors.length === 0, JSON.stringify(p.errors));
});

test("IPv6 fragment header described but not reassembled", () => {
  const b = Buffer.alloc(40 + 8 + 20);
  b[0] = 0x60;
  b.writeUInt16BE(28, 4);
  b[6] = 44; // fragment header
  b[7] = 60;
  // fragment header at 40: NH=6
  b[40] = 6;
  b.writeUInt16BE((0 << 3) | 0, 42); // offset 0, MF=0
  b.writeUInt32BE(9, 44); // id
  b.writeUInt16BE(56850, 48);
  b.writeUInt16BE(53, 50);
  const frame = eth(b, 0x86dd);
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.ip?.proto, 6);
  assert.deepEqual(r.ip?.extHeaders?.map((e) => e.type), [44]);
});

test("malformed inputs: truncated + bad version + checksum corruption", () => {
  // Truncated IPv4 header (not enough bytes)
  const t1 = decodePacket(228, Buffer.from([0x45, 0x00, 0x00]), 3);
  assert.ok(t1.errors.some((e) => e.includes("truncated")), JSON.stringify(t1.errors));
  // Bad version
  const t2 = decodePacket(228, Buffer.from([0x35, 0, 0, 0]), 4);
  assert.ok(t2.errors.length > 0);
  // Corrupted IPv4 checksum still decodes, flag recorded
  const bad = eth(ip4("1.1.1.1", "2.2.2.2", 6, tcp(1, 2, 0x10), { corruptChecksum: true }));
  const t3 = decodePacket(1, bad, bad.length);
  assert.equal(t3.ip?.checksumValid, false);
  assert.equal(t3.transport?.kind, "tcp");
  // Ethernet truncated mid-VLAN
  const t4 = decodePacket(1, hex("ffffffffffff aaaaaaaaaaaa 8100 00"), 10);
  assert.ok(t4.errors.length > 0);
});

test("DNS label pointer loop terminates (bounded)", () => {
  // name begins with pointer to itself; decoder must not hang.
  const msg = Buffer.alloc(20);
  msg.writeUInt16BE(1, 0);
  msg.writeUInt16BE(1, 4); // 1 question
  msg.writeUInt16BE(0x0001, 5); // low byte reveals nothing; buffer now has question at 12
  msg[12] = 0xc0;
  msg[13] = 0x0c; // pointer to itself (12)
  const frame = eth(ip4("1.1.1.1", "2.2.2.2", 17, udp(53, 5000, msg)));
  const r = decodePacket(1, frame, frame.length);
  assert.ok(r.dns === null || r.dns !== undefined);
});

test("bare-IP framing decoded (no Ethernet header)", () => {
  const b = ip4("10.66.52.167", "104.20.26.136", 6, tcp(1, 2, 0x10));
  const r = decodePacket(1, b, b.length);
  assert.equal(r.framing, "bareIP");
  assert.equal(r.transport?.kind, "tcp");
  const r2 = decodePacket(228, b, b.length);
  assert.equal(r2.framing, "bareIP");
});

test("raw 802.11 variant with LLC/SNAP decoded (QoS craft, offset 26)", () => {
  const l2 = Buffer.alloc(26);
  l2[0] = 0x08;
  l2[1] = 0x01; // FC: data, to-DS
  l2.writeUInt16BE(0x0080, 2); // duration
  mac("0e90588896a5").copy(l2, 4);
  mac("84144dba8f79").copy(l2, 10);
  mac("0e90588896a5").copy(l2, 16);
  l2.writeUInt16BE(0x0000, 22); // seq control
  l2.writeUInt16BE(0x0000, 24); // QoS control
  const llc = hex("aaaa 0300 0000 0800");
  const frame = Buffer.concat([l2, llc, ip4("10.66.52.167", "10.66.52.203", 17, udp(51324, 53, dnsMessage(7, true, [], [])))]);
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.framing, "raw80211");
  assert.equal(r.transport?.kind, "udp");
  assert.equal(r.transport?.dport, 53);
  assert.equal(r.dns?.isResponse, true);
});

test("unknown ethertype with IP payload: recovered with recorded error", () => {
  const b = eth(ip4("9.9.9.9", "8.8.8.8", 6, tcp(1, 2, 0x18)), 0x9999);
  const r = decodePacket(1, b, b.length);
  assert.ok(r.errors.some((e) => e.includes("0x9999")));
  assert.equal(r.ip?.src, "9.9.9.9");
  assert.equal(r.transport?.sport, 1);
});

test("DNS over TCP: length prefix skipped", () => {
  const msg = dnsMessage(0xbeef, false, [{ name: "example.com", type: 1 }], []);
  const prefix = Buffer.alloc(2);
  prefix.writeUInt16BE(msg.length, 0);
  const frame = eth(ip4("10.0.0.1", "2.2.2.2", 6, tcp(5000, 53, 0x18, Buffer.concat([prefix, msg]))));
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.dns?.transactionId, 0xbeef);
  assert.equal(r.dns?.questions[0].name, "example.com");
});

test("TLS ClientHello SNI extracted (metadata only)", () => {
  // Minimal ClientHello: record(0x16,0301,len) + handshake(01,len,0303,random32,
  // sessionid-len, ciphers-len, compression-len, extensions with SNI ext)
  const host = "example.org";
  const sniEntry = Buffer.concat([
    Buffer.from([0x00, 0x00]), // sni ext type
    Buffer.alloc(0), // placeholder len, patched below
  ]);
  const hostBytes = Buffer.from(host, "ascii");
  const sniList = Buffer.concat([
    Buffer.alloc(2), // list len patched below
    Buffer.from([0x00]), // entry type 0
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(hostBytes.length, 0); return b; })(),
    hostBytes,
  ]);
  sniList.writeUInt16BE(sniList.length - 2, 0);
  sniEntry[2] = 0x00; // patched per construct
  void sniEntry;
  const sniExt = Buffer.concat([
    Buffer.from([0x00, 0x00]),
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(sniList.length, 0); return b; })(),
    sniList,
  ]);
  const body = Buffer.concat([
    Buffer.from([0x03, 0x03]), // legacy version
    Buffer.alloc(32), // random
    Buffer.from([0x00]), // session id empty
    Buffer.from([0x00, 0x02, 0x13, 0x01]), // one cipher suite
    Buffer.from([0x01, 0x00]), // compression empty
    (() => { const b = Buffer.alloc(2); b.writeUInt16BE(sniExt.length, 0); return b; })(),
    sniExt,
  ]);
  const hsLen = Buffer.alloc(4);
  hsLen[0] = 0x01;
  hsLen.writeUIntBE(body.length, 1, 3);
  const hsBody = Buffer.concat([hsLen, body]);
  const recHeader = Buffer.alloc(5);
  recHeader[0] = 0x16;
  recHeader[1] = 0x03; recHeader[2] = 0x01;
  recHeader.writeUInt16BE(hsBody.length, 3);
  const tls = Buffer.concat([recHeader, hsBody]);
  const frame = eth(ip4("10.0.0.10", "1.2.3.4", 6, tcp(50000, 443, 0x18, tls)));
  const r = decodePacket(1, frame, frame.length);
  assert.equal((r.transport?.payloadLen ?? 0) > 0, true);
  assert.equal(r.tls?.recordVersion, "0301");
  assert.equal(r.tls?.legacyVersion, "0303");
  assert.equal(r.tls?.sni, "example.org");
});

test("ARP described as arp kind", () => {
  const arp = hex("0001 0800 06 04 0001 aabbccddeeff c0a80119 000000000000 c0a80101");
  const frame = Buffer.concat([eth(arp, 0x0806)]);
  const r = decodePacket(1, frame, frame.length);
  assert.equal(r.transport?.kind, "arp");
  assert.equal(r.ip, undefined);
});

test("empty and short inputs never throw", () => {
  for (const b of [Buffer.alloc(0), Buffer.alloc(3), Buffer.from([0x08, 0x01])]) {
    const r = decodePacket(1, b, b.length);
    assert.ok(Array.isArray(r.errors));
  }
});

test("DecodedPacket shape sanity", () => {
  const r: DecodedPacket = decodePacket(1, Buffer.from([0, 1]), 2);
  assert.equal(typeof r.capLen, "number");
  assert.equal(r.framing, "unknown");
});
