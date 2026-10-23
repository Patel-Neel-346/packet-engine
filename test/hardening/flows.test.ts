// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — flow tracker (catalog section I — feasible subset; legacy
// test/flows.test.ts covers handshake/RST/gaps/retrans/fragments already)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { buildFlows } from "../../src/engine/flows.ts";
import { ethHdr, ip4Hdr, makePcap, tcpPkt, udpPkt, SYN, ACK, PSH } from "./pcap-helpers.ts";

/** Build one TCP frame from explicit parts (no checksum claims). */
function rawTcp(
  src: string,
  sport: number,
  dst: string,
  dport: number,
  flags: number,
  seq: number,
  payload: Buffer = Buffer.alloc(0),
): Buffer {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(1, 8); // ack
  tcp[12] = 0x50; // data offset 5
  tcp[13] = flags & 0xff;
  payload.copy(tcp, 20);
  return Buffer.concat([ethHdr(0x0800), ip4Hdr(src, dst, 6, tcp.length), tcp]);
}

/** Minimal ClientHello carrying one SNI (layout proven in tls.test.ts G1). */
function clientHello(sniHost: string): Buffer {
  const name = Buffer.from(sniHost, "ascii");
  const listLen = Buffer.alloc(2);
  listLen.writeUInt16BE(1 + 2 + name.length);
  const nameLen = Buffer.alloc(2);
  nameLen.writeUInt16BE(name.length);
  const extLen = listLen.length + 1 + nameLen.length + name.length;
  const extHdr = Buffer.alloc(4);
  extHdr.writeUInt16BE(0x0000, 0); // server_name
  extHdr.writeUInt16BE(extLen, 2);
  const sniExtPart = Buffer.concat([extHdr, listLen, Buffer.from([0]), nameLen, name]);
  const hsBody = Buffer.concat([
    Buffer.from("0303", "hex"),
    Buffer.alloc(32), // random
    Buffer.from([0]), // session id length
    Buffer.from([0x00, 0x02]),
    Buffer.from([0x00, 0x2f]), // one cipher suite
    Buffer.from([0x00]), // one compression method
    (() => {
      const e = Buffer.alloc(2);
      e.writeUInt16BE(sniExtPart.length);
      return e;
    })(),
    sniExtPart,
  ]);
  const hi = Buffer.alloc(4);
  hi[0] = 0x01; // ClientHello
  hi.writeUIntBE(hsBody.length, 1, 3);
  const rec = Buffer.alloc(5);
  rec[0] = 0x16;
  rec.write("0303", 1, "hex");
  rec.writeUInt16BE(hi.length + hsBody.length, 3);
  return Buffer.concat([rec, hi, hsBody]);
}

describe("flows catalog (I) — keying + attribution", () => {
  it("flow I1: TLS SNI from a ClientHello inside a flow is attributed to that flow's tlsSni", () => {
    const frame = rawTcp(
      "10.0.0.1",
      40000,
      "10.0.0.2",
      443,
      PSH | ACK,
      1,
      clientHello("shop.example.com"),
    );
    const a = buildFlows(makePcap([frame]), "t");
    expect(a.flows).toHaveLength(1);
    expect(a.flows[0].tlsSni).toEqual(["shop.example.com"]);
  });

  it("flow I2: canonical endpoints are ordered (a = the lower ip:port string) regardless of who spoke first", () => {
    // B speaks first, but 10.0.0.1 sorts first — direction labels must be
    // relative to A=10.0.0.1 regardless of the initial packet's direction.
    const pkts = [
      tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, SYN | ACK, 0, 1),
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, ACK, 1, 1),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const f = a.flows[0];
    expect(f.a.ip).toBe("10.0.0.1");
    expect(f.b.ip).toBe("10.0.0.2");
    expect(f.packets.a2b).toBe(1); // only the 10.0.0.1 -> 10.0.0.2 packet
    expect(f.packets.b2a).toBe(1);
  });

  it("flow I3: duplicate EPBs count in packets/bytes (EPB view) but merge in the deduped view", () => {
    // identical bytes 100µs apart -> same ipHash within the 2000µs tolerance
    const pkt = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, SYN, 0, 0);
    const a = buildFlows(makePcap([pkt, Buffer.from(pkt)], 100), "t");
    const f = a.flows[0];
    expect(f.packets.a2b).toBe(2); // EPB view counts copies (documented rule)
    expect(a.duplicatesMerged).toBe(1);
  });

  it("flow I4: same 4-tuple on UDP vs TCP = two different flows (proto is part of the key)", () => {
    const a = buildFlows(
      makePcap([
        tcpPkt("10.0.0.1", 53, "10.0.0.2", 9999, SYN, 0, 0),
        udpPkt("10.0.0.1", 53, "10.0.0.2", 9999, Buffer.from("x")),
      ]),
      "t",
    );
    expect(a.flows).toHaveLength(2);
  });

  it("flow I5: DNS answer attribution maps the queried name onto the answer IP (dnsHostByIp + flow hosts)", () => {
    const dnsMsgBuf = (() => {
      const h = Buffer.alloc(12);
      h.writeUInt16BE(0x2cc0, 0);
      h.writeUInt16BE(0x8180, 2); // response, rcode 0
      h.writeUInt16BE(1, 4); // qd
      h.writeUInt16BE(1, 6); // an
      const qname = Buffer.concat([
        Buffer.from([7]),
        Buffer.from("example"),
        Buffer.from([3]),
        Buffer.from("org"),
        Buffer.from([0]),
      ]);
      const q = Buffer.concat([qname, Buffer.from([0, 1, 0, 1])]); // type A, class IN
      const rec = Buffer.alloc(10);
      rec.writeUInt16BE(1, 0); // type A (fixed 10-byte record: type@0 class@2)
      rec.writeUInt16BE(1, 2); // class IN
      rec.writeUInt16BE(4, 8); // rdlength 4
      const ans = Buffer.concat([Buffer.from([0xc0, 0x0c]), rec, Buffer.from([93, 184, 216, 34])]);
      return Buffer.concat([h, q, ans]);
    })();
    const helloFrame = rawTcp(
      "10.0.0.1",
      40000,
      "93.184.216.34",
      443,
      PSH | ACK,
      1,
      Buffer.from("\x16\x03\x01\x00\x01\x01", "latin1"), // record header bytes only — no real SNI
    );
    const a = buildFlows(
      makePcap([udpPkt("198.51.100.53", 53, "10.0.0.1", 40000, dnsMsgBuf), helloFrame]),
      "t",
    );
    expect(a.dnsHostByIp.find((h) => h.ip === "93.184.216.34")?.names).toContain("example.org");
    const webFlow = a.flows.find((f) => f.kind === "tcp");
    expect(webFlow?.hosts).toContain("example.org");
    expect(webFlow?.tlsSni).toEqual([]); // bogus hello bytes never yield a fake SNI
  });

  it("flow I6: flow time span uses the packet timestamps (lastTs - firstTs = spacing over the span)", () => {
    const pkt = () => tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 1, 1, Buffer.from("a"));
    const a = buildFlows(makePcap([pkt(), pkt(), pkt()], 50000), "t"); // 50 ms spacing
    const f = a.flows[0];
    expect(f.lastTs - f.firstTs).toBeCloseTo(0.1, 5); // 2 × 50 000 µs = 100 000 µs
    expect(f.events.length).toBe(3);
  });

  it("flow I7: ICMP request+reply map to ONE IP-pair flow (port-free keying, both directions counted)", () => {
    const icmpPing = (typeAndCode: number[], src: string, dst: string): Buffer =>
      Buffer.concat([
        ethHdr(0x0800),
        ip4Hdr(src, dst, 1, 12),
        Buffer.concat([Buffer.from(typeAndCode), Buffer.from([0, 1, 0, 1, 1, 2, 3, 4])]),
      ]);
    const a = buildFlows(
      makePcap([
        icmpPing([8, 0], "10.0.0.1", "8.8.8.8"), // echo request
        icmpPing([0, 0], "8.8.8.8", "10.0.0.1"), // echo reply
      ]),
      "t",
    );
    expect(a.flows).toHaveLength(1);
    const f = a.flows[0];
    expect(f.kind).toBe("icmp");
    expect(f.packets.a2b).toBe(1);
    expect(f.packets.b2a).toBe(1);
    expect(f.a.port).toBe(0); // port-free keying
  });

  it("flow I9: SYN/ACK without captured SYN (late capture) -> flow created, synAck recorded (catalog I9)", () => {
    const a = buildFlows(
      makePcap([tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, SYN | ACK, 100, 1)]),
      "t",
    );
    expect(a.flows).toHaveLength(1);
    expect(a.flows[0].tcp?.synAck).toBeDefined();
    expect(a.flows[0].tcp?.syn).toBeUndefined();
  });

  it("flow I10: mid-stream capture with no SYN -> baseAssumed flag set on stream (catalog I10)", () => {
    const a = buildFlows(
      makePcap([
        tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 5000, 1, Buffer.from("midstream")),
      ]),
      "t",
    );
    expect(a.flows).toHaveLength(1);
    const stream = a.flows[0].tcp?.a2b ?? a.flows[0].tcp?.b2a;
    expect(stream?.baseAssumed).toBe(true);
    expect(stream?.bytes.toString("latin1")).toBe("midstream");
  });

  it("flow I14: same ports on different IPs -> distinct flows (5-tuple uniqueness)", () => {
    const a = buildFlows(
      makePcap([
        tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, SYN, 1, 0),
        tcpPkt("10.0.0.3", 1000, "10.0.0.2", 80, SYN, 1, 0),
      ]),
      "t",
    );
    expect(a.flows).toHaveLength(2);
    expect(a.flows[0].id).not.toBe(a.flows[1].id);
  });

  it("flow I15: 32-bit sequence wraparound (RFC 9293 §3.4) -> reassembles across 0xFFFFFFFF boundary with 0 gaps", () => {
    const p1 = tcpPkt(
      "10.0.0.1",
      1000,
      "10.0.0.2",
      80,
      PSH | ACK,
      0xffffff80 >>> 0,
      1,
      Buffer.alloc(128, 0x41),
    );
    const p2 = tcpPkt(
      "10.0.0.1",
      1000,
      "10.0.0.2",
      80,
      PSH | ACK,
      0x00000000,
      1,
      Buffer.alloc(128, 0x42),
    );
    const a = buildFlows(makePcap([p1, p2]), "t");
    const stream = a.flows[0].tcp?.a2b ?? a.flows[0].tcp?.b2a;
    expect(stream?.gapCount).toBe(0);
    expect(stream?.bytes.length).toBe(256);
    expect(stream?.bytes[0]).toBe(0x41);
    expect(stream?.bytes[255]).toBe(0x42);
  });

  it("flow I19: overlapping retransmission (partial overlap) -> partialRetransSegs recorded, novel bytes appended", () => {
    const b1 = Buffer.from("0123456789");
    const b2 = Buffer.from("56789ABCDE"); // 5 bytes overlap (seq 5..9), 5 novel bytes (seq 10..14)
    const p1 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 0, 1, b1);
    const p2 = tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 5, 1, b2);
    const a = buildFlows(makePcap([p1, p2], 5000), "t");
    const stream = a.flows[0].tcp?.a2b ?? a.flows[0].tcp?.b2a;
    expect(stream?.partialRetransSegs).toBe(1);
    expect(stream?.bytes.toString("latin1")).toBe("0123456789ABCDE");
  });

  it("flow I25: bytes and packets per direction are exact for multi-packet exchange (catalog I25)", () => {
    const pkts = [
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 1, 1, Buffer.alloc(10)),
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 11, 1, Buffer.alloc(20)),
      tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, PSH | ACK, 1, 31, Buffer.alloc(30)),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const f = a.flows[0];
    const clientIsA = f.a.ip === "10.0.0.1";
    expect(clientIsA ? f.packets.a2b : f.packets.b2a).toBe(2);
    expect(clientIsA ? f.packets.b2a : f.packets.a2b).toBe(1);
    expect(f.uniquePackets).toBe(3);
  });
});
