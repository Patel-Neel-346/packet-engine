// -----------------------------------------------------------------------------
// FLOW-ENGINE SUITE � src/engine/flows.ts + src/engine/dedupe.ts
// Run:  npm test           (one-shot)      npm run test:watch   (live)
//
// Synthetic packets ONLY � no tshark, no elevation, no files on disk. Every
// suite builds frames byte-by-byte (builders below) and feeds them straight
// into buildFlows/dedupePackets, so a failure points at engine logic, not
// capture tooling.
//
// Coverage map (numbered claim ? suite below):
//   1. sparse-stream reassembly      ? "TCP stream reassembly"
//   2. TCP lifecycle story           ? "TCP lifecycle story"
//   3. HTTP/1.x parsing              ? "HTTP story"
//   4. DNS attribution               ? "DNS attribution"
//   5. ICMP port-less flows          ? "UDP & ICMP flows"
//   6. dedupe tolerance window       ? "dedupe"
//   7. bytesLabel formatting         ? "bytesLabel"
//   8. out-of-order segments         ? "TCP stream reassembly"
//   9. retransmission detection      ? "TCP stream reassembly"
//  11. fragment / non-IP / empty-trace accounting ? "accounting edges"
// -----------------------------------------------------------------------------

import { describe, it, expect } from "@jest/globals";
import { buildFlows, bytesLabel } from "../src/engine/flows.ts";
import { dedupePackets, decodeAllPackets } from "../src/engine/dedupe.ts";

// -- inline fixture builders --------------------------------------------------

function ethHdr(ethertype: number) {
  const h = Buffer.alloc(14);
  Buffer.from("020203040506", "hex").copy(h, 0);
  Buffer.from("020203040507", "hex").copy(h, 6);
  h.writeUInt16BE(ethertype, 12);
  return h;
}

function ip4Hdr(
  src: string,
  dst: string,
  proto: number,
  payloadLen: number,
  id = 0x1234,
  flags = 2,
  frag = 0,
) {
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + payloadLen, 2);
  h.writeUInt16BE(id, 4);
  h.writeUInt16BE((flags << 13) | frag, 6);
  h[8] = 64;
  h[9] = proto;
  src.split(".").forEach((b, i) => (h[12 + i] = Number(b)));
  dst.split(".").forEach((b, i) => (h[16 + i] = Number(b)));
  let sum = 0;
  for (let i = 0; i < 20; i += 2) sum += h.readUInt16BE(i);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  h.writeUInt16BE(~sum & 0xffff, 10);
  return h;
}

function tcpPkt(
  src: string,
  sport: number,
  dst: string,
  dport: number,
  flags: number,
  seq: number,
  ack: number,
  payload = Buffer.alloc(0),
) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 0x50;
  tcp[13] = flags & 0xff;
  tcp.writeUInt16BE(65535, 14);
  payload.copy(tcp, 20);
  const ip = ip4Hdr(src, dst, 6, tcp.length);
  return Buffer.concat([ethHdr(0x0800), ip, tcp]);
}

function udpPkt(src: string, sport: number, dst: string, dport: number, payload: Buffer) {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(sport, 0);
  udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  payload.copy(udp, 8);
  const ip = ip4Hdr(src, dst, 17, udp.length);
  return Buffer.concat([ethHdr(0x0800), ip, udp]);
}

function icmpPkt(src: string, dst: string) {
  const icmp = Buffer.from([0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01]);
  const ip = ip4Hdr(src, dst, 1, icmp.length);
  return Buffer.concat([ethHdr(0x0800), ip, icmp]);
}

/** Hand-rolled PcapngFile: 1 interface (tsresol=6), packets i*tsGapUs apart. */
function makePcap(frames: Buffer[], tsGapUs = 1000) {
  const iface = { id: 0, linkType: 1, snaplen: 65535, tsResolRaw: 6, name: null, os: null };
  const packets = frames.map((data, i) => ({
    interfaceId: 0,
    tsHigh: 0,
    tsLow: i * tsGapUs,
    capLen: data.length,
    origLen: data.length,
    data,
    options: { epbFlags: null, epbHash: null, comment: null, dropCount: null },
  }));
  return {
    shb: { majorVersion: 1, minorVersion: 0, sectionLength: -1n, littleEndian: true },
    interfaces: [iface],
    packets,
    skippedBlocks: [],
    parseErrors: [],
  };
}

const SYN = 0x02,
  FIN = 0x01,
  RST = 0x04,
  ACK = 0x10,
  PSH = 0x08;

// -- suites -------------------------------------------------------------------

describe("bytesLabel", () => {
  it("formats 0B / B / KB / MB with the SI-scaled scheme used in reports", () => {
    expect(bytesLabel(0)).toBe("0B");
    expect(bytesLabel(500)).toBe("500B");
    expect(bytesLabel(1024)).toBe("1.0KB");
    expect(bytesLabel(1024 * 1024)).toBe("1.00MB");
    expect(bytesLabel(1536)).toBe("1.5KB");
  });
});

describe("TCP lifecycle story", () => {
  it("a clean handshake?data?FIN connection sets handshakeComplete and both FINs, with no RST", () => {
    const pkts = [
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, SYN, 0, 0),
      tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, SYN | ACK, 0, 1),
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, ACK, 1, 1),
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 1, 1, Buffer.from("hello")),
      tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, ACK, 1, 6),
      tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, FIN | ACK, 6, 1),
      tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, FIN | ACK, 1, 7),
    ];
    const a = buildFlows(makePcap(pkts), "test");
    expect(a.flows).toHaveLength(1);
    const f = a.flows[0];
    expect(f.kind).toBe("tcp");
    const t = f.tcp!;
    expect(t.syn).toBeTruthy(); // SYN seen
    expect(t.synAck).toBeTruthy(); // SYN-ACK seen
    expect(t.handshakeComplete).toBe(true);
    expect(t.finA2b).toBeTruthy(); // FIN a->b
    expect(t.finB2a).toBeTruthy(); // FIN b->a
    expect(t.rst).toBeFalsy(); // no RST � clean close only
    // 10.0.0.1 < 10.0.0.2 so a=10.0.0.1:1000 ? a2b carries 'hello'
    const a2b = t.a2b;
    expect(a2b).toBeTruthy();
    expect(a2b!.gapCount).toBe(0);
    expect(a2b!.retransSegs).toBe(0);
    expect(a2b!.bytes.toString()).toBe("hello");
  });

  it("an RST is recorded and blocks handshakeComplete", () => {
    const pkts = [
      tcpPkt("1.2.3.4", 5000, "5.6.7.8", 80, SYN, 0, 0),
      tcpPkt("5.6.7.8", 80, "1.2.3.4", 5000, SYN | ACK, 0, 1),
      tcpPkt("1.2.3.4", 5000, "5.6.7.8", 80, RST, 1, 1),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const t = a.flows[0].tcp!;
    expect(t.rst).toBeTruthy();
    expect(t.handshakeComplete).toBe(false);
  });

  it("three simultaneous connections (2 TCP-style + 1 UDP) become three distinct flows", () => {
    const pkts = [
      tcpPkt("20.0.0.1", 1001, "20.0.0.2", 80, SYN, 0, 0),
      tcpPkt("20.0.0.1", 1002, "20.0.0.3", 443, SYN, 0, 0),
      udpPkt("20.0.0.1", 5001, "8.8.8.8", 53, Buffer.from("x")),
      tcpPkt("20.0.0.2", 80, "20.0.0.1", 1001, SYN | ACK, 0, 1),
      tcpPkt("20.0.0.3", 443, "20.0.0.1", 1002, SYN | ACK, 0, 1),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    expect(a.flows).toHaveLength(3);
    expect(a.flows.map((f) => f.kind).sort()).toEqual(["tcp", "tcp", "udp"]);
  });
});

describe("TCP stream reassembly", () => {
  it("out-of-order segments are placed in sequence order, gap-free", () => {
    const pkts = [
      tcpPkt("1.0.0.1", 2000, "1.0.0.2", 443, SYN, 0, 0),
      tcpPkt("1.0.0.2", 443, "1.0.0.1", 2000, SYN | ACK, 0, 1),
      // out-of-order: seq=6 ("World") arrives BEFORE seq=1 ("Hello")
      tcpPkt("1.0.0.1", 2000, "1.0.0.2", 443, PSH | ACK, 6, 1, Buffer.from("World")),
      tcpPkt("1.0.0.1", 2000, "1.0.0.2", 443, PSH | ACK, 1, 1, Buffer.from("Hello")),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const a2b = a.flows[0].tcp!.a2b!;
    expect(a2b.bytes.length).toBeGreaterThanOrEqual(10);
    expect(a2b.bytes.subarray(0, 5).toString()).toBe("Hello");
    expect(a2b.bytes.subarray(5, 10).toString()).toBe("World");
    expect(a2b.gapCount).toBe(0);
  });

  it("a missing segment is recorded as a gap and zeroed in the stream bytes", () => {
    const pkts = [
      tcpPkt("3.0.0.1", 4000, "3.0.0.2", 80, SYN, 0, 0),
      tcpPkt("3.0.0.2", 80, "3.0.0.1", 4000, SYN | ACK, 0, 1),
      tcpPkt("3.0.0.1", 4000, "3.0.0.2", 80, PSH | ACK, 1, 1, Buffer.from("AAAAA")),
      // gap of 5 bytes (seq 6..10 missing)
      tcpPkt("3.0.0.1", 4000, "3.0.0.2", 80, PSH | ACK, 11, 1, Buffer.from("BBBBB")),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const s = a.flows[0].tcp!.a2b!;
    expect(s.gapCount).toBe(1);
    expect(s.gapBytes).toBe(5);
    // AAAAA [00000] BBBBB � the gap is visible, not silently skipped
    expect(s.bytes.length).toBe(15);
    expect(s.bytes.subarray(0, 5).toString()).toBe("AAAAA");
    expect([...s.bytes.subarray(5, 10)]).toEqual([0, 0, 0, 0, 0]);
    expect(s.bytes.subarray(10, 15).toString()).toBe("BBBBB");
  });

  it("a fully-covered retransmitted segment counts once in retransSegs (dedupe uses 5000us spacing)", () => {
    const payload = Buffer.from("data");
    // 5000 us spacing so the byte-identical retransmit is NOT merged as a
    // duplicate capture copy (dedupe tolerance is 2000 us) � it must instead
    // surface as a real retransmission story.
    const pkts = [
      tcpPkt("2.0.0.1", 3000, "2.0.0.2", 80, SYN, 0, 0),
      tcpPkt("2.0.0.2", 80, "2.0.0.1", 3000, SYN | ACK, 0, 1),
      tcpPkt("2.0.0.1", 3000, "2.0.0.2", 80, PSH | ACK, 1, 1, payload),
      tcpPkt("2.0.0.1", 3000, "2.0.0.2", 80, PSH | ACK, 1, 1, payload), // retransmit
    ];
    const a = buildFlows(makePcap(pkts, 5000), "t");
    const f = a.flows[0];
    const s = f.tcp!.a2b;
    expect(s).toBeTruthy();
    expect(s!.retransSegs).toBe(1);
    expect(s!.retransBytes).toBe(payload.length);
    expect(f.uniqueRetransSegs).toBe(1);
    expect(a.retransSegsTotal).toBe(1); // the trace-level rollup used by M3 checks
  });
});

describe("UDP & ICMP flows", () => {
  it("UDP flows keep per-direction packet counts", () => {
    const pkts = [
      udpPkt("5.0.0.1", 12345, "5.0.0.2", 53, Buffer.alloc(100)),
      udpPkt("5.0.0.2", 53, "5.0.0.1", 12345, Buffer.alloc(200)),
      udpPkt("5.0.0.1", 12345, "5.0.0.2", 53, Buffer.alloc(100)),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    expect(a.flows).toHaveLength(1);
    const f = a.flows[0];
    expect(f.kind).toBe("udp");
    expect(f.packets.a2b).toBe(2);
    expect(f.packets.b2a).toBe(1);
  });

  it("ICMP is keyed by the IP pair alone (no ports involved)", () => {
    const pkts = [icmpPkt("6.0.0.1", "6.0.0.2"), icmpPkt("6.0.0.2", "6.0.0.1")];
    const a = buildFlows(makePcap(pkts), "t");
    expect(a.flows).toHaveLength(1);
    expect(a.flows[0].kind).toBe("icmp");
    expect(a.flows[0].packets.a2b + a.flows[0].packets.b2a).toBe(2);
  });
});

describe("HTTP story", () => {
  it("GET + 200 with Content-Length parses head AND body completeness", () => {
    const reqBuf = Buffer.from(
      "GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    );
    const body = Buffer.from("<html>ok</html>");
    const respBuf = Buffer.concat([
      Buffer.from(
        "HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\nContent-Type: text/html\r\n\r\n",
      ),
      body,
    ]);
    const pkts = [
      tcpPkt("9.0.0.1", 6000, "9.0.0.2", 80, SYN, 0, 0),
      tcpPkt("9.0.0.2", 80, "9.0.0.1", 6000, SYN | ACK, 0, 1),
      tcpPkt("9.0.0.1", 6000, "9.0.0.2", 80, PSH | ACK, 1, 1, reqBuf),
      tcpPkt("9.0.0.2", 80, "9.0.0.1", 6000, PSH | ACK, 1, reqBuf.length + 1, respBuf),
      tcpPkt("9.0.0.1", 6000, "9.0.0.2", 80, FIN | ACK, reqBuf.length + 1, respBuf.length + 1),
      tcpPkt("9.0.0.2", 80, "9.0.0.1", 6000, FIN | ACK, respBuf.length + 1, reqBuf.length + 2),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const http = a.flows[0].http;
    expect(http).toBeTruthy();
    expect(http!.requests[0].method).toBe("GET");
    expect(http!.requests[0].uri).toBe("/index.html");
    expect(http!.responses[0].status).toBe(200);
    expect(http!.responses[0].contentLength).toBe(body.length); // the honest byte count
    expect(http!.responses[0].bodyComplete).toBe(true);
  });

  it("chunked Transfer-Encoding is detected and stops parsing as 'chunked', not 'end'", () => {
    const reqBuf = Buffer.from("GET / HTTP/1.1\r\nHost: x.com\r\n\r\n");
    const respBuf = Buffer.from(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    );
    const pkts = [
      tcpPkt("11.0.0.1", 7000, "11.0.0.2", 80, SYN, 0, 0),
      tcpPkt("11.0.0.2", 80, "11.0.0.1", 7000, SYN | ACK, 0, 1),
      tcpPkt("11.0.0.1", 7000, "11.0.0.2", 80, PSH | ACK, 1, 1, reqBuf),
      tcpPkt("11.0.0.2", 80, "11.0.0.1", 7000, PSH | ACK, 1, reqBuf.length + 1, respBuf),
      tcpPkt("11.0.0.1", 7000, "11.0.0.2", 80, FIN | ACK, reqBuf.length + 1, respBuf.length + 1),
      tcpPkt("11.0.0.2", 80, "11.0.0.1", 7000, FIN | ACK, respBuf.length + 1, reqBuf.length + 2),
    ];
    const a = buildFlows(makePcap(pkts), "t");
    const http = a.flows[0].http;
    expect(http).toBeTruthy();
    expect(http!.responses[0].chunked).toBe(true);
    expect(http!.parsingStopped).toBe("chunked");
  });
});

describe("DNS attribution", () => {
  it("an A record maps the answered IP to the queried name (dnsHostByIp)", () => {
    // Hand-built response: example.com ? 93.184.216.34
    const name = "example.com";
    const labels = name
      .split(".")
      .map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
    const nameBuf = Buffer.concat([...labels, Buffer.from([0])]);
    const hdr = Buffer.alloc(12);
    hdr.writeUInt16BE(1, 0); // id
    hdr.writeUInt16BE(0x8000, 2); // QR=1 (response)
    hdr.writeUInt16BE(1, 4); // QDCOUNT
    hdr.writeUInt16BE(1, 6); // ANCOUNT
    const qSection = Buffer.concat([nameBuf, Buffer.from([0, 1, 0, 1])]);
    const ansPtr = Buffer.from([0xc0, 0x0c]); // pointer to question name
    const ansMeta = Buffer.alloc(10);
    ansMeta.writeUInt16BE(1, 0); // TYPE A
    ansMeta.writeUInt16BE(1, 2); // CLASS IN
    ansMeta.writeUInt32BE(300, 4); // TTL
    ansMeta.writeUInt16BE(4, 8); // RDLENGTH
    const ip = Buffer.from([93, 184, 216, 34]);
    const dns = Buffer.concat([hdr, qSection, ansPtr, ansMeta, ip]);
    const pkt = udpPkt("8.8.8.8", 53, "10.0.0.1", 12000, dns);
    const a = buildFlows(makePcap([pkt]), "t");
    const rec = a.dnsHostByIp.find((r) => r.ip === "93.184.216.34");
    expect(rec).toBeTruthy();
    expect(rec!.names.includes("example.com")).toBe(true);
  });
});

describe("dedupe (capture-copy collapsing)", () => {
  it("same-hash packets within the 2000us tolerance collapse into one unique group", () => {
    const pkt = tcpPkt("12.0.0.1", 8000, "12.0.0.2", 80, SYN, 0, 0);
    const pcap = makePcap([pkt, pkt], 1000); // 1000us apart < tolerance
    const decoded = decodeAllPackets(pcap);
    const { groups, duplicatesMerged } = dedupePackets(pcap, decoded);
    expect(groups).toHaveLength(1);
    expect(duplicatesMerged).toBe(1);
  });

  it("same-hash packets OUTSIDE the tolerance are two separate uniques (not a copy)", () => {
    const pkt = tcpPkt("13.0.0.1", 9000, "13.0.0.2", 80, SYN, 0, 0);
    const pcap = makePcap([pkt, pkt], 5000); // 5000us apart > tolerance
    const decoded = decodeAllPackets(pcap);
    const { groups, duplicatesMerged } = dedupePackets(pcap, decoded);
    expect(groups).toHaveLength(2);
    expect(duplicatesMerged).toBe(0);
  });
});

describe("accounting edges (fragments, non-IP, empty traces)", () => {
  it("victim of fragmentation: a non-first IPv4 fragment goes to fragments[], NOT flows[]", () => {
    const fragPayload = Buffer.alloc(20);
    // frag offset 1480/8=185 ? this fragment starts at byte 1480; no
    // first-fragment seen ? must not be keyed to any flow.
    const ip = ip4Hdr("7.0.0.1", "7.0.0.2", 6, fragPayload.length, 0xabcd, 0, 1480 / 8);
    const pkt = Buffer.concat([ethHdr(0x0800), ip, fragPayload]);
    const a = buildFlows(makePcap([pkt]), "t");
    expect(a.flows).toHaveLength(0);
    expect(a.fragments).toHaveLength(1);
    expect(a.nonFlowEpbs).toBe(0);
  });

  it("non-IP frames (ARP ethertype) are counted as nonFlowEpbs", () => {
    const arp = Buffer.alloc(28, 0);
    const pkt = Buffer.concat([ethHdr(0x0806), arp]);
    const a = buildFlows(makePcap([pkt]), "t");
    expect(a.flows).toHaveLength(0);
    expect(a.nonFlowEpbs).toBe(1);
  });

  it("an empty PCAPNG produces zero flows and zero warnings", () => {
    const a = buildFlows(makePcap([]), "empty");
    expect(a.flows).toHaveLength(0);
    expect(a.totalEpbs).toBe(0);
    expect(a.warnings).toHaveLength(0);
  });
});
