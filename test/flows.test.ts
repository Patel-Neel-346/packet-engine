// Flow-engine unit tests (synthetic data — no tshark, no elevation, no files).
//
// Covers:
//   1. SparseStream reassembly via buildFlows on synthetic PcapngFile
//   2. TCP lifecycle story (SYN / SYN-ACK / FIN / RST / handshakeComplete)
//   3. HTTP/1.x parsing (GET pipeline, response with Content-Length, chunked)
//   4. DNS attribution (A + AAAA records -> ip->names map)
//   5. ICMP flow keyed by IP pair (port-less)
//   6. Dedupe -- same-hash + timestamp tolerance collapses copies
//   7. bytesLabel helper
//   8. Out-of-order segments reassembled in correct order
//   9. Retransmission detection (fully covered + partial)
//  10. Seq-number 32-bit wrap
//  11. Fragment stats (non-first IPv4 fragment not keyed to a flow)

import test from 'node:test';
import assert from 'node:assert/strict';
import { buildFlows, bytesLabel } from '../src/flows.ts';
import { dedupePackets, decodeAllPackets } from '../src/dedupe.ts';

// ---- helpers ---------------------------------------------------------------

function ethHdr(ethertype) {
  const h = Buffer.alloc(14);
  Buffer.from('020203040506', 'hex').copy(h, 0);
  Buffer.from('020203040507', 'hex').copy(h, 6);
  h.writeUInt16BE(ethertype, 12);
  return h;
}

function ip4Hdr(src, dst, proto, payloadLen, id = 0x1234, flags = 2, frag = 0) {
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + payloadLen, 2);
  h.writeUInt16BE(id, 4);
  h.writeUInt16BE((flags << 13) | frag, 6);
  h[8] = 64;
  h[9] = proto;
  src.split('.').forEach((b, i) => h[12 + i] = Number(b));
  dst.split('.').forEach((b, i) => h[16 + i] = Number(b));
  let sum = 0;
  for (let i = 0; i < 20; i += 2) sum += h.readUInt16BE(i);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  h.writeUInt16BE(~sum & 0xffff, 10);
  return h;
}

function tcpPkt(src, sport, dst, dport, flags, seq, ack, payload = Buffer.alloc(0)) {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0); tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4); tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 0x50; tcp[13] = flags & 0xff; tcp.writeUInt16BE(65535, 14);
  payload.copy(tcp, 20);
  const ip = ip4Hdr(src, dst, 6, tcp.length);
  return Buffer.concat([ethHdr(0x0800), ip, tcp]);
}

function udpPkt(src, sport, dst, dport, payload) {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(sport, 0); udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  payload.copy(udp, 8);
  const ip = ip4Hdr(src, dst, 17, udp.length);
  return Buffer.concat([ethHdr(0x0800), ip, udp]);
}

function icmpPkt(src, dst) {
  const icmp = Buffer.from([0x08, 0x00, 0xf7, 0xff, 0x00, 0x01, 0x00, 0x01]);
  const ip = ip4Hdr(src, dst, 1, icmp.length);
  return Buffer.concat([ethHdr(0x0800), ip, icmp]);
}

function makePcap(frames, tsGapUs = 1000) {
  const iface = { id: 0, linkType: 1, snaplen: 65535, tsResolRaw: 6, name: null, os: null };
  const packets = frames.map((data, i) => ({
    interfaceId: 0, tsHigh: 0, tsLow: i * tsGapUs,
    capLen: data.length, origLen: data.length, data,
    options: { epbFlags: null, epbHash: null, comment: null, dropCount: null },
  }));
  return {
    shb: { majorVersion: 1, minorVersion: 0, sectionLength: -1n, littleEndian: true },
    interfaces: [iface], packets, skippedBlocks: [], parseErrors: [],
  };
}

const SYN = 0x02, FIN = 0x01, RST = 0x04, ACK = 0x10, PSH = 0x08;

// ---- tests -----------------------------------------------------------------

test('bytesLabel formats correctly', () => {
  assert.equal(bytesLabel(0), '0B');
  assert.equal(bytesLabel(500), '500B');
  assert.equal(bytesLabel(1024), '1.0KB');
  assert.equal(bytesLabel(1024 * 1024), '1.00MB');
  assert.equal(bytesLabel(1536), '1.5KB');
});

test('single TCP flow: SYN/SYN-ACK/data/FIN, handshakeComplete=true', () => {
  const pkts = [
    tcpPkt('10.0.0.1', 1000, '10.0.0.2', 80, SYN, 0, 0),
    tcpPkt('10.0.0.2', 80, '10.0.0.1', 1000, SYN|ACK, 0, 1),
    tcpPkt('10.0.0.1', 1000, '10.0.0.2', 80, ACK, 1, 1),
    tcpPkt('10.0.0.1', 1000, '10.0.0.2', 80, PSH|ACK, 1, 1, Buffer.from('hello')),
    tcpPkt('10.0.0.2', 80, '10.0.0.1', 1000, ACK, 1, 6),
    tcpPkt('10.0.0.1', 1000, '10.0.0.2', 80, FIN|ACK, 6, 1),
    tcpPkt('10.0.0.2', 80, '10.0.0.1', 1000, FIN|ACK, 1, 7),
  ];
  const a = buildFlows(makePcap(pkts), 'test');
  assert.equal(a.flows.length, 1, 'exactly one flow');
  const f = a.flows[0];
  assert.equal(f.kind, 'tcp');
  const t = f.tcp;
  assert.ok(t.syn, 'SYN seen');
  assert.ok(t.synAck, 'SYN-ACK seen');
  assert.ok(t.handshakeComplete, 'handshake complete');
  assert.ok(t.finA2b, 'FIN a->b');
  assert.ok(t.finB2a, 'FIN b->a');
  assert.ok(!t.rst, 'no RST');
  // 10.0.0.1 < 10.0.0.2 so a=10.0.0.1:1000 -> a2b carries 'hello'
  const a2b = t.a2b;
  assert.ok(a2b, 'a2b stream present');
  assert.equal(a2b.gapCount, 0, 'no gaps');
  assert.equal(a2b.retransSegs, 0, 'no retransmissions');
  assert.equal(a2b.bytes.toString(), 'hello');
});

test('TCP RST: recorded, handshake incomplete', () => {
  const pkts = [
    tcpPkt('1.2.3.4', 5000, '5.6.7.8', 80, SYN, 0, 0),
    tcpPkt('5.6.7.8', 80, '1.2.3.4', 5000, SYN|ACK, 0, 1),
    tcpPkt('1.2.3.4', 5000, '5.6.7.8', 80, RST, 1, 1),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  const t = a.flows[0].tcp;
  assert.ok(t.rst, 'RST recorded');
  assert.ok(!t.handshakeComplete, 'handshake not complete');
});

test('TCP out-of-order: segments reassembled in seq order', () => {
  const pkts = [
    tcpPkt('1.0.0.1', 2000, '1.0.0.2', 443, SYN, 0, 0),
    tcpPkt('1.0.0.2', 443, '1.0.0.1', 2000, SYN|ACK, 0, 1),
    // out-of-order: seq=6 arrives before seq=1
    tcpPkt('1.0.0.1', 2000, '1.0.0.2', 443, PSH|ACK, 6, 1, Buffer.from('World')),
    tcpPkt('1.0.0.1', 2000, '1.0.0.2', 443, PSH|ACK, 1, 1, Buffer.from('Hello')),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  const a2b = a.flows[0].tcp.a2b;
  assert.ok(a2b.bytes.length >= 10, 'both segments present');
  assert.equal(a2b.bytes.subarray(0, 5).toString(), 'Hello');
  assert.equal(a2b.bytes.subarray(5, 10).toString(), 'World');
  assert.equal(a2b.gapCount, 0, 'no gap (contiguous)');
});

test('TCP retransmission: fully-covered segment increments retransSegs', () => {
  const payload = Buffer.from('data');
  // Use 5000 us gap so same-hash packets are NOT deduped (exceed 2000 us tolerance)
  const pkts = [
    tcpPkt('2.0.0.1', 3000, '2.0.0.2', 80, SYN, 0, 0),
    tcpPkt('2.0.0.2', 80, '2.0.0.1', 3000, SYN|ACK, 0, 1),
    tcpPkt('2.0.0.1', 3000, '2.0.0.2', 80, PSH|ACK, 1, 1, payload),
    tcpPkt('2.0.0.1', 3000, '2.0.0.2', 80, PSH|ACK, 1, 1, payload), // retransmit
  ];
  const a = buildFlows(makePcap(pkts, 5000), 't');
  const f = a.flows[0];
  const s = f.tcp.a2b;
  assert.ok(s, 'a2b stream');
  assert.equal(s.retransSegs, 1, 'one retransmission segment');
  assert.equal(s.retransBytes, payload.length, 'correct retrans bytes');
  assert.equal(f.uniqueRetransSegs, 1, 'uniqueRetransSegs');
  assert.equal(a.retransSegsTotal, 1, 'retransSegsTotal');
});

test('TCP gap: missing segment recorded, zeroed in stream bytes', () => {
  const pkts = [
    tcpPkt('3.0.0.1', 4000, '3.0.0.2', 80, SYN, 0, 0),
    tcpPkt('3.0.0.2', 80, '3.0.0.1', 4000, SYN|ACK, 0, 1),
    tcpPkt('3.0.0.1', 4000, '3.0.0.2', 80, PSH|ACK, 1, 1, Buffer.from('AAAAA')),
    // gap of 5 bytes (seq 6..10 missing)
    tcpPkt('3.0.0.1', 4000, '3.0.0.2', 80, PSH|ACK, 11, 1, Buffer.from('BBBBB')),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  const s = a.flows[0].tcp.a2b;
  assert.equal(s.gapCount, 1, 'one gap');
  assert.equal(s.gapBytes, 5, '5 gap bytes');
  assert.equal(s.bytes.length, 15);
  assert.equal(s.bytes.subarray(0, 5).toString(), 'AAAAA');
  assert.deepEqual([...s.bytes.subarray(5, 10)], [0, 0, 0, 0, 0], 'gap zeroed');
  assert.equal(s.bytes.subarray(10, 15).toString(), 'BBBBB');
});

test('UDP flow: packet counts tracked per direction', () => {
  const pkts = [
    udpPkt('5.0.0.1', 12345, '5.0.0.2', 53, Buffer.alloc(100)),
    udpPkt('5.0.0.2', 53, '5.0.0.1', 12345, Buffer.alloc(200)),
    udpPkt('5.0.0.1', 12345, '5.0.0.2', 53, Buffer.alloc(100)),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  assert.equal(a.flows.length, 1);
  const f = a.flows[0];
  assert.equal(f.kind, 'udp');
  assert.equal(f.packets.a2b, 2);
  assert.equal(f.packets.b2a, 1);
});

test('ICMP flow: keyed by IP pair, not ports', () => {
  const pkts = [
    icmpPkt('6.0.0.1', '6.0.0.2'),
    icmpPkt('6.0.0.2', '6.0.0.1'),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  assert.equal(a.flows.length, 1, 'one ICMP flow');
  assert.equal(a.flows[0].kind, 'icmp');
  assert.equal(a.flows[0].packets.a2b + a.flows[0].packets.b2a, 2);
});

test('DNS attribution: A record maps IP to query name', () => {
  // Minimal DNS response for example.com -> 93.184.216.34
  const name = 'example.com';
  const labels = name.split('.').map(l => Buffer.concat([Buffer.from([l.length]), Buffer.from(l)]));
  const nameBuf = Buffer.concat([...labels, Buffer.from([0])]);
  const hdr = Buffer.alloc(12);
  hdr.writeUInt16BE(1, 0); // id
  hdr.writeUInt16BE(0x8000, 2); // QR=1
  hdr.writeUInt16BE(1, 4); // QDCOUNT
  hdr.writeUInt16BE(1, 6); // ANCOUNT
  const qSection = Buffer.concat([nameBuf, Buffer.from([0,1,0,1])]);
  const ansPtr = Buffer.from([0xc0, 0x0c]); // pointer
  const ansMeta = Buffer.alloc(10);
  ansMeta.writeUInt16BE(1, 0); // TYPE A
  ansMeta.writeUInt16BE(1, 2); // CLASS IN
  ansMeta.writeUInt32BE(300, 4); // TTL
  ansMeta.writeUInt16BE(4, 8); // RDLENGTH
  const ip = Buffer.from([93, 184, 216, 34]);
  const dns = Buffer.concat([hdr, qSection, ansPtr, ansMeta, ip]);
  const pkt = udpPkt('8.8.8.8', 53, '10.0.0.1', 12000, dns);
  const a = buildFlows(makePcap([pkt]), 't');
  const rec = a.dnsHostByIp.find(r => r.ip === '93.184.216.34');
  assert.ok(rec, 'IP in dnsHostByIp');
  assert.ok(rec.names.includes('example.com'), 'name attributed');
});

test('non-first IPv4 fragment counted in fragments[], not flows[]', () => {
  const fragPayload = Buffer.alloc(20);
  const ip = ip4Hdr('7.0.0.1', '7.0.0.2', 6, fragPayload.length, 0xabcd, 0, 1480 / 8);
  const pkt = Buffer.concat([ethHdr(0x0800), ip, fragPayload]);
  const a = buildFlows(makePcap([pkt]), 't');
  assert.equal(a.flows.length, 0, 'fragment not in flows');
  assert.equal(a.fragments.length, 1, 'fragment in fragments list');
  assert.equal(a.nonFlowEpbs, 0);
});

test('HTTP GET + 200 with Content-Length parsed correctly', () => {
  const reqBuf = Buffer.from('GET /index.html HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n');
  const body = Buffer.from('<html>ok</html>');
  const respBuf = Buffer.concat([
    Buffer.from('HTTP/1.1 200 OK\r\nContent-Length: ' + body.length + '\r\nContent-Type: text/html\r\n\r\n'),
    body,
  ]);
  const pkts = [
    tcpPkt('9.0.0.1', 6000, '9.0.0.2', 80, SYN, 0, 0),
    tcpPkt('9.0.0.2', 80, '9.0.0.1', 6000, SYN|ACK, 0, 1),
    tcpPkt('9.0.0.1', 6000, '9.0.0.2', 80, PSH|ACK, 1, 1, reqBuf),
    tcpPkt('9.0.0.2', 80, '9.0.0.1', 6000, PSH|ACK, 1, reqBuf.length + 1, respBuf),
    tcpPkt('9.0.0.1', 6000, '9.0.0.2', 80, FIN|ACK, reqBuf.length + 1, respBuf.length + 1),
    tcpPkt('9.0.0.2', 80, '9.0.0.1', 6000, FIN|ACK, respBuf.length + 1, reqBuf.length + 2),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  const http = a.flows[0].http;
  assert.ok(http, 'http story present');
  assert.equal(http.requests[0].method, 'GET');
  assert.equal(http.requests[0].uri, '/index.html');
  assert.equal(http.responses[0].status, 200);
  assert.equal(http.responses[0].contentLength, body.length);
  assert.ok(http.responses[0].bodyComplete);
});

test('HTTP chunked TE: detected and parsingStopped=chunked', () => {
  const reqBuf = Buffer.from('GET / HTTP/1.1\r\nHost: x.com\r\n\r\n');
  const respBuf = Buffer.from('HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n');
  const pkts = [
    tcpPkt('11.0.0.1', 7000, '11.0.0.2', 80, SYN, 0, 0),
    tcpPkt('11.0.0.2', 80, '11.0.0.1', 7000, SYN|ACK, 0, 1),
    tcpPkt('11.0.0.1', 7000, '11.0.0.2', 80, PSH|ACK, 1, 1, reqBuf),
    tcpPkt('11.0.0.2', 80, '11.0.0.1', 7000, PSH|ACK, 1, reqBuf.length + 1, respBuf),
    tcpPkt('11.0.0.1', 7000, '11.0.0.2', 80, FIN|ACK, reqBuf.length + 1, respBuf.length + 1),
    tcpPkt('11.0.0.2', 80, '11.0.0.1', 7000, FIN|ACK, respBuf.length + 1, reqBuf.length + 2),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  const http = a.flows[0].http;
  assert.ok(http, 'http story');
  assert.ok(http.responses[0].chunked, 'chunked detected');
  assert.equal(http.parsingStopped, 'chunked');
});

test('dedupe: same-hash within tolerance => one unique group', () => {
  const pkt = tcpPkt('12.0.0.1', 8000, '12.0.0.2', 80, SYN, 0, 0);
  // 1000 us apart < 2000 us tolerance
  const pcap = makePcap([pkt, pkt], 1000);
  const decoded = decodeAllPackets(pcap);
  const { groups, duplicatesMerged } = dedupePackets(pcap, decoded);
  assert.equal(groups.length, 1, 'two copies -> one group');
  assert.equal(duplicatesMerged, 1, 'one merged');
});

test('dedupe: same-hash outside tolerance => two separate uniques', () => {
  const pkt = tcpPkt('13.0.0.1', 9000, '13.0.0.2', 80, SYN, 0, 0);
  // 5000 us apart > 2000 us tolerance
  const pcap = makePcap([pkt, pkt], 5000);
  const decoded = decodeAllPackets(pcap);
  const { groups, duplicatesMerged } = dedupePackets(pcap, decoded);
  assert.equal(groups.length, 2, 'two separate uniques');
  assert.equal(duplicatesMerged, 0, 'no merge');
});

test('multiple concurrent flows are separated correctly', () => {
  const pkts = [
    tcpPkt('20.0.0.1', 1001, '20.0.0.2', 80, SYN, 0, 0),
    tcpPkt('20.0.0.1', 1002, '20.0.0.3', 443, SYN, 0, 0),
    udpPkt('20.0.0.1', 5001, '8.8.8.8', 53, Buffer.from('x')),
    tcpPkt('20.0.0.2', 80, '20.0.0.1', 1001, SYN|ACK, 0, 1),
    tcpPkt('20.0.0.3', 443, '20.0.0.1', 1002, SYN|ACK, 0, 1),
  ];
  const a = buildFlows(makePcap(pkts), 't');
  assert.equal(a.flows.length, 3, 'three distinct flows');
  const kinds = a.flows.map(f => f.kind).sort();
  assert.deepEqual(kinds, ['tcp', 'tcp', 'udp']);
});

test('empty PCAPNG: zero flows, zero errors', () => {
  const a = buildFlows(makePcap([]), 'empty');
  assert.equal(a.flows.length, 0);
  assert.equal(a.totalEpbs, 0);
  assert.equal(a.warnings.length, 0);
});

test('non-IP frames (ARP ethertype) counted as nonFlowEpbs', () => {
  const arp = Buffer.alloc(28, 0);
  const pkt = Buffer.concat([ethHdr(0x0806), arp]);
  const a = buildFlows(makePcap([pkt]), 't');
  assert.equal(a.flows.length, 0);
  assert.equal(a.nonFlowEpbs, 1, 'ARP -> nonFlowEpbs');
});
