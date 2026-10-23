// ─────────────────────────────────────────────────────────────────────────────
// HARDENING FIXTURE HELPERS — pcapng-level builders for the flows layer
// (adapted from test/flows.test.ts so every hardening suite builds frames the
// same way; raw-frame builders stay in ./helpers.ts)
// ─────────────────────────────────────────────────────────────────────────────

export function ethHdr(ethertype: number): Buffer {
  const h = Buffer.alloc(14);
  Buffer.from("020203040506", "hex").copy(h, 0);
  Buffer.from("020203040507", "hex").copy(h, 6);
  h.writeUInt16BE(ethertype, 12);
  return h;
}

export function ip4Hdr(
  src: string,
  dst: string,
  proto: number,
  payloadLen: number,
  id = 0x1234,
  flags = 2,
  frag = 0,
): Buffer {
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

export function tcpPkt(
  src: string,
  sport: number,
  dst: string,
  dport: number,
  flags: number,
  seq: number,
  ack: number,
  payload: Buffer = Buffer.alloc(0),
): Buffer {
  const tcp = Buffer.alloc(20 + payload.length);
  tcp.writeUInt16BE(sport, 0);
  tcp.writeUInt16BE(dport, 2);
  tcp.writeUInt32BE(seq >>> 0, 4);
  tcp.writeUInt32BE(ack >>> 0, 8);
  tcp[12] = 0x50; // data offset 5
  tcp[13] = flags & 0xff;
  tcp.writeUInt16BE(65535, 14);
  payload.copy(tcp, 20);
  const ip = ip4Hdr(src, dst, 6, tcp.length);
  return Buffer.concat([ethHdr(0x0800), ip, tcp]);
}

export function udpPkt(
  src: string,
  sport: number,
  dst: string,
  dport: number,
  payload: Buffer,
): Buffer {
  const udp = Buffer.alloc(8 + payload.length);
  udp.writeUInt16BE(sport, 0);
  udp.writeUInt16BE(dport, 2);
  udp.writeUInt16BE(8 + payload.length, 4);
  payload.copy(udp, 8);
  const ip = ip4Hdr(src, dst, 17, udp.length);
  return Buffer.concat([ethHdr(0x0800), ip, udp]);
}

/** Hand-rolled PcapngFile: 1 interface (tsresol=6), packets i*tsGapUs apart. */
export function makePcap(frames: Buffer[], tsGapUs = 1000) {
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

export const SYN = 0x02,
  FIN = 0x01,
  RST = 0x04,
  PSH = 0x08,
  ACK = 0x10;
