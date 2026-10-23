// ============================================================================
// PacketDecoder — High-Performance Layered Dissection Engine
//
// Pure TypeScript packet dissecting engine supporting framings captured by
// pktmon/etl2pcap on Windows and standard pcap/pcapng captures:
//   - Layer 2: Ethernet II, IEEE 802.1Q/802.1ad VLAN tags, ARP, Bare-IP, Raw 802.11
//   - Layer 3: IPv4 (RFC 791), IPv6 (RFC 8200) with full extension header chains
//   - Layer 4: TCP (RFC 9293), UDP (RFC 768), ICMP (RFC 792), ICMPv6 (RFC 4443)
//   - Layer 7: DNS queries/answers (RFC 1035), TLS ClientHello/ServerHello (RFC 8446)
//
// Design Invariants:
//   1. Zero I/O, zero external dependencies — pure, deterministic arithmetic.
//   2. Never throws exceptions — all malformed/truncated data is captured in `errors`.
//   3. Honest partial decoding — fields validly parsed before an error are preserved.
//   4. Bounded execution — loops (DNS compression pointers, IPv6 extensions, TCP options)
//      are strictly bounded to prevent DoS or CPU lockups on adversarial inputs.
// ============================================================================

// ============================================================================
// 1. DATA TYPES & PUBLIC INTERFACES
// ============================================================================

export type TransportKind = "tcp" | "udp" | "icmp" | "icmpv6" | "arp" | "other";

export interface IpInfo {
  version: 4 | 6;
  src: string;
  dst: string;
  /** IPv4 identification field (fragment id) — recorded for every IPv4 packet (RFC 791). */
  id?: number;
  firstProto: number;
  proto: number;
  ttlHop: number;
  totalLen: number;
  headerLen: number;
  payloadLen: number;
  fragment?: {
    id: number;
    offsetBytes: number;
    moreFragments: boolean;
    dontFragment: boolean;
  };
  extHeaders?: Array<{ type: number; lenBytes: number }>;
  /** IPv6 header §3 metadata (traffic class + 20-bit flow label). */
  trafficClass?: number;
  flowLabel?: number;
  checksumValid?: boolean;
}

export interface TransportInfo {
  kind: TransportKind;
  proto: number;
  sport?: number;
  dport?: number;
  seq?: number;
  ack?: number;
  tcpFlags?: number;
  window?: number;
  /** TCP urgent pointer (RFC 9293 §3.3.1). */
  urgentPtr?: number;
  /** TCP header options parsed to metadata (RFC 9293 / RFC 1323). */
  options?: {
    mss?: number;
    windowScale?: number;
    sackPermitted?: boolean;
    timestamps?: { val: number; echo: number };
  };
  /** TCP/UDP checksum verified against pseudo-header (RFC 1071 / RFC 9293). */
  checksumValid?: boolean;
  /** UDP checksum field is 0: allowed over IPv4 (RFC 768), flagged on IPv6. */
  checksumZero?: boolean;
  /** ICMP/ICMPv6 type and code. */
  icmpType?: number;
  icmpCode?: number;
  /** ICMP echo identifier and sequence number for ping request/reply. */
  icmpEchoId?: number;
  icmpEchoSeq?: number;
  /** ARP operation (1=request, 2=reply). */
  arpOpcode?: number;
  payloadLen: number;
  /** Byte offset of the transport header within frame bytes. */
  headerOff?: number;
  /** Length of the transport header (e.g. 20-60 TCP, 8 UDP). */
  headerLen?: number;
}

export interface DnsInfo {
  transactionId: number;
  isResponse: boolean;
  opcode: number;
  rcode: number;
  truncated: boolean;
  questions: Array<{ name: string; type: number }>;
  answerNames: string[];
  aRecords: string[];
  aaaaRecords: string[];
  /** OPT pseudo-record (EDNS0) present in the answers — metadata only. */
  edns?: boolean;
}

export interface TlsHelloInfo {
  /** TLS record version, e.g. "0301" / "0303". */
  recordVersion: string;
  /** ClientHello legacy version, e.g. "0303". */
  legacyVersion: string;
  /** Handshake type observed. */
  handshake?: "clientHello" | "serverHello";
  /** supported_versions extension hex entries (e.g. ["0304"] for TLS 1.3). */
  supportedVersions?: string[];
  /** Encrypted ClientHello extension present (outer SNI reported). */
  ech?: boolean;
  sni?: string;
}

export interface DecodedPacket {
  framing: "ethernet" | "vlan" | "bareIP" | "raw80211" | "unknown";
  srcMac?: string;
  dstMac?: string;
  ethertype?: number;
  vlanIds?: number[];
  linkType: number;
  capLen: number;
  origLen: number;
  ipOffset: number;
  ip?: IpInfo;
  transport?: TransportInfo;
  dns?: DnsInfo;
  tls?: TlsHelloInfo;
  errors: string[];
}

// ============================================================================
// 2. CONSTANTS & PROTOCOL MASKS
// ============================================================================

export const TCP_FIN = 0x01;
export const TCP_SYN = 0x02;
export const TCP_RST = 0x04;
export const TCP_PSH = 0x08;
export const TCP_ACK = 0x10;
export const TCP_URG = 0x20;

// ============================================================================
// 3. LAYER 2 (FRAMING & LINK-LAYER DECODERS)
// ============================================================================

/** Formats a 6-byte MAC address buffer into standard colon-hex format. */
function macString(b: Buffer, off: number): string {
  const parts: string[] = [];
  for (let i = 0; i < 6; i++) {
    parts.push(b[off + i].toString(16).padStart(2, "0"));
  }
  return parts.join(":");
}

interface EthernetView {
  ipOffset: number;
  ethertype: number;
  vlanIds?: number[];
  srcMac: string;
  dstMac: string;
}

/**
 * Dissects an Ethernet II frame header, handling single or stacked 802.1Q/802.1ad VLAN tags.
 */
function parseEthernet(bytes: Buffer, errors: string[]): EthernetView | null {
  if (bytes.length < 14) {
    errors.push(`ethernet: frame too short (${bytes.length} bytes)`);
    return null;
  }
  const dstMac = macString(bytes, 0);
  const srcMac = macString(bytes, 6);
  let ethertype = bytes.readUInt16BE(12);
  let off = 14;
  const vlanIds: number[] = [];

  // Support 802.1Q (0x8100) and 802.1ad QinQ (0x88a8) stacking up to 4 tags
  for (let guard = 0; guard < 4 && (ethertype === 0x8100 || ethertype === 0x88a8); guard++) {
    if (bytes.length < off + 4) {
      errors.push("ethernet: truncated VLAN tag");
      return null;
    }
    vlanIds.push(bytes.readUInt16BE(off) & 0x0fff);
    ethertype = bytes.readUInt16BE(off + 2);
    off += 4;
  }

  return {
    ipOffset: off,
    ethertype,
    vlanIds: vlanIds.length > 0 ? vlanIds : undefined,
    srcMac,
    dstMac,
  };
}

/**
 * Locates an LLC/SNAP encapsulation header (0xAA 0xAA 0x03) used in 802.11/token ring captures.
 */
function parseLlcSnap(bytes: Buffer, off: number, errors: string[]): number | null {
  const limit = Math.min(bytes.length, off + 64);
  for (let i = off; i + 8 <= limit; i++) {
    if (bytes[i] === 0xaa && bytes[i + 1] === 0xaa && bytes[i + 2] === 0x03) {
      const type = bytes.readUInt16BE(i + 6);
      if (type === 0x0800 || type === 0x86dd || type === 0x0806) {
        return i + 8;
      }
    }
  }
  errors.push(`llcsnap: no LLC/SNAP marker found from offset ${off}`);
  return null;
}

/**
 * Detects raw 802.11 data frames (e.g. from Windows nwifi.sys pktmon provider).
 */
function looksLikeRaw80211Data(bytes: Buffer): boolean {
  if (bytes.length < 20) return false;
  // Type = 2 (Data frame), Version = 0 (bits 2-3 == 2)
  if ((bytes[0] & 0x0c) !== 0x08) return false;
  const limit = Math.min(bytes.length - 8, 64);
  for (let i = 14; i <= limit; i++) {
    if (bytes[i] === 0xaa && bytes[i + 1] === 0xaa && bytes[i + 2] === 0x03) {
      const type = bytes.readUInt16BE(i + 6);
      if (type === 0x0800 || type === 0x86dd) return true;
    }
  }
  return false;
}

/**
 * Fallback scanner for bare IP datagrams lacking an L2 header (e.g. pktmon TCPIP provider).
 */
function findBareIpStart(bytes: Buffer): number | null {
  const limit = Math.min(64, bytes.length - 20);
  for (let off = 0; off <= limit; off++) {
    const v = bytes[off];
    const ver = v >>> 4;
    if (ver === 4) {
      const ihl = v & 0x0f;
      if (ihl < 5) continue;
      const total = bytes.readUInt16BE(off + 2);
      if (total >= 20 && off + total === bytes.length) return off;
      if (total > 20 && total <= bytes.length - off) return off;
    } else if (ver === 6) {
      const total = bytes.readUInt16BE(off + 4) + 40;
      if (off + total === bytes.length && total >= 40) return off;
      if (total > 40 && total <= bytes.length - off) return off;
    }
  }
  return null;
}

// ============================================================================
// 4. LAYER 3 (CHECKSUM UTILITIES)
// ============================================================================

/**
 * One's-complement sum over a byte range (RFC 1071 §4.1).
 * Odd trailing bytes are padded in the high nibble.
 */
function byteSum16(bytes: Buffer, from: number, toExclusive: number): number {
  let sum = 0;
  const even = toExclusive - ((toExclusive - from) % 2);
  for (let i = from; i + 1 < even; i += 2) {
    sum += bytes.readUInt16BE(i);
  }
  if ((toExclusive - from) % 2 === 1) {
    sum += bytes[toExclusive - 1] << 8;
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  return sum & 0xffff;
}

/**
 * Verifies a TCP or UDP transport checksum against its pseudo-header (RFC 768 / RFC 9293).
 * Returns { valid: true } when checksum folds to 0xffff, or { zero: true } when UDP checksum is 0.
 */
function verifyTransportChecksum(
  bytes: Buffer,
  ipStart: number,
  version: 4 | 6,
  proto: number,
  segStart: number,
  segLen: number,
  storedOff: number,
): { valid?: boolean; zero?: boolean } {
  if (segLen <= 0 || segLen > 0xffff || segStart + 8 > bytes.length) return {};
  const stored = bytes.readUInt16BE(segStart + storedOff);
  const segEnd = Math.min(segStart + segLen, bytes.length);

  let sum = byteSum16(bytes, segStart, segEnd);
  if (version === 4) {
    // IPv4 pseudo-header: src (4) + dst (4) + zero (1) + proto (1) + length (2)
    const pseudo = bytes.subarray(ipStart + 12, ipStart + 20);
    sum += byteSum16(pseudo, 0, 8) + proto + segLen;
  } else {
    // IPv6 pseudo-header: src (16) + dst (16) + length (4) + nextHeader (4)
    const pseudo = bytes.subarray(ipStart + 8, ipStart + 40);
    sum += byteSum16(pseudo, 0, 32) + segLen + proto;
  }

  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }

  return { valid: sum === 0xffff, zero: stored === 0 };
}

// ============================================================================
// 5. LAYER 3 (IPv4 & IPv6 DISSECTORS)
// ============================================================================

/**
 * Dissects an IPv4 header (RFC 791). Supports IHL options and fragmentation flags.
 */
function parseIpv4(
  bytes: Buffer,
  off: number,
  errors: string[],
): { ip: IpInfo; nextOffset: number } | null {
  if (bytes.length < off + 20) {
    errors.push(`ipv4: header truncated (have ${bytes.length - off} need 20)`);
    return null;
  }
  const ihl = (bytes[off] & 0x0f) * 4;
  if (ihl < 20) {
    errors.push(`ipv4: bad IHL ${ihl}`);
    return null;
  }
  if (bytes.length < off + ihl) {
    errors.push(`ipv4: options truncated (have ${bytes.length - off} need ${ihl})`);
    return null;
  }

  const totalLen = bytes.readUInt16BE(off + 2);
  const id = bytes.readUInt16BE(off + 4);

  // RFC 791 §3.1: Total length cannot be smaller than header length (0 tolerated for TSO)
  if (totalLen !== 0 && (totalLen < 20 || totalLen < ihl)) {
    errors.push(`ipv4.bad-total-length: total length ${totalLen} < header length ${ihl}`);
  }
  if (totalLen > bytes.length - off) {
    errors.push(`ipv4.truncated: total length ${totalLen} exceeds captured ${bytes.length - off}`);
  }

  const flagsFrag = bytes.readUInt16BE(off + 6);
  const ttl = bytes[off + 8];
  const proto = bytes[off + 9];

  const src = [
    bytes[off + 12],
    bytes[off + 13],
    bytes[off + 14],
    bytes[off + 15],
  ].join(".");

  const dst = [
    bytes[off + 16],
    bytes[off + 17],
    bytes[off + 18],
    bytes[off + 19],
  ].join(".");

  // Verify IPv4 header checksum
  let sum = 0;
  for (let i = 0; i < ihl; i += 2) {
    sum += bytes.readUInt16BE(off + i);
  }
  while (sum > 0xffff) {
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  const checksumValid = (sum ^ 0xffff) === 0;

  const moreFragments = (flagsFrag & 0x2000) !== 0;
  const offsetUnits = flagsFrag & 0x1fff;
  const dontFragment = (flagsFrag & 0x4000) !== 0;
  const isFragmenting = moreFragments || offsetUnits > 0;

  const ip: IpInfo = {
    version: 4,
    id,
    src,
    dst,
    firstProto: proto,
    proto,
    ttlHop: ttl,
    totalLen,
    headerLen: ihl,
    payloadLen: totalLen > ihl ? totalLen - ihl : 0,
    checksumValid,
  };

  if (isFragmenting || dontFragment) {
    ip.fragment = {
      id,
      offsetBytes: offsetUnits * 8,
      moreFragments,
      dontFragment,
    };
  }

  return { ip, nextOffset: off + ihl };
}

/** Formats a 16-byte IPv6 address into RFC 5952 canonical text representation. */
function formatV6(q: number[]): string {
  // RFC 5952 §5: IPv4-mapped address (::ffff:a.b.c.d)
  if (
    q[0] === 0 && q[1] === 0 && q[2] === 0 && q[3] === 0 &&
    q[4] === 0 && q[5] === 0 && q[6] === 0 && q[7] === 0 &&
    q[8] === 0 && q[9] === 0 && q[10] === 0xff && q[11] === 0xff
  ) {
    return `::ffff:${q[12]}.${q[13]}.${q[14]}.${q[15]}`;
  }

  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push((((q[i] << 8) | q[i + 1]) >>> 0).toString(16));
  }

  // Find longest run of consecutive zeros for "::" compression
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < groups.length; i++) {
    if (groups[i] === "0") {
      let j = i;
      while (j < groups.length && groups[j] === "0") j++;
      if (j - i > bestLen) {
        best = i;
        bestLen = j - i;
      }
      i = j;
    }
  }

  if (bestLen < 2) return groups.join(":");
  return groups.slice(0, best).join(":") + "::" + groups.slice(best + bestLen).join(":");
}

/**
 * Dissects an IPv6 header and walks extension headers (RFC 8200 §4):
 * Hop-by-hop (0), Routing (43), Fragment (44), AH (51), Destination options (60).
 */
function parseIpv6(
  bytes: Buffer,
  off: number,
  errors: string[],
): { ip: IpInfo; nextOffset: number } | null {
  if (bytes.length < off + 40) {
    errors.push(`ipv6: header truncated (have ${bytes.length - off} need 40)`);
    return null;
  }
  if (bytes[off] >> 4 !== 6) {
    errors.push(`ipv6: bad version ${bytes[off] >> 4}`);
    return null;
  }

  const payloadLen = bytes.readUInt16BE(off + 4);
  if (payloadLen > bytes.length - off - 40) {
    errors.push(`ipv6.truncated: payload length ${payloadLen} exceeds captured ${bytes.length - off - 40}`);
  }

  const ttlHop = bytes[off + 7];
  const firstProto = bytes[off + 6];
  const trafficClass = ((bytes[off] << 4) | (bytes[off + 1] >> 4)) & 0xff;
  const flowLabel = (((bytes[off + 1] & 0x0f) << 16) | bytes.readUInt16BE(off + 2)) >>> 0;

  const qSrc: number[] = [];
  for (let i = 0; i < 16; i++) qSrc.push(bytes[off + 8 + i]);
  const qDst: number[] = [];
  for (let i = 0; i < 16; i++) qDst.push(bytes[off + 24 + i]);

  const ext: Array<{ type: number; lenBytes: number }> = [];
  let fragMeta: { id: number; offsetBytes: number; moreFragments: boolean } | null = null;
  let nh = firstProto;
  let cur = off + 40;

  // Walk up to 8 extension headers with bounds protection
  for (let guard = 0; guard < 8; guard++) {
    if (nh !== 0 && nh !== 43 && nh !== 44 && nh !== 51 && nh !== 60) break;
    if (cur >= bytes.length) {
      errors.push(`ipv6: ext header ${nh} truncated at ${cur}`);
      return null;
    }

    if (nh === 44) {
      // Fragment Header (fixed 8 bytes, RFC 8200 §4.5)
      if (cur + 8 > bytes.length) {
        errors.push("ipv6: fragment header truncated");
        return null;
      }
      ext.push({ type: nh, lenBytes: 8 });
      const offUnits = bytes.readUInt16BE(cur + 2) >> 3;
      const moreFrag = (bytes.readUInt16BE(cur + 2) & 1) !== 0;
      const fragId = bytes.readUInt32BE(cur + 4) >>> 0;
      fragMeta = { id: fragId, offsetBytes: offUnits * 8, moreFragments: moreFrag };
      nh = bytes[cur];
      cur += 8;
      continue;
    }

    if (nh === 51) {
      // Authentication Header (RFC 4302 §2.2): Length = (payloadLen + 2) * 4
      if (cur + 12 > bytes.length) {
        errors.push("ipv6: AH header truncated");
        return null;
      }
      const ahLen = (bytes[cur + 1] + 2) * 4;
      if (ahLen < 12 || cur + ahLen > bytes.length) {
        errors.push(`ipv6: AH header length ${ahLen} out of capture`);
        return null;
      }
      ext.push({ type: nh, lenBytes: ahLen });
      nh = bytes[cur];
      cur += ahLen;
      continue;
    }

    // Generic extension headers (Hop-by-hop, Routing, Destination options)
    if (cur + 2 > bytes.length || cur + 8 > bytes.length) {
      errors.push(`ipv6: ext header ${nh} truncated at ${cur}`);
      return null;
    }
    const extLenBytes = (bytes[cur + 1] + 1) * 8;
    if (cur + extLenBytes > bytes.length) {
      errors.push(`ipv6: ext header ${nh} length ${extLenBytes} out of capture`);
      return null;
    }
    ext.push({ type: nh, lenBytes: extLenBytes });
    nh = bytes[cur];
    cur += extLenBytes;
  }

  // If another extension header is still queued after 8 headers, abort chain
  if (nh === 0 || nh === 43 || nh === 44 || nh === 51 || nh === 60) {
    errors.push("ipv6.chain-too-long: extension header chain exceeds the documented limit of 8");
    return null;
  }

  const ip: IpInfo = {
    version: 6,
    src: formatV6(qSrc),
    dst: formatV6(qDst),
    firstProto,
    proto: nh,
    ttlHop,
    totalLen: 40 + payloadLen,
    headerLen: 40,
    payloadLen,
    trafficClass,
    flowLabel,
    extHeaders: ext.length > 0 ? ext : undefined,
  };

  if (fragMeta) {
    ip.fragment = { ...fragMeta, dontFragment: false };
  }

  return { ip, nextOffset: cur };
}

// ============================================================================
// 6. LAYER 4 (TCP / UDP / ICMP TRANSPORT DISSECTORS)
// ============================================================================

/**
 * Dissects TCP options (RFC 9293 §3.3.1) into structured metadata.
 */
function parseTcpOptions(
  bytes: Buffer,
  optOff: number,
  optEnd: number,
  errors: string[],
): TransportInfo["options"] {
  const options: NonNullable<TransportInfo["options"]> = {};
  let cur = optOff;

  while (cur < optEnd) {
    const kind = bytes[cur];
    if (kind === 0) break; // End of Option List (EOL)
    if (kind === 1) {
      cur += 1; // No-Operation (NOP)
      continue;
    }

    const len = cur + 2 <= bytes.length ? bytes[cur + 1] : 0;
    if (len < 2) {
      errors.push(`tcp.bad-options: option kind ${kind} length ${len} (minimum 2, RFC 9293 §3.3.1)`);
      break;
    }
    if (cur + len > optEnd || cur + len > bytes.length) {
      errors.push(`tcp.bad-options: option kind ${kind} length ${len} overruns the data-offset boundary`);
      break;
    }

    if (kind === 2 && len === 4) {
      // Maximum Segment Size (MSS)
      options.mss = bytes.readUInt16BE(cur + 2);
    } else if (kind === 3 && len === 3) {
      // Window Scale
      options.windowScale = bytes[cur + 2];
    } else if (kind === 4 && len === 2) {
      // SACK Permitted
      options.sackPermitted = true;
    } else if (kind === 8 && len === 10) {
      // Timestamps
      options.timestamps = {
        val: bytes.readUInt32BE(cur + 2) >>> 0,
        echo: bytes.readUInt32BE(cur + 6) >>> 0,
      };
    }
    cur += len;
  }

  return Object.keys(options).length > 0 ? options : undefined;
}

/**
 * Dissects a TCP segment header (RFC 9293).
 */
function parseTcp(
  bytes: Buffer,
  off: number,
  ip: IpInfo,
  errors: string[],
): TransportInfo {
  if (bytes.length < off + 20) {
    errors.push(`tcp: header truncated (have ${bytes.length - off} need 20)`);
    return { kind: "other", proto: 6, payloadLen: Math.max(0, bytes.length - off) };
  }

  const sport = bytes.readUInt16BE(off);
  const dport = bytes.readUInt16BE(off + 2);
  const dataOff = (bytes[off + 12] >> 4) * 4;

  if (dataOff < 20 || off + dataOff > bytes.length) {
    errors.push(`tcp: bad data offset ${dataOff}`);
    return {
      kind: "tcp",
      proto: 6,
      sport,
      dport,
      tcpFlags: bytes[off + 13] & 0xff,
      payloadLen: 0,
    };
  }

  const payloadLen = ip.payloadLen > dataOff ? ip.payloadLen - dataOff : 0;
  const seq = bytes.readUInt32BE(off + 4) >>> 0;
  const ack = bytes.readUInt32BE(off + 8) >>> 0;
  const urgentPtr = bytes.readUInt16BE(off + 18);
  const options = parseTcpOptions(bytes, off + 20, off + dataOff, errors);

  return {
    kind: "tcp",
    proto: 6,
    sport,
    dport,
    seq,
    ack,
    tcpFlags: bytes[off + 13] & 0xff,
    window: bytes.readUInt16BE(off + 14),
    urgentPtr,
    ...(options ? { options } : {}),
    payloadLen,
    headerOff: off,
    headerLen: dataOff,
  };
}

/**
 * Dissects a UDP datagram header (RFC 768).
 */
function parseUdp(bytes: Buffer, off: number, errors: string[]): TransportInfo {
  if (bytes.length < off + 8) {
    errors.push(`udp: header truncated (have ${bytes.length - off} need 8)`);
    return { kind: "other", proto: 17, payloadLen: Math.max(0, bytes.length - off) };
  }

  const sport = bytes.readUInt16BE(off);
  const dport = bytes.readUInt16BE(off + 2);
  const dgramLen = bytes.readUInt16BE(off + 4);

  if (dgramLen >= 1 && dgramLen < 8) {
    errors.push(`udp.bad-length: length ${dgramLen} (RFC 768 minimum is 8; 0 = IPv6 jumbogram)`);
  }
  if (dgramLen > 8 && dgramLen > bytes.length - off) {
    errors.push(`udp.truncated: declared length ${dgramLen} exceeds captured ${bytes.length - off}`);
  }

  const payloadLen = dgramLen > 8 ? Math.min(dgramLen - 8, Math.max(0, bytes.length - off - 8)) : 0;
  return { kind: "udp", proto: 17, sport, dport, payloadLen, headerOff: off, headerLen: 8 };
}

/**
 * Dissects an ICMP message header (RFC 792).
 */
function parseIcmp(bytes: Buffer, off: number, ip: IpInfo, errors: string[]): TransportInfo {
  const avail = bytes.length - off;
  if (avail < 4) {
    errors.push(`icmp.truncated: ${Math.max(0, avail)} bytes captured, need 4 for type+code (RFC 792 §2)`);
    return {
      kind: "icmp",
      proto: 1,
      payloadLen: Math.max(0, ip.payloadLen),
      icmpType: avail >= 1 ? bytes[off] : undefined,
    };
  }

  const ity = bytes[off];
  const t: TransportInfo = {
    kind: "icmp",
    proto: 1,
    payloadLen: Math.max(0, ip.payloadLen),
    icmpType: ity,
    icmpCode: bytes[off + 1],
  };

  if ((ity === 8 || ity === 0) && avail >= 8) {
    t.icmpEchoId = bytes.readUInt16BE(off + 4);
    t.icmpEchoSeq = bytes.readUInt16BE(off + 6);
  }

  return t;
}

/**
 * Dissects an ICMPv6 message header (RFC 4443).
 */
function parseIcmpv6(bytes: Buffer, off: number, ip: IpInfo, errors: string[]): TransportInfo {
  const avail = bytes.length - off;
  if (avail < 4) {
    errors.push(`icmpv6.truncated: ${Math.max(0, avail)} bytes captured, need 4 for type+code (RFC 4443 §2.1)`);
    return {
      kind: "icmpv6",
      proto: 58,
      payloadLen: Math.max(0, ip.payloadLen),
      icmpType: avail >= 1 ? bytes[off] : undefined,
    };
  }

  const ity = bytes[off];
  const t: TransportInfo = {
    kind: "icmpv6",
    proto: 58,
    payloadLen: Math.max(0, ip.payloadLen),
    icmpType: ity,
    icmpCode: bytes[off + 1],
  };

  if ((ity === 128 || ity === 129) && avail >= 8) {
    t.icmpEchoId = bytes.readUInt16BE(off + 4);
    t.icmpEchoSeq = bytes.readUInt16BE(off + 6);
  }

  return t;
}

// ============================================================================
// 7. LAYER 7 (DNS & TLS APPLICATION METADATA)
// ============================================================================

/**
 * Dissects a DNS domain name with RFC 1035 §4.1.4 compression pointer handling.
 * Ensures bounded traversal and cycle detection.
 */
function parseDnsName(
  bytes: Buffer,
  off: number,
  errors: string[],
  dnsBase: number,
  dnsLen: number,
): { name: string; end: number; rejected?: boolean } {
  const labels: string[] = [];
  let cur = off;
  let jumped = false;
  let end = -1;
  let nameLen = 0;
  let rejected = false;
  const visited = new Set<number>();

  for (let guard = 0; guard < 255; guard++) {
    if (cur >= bytes.length) {
      errors.push(`dns: name truncated at ${cur}`);
      rejected = true;
      break;
    }

    const len = bytes[cur];
    if ((len & 0xc0) === 0xc0) {
      // 14-bit compression pointer
      if (cur + 1 >= bytes.length) {
        errors.push(`dns: pointer truncated at ${cur}`);
        rejected = true;
        break;
      }
      const targetRel = ((len & 0x3f) << 8) | bytes[cur + 1];
      if (targetRel < 12) {
        errors.push(`dns.pointer-target: pointer to ${targetRel} points into the DNS header (invalid, RFC 1035 §4.1.4)`);
        rejected = true;
        break;
      }
      if (targetRel >= dnsLen) {
        errors.push(`dns.pointer-target: pointer to ${targetRel} points past the message end`);
        return { name: labels.join(".") || ".", end: cur + 2, rejected: true };
      }

      const target = dnsBase + targetRel;
      if (cur + 1 >= bytes.length || target >= bytes.length) {
        errors.push(`dns.pointer-target: pointer to ${targetRel} points past the captured bytes`);
        return { name: labels.join(".") || ".", end: cur + 2, rejected: true };
      }
      if (visited.has(targetRel)) {
        errors.push(`dns.pointer-loop: pointer target ${targetRel} already visited (bounded termination, RFC 1035 §4.1.4)`);
        rejected = true;
        break;
      }

      visited.add(targetRel);
      if (!jumped) end = cur + 2;
      cur = target;
      jumped = true;
      continue;
    }

    if (len === 0) {
      // Root label
      if (!jumped) end = cur + 1;
      break;
    }

    if (len > 63) {
      errors.push(`dns.label-too-long: label length ${len} (RFC 1035 §2.3.4 maximum is 63)`);
      rejected = true;
      break;
    }

    cur += 1;
    if (cur + len > bytes.length) {
      errors.push(`dns: label truncated at ${cur}`);
      rejected = true;
      break;
    }

    nameLen += len + 1;
    if (nameLen > 255) {
      errors.push("dns.name-too-long: name exceeds 255 bytes (RFC 1035 §2.3.4)");
      rejected = true;
      break;
    }

    labels.push(bytes.subarray(cur, cur + len).toString("ascii"));
    cur += len;
    if (!jumped) end = cur;
  }

  const name = labels.length === 0 ? "." : labels.join(".");
  return { name, end, rejected: rejected || undefined };
}

/**
 * Dissects a DNS protocol message (RFC 1035).
 */
function parseDns(bytes: Buffer, off: number, errors: string[], dnsLen?: number): DnsInfo | null {
  if (bytes.length < off + 12) {
    errors.push(`dns: header truncated (have ${bytes.length - off} need 12)`);
    return null;
  }

  const messageLen = dnsLen !== undefined && dnsLen > 0
    ? Math.min(dnsLen, bytes.length - off)
    : bytes.length - off;

  const id = bytes.readUInt16BE(off);
  const flags = bytes.readUInt16BE(off + 2);
  const qd = bytes.readUInt16BE(off + 4);
  const an = bytes.readUInt16BE(off + 6);

  const dns: DnsInfo = {
    transactionId: id,
    isResponse: (flags & 0x8000) !== 0,
    opcode: (flags >> 11) & 0x0f,
    rcode: flags & 0x0f,
    truncated: (flags & 0x0200) !== 0,
    questions: [],
    answerNames: [],
    aRecords: [],
    aaaaRecords: [],
  };

  let cur = off + 12;

  // Dissect Questions
  for (let q = 0; q < Math.min(qd, 10); q++) {
    if (cur >= bytes.length) {
      errors.push("dns: questions truncated");
      break;
    }
    const ni = parseDnsName(bytes, cur, errors, off, messageLen);
    if (ni.rejected) break;
    const end = ni.end;
    if (end + 4 > bytes.length) {
      errors.push("dns: question trailer truncated");
      break;
    }
    dns.questions.push({ name: ni.name, type: bytes.readUInt16BE(end) });
    cur = end + 4;
  }

  // Dissect Answers
  for (let a = 0; a < Math.min(an, 20); a++) {
    if (cur >= bytes.length) {
      errors.push(`dns.truncated-answers: ${an} answers declared but only ${a} parsed (message truncated)`);
      break;
    }
    const ni = parseDnsName(bytes, cur, errors, off, messageLen);
    if (ni.rejected) break;
    const end = ni.end;
    if (end + 10 > bytes.length) {
      errors.push(`dns.truncated-answers: answer ${a} (of ${an}) is truncated`);
      break;
    }

    const type = bytes.readUInt16BE(end);
    const rdLen = bytes.readUInt16BE(end + 8);
    const rdStart = end + 10;
    if (rdStart + rdLen > bytes.length) {
      errors.push("dns: rdata truncated");
      break;
    }

    if (type === 1 && rdLen === 4) {
      // A record
      dns.aRecords.push(`${bytes[rdStart]}.${bytes[rdStart + 1]}.${bytes[rdStart + 2]}.${bytes[rdStart + 3]}`);
    } else if (type === 1 && rdLen !== 4) {
      errors.push(`dns.bad-rdata-length: A record rdata length ${rdLen} (RFC 1035 §3.4.1 expects 4)`);
    } else if (type === 28 && rdLen === 16) {
      // AAAA record
      const q: number[] = [];
      for (let i = 0; i < 16; i++) q.push(bytes[rdStart + i]);
      dns.aaaaRecords.push(formatV6(q));
    } else if (type === 28 && rdLen !== 16) {
      errors.push(`dns.bad-rdata-length: AAAA record rdata length ${rdLen} (RFC 3596 §2.2 expects 16)`);
    } else if (type === 41) {
      // EDNS0 OPT record (metadata only)
      dns.edns = true;
    } else if (type === 5 || type === 2) {
      // CNAME or NS
      dns.answerNames.push(parseDnsName(bytes, rdStart, errors, off, messageLen).name);
    }

    cur = rdStart + rdLen;
  }

  return dns;
}

/**
 * Dissects TLS ClientHello or ServerHello handshake records for SNI and version metadata (RFC 8446).
 */
function parseTlsClientHello(
  bytes: Buffer,
  off: number,
  errors: string[],
): TlsHelloInfo | null {
  const need = (start: number, n: number): boolean => start + n <= bytes.length;
  if (!need(off, 5)) return null;
  if (bytes[off] !== 0x16) return null; // TLS handshake record byte

  const recVer = bytes.subarray(off + 1, off + 3).toString("hex");
  const hs = off + 5;
  if (!need(hs, 4)) return null;

  const hsType = bytes[hs];
  if (hsType !== 0x01 && hsType !== 0x02) return null; // 1 = ClientHello, 2 = ServerHello

  const legacyVersionHs = bytes.subarray(hs + 4, hs + 6).toString("hex");
  let cur = hs + 6 + 32; // Skip version + 32-byte random

  if (!need(cur, 1)) return null;
  const sidLen = bytes[cur];
  cur += 1 + sidLen;

  if (!need(cur, 2)) return null;
  const csLen = bytes.readUInt16BE(cur);
  cur += 2 + csLen;

  if (!need(cur, 1)) return null;
  const compLen = bytes[cur];
  cur += 1 + compLen;

  if (!need(cur, 2)) return null;
  const extLen = bytes.readUInt16BE(cur);
  cur += 2;

  const extListOverruns = extLen > bytes.length - cur;
  const extEnd = Math.min(cur + extLen, bytes.length);
  let sni: string | undefined;
  const supportedVersions: string[] = [];
  let ech = false;

  for (let guard = 0; guard < 32 && cur + 4 <= extEnd; guard++) {
    const et = bytes.readUInt16BE(cur);
    const el = bytes.readUInt16BE(cur + 2);

    if (et === 0x0000 && el >= 5 && need(cur + 4 + 5, 0)) {
      // server_name extension (RFC 6066 §3)
      const nameLen = bytes.readUInt16BE(cur + 4 + 3);
      if (need(cur + 4 + 5, nameLen)) {
        sni = bytes.subarray(cur + 4 + 5, cur + 4 + 5 + nameLen).toString("ascii");
      }
    } else if (et === 0x002b && el >= 1 && need(cur + 4, el) && el % 2 === 1) {
      // supported_versions extension (RFC 8446 §4.2.1)
      for (let v = cur + 5; v + 2 <= cur + 4 + el; v += 2) {
        supportedVersions.push(bytes.subarray(v, v + 2).toString("hex"));
      }
    } else if (et === 0xfe0d || et === 0xfe0e) {
      // Encrypted ClientHello (ECH / GREASE)
      ech = true;
    }
    cur += 4 + el;
  }

  const info: TlsHelloInfo = {
    recordVersion: recVer,
    legacyVersion: legacyVersionHs,
    handshake: hsType === 0x01 ? "clientHello" : "serverHello",
  };

  if (extListOverruns && sni !== undefined) {
    errors.push(`tls.truncated-extensions: extension list length ${extLen} exceeds captured ${bytes.length} - ${cur - extLen} bytes`);
  }
  if (supportedVersions.length > 0) info.supportedVersions = supportedVersions;
  if (ech) info.ech = true;
  if (sni) info.sni = sni;

  return info;
}

// ============================================================================
// 8. PACKET DISPATCHER (decodePacket)
// ============================================================================

/**
 * Decodes one raw captured packet frame for the given linkType.
 * Guaranteed never to throw; errors accumulate in the returned `DecodedPacket.errors`.
 */
export function decodePacket(linkType: number, bytes: Buffer, origLen: number): DecodedPacket {
  const errors: string[] = [];
  const out: DecodedPacket = {
    framing: "unknown",
    linkType,
    capLen: bytes.length,
    origLen,
    ipOffset: -1,
    errors,
  };

  if (bytes.length === 0) {
    errors.push("empty packet");
    return out;
  }

  // --- Step 1: L2 Framing & Link-Layer Dissection ---
  let ipStart: number | null = null;
  if (linkType === 1) {
    const eth = parseEthernet(bytes, errors);
    if (eth) {
      out.ethertype = eth.ethertype;
      out.srcMac = eth.srcMac;
      out.dstMac = eth.dstMac;
      out.vlanIds = eth.vlanIds;
      out.framing = eth.vlanIds ? "vlan" : "ethernet";

      if (eth.ethertype === 0x0806) {
        // ARP packet (RFC 826)
        const arpOpcode = bytes.length >= eth.ipOffset + 8
          ? bytes.readUInt16BE(eth.ipOffset + 6)
          : undefined;
        out.transport = {
          kind: "arp",
          proto: 2,
          payloadLen: Math.max(0, bytes.length - eth.ipOffset),
          ...(arpOpcode !== undefined ? { arpOpcode } : {}),
        };
        return out;
      }

      if (eth.ethertype === 0x0800 || eth.ethertype === 0x86dd) {
        ipStart = eth.ipOffset;
      } else if (looksLikeRaw80211Data(bytes)) {
        out.framing = "raw80211";
        ipStart = parseLlcSnap(bytes, 14, errors);
      } else {
        const bare = findBareIpStart(bytes);
        if (bare !== null) {
          ipStart = bare;
          if (bare === 0) out.framing = "bareIP";
          errors.push(`unknown ethertype 0x${eth.ethertype.toString(16)}: IP recovered at offset ${bare}`);
        } else {
          errors.push(`unknown ethertype 0x${eth.ethertype.toString(16)} (no IP payload found)`);
        }
      }
    }
  }

  // Fallback for bare IP or unhandled L2 framings
  if (ipStart === null) {
    const ver = bytes[0] >>> 4;
    if (ver === 4 || ver === 6) {
      ipStart = 0;
      if (out.framing === "unknown") out.framing = "bareIP";
    } else {
      const bare = findBareIpStart(bytes);
      if (bare !== null) {
        ipStart = bare;
        if (out.framing === "unknown") out.framing = "bareIP";
      } else {
        errors.push("no IP packet located");
      }
    }
  }

  if (ipStart === null) return out;

  // --- Step 2: L3 IP Dissection ---
  let ipParsed: { ip: IpInfo; nextOffset: number } | null = null;
  const ipVersion = bytes[ipStart] >>> 4;
  if (ipVersion === 4) {
    ipParsed = parseIpv4(bytes, ipStart, errors);
  } else if (ipVersion === 6) {
    ipParsed = parseIpv6(bytes, ipStart, errors);
  } else {
    errors.push(`unknown IP version ${ipVersion}`);
  }

  if (ipParsed === null) return out;
  out.ip = ipParsed.ip;
  out.ipOffset = ipStart;
  const { ip, nextOffset } = ipParsed;

  // --- Step 3: L4 Transport & L7 Protocol Dissection ---
  if (ip.proto === 6) {
    // Non-first fragments carry payload only, not transport headers
    if (ip.fragment !== undefined && ip.fragment.offsetBytes > 0) {
      out.transport = { kind: "other", proto: 6, payloadLen: 0 };
      return out;
    }

    const t = parseTcp(bytes, nextOffset, ip, errors);
    out.transport = t;

    if (t.kind === "tcp" && t.sport !== undefined) {
      // Verify TCP checksum
      const c = verifyTransportChecksum(bytes, ipStart, ip.version, 6, nextOffset, ip.payloadLen, 16);
      if (c.valid !== undefined) t.checksumValid = c.valid;

      const isTlsPort = t.sport === 443 || t.dport === 443;
      const tcpHdrLen = (bytes[nextOffset + 12] >> 4) * 4;
      const payloadOff = nextOffset + tcpHdrLen;

      // Speculative TLS inspection on port 443
      if (isTlsPort && bytes.length > payloadOff) {
        const hello = parseTlsClientHello(bytes, payloadOff, errors);
        if (hello) out.tls = hello;
      }

      // DNS over TCP (RFC 1035 §4.2.2: 2-byte prefix length + DNS message)
      if (t.sport === 53 || t.dport === 53) {
        const hasPrefix = bytes.length >= payloadOff + 14;
        const prefixLen = hasPrefix ? bytes.readUInt16BE(payloadOff) : 0;
        if (hasPrefix && prefixLen >= 12 && bytes.length >= payloadOff + 2 + prefixLen) {
          const d = parseDns(bytes, payloadOff + 2, errors, prefixLen);
          if (d) out.dns = d;
        }
      }
    }
  } else if (ip.proto === 17) {
    // Non-first UDP fragments carry no transport header
    if (ip.fragment !== undefined && ip.fragment.offsetBytes > 0) {
      out.transport = { kind: "other", proto: 17, payloadLen: 0 };
      return out;
    }

    const t = parseUdp(bytes, nextOffset, errors);
    out.transport = t;

    // Verify UDP checksum
    const c = verifyTransportChecksum(bytes, ipStart, ip.version, 17, nextOffset, ip.payloadLen, 6);
    if (c.valid !== undefined || c.zero) {
      t.checksumZero = c.zero ?? false;
      t.checksumValid = c.zero ? ip.version === 4 : c.valid;
    }

    // DNS over UDP (port 53)
    if (t.sport === 53 || t.dport === 53) {
      const d = parseDns(bytes, nextOffset + 8, errors, t.payloadLen);
      if (d) out.dns = d;
    }
  } else if (ip.proto === 1) {
    out.transport = parseIcmp(bytes, nextOffset, ip, errors);
  } else if (ip.proto === 58) {
    out.transport = parseIcmpv6(bytes, nextOffset, ip, errors);
  } else {
    out.transport = { kind: "other", proto: ip.proto, payloadLen: Math.max(0, ip.payloadLen) };
  }

  return out;
}

// ============================================================================
// 9. FLOW CONVERSATION IDENTIFIERS (canonicalFlow & flowIdOf)
// ============================================================================

/**
 * Normalizes 5-tuple flow endpoints into a canonical order so both directions
 * map to the identical conversation pair.
 */
export function canonicalFlow(
  proto: number,
  src: string,
  sport: number,
  dst: string,
  dport: number,
): { aip: string; aport: number; bip: string; bport: number; proto: number } {
  const ka = `${sport}|${src}`;
  const kb = `${dport}|${dst}`;
  return ka <= kb
    ? { aip: src, aport: sport, bip: dst, bport: dport, proto }
    : { aip: dst, aport: dport, bip: src, bport: sport, proto };
}

/**
 * Returns canonical conversation ID `p<proto> aip:aport <--> bip:bport` for a packet,
 * or null when transport ports are not present.
 */
export function flowIdOf(p: DecodedPacket): string | null {
  const t = p.transport;
  const i = p.ip;
  if (!t || !i || t.kind === "other" || t.kind === "arp") return null;
  if (t.sport === undefined || t.dport === undefined) return null;
  const f = canonicalFlow(t.proto, i.src, t.sport, i.dst, t.dport);
  return `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`;
}
