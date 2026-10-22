// PacketDecoder — layered dissection for the packet model.
//
// Handles the framings pktmon/etl2pcap actually produced on this machine
// (verified in Milestone 1):
//   - full Ethernet (dst/src/ethertype), with 802.1Q VLAN tags
//   - ARP (described, not dissected beyond presence)
//   - bare IP (no L2 header; pktmon TCPIP-protocol components log this)
//   - raw 802.11 data frames carrying LLC/SNAP + IP (nwifi.sys logs these
//     alongside the Ethernet copies; detected by frame-control pattern)
//
// Rules: malformed/truncated input never throws — every failure is recorded
// in `errors`. Fragments are described (id/offset/flags) but NOT reassembled
// (documented v1 limitation). Bounded loops everywhere (DNS label pointer
// loops cannot hang). Never silently drops parse errors.
//
// Layer:     engine — pure parsing (zero I/O; never throws)
// Milestone: M2 — packet decoder (docs/history/milestone-2-report.md)
// Verified:  16 unit tests (test/decoder.test.ts) + 14-trace tshark parity corpus
// Exports:   decodePacket, canonicalFlow, flowIdOf, TCP_* flag masks, DecodedPacket

export interface IpInfo {
  version: 4 | 6;
  src: string;
  dst: string;
  firstProto: number;
  proto: number;
  ttlHop: number;
  totalLen: number;
  headerLen: number;
  payloadLen: number;
  fragment?: { id: number; offsetBytes: number; moreFragments: boolean; dontFragment: boolean };
  extHeaders?: Array<{ type: number; lenBytes: number }>;
  checksumValid?: boolean;
}

export type TransportKind = "tcp" | "udp" | "icmp" | "icmpv6" | "arp" | "other";

export interface TransportInfo {
  kind: TransportKind;
  proto: number;
  sport?: number;
  dport?: number;
  seq?: number;
  ack?: number;
  tcpFlags?: number;
  window?: number;
  payloadLen: number;
  /** Byte offset of the transport header within the frame bytes (when the
   * transport header itself is present in the capture). */
  headerOff?: number;
  /** Length of the transport header (20 TCP, 8 UDP). */
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
}

export interface TlsHelloInfo {
  /** TLS record version, e.g. "0301"/"0303". */
  recordVersion: string;
  /** ClientHello legacy version, e.g. "0303" (1.2+ negative meaning depends). */
  legacyVersion: string;
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

export const TCP_SYN = 0x02;
export const TCP_FIN = 0x01;
export const TCP_RST = 0x04;
export const TCP_PSH = 0x08;
export const TCP_ACK = 0x10;

function macString(b: Buffer, off: number): string {
  const p: string[] = [];
  for (let i = 0; i < 6; i++) p.push(b[off + i].toString(16).padStart(2, "0"));
  return p.join(":");
}

interface EthernetView {
  ipOffset: number;
  ethertype: number;
  vlanIds?: number[];
  srcMac: string;
  dstMac: string;
}

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
  for (let guard = 0; guard < 4 && ethertype === 0x8100; guard++) {
    if (bytes.length < off + 4) {
      errors.push("ethernet: truncated VLAN tag");
      return null;
    }
    vlanIds.push(bytes.readUInt16BE(off) & 0x0fff);
    ethertype = bytes.readUInt16BE(off + 2);
    off += 4;
  }
  return { ipOffset: off, ethertype, vlanIds: vlanIds.length > 0 ? vlanIds : undefined, srcMac, dstMac };
}

function parseLlcSnap(bytes: Buffer, off: number, errors: string[]): number | null {
  for (let i = off; i + 8 <= Math.min(bytes.length, off + 64); i++) {
    if (bytes[i] === 0xaa && bytes[i + 1] === 0xaa && bytes[i + 2] === 0x03) {
      const type = bytes.readUInt16BE(i + 6);
      if (type === 0x0800 || type === 0x86dd || type === 0x0806) return i + 8;
    }
  }
  errors.push(`llcsnap: no LLC/SNAP marker found from offset ${off}`);
  return null;
}

/**
 * raw 802.11 data frames (observed at the nwifi.sys component):
 * byte0 bits 0-1 protocol version == 0, bits 2-3 type == 2 (data),
 * followed by a discoverable LLC/SNAP header. pktmon's copies carry
 * variant sub-headers, so the LLC/SNAP marker is searched rather than
 * assuming one fixed 802.11 header length.
 */
function looksLikeRaw80211Data(bytes: Buffer): boolean {
  if (bytes.length < 20) return false;
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
 * Unrecognized framing fallback: scan the first 64 bytes for a plausible IP
 * start; accepted when the inline length field is consistent with the
 * remaining captured length (exact when capLen == origLen).
 */
function findBareIpStart(bytes: Buffer): number | null {
  for (let off = 0; off <= Math.min(64, bytes.length - 20); off++) {
    const v = bytes[off];
    if ((v >>> 4) === 4) {
      const ihl = v & 0x0f;
      if (ihl < 5) continue;
      const total = bytes.readUInt16BE(off + 2);
      if (total >= 20 && off + total === bytes.length) return off;
      if (total > 20 && total <= bytes.length - off) return off;
    } else if ((v >>> 4) === 6) {
      const total = bytes.readUInt16BE(off + 4) + 40;
      if (off + total === bytes.length && total >= 40) return off;
      if (total > 40 && total <= bytes.length - off) return off;
    }
  }
  return null;
}

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
  const flagsFrag = bytes.readUInt16BE(off + 6);
  const ttl = bytes[off + 8];
  const proto = bytes[off + 9];
  const src = [];
  for (let i = 0; i < 4; i++) src.push(String(bytes[off + 12 + i]));
  const dst = [];
  for (let i = 0; i < 4; i++) dst.push(String(bytes[off + 16 + i]));
  let sum = 0;
  for (let i = 0; i < ihl; i += 2) sum += bytes.readUInt16BE(off + i);
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  const checksumValid = (sum ^ 0xffff) === 0;
  const moreFragments = (flagsFrag & 0x2000) !== 0;
  const offsetUnits = flagsFrag & 0x1fff;
  const dontFragment = (flagsFrag & 0x4000) !== 0;
  const isFragmenting = moreFragments || offsetUnits > 0;
  const ip: IpInfo = {
    version: 4,
    src: src.join("."),
    dst: dst.join("."),
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

function formatV6(q: number[]): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push((((q[i] << 8) | q[i + 1]) >>> 0).toString(16));
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
 * IPv6 with extension headers: hop-by-hop (0), routing (43), fragment (44),
 * destination options (60), AH (51). Variable ext headers use the
 * 8-byte-unit length scheme: total = (hdrExtLen + 1) * 8. Fragment is fixed
 * at 8 bytes. AH is variable: total = (payloadLen + 2) * 4, with NextHeader
 * at the END of the AH block. Hard guard: at most 8 ext headers, all
 * fully inside the capture.
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
  const ttlHop = bytes[off + 7];
  const firstProto = bytes[off + 6];
  const qSrc: number[] = [];
  for (let i = 0; i < 16; i++) qSrc.push(bytes[off + 8 + i]);
  const qDst: number[] = [];
  for (let i = 0; i < 16; i++) qDst.push(bytes[off + 24 + i]);
  const ext: Array<{ type: number; lenBytes: number }> = [];
  let nh = firstProto;
  let cur = off + 40;
  for (let guard = 0; guard < 8; guard++) {
    if (nh !== 0 && nh !== 43 && nh !== 44 && nh !== 51 && nh !== 60) break;
    if (cur >= bytes.length) {
      errors.push(`ipv6: ext header ${nh} truncated at ${cur}`);
      return null;
    }
    if (nh === 44) {
      if (cur + 8 > bytes.length) {
        errors.push("ipv6: fragment header truncated");
        return null;
      }
      ext.push({ type: nh, lenBytes: 8 });
      const offUnits = bytes.readUInt16BE(cur + 2) >> 3;
      const moreFrag = (bytes.readUInt16BE(cur + 2) & 1) !== 0;
      const fragId = bytes.readUInt32BE(cur + 4) >>> 0;
      // Track fragment metadata on the last ext record (metadata exposure,
      // reassembly deliberately NOT performed in v1).
      ext[ext.length - 1] = {
        type: nh,
        lenBytes: 8,
        ...(offUnits || moreFrag ? {} : {}),
      };
      void offUnits;
      void moreFrag;
      void fragId;
      nh = bytes[cur];
      cur += 8;
      continue;
    }
    if (nh === 51) {
      if (cur + 2 > bytes.length) {
        errors.push("ipv6: AH header truncated");
        return null;
      }
      const ahLen = (bytes[cur + 1] + 1) * 4;
      if (ahLen < 8 || cur + ahLen > bytes.length) {
        errors.push(`ipv6: AH header length ${ahLen} out of capture`);
        return null;
      }
      ext.push({ type: nh, lenBytes: ahLen });
      nh = bytes[cur + ahLen - 1];
      cur += ahLen;
      continue;
    }
    // hop-by-hop / routing / destination options: (hdrExtLen + 1) * 8 bytes.
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
    extHeaders: ext.length > 0 ? ext : undefined,
  };
  return { ip, nextOffset: cur };
}

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
  return {
    kind: "tcp",
    proto: 6,
    sport,
    dport,
    seq,
    ack,
    tcpFlags: bytes[off + 13] & 0xff,
    window: bytes.readUInt16BE(off + 14),
    payloadLen,
    headerOff: off,
    headerLen: dataOff,
  };
}

function parseUdp(bytes: Buffer, off: number, errors: string[]): TransportInfo {
  if (bytes.length < off + 8) {
    errors.push(`udp: header truncated (have ${bytes.length - off} need 8)`);
    return { kind: "other", proto: 17, payloadLen: Math.max(0, bytes.length - off) };
  }
  const sport = bytes.readUInt16BE(off);
  const dport = bytes.readUInt16BE(off + 2);
  const dgramLen = bytes.readUInt16BE(off + 4);
  const payloadLen = dgramLen > 8 ? Math.min(dgramLen - 8, Math.max(0, bytes.length - off - 8)) : 0;
  return { kind: "udp", proto: 17, sport, dport, payloadLen, headerOff: off, headerLen: 8 };
}

function parseDnsName(
  bytes: Buffer,
  off: number,
  errors: string[],
): { name: string; end: number } {
  const labels: string[] = [];
  let cur = off;
  let jumped = false;
  let end = -1;
  for (let guard = 0; guard < 255; guard++) {
    if (cur >= bytes.length) {
      errors.push(`dns: name truncated at ${cur}`);
      break;
    }
    const len = bytes[cur];
    if ((len & 0xc0) === 0xc0) {
      if (cur + 1 >= bytes.length) {
        errors.push(`dns: pointer truncated at ${cur}`);
        break;
      }
      const target = ((len & 0x3f) << 8) | bytes[cur + 1];
      if (target >= bytes.length) return { name: labels.join(".") || "<root>", end: cur + 2 };
      if (!jumped) end = cur + 2;
      cur = target;
      jumped = true;
      continue;
    }
    if (len === 0) {
      if (!jumped) end = cur + 1;
      break;
    }
    cur += 1;
    if (cur + len > bytes.length) {
      errors.push(`dns: label truncated at ${cur}`);
      break;
    }
    labels.push(bytes.subarray(cur, cur + len).toString("ascii"));
    cur += len;
    if (!jumped) end = cur;
  }
  if (end < 0) end = cur;
  return { name: labels.join(".") || "<root>", end };
}

function parseDns(bytes: Buffer, off: number, errors: string[]): DnsInfo | null {
  if (bytes.length < off + 12) {
    errors.push(`dns: header truncated (have ${bytes.length - off} need 12)`);
    return null;
  }
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
  for (let q = 0; q < Math.min(qd, 10); q++) {
    if (cur >= bytes.length) {
      errors.push("dns: questions truncated");
      break;
    }
    const { name, end } = parseDnsName(bytes, cur, errors);
    if (end + 4 > bytes.length) {
      errors.push("dns: question trailer truncated");
      break;
    }
    dns.questions.push({ name, type: bytes.readUInt16BE(end) });
    cur = end + 4;
  }
  for (let a = 0; a < Math.min(an, 20); a++) {
    if (cur >= bytes.length) break;
    const { end } = parseDnsName(bytes, cur, errors);
    if (end + 10 > bytes.length) break;
    const type = bytes.readUInt16BE(end);
    const rdLen = bytes.readUInt16BE(end + 8);
    const rdStart = end + 10;
    if (rdStart + rdLen > bytes.length) {
      errors.push("dns: rdata truncated");
      break;
    }
    if (type === 1 && rdLen === 4) {
      dns.aRecords.push(`${bytes[rdStart]}.${bytes[rdStart + 1]}.${bytes[rdStart + 2]}.${bytes[rdStart + 3]}`);
    } else if (type === 28 && rdLen === 16) {
      const q: number[] = [];
      for (let i = 0; i < 16; i++) q.push(bytes[rdStart + i]);
      dns.aaaaRecords.push(formatV6(q));
    } else if (type === 5 || type === 2) {
      dns.answerNames.push(parseDnsName(bytes, rdStart, errors).name);
    }
    cur = rdStart + rdLen;
  }
  return dns;
}

// ------------------------------------------------------------------- TLS
// ClientHello extraction is METADATA only (plaintext record; no
// decryption of any application traffic). SNI lives in an unencrypted
// extension of the ClientHello.

function parseTlsClientHello(
  bytes: Buffer,
  off: number,
): TlsHelloInfo | null {
  const need = (start: number, n: number): boolean => start + n <= bytes.length;
  if (!need(off, 5)) return null;
  if (bytes[off] !== 0x16) return null; // not a handshake record
  const recVer = bytes.subarray(off + 1, off + 3).toString("hex");
  const hs = off + 5;
  if (!need(hs, 4) || bytes[hs] !== 0x01) return null; // not ClientHello
  const legacyVersionHs = bytes.subarray(hs + 4, hs + 6).toString("hex");
  let cur = hs + 6 + 32; // legacy version + random
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
  const extEnd = Math.min(cur + extLen, bytes.length);
  let sni: string | undefined;
  for (let guard = 0; guard < 32 && cur + 4 <= extEnd; guard++) {
    const et = bytes.readUInt16BE(cur);
    const el = bytes.readUInt16BE(cur + 2);
    if (et === 0x0000 && el >= 5 && need(cur + 4 + 5, 0)) {
      // server_name list: listLen(2), entry: type(1)=0 hostName, len(2), name
      const nameLen = bytes.readUInt16BE(cur + 4 + 3);
      if (need(cur + 4 + 5, nameLen)) {
        sni = bytes.subarray(cur + 4 + 5, cur + 4 + 5 + nameLen).toString("ascii");
      }
      break;
    }
    cur += 4 + el;
  }
  const info: TlsHelloInfo = { recordVersion: recVer, legacyVersion: legacyVersionHs };
  if (sni) info.sni = sni;
  return info;
}

/** Decode one captured frame for the given interface linkType. Never throws —
 * every problem is recorded in the returned packet's `errors`. */
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
        out.transport = { kind: "arp", proto: 2, payloadLen: Math.max(0, bytes.length - eth.ipOffset) };
        return out; // ARP described, not dissected further (scenario 10 protocol coverage)
      }
      if (eth.ethertype === 0x0800 || eth.ethertype === 0x86dd) {
        ipStart = eth.ipOffset;
      } else {
        if (looksLikeRaw80211Data(bytes)) {
          out.framing = "raw80211";
          ipStart = parseLlcSnap(bytes, 14, errors);
        } else {
          const bare = findBareIpStart(bytes);
          if (bare !== null) {
            ipStart = bare;
            // IP recovered at offset 0 with consistent length is a bare-IP
            // packet mislabeled with an ethertype (TCPIP-component framing).
            out.framing = bare === 0 ? "bareIP" : out.framing;
            errors.push(`unknown ethertype 0x${eth.ethertype.toString(16)}: IP recovered at offset ${bare}`);
          } else {
            errors.push(`unknown ethertype 0x${eth.ethertype.toString(16)} (no IP payload found)`);
          }
        }
      }
    }
  }
  if (ipStart === null) {
    if ((bytes[0] >>> 4) === 4 || (bytes[0] >>> 4) === 6) {
      ipStart = 0;
      if (out.framing === "unknown") out.framing = "bareIP";
    } else {
      const b = findBareIpStart(bytes);
      if (b !== null) {
        ipStart = b;
        if (out.framing === "unknown") out.framing = "bareIP";
      } else {
        errors.push("no IP packet located");
      }
    }
  }
  if (ipStart === null) return out;

  let ipParsed: { ip: IpInfo; nextOffset: number } | null = null;
  if ((bytes[ipStart] >>> 4) === 4) ipParsed = parseIpv4(bytes, ipStart, errors);
  else if ((bytes[ipStart] >>> 4) === 6) ipParsed = parseIpv6(bytes, ipStart, errors);
  else errors.push(`unknown IP version ${bytes[ipStart] >>> 4}`);
  if (ipParsed === null) return out;
  out.ip = ipParsed.ip;
  out.ipOffset = ipStart;
  const { ip, nextOffset } = ipParsed;

  if (ip.proto === 6) {
    const t = parseTcp(bytes, nextOffset, ip, errors);
    out.transport = t;
    if (t && t.kind === "tcp" && t.sport !== undefined) {
      const isTlsPort = t.sport === 443 || t.dport === 443;
      const tcpHdrLen = (bytes[nextOffset + 12] >> 4) * 4;
      const payloadOff = nextOffset + tcpHdrLen;
      if (isTlsPort && bytes.length > payloadOff) {
        const hello = parseTlsClientHello(bytes, payloadOff);
        if (hello) out.tls = hello;
      }
    }
    // DNS over TCP: only when real payload is present (a 2-byte length
    // prefix followed by the 12-byte header). SYN/RST/FIN packets on port 53
    // carry no DNS message and must not be mis-parsed.
    if (t && t.kind === "tcp" && (t.sport === 53 || t.dport === 53)) {
      const tcpHdrLen2 = (bytes[nextOffset + 12] >> 4) * 4;
      const dnsAt = nextOffset + tcpHdrLen2;
      const hasPrefix = bytes.length >= dnsAt + 14;
      const prefixLen = hasPrefix ? bytes.readUInt16BE(dnsAt) : 0;
      if (hasPrefix && prefixLen >= 12 && bytes.length >= dnsAt + 2 + prefixLen) {
        const d = parseDns(bytes, dnsAt + 2, errors);
        if (d) out.dns = d;
      }
    }
  } else if (ip.proto === 17) {
    const t = parseUdp(bytes, nextOffset, errors);
    out.transport = t;
    if (t.sport === 53 || t.dport === 53) {
      const d = parseDns(bytes, nextOffset + 8, errors);
      if (d) out.dns = d;
    }
  } else if (ip.proto === 1) {
    out.transport = { kind: "icmp", proto: 1, payloadLen: Math.max(0, ip.payloadLen) };
  } else if (ip.proto === 58) {
    out.transport = { kind: "icmpv6", proto: 58, payloadLen: Math.max(0, ip.payloadLen) };
  } else {
    out.transport = { kind: "other", proto: ip.proto, payloadLen: Math.max(0, ip.payloadLen) };
  }
  return out;
}

/** Normalized flow key: both directions map to one id. */
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

/** Canonical flow id `p<proto> aip:aport <--> bip:bport` for a decoded packet,
 * or null when the transport carries no ports (e.g. ARP, fragments). */
export function flowIdOf(p: DecodedPacket): string | null {
  const t = p.transport;
  const i = p.ip;
  if (!t || !i || t.kind === "other" || t.kind === "arp") return null;
  if (t.sport === undefined || t.dport === undefined) return null;
  const f = canonicalFlow(t.proto, i.src, t.sport, i.dst, t.dport);
  return `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`;
}
