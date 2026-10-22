// Pure-TS PCAPNG parser (subset, sufficient for pktmon etl2pcap output).
//
// Implements the published "PCAPng: A Next Generation Capture File Format"
// block layout: [BlockType u32][BlockTotalLength u32][body, padded to 4]
// [BlockTotalLength u32]. Handles Section Header (SHB), Interface Description
// (IDB), Enhanced Packet (EPB) and Simple Packet (SPB) blocks; every other
// block type is skipped but counted (never silently dropped).
//
// Verified against real pktmon output in Milestone 1 and cross-checked with
// tshark (Wireshark 4.6.9) frame-by-frame.

export interface PcapngShb {
  majorVersion: number;
  minorVersion: number;
  sectionLength: bigint;
  littleEndian: boolean;
}

export interface PcapngInterface {
  /** Position in the file (0-based). */
  id: number;
  /** LinkType per the pcapng spec (1 = Ethernet / LINKTYPE_ETHERNET). */
  linkType: number;
  snaplen: number;
  /** Raw if_tsresol byte. Default per spec is 6 (decimal, microseconds). */
  tsResolRaw: number;
  name: string | null;
  os: string | null;
}

export interface PcapngPacketOptions {
  epbFlags: Buffer | null;
  epbHash: Buffer | null;
  comment: string | null;
  dropCount: number | null; // epb_dropcount, option 8 (u64)
}

export interface PcapngPacket {
  interfaceId: number;
  tsHigh: number;
  tsLow: number;
  capLen: number;
  origLen: number;
  data: Buffer;
  options: PcapngPacketOptions;
}

export interface PcapngSkipped {
  blockType: number;
  count: number;
}

export interface PcapngParseError {
  offset: number;
  message: string;
}

export interface PcapngFile {
  shb: PcapngShb | null;
  interfaces: PcapngInterface[];
  packets: PcapngPacket[];
  skippedBlocks: PcapngSkipped[];
  parseErrors: PcapngParseError[];
}

const BLOCK_SHB = 0x0a0d0d0a;
const BLOCK_IDB = 0x00000001;
const BLOCK_SPB = 0x00000003;
const BLOCK_EPB = 0x00000006;

interface Readers {
  u16: (o: number) => number;
  u32: (o: number) => number;
  i64: (o: number) => bigint;
}

function readers(buf: Buffer, le: boolean): Readers {
  return {
    u16: (o) => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o)),
    u32: (o) => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o)),
    i64: (o) => (le ? buf.readBigInt64LE(o) : buf.readBigInt64BE(o)),
  };
}

/** Pad an option/data length to the 32-bit boundary per pcapng spec. */
function pad4(n: number): number {
  return (n + 3) & ~3;
}

/**
 * if_tsresol (option 9): high bit 0 => decimal (10^-t), 1 => binary
 * (2^-(t & 0x7f)). Default per spec: t = 6 (microseconds).
 */
export function timestampDivisor(tsResolRaw: number): number {
  if ((tsResolRaw & 0x80) !== 0) {
    return Math.pow(2, tsResolRaw & 0x7f);
  }
  return Math.pow(10, tsResolRaw === 0 ? 6 : tsResolRaw);
}

/** Absolute ticks = high * 2^32 + low (uint64 arithmetic kept exact). */
export function tickValue(tsHigh: number, tsLow: number): bigint {
  return (BigInt(tsHigh) << 32n) | BigInt(tsLow >>> 0);
}

/** Timestamp in epoch seconds (float) per interface resolution. */
export function packetTimestampSeconds(
  pkt: PcapngPacket,
  ifaces: PcapngInterface[],
): number {
  const iface = ifaces[pkt.interfaceId];
  const resol = iface ? iface.tsResolRaw : 6;
  const div = timestampDivisor(resol);
  return Number(tickValue(pkt.tsHigh, pkt.tsLow)) / div;
}

function readCstring(buf: Buffer): string | null {
  const nul = buf.indexOf(0);
  const s = nul === -1 ? buf : buf.subarray(0, nul);
  return s.length === 0 ? "" : s.toString("utf8");
}

export function parsePcapng(buf: Buffer): PcapngFile {
  const out: PcapngFile = {
    shb: null,
    interfaces: [],
    packets: [],
    skippedBlocks: [],
    parseErrors: [],
  };
  const skippedByType = new Map<number, number>();

  if (buf.length < 28) {
    out.parseErrors.push({
      offset: 0,
      message: `file too small (${buf.length} bytes) for SHB`,
    });
    return out;
  }

  let off = 0;
  // Default little-endian until an SHB says otherwise.
  let r = readers(buf, true);

  while (off + 8 <= buf.length) {
    let blockType = r.u32(off);
    let totalLen = r.u32(off + 4);

    if (totalLen < 12 || off + totalLen > buf.length) {
      // Try the block-length fix-up for truncated files? No: fail loudly,
      // record and stop (never silently drop a parse error).
      out.parseErrors.push({
        offset: off,
        message: `bad block length ${totalLen} at offset ${off} (type 0x${(
          blockType >>> 0
        ).toString(16)})`,
      });
      break;
    }

    if (blockType === BLOCK_SHB) {
      // Body: byte-order magic at off+8.
      // - File bytes 1A 2B 3C 4D => writer was big-endian
      // - File bytes 4D 3C 2B 1A => writer was little-endian
      const magicBE = buf.readUInt32BE(off + 8);
      let le: boolean;
      if (magicBE === 0x1a2b3c4d) le = false;
      else if (magicBE === 0x4d3c2b1a) le = true;
      else {
        out.parseErrors.push({
          offset: off + 8,
          message: `bad SHB byte-order magic 0x${magicBE
            .toString(16)
            .padStart(8, "0")}`,
        });
        break;
      }
      r = readers(buf, le);
      blockType = r.u32(off); // re-read in section byte order (same value)
      totalLen = r.u32(off + 4);
      if (totalLen < 12 || off + totalLen > buf.length) {
        out.parseErrors.push({
          offset: off,
          message: "bad SHB length after endianness fix-up",
        });
        break;
      }
      const major = r.u16(off + 12);
      const minor = r.u16(off + 14);
      const sectionLength = r.i64(off + 16);
      out.shb = {
        majorVersion: major,
        minorVersion: minor,
        sectionLength,
        littleEndian: le,
      };
      // Per spec, parsing stops after the first SHB when the section length
      // is not in this buffer; simple subset parser: keep scanning — pktmon
      // writes a single section.
    } else if (blockType === BLOCK_IDB) {
      const linkType = r.u16(off + 8);
      const snaplen = r.u32(off + 12);
      const iface: PcapngInterface = {
        id: out.interfaces.length,
        linkType,
        snaplen,
        tsResolRaw: 6,
        name: null,
        os: null,
      };
      // Options: from off+16 to off+totalLen-4.
      let o = off + 16;
      const optEnd = off + totalLen - 4;
      while (o + 4 <= optEnd) {
        const code = r.u16(o);
        const len = r.u16(o + 2);
        if (code === 0) break; // opt_endofopt
        if (len > optEnd - o - 4) {
          out.parseErrors.push({
            offset: o,
            message: `IDB option overruns block (code ${code}, len ${len})`,
          });
          o = optEnd;
          break;
        }
        const value = buf.subarray(o + 4, o + 4 + len);
        if (code === 9) iface.tsResolRaw = value.length > 0 ? value[0] : 6;
        else if (code === 2) iface.name = readCstring(value);
        else if (code === 3) iface.os = readCstring(value);
        o += 4 + pad4(len);
      }
      out.interfaces.push(iface);
    } else if (blockType === BLOCK_EPB) {
      const ifaceId = r.u32(off + 8);
      const tsHigh = r.u32(off + 12);
      const tsLow = r.u32(off + 16);
      const capLen = r.u32(off + 20);
      const origLen = r.u32(off + 24);
      const dataStart = off + 28;
      const dataPad = pad4(capLen);
      if (dataStart + capLen > off + totalLen - 4 || origLen < capLen) {
        out.parseErrors.push({
          offset: off,
          message: `EPB capLen=${capLen} origLen=${origLen} violates block total ${totalLen}`,
        });
        off += totalLen;
        continue;
      }
      const data = Buffer.from(buf.subarray(dataStart, dataStart + capLen)); // copy
      const opts: PcapngPacketOptions = {
        epbFlags: null,
        epbHash: null,
        comment: null,
        dropCount: null,
      };
      let o = dataStart + dataPad;
      const optEnd = off + totalLen - 4;
      while (o + 4 <= optEnd) {
        const code = r.u16(o);
        const len = r.u16(o + 2);
        if (code === 0) break;
        if (len > optEnd - o - 4) {
          out.parseErrors.push({
            offset: o,
            message: `EPB option overruns block (code ${code}, len ${len})`,
          });
          break;
        }
        const value = buf.subarray(o + 4, o + 4 + len);
        if (code === 2) opts.comment = readCstring(value);
        else if (code === 4) opts.epbHash = Buffer.from(value);
        else if (code === 6) opts.epbFlags = Buffer.from(value);
        else if (code === 8 && len === 8) opts.dropCount = r.u32(o + 4); // low half
        o += 4 + pad4(len);
      }
      out.packets.push({
        interfaceId: ifaceId,
        tsHigh,
        tsLow,
        capLen,
        origLen,
        data,
        options: opts,
      });
    } else if (blockType === BLOCK_SPB) {
      const origLen = r.u32(off + 8);
      const dataStart = off + 12;
      const capLen = Math.min(origLen, totalLen - 16);
      if (dataStart + capLen > buf.length) {
        out.parseErrors.push({
          offset: off,
          message: `SPB overruns file (origLen=${origLen})`,
        });
        off += totalLen;
        continue;
      }
      // SPB has no timestamp/interface fields; record with what spec allows.
      out.packets.push({
        interfaceId: 0,
        tsHigh: 0,
        tsLow: 0,
        capLen,
        origLen,
        data: Buffer.from(buf.subarray(dataStart, dataStart + capLen)),
        options: { epbFlags: null, epbHash: null, comment: null, dropCount: null },
      });
    } else {
      const n = skippedByType.get(blockType) ?? 0;
      skippedByType.set(blockType, n + 1);
    }

    off += totalLen;
  }

  for (const [blockType, count] of skippedByType) {
    out.skippedBlocks.push({ blockType, count });
  }
  return out;
}

/** Human-readable link type name (subset; full table per IANA if in doubt). */
export function linkTypeName(linkType: number): string {
  const names: Record<number, string> = {
    0: "BSD loopback",
    1: "Ethernet",
    6: "IEEE 802.5",
    9: "PPP",
    101: "Raw IP",
    113: "Linux SLL",
    147: "Raw IP (OpenBSD)",
    228: "IPv4",
    229: "IPv6",
  };
  return names[linkType] ?? `unknown(${linkType})`;
}
