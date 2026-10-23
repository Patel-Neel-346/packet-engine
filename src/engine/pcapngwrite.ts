// M4-a: minimal PCAPNG writer — needed so the loopback tap can emit traces
// that BOTH the engine pipeline (parsePcapng) and tshark read from the same
// file, with no format conversion in between. It matches the shape of every
// trace in this corpus (verified property of all etl2pcap outputs): one SHB,
// one IDB with linktype Ethernet(1) and if_tsresol=6 (decimal microseconds),
// then EPBs in wire order. Block CRCs are omitted — the pcapng spec makes
// them optional per block and parsePcapng does not expect them.
//
// Layer:     engine — pure serialization (Buffer out; caller does the I/O)
// Milestone: M4a — loopback-tap trace writer (docs/project-status.md)
// Verified:  writer→parsePcapng roundtrip (test/loopbacktap.test.ts); tshark reads its output in the m4a gate
// Exports:   writePcapng, PcapngChunk, PcapngWriteOptions

const SHB_BLOCK = 0x0a0d0d0a;
const IDB_BLOCK = 0x00000001;
const EPB_BLOCK = 0x00000006;
const SHB_BOM = 0x1a2b3c4d;

export interface PcapngChunk {
  /** Full frame bytes as they appeared "on the wire" (capLen = data.length). */
  data: Buffer;
  origLen: number;
  /** Timestamp, seconds since epoch (fractional). */
  ts: number;
}

export interface PcapngWriteOptions {
  linkType: number;
  /** Snaplen recorded in the IDB. */
  snapLen?: number;
  /** Human-readable writer id (option code 4 = shb_userappl). */
  userAppl?: string;
}

/** Serialize Ethernet-framed chunks to a complete PCAPNG file buffer. */
export function writePcapng(chunks: PcapngChunk[], opts?: Partial<PcapngWriteOptions>): Buffer {
  const linkType = opts?.linkType ?? 1;
  const snapLen = opts?.snapLen ?? 262144;
  const parts: Buffer[] = [];

  // ── SHB: bom(4) ver(2+2) sectionLen(8), optional userappl option ─────────
  {
    const body = Buffer.alloc(16);
    body.writeUInt32LE(SHB_BOM, 0);
    body.writeUInt16LE(1, 4);
    body.writeUInt16LE(0, 6);
    body.writeBigUInt64LE(0xffffffffffffffffn, 8);
    const opt = opts?.userAppl
      ? optionItem(4, Buffer.from(opts.userAppl, "utf8"))
      : Buffer.alloc(0);
    parts.push(blockBody(SHB_BLOCK, Buffer.concat([body, opt])));
  }

  // ── IDB: linktype(2) reserved(2) snaplen(4), opts: if_tsresol=6, end ──────
  {
    const body = Buffer.alloc(8);
    body.writeUInt16LE(linkType, 0);
    body.writeUInt16LE(0, 2);
    body.writeUInt32LE(snapLen, 4);
    const opt = Buffer.concat([
      optionItem(9 /* if_tsresol */, Buffer.from([6])),
      optionItem(0 /* end of options */, null),
    ]);
    parts.push(blockBody(IDB_BLOCK, Buffer.concat([body, opt])));
  }

  // ── EPBs ──────────────────────────────────────────────────────────────────
  for (const c of chunks) {
    // microseconds since epoch (ts is seconds, fractional)
    const micro = BigInt(Math.round(c.ts * 1e6));
    const head = Buffer.alloc(20);
    head.writeUInt32LE(0, 0); // interface id
    head.writeUInt32LE(Number(micro >> 32n) >>> 0, 4);
    head.writeUInt32LE(Number(micro & 0xffffffffn) >>> 0, 8);
    head.writeUInt32LE(c.data.length >>> 0, 12); // captured len
    head.writeUInt32LE(c.origLen >>> 0, 16); // original len
    parts.push(blockBody(EPB_BLOCK, Buffer.concat([head, pad4(c.data)])));
  }

  return Buffer.concat(parts);
}

/** option item: code(2) len(2) value(pad to 4) */
function optionItem(code: number, value: Buffer | null): Buffer {
  if (!value || value.length === 0) {
    const b = Buffer.alloc(4);
    b.writeUInt16LE(code, 0);
    b.writeUInt16LE(0, 2);
    return b;
  }
  const padded = pad4(value);
  const b = Buffer.alloc(4 + padded.length);
  b.writeUInt16LE(code, 0);
  b.writeUInt16LE(value.length, 2);
  padded.copy(b, 4);
  return b;
}

function pad4(b: Buffer): Buffer {
  const r = b.length % 4;
  return r === 0 ? b : Buffer.concat([b, Buffer.alloc(4 - r)]);
}

/** Assemble one block: type(4) totalLen(4) body [pad] totalLen(4 again). */
function blockBody(blockType: number, body: Buffer): Buffer {
  const total = 8 + body.length + 4;
  const head = Buffer.alloc(8);
  const tail = Buffer.alloc(4);
  head.writeUInt32LE(blockType >>> 0, 0);
  head.writeUInt32LE(total >>> 0, 4);
  tail.writeUInt32LE(total >>> 0, 0);
  return Buffer.concat([head, body, tail]);
}
