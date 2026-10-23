// ─────────────────────────────────────────────────────────────────────────────
// HARDENING FIXTURE HELPERS — shared parameterized byte builders
// (test catalog rule: "Extend the builders so any field can be overridden,
// including illegal values. Never paste unexplained hex blobs.")
//
// Every builder takes an overrides object; every overridable field has a sane
// default. Test files ALSO keep behavior-specific byte literals inline where a
// layout is one-off. Named-error-code assertion lives here too:
// `hasError(p, "ipv4.bad-ihl")` matches the CODE (never the free-text tail).
// ─────────────────────────────────────────────────────────────────────────────

import { decodePacket, type DecodedPacket } from "../../src/engine/decoder.ts";

export function macBytes(hexStr: string): Buffer {
  const b = Buffer.alloc(6);
  for (let i = 0; i < 6; i++) b[i] = parseInt(hexStr.slice(i * 2, i * 2 + 2), 16);
  return b;
}

export function macText(b: Buffer, off = 0): string {
  const p: string[] = [];
  for (let i = 0; i < 6; i++) p.push(b[off + i].toString(16).padStart(2, "0"));
  return p.join(":");
}

export type EthernetOpts = {
  ethertype?: number;
  dst?: string;
  src?: string;
  /** Sequence of VLAN tags: shorter array = reuse the same TPID. */
  vlans?: number[];
  /** Explicit TPIDs per VLAN tag (802.1ad double-tag uses [0x88a8, 0x8100]). */
  tpids?: number[];
  /** Truncate the emitted frame to exactly this byte count (legal values,
   * even ones shorter than the frame layout require). */
  cutTo?: number;
};

/** Ethernet II frame (optionally VLAN-stacked) around an L3 payload. */
export function eth(payload: Buffer, o: EthernetOpts = {}): Buffer {
  const parts = [
    macBytes(o.dst ?? "020203040506"),
    macBytes(o.src ?? "020203040507"),
  ];
  const vlans = o.vlans ?? [];
  vlans.forEach((id, i) => {
    const tpid = o.tpids?.[i] ?? 0x8100;
    const tag = Buffer.alloc(4);
    tag.writeUInt16BE(tpid, 0);
    tag.writeUInt16BE(id & 0x0fff, 2);
    parts.push(tag);
  });
  const et = Buffer.alloc(2);
  et.writeUInt16BE(o.ethertype ?? 0x0800, 0);
  parts.push(et, payload);
  const frame = Buffer.concat(parts);
  return o.cutTo !== undefined ? frame.subarray(0, o.cutTo) : frame;
}

export type Ip4Opts = {
  ihl?: number; // in BYTE units (20 = IHL 5); fills options with EOL/NOPs
  totalLen?: number; // override the announced Total Length (legal or not)
  id?: number;
  flags?: number; // bits 15..0 of the flags+fragment field
  frag?: number; // bottom 13 bits (offset in 8-byte units)
  ttl?: number;
  versionNibble?: number;
  /** IP protocol byte. */
  proto?: number;
  checksumZero?: boolean; // emit 0x0000 checksum
  corruptChecksum?: boolean;
};

/** IPv4 header + payload, with a VALID checksum unless corruption is asked. */
export function ip4(payload: Buffer, o: Ip4Opts = {}): Buffer {
  const ihl = o.ihl ?? 20;
  const h = Buffer.alloc(ihl);
  h[0] = ((o.versionNibble ?? 4) << 4) | ihl / 4;
  h.writeUInt16BE(o.totalLen ?? ihl + payload.length, 2);
  h.writeUInt16BE(o.id ?? 0x1234, 4);
  h.writeUInt16BE(((o.flags ?? 2) << 13) | (o.frag ?? 0), 6);
  h[8] = o.ttl ?? 64;
  h[9] = o.proto ?? 6;
  const s = "10.0.0.1".split(".");
  const d = "10.0.0.2".split(".");
  for (let i = 0; i < 4; i++) { h[12 + i] = Number(s[i]); h[16 + i] = Number(d[i]); }
  if (!o.checksumZero && !o.corruptChecksum) {
    let sum = 0;
    for (let i = 0; i < ihl; i += 2) sum += h.readUInt16BE(i);
    while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
    h.writeUInt16BE(~sum & 0xffff, 10);
  }
  return Buffer.concat([h, payload]);
}

export type TcpOpts = {
  sport?: number;
  dport?: number;
  flags?: number;
  seq?: number;
  ack?: number;
  window?: number;
  urgent?: number;
  /** data-offset units (5 = 20 bytes default). Illegal values allowed. */
  dataOffsetUnits?: number;
  /** Raw option bytes placed after the base 20-byte header (scaled by
   * dataOffsetUnits). E.g. MSS option: tcpOptionMss(1460). */
  rawOptions?: Buffer;
};

export function tcpOptionMss(mss: number): Buffer {
  const b = Buffer.from([2, 4, 0, 0]);
  b.writeUInt16BE(mss, 2);
  return b;
}

export function tcpOptionWs(ws: number): Buffer { return Buffer.from([3, 3, ws]); }
export function tcpOptionSackPermitted(): Buffer { return Buffer.from([4, 2]); }
export function tcpOptionTimestamps(val: number, echo: number): Buffer {
  const b = Buffer.alloc(10); b[0] = 8; b[1] = 10;
  b.writeUInt32BE(val >>> 0, 2); b.writeUInt32BE(echo >>> 0, 6);
  return b;
}

/** TCP header + payload (checksum is ALWAYS 0x0000 here — field exposed by
 * the engine but not asserted unless the test builds real ones). */
export function tcp(o: TcpOpts = {}, payload: Buffer = Buffer.alloc(0)): Buffer {
  const units = o.dataOffsetUnits ?? 5;
  const headLen = units * 4;
  const opt = o.rawOptions ?? Buffer.alloc(Math.max(0, headLen - 20));
  const b = Buffer.alloc(headLen + payload.length);
  b.writeUInt16BE(o.sport ?? 5000, 0);
  b.writeUInt16BE(o.dport ?? 80, 2);
  b.writeUInt32BE((o.seq ?? 1) >>> 0, 4);
  b.writeUInt32BE((o.ack ?? 1) >>> 0, 8);
  b[12] = units << 4;
  b[13] = (o.flags ?? 0x10) & 0xff;
  // bounded writes: illegal (short) data offsets must NOT crash the builder
  if (headLen >= 16) b.writeUInt16BE(o.window ?? 65535, 14);
  if (headLen >= 20) b.writeUInt16BE(o.urgent ?? 0, 18); // urgent pointer field (offset 18)
  opt.copy(b, 20);
  payload.copy(b, headLen);
  return b;
}

export type UdpOpts = {
  sport?: number;
  dport?: number;
  /** Override the announced datagram length (0 = jumbogram, 1-7 = illegal <8). */
  lenOverride?: number;
};

export function udp(payload: Buffer, o: UdpOpts = {}): Buffer {
  const b = Buffer.alloc(8 + payload.length);
  b.writeUInt16BE(o.sport ?? 4000, 0);
  b.writeUInt16BE(o.dport ?? 5000, 2);
  b.writeUInt16BE(o.lenOverride ?? 8 + payload.length, 4);
  b.writeUInt16BE(0, 6); // checksum 0
  payload.copy(b, 8);
  return b;
}

/** DNS quick-builder: header + labeled questions. */
export function dnsMsg(o: {
  id?: number; isResponse?: boolean; rcode?: number; qd?: number; an?: number;
  questions?: Array<{ name: string; type: number }>;
}): Buffer {
  const parts: Buffer[] = [];
  const h = Buffer.alloc(12);
  h.writeUInt16BE(o.id ?? 0x2ccb, 0);
  const opq = 0x0100 | (o.isResponse ? 0x8000 : 0) | (o.rcode ?? 0);
  h.writeUInt16BE(opq, 2);
  const qs = o.questions ?? [{ name: "example.org", type: 1 }];
  h.writeUInt16BE(o.qd ?? qs.length, 4);
  h.writeUInt16BE(o.an ?? 0, 6);
  parts.push(h);
  for (const q of qs) {
    if (q.name === "." || q.name === "") {
      parts.push(Buffer.from([0]));
    } else {
      for (const label of q.name.split(".")) {
        const one = Buffer.alloc(1 + label.length);
        one[0] = label.length;
        one.write(label, 1);
        parts.push(one);
      }
      parts.push(Buffer.from([0]));
    }
    const t = Buffer.alloc(4);
    t.writeUInt16BE(q.type, 0);
    t.writeUInt16BE(1, 2);
    parts.push(t);
  }
  return Buffer.concat(parts);
}

// ── IPv6 + extension-header chain builders (catalog C) ─────────────────────

export type ExtSpec =
  | { kind: "hbh" | "routing" | "dstopt"; units: number; nhAfter: number }
  | { kind: "frag"; nhAfter: number; offUnits: number; mf: boolean; id: number }
  | { kind: "ah"; pl: number; nhAfter: number };

/** Serialize one extension header. byte0 of every header is its NextHeader. */
export function buildExt(spec: ExtSpec, afterNh: number): Buffer {
  if (spec.kind === "frag") {
    const b = Buffer.alloc(8);
    b[0] = afterNh; // NextHeader
    b.writeUInt16BE((spec.offUnits << 3) | (spec.mf ? 1 : 0), 2);
    b.writeUInt32BE(spec.id >>> 0, 4);
    return b;
  }
  if (spec.kind === "ah") {
    // RFC 4302 §2: NH(byte0), PayloadLen(byte1, words-2), Reserved, SPI, Seq
    const b = Buffer.alloc((spec.pl + 2) * 4);
    b[0] = afterNh;
    b[1] = spec.pl;
    b.writeUInt32BE(0x11223344 >>> 0, 4); // SPI filler (data, not signal)
    return b;
  }
  const total = (spec.units + 1) * 8;
  const b = Buffer.alloc(total);
  b[0] = afterNh; // NextHeader is derived from the header that follows
  b[1] = spec.units;
  // filler bytes: hop-by-hop 0x00 options, routing type 0/segmentsLeft 0, dst-opt 0 options
  if (spec.kind === "routing") { b[2] = 0; b[3] = 0; }
  return b;
}

export type Ip6Opts = {
  src?: string; // hex digits, 32 chars
  dst?: string;
  nh?: number;
  hopLimit?: number;
  payloadLenOverride?: number;
  versionNibble?: number;
  /** Extension headers ordered outermost → innermost. The final NH value
   * reached by unwinding the chain is `nh` itself; each spec records the NH
   * that follows the NEXT header, so the chain is written per RFC walk. */
  exts?: ExtSpec[];
};

/** IPv6 header + ext chain + payload. Addresses default to
 * 2001:db8::1 → 2001:db8::2 (doc-suite, RFC 3849). */
export function ip6(payload: Buffer, o: Ip6Opts = {}): Buffer {
  const extsBytes: Buffer[] = [];
  const nhOf = (s: ExtSpec): number =>
    s.kind === "frag" ? 44 : s.kind === "hbh" ? 0 : s.kind === "routing" ? 43 : s.kind === "ah" ? 51 : 60;
  // unwinding: the LAST spec's NH is `o.nh`, intermediates chain to the next.
  for (let i = 0; i < (o.exts?.length ?? 0); i++) {
    const spec = o.exts![i];
    const nextSpec = o.exts![i + 1];
    const after = nextSpec ? nhOf(nextSpec) : o.nh ?? 6;
    extsBytes.push(buildExt(spec, after));
  }
  const head = Buffer.alloc(40);
  head[0] = (o.versionNibble ?? 6) << 4;
  head.writeUInt16BE(o.payloadLenOverride ?? 0, 4); // patched below
  head[6] = o.exts?.length ? nhOf(o.exts[0]) : (o.nh ?? 6);
  head[7] = o.hopLimit ?? 64;
  const src = o.src ?? "20010db8000000000000000000000001";
  const dst = o.dst ?? "20010db8000000000000000000000002";
  const sb = Buffer.from(src, "hex"); const db = Buffer.from(dst, "hex");
  sb.copy(head, 8); db.copy(head, 24);
  const body = Buffer.concat([...extsBytes, payload]);
  const realPayloadLen = o.payloadLenOverride ?? body.length;
  head.writeUInt16BE(realPayloadLen & 0xffff, 4);
  return Buffer.concat([head, body]);
}

// ── assertion helpers ───────────────────────────────────────────────────────

/** True when a decoded packet recorded the NAMED error code. Codes are the
 * stable prefix ("ipv4.bad-ihl: …") — assert the code, never the tail text. */
export function hasError(p: DecodedPacket, code: string): boolean {
  return p.errors.some((e) => e.startsWith(code));
}

/** Count of recorded errors whose code SOMEWHAT matches a prefix set. */
export function errorCodes(p: DecodedPacket): string[] {
  return p.errors.map((e) => e.split(":")[0]);
}

/** decodePacket wrapper asserting the never-throw contract. */
export function decode(linkType: number, bytes: Buffer, origLen = bytes.length): DecodedPacket {
  // Contract: must not throw, must always return a DecodedPacket with errors[].
  const r = decodePacket(linkType, bytes, origLen);
  return r;
}

/** Deterministic PRNG (mulberry32) — the seed is printed by fuzz tests. */
export function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
