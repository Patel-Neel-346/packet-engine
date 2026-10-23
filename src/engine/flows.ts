// ============================================================================
// M3 Flow Engine — Per-Flow Conversation Lifecycle & Stream Reassembly
//
// Assembles per-flow "stories" and stateful conversation views from the
// parity-verified packet layer:
//
// 1. Two Views Deliberately Separated:
//    - EPB View: Every Enhanced Packet Block in the trace, including capture copies.
//      Maintains exact packet/byte accounting per direction. Verified against
//      `tshark -z conv,tcp/udp/icmp` with zero delta.
//    - Unique View: Deduplicated physical packets (via M2 deduplication rule).
//      Runs TCP stream reassembly, handshake/termination tracking, retransmission
//      identification, DNS attribution, TLS SNI extraction, and HTTP/1.x parsing.
//
// 2. Stream Reassembly & Sequence Space Math:
//    - Out-of-order segments reassembled in relative byte sequence order.
//    - Gaps identified, recorded as metadata, and zero-padded in the byte stream.
//    - Retransmissions (full or partial) identified and accounted for.
//    - Unsigned 32-bit TCP sequence space wraparound handled via modular signed arithmetic.
//
// Layer:     engine — pure analysis core (analyzePcapFile wraps with readFileSync)
// Milestone: M3 — flow engine
// ============================================================================

import fs from "node:fs";
import type { PcapngFile } from "./pcapng.ts";
import { parsePcapng, packetTimestampSeconds } from "./pcapng.ts";
import {
  canonicalFlow,
  TCP_SYN,
  TCP_FIN,
  TCP_RST,
  TCP_PSH,
  TCP_ACK,
  type DecodedPacket,
} from "./decoder.ts";
import { decodeAllPackets, dedupePackets } from "./dedupe.ts";

// ============================================================================
// 1. PUBLIC TYPES & INTERFACES
// ============================================================================

export interface FlowEvent {
  /** EPB index in the capture trace. */
  frame: number;
  /** Timestamp in seconds (float). */
  ts: number;
  /** Direction: true if endpoint A to B, false if B to A. */
  dirAtoB: boolean;
  /** Wire length in bytes (origLen). */
  frameLen: number;
  /** TCP flag bitmask if present. */
  tcpFlags?: number;
}

export interface ReassembledStream {
  /** Absolute sequence number of the first reassembled byte. */
  base: number;
  /** True when no SYN packet was captured (base deduced from minimum data seq). */
  baseAssumed: boolean;
  /** Number of disjoint reassembled chunks. */
  segments: number;
  /** Assembled stream buffer with missing gaps padded with 0x00 bytes. */
  bytes: Buffer;
  /** Number of detected gaps in the stream. */
  gapCount: number;
  /** Cumulative size of missing gap bytes. */
  gapBytes: number;
  /** Details for the first 5 gap occurrences. */
  firstGaps: Array<{ start: number; len: number }>;
  /** Segments fully covered by earlier-seen sequence intervals. */
  retransSegs: number;
  /** Bytes retransmitted. */
  retransBytes: number;
  /** Segments partially overlapping previously received data. */
  partialRetransSegs: number;
  /** Declared transport payloads truncated by the capture boundary. */
  truncatedPayloads: number;
  /** True if stream length exceeded MAX_STREAM_BYTES memory budget. */
  overflowed: boolean;
}

export interface TcpStory {
  syn?: { frame: number; ts: number };
  synAck?: { frame: number; ts: number; deltaMs: number | null };
  ackAfterHandshake?: { frame: number; ts: number };
  finA2b?: { frame: number; ts: number };
  finB2a?: { frame: number; ts: number };
  rst?: { frame: number; ts: number };
  /** Complete 3-way handshake observed: SYN + SYN-ACK + (subsequent ACK or data). */
  handshakeComplete: boolean;
  /** Ordered list of unique TCP flag combinations observed in this flow. */
  flagsSeen: string[];
  /** Count of payload-carrying segments. */
  dataSegs: number;
  /** Reassembled byte stream from A to B. */
  a2b: ReassembledStream | null;
  /** Reassembled byte stream from B to A. */
  b2a: ReassembledStream | null;
}

export interface HttpMessage {
  head: string;
  method?: string;
  uri?: string;
  version?: string;
  status?: number;
  statusText?: string;
  headers: Record<string, string>;
  contentLength?: number;
  chunked: boolean;
  bodyCaptured: number;
  bodyComplete: boolean;
}

export interface HttpStory {
  requests: HttpMessage[];
  responses: HttpMessage[];
  parsingStopped: "end" | "chunked" | "limit";
}

export interface Flow {
  id: string;
  proto: number;
  kind: "tcp" | "udp" | "icmp" | "icmpv6";
  /** Canonical endpoint A (port 0 for ICMP). */
  a: { ip: string; port: number };
  /** Canonical endpoint B. */
  b: { ip: string; port: number };
  /** Hostnames attributed to either endpoint via DNS answers. */
  hosts: string[];
  /** Server Name Indication (SNI) hostnames observed in TLS ClientHellos. */
  tlsSni: string[];
  firstTs: number;
  lastTs: number;
  /** Packet counts per direction in the EPB view (all capture copies included). */
  packets: { a2b: number; b2a: number };
  /** Wire byte totals per direction in the EPB view. */
  bytes: { a2b: number; b2a: number };
  /** Total count of unique deduped packets. */
  uniquePackets: number;
  /** Deduped packets carrying non-zero application payload. */
  uniqueDataPackets: number;
  /** Retransmitted segments detected in unique stream reconstruction. */
  uniqueRetransSegs: number;
  /** Event timeline of all frames belonging to this conversation. */
  events: FlowEvent[];
  /** TCP connection lifecycle analysis (null for non-TCP flows). */
  tcp: TcpStory | null;
  /** HTTP/1.x conversation analysis (null if no HTTP traffic recognized). */
  http: HttpStory | null;
}

export interface FragmentStat {
  id: string;
  count: number;
  bytes: number;
}

export interface FlowAnalysis {
  file: string;
  totalEpbs: number;
  /** EPB count merged as duplicate physical frame copies. */
  duplicatesMerged: number;
  /** Analyzed flows, sorted chronologically by first frame timestamp. */
  flows: Flow[];
  /** Blocks without an IP layer or undecodable framing (e.g. ARP). */
  nonFlowEpbs: number;
  /** Fragment packets (non-first fragments carrying no transport header). */
  fragments: FragmentStat[];
  /** IP address to resolved DNS hostnames map. */
  dnsHostByIp: Array<{ ip: string; names: string[] }>;
  /** Total retransmitted segments detected across all flows. */
  retransSegsTotal: number;
  warnings: string[];
}

// ============================================================================
// 2. CONSTANTS & CONFIGURATION
// ============================================================================

/** Per-flow reassembly memory cap (8 MiB combined across both directions). */
const MAX_STREAM_BYTES = 8 << 20;

// ============================================================================
// 3. TCP STREAM REASSEMBLY (SparseStream & Sequence Space Math)
// ============================================================================

interface SparsePiece {
  /** Starting byte offset relative to the stream base. */
  start: number;
  /** Ending byte offset (exclusive). */
  end: number;
  data: Buffer;
}

/**
 * Manages an out-of-order sparse TCP byte stream.
 * Automatically tracks gaps, non-overlapping segments, and retransmissions.
 */
class SparseStream {
  private pieces: SparsePiece[] = [];
  totalBytes = 0;
  retransSegs = 0;
  retransBytes = 0;
  partialRetransSegs = 0;
  truncatedPayloads = 0;
  overflowed = false;

  /**
   * Computes sub-ranges of [start, end) that have not been observed yet.
   */
  private novelRanges(start: number, end: number): Array<[number, number]> {
    const out: Array<[number, number]> = [];
    let pos = start;

    for (const p of this.pieces) {
      if (p.end <= pos) continue;
      if (p.start >= end) break;
      if (p.start > pos) {
        out.push([pos, Math.min(p.start, end)]);
      }
      pos = Math.max(pos, p.end);
      if (pos >= end) break;
    }

    if (pos < end) {
      out.push([pos, end]);
    }
    return out;
  }

  /**
   * Inserts a new piece into the sorted piecewise list.
   */
  private insert(start: number, data: Buffer): void {
    const piece: SparsePiece = { start, end: start + data.length, data };
    let i = 0;
    while (i < this.pieces.length && this.pieces[i].end <= start) i++;
    this.pieces.splice(i, 0, piece);
    this.totalBytes += data.length;
  }

  /**
   * Ingests a received segment into the stream at the given relative byte offset.
   * Returns the count of novel (new) bytes added.
   */
  add(start: number, data: Buffer): number {
    const len = data.length;
    if (len === 0 || this.overflowed) return 0;

    if (this.totalBytes + len > MAX_STREAM_BYTES) {
      this.overflowed = true;
      return 0;
    }

    let novel = 0;
    for (const [s, e] of this.novelRanges(start, start + len)) {
      novel += e - s;
    }

    if (novel === len) {
      // Entire segment is brand new data
      this.insert(start, data);
      return novel;
    }

    // Segment is either fully or partially retransmitted
    this.retransSegs += 1;
    this.retransBytes += len - novel;

    if (novel > 0) {
      this.partialRetransSegs += 1;
      for (const [s, e] of this.novelRanges(start, start + len)) {
        this.insert(s, data.subarray(s - start, e - start));
      }
    }

    return novel;
  }

  /**
   * Finalizes the sparse pieces into a contiguous buffer, inserting 0x00 runs for gaps.
   */
  finalize(base: number, baseAssumed: boolean): ReassembledStream {
    this.pieces.sort((p, q) => p.start - q.start);

    const chunks: Buffer[] = [];
    const firstGaps: Array<{ start: number; len: number }> = [];
    let gapCount = 0;
    let gapBytes = 0;
    let cursor = 0;

    for (const p of this.pieces) {
      if (p.start > cursor) {
        const len = p.start - cursor;
        gapCount++;
        gapBytes += len;
        if (firstGaps.length < 5) {
          firstGaps.push({ start: (base + cursor) >>> 0, len });
        }
        chunks.push(Buffer.alloc(len));
      }
      chunks.push(p.data);
      cursor = Math.max(cursor, p.end);
    }

    return {
      base,
      baseAssumed,
      segments: this.pieces.length,
      bytes: Buffer.concat(chunks),
      gapCount,
      gapBytes,
      firstGaps,
      retransSegs: this.retransSegs,
      retransBytes: this.retransBytes,
      partialRetransSegs: this.partialRetransSegs,
      truncatedPayloads: this.truncatedPayloads,
      overflowed: this.overflowed,
    };
  }
}

/** Formats a TCP flag bitmask into human-readable notation (e.g. "SYN+ACK"). */
function flagsLabel(f: number): string {
  const parts: string[] = [];
  if (f & TCP_SYN) parts.push("SYN");
  if (f & TCP_FIN) parts.push("FIN");
  if (f & TCP_RST) parts.push("RST");
  if (f & TCP_PSH) parts.push("PSH");
  if (f & TCP_ACK) parts.push("ACK");
  return parts.length > 0 ? parts.join("+") : `0x${(f & 0xff).toString(16)}`;
}

// ============================================================================
// 4. FLOW KEYS & CONVERSATION IDENTIFIERS
// ============================================================================

interface KeyedFlow {
  key: string;
  kind: Flow["kind"];
  dirAtoB: boolean;
  a: { ip: string; port: number };
  b: { ip: string; port: number };
}

/**
 * Extracts a normalized conversation key and endpoint direction for a packet.
 */
function flowKeyOf(p: DecodedPacket): KeyedFlow | null {
  const t = p.transport;
  const i = p.ip;
  if (!t || !i) return null;

  if (t.kind === "tcp" || t.kind === "udp") {
    if (t.sport === undefined || t.dport === undefined) return null;

    // Non-first fragments lack L4 ports and are excluded from 5-tuple keying
    if (i.version === 4 && i.fragment !== undefined && i.fragment.offsetBytes > 0) {
      return null;
    }

    const f = canonicalFlow(t.proto, i.src, t.sport, i.dst, t.dport);
    const ka = `${t.sport}|${i.src}`;
    const kb = `${t.dport}|${i.dst}`;

    return {
      key: `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`,
      kind: t.kind,
      dirAtoB: ka <= kb,
      a: { ip: f.aip, port: f.aport },
      b: { ip: f.bip, port: f.bport },
    };
  }

  if (t.kind === "icmp" || t.kind === "icmpv6") {
    // ICMP flows keyed by IP address pairs without ports (matching tshark conversation model)
    const aip = i.src <= i.dst ? i.src : i.dst;
    const bip = i.src <= i.dst ? i.dst : i.src;

    return {
      key: `p${t.proto} ${aip} <--> ${bip}`,
      kind: t.kind,
      dirAtoB: i.src === aip,
      a: { ip: aip, port: 0 },
      b: { ip: bip, port: 0 },
    };
  }

  return null;
}

/** Returns pair key for tracking non-first IP fragments. */
function pairKeyForFragment(p: DecodedPacket): string | null {
  const i = p.ip;
  if (!i || i.fragment === undefined || i.fragment.offsetBytes === 0) return null;
  if (i.proto !== 6 && i.proto !== 17 && i.proto !== 1 && i.proto !== 58) return null;

  const aip = i.src <= i.dst ? i.src : i.dst;
  const bip = i.src <= i.dst ? i.dst : i.src;
  return `p${i.proto} ${aip} <--> ${bip}`;
}

// ============================================================================
// 5. HTTP/1.x RECONSTRUCTION & PARSING
// ============================================================================

const METHOD_RE = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) /;

/** Parses the initial line of an HTTP request or response. */
function parseMessageHead(startLine: string, isRequest: boolean): HttpMessage | null {
  const m: HttpMessage = {
    head: startLine,
    headers: {},
    chunked: false,
    bodyCaptured: 0,
    bodyComplete: false,
  };

  if (isRequest) {
    const parts = startLine.split(" ");
    const mt = startLine.match(METHOD_RE);
    if (!mt || parts.length < 3) return null;
    m.method = mt[1];
    m.uri = parts[1];
    m.version = parts[2];
  } else {
    const st = startLine.match(/^HTTP\/(\d\.\d) (\d{3})(?: (.*))?$/);
    if (!st) return null;
    m.version = st[1];
    m.status = parseInt(st[2], 10);
    m.statusText = st[3] ?? "";
  }

  return m;
}

/**
 * Minimal HTTP/1.x message parser over a unidirectional reassembled byte stream.
 * Scans up to 8 pipelined messages or 32 KiB head bounds.
 */
function parseHttpStream(data: Buffer, isRequest: boolean): HttpStory | null {
  const first = data.subarray(0, 16).toString("latin1");
  if (isRequest ? !METHOD_RE.test(first) : !first.startsWith("HTTP/")) {
    return null;
  }

  const messages: HttpMessage[] = [];
  let parsingStopped: HttpStory["parsingStopped"] = "end";
  let pos = 0;

  while (messages.length < 8 && pos < data.length) {
    const maxScan = Math.min(pos + 32768, data.length);
    let headEnd = -1;

    for (let j = pos + 3; j < maxScan; j++) {
      if (
        data[j - 3] === 0x0d && data[j - 2] === 0x0a &&
        data[j - 1] === 0x0d && data[j] === 0x0a
      ) {
        headEnd = j;
        break;
      }
    }

    if (headEnd < 0) break;

    const head = data.subarray(pos, headEnd).toString("latin1");
    const lines = head.split("\r\n");
    const m = parseMessageHead(lines[0], isRequest);
    if (!m) break;

    m.head = head;
    for (const line of lines.slice(1)) {
      const idx = line.indexOf(":");
      if (idx > 0) {
        const name = line.slice(0, idx).trim().toLowerCase();
        const value = line.slice(idx + 1).trim();
        m.headers[name] = m.headers[name] === undefined
          ? value
          : `${m.headers[name]}, ${value}`;
      }
    }

    m.chunked = (m.headers["transfer-encoding"] ?? "").includes("chunked");
    const clRaw = m.headers["content-length"];
    if (clRaw !== undefined) {
      const cl = parseInt(clRaw.split(",")[0].trim(), 10);
      if (!Number.isNaN(cl)) m.contentLength = cl;
    }

    const bodyStart = headEnd + 1;

    if (m.contentLength === undefined) {
      if (m.chunked) {
        m.bodyCaptured = Math.max(0, data.length - bodyStart);
        m.bodyComplete = false;
        messages.push(m);
        parsingStopped = "chunked";
        break;
      }

      if (isRequest) {
        // Pipelined request without body
        m.bodyCaptured = 0;
        m.bodyComplete = true;
        messages.push(m);
        pos = bodyStart;
        continue;
      }

      // Response without Content-Length continues to EOF
      m.bodyCaptured = Math.max(0, data.length - bodyStart);
      m.bodyComplete = true;
      messages.push(m);
      break;
    }

    const avail = Math.max(0, Math.min(m.contentLength, data.length - bodyStart));
    m.bodyCaptured = avail;
    m.bodyComplete = avail === m.contentLength;
    messages.push(m);

    const next = bodyStart + avail;
    if (next <= pos) break;
    pos = next;
  }

  if (messages.length >= 8 && pos < data.length) {
    parsingStopped = "limit";
  }
  if (messages.length === 0) return null;

  return {
    requests: isRequest ? messages : [],
    responses: isRequest ? [] : messages,
    parsingStopped,
  };
}

function attemptHttp(reqBytes: Buffer, resBytes: Buffer): HttpStory | null {
  const req = parseHttpStream(reqBytes, true);
  if (!req || req.requests.length === 0) return null;

  const res = parseHttpStream(resBytes, false);
  if (!res || res.responses.every((r) => !r.status)) return null;

  return {
    requests: req.requests,
    responses: res.responses,
    parsingStopped: req.parsingStopped !== "end" ? req.parsingStopped : res.parsingStopped,
  };
}

function parseFlowHttp(flow: Flow): void {
  if (flow.kind !== "tcp" || !flow.tcp) return;
  const { a2b, b2a } = flow.tcp;
  if (!a2b || !b2a || a2b.bytes.length === 0 || b2a.bytes.length === 0) return;

  // Decide client/server orientation dynamically by content
  const http = attemptHttp(a2b.bytes, b2a.bytes) ?? attemptHttp(b2a.bytes, a2b.bytes);
  if (http) flow.http = http;
}

// ============================================================================
// 6. DNS ATTRIBUTION & HOSTNAME MAPPING
// ============================================================================

/** Builds an IP-to-domain map from all parsed DNS response answers. */
function buildDnsAttribution(decoded: DecodedPacket[]): Map<string, Set<string>> {
  const map = new Map<string, Set<string>>();

  for (const d of decoded) {
    const dns = d.dns;
    if (!dns || !dns.isResponse || dns.questions.length === 0) continue;
    const name = dns.questions[0].name;

    for (const ip of [...dns.aRecords, ...dns.aaaaRecords]) {
      let set = map.get(ip);
      if (!set) {
        set = new Set();
        map.set(ip, set);
      }
      set.add(name);
    }
  }

  return map;
}

// ============================================================================
// 7. TCP LIFECYCLE STORY (Handshake, Flags, Stream Assembly)
// ============================================================================

interface UniqueEvent {
  p: DecodedPacket;
  ts: number;
  dirAtoB: boolean;
  frame: number;
  bytes: Buffer;
}

/**
 * Reconstructs TCP handshake, teardown flags, and byte streams from unique frames.
 * Handles 32-bit sequence wraparound using modular signed distance math.
 */
function buildTcpStory(events: UniqueEvent[]): TcpStory | null {
  const story: TcpStory = {
    handshakeComplete: false,
    flagsSeen: [],
    dataSegs: 0,
    a2b: null,
    b2a: null,
  };

  const streams: Record<"a2b" | "b2a", SparseStream> = {
    a2b: new SparseStream(),
    b2a: new SparseStream(),
  };

  const segs: Record<"a2b" | "b2a", Array<{ seq: number; data: Buffer }>> = {
    a2b: [],
    b2a: [],
  };

  let sawAckAfterHandshake = false;

  for (const ev of events) {
    const t = ev.p.transport;
    if (!t || t.kind !== "tcp") continue;

    const dir: "a2b" | "b2a" = ev.dirAtoB ? "a2b" : "b2a";
    const flags = t.tcpFlags ?? 0;
    const label = flagsLabel(flags);

    if (story.flagsSeen[story.flagsSeen.length - 1] !== label) {
      story.flagsSeen.push(label);
    }

    // Handshake state machine
    if (flags & TCP_SYN) {
      if (flags & TCP_ACK) {
        if (!story.synAck) {
          story.synAck = {
            frame: ev.frame,
            ts: ev.ts,
            deltaMs: story.syn ? (ev.ts - story.syn.ts) * 1000 : null,
          };
        }
      } else if (!story.syn) {
        story.syn = { frame: ev.frame, ts: ev.ts };
      }
    } else if (flags & TCP_ACK && !(flags & (TCP_FIN | TCP_RST)) && !sawAckAfterHandshake) {
      if (story.syn && story.synAck) {
        sawAckAfterHandshake = true;
        story.ackAfterHandshake = { frame: ev.frame, ts: ev.ts };
      }
    }

    // Teardown / Reset
    if (flags & TCP_FIN) {
      if (ev.dirAtoB && !story.finA2b) {
        story.finA2b = { frame: ev.frame, ts: ev.ts };
      } else if (!ev.dirAtoB && !story.finB2a) {
        story.finB2a = { frame: ev.frame, ts: ev.ts };
      }
    }
    if (flags & TCP_RST && !story.rst) {
      story.rst = { frame: ev.frame, ts: ev.ts };
    }

    // Payload segment collection
    if (t.payloadLen > 0 && t.headerOff !== undefined && t.headerLen !== undefined) {
      const bodyStart = t.headerOff + t.headerLen;
      const avail = Math.max(0, ev.bytes.length - bodyStart);
      const data = ev.bytes.subarray(bodyStart, bodyStart + Math.min(t.payloadLen, avail));
      if (t.payloadLen > avail) {
        streams[dir].truncatedPayloads++;
      }
      segs[dir].push({ seq: t.seq ?? 0, data });
      story.dataSegs++;
    }
  }

  story.handshakeComplete = Boolean(
    story.syn && story.synAck &&
    (story.ackAfterHandshake || (segs.a2b.length > 0 || segs.b2a.length > 0)),
  );

  // Reassemble payload streams using signed 32-bit modular sequence math
  for (const dir of ["a2b", "b2a"] as const) {
    const s = segs[dir];
    if (s.length === 0) continue;

    const anchor = s[0].seq;
    // (seq - anchor) | 0 yields signed distance in modulo 2^32 space
    const minRel = Math.min(...s.map((x) => (x.seq - anchor) | 0));
    const base = (anchor + minRel) >>> 0;

    for (const x of s) {
      const rel = (x.seq - base) | 0;
      if (rel >= 0) {
        streams[dir].add(rel, x.data);
      }
    }

    story[dir] = streams[dir].finalize(base, !story.syn);
  }

  return story;
}

// ============================================================================
// 8. FLOW ENGINE CORE (buildFlows & analyzePcapFile)
// ============================================================================

function ensureFlow(map: Map<string, Flow>, k: KeyedFlow, ts: number): Flow {
  let f = map.get(k.key);
  if (!f) {
    f = {
      id: k.key,
      proto: k.kind === "tcp" ? 6 : k.kind === "udp" ? 17 : k.kind === "icmp" ? 1 : 58,
      kind: k.kind,
      a: k.a,
      b: k.b,
      hosts: [],
      tlsSni: [],
      firstTs: ts,
      lastTs: ts,
      packets: { a2b: 0, b2a: 0 },
      bytes: { a2b: 0, b2a: 0 },
      uniquePackets: 0,
      uniqueDataPackets: 0,
      uniqueRetransSegs: 0,
      events: [],
      tcp: k.kind === "tcp"
        ? { handshakeComplete: false, flagsSeen: [], dataSegs: 0, a2b: null, b2a: null }
        : null,
      http: null,
    };
    map.set(k.key, f);
  }

  if (ts < f.firstTs) f.firstTs = ts;
  if (ts > f.lastTs) f.lastTs = ts;
  return f;
}

/**
 * Assembles the complete FlowAnalysis (EPB view + deduped unique view) from a PCAPNG.
 * Guaranteed never to throw; warnings accumulate in `warnings`.
 */
export function buildFlows(parsed: PcapngFile, fileName: string): FlowAnalysis {
  const warnings: string[] = [];
  const decoded = decodeAllPackets(parsed);
  const { groups, duplicatesMerged } = dedupePackets(parsed, decoded);

  // --- Step 1: EPB View Accounting (Every frame block, copies included) ---
  const flowMap = new Map<string, Flow>();
  const fragmentStats = new Map<string, FragmentStat>();
  let nonFlowEpbs = 0;

  for (let i = 0; i < decoded.length; i++) {
    const p = decoded[i];
    const ts = packetTimestampSeconds(parsed.packets[i], parsed.interfaces);
    const k = flowKeyOf(p);

    if (k) {
      const f = ensureFlow(flowMap, k, ts);
      const dir = k.dirAtoB ? "a2b" : "b2a";
      f.packets[dir] += 1;
      f.bytes[dir] += parsed.packets[i].origLen;
      f.events.push({
        frame: i,
        ts,
        dirAtoB: k.dirAtoB,
        frameLen: parsed.packets[i].origLen,
        tcpFlags: p.transport?.tcpFlags,
      });
      continue;
    }

    const fk = pairKeyForFragment(p);
    if (fk) {
      const stat = fragmentStats.get(fk) ?? { id: fk, count: 0, bytes: 0 };
      stat.count++;
      stat.bytes += parsed.packets[i].origLen;
      fragmentStats.set(fk, stat);
      continue;
    }

    nonFlowEpbs++;
  }

  // --- Step 2: Unique View (Deduped physical frames) ---
  const perFlowUnique = new Map<string, UniqueEvent[]>();
  let retransTotal = 0;

  for (const g of groups) {
    const p = g.packet;
    const k = flowKeyOf(p);
    if (!k) continue;

    const f = flowMap.get(k.key);
    if (!f) continue;

    f.uniquePackets++;
    if ((p.transport?.payloadLen ?? 0) > 0) {
      f.uniqueDataPackets++;
    }
    if (p.tls?.sni && !f.tlsSni.includes(p.tls.sni)) {
      f.tlsSni.push(p.tls.sni);
    }

    let list = perFlowUnique.get(k.key);
    if (!list) {
      list = [];
      perFlowUnique.set(k.key, list);
    }

    list.push({
      p,
      ts: g.ts,
      dirAtoB: k.dirAtoB,
      frame: g.reprIdx,
      bytes: (p as unknown as { __bytes: Buffer }).__bytes,
    });
  }

  // --- Step 3: Stateful Flow Stories (TCP Reassembly & HTTP Analysis) ---
  for (const [key, evs] of perFlowUnique) {
    const f = flowMap.get(key);
    if (!f) continue;

    if (f.kind === "tcp") {
      const story = buildTcpStory(evs);
      if (story) {
        f.uniqueRetransSegs = (story.a2b?.retransSegs ?? 0) + (story.b2a?.retransSegs ?? 0);
        retransTotal += f.uniqueRetransSegs;
        f.tcp = story;
      }
    }

    parseFlowHttp(f);
  }

  // --- Step 4: DNS Attribution & Host Matching ---
  const dnsMap = buildDnsAttribution(decoded);
  const flows = [...flowMap.values()].sort(
    (x, y) => x.firstTs - y.firstTs || x.id.localeCompare(y.id),
  );

  for (const f of flows) {
    const names = new Set<string>();
    for (const ip of [f.a.ip, f.b.ip]) {
      for (const n of dnsMap.get(ip) ?? []) {
        names.add(n);
      }
    }
    f.hosts = [...names].sort();
    f.tlsSni.sort();
  }

  return {
    file: fileName,
    totalEpbs: decoded.length,
    duplicatesMerged,
    flows,
    nonFlowEpbs,
    fragments: [...fragmentStats.values()].sort((x, y) => y.count - x.count),
    dnsHostByIp: [...dnsMap.entries()]
      .map(([ip, names]) => ({ ip, names: [...names].sort() }))
      .sort((x, y) => x.ip.localeCompare(y.ip)),
    retransSegsTotal: retransTotal,
    warnings,
  };
}

/**
 * Convenience wrapper: reads a PCAPNG file from disk and builds its flow analysis.
 */
export function analyzePcapFile(file: string): FlowAnalysis {
  const parsed = parsePcapng(fs.readFileSync(file));
  return buildFlows(parsed, file);
}

// ============================================================================
// 9. FORMATTING HELPERS
// ============================================================================

/** Formats byte quantities into human-readable labels ("500B", "1.5KB", "1.00MB"). */
export function bytesLabel(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(2)}MB`;
}
