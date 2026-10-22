// M3 Flow Engine — assembles per-flow "stories" from the parity-verified
// packet layer.
//
// Two views, deliberately separated:
//   EPB view    — every Enhanced Packet Block in the trace, copies included.
//                 Packet/byte counts per flow per direction. This is the view
//                 verified against `tshark -z conv,tcp/udp/icmp` in M3.3.
//   Unique view — the M2 dedupe rule collapses copies of one physical packet;
//                 TCP stream reassembly, handshake/close, retransmission
//                 detection, DNS attribution, TLS SNI, HTTP parsing run here.
//
// Flow key: `canonicalFlow` from the decoder (the same normalization the M2
// parity flow family check used), extended with port-less pair keys for
// ICMP/ICMPv6 (tshark conversation granularity). Non-first IPv4 fragments
// carry no ports (the decoder would mis-read payload bytes as L4 headers),
// so TCP/UDP fragments are counted separately and reconciled in M3.3.
// Analysis never throws; problems accumulate in `warnings`.

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

export interface FlowEvent {
  frame: number; // EPB index in the trace
  ts: number; // capture seconds
  dirAtoB: boolean;
  frameLen: number; // wire length (origLen)
  tcpFlags?: number;
}

export interface ReassembledStream {
  base: number; // absolute seq of the first reassembled byte
  baseAssumed: boolean; // true when no SYN was observed (base = min data seq)
  segments: number; // disjoint reassembled pieces
  bytes: Buffer; // gaps appear as literal 0x00 runs (itemized below)
  gapCount: number;
  gapBytes: number;
  firstGaps: Array<{ start: number; len: number }>;
  retransSegs: number; // segments fully covered by earlier data
  retransBytes: number;
  partialRetransSegs: number; // segments partly covered by earlier data
  truncatedPayloads: number; // declared payload cut by the capture length
  overflowed: boolean;
}

export interface TcpStory {
  syn?: { frame: number; ts: number };
  synAck?: { frame: number; ts: number; deltaMs: number | null };
  ackAfterHandshake?: { frame: number; ts: number };
  finA2b?: { frame: number; ts: number };
  finB2a?: { frame: number; ts: number };
  rst?: { frame: number; ts: number };
  handshakeComplete: boolean; // SYN + SYN-ACK + a subsequent data/ACK seen
  flagsSeen: string[]; // distinct flag-combination labels, order of first sight
  dataSegs: number;
  a2b: ReassembledStream | null;
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
  bodyCaptured: number; // body bytes present in the reassembled stream
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
  a: { ip: string; port: number }; // canonical endpoint (port 0 for icmp)
  b: { ip: string; port: number };
  hosts: string[]; // DNS-attributed hostnames for either endpoint IP
  tlsSni: string[]; // unique SNI values from ClientHellos in this flow
  firstTs: number;
  lastTs: number;
  packets: { a2b: number; b2a: number }; // EPB counts (copies included)
  bytes: { a2b: number; b2a: number }; // wire-length sums (copies included)
  uniquePackets: number; // deduped
  uniqueDataPackets: number; // deduped with payload > 0
  uniqueRetransSegs: number; // deduped segments covering already-seen data
  events: FlowEvent[]; // EPB view
  tcp: TcpStory | null;
  http: HttpStory | null;
}

export interface FragmentStat {
  id: string; // e.g. "p6 10.0.0.1 <--> 1.2.3.4"
  count: number;
  bytes: number;
}

export interface FlowAnalysis {
  file: string;
  totalEpbs: number;
  duplicatesMerged: number; // EPBs merged as copies (M2 dedupe rule)
  flows: Flow[]; // sorted by firstTs
  nonFlowEpbs: number; // ARP / undecodable / blocks with no IP layer
  fragments: FragmentStat[]; // non-first IPv4 fragments (no ports to key on)
  dnsHostByIp: Array<{ ip: string; names: string[] }>; // from DNS answers
  retransSegsTotal: number;
  warnings: string[];
}

const MAX_STREAM_BYTES = 8 << 20; // 8 MiB per flow across both directions

// ------------------------------------------------------------- reassembly

interface SparsePiece {
  start: number; // byte index relative to stream base
  end: number; // exclusive
  data: Buffer;
}

class SparseStream {
  private pieces: SparsePiece[] = []; // disjoint, sorted
  totalBytes = 0;
  retransSegs = 0;
  retransBytes = 0;
  partialRetransSegs = 0;
  truncatedPayloads = 0;
  overflowed = false;

  /** Disjoint sub-ranges of [start,end) not covered yet. */
  private novelRanges(start: number, end: number): Array<[number, number]> {
    const out: Array<[number, number]> = [];
    let pos = start;
    for (const p of this.pieces) {
      if (p.end <= pos) continue;
      if (p.start >= end) break;
      if (p.start > pos) out.push([pos, Math.min(p.start, end)]);
      pos = Math.max(pos, p.end);
      if (pos >= end) break;
    }
    if (pos < end) out.push([pos, end]);
    return out;
  }

  private insert(start: number, data: Buffer): void {
    const piece: SparsePiece = { start, end: start + data.length, data };
    let i = 0;
    while (i < this.pieces.length && this.pieces[i].end <= start) i++;
    this.pieces.splice(i, 0, piece);
    this.totalBytes += data.length;
  }

  /** Add one wire segment; returns novel (non-duplicate) byte count. */
  add(start: number, data: Buffer): number {
    const len = data.length;
    if (len === 0 || this.overflowed) return 0;
    if (this.totalBytes + len > MAX_STREAM_BYTES) {
      this.overflowed = true;
      return 0;
    }
    let novel = 0;
    for (const [s, e] of this.novelRanges(start, start + len)) novel += e - s;
    if (novel === len) {
      this.insert(start, data);
      return novel;
    }
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

  /** Walk pieces in order, inserting zero runs for gaps. */
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
        if (firstGaps.length < 5) firstGaps.push({ start: base + cursor, len });
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

function flagsLabel(f: number): string {
  const parts: string[] = [];
  if (f & TCP_SYN) parts.push("SYN");
  if (f & TCP_FIN) parts.push("FIN");
  if (f & TCP_RST) parts.push("RST");
  if (f & TCP_PSH) parts.push("PSH");
  if (f & TCP_ACK) parts.push("ACK");
  return parts.length ? parts.join("+") : `0x${(f & 0xff).toString(16)}`;
}

// -------------------------------------------------------------- flow keys

interface KeyedFlow {
  key: string;
  kind: Flow["kind"];
  dirAtoB: boolean;
  a: { ip: string; port: number };
  b: { ip: string; port: number };
}

function flowKeyOf(p: DecodedPacket): KeyedFlow | null {
  const t = p.transport;
  const i = p.ip;
  if (!t || !i) return null;
  if (t.kind === "tcp" || t.kind === "udp") {
    if (t.sport === undefined || t.dport === undefined) return null;
    // Non-first fragments have no L4 header — the decoder would misread
    // payload bytes as header fields, so they cannot key by ports.
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
    // Pair key needs no ports — non-first fragments can join these flows.
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

function pairKeyForFragment(p: DecodedPacket): string | null {
  const i = p.ip;
  if (!i || i.fragment === undefined || i.fragment.offsetBytes === 0) return null;
  if (i.proto !== 6 && i.proto !== 17 && i.proto !== 1 && i.proto !== 58) return null;
  const aip = i.src <= i.dst ? i.src : i.dst;
  const bip = i.src <= i.dst ? i.dst : i.src;
  return `p${i.proto} ${aip} <--> ${bip}`;
}

// --------------------------------------------------------------- HTTP

const METHOD_RE = /^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|TRACE|CONNECT) /;

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

function headerOf(m: HttpMessage, name: string): string | undefined {
  return m.headers[name];
}

/**
 * Minimal HTTP/1.x message walker over one direction's reassembled stream.
 * Cap: 8 messages, 32 KiB per head. Chunked bodies are detected but not
 * de-chunked (recorded honestly as parsingStopped="chunked").
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
        m.headers[name] = m.headers[name] === undefined ? value : `${m.headers[name]}, ${value}`;
      }
    }
    m.chunked = (m.headers["transfer-encoding"] ?? "").includes("chunked");
    const clRaw = headerOf(m, "content-length");
    if (clRaw !== undefined) {
      const cl = parseInt(clRaw.split(",")[0].trim(), 10);
      if (!Number.isNaN(cl)) m.contentLength = cl;
    }
    const bodyStart = headEnd + 1;
    if (m.contentLength === undefined) {
      if (m.chunked) {
        // Chunked bodies detected but not de-chunked.
        m.bodyCaptured = Math.max(0, data.length - bodyStart);
        m.bodyComplete = false;
        messages.push(m);
        parsingStopped = "chunked";
        break;
      }
      if (isRequest) {
        // No content-length and not chunked: no body bytes are expected;
        // a pipelined request may follow.
        m.bodyCaptured = 0;
        m.bodyComplete = true;
        messages.push(m);
        pos = bodyStart;
        continue;
      }
      // Response without content-length: body runs to end of stream.
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
  if (messages.length >= 8 && pos < data.length) parsingStopped = "limit";
  if (messages.length === 0) return null;
  return {
    requests: isRequest ? messages : [],
    responses: isRequest ? [] : messages,
    parsingStopped,
  };
}

// ------------------------------------------------------------- DNS map

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

// ------------------------------------------------------------- analysis

interface UniqueEvent {
  p: DecodedPacket;
  ts: number;
  dirAtoB: boolean;
  frame: number;
  bytes: Buffer;
}

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
    if (story.flagsSeen[story.flagsSeen.length - 1] !== label) story.flagsSeen.push(label);

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
    if (flags & TCP_FIN) {
      if (ev.dirAtoB && !story.finA2b) story.finA2b = { frame: ev.frame, ts: ev.ts };
      else if (!ev.dirAtoB && !story.finB2a) story.finB2a = { frame: ev.frame, ts: ev.ts };
    }
    if (flags & TCP_RST && !story.rst) story.rst = { frame: ev.frame, ts: ev.ts };

    // Data segment collection (unique view).
    if (t.payloadLen > 0 && t.headerOff !== undefined && t.headerLen !== undefined) {
      const bodyStart = t.headerOff + t.headerLen;
      const avail = Math.max(0, ev.bytes.length - bodyStart);
      const data = ev.bytes.subarray(bodyStart, bodyStart + Math.min(t.payloadLen, avail));
      if (t.payloadLen > avail) streams[dir].truncatedPayloads++;
      segs[dir].push({ seq: t.seq ?? 0, data });
      story.dataSegs++;
    }
  }
  story.handshakeComplete = Boolean(
    story.syn && story.synAck && (story.ackAfterHandshake || (segs.a2b.length > 0 || segs.b2a.length > 0)),
  );

  for (const dir of ["a2b", "b2a"] as const) {
    const s = segs[dir];
    if (s.length === 0) continue;
    const base = Math.min(...s.map((x) => x.seq));
    for (const x of s) {
      let rel = x.seq - base;
      if (rel < -0x80000000) rel += 0x100000000; // seq wrapped since base
      if (rel >= 0) streams[dir].add(rel, x.data);
    }
    story[dir] = streams[dir].finalize(base, !story.syn);
  }
  return story;
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
  // The canonical endpoint order is lexical (ip+port string), so which side
  // held the CLIENT differs per flow — it is decided by CONTENT, not
  // position. Request buffers cannot be response buffers: the METHOD_RE gate
  // rejects lines starting "HTTP/" and the response gate rejects "GET ".
  // a2b-first preserves M3.3 behavior; the swapped orientation covers flows
  // where the server endpoint sorts canonically first (loopback traces).
  const http = attemptHttp(a2b.bytes, b2a.bytes) ?? attemptHttp(b2a.bytes, a2b.bytes);
  if (http) flow.http = http;
}

export function buildFlows(parsed: PcapngFile, fileName: string): FlowAnalysis {
  const warnings: string[] = [];
  const decoded = decodeAllPackets(parsed);
  const { groups, duplicatesMerged } = dedupePackets(parsed, decoded);

  // ---- EPB view -----------------------------------------------------
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

  // ---- Unique view --------------------------------------------------
  const perFlowUnique = new Map<string, UniqueEvent[]>();
  let retransTotal = 0;
  for (const g of groups) {
    const p = g.packet;
    const k = flowKeyOf(p);
    if (!k) continue;
    const f = flowMap.get(k.key);
    if (!f) continue;
    f.uniquePackets++;
    if ((p.transport?.payloadLen ?? 0) > 0) f.uniqueDataPackets++;
    if (p.tls?.sni && !f.tlsSni.includes(p.tls.sni)) f.tlsSni.push(p.tls.sni);
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

  // ---- DNS attribution + ordering -----------------------------------
  const dnsMap = buildDnsAttribution(decoded);
  const flows = [...flowMap.values()].sort(
    (x, y) => x.firstTs - y.firstTs || x.id.localeCompare(y.id),
  );
  for (const f of flows) {
    const names = new Set<string>();
    for (const ip of [f.a.ip, f.b.ip]) {
      for (const n of dnsMap.get(ip) ?? []) names.add(n);
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

export function analyzePcapFile(file: string): FlowAnalysis {
  const parsed = parsePcapng(fs.readFileSync(file));
  return buildFlows(parsed, file);
}

export function bytesLabel(n: number): string {
  if (n < 1024) return `${n}B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)}KB`;
  return `${(n / 1048576).toFixed(2)}MB`;
}
