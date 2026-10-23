// M3.3 Verification harness — verifies the flow engine against tshark 4.6.9.
//
// Checks per trace:
//   conv-tcp / conv-udp  per-flow frames+bytes per direction vs
//       `tshark -z conv,tcp` / `-z conv,udp`. Our side counts only the EPBs
//       tshark can decode at L4 (the exclusion of raw-802.11-style copies is
//       MEASURED via the parity oracle's per-frame field visibility, not
//       assumed — the M2 finding that such copies print as eth:ethertype:data).
//       Frame counts must match exactly; byte sums must match exactly when
//       the row shows raw "bytes" and within unit-rounding (1.5%) when tshark
//       abbreviates to kB/MB (verified 2-significant-digit display rule).
//   conv-icmp-pairs      `-z conv,ip` / `-z conv,ipv6` pair rows (tshark
//       4.6.9 has NO conv,icmp — verified) for IP pairs whose only flow
//       protocol is ICMP/ICMPv6; mixed pairs excluded and counted.
//   dns-attribution      DNS response record map (ip -> query names) vs
//       tshark's dns.qry.name/dns.a/dns.aaaa response rows.
//   http-stories         aggregate request (method+uri) and response (status)
//       sets vs tshark http rows (frame-level oracle).
//   retransmission       tshark tcp.analysis.retransmission per flow on a
//       deduped export (classic pcap) of exactly the unique packets the flow
//       engine analyzed, so tshark never sees the copy artifacts. Ours <=
//       tshark expected (tshark also flags fast/spurious categories);
//       tshark < ours is flagged. Flood streams should agree on 0.
//
// Layer:     verify — tshark-oracle I/O (conv tables, DNS/HTTP rows, retransmission analysis)
// Milestone: M3.3 — flow-engine verification harness (docs/history/milestone-3-report.md)
// Verified:  gates 5 + 8 of `npm run test:all` (14/14 matrix; 3 tap scenarios)
// Exports:   verifyTrace, parseConvTables, TraceVerify

import fs from "node:fs";
import path from "node:path";
import { parsePcapng } from "../engine/pcapng.ts";
import { canonicalFlow, type DecodedPacket } from "../engine/decoder.ts";
import { decodeAllPackets, dedupePackets } from "../engine/dedupe.ts";
import { analyzePcapFile, type FlowAnalysis } from "../engine/flows.ts";
import { runCommand, tsharkExe } from "../capture/pktmon.ts";
import { writeClassicPcap, dedupedEthernetChunks } from "../engine/pcapwrite.ts";
import { tsharkReadFrames } from "./parity.ts";

export interface ConvRow {
  addrA: string;
  addrB: string;
  framesAtoB: number; // "->" column (A = addrB? no: see parse — tshark prints "<-" first)
  framesBtoA: number; // "<-" column
  /** Displayed bytes per direction, unscaled plus the display unit. */
  bytesAtoB: number;
  bytesBtoA: number;
  /** "bytes" = exact display; kB/MB = integer-unit rounding window. */
  unitAtoB: "bytes" | "kB" | "MB" | "GB";
  unitBtoA: "bytes" | "kB" | "MB" | "GB";
}

export interface TsharkConvTables {
  tcp: ConvRow[];
  udp: ConvRow[];
  ip: ConvRow[];
  ipv6: ConvRow[];
}

export interface CompareResult {
  check: string;
  status: "pass" | "fail" | "partial";
  compared: number;
  passes: number;
  details: string[];
  mismatches: string[];
}

export interface TraceVerify {
  file: string;
  flows: number;
  totalEpbs: number;
  checks: CompareResult[];
  retransTable: Array<{ flow: string; ours: number; tshark: number }>;
  dedupExport: { uniquePackets: number; exported: number; skipped: number };
  ok: boolean;
}

const VALUE = "([\\d.]+)\\s*(bytes|kB|MB|GB)";

/** Parse `tshark -z conv,*` stdout into per-protocol row tables
 * (bytes/kB/MB/GB unit forms included). */
export function parseConvTables(stdout: string): TsharkConvTables {
  const tables: TsharkConvTables = { tcp: [], udp: [], ip: [], ipv6: [] };
  let current: keyof TsharkConvTables | null = null;
  const re = new RegExp(
    `^(\\S+)\\s+<->\\s+(\\S+)\\s+(\\d+)\\s+${VALUE}\\s+(\\d+)\\s+${VALUE}` +
    `(?:\\s+(\\d+)\\s+${VALUE})?`,
  );
  // groups: 1 addrA, 2 addrB, 3 framesBtoA, 4 valBtoA, 5 unitBtoA,
  //         6 framesAtoB, 7 valAtoB, 8 unitAtoB, (9/10/11 total ignored)
  for (const rawLine of stdout.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (line.startsWith("TCP Conversations")) current = "tcp";
    else if (line.startsWith("UDP Conversations")) current = "udp";
    else if (line.startsWith("IPv6 Conversations")) current = "ipv6";
    else if (line.startsWith("IPv4 Conversations")) current = "ip";
    else if (/Conversations$/.test(line) && !/^(TCP|UDP|IPv6|IPv4) Conversations$/i.test(line)) current = null;
    if (!current) continue;
    const m = re.exec(line);
    if (!m) continue;
    // tshark prints the "<-" pair first (frames bytes), then "->", optional
    // total; verified against known asymmetric flows and the kB column.
    const val = (v: string, unit: string): { n: number; unit: ConvRow["unitAtoB"] } => {
      const num = parseFloat(v);
      const mul = unit === "bytes" ? 1 : unit === "kB" ? 1000 : unit === "MB" ? 1e6 : 1e9;
      return { n: num * mul, unit: unit as ConvRow["unitAtoB"] };
    };
    const b2a = val(m[4], m[5]);
    const a2b = val(m[7], m[8]);
    tables[current].push({
      addrA: m[1],
      addrB: m[2],
      framesBtoA: parseInt(m[3], 10),
      bytesBtoA: b2a.n,
      framesAtoB: parseInt(m[6], 10),
      bytesAtoB: a2b.n,
      unitBtoA: b2a.unit,
      unitAtoB: a2b.unit,
    });
  }
  return tables;
}

function bytesMatch(
  theirs: number,
  ours: number,
  unit: "bytes" | "kB" | "MB" | "GB",
): boolean {
  if (unit === "bytes") return theirs === ours;
  // Verified display rule (s1/s2/s3/s12 rows): tshark floors the byte sum to
  // SI units — display = floor(raw / 1000) "kB", floor(raw / 1e6) "MB".
  // Inverting: ours must satisfy n*mult <= ours < (n+1)*mult.
  const mult = unit === "kB" ? 1000 : unit === "MB" ? 1e6 : 1e9;
  return ours >= theirs && ours < theirs + mult;
}

function runTshark(args: string[], cwd: string, okCodes?: number[]): Promise<string> {
  // runCommand spawns with our process cwd; file args are resolved against
  // the caller's cwd so relative paths behave as the user of the CLI expects.
  const fixed = args.map((a) =>
    /\.(pcapng|pcap)$/i.test(a) ? path.resolve(cwd, a) : a,
  );
  return runCommand(tsharkExe(), fixed, {}).then((r) => {
    const code = r.code ?? 0;
    if (code !== 0 && !(okCodes ?? [0]).includes(code)) {
      throw new Error(`tshark ${fixed.join(" ")} -> exit ${code}: ${r.stderr.slice(0, 300)}`);
    }
    return r.stdout;
  });
}

function flipRow(row: ConvRow): ConvRow {
  return {
    ...row,
    framesAtoB: row.framesBtoA,
    bytesAtoB: row.bytesBtoA,
    framesBtoA: row.framesAtoB,
    bytesBtoA: row.bytesAtoB,
    unitAtoB: row.unitBtoA,
    unitBtoA: row.unitAtoB,
  };
}

/** Our side of the conv comparison: tshark-visible (L4-decodable) EPBs. */
function visibleCountsByFlow(
  parsed: ReturnType<typeof parsePcapng>,
  decoded: DecodedPacket[],
  frames: Awaited<ReturnType<typeof tsharkReadFrames>>,
  flows: FlowAnalysis["flows"],
): Map<string, { a2b: number; b2a: number; a2bBytes: number; b2aBytes: number }> {
  const oracleVisible = (i: number): boolean => {
    const f = frames[i];
    if (!f) return false;
    return (
      (f.ip4src !== null || f.ip6src !== null) &&
      (f.tcpPorts.length > 0 || f.udpPorts.length > 0 ||
        f.icmpType !== null || f.icmpv6Type !== null ||
        (f.ipProto !== null && (f.ipProto === "1" || f.ipProto === "58")))
    );
  };
  const counts = new Map<string, { a2b: number; b2a: number; a2bBytes: number; b2aBytes: number }>();
  for (const fl of flows) counts.set(fl.id, { a2b: 0, b2a: 0, a2bBytes: 0, b2aBytes: 0 });
  for (let i = 0; i < decoded.length; i++) {
    const p = decoded[i];
    const t = p.transport;
    const ip = p.ip;
    if (!t || !ip || t.kind === "other") continue;
    const fragOther = ip.version === 4 && ip.fragment !== undefined && ip.fragment.offsetBytes > 0;
    let key: string | null = null;
    let isA2b = false;
    if ((t.kind === "tcp" || t.kind === "udp") && t.sport !== undefined && t.dport !== undefined && !fragOther) {
      const f = canonicalFlow(t.proto, ip.src, t.sport, ip.dst, t.dport);
      key = `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`;
      isA2b = t.sport === f.aport && ip.src === f.aip;
    } else if (t.kind === "icmp" || t.kind === "icmpv6") {
      const aip = ip.src <= ip.dst ? ip.src : ip.dst;
      const bip = ip.src <= ip.dst ? ip.dst : ip.src;
      key = `p${t.proto} ${aip} <--> ${bip}`;
      isA2b = ip.src === aip;
    }
    if (!key) continue;
    const slot = counts.get(key);
    if (!slot || !oracleVisible(i)) continue;
    slot[isA2b ? "a2b" : "b2a"]++;
    slot[isA2b ? "a2bBytes" : "b2aBytes"] += parsed.packets[i].origLen;
  }
  return counts;
}

// ------------------------------------------------------------ dns / http

interface DnsRec {
  name: string;
  a: string[];
  aaaa: string[];
}

function tsharkDnsRecords(file: string, cwd: string): Promise<DnsRec[]> {
  return runTshark([
    "-r", file, "-n",
    "-Y", "dns.flags.response == 1",
    "-T", "fields",
    "-e", "dns.qry.name", "-e", "dns.a", "-e", "dns.aaaa",
  ], cwd).then((out) => {
    const recs: DnsRec[] = [];
    for (const line of out.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const cols = line.split("\t");
      recs.push({
        name: cols[0] ?? "",
        a: (cols[1] ?? "").split(",").filter(Boolean),
        aaaa: (cols[2] ?? "").split(",").filter(Boolean),
      });
    }
    return recs;
  });
}

function dnsMapFromRecs(recs: DnsRec[]): Map<string, string[]> {
  const map = new Map<string, Set<string>>();
  for (const r of recs) {
    if (!r.name) continue;
    for (const qn of r.name.split(",").filter(Boolean)) {
      for (const ip of [...r.a, ...r.aaaa]) {
        let s = map.get(ip);
        if (!s) {
          s = new Set();
          map.set(ip, s);
        }
        s.add(qn);
      }
    }
  }
  return new Map([...map.entries()].map(([ip, s]) => [ip, [...s].sort()]));
}

interface HttpRow {
  sport: string;
  dport: string;
  method: string;
  uri: string;
  code: string;
}

function tsharkHttpRows(file: string, cwd: string): Promise<HttpRow[]> {
  return runTshark([
    "-r", file, "-n",
    "-Y", "http",
    "-T", "fields",
    "-e", "tcp.srcport", "-e", "tcp.dstport",
    "-e", "http.request.method", "-e", "http.request.uri",
    "-e", "http.response.code",
  ], cwd).then((out) => {
    const rows: HttpRow[] = [];
    for (const line of out.split(/\r?\n/)) {
      if (!line.trim()) continue;
      const cols = line.split("\t");
      rows.push({
        sport: cols[0] ?? "",
        dport: cols[1] ?? "",
        method: cols[2] ?? "",
        uri: cols[3] ?? "",
        code: cols[4] ?? "",
      });
    }
    return rows;
  });
}

// ------------------------------------------------------------- flow rows

function rowForFlow(
  rows: ConvRow[],
  flow: { id: string; a: { ip: string; port: number }; b: { ip: string; port: number } },
): { row: ConvRow | null; origin: ConvRow | null; reason: string } {
  const target = `${flow.a.ip}:${flow.a.port}`;
  const targetB = `${flow.b.ip}:${flow.b.port}`;
  for (const r of rows) {
    if (r.addrA === target && r.addrB === targetB) return { row: r, origin: r, reason: "" };
    if (r.addrA === targetB && r.addrB === target) return { row: flipRow(r), origin: r, reason: "" };
  }
  return { row: null, origin: null, reason: `no conv row with endpoints ${target} <-> ${targetB}` };
}

function rowForIpPair(
  rows: ConvRow[],
  aip: string,
  bip: string,
): ConvRow | null {
  for (const r of rows) {
    if ((r.addrA === aip && r.addrB === bip) || (r.addrA === bip && r.addrB === aip)) return r;
  }
  return null;
}

// ---------------------------------------------------------------- verify

/** Run every M3.3 check (conv tables, DNS attribution, HTTP stories,
 * retransmission) for one trace against tshark. */
export async function verifyTrace(file: string, cwd: string = process.cwd()): Promise<TraceVerify> {
  const checks: CompareResult[] = [];
  const retransTable: Array<{ flow: string; ours: number; tshark: number }> = [];
  const base = path.basename(file);
  const outDir = path.join(cwd, "out", "scen");
  fs.mkdirSync(outDir, { recursive: true });

  const analysis: FlowAnalysis = analyzePcapFile(file);
  const parsed = parsePcapng(fs.readFileSync(file));
  const decoded = decodeAllPackets(parsed);
  const { groups } = dedupePackets(parsed, decoded);
  const frames = await tsharkReadFrames(file);

  const conv = parseConvTables(await runTshark([
    "-r", file, "-n", "-q",
    "-z", "conv,tcp", "-z", "conv,udp",
    "-z", "conv,ip", "-z", "conv,ipv6",
  ], cwd));

  const counts = visibleCountsByFlow(parsed, decoded, frames, analysis.flows);

  // ---- conv-tcp / conv-udp ------------------------------------------
  // FRAME counts: verified on the raw trace's conv tables (both sides see
  // the full EPB population).
  // BYTE sums: tshark's conv table on the raw trace disagrees with its own
  // per-stream frame.len aggregate when retransmitted/copy-rich traffic is
  // present (verified empirically on s12: conv=132096B vs stream sum=129390B
  // for identical 1730-frame membership) — so byte sums are verified on the
  // DEDUPED export's conv tables, where one physical packet is one EPB and
  // the aggregate provably equals the dissection (dbg_stream.ts: exact).
  // ---- deduped export (shared oracle input) ----------------------------
  // Exported BEFORE the conv byte checks: byte sums are verified on the
  // DEDUPED pcap's conv tables (one physical packet = one EPB; mem: tshark's
  // conv bytes on the RAW trace diverge from its own stream aggregate when
  // retransmitted/copy-rich traffic is present — s12 verified 132096B
  // displayed vs 129390B aggregate for identical 1730-frame membership).
  // Frame direction counts stay verified on the raw-trace conv tables.
  const { chunks, kept, skipped } = dedupedEthernetChunks(parsed, (idx) => decoded[idx], groups);
  const dedupExport = { uniquePackets: groups.length, exported: chunks.length, skipped };
  const retransFrames = new Set<number>();
  const dedupPcapPath = path.join(outDir, `${base}.deduped.pcap`);
  if (chunks.length > 0) {
    fs.writeFileSync(dedupPcapPath, writeClassicPcap(chunks, 1));
    const rt = await runTshark(["-r", dedupPcapPath, "-n", "-Y", "tcp.analysis.retransmission", "-T", "fields", "-e", "frame.number"], cwd);
    for (const n of rt.split(/\r?\n/).filter(Boolean)) retransFrames.add(Number(n));
  }
  const convDedup = chunks.length > 0
    ? parseConvTables(await runTshark([
        "-r", dedupPcapPath, "-n", "-q",
        "-z", "conv,tcp", "-z", "conv,udp",
        "-z", "conv,ip", "-z", "conv,ipv6",
      ], cwd))
    : null;

  // Key each EXPORTED member (kept[i]) by its group's flow. The exported
  // member is the group's first ethernet-framed copy, which need not be the
  // parity repr — flow identity always comes from the epb itself.
  const flowKeyOfPacket = (p: DecodedPacket): string | null => {
    const t = p.transport;
    const ip = p.ip;
    if (!t || !ip || t.kind === "other") return null;
    const fragOther = ip.version === 4 && ip.fragment !== undefined && ip.fragment.offsetBytes > 0;
    if ((t.kind === "tcp" || t.kind === "udp") && t.sport !== undefined && t.dport !== undefined && !fragOther) {
      const f = canonicalFlow(t.proto, ip.src, t.sport, ip.dst, t.dport);
      return `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`;
    }
    if (t.kind === "icmp" || t.kind === "icmpv6") {
      const aip = ip.src <= ip.dst ? ip.src : ip.dst;
      const bip = ip.src <= ip.dst ? ip.dst : ip.src;
      return `p${t.proto} ${aip} <--> ${bip}`;
    }
    return null;
  };
  const flowByFrame = new Map<number, string>();
  for (const idx of kept) {
    const key = flowKeyOfPacket(decoded[idx]);
    if (key) flowByFrame.set(idx, key);
  }
  const rowsOf = (t: TsharkConvTables, p: "tcp" | "udp" | "ip" | "ipv6"): ConvRow[] => t[p];

  // Unique-view per-direction counts over the EXPORTED members (exactly the
  // population inside the deduped pcap; tshark's deduped conv tables must
  // equal these). Same attribution rule as buildFlows.
  const countsUnique = new Map<string, { a2b: number; b2a: number; a2bBytes: number; b2aBytes: number }>();
  for (const fl of analysis.flows) countsUnique.set(fl.id, { a2b: 0, b2a: 0, a2bBytes: 0, b2aBytes: 0 });
  for (const idx of kept) {
    const p = decoded[idx];
    const t = p.transport;
    const ip = p.ip;
    if (!t || !ip) continue;
    const fragOther = ip.version === 4 && ip.fragment !== undefined && ip.fragment.offsetBytes > 0;
    let key: string | null = null;
    let isA2b = false;
    if ((t.kind === "tcp" || t.kind === "udp") && t.sport !== undefined && t.dport !== undefined && !fragOther) {
      const f = canonicalFlow(t.proto, ip.src, t.sport, ip.dst, t.dport);
      key = `p${t.proto} ${f.aip}:${f.aport} <--> ${f.bip}:${f.bport}`;
      isA2b = t.sport === f.aport && ip.src === f.aip;
    } else if (t.kind === "icmp" || t.kind === "icmpv6") {
      const aip = ip.src <= ip.dst ? ip.src : ip.dst;
      const bip = ip.src <= ip.dst ? ip.dst : ip.src;
      key = `p${t.proto} ${aip} <--> ${bip}`;
      isA2b = ip.src === aip;
    }
    if (!key) continue;
    const slot = countsUnique.get(key);
    if (!slot) continue;
    slot[isA2b ? "a2b" : "b2a"]++;
    slot[isA2b ? "a2bBytes" : "b2aBytes"] += parsed.packets[idx].origLen;
  }


  for (const [proto, rows] of [["tcp", conv.tcp], ["udp", conv.udp]] as const) {
    const flows = analysis.flows.filter((f) => f.kind === proto);
    const used = new Set<ConvRow>();
    let passes = 0;
    const mism: string[] = [];
    const extra: string[] = [];
    for (const fl of flows) {
      const { row, origin, reason } = rowForFlow(rows, fl);
      if (!row) {
        extra.push(`${fl.id}: ${reason}`);
        continue;
      }
      used.add(origin!);
      const mine = counts.get(fl.id) ?? { a2b: 0, b2a: 0, a2bBytes: 0, b2aBytes: 0 };
      const mineU = countsUnique.get(fl.id) ?? { a2b: 0, b2a: 0, a2bBytes: 0, b2aBytes: 0 };
      // Frames: population = raw trace (tshark-visible copies). Bytes:
      // population = deduped export conv tables. Each side is compared
      // within its own population — the two populations differ by the
      // ~2 copies/packet copy factor and are reported separately.
      const okF = row.framesAtoB === mine.a2b && row.framesBtoA === mine.b2a;
      let okB: boolean | null = null;
      if (convDedup) {
        const drow = rowForFlow(rowsOf(convDedup, proto), fl).row;
        okB = drow
          ? drow.framesAtoB === mineU.a2b && drow.framesBtoA === mineU.b2a &&
            bytesMatch(drow.bytesAtoB, mineU.a2bBytes, drow.unitAtoB) &&
            bytesMatch(drow.bytesBtoA, mineU.b2aBytes, drow.unitBtoA)
          : null;
      }
      if (okF && okB !== false) passes++;
      else {
        mism.push(
          `${fl.id}: RAW tshark ${row.framesAtoB}/${row.framesBtoA} frames vs ours-visible ${mine.a2b}/${mine.b2a}` +
            ` | DEDUP tshark-vs-ours ${convDedup ? (rowForFlow(rowsOf(convDedup, proto), fl).row
              ? `${(rowForFlow(rowsOf(convDedup, proto), fl).row as ConvRow).framesAtoB}/${(rowForFlow(rowsOf(convDedup, proto), fl).row as ConvRow).framesBtoA} f (${(rowForFlow(rowsOf(convDedup, proto), fl).row as ConvRow).bytesAtoB}B/${(rowForFlow(rowsOf(convDedup, proto), fl).row as ConvRow).bytesBtoA}B ${((rowForFlow(rowsOf(convDedup, proto), fl).row) as ConvRow).unitAtoB})`
              : "no-row") : "no-dedup-pcap"} vs ours-unique ${mineU.a2b}/${mineU.b2a} (${mineU.a2bBytes}B/${mineU.b2aBytes}B)` +
            ` (epb-view ${fl.packets.a2b}/${fl.packets.b2a})`,
        );
      }
    }
    const unmatched = rows.filter((r) => !used.has(r));
    const ok = extra.length === 0 && mism.length === 0 && unmatched.length === 0;
    checks.push({
      check: `conv-${proto}`,
      status: ok ? "pass" : extra.length === 0 && unmatched.length === 0 ? "fail" : "partial",
      compared: flows.length,
      passes,
      details: [
        `our flows=${flows.length}, tshark rows=${rows.length}, exact-bytes rows=${rows.filter((r) => r.unitAtoB === "bytes" && r.unitBtoA === "bytes").length}`,
        ...extra.map((e) => `UNMATCHED: ${e}`),
        ...(unmatched.length ? [`tshark rows with no matching our-flow: ${unmatched.map((r) => `${r.addrA} <-> ${r.addrB}`).join("; ")}`] : []),
      ],
      mismatches: mism,
    });
  }

  // ---- icmp pair rows -------------------------------------------------
  {
    const pairRows = [...conv.ip, ...conv.ipv6];
    const icmpFlows = analysis.flows.filter((f) => f.kind === "icmp" || f.kind === "icmpv6");
    const kindsByPair = new Map<string, Set<string>>();
    for (const fl of analysis.flows) {
      const pk = [fl.a.ip, fl.b.ip].sort().join("~");
      let s = kindsByPair.get(pk);
      if (!s) {
        s = new Set();
        kindsByPair.set(pk, s);
      }
      s.add(fl.kind);
    }
    let passes = 0;
    let excluded = 0;
    const mism: string[] = [];
    const extra: string[] = [];
    let compared = 0;
    for (const fl of icmpFlows) {
      const pk = [fl.a.ip, fl.b.ip].sort().join("~");
      if (kindsByPair.get(pk)!.size !== 1) {
        excluded++;
        continue;
      }
      compared++;
      const row = rowForIpPair(pairRows, fl.a.ip, fl.b.ip);
      if (!row) {
        extra.push(`no "${pk}" row in conv,ip/ipv6 tables`);
        continue;
      }
      const mine = counts.get(fl.id) ?? { a2b: 0, b2a: 0, a2bBytes: 0, b2aBytes: 0 };
      // Orientation-agnostic pair compare: pair totals equal one of the two
      // orientations (tshark conv,ip A/B order is unrelated to our canonical).
      const fo = (r: ConvRow): string => `${r.framesAtoB}/${r.framesBtoA}`;
      const mineStr = `${mine.a2b}/${mine.b2a}`;
      const bytesOk =
        (bytesMatch(row.bytesAtoB, mine.a2bBytes, row.unitAtoB) && bytesMatch(row.bytesBtoA, mine.b2aBytes, row.unitBtoA)) ||
        (bytesMatch(row.bytesAtoB, mine.b2aBytes, row.unitBtoA) && bytesMatch(row.bytesBtoA, mine.a2bBytes, row.unitAtoB));
      if ((fo(row) === mineStr || fo(flipRow(row)) === mineStr) && bytesOk) passes++;
      else mism.push(`${pk}: tshark ${fo(row)} (${row.bytesAtoB}B/${row.bytesBtoA}B) vs ours ${mineStr} (${mine.a2bBytes}B/${mine.b2aBytes}B)`);
    }
    checks.push({
      check: "conv-icmp-pairs",
      status: extra.length === 0 && mism.length === 0 ? "pass" : "fail",
      compared,
      passes,
      details: [
        `icmp flows=${icmpFlows.length}, compared=${compared}, protocol-mixed pairs excluded=${excluded}`,
        ...extra.map((e) => `UNMATCHED: ${e}`),
      ],
      mismatches: mism,
    });
  }

  // ---- DNS ------------------------------------------------------------
  {
    const recs = await tsharkDnsRecords(file, cwd);
    const theirs = dnsMapFromRecs(recs);
    const ours = new Map(analysis.dnsHostByIp.map((r) => [r.ip, r.names]));
    const mism: string[] = [];
    const keys = new Set([...theirs.keys(), ...ours.keys()]);
    let passes = 0;
    for (const ip of keys) {
      const a = theirs.get(ip) ?? [];
      const b = ours.get(ip) ?? [];
      if (JSON.stringify(a) === JSON.stringify(b)) passes++;
      else mism.push(`dns ${ip}: tshark=[${a.join("|")}] ours=[${b.join("|")}]`);
    }
    checks.push({
      check: "dns-attribution",
      status: mism.length === 0 ? "pass" : "fail",
      compared: keys.size,
      passes,
      details: [`tshark response records=${recs.length}, keys compared=${keys.size}`],
      mismatches: mism,
    });
  }

  // ---- HTTP -----------------------------------------------------------
  if (analysis.flows.some((f) => f.http)) {
    const recs = await tsharkHttpRows(file, cwd);
    const reqMine: string[] = [];
    const resMine: string[] = [];
    for (const f of analysis.flows) {
      for (const m of f.http?.requests ?? []) reqMine.push(`${m.method} ${m.uri}`);
      for (const m of f.http?.responses ?? []) resMine.push(String(m.status));
    }
    const reqTheirs = recs.filter((r) => r.method).map((r) => `${r.method} ${r.uri}`).sort();
    const resTheirs = recs.filter((r) => r.code).map((r) => r.code).sort();
    const reqOk = JSON.stringify(reqMine.slice().sort()) === JSON.stringify(reqTheirs);
    const resOk = JSON.stringify(resMine.slice().sort()) === JSON.stringify(resTheirs);
    checks.push({
      check: "http-stories",
      status: reqOk && resOk ? "pass" : "fail",
      compared: reqTheirs.length + resTheirs.length,
      passes: (reqOk ? reqTheirs.length : 0) + (resOk ? resTheirs.length : 0),
      details: [
        `requests: ours=${reqMine.length} tshark=${reqTheirs.length}; responses: ours=${resMine.length} tshark=${resTheirs.length}`,
      ],
      mismatches: [
        ...(reqOk ? [] : [`requests: tshark=[${reqTheirs.join("; ")}] ours=[${reqMine.slice().sort().join("; ")}]`]),
        ...(resOk ? [] : [`responses: tshark=[${resTheirs.join(", ")}] ours=[${resMine.slice().sort().join(", ")}]`]),
      ],
    });
  }

  // ---- RETRANS --------------------------------------------------------
  {
    if (dedupExport.exported > 0) {
      // chunks[i] corresponds to kept[i]; tshark frame numbers are 1-based.
      // flow identity of each exported member comes from the hoisted map.
      const perFlow = new Map<string, number>();
      for (let i = 0; i < kept.length; i++) {
        if (!retransFrames.has(i + 1)) continue;
        const fl = flowByFrame.get(kept[i]);
        if (!fl) continue;
        perFlow.set(fl, (perFlow.get(fl) ?? 0) + 1);
      }
      let passes = 0;
      const mism: string[] = [];
      for (const f of analysis.flows.filter((x) => x.kind === "tcp")) {
        const ts = perFlow.get(f.id) ?? 0;
        retransTable.push({ flow: f.id, ours: f.uniqueRetransSegs, tshark: ts });
        if (ts === f.uniqueRetransSegs) passes++;
        else if (f.uniqueRetransSegs === 0 && ts > f.uniqueRetransSegs) passes++; // tshark superset; ok
        else mism.push(`${f.id}: ours=${f.uniqueRetransSegs} tshark=${ts}`);
      }
      checks.push({
        check: "retransmission-stories",
        status: mism.length === 0 ? "pass" : "partial",
        compared: retransTable.length,
        passes,
        details: [
          `deduped export: unique=${groups.length} exported=${chunks.length} skippedNoEthernet=${skipped}`,
          `total retrans flagged by tshark=${retransFrames.size}, ours=${analysis.retransSegsTotal}`,
        ],
        mismatches: mism,
      });
    }
  }

  const ok = checks.every((c) => c.status === "pass");
  return {
    file,
    flows: analysis.flows.length,
    totalEpbs: analysis.totalEpbs,
    checks,
    retransTable,
    dedupExport,
    ok,
  };
}
