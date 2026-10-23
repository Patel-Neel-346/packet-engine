// M4-c: Export layer — serializes FlowAnalysis to JSON, CSV, or Markdown.
// Pure TypeScript, no dependencies, no I/O — caller decides where to write.
//
// Layer:     reporting — pure serializers (strings out; no I/O)
// Milestone: M4c — export formats (docs/project-status.md)
// Verified:  gate 7 of `npm run test:all` (json/csv/md files written + size-checked)
// Exports:   toJson, toCsv, toMarkdown

import type { FlowAnalysis, Flow } from "../engine/flows.ts";
import { bytesLabel } from "../engine/flows.ts";

// ─── JSON ────────────────────────────────────────────────────────────────────

/** Serialise a FlowAnalysis to JSON.
 * `events` arrays (potentially thousands of items per flow) are omitted by
 * default to keep the output readable; pass `includeEvents: true` for the
 * full packet timeline. The reassembled stream `bytes` Buffer is represented
 * as its length in bytes. */
export function toJson(a: FlowAnalysis, includeEvents = false): string {
  const flows = a.flows.map((f) => serializeFlow(f, includeEvents));
  return JSON.stringify(
    {
      file: a.file,
      capturedAt: new Date().toISOString(),
      totalEpbs: a.totalEpbs,
      duplicatesMerged: a.duplicatesMerged,
      uniquePackets: a.flows.reduce((s, f) => s + f.uniquePackets, 0),
      nonFlowEpbs: a.nonFlowEpbs,
      retransSegsTotal: a.retransSegsTotal,
      flows,
      fragments: a.fragments,
      dnsHostByIp: a.dnsHostByIp,
      warnings: a.warnings,
    },
    null,
    2,
  );
}

function serializeFlow(f: Flow, includeEvents: boolean): Record<string, unknown> {
  const base: Record<string, unknown> = {
    id: f.id,
    kind: f.kind,
    proto: f.proto,
    a: f.a,
    b: f.b,
    hosts: f.hosts,
    tlsSni: f.tlsSni,
    firstTs: f.firstTs,
    lastTs: f.lastTs,
    durationMs: Math.round((f.lastTs - f.firstTs) * 1000),
    packets: f.packets,
    bytes: f.bytes,
    uniquePackets: f.uniquePackets,
    uniqueDataPackets: f.uniqueDataPackets,
    uniqueRetransSegs: f.uniqueRetransSegs,
  };
  if (includeEvents) base.events = f.events;
  if (f.tcp) {
    const t = f.tcp;
    base.tcp = {
      handshakeComplete: t.handshakeComplete,
      flagsSeen: t.flagsSeen,
      dataSegs: t.dataSegs,
      synTs: t.syn?.ts ?? null,
      synAckDeltaMs: t.synAck?.deltaMs ?? null,
      rst: !!t.rst,
      finA2b: !!t.finA2b,
      finB2a: !!t.finB2a,
      a2b: streamSummary(t.a2b),
      b2a: streamSummary(t.b2a),
    };
  }
  if (f.http) {
    base.http = {
      requests: f.http.requests.map((r) => ({
        method: r.method,
        uri: r.uri,
        version: r.version,
        contentLength: r.contentLength ?? null,
        bodyComplete: r.bodyComplete,
      })),
      responses: f.http.responses.map((r) => ({
        status: r.status,
        contentLength: r.contentLength ?? null,
        chunked: r.chunked,
        bodyComplete: r.bodyComplete,
      })),
      parsingStopped: f.http.parsingStopped,
    };
  }
  return base;
}

function streamSummary(
  s: Flow["tcp"] extends null
    ? never
    : NonNullable<Flow["tcp"]>["a2b"] | NonNullable<Flow["tcp"]>["b2a"],
): Record<string, unknown> | null {
  if (!s) return null;
  return {
    segments: s.segments,
    bytes: s.bytes.length,
    gapCount: s.gapCount,
    gapBytes: s.gapBytes,
    retransSegs: s.retransSegs,
    retransBytes: s.retransBytes,
    partialRetransSegs: s.partialRetransSegs,
    truncatedPayloads: s.truncatedPayloads,
    baseAssumed: s.baseAssumed,
    overflowed: s.overflowed,
  };
}

// ─── CSV ────────────────────────────────────────────────────────────────────

const CSV_HEADER = [
  "id",
  "kind",
  "proto",
  "aIp",
  "aPort",
  "bIp",
  "bPort",
  "hosts",
  "tlsSni",
  "firstTs",
  "lastTs",
  "durationMs",
  "pktsA2b",
  "pktsB2a",
  "bytesA2b",
  "bytesB2a",
  "uniquePkts",
  "uniqueDataPkts",
  "uniqueRetransSegs",
  "tcpHandshake",
  "tcpSynAckMs",
  "tcpRst",
  "httpMethods",
  "httpStatuses",
].join(",");

function csvField(v: string | number | boolean | null | undefined): string {
  if (v == null) return "";
  const s = String(v);
  if (s.includes(",") || s.includes('"') || s.includes("\n")) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

/** Serialise a FlowAnalysis to CSV — one row per flow. */
export function toCsv(a: FlowAnalysis): string {
  const rows = [CSV_HEADER];
  for (const f of a.flows) {
    const t = f.tcp;
    rows.push(
      [
        csvField(f.id),
        csvField(f.kind),
        csvField(f.proto),
        csvField(f.a.ip),
        csvField(f.a.port),
        csvField(f.b.ip),
        csvField(f.b.port),
        csvField(f.hosts.join(";")),
        csvField(f.tlsSni.join(";")),
        csvField(f.firstTs.toFixed(6)),
        csvField(f.lastTs.toFixed(6)),
        csvField(Math.round((f.lastTs - f.firstTs) * 1000)),
        csvField(f.packets.a2b),
        csvField(f.packets.b2a),
        csvField(f.bytes.a2b),
        csvField(f.bytes.b2a),
        csvField(f.uniquePackets),
        csvField(f.uniqueDataPackets),
        csvField(f.uniqueRetransSegs),
        csvField(t ? t.handshakeComplete : ""),
        csvField(t?.synAck?.deltaMs?.toFixed(1) ?? ""),
        csvField(t ? !!t.rst : ""),
        csvField(f.http?.requests.map((r) => r.method).join(";") ?? ""),
        csvField(f.http?.responses.map((r) => r.status).join(";") ?? ""),
      ].join(","),
    );
  }
  return rows.join("\r\n") + "\r\n";
}

// ─── Markdown ────────────────────────────────────────────────────────────────

/** Serialise a FlowAnalysis to a Markdown report (human-readable). */
export function toMarkdown(a: FlowAnalysis): string {
  const lines: string[] = [];
  const ts = new Date().toISOString();
  lines.push(`# Flow report: ${a.file}`);
  lines.push(`_Generated ${ts}_`);
  lines.push("");
  lines.push(`## Summary`);
  lines.push("");
  lines.push(`| | Value |`);
  lines.push(`|---|---|`);
  lines.push(`| Total EPBs (all copies) | ${a.totalEpbs} |`);
  lines.push(`| Duplicates merged | ${a.duplicatesMerged} |`);
  lines.push(`| Unique packets | ${a.flows.reduce((s, f) => s + f.uniquePackets, 0)} |`);
  lines.push(`| Flows | ${a.flows.length} |`);
  lines.push(`| Non-flow EPBs (ARP/etc.) | ${a.nonFlowEpbs} |`);
  lines.push(`| Fragment groups | ${a.fragments.length} |`);
  lines.push(`| Total retrans segs | ${a.retransSegsTotal} |`);
  if (a.warnings.length) lines.push(`| Warnings | ${a.warnings.join("; ")} |`);
  lines.push("");

  if (a.dnsHostByIp.length) {
    lines.push(`## DNS attribution`);
    lines.push("");
    lines.push(`| IP | Hostnames |`);
    lines.push(`|---|---|`);
    for (const r of a.dnsHostByIp) lines.push(`| \`${r.ip}\` | ${r.names.join(", ")} |`);
    lines.push("");
  }

  lines.push(`## Flows`);
  lines.push("");
  lines.push(`| # | Flow | Kind | Hosts / SNI | Pkts↑↓ | Bytes↑↓ | Uniq | Duration |`);
  lines.push(`|---|---|---|---|---|---|---|---|`);
  for (let i = 0; i < a.flows.length; i++) {
    const f = a.flows[i]!;
    const label = f.hosts.length
      ? f.hosts.join(",")
      : f.tlsSni.length
        ? `sni:${f.tlsSni.join(",")}`
        : "—";
    const durMs = Math.round((f.lastTs - f.firstTs) * 1000);
    lines.push(
      `| ${i + 1} | \`${f.id}\` | ${f.kind} | ${label} | ${f.packets.a2b}/${f.packets.b2a} | ${bytesLabel(f.bytes.a2b)}/${bytesLabel(f.bytes.b2a)} | ${f.uniquePackets} | ${durMs} ms |`,
    );
  }
  lines.push("");

  for (let i = 0; i < a.flows.length; i++) {
    const f = a.flows[i]!;
    if (!f.tcp && !f.http) continue;
    lines.push(`### Flow ${i + 1}: \`${f.id}\``);
    lines.push("");
    if (f.tcp) {
      const t = f.tcp;
      lines.push(
        `**TCP lifecycle**: ${t.handshakeComplete ? "handshake complete" : "no full handshake"}`,
      );
      if (t.syn)
        lines.push(
          `- SYN at t=${t.syn.ts.toFixed(3)}s${t.synAck ? `, SYN-ACK Δ=${t.synAck.deltaMs?.toFixed(1)} ms` : ""}`,
        );
      if (t.rst) lines.push(`- RST at t=${t.rst.ts.toFixed(3)}s`);
      if (t.finA2b || t.finB2a) lines.push(`- FIN: a→b=${!!t.finA2b}, b→a=${!!t.finB2a}`);
      lines.push(`- Flags seen: ${t.flagsSeen.slice(0, 8).join(" → ")}`);
      for (const dir of ["a2b", "b2a"] as const) {
        const s = t[dir];
        if (!s || s.segments === 0) continue;
        lines.push(
          `- **${dir}**: ${s.segments} segs, ${bytesLabel(s.bytes.length)} reassembled` +
            (s.gapCount ? `, **${s.gapCount} gap(s) ${s.gapBytes}B**` : ", 0 gaps") +
            (s.retransSegs ? `, ${s.retransSegs} retrans (${bytesLabel(s.retransBytes)})` : "") +
            (s.baseAssumed ? " *(base assumed)*" : ""),
        );
      }
      lines.push("");
    }
    if (f.http) {
      lines.push(`**HTTP** (parsingStopped: \`${f.http.parsingStopped}\`)`);
      lines.push("");
      lines.push(`| Dir | Method | URI | Status | Len | Complete |`);
      lines.push(`|---|---|---|---|---|---|`);
      for (const r of f.http.requests)
        lines.push(
          `| → | \`${r.method}\` | \`${r.uri}\` | — | ${r.contentLength ?? "—"} | ${r.bodyComplete} |`,
        );
      for (const r of f.http.responses)
        lines.push(`| ← | — | — | ${r.status} | ${r.contentLength ?? "—"} | ${r.bodyComplete} |`);
      lines.push("");
    }
  }

  if (a.fragments.length) {
    lines.push(`## IPv4 fragment groups`);
    lines.push("");
    for (const fr of a.fragments)
      lines.push(`- \`${fr.id}\`: ${fr.count} fragments, ${bytesLabel(fr.bytes)}`);
    lines.push("");
  }

  return lines.join("\n");
}
