// m3-flows console printer: renders the FlowEngine's per-flow "stories" for a
// single PCAPNG trace to stdout — flow list, DNS attribution, fragments, TCP
// lifecycle/reassembly lines, and HTTP message summaries. Pure printing: all
// analysis happens in engine/flows.ts.
//
// Layer:     reporting — console printer (reads one trace; stdout only)
// Milestone: M3 — m3-flows printer, extracted verbatim from cli.ts (docs/history/milestone-3-report.md)
// Verified:  output compared before/after the extraction (baseline-identical smoke run)
// Exports:   printFlowStories

import fs from "node:fs";
import { analyzePcapFile, bytesLabel } from "../engine/flows.ts";

/** Print the flow stories for one trace; returns a process exit code. */
export function printFlowStories(traceFile: string): number {
  if (!fs.existsSync(traceFile)) {
    console.error(`file not found: ${traceFile}`);
    return 1;
  }
  const a = analyzePcapFile(traceFile);
  console.log(
    `file=${a.file} epbs=${a.totalEpbs} dupsMerged=${a.duplicatesMerged} flows=${a.flows.length} nonFlow=${a.nonFlowEpbs} frags=${a.fragments.length} retransSegs=${a.retransSegsTotal}`,
  );
  console.log(`dns names: ${a.dnsHostByIp.length}`);
  for (const rec of a.dnsHostByIp.slice(0, 12))
    console.log(`  ${rec.ip} <- ${rec.names.join(", ")}`);
  if (a.fragments.length)
    console.log(`fragments: ${a.fragments.map((f) => `${f.id} x${f.count}`).join(", ")}`);
  console.log("flows:");
  for (let i = 0; i < a.flows.length; i++) {
    const f = a.flows[i];
    const line =
      `${String(i + 1).padStart(3)}. ${f.id}` +
      (f.hosts.length ? ` [${f.hosts.join(",")}]` : "") +
      (f.tlsSni.length ? ` sni=${f.tlsSni.join(",")}` : "") +
      ` pkts=${f.packets.a2b}/${f.packets.b2a}` +
      ` bytes=${bytesLabel(f.bytes.a2b)}/${bytesLabel(f.bytes.b2a)}` +
      ` uniq=${f.uniquePackets} data=${f.uniqueDataPackets}`;
    console.log(line);
    if (f.tcp) {
      const t = f.tcp;
      const hs = t.syn
        ? `syn+t=${t.synAck ? t.synAck.deltaMs?.toFixed(1) : "?"}ms`
        : "no-syn";
      const flags = t.flagsSeen.slice(0, 6).join(",");
      for (const dir of ["a2b", "b2a"] as const) {
        const s = t[dir];
        if (s && s.segments > 0) {
          console.log(
            `      ${dir}: segments=${s.segments} bytes=${s.bytes.length}` +
              (s.gapCount ? ` gaps=${s.gapCount}(${s.gapBytes}B)` : " gaps=0") +
              ` retrans=${s.retransSegs}(${s.retransBytes}B)` +
              (s.partialRetransSegs ? ` partial=${s.partialRetransSegs}` : "") +
              (s.truncatedPayloads ? ` trunc=${s.truncatedPayloads}` : "") +
              (s.baseAssumed ? " [base-assumed]" : "") +
              ` flagsTail=${flags} ${hs}${t.rst ? " RST" : ""}${t.finA2b || t.finB2a ? " FIN" : ""}`,
          );
        }
      }
      if (f.http) {
        for (const m of f.http.requests)
          console.log(`      http req: ${m.method} ${m.uri} ${m.version} clen=${m.contentLength ?? "-"} complete=${m.bodyComplete}`);
        for (const m of f.http.responses)
          console.log(`      http res: ${m.status} ${m.statusText} clen=${m.contentLength ?? "-"} bodyCaptured=${m.bodyCaptured} complete=${m.bodyComplete}`);
      }
    }
  }
  if (a.warnings.length) console.log(`warnings: ${a.warnings.join(" | ")}`);
  return 0;
}
