// M3.3 full verification matrix: runs verifyTrace() over every trace in the
// captured corpus and writes the per-trace per-check report
// (test-results/milestone3-checks.md) plus machine-readable results
// (out/scen/m3_results.json). Exit 0 only when every trace fully passes.
// Console strings are load-bearing: `npm run test:all` gate 5 parses the
// `done: N/N fully pass` summary line.
//
// Layer:     verify — matrix orchestration (drives verifyTrace over the corpus)
// Milestone: M3.3 — full-corpus matrix (docs/history/milestone-3-report.md)
// Verified:  gate 5 of `npm run test:all` — 14/14 traces fully pass
// Exports:   runM3Matrix

import fs from "node:fs";
import path from "node:path";
import { verifyTrace } from "./m3Verify.ts";
import { OUT_DIR, SCEN_DIR } from "../paths.ts";

/** The standing corpus: baseline + every M2 scenario trace, in matrix order. */
const ALL_TRACES: Array<[string, string]> = [
  ["m1_baseline", path.join(OUT_DIR, "m1.pcapng")],
  ["s1_https", path.join(SCEN_DIR, "s1_https_all.pcapng")],
  ["s2_http_external", path.join(SCEN_DIR, "s2_http_external_all.pcapng")],
  ["s3_dns", path.join(SCEN_DIR, "s3_dns_all.pcapng")],
  ["s4_large", path.join(SCEN_DIR, "s4_large_all.pcapng")],
  ["s5_tcp_lifecycle", path.join(SCEN_DIR, "s5_tcp_lifecycle_all.pcapng")],
  ["s6_v4v6", path.join(SCEN_DIR, "s6_v4v6_all.pcapng")],
  ["s7_parallel", path.join(SCEN_DIR, "s7_parallel_all.pcapng")],
  ["s8_icmp", path.join(SCEN_DIR, "s8_icmp_all.pcapng")],
  ["s15_tlshello", path.join(SCEN_DIR, "s15_tlshello_all.pcapng")],
  ["s9_quic", path.join(SCEN_DIR, "s9_quic_all.pcapng")],
  ["s10_arpdhcp", path.join(SCEN_DIR, "s10_arpdhcp_all.pcapng")],
  ["s12_retrans", path.join(SCEN_DIR, "s12_retrans_all.pcapng")],
  ["s14_burst", path.join(SCEN_DIR, "s14_burst_all.pcapng")],
];

/** Verify every trace in the corpus and write test-results/milestone3-checks.md
 * + out/scen/m3_results.json. Exit 0 only when every trace fully passes. */
export async function runM3Matrix(): Promise<number> {
  const md: string[] = [
    "# Milestone 3.3 — flow-engine verification vs tshark 4.6.9",
    "",
    "Per trace: frame-direction counts on the raw-trace conv tables; byte",
    "sums on the deduped-export conv tables; DNS record map, HTTP story",
    "aggregates, and per-flow retransmission counts (deduped export).",
    "",
  ];
  const jsonOut: unknown[] = [];
  let fullPass = 0;
  let withFindings = 0;
  for (const [id, traceFile] of ALL_TRACES) {
    if (!fs.existsSync(traceFile)) {
      md.push(`## ${id}`, "", `MISSING file ${traceFile} — skipped`, "");
      continue;
    }
    process.stdout.write(`verifying ${id}... `);
    const t = await verifyTrace(traceFile, process.cwd());
    jsonOut.push(t);
    process.stdout.write(`ok=${t.ok}\n`);
    md.push(
      `## ${id} — ${t.ok ? "ALL PASS" : "findings"}`,
      "",
      `- flows=${t.flows}, EPBs=${t.totalEpbs}, dedup export: unique=${t.dedupExport.uniquePackets} exported=${t.dedupExport.exported} skippedNoEthernet=${t.dedupExport.skipped}`,
      "",
      "| check | status | passes |",
      "|---|---|---|",
    );
    for (const c of t.checks) {
      md.push(`| ${c.check} | ${c.status.toUpperCase()} | ${c.passes}/${c.compared} |`);
      for (const d of c.details) md.push(`> detail: ${d}`);
      for (const m of c.mismatches) md.push(`> mismatch: ${m}`);
    }
    md.push("");
    if (t.ok) fullPass++; else withFindings++;
    fs.writeFileSync(
      path.join(SCEN_DIR, "m3_results.json"),
      JSON.stringify(jsonOut, null, 2),
    );
  }
  md.push("---", "", `**Summary: ${fullPass}/${ALL_TRACES.length} traces fully pass; ${withFindings} with findings.**`);
  fs.mkdirSync("test-results", { recursive: true });
  fs.writeFileSync("test-results/milestone3-checks.md", md.join("\n"));
  console.log(`\ndone: ${fullPass}/${ALL_TRACES.length} fully pass → test-results/milestone3-checks.md`);
  return fullPass === ALL_TRACES.length ? 0 : 1;
}
