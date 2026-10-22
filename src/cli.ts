// CLI entry. Node 24 runs .ts directly (type stripping), tsc only typechecks.

import { m1Capture } from "./m1Capture.ts";
import { m1Verify } from "./m1Verify.ts";
import { m1Pick } from "./m1Pick.ts";
import { runMilestoneBatch } from "./m2Run.ts";
import { coreScenarios, extendedScenarios, buildPlans } from "./scenarios.ts";
import { buildTrafficContext } from "./traffic.ts";
import { PktmonBackend } from "./pktmonBackend.ts";
import { analyzePcapFile, bytesLabel } from "./flows.ts";
import { verifyTrace } from "./m3Verify.ts";
import { scanAndReportAll, watchDirectory, printConsoleSummary } from "./watch.ts";
import { toJson, toCsv, toMarkdown } from "./export.ts";
import { runM4Loopback, printM4Loopback } from "./m4Loopback.ts";
import { runTestAll } from "./testAll.ts";
import fs from "node:fs";
import path from "node:path";

const OUT_DIR = path.resolve("out");
const SCEN_DIR = path.join(OUT_DIR, "scen");

async function main(): Promise<number> {
  const cmd = process.argv[2];
  switch (cmd) {
    case "m1-capture":
      return m1Capture();
    case "m1-verify":
      return m1Verify();
    case "m1-pick":
      return m1Pick();
    case "m2-core":
      await runMilestoneBatch("core");
      return 0;
    case "m2-ext":
      await runMilestoneBatch("ext");
      return 0;
    case "m2-plan": {
      const which = process.argv[3] === "ext" ? "ext" : "core";
      const ctx2 = await buildTrafficContext();
      const scen = which === "core" ? coreScenarios() : extendedScenarios();
      const be = new PktmonBackend(OUT_DIR, SCEN_DIR);
      const ps1 = be.buildBundleScript({ bundleId: `m2_${which}`, plans: buildPlans(scen, ctx2) });
      const file = path.join(SCEN_DIR, `m2_${which}.ps1`);
      fs.mkdirSync(SCEN_DIR, { recursive: true });
      fs.writeFileSync(file, ps1, "utf8");
      console.log(`bundle script written: ${file} (NOT executed)`);
      return 0;
    }
    case "m3-flows": {
      const traceFile = process.argv[3];
      if (!traceFile) {
        console.error("usage: m3-flows <trace.pcapng>");
        return 2;
      }
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
    case "m3-verify": {
      // Run the full M3.3 matrix and write test-results/milestone3-checks.md
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
    case "m4-report": {
      const dir = process.argv[3] ?? "out/scen";
      const reportDir = process.argv[4] ?? path.join("out", "m4-reports");
      const summaries = scanAndReportAll(dir, reportDir);
      printConsoleSummary(summaries);
      console.log(`dashboard: ${path.join(reportDir, "index.html")}`);
      return summaries.length > 0 ? 0 : 1;
    }
    case "m4-watch": {
      const dir = process.argv[3] ?? "out/scen";
      const reportDir = process.argv[4] ?? path.join("out", "m4-reports");
      const once = process.argv.includes("--once");
      const open = process.argv.includes("--open");
      await watchDirectory({ dir, reportDir, once, open });
      return 0;
    }
    case "m4-export": {
      const traceFile = process.argv[3];
      const fmt = (process.argv[4] ?? "json").toLowerCase();
      if (!traceFile) {
        console.error("usage: m4-export <trace.pcapng> [json|csv|md]");
        return 2;
      }
      if (!fs.existsSync(traceFile)) {
        console.error(`file not found: ${traceFile}`);
        return 1;
      }
      const a = analyzePcapFile(traceFile);
      const out_ =
        fmt === "json" ? toJson(a) : fmt === "csv" ? toCsv(a) : fmt === "md" ? toMarkdown(a) : null;
      if (out_ === null) {
        console.error(`unknown format: ${fmt} (use json|csv|md)`);
        return 2;
      }
      const base = path.basename(traceFile, path.extname(traceFile));
      const dest = path.join("out", "m4-reports", `${base}.${fmt === "md" ? "md" : fmt}`);
      fs.mkdirSync(path.dirname(dest), { recursive: true });
      fs.writeFileSync(dest, out_, "utf8");
      console.log(`wrote ${dest} (${out_.length} bytes)`);
      return 0;
    }
    case "m4-loopback": {
      const withTshark = process.argv.includes("--tshark");
      const dirFlagIdx = process.argv.indexOf("--dir");
      const outDir = dirFlagIdx >= 0 ? process.argv[dirFlagIdx + 1] : undefined;
      const { allOk, runs } = await runM4Loopback({ withTshark, outDir });
      for (const line of printM4Loopback(runs)) console.log(line);
      console.log(allOk ? "m4-loopback: ALL PASS" : "m4-loopback: FAILURES PRESENT");
      return allOk ? 0 : 1;
    }
    case "test-all": {
      const rs = await runTestAll();
      return rs.every((r) => r.ok) ? 0 : 1;
    }
    default:
      console.log("strobe-packet-tracker (Milestone 3 + M4 ergonomics)");
      console.log("");
      console.log("  m1-capture  elevated pktmon capture + PCAPNG export (one UAC prompt)");
      console.log("  m1-pick     select best per-component trace -> out/m1.pcapng");
      console.log("  m1-verify   cross-check out/m1.pcapng with tshark, frame by frame");
      console.log("  m2-core     Milestone 2 CORE scenario corpus (one UAC prompt, ~5 min)");
      console.log("  m2-ext      Milestone 2 EXTENDED scenarios (one UAC prompt)");
      console.log("  m3-flows    print per-flow stories for a PCAPNG trace");
      console.log("              usage: node src/cli.ts m3-flows <trace.pcapng>");
      console.log("  m3-verify   run the M3.3 full-matrix vs tshark → test-results/milestone3-checks.md");
      console.log("  m4-report   analyze a directory of traces -> HTML dashboard + per-trace reports");
      console.log("              usage: node src/cli.ts m4-report <dir> [reportDir]");
      console.log("  m4-watch    live-watch a directory, regenerate the dashboard on change");
      console.log("              usage: node src/cli.ts m4-watch <dir> [reportDir] [--once] [--open]");
      console.log("  m4-export   export a trace's flow analysis as json/csv/md");
      console.log("              usage: node src/cli.ts m4-export <trace.pcapng> [json|csv|md]");
      console.log("  m4-loopback M4-a userspace loopback tap: capture local scenarios + verify");
      console.log("              usage: node src/cli.ts m4-loopback [--tshark] [--dir <out>]");
      console.log("  test-all    run EVERY verification gate (tsc, tests, m1+, parity, m3 matrix, m4, m4a)");
      console.log("");
      return 2;
  }
}

main()
  .then((code) => process.exit(code))
  .catch((e) => {
    console.error(e);
    process.exit(1);
  });
