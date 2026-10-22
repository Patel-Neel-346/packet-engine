// CLI entry point. Node 24 runs .ts directly (type stripping); tsc only
// typechecks. This file is dispatch-only: argument handling plus delegation to
// the command implementations in their owning layers (capture/, verify/,
// reporting/, tap/) — see docs/ARCHITECTURE.md for the layer map.
//
// NOTE: several console strings below are load-bearing — `npm run test:all`
// (src/testAll.ts) parses output of the commands this dispatcher routes to
// (e.g. the `done: N/N fully pass` line from m3-verify). Do not reword them
// without updating the gates.
//
// Layer:     entry point — dispatch only (no command logic lives here)
// Milestone: spans M1–M4a (every npm script routes through this exact path)
// Verified:  all npm scripts + every `npm run test:all` gate exercise it
// Exports:   none (process entry)

import fs from "node:fs";
import path from "node:path";
import { m1Capture } from "./capture/m1Capture.ts";
import { m1Pick } from "./capture/m1Pick.ts";
import { runMilestoneBatch, writeM2Plan } from "./capture/m2Run.ts";
import { m1Verify } from "./verify/m1Verify.ts";
import { runM3Matrix } from "./verify/m3Matrix.ts";
import { printFlowStories } from "./reporting/flowStories.ts";
import { scanAndReportAll, watchDirectory, printConsoleSummary } from "./reporting/watch.ts";
import { toJson, toCsv, toMarkdown } from "./reporting/export.ts";
import { analyzePcapFile } from "./engine/flows.ts";
import { runM4Loopback, printM4Loopback } from "./tap/m4Loopback.ts";
import { runTestAll } from "./testAll.ts";

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
    case "m2-plan":
      return writeM2Plan(process.argv[3] === "ext" ? "ext" : "core");
    case "m3-flows": {
      const traceFile = process.argv[3];
      if (!traceFile) {
        console.error("usage: m3-flows <trace.pcapng>");
        return 2;
      }
      return printFlowStories(traceFile);
    }
    case "m3-verify":
      return runM3Matrix();
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
      console.log("  m2-plan     generate the M2 bundle script without running it (no UAC)");
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
