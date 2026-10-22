// M4-c: Watch mode and batch reporting.
// Scans a directory for .pcapng files, runs FlowAnalysis, generates HTML reports
// and an aggregate index dashboard, with support for live polling/watching.

import fs from "node:fs";
import path from "node:path";
import { exec } from "node:child_process";
import { analyzePcapFile, bytesLabel } from "./flows.ts";
import { generateHtml } from "./report.ts";
import { toCsv, toJson, toMarkdown } from "./export.ts";

export interface TraceSummary {
  file: string;
  basename: string;
  sizeBytes: number;
  totalEpbs: number;
  uniquePackets: number;
  flows: number;
  tcpFlows: number;
  udpFlows: number;
  icmpFlows: number;
  retransSegs: number;
  dnsAttributions: number;
  durationMs: number;
  reportPath: string;
  analyzedAt: string;
}

export interface WatchOptions {
  dir: string;
  reportDir: string;
  intervalMs?: number;
  once?: boolean;
  open?: boolean;
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(2)}s`;
}

/** Analyzes a single trace file, writes HTML report, and returns summary */
export function processTraceFile(tracePath: string, reportDir: string): TraceSummary {
  fs.mkdirSync(reportDir, { recursive: true });
  const basename = path.basename(tracePath, path.extname(tracePath));
  const stats = fs.statSync(tracePath);
  const a = analyzePcapFile(tracePath);

  const reportHtml = generateHtml(a);
  const reportPath = path.join(reportDir, `${basename}.html`);
  fs.writeFileSync(reportPath, reportHtml, "utf8");

  let minTs = Infinity;
  let maxTs = -Infinity;
  let tcpCount = 0;
  let udpCount = 0;
  let icmpCount = 0;

  for (const f of a.flows) {
    if (f.firstTs < minTs) minTs = f.firstTs;
    if (f.lastTs > maxTs) maxTs = f.lastTs;
    if (f.kind === "tcp") tcpCount++;
    else if (f.kind === "udp") udpCount++;
    else if (f.kind === "icmp" || f.kind === "icmpv6") icmpCount++;
  }

  const durationMs = minTs < maxTs ? Math.round((maxTs - minTs) * 1000) : 0;
  const uniquePackets = a.flows.reduce((s, f) => s + f.uniquePackets, 0);

  return {
    file: tracePath,
    basename,
    sizeBytes: stats.size,
    totalEpbs: a.totalEpbs,
    uniquePackets,
    flows: a.flows.length,
    tcpFlows: tcpCount,
    udpFlows: udpCount,
    icmpFlows: icmpCount,
    retransSegs: a.retransSegsTotal,
    dnsAttributions: a.dnsHostByIp.length,
    durationMs,
    reportPath,
    analyzedAt: new Date().toISOString(),
  };
}

/** Generates an aggregate index.html linking to all per-trace reports */
export function generateIndexHtml(summaries: TraceSummary[], reportDir: string): string {
  const ts = new Date().toISOString();
  const totalEpbs = summaries.reduce((s, t) => s + t.totalEpbs, 0);
  const totalFlows = summaries.reduce((s, t) => s + t.flows, 0);
  const totalUnique = summaries.reduce((s, t) => s + t.uniquePackets, 0);

  const rows = summaries.map((s, idx) => {
    const relLink = path.basename(s.reportPath);
    return `
    <tr>
      <td class="mono">${idx + 1}</td>
      <td><strong><a href="${relLink}">${s.basename}</a></strong></td>
      <td class="num">${s.totalEpbs}</td>
      <td class="num">${s.uniquePackets}</td>
      <td class="num"><strong>${s.flows}</strong></td>
      <td class="num"><span class="badge tcp">T:${s.tcpFlows}</span> <span class="badge udp">U:${s.udpFlows}</span> <span class="badge icmp">I:${s.icmpFlows}</span></td>
      <td class="num">${s.retransSegs > 0 ? `<span class="badge warn">${s.retransSegs}</span>` : "0"}</td>
      <td class="num">${s.dnsAttributions}</td>
      <td class="num">${formatDuration(s.durationMs)}</td>
      <td class="num mono">${bytesLabel(s.sizeBytes)}</td>
      <td><a class="action-btn" href="${relLink}">View Report &rarr;</a></td>
    </tr>`;
  }).join("");

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Packet Engine — Traces Dashboard</title>
<style>
:root {
  --bg: #0f1117; --surface: #1a1d27; --surface2: #22263a; --border: #2e3250;
  --accent: #6c8fff; --accent2: #4ecca3; --warn: #ffca28; --err: #ff5252;
  --text: #e8eaf6; --muted: #7b82b0; --font: 'Inter', system-ui, sans-serif;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: var(--font); font-size: 14px; line-height: 1.5; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
.topbar { background: var(--surface); border-bottom: 1px solid var(--border); padding: .85rem 1.5rem; display: flex; align-items: center; justify-content: space-between; }
.badge-title { font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .08em; }
h1 { font-size: 1.35rem; font-weight: 700; letter-spacing: -.5px; }
.main { padding: 1.5rem; max-width: 1400px; margin: 0 auto; }
.cards { display: flex; flex-wrap: wrap; gap: 1rem; margin-bottom: 1.5rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: .85rem 1.25rem; min-width: 140px; text-align: center; }
.card-val { font-size: 1.7rem; font-weight: 700; color: var(--accent); }
.card-label { font-size: .7rem; color: var(--muted); text-transform: uppercase; margin-top: .15rem; }
table.dash-table { width: 100%; border-collapse: collapse; background: var(--surface); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }
table.dash-table th { background: var(--surface2); color: var(--muted); font-size: .7rem; text-transform: uppercase; letter-spacing: .06em; padding: .65rem .9rem; text-align: left; border-bottom: 1px solid var(--border); }
table.dash-table td { padding: .6rem .9rem; border-bottom: 1px solid var(--border); }
table.dash-table tr:hover { background: var(--surface2); }
.mono { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: .82rem; }
.num { text-align: right; font-variant-numeric: tabular-nums; }
.badge { font-size: .68rem; padding: .15rem .4rem; border-radius: 3px; font-weight: 600; display: inline-block; }
.badge.tcp { background: #1e3a5f; color: #6c8fff; }
.badge.udp { background: #1a3d2e; color: #4ecca3; }
.badge.icmp { background: #3d2a1a; color: #ffca28; }
.badge.warn { background: #4a2c11; color: #ffca28; }
.action-btn { background: #263353; color: #9bb2ff; padding: .3rem .6rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }
.action-btn:hover { background: #364977; text-decoration: none; }
footer { text-align: center; padding: 2rem; color: var(--muted); font-size: .75rem; }
</style>
</head>
<body>
<div class="topbar">
  <div>
    <div class="badge-title">Strobe Packet Engine &bull; Milestone 4</div>
    <h1>Trace Analysis Dashboard</h1>
  </div>
  <div style="text-align: right;">
    <div class="badge-title">Generated</div>
    <div class="mono">${ts}</div>
  </div>
</div>
<div class="main">
  <div class="cards">
    <div class="card"><div class="card-val">${summaries.length}</div><div class="card-label">Traces</div></div>
    <div class="card"><div class="card-val">${totalEpbs}</div><div class="card-label">Total EPBs</div></div>
    <div class="card"><div class="card-val">${totalUnique}</div><div class="card-label">Unique Packets</div></div>
    <div class="card"><div class="card-val">${totalFlows}</div><div class="card-label">Total Flows</div></div>
  </div>
  <table class="dash-table">
    <thead>
      <tr>
        <th>#</th>
        <th>Trace</th>
        <th class="num">EPBs</th>
        <th class="num">Unique</th>
        <th class="num">Flows</th>
        <th class="num">Breakdown</th>
        <th class="num">Retrans</th>
        <th class="num">DNS</th>
        <th class="num">Duration</th>
        <th class="num">File Size</th>
        <th>Report</th>
      </tr>
    </thead>
    <tbody>${rows}</tbody>
  </table>
</div>
<footer>strobe-packet-tracker M4 &bull; Local Engine Ergonomics</footer>
</body>
</html>`;
}

/** Print formatted table of summaries to stdout */
export function printConsoleSummary(summaries: TraceSummary[]): void {
  console.log("\n==========================================================================================");
  console.log("                       STROBE PACKET ENGINE — TRACE INVENTORY                             ");
  console.log("==========================================================================================");
  console.log(
    " #  Trace Name                   EPBs   Uniq   Flows   TCP  UDP  ICM  Retrans    DNS   Duration"
  );
  console.log("------------------------------------------------------------------------------------------");
  summaries.forEach((s, i) => {
    const num = String(i + 1).padStart(2);
    const name = s.basename.padEnd(25).slice(0, 25);
    const epbs = String(s.totalEpbs).padStart(6);
    const uniq = String(s.uniquePackets).padStart(6);
    const flows = String(s.flows).padStart(7);
    const tcp = String(s.tcpFlows).padStart(5);
    const udp = String(s.udpFlows).padStart(4);
    const icmp = String(s.icmpFlows).padStart(4);
    const retrans = String(s.retransSegs).padStart(8);
    const dns = String(s.dnsAttributions).padStart(6);
    const dur = formatDuration(s.durationMs).padStart(10);
    console.log(`${num}  ${name}  ${epbs} ${uniq} ${flows} ${tcp} ${udp} ${icmp} ${retrans} ${dns} ${dur}`);
  });
  console.log("------------------------------------------------------------------------------------------");
  const totEpbs = summaries.reduce((a, b) => a + b.totalEpbs, 0);
  const totUniq = summaries.reduce((a, b) => a + b.uniquePackets, 0);
  const totFlows = summaries.reduce((a, b) => a + b.flows, 0);
  console.log(
    `    TOTAL (${summaries.length} traces):`.padEnd(29) +
    `${String(totEpbs).padStart(6)} ${String(totUniq).padStart(6)} ${String(totFlows).padStart(7)}`
  );
  console.log("==========================================================================================\n");
}

/** Scans target directory, processes all .pcapng files, updates index.html */
export function scanAndReportAll(dir: string, reportDir: string): TraceSummary[] {
  if (!fs.existsSync(dir)) {
    throw new Error(`Directory not found: ${dir}`);
  }
  const files = fs
    .readdirSync(dir)
    .filter((f) => f.endsWith(".pcapng"))
    .sort();

  const summaries: TraceSummary[] = [];
  for (const file of files) {
    const fullPath = path.join(dir, file);
    try {
      const summary = processTraceFile(fullPath, reportDir);
      summaries.push(summary);
    } catch (err: any) {
      console.warn(`[warn] Failed to process ${file}: ${err.message}`);
    }
  }

  const indexHtml = generateIndexHtml(summaries, reportDir);
  const indexPath = path.join(reportDir, "index.html");
  fs.writeFileSync(indexPath, indexHtml, "utf8");

  return summaries;
}

/** Open a file in the default browser on Windows */
export function openInBrowser(filePath: string): void {
  const abs = path.resolve(filePath);
  if (process.platform === "win32") {
    exec(`start "" "${abs}"`);
  } else if (process.platform === "darwin") {
    exec(`open "${abs}"`);
  } else {
    exec(`xdg-open "${abs}"`);
  }
}

/** Watch a directory for new or updated .pcapng files */
export async function watchDirectory(opts: WatchOptions): Promise<void> {
  const { dir, reportDir, intervalMs = 2500, once = false, open = false } = opts;
  console.log(`[m4-watch] Scanning ${dir}... reports -> ${reportDir}`);
  const summaries = scanAndReportAll(dir, reportDir);
  printConsoleSummary(summaries);

  const indexPath = path.join(reportDir, "index.html");
  console.log(`[m4-watch] Index dashboard written: ${indexPath}`);

  if (open) {
    console.log(`[m4-watch] Opening dashboard in browser...`);
    openInBrowser(indexPath);
  }

  if (once) {
    return;
  }

  console.log(`[m4-watch] Watching for updates every ${intervalMs}ms (Ctrl+C to stop)...`);

  const fileState = new Map<string, number>();
  for (const f of fs.readdirSync(dir)) {
    if (f.endsWith(".pcapng")) {
      fileState.set(f, fs.statSync(path.join(dir, f)).mtimeMs);
    }
  }

  await new Promise<void>((resolve) => {
    const interval = setInterval(() => {
      try {
        let changed = false;
        const currentFiles = fs.readdirSync(dir).filter((f) => f.endsWith(".pcapng"));
        for (const file of currentFiles) {
          const fullPath = path.join(dir, file);
          const mtime = fs.statSync(fullPath).mtimeMs;
          const prev = fileState.get(file);
          if (prev === undefined || prev !== mtime) {
            console.log(`[m4-watch] Detected change in ${file}`);
            fileState.set(file, mtime);
            changed = true;
          }
        }
        if (changed) {
          const updated = scanAndReportAll(dir, reportDir);
          printConsoleSummary(updated);
          console.log(`[m4-watch] Dashboard updated at ${new Date().toLocaleTimeString()}`);
        }
      } catch (err: any) {
        console.error(`[m4-watch] Error during poll: ${err.message}`);
      }
    }, intervalMs);

    process.on("SIGINT", () => {
      clearInterval(interval);
      console.log("\n[m4-watch] Stopped.");
      resolve();
    });
  });
}
