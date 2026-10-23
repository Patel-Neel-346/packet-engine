// Milestone 2 batch runner: elevates ONE bundle for the whole batch and,
// from the NON-elevated side, drives each scenario's traffic generation in
// lock-step via signal files. Afterwards every scenario trace is parsed,
// deduped and compared against tshark (parity metric), and a summary table
// is written to test-results/milestone2.md.
//
// Layer:     capture — batch orchestration (elevated capture + parity summary)
// Milestone: M2 — scenario batch runner (docs/history/milestone-2-report.md)
// Verified:  produced the 14-trace corpus + parity summaries (test-results/milestone2-*.md); writeM2Plan runs offline, no UAC
// Exports:   runMilestoneBatch, writeM2Plan

import fs from "node:fs";
import path from "node:path";
import { PktmonBackend } from "./pktmonBackend.ts";
import { parsePcapng } from "../engine/pcapng.ts";
import {
  coreScenarios,
  extendedScenarios,
  buildPlans,
  type ScenarioDef,
} from "../traffic/scenarios.ts";
import { buildTrafficContext, type TrafficContext } from "../traffic/traffic.ts";
import { computeParity, tsharkReadFrames, type ParityResult } from "../verify/parity.ts";
import { tsharkExe, runCommand } from "./pktmon.ts";
import { OUT_DIR, SCEN_DIR, RESULTS_DIR } from "../paths.ts";

function waitForFresh(
  file: string,
  sinceMs: number,
  timeoutMs: number,
  pollMs = 100,
): Promise<boolean> {
  // Only a file created/modified AFTER sinceMs counts â€” stale files from a
  // previous batch must not satisfy the wait.
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = setInterval(() => {
      try {
        const st = fs.statSync(file);
        if (st.mtimeMs >= sinceMs) {
          clearInterval(tick);
          resolve(true);
          return;
        }
      } catch {
        /* not yet */
      }
      if (Date.now() > deadline) {
        clearInterval(tick);
        resolve(false);
      }
    }, pollMs);
  });
}

function waitFor(file: string, timeoutMs: number, pollMs = 100): Promise<boolean> {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = setInterval(() => {
      if (fs.existsSync(file)) {
        clearInterval(tick);
        resolve(true);
      } else if (Date.now() > deadline) {
        clearInterval(tick);
        resolve(false);
      }
    }, pollMs);
  });
}

interface PcapCount {
  file: string;
  exists: boolean;
  bytes: number;
  epbs: number;
  error: string | null;
}

function countPcapng(file: string): PcapCount {
  if (!fs.existsSync(file)) {
    return { file, exists: false, bytes: 0, epbs: 0, error: "missing" };
  }
  const bytes = fs.statSync(file).size;
  if (bytes === 0) return { file, exists: true, bytes, epbs: 0, error: "0-byte (M1 lesson)" };
  try {
    const parsed = parsePcapng(fs.readFileSync(file));
    return { file, exists: true, bytes, epbs: parsed.packets.length, error: null };
  } catch (e) {
    return { file, exists: true, bytes, epbs: 0, error: String(e).slice(0, 120) };
  }
}

async function countTsharkFilter(file: string, displayFilter: string): Promise<number> {
  const res = await runCommand(
    tsharkExe(),
    ["-r", file, "-n", "-Y", displayFilter, "-T", "fields", "-e", "frame.number"],
    { timeoutMs: 240_000 },
  );
  if (res.code !== 0) return -1;
  return res.stdout.split(/\r?\n/).filter((l) => l.trim() !== "").length;
}

async function scenarioExtras(def: ScenarioDef, scenFile: string): Promise<Record<string, string>> {
  const extra: Record<string, string> = {};
  if (def.id === "s12_retrans") {
    const n = await countTsharkFilter(scenFile, "tcp.analysis.retransmission");
    extra["tsharkRetransmissions"] = String(n);
  }
  if (def.id === "s14_burst") {
    const frames = await tsharkReadFrames(scenFile);
    extra["tsharkFrameCount"] = String(frames.length);
  }
  if (def.id === "s10_arpdhcp") {
    const parts: string[] = [];
    for (const cid of [13, 36, 74, 75]) {
      const f = path.join(SCEN_DIR, `${def.id}_c${cid}.pcapng`);
      if (!fs.existsSync(f)) continue;
      const c = await countTsharkFilter(f, "arp");
      parts.push(`comp${cid}:arp=${c}`);
    }
    extra["arpByComponent"] = parts.join(" ") || "none";
  }
  if (def.id === "s11_loopback") {
    const parts: string[] = [];
    let sumCompEpbs = 0;
    for (const cid of [13, 33, 36, 74, 75]) {
      const f = path.join(SCEN_DIR, `${def.id}_c${cid}.pcapng`);
      const c = countPcapng(f);
      sumCompEpbs += c.epbs;
      parts.push(`c${cid}=${c.epbs}`);
    }
    const all = countPcapng(scenFile);
    extra["epbsByComponent"] = parts.join(" ");
    extra["epbsAll"] = String(all.epbs);
    extra["otherComponentsSaw"] = String(Math.max(0, all.epbs - sumCompEpbs));
  }
  if (def.id === "s9_quic") {
    const quic = await countTsharkFilter(scenFile, "quic || http3");
    const udp443 = await countTsharkFilter(scenFile, "udp.port == 443");
    extra["quicFrames"] = String(quic);
    extra["udp443"] = String(udp443);
  }
  return extra;
}

interface ScenarioRow {
  id: string;
  title: string;
  steps: string[];
  notes: string[];
  parity: ParityResult | null;
  extra: Record<string, string>;
  capture: PcapCount;
  tracePick: string;
}

function rowLine(row: ScenarioRow): string {
  const p = row.parity;
  const parity = p ? `${p.parityPct}%` : "n/a";
  const unsup = p ? String(p.unsupported) : "-";
  const uniq = p ? String(p.uniquePackets) : "-";
  const dups = p ? String(p.duplicatesMerged) : "-";
  const extra = Object.entries(row.extra)
    .filter(([k]) => k !== "tsharkFrameCount")
    .map(([k, v]) => `${k}=${v}`)
    .join(", ");
  return `| ${row.id} | ${uniq} | ${dups} | ${parity} | ${unsup} | ${row.capture.epbs} | ${extra} |`;
}

/** m2-plan: generate the bundle PowerShell script for a batch and write it to
 * out/scen/m2_<batch>.ps1. Offline, no UAC — nothing is executed. */
export async function writeM2Plan(which: "core" | "ext"): Promise<number> {
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

/** Run a whole M2 batch with ONE elevated bundle: capture every scenario,
 * then compute the per-trace parity metric and write
 * test-results/milestone2-<batch>.md. */
export async function runMilestoneBatch(batch: "core" | "ext"): Promise<void> {
  fs.mkdirSync(SCEN_DIR, { recursive: true });
  fs.mkdirSync(RESULTS_DIR, { recursive: true });
  const resultsMd = path.join(RESULTS_DIR, `milestone2-${batch}.md`);
  const scenarios: ScenarioDef[] = batch === "core" ? coreScenarios() : extendedScenarios();
  const ctx: TrafficContext = await buildTrafficContext();
  const backend = new PktmonBackend(OUT_DIR, SCEN_DIR);

  console.log("== traffic context (resolved, non-elevated) ==");
  console.log(
    JSON.stringify({
      exampleV4: ctx.exampleV4,
      exampleV6: ctx.exampleV6,
      speedV4: ctx.speedV4,
      speedV6: ctx.speedV6,
      quicV4: ctx.quicV4,
      quicV6: ctx.quicV6,
      resolver: ctx.resolver,
      localIp: ctx.localIp,
    }),
  );

  const backendStatus = await backend.checkAvailableNonElevated();
  console.log(`pktmon non-elevated status: ${JSON.stringify(backendStatus)}`);

  const plans = buildPlans(scenarios, ctx);
  const bundleId = `m2_${batch}`;
  console.log(
    `launching elevated bundle ${bundleId} with ${plans.length} scenarios (one UAC prompt)...`,
  );
  const launchedAt = Date.now();

  // Kick the elevated bundle off; the UAC prompt shows up now. Do NOT await
  // yet â€” we drive the traffic while the (elevated) capture side waits.
  const bundlePromise = backend.runBundle({ bundleId, plans });

  const rows: ScenarioRow[] = [];
  for (let i = 0; i < scenarios.length; i++) {
    const s = scenarios[i];
    const started = path.join(SCEN_DIR, `${s.id}.capturestarted`);
    const trafficDone = path.join(SCEN_DIR, `${s.id}.trafficdone`);
    const done = path.join(SCEN_DIR, `${s.id}.capturedone`);
    process.stdout.write(`[${i + 1}/${scenarios.length}] ${s.id}: waiting for capture start...  `);
    const okStart = await waitForFresh(started, launchedAt - 2_000, 300_000);
    const startedFs = okStart ? fs.statSync(started) : null;
    if (!okStart) {
      console.log(`TIMEOUT waiting for capture start (UAC denied or bundle failed?).`);
      rows.push({
        id: s.id,
        title: s.title,
        steps: [],
        notes: ["capture never started"],
        parity: null,
        extra: {},
        capture: countPcapng(path.join(SCEN_DIR, `${s.id}_all.pcapng`)),
        tracePick: "-",
      });
      break;
    }
    console.log(`started=${startedFs?.mtime.toISOString()}; generating traffic...`);
    const real = await s.run(ctx);
    fs.writeFileSync(trafficDone, "done", "utf8");
    const okDone = await waitForFresh(
      done,
      startedFs?.mtimeMs ?? launchedAt,
      ((s.timeoutSec ?? 75) + 30) * 1000,
    );
    console.log(`  -> capture done=${okDone}, steps=[${real.steps.map((x) => x.step).join(", ")}]`);
    // Prefer the all-components trace (dedupe merges the copies).
    const allFile = path.join(SCEN_DIR, `${s.id}_all.pcapng`);
    const pick = countPcapng(allFile);
    const extra = okDone ? await scenarioExtras(s, allFile) : { error: "capture did not finish" };
    rows.push({
      id: s.id,
      title: s.title,
      steps: real.steps.map((x) => `${x.step}:exit=${x.code}:${x.detail}`),
      notes: real.notes,
      parity: null,
      extra,
      capture: pick,
      tracePick: allFile,
    });
  }
  console.log(`waiting for the elevated bundle to exit...`);
  const bundleResult = await bundlePromise;
  console.log(`bundle exit=${bundleResult.exitCode}, log=${bundleResult.logFile}`);
  if (bundleResult.logContent) {
    fs.writeFileSync(
      path.join(SCEN_DIR, `${bundleId}.recorded.log`),
      bundleResult.logContent,
      "utf8",
    );
  }

  // Surface per-scenario filter/fallback results from the recorded bundle log.
  for (const row of rows) {
    const logLines = bundleResult.logContent.split(/\r?\n/);
    for (const line of logLines) {
      if (line.includes(row.id) && line.startsWith("[FALLBACK")) {
        row.notes.push(`bundle-log: ${line.slice(0, 200)}`);
      }
      if (line.includes(row.id) && line.startsWith("[STEP filterAdd") && /code=[1-9]/.test(line)) {
        row.notes.push(`bundle-log: ${line.slice(0, 200)}`);
      }
      if (line.includes(row.id) && line.startsWith("[FAIL")) {
        row.notes.push(`bundle-log: ${line.slice(0, 200)}`);
      }
    }
  }

  // Parity per captured scenario.
  for (const row of rows) {
    if (!row.capture.exists || row.capture.bytes === 0 || row.capture.epbs === 0) {
      row.parity = null;
      row.notes.push(`parity skipped: ${row.capture.error ?? "no packets captured"}`);
      continue;
    }
    try {
      row.parity = await computeParity(row.id, row.tracePick, {
        notes: [...row.notes],
      });
      row.parity.notes = [...row.notes, ...(row.parity.notes ?? [])];
    } catch (e) {
      row.parity = null;
      row.notes.push(`parity error: ${String(e).slice(0, 160)}`);
    }
  }

  const lines: string[] = [];
  lines.push(`# Milestone 2 â€” scenario corpus results (batch: ${batch})`);
  lines.push("");
  lines.push(`Captured at: ${new Date().toISOString()}`);
  lines.push("");
  lines.push(`| scenario | uniquePkts | dupsMerged | parity | unsupported | traceEPBs | extras |`);
  lines.push(`|---|---|---|---|---|---|---|`);
  for (const row of rows) lines.push(rowLine(row));
  lines.push("");
  lines.push(
    `Parity target: >= 90% for core scenarios (M2 addendum). Parity = packets with ALL compared fields (ts, cap/frame len, src/dst IP, ports, protocol, TCP flags, flow membership, DNS/SNI content when parsed) matching tshark 4.6.9, among unique packets after cross-component/raw-802.11 dedupe.`,
  );
  lines.push("");
  lines.push(`## Traffic generation details`);
  for (const row of rows) {
    lines.push("");
    lines.push(`### ${row.id} â€” ${row.title}`);
    lines.push(
      `- trace: ${path.basename(row.tracePick)} exists=${row.capture.exists} bytes=${row.capture.bytes} epbs=${row.capture.epbs}${row.capture.error ? ` (${row.capture.error})` : ""}`,
    );
    for (const n of row.notes) lines.push(`- note: ${n}`);
    for (const s of row.steps) lines.push(`- step: ${s}`);
    const p = row.parity;
    if (p) {
      lines.push(
        `- parity: unique=${p.uniquePackets} matched=${p.matched} parity=${p.parityPct}% unsupported=${p.unsupported} dupsMerged=${p.duplicatesMerged} framing=${JSON.stringify(p.framingCounts)}`,
      );
      lines.push(`- protocolMatrix=${JSON.stringify(p.protocolMatrix)}`);
      lines.push(
        `- flows: ours=${p.flowCountOurs} tshark=${p.flowCountTshark} match=${p.flowsMatch}`,
      );
      for (const m of p.mismatchSamples) lines.push(`- sample: ${m}`);
    }
  }
  fs.writeFileSync(resultsMd, lines.join("\n"), "utf8");
  console.log(`summary written: ${resultsMd}`);

  const jsonPath = path.join(SCEN_DIR, `m2_${batch}_results.json`);
  fs.writeFileSync(
    jsonPath,
    JSON.stringify(
      rows.map((r) => ({
        id: r.id,
        title: r.title,
        capture: r.capture,
        parity: r.parity,
        extra: r.extra,
        steps: r.steps,
        notes: r.notes,
      })),
      null,
      2,
    ),
    "utf8",
  );
  console.log(`json results: ${jsonPath}`);

  console.log("");
  console.log(`| scenario | uniquePkts | dupsMerged | parity | unsupported | traceEPBs |`);
  for (const row of rows) {
    const p = row.parity;
    console.log(
      `| ${row.id} | ${p ? p.uniquePackets : "-"} | ${p ? p.duplicatesMerged : "-"} | ${p ? p.parityPct + "%" : "n/a"} | ${p ? p.unsupported : "-"} | ${row.capture.epbs} |`,
    );
  }
}
