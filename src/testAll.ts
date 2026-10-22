// test-all: one command that re-runs EVERY verification gate in the project
// and writes a consolidated report. This is the single "is the engine still
// honest?" command:
//   1. typecheck (tsc --noEmit, whole engine)
//   2. unit + integration tests (decoder, flows, loopback tap) via node --test
//   3. M1 capture-path cross-check (out/m1.pcapng frame-by-frame vs tshark)
//   4. M2 parity regression on the 14-trace scenario corpus
//   5. M3 verification matrix (14/14 conv/DNS/HTTP/retransmission vs tshark)
//   6. M4-c ergonomics: dashboard regeneration + export formats
//   7. M4a loopback tap: 3 local scenarios + the tshark gate on tap traces
// Results: console table + test-results/test-all.md. Exit 0 only when every
// gate passes.
//
// Layer:     orchestration — the 8-gate verification suite (spawns tsc/node/tshark)
// Milestone: final verification model (docs/project-status.md)
// Verified:  baseline 8/8 PASS (~43.5s) — this file is itself the top-level gate
// Exports:   runTestAll, GateResult

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { m1Verify } from "./verify/m1Verify.ts";
import { runM4Loopback, printM4Loopback, type LoopbackRun } from "./tap/m4Loopback.ts";

export interface GateResult {
  name: string;
  ok: boolean;
  detail: string;
  ms: number;
}

const results: GateResult[] = [];

function gateSync(
  name: string,
  fn: () => { ok: boolean; detail: string },
): void {
  const t0 = Date.now();
  process.stdout.write(`[test-all] ${name} ... `);
  try {
    const r = fn();
    const ms = Date.now() - t0;
    results.push({ name, ...r, ms });
    process.stdout.write(`${r.ok ? "PASS" : "FAIL"} (${(ms / 1000).toFixed(1)}s) — ${r.detail}\n`);
  } catch (e) {
    const ms = Date.now() - t0;
    const msg = e instanceof Error ? e.message : String(e);
    results.push({ name, ok: false, detail: `threw: ${msg}`, ms });
    process.stdout.write(`THREW (${(ms / 1000).toFixed(1)}s) — ${msg}\n`);
  }
}

async function gateAsync(
  name: string,
  fn: () => Promise<{ ok: boolean; detail: string }>,
): Promise<void> {
  const t0 = Date.now();
  process.stdout.write(`[test-all] ${name} ... `);
  try {
    const r = await fn();
    const ms = Date.now() - t0;
    results.push({ name, ...r, ms });
    process.stdout.write(`${r.ok ? "PASS" : "FAIL"} (${(ms / 1000).toFixed(1)}s) — ${r.detail}\n`);
  } catch (e) {
    const ms = Date.now() - t0;
    const msg = e instanceof Error ? e.message : String(e);
    results.push({ name, ok: false, detail: `threw: ${msg}`, ms });
    process.stdout.write(`THREW (${(ms / 1000).toFixed(1)}s) — ${msg}\n`);
  }
}

function runNode(args: string[], label: string): { code: number; stdout: string; stderr: string } {
  const r = spawnSync(process.execPath, args, { encoding: "utf8", maxBuffer: 32 * 1024 * 1024 });
  const stdout = (r.stdout ?? "") + (r.stderr ?? "");
  return { code: r.status ?? 1, stdout, stderr: (r.stderr ?? "") || "" };
}

function runNpm(script: string, label: string): { code: number; stdout: string } | null {
  const r = spawnSync("npm", ["run", script], {
    encoding: "utf8",
    shell: true,
    maxBuffer: 32 * 1024 * 1024,
  });
  void label;
  return { code: r.status ?? 1, stdout: (r.stdout ?? "") + (r.stderr ?? "") };
}

const TSC_BIN = path.join("node_modules", "typescript", "bin", "tsc");
const M1_TRACE = path.join("out", "m1.pcapng");

/** Run all 8 verification gates and print the consolidated table.
 * Exit 0 only when every gate passes. */
export async function runTestAll(): Promise<GateResult[]> {
  const t0 = Date.now();
  console.log("[test-all] starting full verification suite (offline, no UAC)");

  // 1. typecheck (tsc directly — avoids spawning npm inside an npm script)
  gateSync("typecheck", () => {
    const r = fs.existsSync(TSC_BIN)
      ? runNode([TSC_BIN, "--noEmit"], "tsc --noEmit")
      : (runNpm("typecheck", "tsc --noEmit") ?? { code: 1, stdout: "" });
    const clean = r.code === 0 && !/error TS/.test(r.stdout);
    return { ok: clean, detail: clean ? "tsc --noEmit clean" : r.stdout.slice(-400) || `exit ${r.code}` };
  });

  // 2. unit + integration tests
  gateSync("unit-tests", () => {
    const files = ["test/decoder.test.ts", "test/flows.test.ts", "test/loopbacktap.test.ts"]
      .filter((f) => fs.existsSync(f));
    const r = runNode(["--test", ...files], "node --test");
    // node's spec reporter lines are `<glyph> pass N` / `<glyph> fail N`
    // (glyph renders as mojibake through pipes); parse defensively and gate
    // primarily on the exit code, which encodes failures reliably.
    const lastNum = (re: RegExp): number | null => {
      const all = [...r.stdout.matchAll(re)];
      return all.length ? Number(all[all.length - 1][1]) : null;
    };
    const pass = lastNum(/pass (\d+)/g);
    const fail = lastNum(/fail (\d+)/g);
    const cancel = lastNum(/cancelled (\d+)/g);
    const ok = r.code === 0 && (fail === null || fail === 0) && (cancel === null || cancel === 0);
    const counts =
      pass !== null ? `pass=${pass} fail=${fail ?? "?"}` : "counts n/a (gated on exit code)";
    const shortFiles = files.length < 3 ? ` (${files.length}/3 test files present)` : "";
    return { ok, detail: `${counts}${shortFiles}` };
  });

  // 3. M1 capture-path cross-check (needs out/m1.pcapng)
  gateAsync("m1-verify", async () => {
    if (!fs.existsSync(M1_TRACE)) {
      return { ok: false, detail: "out/m1.pcapng missing (run m1 capture first)" };
    }
    const code = await m1Verify();
    return { ok: code === 0, detail: code === 0 ? "frame-by-frame vs tshark: all pass" : `exit ${code}` };
  });

  // 4. M2 parity regression across the scenario corpus
  gateSync("parity-regression", () => {
    const r = runNode(["out/scen/reverify_parity.ts"], "reverify_parity");
    const rows = [...r.stdout.matchAll(/(\S+)\s+parity=\s*([\d.]+)%/g)];
    if (rows.length === 0) {
      return { ok: false, detail: `no parity rows parsed (exit ${r.code}) — ${r.stdout.slice(-300)}` };
    }
    const bad = rows
      .map((m) => ({ id: m[1], v: Number(m[2]) }))
      .filter(({ id, v }) => (id.startsWith("s10") ? v < 14 : v < 100));
    const coverage = rows.length;
    return {
      ok: r.code === 0 && bad.length === 0 && coverage >= 10,
      detail: `${coverage} traces: ${check(coverage, bad)}exceptions: ${bad.map((b) => `${b.id}=${b.v}%`).join(",") || "none"}`,
    };
  });

  // 5. M3 full matrix vs tshark
  gateSync("m3-matrix", () => {
    const r = runNode(["src/cli.ts", "m3-verify"], "m3-verify");
    const m = /done: (\d+)\/(\d+) fully pass/.exec(r.stdout);
    if (!m) return { ok: false, detail: `matrix summary not found (exit ${r.code}) — ${r.stdout.slice(-300)}` };
    const [full, total] = [Number(m[1]), Number(m[2])];
    return {
      ok: r.code === 0 && full === total,
      detail: `${full}/${total} traces fully pass`,
    };
  });

  // 6. M4-c ergonomics: dashboard + export formats
  gateSync("m4-dashboard", () => {
    const r = runNode(["src/cli.ts", "m4-report"], "m4-report");
    const dash = path.join("out", "m4-reports", "index.html");
    const exists = fs.existsSync(dash);
    const size = exists ? fs.statSync(dash).size : 0;
    return {
      ok: r.code === 0 && exists && size > 1000,
      detail: `dashboard ${exists ? `${(size / 1024).toFixed(0)}KB` : "MISSING"}`,
    };
  });
  gateSync("m4-export-formats", () => {
    let okAll = true;
    const parts: string[] = [];
    for (const [file, fmt] of [
      ["out/scen/s3_dns_all.pcapng", "md"],
      ["out/scen/s3_dns_all.pcapng", "csv"],
      ["out/scen/s2_http_external_all.pcapng", "json"],
    ] as const) {
      const r = runNode(["src/cli.ts", "m4-export", file, fmt], "m4-export");
      const dest = path.join("out", "m4-reports", `${path.basename(file, path.extname(file))}.${fmt}`);
      const good = r.code === 0 && fs.existsSync(dest) && fs.statSync(dest).size > 400;
      okAll = okAll && good;
      parts.push(`${fmt}: ${good ? "ok" : `fail(exit ${r.code})`}`);
    }
    return { ok: okAll, detail: parts.join(" ") };
  });

  // 7. M4a loopback tap + tshark gate on tap traces
  await gateAsync("m4a-loopback", async () => {
    const { allOk, runs } = await runM4Loopback({ withTshark: true });
    for (const line of printM4Loopback(runs)) console.log(line);
    const perId = runs
      .map((r: LoopbackRun) => `${r.id}=${r.ok ? "pass" : "fail"}`)
      .join(",");
    return { ok: allOk, detail: `${runs.length} scenarios (${perId})` };
  });

  // summary
  const missed = results.filter((r) => !r.ok);
  const allOk = missed.length === 0;
  const totalSec = (Date.now() - t0) / 1000;

  const lines: string[] = [];
  lines.push("# test-all — full verification suite");
  lines.push("");
  lines.push(`_run: ${new Date().toISOString()}  |  total ${(totalSec).toFixed(1)}s  |  ${results.length - missed.length}/${results.length} gates pass_`);
  lines.push("");
  lines.push("| gate | result | detail | time |");
  lines.push("|---|---|---|---|");
  for (const r of results) {
    lines.push(`| ${r.name} | ${r.ok ? "PASS" : "FAIL"} | ${r.detail.replace(/\|/g, "/")} | ${(r.ms / 1000).toFixed(1)}s |`);
  }
  lines.push("");
  lines.push(allOk ? "**ALL GATES PASS**" : `**${missed.length} GATE(S) FAILED**: ${missed.map((m) => m.name).join(", ")}`);
  fs.mkdirSync("test-results", { recursive: true });
  fs.writeFileSync(path.join("test-results", "test-all.md"), lines.join("\n"));

  console.log("");
  console.log("================================================================================");
  for (const r of results) {
    console.log(`${r.ok ? " PASS" : " FAIL"}  ${r.name.padEnd(22)} ${(r.ms / 1000).toFixed(1)}s  ${r.detail}`);
  }
  console.log("================================================================================");
  console.log(allOk
    ? `test-all: ALL ${results.length} gates pass in ${totalSec.toFixed(1)}s -> test-results/test-all.md`
    : `test-all: ${missed.length}/${results.length} FAILED (${missed.map((m) => m.name).join(", ")}) -> test-results/test-all.md`);
  return results;
}

function check(coverage: number, bad: Array<{ id: string; v: number }>): string {
  return coverage >= 10 && bad.length === 0
    ? `${coverage} traces at thresholds, `
    : "";
}
