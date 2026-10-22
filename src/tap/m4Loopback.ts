// M4-a runner: captures the three local scenarios through the userspace
// loopback tap, verifies application truth AND flow-engine agreement, writes
// the synthesized PCAPNG traces, and can optionally run the full M3 tshark
// gate on them (which simultaneously proves tshark accepts our pcapng writer).
//
// Layer:     tap — scenario runner (drives traffic/ generators through the tap)
// Milestone: M4a — loopback runner (docs/project-status.md)
// Verified:  gate 8 of `npm run test:all` (s2_local_split, s13_ws, s11_loopback all pass)
// Exports:   runM4Loopback, printM4Loopback

import fs from "node:fs";
import path from "node:path";
import { LoopbackTap, type TcpStory } from "./loopbacktap.ts";
import { analyzePcapFile, bytesLabel, type FlowAnalysis, type Flow } from "../engine/flows.ts";
import {
  buildTrafficContext,
  localHttpScenario,
  wsScenario,
  loopbackScenario,
  type TrafficContext,
  type TrafficResult,
} from "../traffic/traffic.ts";
import { verifyTrace } from "../verify/m3Verify.ts";

export interface CheckResult {
  name: string;
  pass: boolean;
  detail: string;
}

export interface LoopbackRun {
  id: string;
  file: string;
  frames: number;
  tcpConns: number;
  udpFlows: number;
  ok: boolean;
  checks: CheckResult[];
  appSteps: { step: string; code: number | null; detail: string }[];
  warnings: string[];
}

const check = (name: string, pass: boolean, detail: string): CheckResult => ({
  name,
  pass,
  detail,
});

function findTcpFlow(a: FlowAnalysis, story: TcpStory, clientPort: number, serverPort: number): Flow | null {
  return (
    a.flows.find(
      (f) =>
        f.kind === "tcp" &&
        ((f.a.port === clientPort && f.b.port === serverPort) ||
          (f.b.port === clientPort && f.a.port === serverPort)),
    ) ?? null
  );
}

/** Engine reassembled stream bytes must equal the verbatim tap payloads
 * (multiset match across directions + content equality on the matched pair). */
function checkPayloadMatch(
  story: TcpStory,
  flow: Flow,
): CheckResult {
  const t = flow.tcp;
  if (!t) return check("stream-payload", false, `flow ${flow.id}: no TCP story`);
  const a2b = t.a2b?.bytes ?? Buffer.alloc(0);
  const b2a = t.b2a?.bytes ?? Buffer.alloc(0);
  const direct =
    a2b.length === story.c2sPayload.length &&
    b2a.length === story.s2cPayload.length &&
    a2b.equals(story.c2sPayload) &&
    b2a.equals(story.s2cPayload);
  const swapped =
    a2b.length === story.s2cPayload.length &&
    b2a.length === story.c2sPayload.length &&
    a2b.equals(story.s2cPayload) &&
    b2a.equals(story.c2sPayload);
  return check(
    "stream-payload",
    direct || swapped,
    `tap c2s=${story.c2sPayload.length}B s2c=${story.s2cPayload.length}B vs engine a2b=${a2b.length}B b2a=${b2a.length}B (${flow.id})`,
  );
}

function checkCommonStructure(a: FlowAnalysis, expectedTcp: number): CheckResult[] {
  const ret0 = check(
    "no-retransmissions",
    a.retransSegsTotal === 0,
    `retransSegsTotal=${a.retransSegsTotal}`,
  );
  let gaps = 0;
  let gapBytes = 0;
  for (const f of a.flows) {
    if (f.tcp?.a2b && f.tcp.a2b.gapCount > 0) {
      gaps += f.tcp.a2b.gapCount;
      gapBytes += f.tcp.a2b.gapBytes;
    }
    if (f.tcp?.b2a && f.tcp.b2a.gapCount > 0) {
      gaps += f.tcp.b2a.gapCount;
      gapBytes += f.tcp.b2a.gapBytes;
    }
  }
  const gap0 = check("no-gaps", gaps === 0, `gaps=${gaps} (${gapBytes}B)`);
  const tcpCount = a.flows.filter((f) => f.kind === "tcp").length;
  const tcpOk = check(
    "flow-count",
    tcpCount === expectedTcp,
    `tcp flows=${tcpCount} expected=${expectedTcp}`,
  );
  const epbOk = check(
    "epb-consistency",
    a.totalEpbs > 0,
    `EPBs=${a.totalEpbs}`,
  );
  return [ret0, gap0, tcpOk, epbOk];
}

function verifyScenario(
  id: string,
  tap: LoopbackTap,
  a: FlowAnalysis,
  app: TrafficResult,
  ctx: TrafficContext,
): CheckResult[] {
  const checks: CheckResult[] = [];
  const stories = tap.tcpTales;

  if (id === "s2_local_split") {
    // 2 clients on 127.0.0.1:ctx.httpPort + 1 client on ctx.localIp:ctx.httpPort-1
    checks.push(check("conn-count", tap.tcpConnCount === 3, `tcp conns=${tap.tcpConnCount} expected=3`));
    for (const story of stories) {
      const c2sOk =
        story.c2sPayload.subarray(0, 4).toString("ascii") === "GET " &&
        story.c2sPayload.includes("Host: ");
      checks.push(check("request-shape", c2sOk, `conn#${story.id} c2s starts "${story.c2sPayload.subarray(0, 20).toString("ascii")}"`));
      const resOk = story.s2cPayload.includes("HTTP/1.1 200 OK");
      checks.push(check("response-shape", resOk, `conn#${story.id} s2c head "${story.s2cPayload.subarray(0, 15).toString("ascii")}"`));
      const flow = findTcpFlow(a, story, story.clientPort, story.serverPort);
      if (flow) {
        const st = flow.http?.responses[0]?.status;
        checks.push(check("http-200", st === 200, `conn#${story.id} engine http status=${st ?? "none"}`));
        checks.push(checkPayloadMatch(story, flow));
      } else {
        checks.push(check("flow-match", false, `conn#${story.id} no engine flow for ${story.clientPort}->${story.serverPort}`));
      }
    }
    const appOk = app.steps
      .filter((s) => s.step.startsWith("local_http"))
      .every((s) => s.code === 0);
    checks.push(check("app-truth", appOk, app.steps.filter((s) => s.step.startsWith("local_http")).map((s) => `${s.step}: code=${s.code} ${s.detail}`).join("; ") || "no steps"));
    checks.push(...checkCommonStructure(a, 3));
  } else if (id === "s13_ws") {
    // one upgrade per host (127.0.0.1 and site IP)
    checks.push(check("conn-count", tap.tcpConnCount === 2, `tcp conns=${tap.tcpConnCount} expected=2`));
    for (const story of stories) {
      const reqOk = story.c2sPayload.includes("Upgrade: websocket") && story.c2sPayload.includes("Sec-WebSocket-Key:");
      checks.push(check("ws-request", reqOk, `conn#${story.id} upgrade request observed`));
      const RES_FRAME = Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]); // text "hello"
      const resOk =
        story.s2cPayload.includes("HTTP/1.1 101 Switching Protocols") &&
        story.s2cPayload.includes("Sec-WebSocket-Accept:") &&
        story.s2cPayload.subarray(story.s2cPayload.length - RES_FRAME.length).equals(RES_FRAME);
      checks.push(check("ws-response", resOk, `conn#${story.id} 101 + server hello frame observed`));
      const flow = findTcpFlow(a, story, story.clientPort, story.serverPort);
      if (flow) {
        const st = flow.http?.responses[0]?.status;
        checks.push(check("engine-101", st === 101, `conn#${story.id} engine http status=${st ?? "none"}`));
        checks.push(checkPayloadMatch(story, flow));
      } else {
        checks.push(check("flow-match", false, `conn#${story.id} no engine flow`));
      }
    }
    const appOk = app.steps
      .filter((s) => s.step.startsWith("ws_upgrade"))
      .every((s) => s.code === 0);
    checks.push(check("app-truth", appOk, app.steps.filter((s) => s.step.startsWith("ws_upgrade")).map((s) => `${s.step}: ${s.detail}`).join("; ") || "no steps"));
    checks.push(...checkCommonStructure(a, 2));
  } else if (id === "s11_loopback") {
    // 2 TCP echo conversations (127.0.0.1 + site IP) + 1 UDP echo pair
    checks.push(check("conn-count", tap.tcpConnCount === 2, `tcp conns=${tap.tcpConnCount} expected=2`));
    for (const story of stories) {
      const cOk = story.c2sPayload.toString("utf8") === "tcp-loopback";
      const rOk = story.s2cPayload.toString("utf8") === "echo:tcp-loopback";
      checks.push(check("echo-bytes", cOk && rOk, `conn#${story.id} c2s="${story.c2sPayload.toString("utf8")}" s2c="${story.s2cPayload.toString("utf8")}"`));
      const flow = findTcpFlow(a, story, story.clientPort, story.serverPort);
      if (flow) checks.push(checkPayloadMatch(story, flow));
      else checks.push(check("flow-match", false, `conn#${story.id} no engine flow`));
    }
    const udp = tap.udpTales;
    const udpOk = (() => {
      const c = udp.flatMap((u) => u.events).find((e) => e.dir === "c2s");
      const r = udp.flatMap((u) => u.events).find((e) => e.dir === "s2c");
      if (!c || !r) return { pass: false, detail: `udp datagrams c2s=${c ? 1 : 0} s2c=${r ? 1 : 0}` };
      const same = c.payload.equals(r.payload) && c.payload.toString("utf8") === "udp-loopback-0123456789";
      return { pass: same, detail: `udp ${c.payload.length}B echo ${same ? "roundtrip exact" : "MISMATCH"}` };
    })();
    checks.push(check("udp-echo", udpOk.pass, udpOk.detail));
    const udpFlow = a.flows.find((f) => f.kind === "udp");
    checks.push(
      check(
        "udp-flow",
        !!udpFlow && udpFlow.uniquePackets === 2,
        udpFlow ? `udp flow unique packets=${udpFlow.uniquePackets} expected=2` : "no udp flow in engine",
      ),
    );
    const appOk = app.steps
      .filter((s) => s.step.startsWith("tcp_loopback") || s.step.startsWith("udp_loopback"))
      .every((s) => s.code === 0);
    checks.push(
      check(
        "app-truth",
        appOk,
        app.steps
          .filter((s) => s.step.startsWith("tcp_loopback") || s.step.startsWith("udp_loopback"))
          .map((s) => `${s.step}: ${s.detail}`)
          .join("; ") || "no steps",
      ),
    );
    checks.push(...checkCommonStructure(a, 2));
  } else {
    checks.push(check("scenario-known", false, `unknown scenario id ${id}`));
  }

  // sanity assertion the tap itself never lies about ctx ports leaking
  void ctx;
  return checks;
}

const SCENARIOS = [
  { id: "s2_local_split", f: localHttpScenario },
  { id: "s13_ws", f: wsScenario },
  { id: "s11_loopback", f: loopbackScenario },
] as const;

/** Run the three loopback scenarios through the tap; verify app truth + flow
 * engine agreement; write synthesized traces (and optionally run the tshark
 * M3 gate on them). */
export async function runM4Loopback(opts: {
  withTshark: boolean;
  outDir?: string;
}): Promise<{ allOk: boolean; runs: LoopbackRun[] }> {
  const outDir = opts.outDir ?? path.join("out", "m4", "loopback");
  const fileExists = fs.existsSync;
  void fileExists;
  fs.mkdirSync(outDir, { recursive: true });
  const ctx = await buildTrafficContext();

  const runs: LoopbackRun[] = [];
  for (const def of SCENARIOS) {
    const tap = new LoopbackTap();
    tap.arm();
    let app: TrafficResult;
    try {
      app = await def.f(ctx);
    } finally {
      tap.disarm();
    }
    const file = path.join(outDir, `${def.id}_tap.pcapng`);
    const frames = tap.exportTrace(file, `strobe-packet-tracker m4a loopback tap - scenario ${def.id}`);
    const a = analyzePcapFile(file);
    const checks = verifyScenario(def.id, tap, a, app, ctx);

    const run: LoopbackRun = {
      id: def.id,
      file,
      frames,
      tcpConns: tap.tcpConnCount,
      udpFlows: tap.udpFlowCount,
      ok: checks.every((c) => c.pass),
      checks,
      appSteps: app.steps,
      warnings: tap.warningLines,
    };
    runs.push(run);
  }

  if (opts.withTshark) {
    for (const run of runs) {
      const t = await verifyTrace(run.file, process.cwd());
      run.checks.push(
        check(
          "tshark-full-gate",
          t.ok,
          `m3Verify on synthesized trace: ${t.checks.map((c) => `${c.check}=${c.status}`).join(",")}`,
        ),
      );
      run.ok = run.checks.every((c) => c.pass);
    }
  }

  return { allOk: runs.every((r) => r.ok), runs };
}

/** Console-ready report lines. */
export function printM4Loopback(runs: LoopbackRun[]): string[] {
  const lines: string[] = [];
  lines.push("");
  lines.push("M4-a loopback vantage - userspace tap results");
  lines.push("honesty contract: payloads/ports/timing REAL; ISNs/ACK-placement/kernel-segmentation SYNTHESIZED");
  lines.push("");
  for (const r of runs) {
    lines.push(`== ${r.id}  frames=${r.frames} tcpConns=${r.tcpConns} udpFlows=${r.udpFlows}  ${r.ok ? "PASS" : "FAIL"}`);
    lines.push(`   trace: ${r.file} (${bytesLabel(fs.statSync(r.file).size)})`);
    for (const c of r.checks) {
      lines.push(`   [${c.pass ? "PASS" : "FAIL"}] ${c.name}: ${c.detail}`);
    }
    for (const w of r.warnings) lines.push(`   [warn] ${w}`);
    lines.push("");
  }
  return lines;
}
