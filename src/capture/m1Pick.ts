// Artifact-side pick: after a capture, classify each per-component PCAPNG
// (out/m1_comp<id>.pcapng) with tshark's decoded layer stack and select the
// component that yields the most fully decoded frames as the primary trace
// (out/m1.pcapng). Uses only documented tshark fields/flags.
//
// Background fact recorded earlier: pktmon TCPIP-protocol components log
// bare IP packets (no Ethernet header) while filter components log full
// Ethernet frames, so this pick matters after each machine-specific run.
//
// Layer:     capture — artifact-side analysis (tshark-assisted)
// Milestone: M1 — trace pick (docs/history/milestone-1-report.md)
// Verified:  picked out/m1.pcapng used by the M1/M3 verification gates on this machine
// Exports:   m1Pick

import fs from "node:fs";
import path from "node:path";
import { parsePcapng } from "../engine/pcapng.ts";
import { runCommand, tsharkExe } from "./pktmon.ts";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const OUT = path.join(REPO, "out");

interface CompStats {
  file: string;
  compId: number;
  epbs: number;
  ethFrames: number;
  bareL3: number;
  ipFrames: number;
}

async function compStats(file: string): Promise<
  Omit<CompStats, "file" | "compId">
> {
  const res = await runCommand(
    tsharkExe(),
    [
      "-r",
      file,
      "-n",
      "-T",
      "fields",
      "-e",
      "frame.protocols",
      "-e",
      "ip.src",
      "-e",
      "ipv6.src",
    ],
    { timeoutMs: 120_000 },
  );
  if (res.code !== 0) {
    throw new Error(`tshark failed on ${file}: ${res.stderr.slice(0, 300)}`);
  }
  let ethFrames = 0;
  let bareL3 = 0;
  let ipFrames = 0;
  for (const line of res.stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const c = line.split("\t");
    const layers = (c[0] ?? "").split(":").filter((p) => p !== "");
    if (layers[0] === "eth") {
      ethFrames++;
    } else {
      bareL3++;
    }
    if ((c[1] ?? "") !== "" || (c[2] ?? "") !== "") ipFrames++;
  }
  return { epbs: parsePcapng(fs.readFileSync(file)).packets.length, ethFrames, bareL3, ipFrames };
}

/** Classify the per-component traces (out/m1_comp<id>.pcapng) and copy the
 * best-decoded one to out/m1.pcapng. Returns a process exit code. */
export async function m1Pick(): Promise<number> {
  const compFiles = fs
    .readdirSync(OUT)
    .filter((f) => /^m1_comp(\d+)\.pcapng$/.test(f));
  if (compFiles.length === 0) {
    console.log("No m1_comp*.pcapng artifacts. Run: npm run m1:capture");
    return 3;
  }
  console.log("== Per-component trace quality (tshark layer stack) ==");
  const rows: CompStats[] = [];
  for (const f of compFiles) {
    const m = f.match(/^m1_comp(\d+)\.pcapng$/);
    const compId = Number(m![1]);
    const file = path.join(OUT, f);
    const s = await compStats(file);
    rows.push({ file, compId, ...s });
    console.log(
      `  comp ${compId}: packets=${s.epbs} fullL2=${s.ethFrames} bareL3=${s.bareL3} decodedIP=${s.ipFrames}`,
    );
  }
  // Prefer most full-L2 frames; tie-break on total IP-decoded frames.
  const best = [...rows].sort(
    (a, b) => b.ethFrames - a.ethFrames || b.ipFrames - a.ipFrames,
  )[0];
  const target = path.join(OUT, "m1.pcapng");
  fs.copyFileSync(best.file, target);
  console.log(
    `Selected component ${best.compId} (${path.basename(best.file)}) -> ${target}`,
  );
  return 0;
}
