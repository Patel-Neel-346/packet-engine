// Milestone 1 verification: independent cross-check of the pktmon-exported
// PCAPNG.
//   1. Parse out/m1.pcapng with our own pure-TS pcapng parser.
//   2. Read the same file with tshark (Wireshark 4.6.9) as an independent
//      implementation.
//   3. Compare counts, per-frame cap_len/orig_len/timestamps, and report
//      protocol/flow/duplicate/truncation facts.
// Nothing is claimed unless it was actually computed and printed here.
//
// Layer:     verify — tshark-oracle I/O (reads the trace twice: our parser + tshark)
// Milestone: M1 — capture-path cross-check (docs/history/milestone-1-report.md)
// Verified:  gate 3 of `npm run test:all` (96 frames, 0 mismatches on the baseline trace)
// Exports:   m1Verify

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import {
  parsePcapng,
  packetTimestampSeconds,
  linkTypeName,
  type PcapngFile,
} from "../engine/pcapng.ts";
import { runCommand, tsharkExe } from "../capture/pktmon.ts";

const REPO = path.resolve(import.meta.dirname, "..", "..");
const OUT = path.join(REPO, "out");
const PCAPNG = path.join(OUT, "m1.pcapng");
const REPORT = path.join(OUT, "m1-verify.json");

interface TsharkFrame {
  num: number;
  capLen: number;
  frameLen: number;
  timeEpoch: number;
  ethType: string | null;
  ipProto: string | null;
  ipv6Next: string | null;
  tcpPorts: string[];
  udpPorts: string[];
  src: string | null;
  dst: string | null;
  /** tshark's decoded layer stack, e.g. ["eth","ethertype:ipv6","ipv6","tcp"] */
  protocols: string[];
}

async function tsharkReadFrames(file: string): Promise<TsharkFrame[]> {
  const args = [
    "-r",
    file,
    "-n",
    "-T",
    "fields",
    "-e",
    "frame.number",
    "-e",
    "frame.cap_len",
    "-e",
    "frame.len",
    "-e",
    "frame.time_epoch",
    "-e",
    "eth.type",
    "-e",
    "ip.proto",
    "-e",
    "ipv6.nxt",
    "-e",
    "tcp.port",
    "-e",
    "udp.port",
    "-e",
    "ip.src",
    "-e",
    "ip.dst",
    "-e",
    "ipv6.src",
    "-e",
    "ipv6.dst",
    "-e",
    "frame.protocols",
  ];
  const res = await runCommand(tsharkExe(), args, { timeoutMs: 180_000 });
  if (res.code !== 0) {
    throw new Error(
      `tshark failed (exit ${res.code}): ${res.stderr.slice(0, 500) || res.stdout.slice(0, 500)}`,
    );
  }
  const frames: TsharkFrame[] = [];
  for (const line of res.stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const c = line.split("\t");
    const ip4 = (c[9] ?? "") + "," + (c[10] ?? "");
    const ip6 = (c[11] ?? "") + "," + (c[12] ?? "");
    const pair = ip4.length > 1 ? ip4 : ip6;
    const [src, dst] = pair.split(",");
    frames.push({
      num: Number(c[0]),
      capLen: Number(c[1]),
      frameLen: Number(c[2]),
      timeEpoch: Number(c[3]),
      ethType: c[4] === "" ? null : c[4],
      ipProto: c[5] === "" ? null : c[5],
      ipv6Next: c[6] === "" ? null : c[6],
      tcpPorts: c[7] ? c[7].split(",").filter((x) => x !== "") : [],
      udpPorts: c[8] ? c[8].split(",").filter((x) => x !== "") : [],
      src: src === "" ? null : src,
      dst: dst === "" ? null : dst,
      protocols: (c[13] ?? "").split(":").filter((p) => p !== ""),
    });
  }
  return frames;
}

interface FlowKey {
  proto: string;
  src: string;
  sport: number;
  dst: string;
  dport: number;
}

function canonicalFlow(
  proto: string,
  src: string,
  sport: number,
  dst: string,
  dport: number,
): FlowKey {
  // Normalized so both directions map to the same flow ID (port/address sort).
  const a = `${src}:${sport}`;
  const b = `${dst}:${dport}`;
  return a <= b
    ? { proto, src, sport, dst, dport }
    : { proto, src: dst, sport: dport, dst: src, dport: sport };
}

function flowId(f: FlowKey): string {
  return `${f.proto} ${f.src}:${f.sport} <--> ${f.dst}:${f.dport}`;
}

/** Cross-check out/m1.pcapng frame-by-frame against tshark (counts,
 * cap_len/orig_len/timestamps). Returns a process exit code. */
export async function m1Verify(): Promise<number> {
  if (!fs.existsSync(PCAPNG)) {
    console.log(`Missing ${PCAPNG}. Run: npm run m1:capture`);
    return 3;
  }
  const buf = fs.readFileSync(PCAPNG);
  const parsed: PcapngFile = parsePcapng(buf);

  console.log("== Our PCAPNG parse ==");
  console.log(
    `SHB: v${parsed.shb?.majorVersion ?? "?"}.${parsed.shb?.minorVersion ?? "?"} littleEndian=${parsed.shb?.littleEndian}`,
  );
  for (const ifc of parsed.interfaces) {
    console.log(
      `IDB#${ifc.id}: linkType=${ifc.linkType} (${linkTypeName(ifc.linkType)}) snaplen=${ifc.snaplen} if_tsresol=${ifc.tsResolRaw} name=${JSON.stringify(ifc.name)}`,
    );
  }
  console.log(
    `EPBs: ${parsed.packets.length} | skipped blocks: ${JSON.stringify(parsed.skippedBlocks)} | parse errors: ${parsed.parseErrors.length}`,
  );
  for (const e of parsed.parseErrors) {
    console.log(`  PARSE ERROR @${e.offset}: ${e.message}`);
  }

  console.log("\n== tshark (independent tool) readback ==");
  const ver = await runCommand(tsharkExe(), ["--version"], { timeoutMs: 30_000 });
  if (ver.code !== 0) {
    console.log(`tshark not usable: exit=${ver.code} ${ver.stderr.slice(0, 200)}`);
    return 3;
  }
  console.log(ver.stdout.split(/\r?\n/)[0]);
  const frames = await tsharkReadFrames(PCAPNG);
  console.log(`tshark frames: ${frames.length}`);

  // --- Frame-by-frame comparison ---
  let mismatches = 0;
  let maxTimeDeltaUs = 0;
  const mismatchSamples: string[] = [];
  const n = Math.min(frames.length, parsed.packets.length);
  if (frames.length !== parsed.packets.length) {
    console.log(
      `COUNT MISMATCH: our EPBs=${parsed.packets.length} tshark frames=${frames.length}`,
    );
    mismatches++;
  }
  for (let i = 0; i < n; i++) {
    const ours = parsed.packets[i];
    const ts = packetTimestampSeconds(ours, parsed.interfaces);
    const f = frames[i];
    const capOk = ours.capLen === f.capLen;
    const origOk = ours.origLen === f.frameLen;
    const deltaUs = Math.round(Math.abs(ts - f.timeEpoch) * 1e6);
    maxTimeDeltaUs = Math.max(maxTimeDeltaUs, deltaUs);
    const timeOk = deltaUs <= 2;
    if (!capOk || !origOk || !timeOk) {
      mismatches++;
      if (mismatchSamples.length < 10) {
        mismatchSamples.push(
          `#${f.num} ours(cap=${ours.capLen},orig=${ours.origLen}) tshark(cap=${f.capLen},len=${f.frameLen}) dt=${deltaUs}us`,
        );
      }
    }
  }
  console.log(
    `Compare: ${n} frames, mismatches=${mismatches}, max time delta=${maxTimeDeltaUs}us (tolerance 2us)`,
  );
  for (const s of mismatchSamples) console.log(`  MISMATCH ${s}`);

  // --- Truncation fact ---
  const truncated = parsed.packets.filter((p) => p.capLen < p.origLen).length;
  console.log(
    `Truncation: capLen < origLen on ${truncated} frames (0 means pktmon logged full packets; --pkt-size 0 was used)`,
  );

  // --- Decode sanity using tshark's own layer stack (independent oracle) ---
  const ethFrames = frames.filter((f) => f.protocols[0] === "eth").length;
  const bareL3 = frames.length - ethFrames;
  console.log(
    `Layer check: ${ethFrames} frames decoded with a full Ethernet L2 stack, ${bareL3} decoded as bare L3 packets (no L2 header; pktmon TCPIP-protocol components log IP packets without the Ethernet header)`,
  );

  // --- Filter-scope check (Test D lite): what is actually in the capture ---
  const portSets: Record<string, number> = {};
  const flows = new Map<string, FlowKey>();
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];
    let proto = "other";
    let ports: string[] = [];
    if (f.tcpPorts.length > 0) {
      proto = "tcp";
      ports = f.tcpPorts;
    } else if (f.udpPorts.length > 0) {
      proto = "udp";
      ports = f.udpPorts;
    }
    const k = ports.join(",");
    portSets[`${proto}:${k}`] = (portSets[`${proto}:${k}`] ?? 0) + 1;
    if (proto !== "other" && f.src && f.dst) {
      const sport = Number(ports[0] ?? 0);
      const dport = Number(ports[ports.length - 1] ?? 0);
      const flow = canonicalFlow(
        proto,
        f.src,
        sport,
        f.dst,
        dport,
      );
      flows.set(flowId(flow), flow);
    }
  }
  console.log(`Port distribution: ${JSON.stringify(portSets)}`);
  console.log(`Distinct flows observed: ${flows.size}`);
  for (const id of [...flows.keys()].slice(0, 12)) console.log(`  flow ${id}`);
  const inScope = frames.length - (portSets["other:"] ?? 0);
  console.log(
    `Scope: ${inScope}/${frames.length} frames carry TCP or UDP (filter allows only TCP 443 to example.org and UDP 53)`,
  );

  // --- Duplicate observation check (multi-component duplicates, Test G lite) ---
  // Two duplicate notions:
  //   (a) byte-identical packets (same ts + len + sha1 of bytes)
  //   (b) same event duplicated at a different capture point: same timestamp
  //       (and close lengths) but possibly different framing (L2 header added
  //       or stripped by the component).
  const seen = new Map<string, number>();
  for (const p of parsed.packets) {
    const h = crypto.createHash("sha1").update(p.data).digest("hex");
    const key = `${p.tsHigh}:${p.tsLow}:${p.origLen}:${h}`;
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  const dupGroups = [...seen.entries()].filter(([, c]) => c > 1).length;
  const dupFrames = [...seen.values()].reduce((a, c) => (c > 1 ? a + c : a), 0);
  const tsSeen = new Map<string, number>();
  for (const p of parsed.packets) {
    const key = `${p.tsHigh}:${p.tsLow}`;
    tsSeen.set(key, (tsSeen.get(key) ?? 0) + 1);
  }
  const tsDupGroups = [...tsSeen.entries()].filter(([, c]) => c > 1).length;
  const tsDupFrames = [...tsSeen.values()].reduce((a, c) => (c > 1 ? a + c : a), 0);
  console.log(
    `Duplicates: byte-identical groups=${dupGroups} covering ${dupFrames} frames; same-timestamp groups=${tsDupGroups} covering ${tsDupFrames} frames (cross-component re-observations)`,
  );

  const pass =
    mismatches === 0 && frames.length === parsed.packets.length;

  console.log(`\n[VERIFY] ${pass ? "PASS" : "FAIL"} (mismatches=${mismatches})`);
  fs.writeFileSync(
    REPORT,
    JSON.stringify(
      {
        shb: parsed.shb,
        interfaces: parsed.interfaces,
        epbs: parsed.packets.length,
        tsharkFrames: frames.length,
        mismatches,
        maxTimeDeltaUs,
        truncated,
        parseErrors: parsed.parseErrors,
        portSets,
        flows: [...flows.keys()],
        ethFrames,
        bareL3,
        dupGroups,
        dupFrames,
        tsDupGroups,
        tsDupFrames,
        pass,
      },
      (_k, v) => (typeof v === "bigint" ? Number(v) : v),
      2,
    ),
    "utf8",
  );
  console.log(`Report JSON: ${REPORT}`);
  return pass ? 0 : 3;
}
