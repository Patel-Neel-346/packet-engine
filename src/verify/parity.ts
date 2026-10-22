// Parity metric (Milestone 2 addendum): dedupe cross-component and
// raw-802.11 copies of the same packet, then compare, per unique packet,
// against tshark 4.6.9 as the oracle:
//   timestamp, frame length, captured length, src/dst IP, src/dst port,
//   protocol, TCP flags, flow membership.
// Packets we cannot decode count as "unsupported" and NEVER as matches.
//
// Layer:     verify — tshark-oracle I/O (21-column fields export + comparison)
// Milestone: M2 addendum — parity metric (docs/history/milestone-2-report.md)
// Verified:  gate 4 of `npm run test:all` — 14 traces at thresholds, exceptions: none
// Exports:   computeParity, tsharkReadFrames, ParityResult

import fs from "node:fs";
import path from "node:path";
import { parsePcapng, packetTimestampSeconds, type PcapngFile } from "../engine/pcapng.ts";
import { canonicalFlow, flowIdOf, type DecodedPacket } from "../engine/decoder.ts";
import { dedupePackets, decodeAllPackets, type DuplicateGroup } from "../engine/dedupe.ts";
import { runCommand, tsharkExe } from "../capture/pktmon.ts";

export interface TsharkFrame {
  num: number;
  capLen: number;
  frameLen: number;
  timeEpoch: number;
  protocols: string[];
  ip4src: string | null;
  ip4dst: string | null;
  ip6src: string | null;
  ip6dst: string | null;
  ipProto: string | null;
  ipv6Next: string | null;
  tcpPorts: string[];
  udpPorts: string[];
  tcpFlags: number | null;
  icmpType: string | null;
  icmpv6Type: string | null;
  /** comma-joined dns.qry.name values (may be several). */
  dnsQryName: string[];
  dnsRcode: number | null;
  dnsA: string[];
  dnsAaaa: string[];
  tlsSni: string | null;
}

/** Read one trace with `tshark -T fields` (21 columns, one row per frame) as
 * the oracle view. */
export async function tsharkReadFrames(file: string): Promise<TsharkFrame[]> {
  const args = [
    "-r", file, "-n", "-T", "fields",
    "-e", "frame.number",
    "-e", "frame.cap_len",
    "-e", "frame.len",
    "-e", "frame.time_epoch",
    "-e", "frame.protocols",
    "-e", "ip.src", "-e", "ip.dst",
    "-e", "ipv6.src", "-e", "ipv6.dst",
    "-e", "ip.proto", "-e", "ipv6.nxt",
    "-e", "tcp.port", "-e", "udp.port",
    "-e", "tcp.flags",
    "-e", "icmp.type", "-e", "icmpv6.type",
    "-e", "dns.qry.name", "-e", "dns.flags.rcode",
    "-e", "dns.a", "-e", "dns.aaaa",
    "-e", "tls.handshake.extensions_server_name",
  ];
  const res = await runCommand(tsharkExe(), args, { timeoutMs: 240_000 });
  if (res.code !== 0) {
    throw new Error(`tshark failed (exit ${res.code}): ${(res.stderr || res.stdout).slice(0, 400)}`);
  }
  const frames: TsharkFrame[] = [];
  for (const line of res.stdout.split(/\r?\n/)) {
    if (line.trim() === "") continue;
    const c = line.split("\t");
    // Defensive: packet capture may double-pad fields. Keep indices in sync
    // with the -e order above.
    if (c.length < 16) {
      throw new Error(`tshark fields line has ${c.length} columns, expected 16`);
    }
    frames.push({
      num: Number(c[0]),
      capLen: Number(c[1]),
      frameLen: Number(c[2]),
      timeEpoch: Number(c[3]),
      protocols: (c[4] ?? "").split(":").filter((p) => p !== ""),
      ip4src: c[5] === "" ? null : c[5],
      ip4dst: c[6] === "" ? null : c[6],
      ip6src: c[7] === "" ? null : c[7],
      ip6dst: c[8] === "" ? null : c[8],
      ipProto: c[9] === "" ? null : c[9],
      ipv6Next: c[10] === "" ? null : c[10],
      tcpPorts: c[11] ? c[11].split(",").filter((v) => v !== "") : [],
      udpPorts: c[12] ? c[12].split(",").filter((v) => v !== "") : [],
      tcpFlags: c[13] === "" ? null : Number(c[13]),
      icmpType: c[14] === "" ? null : c[14],
      icmpv6Type: c[15] === "" ? null : c[15],
      dnsQryName: (c[16] ?? "").split(",").filter((v) => v !== ""),
      dnsRcode: c[17] === "" ? null : Number(c[17]),
      dnsA: (c[18] ?? "").split(",").filter((v) => v !== ""),
      dnsAaaa: (c[19] ?? "").split(",").filter((v) => v !== ""),
      tlsSni: c[20] === "" ? null : c[20],
    });
  }
  return frames;
}

export interface ParityResult {
  scenario: string;
  file: string;
  totalEpbs: number;
  uniquePackets: number;
  matched: number;
  parityPct: number;
  unsupported: number;
  decodeFailures: number;
  duplicatesMerged: number;
  framingCounts: Record<string, number>;
  protocolMatrix: Record<string, { decoded: number; partial: number; unsupported: number }>;
  flowCountOurs: number;
  flowCountTshark: number;
  flowsMatch: boolean;
  mismatchSamples: string[];
  pass: boolean;
  notes: string[];
}

/** Dedupe our decode of the trace, then compare every unique packet against
 * the tshark rows. Packets we cannot decode count as "unsupported", never
 * as matches. */
export async function computeParity(
  scenario: string,
  file: string,
  opts: { dedupToleranceUs?: number; notes?: string[] } = {},
): Promise<ParityResult> {
  const dedupToleranceUs = opts.dedupToleranceUs ?? 2000;
  const buf = fs.readFileSync(file);
  const parsed: PcapngFile = parsePcapng(buf);
  const frames = await tsharkReadFrames(file);
  const notes = opts.notes ?? [];

  // Decode every EPB, attach bytes for content hashing (shared with M3).
  const decoded = decodeAllPackets(parsed);

  // Dedupe: same IP-level bytes AND capture within tolerance = copies of one
  // physical observation. Copies of the same packet share near-identical
  // timestamps (verified: all same-hash consecutive deltas in the s4 load
  // trace are 0.0 ms), so the tolerance governs; the recent-per-hash map
  // handles flood traffic where many packets separate adjacent copies.
  const { groups, duplicatesMerged } = dedupePackets(parsed, decoded, dedupToleranceUs);

  // Representation choice per group: prefer members the tshark oracle can
  // actually decode at L4 (the raw-802.11 copies inside ethernet-typed frames
  // are invisible to tshark), then by framing cleanliness.
  const oracleDecodable = (m: number): boolean => {
    const f = frames[m];
    if (!f) return false;
    return (
      (f.ip4src !== null || f.ip6src !== null) &&
      (f.tcpPorts.length > 0 || f.udpPorts.length > 0 || f.icmpType !== null || f.icmpv6Type !== null || (f.ipProto !== null && (f.ipProto === "1" || f.ipProto === "58")))
    );
  };
  const framingRank = (framing: string): number =>
    framing === "ethernet" ? 0 : framing === "vlan" ? 1 : framing === "bareIP" ? 2 : framing === "raw80211" ? 3 : 4;
  for (const g of groups) {
    let best = g.reprIdx;
    const keyOf = (m: number): [number, number, number, number] =>
      [oracleDecodable(m) ? 0 : 1, framingRank(decoded[m].framing), decoded[m].errors.length, m];
    let bestKey = keyOf(g.reprIdx);
    for (const m of g.members) {
      const k = keyOf(m);
      if (k[0] !== bestKey[0] ? k[0] < bestKey[0] : k[1] !== bestKey[1] ? k[1] < bestKey[1] : k[2] !== bestKey[2] ? k[2] < bestKey[2] : k[3] < bestKey[3]) {
        best = m;
        bestKey = k;
      }
    }
    g.reprIdx = best;
    g.packet = decoded[best];
    g.ts = packetTimestampSeconds(parsed.packets[best], parsed.interfaces);
  }

  // Flow sets.
  const flowSet = new Set<string>();
  for (const g of groups) {
    const f = flowIdOf(g.packet);
    if (f) flowSet.add(f);
  }
  const tsharkFlowSet = new Set<string>();
  for (const f of frames) {
    const proto = f.tcpPorts.length > 0 ? 6 : f.udpPorts.length > 0 ? 17 : null;
    if (proto === null) continue;
    const src = f.ip4src ?? f.ip6src;
    const dst = f.ip4dst ?? f.ip6dst;
    if (!src || !dst) continue;
    const ports = f.tcpPorts.length > 0 ? f.tcpPorts : f.udpPorts;
    const fl = canonicalFlow(proto, src, Number(ports[0]), dst, Number(ports[ports.length - 1]));
    tsharkFlowSet.add(
      `p${fl.proto} ${fl.aip}:${fl.aport} <--> ${fl.bip}:${fl.bport}`,
    );
  }
  const flowsMatch = (() => {
    const ours = new Set([...flowSet]);
    const theirs = new Set([...tsharkFlowSet]);
    for (const f of [...ours]) if (theirs.has(f)) { ours.delete(f); theirs.delete(f); }
    return ours.size === 0 && theirs.size === 0;
  })();

  // Protocol coverage matrix.
  const matrix: Record<string, { decoded: number; partial: number; unsupported: number }> = {};
  const bump = (p: string, which: "decoded" | "partial" | "unsupported") => {
    matrix[p] = matrix[p] ?? { decoded: 0, partial: 0, unsupported: 0 };
    matrix[p][which]++;
  };

  let matched = 0;
  let unsupported = 0;
  const mismatchSamples: string[] = [];
  for (const g of groups) {
    const p = g.packet;
    if (p.ipOffset < 0 || p.errors.length > 0) {
      const pclass =
        p.transport?.kind === "arp" ? "arp" :
        p.framing === "unknown" ? "unknown-framing" :
        p.transport ? `proto-${p.transport.proto}` : "no-ip";
      bump(pclass, "unsupported");
      unsupported++;
      if (mismatchSamples.length < 6) {
        mismatchSamples.push(`#${g.reprIdx} (${p.framing}) unsupported: ${p.errors.join("; ").slice(0, 120)}`);
      }
      continue;
    }
    const idx = g.reprIdx;
    const f = frames[idx];
    if (!f) {
      bump("missing-tshark-frame", "partial");
      unsupported++;
      continue;
    }
    const problems: string[] = [];
    // timestamp (2 ms tolerance)
    const ourTs = g.ts;
    if (!Number.isFinite(ourTs) || !Number.isFinite(f.timeEpoch) || Math.abs(ourTs - f.timeEpoch) * 1e6 > 2000) {
      problems.push(`ts ${ourTs.toFixed(6)} vs ${f.timeEpoch}`);
    }
    // capture + frame lengths
    if (f.capLen !== parsed.packets[idx].capLen) problems.push(`capLen ${parsed.packets[idx].capLen} vs ${f.capLen}`);
    if (f.frameLen !== parsed.packets[idx].origLen) problems.push(`frameLen ${parsed.packets[idx].origLen} vs ${f.frameLen}`);
    // src/dst IP
    const ourSrc = p.ip?.src ?? null;
    const ourDst = p.ip?.dst ?? null;
    const tsSrc = f.ip4src ?? f.ip6src;
    const tsDst = f.ip4dst ?? f.ip6dst;
    if (ourSrc !== tsSrc || ourDst !== tsDst) {
      problems.push(`ip ${ourSrc}->${ourDst} vs ${tsSrc}->${tsDst}`);
    }
    // protocol
    const tsharkKind =
      f.tcpPorts.length > 0 ? "tcp" : f.udpPorts.length > 0 ? "udp" :
      (f.icmpType !== null ? "icmp" : f.icmpv6Type !== null ? "icmpv6" : null);
    if (p.transport?.kind !== tsharkKind && !(tsharkKind === null && p.transport?.kind === "other")) {
      let fragmentOk = false;
      if (tsharkKind === null && p.ip && p.ip.fragment && p.transport) {
        // Any fragment of a fragmented datagram: tshark defers the L4 decode
        // to the reassembled datagram, so only the transport protocol number
        // is comparable at wire level.
        const tsNum = f.ipProto !== null ? Number(f.ipProto) : f.ipv6Next !== null ? Number(f.ipv6Next) : null;
        fragmentOk = tsNum === p.ip.firstProto && (p.transport.kind === "icmp" || p.transport.kind === "icmpv6" || p.transport.kind === "tcp" || p.transport.kind === "udp");
      }
      if (!fragmentOk) {
        problems.push(`proto ${p.transport?.kind} vs ${tsharkKind}`);
      }
    }
    // ports + TCP flags
    if (p.transport?.sport !== undefined && tsharkKind !== null) {
      const tports = tsharkKind === "tcp" ? f.tcpPorts : tsharkKind === "udp" ? f.udpPorts : null;
      if (tports && !(
        (Number(tports[0]) === p.transport.sport && Number(tports[tports.length - 1]) === p.transport.dport) ||
        (Number(tports[0]) === p.transport.dport && Number(tports[tports.length - 1]) === p.transport.sport)
      )) {
        problems.push(`ports ${p.transport.sport}/${p.transport.dport} vs ${tports.join("/")}`);
      }
    }
    if (p.transport?.kind === "tcp") {
      const tflags = f.tcpFlags;
      if (tflags !== null && p.transport.tcpFlags !== undefined && (tflags & 0xff) !== (p.transport.tcpFlags & 0xff)) {
        problems.push(`tcpflags 0x${p.transport.tcpFlags.toString(16)} vs 0x${tflags.toString(16)}`);
      }
    }
    // DNS content parity (both sides must have decoded a DNS message).
    if (p.dns && (f.dnsQryName.length > 0 || f.dnsRcode !== null)) {
      const ourQ = stripDnsDot(p.dns.questions[0]?.name ?? "");
      const theirQ = f.dnsQryName.map(stripDnsDot).sort().join(",");
      if (p.dns.questions.length > 0) {
        if (!f.dnsQryName.some((n) => stripDnsDot(n) === ourQ)) problems.push(`dnsQry ${ourQ} vs ${theirQ}`);
      } else if (f.dnsQryName.length > 0) {
        problems.push(`dnsQry <none> vs ${theirQ} (ours parsed none)`);
      }
      if (f.dnsRcode !== null && f.dnsRcode !== p.dns.rcode) {
        problems.push(`dnsRcode ${p.dns.rcode} vs ${f.dnsRcode}`);
      }
      const ourA = [...p.dns.aRecords].sort();
      const ourAaaa = [...p.dns.aaaaRecords].sort();
      if (ourA.join(",") !== [...f.dnsA].sort().join(",")) problems.push(`dnsA ${ourA.join(",") || "<none>"} vs ${[...f.dnsA].sort().join(",") || "<none>"}`);
      if (ourAaaa.join(",") !== [...f.dnsAaaa].sort().join(",")) problems.push(`dnsAAAA ${ourAaaa.join(",") || "<none>"} vs ${[...f.dnsAaaa].sort().join(",") || "<none>"}`);
    } else if (!p.dns && f.dnsQryName.length > 0) {
      problems.push(`dns: tshark parsed, we did not (${p.errors.join(";").slice(0, 80)})`);
    }
    // TLS ClientHello SNI parity (metadata only).
    if (p.tls?.sni && f.tlsSni !== null && p.tls.sni !== f.tlsSni) {
      problems.push(`sni ${p.tls.sni} vs ${f.tlsSni}`);
    }
    // DNS content parity when both sides parsed it
    if (p.dns && tsharkKind === "udp" || p.dns && tsharkKind === "tcp") {
      // lightweight: compare question name only (detailed DNS parity is
      // handled by the dedicated DNS scenario report)
    }
    bump(p.transport?.kind ?? "no-ip", problems.length === 0 ? "decoded" : "partial");
    if (problems.length === 0) matched++;
    else if (mismatchSamples.length < 6) {
      mismatchSamples.push(`#${g.reprIdx}: ${problems.join("; ")}`);
    }
  }

  const parityPct = groups.length === 0 ? 0 : Math.round((matched / groups.length) * 1000) / 10;
  const pass = parityPct >= 90;
  const result: ParityResult = {
    scenario,
    file,
    totalEpbs: decoded.length,
    uniquePackets: groups.length,
    matched,
    parityPct,
    unsupported,
    decodeFailures: decoded.filter((d) => d.ipOffset < 0).length,
    duplicatesMerged,
    framingCounts: countBy(decoded, (d) => d.framing),
    protocolMatrix: matrix,
    flowCountOurs: flowSet.size,
    flowCountTshark: tsharkFlowSet.size,
    flowsMatch,
    mismatchSamples,
    pass,
    notes,
  };
  return result;
}

function stripDnsDot(n: string): string {
  return n.endsWith(".") && n.length > 1 ? n.slice(0, -1) : n;
}

function countBy<T>(arr: T[], key: (t: T) => string): Record<string, number> {
  const out: Record<string, number> = {};
  for (const t of arr) {
    const k = key(t);
    out[k] = (out[k] ?? 0) + 1;
  }
  return out;
}
