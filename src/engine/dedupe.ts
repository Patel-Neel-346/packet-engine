// Shared M2/M3 analysis helpers so "what is one physical packet" cannot
// drift apart between the parity engine and the flow engine.
//
// Dedupe rule (verified in M2): same IP-level bytes (sha1 of the bytes from
// ipOffset onward — identical across ethernet / raw802.11 / bare-IP copies)
// AND capture timestamps within tolerance (measured 0.0 ms between copies
// even on loaded traces) = copies of one physical observation. A
// recent-per-hash map handles flood traffic where many packets separate
// adjacent copies (the naive 24-group backward scan under-merged under load).
//
// Layer:     engine — pure analysis (node:crypto hash only; no fs/net)
// Milestone: M2 — dedupe rule, shared with the M3 flow engine (docs/history/milestone-2-report.md)
// Verified:  tolerance cases unit-tested (test/flows.test.ts); drives both the parity metric and the flow unique view
// Exports:   decodeAllPackets, dedupePackets, ipHash, epbInterfaceLink

import crypto from "node:crypto";
import type { PcapngFile } from "./pcapng.ts";
import { packetTimestampSeconds } from "./pcapng.ts";
import { decodePacket } from "./decoder.ts";
import type { DecodedPacket } from "./decoder.ts";

export interface DuplicateGroup {
  packet: DecodedPacket;
  ts: number; // repr capture stamp (seconds)
  members: number[]; // EPB indexes
  reprIdx: number;
}

/** Link type of the EPB's capture interface (IDB), needed for decode. */
export function epbInterfaceLink(parsed: PcapngFile, interfaceId: number): number {
  const itf = parsed.interfaces[interfaceId];
  return itf?.linkType ?? 1;
}

/** Decode every EPB and attach the raw bytes for content-level hashing. */
export function decodeAllPackets(parsed: PcapngFile): DecodedPacket[] {
  return parsed.packets.map((epb, idx) => {
    const d = decodePacket(epbInterfaceLink(parsed, epb.interfaceId), epb.data, epb.origLen);
    (d as unknown as { __bytes: Buffer }).__bytes = epb.data;
    (d as unknown as { __frame: number }).__frame = idx;
    return d;
  });
}

/** sha1 over the IP-level bytes (from ipOffset onward) — identical across
 * ethernet / raw-802.11 / bare-IP copies of one physical packet; null when
 * the packet is not IP or its raw bytes are unavailable. */
export function ipHash(p: DecodedPacket): string | null {
  if (p.ipOffset < 0) return null;
  const buf = (p as unknown as { __bytes?: Buffer }).__bytes;
  if (!buf) return null;
  return crypto.createHash("sha1").update(buf.subarray(p.ipOffset)).digest("hex");
}

/** Group copies of one physical packet: same ipHash AND capture timestamps
 * within `toleranceUs` merge into one DuplicateGroup (representative = first
 * member); every EPB index survives in `members`. */
export function dedupePackets(
  parsed: PcapngFile,
  decoded: DecodedPacket[],
  toleranceUs = 2000,
): { groups: DuplicateGroup[]; duplicatesMerged: number } {
  const groups: DuplicateGroup[] = [];
  const recentByHash = new Map<string, DuplicateGroup>();
  for (let i = 0; i < decoded.length; i++) {
    const d = decoded[i];
    const h = ipHash(d);
    const t = packetTimestampSeconds(parsed.packets[i], parsed.interfaces);
    if (h === null) {
      groups.push({ packet: d, ts: t, members: [i], reprIdx: i });
      continue;
    }
    const cand = recentByHash.get(h);
    if (
      cand &&
      Math.abs(
        packetTimestampSeconds(parsed.packets[cand.reprIdx], parsed.interfaces) - t,
      ) * 1e6 <= toleranceUs
    ) {
      cand.members.push(i);
      recentByHash.set(h, cand); // latest occurrence wins for future diffs
    } else {
      const g = { packet: d, ts: t, members: [i], reprIdx: i };
      groups.push(g);
      recentByHash.set(h, g);
    }
  }
  return { groups, duplicatesMerged: decoded.length - groups.length };
}
