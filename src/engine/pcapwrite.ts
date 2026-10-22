// Minimal classic-libpcap writer — used by the M3 verification harness to
// export the DEDUPED packet view (epb subset, original wire order) so tshark
// can run its own retransmission analysis on exactly the packet population
// the flow engine analyzed (removes the ~2 duplicate-copy artifacts that made
// tshark's retrans count track copy structure rather than true retransmits).
//
// Constraint (verified): all pktmon/etl2pcap traces here have a single IDB
// with linktype Ethernet(1), so a single-linktype pcap is lossless for
// ethernet-framed members. Non-ethernet duplicates (raw80211-style copies)
// are skipped by the exporter and reported.
//
// Layer:     engine — pure serialization (Buffer out; caller does the I/O)
// Milestone: M3.3 — deduped-oracle export (docs/history/milestone-3-report.md)
// Verified:  consumed by the M3.3 retransmission gate — tshark reads its output
// Exports:   writeClassicPcap, dedupedEthernetChunks, PcapExportChunk

import type { PcapngFile } from "./pcapng.ts";
import { packetTimestampSeconds } from "./pcapng.ts";

export interface PcapExportChunk {
  data: Buffer; // raw frame bytes (as captured; capLen = data.length)
  origLen: number;
  /** Optional replacement timestamp (seconds); falls back to the EPB. */
  ts?: number;
}

const PCAP_MAGIC = 0xa1b2c3d4;

/** Serialize chunks to a classic-libpcap (v2.4) file buffer: one global
 * header + one record per chunk. */
export function writeClassicPcap(
  chunks: PcapExportChunk[],
  linkType: number,
  /** Timestamps by chunk when omitted from the chunks themselves. */
  tsFallback?: number[],
): Buffer {
  const parts: Buffer[] = [];
  const gh = Buffer.alloc(24);
  gh.writeUInt32LE(PCAP_MAGIC, 0);
  gh.writeUInt16LE(2, 4); // version 2.4
  gh.writeUInt16LE(4, 6);
  gh.writeInt32LE(0, 8); // thiszone
  gh.writeUInt32LE(0, 12); // sigfigs
  gh.writeUInt32LE(262144, 16); // snaplen
  gh.writeUInt32LE(linkType, 20);
  parts.push(gh);
  for (let i = 0; i < chunks.length; i++) {
    const ch = chunks[i];
    const ts = ch.ts ?? (tsFallback ? tsFallback[i] : 0);
    const sec = Math.floor(ts);
    const usec = Math.round((ts - sec) * 1e6);
    const ph = Buffer.alloc(16);
    ph.writeUInt32LE(sec >>> 0, 0);
    // clamp usec (round could give 1e6)
    ph.writeUInt32LE(Math.min(usec, 999999) >>> 0, 4);
    ph.writeUInt32LE(ch.data.length >>> 0, 8);
    ph.writeUInt32LE(ch.origLen >>> 0, 12);
    parts.push(ph, ch.data);
  }
  return Buffer.concat(parts);
}

/** One ethernet-framed representative per dedupe group, in trace order. */
export function dedupedEthernetChunks(
  parsed: PcapngFile,
  decodeWithFrame: (idx: number) => { framing: string } | null,
  groups: Array<{ members: number[] }>,
): { chunks: PcapExportChunk[]; kept: number[]; skipped: number } {
  const chunks: PcapExportChunk[] = [];
  const kept: number[] = [];
  let skipped = 0;
  for (const g of groups) {
    let picked: number | null = null;
    for (const m of g.members) {
      if (decodeWithFrame(m)?.framing === "ethernet") {
        picked = m;
        break;
      }
    }
    if (picked === null) {
      skipped++;
      continue;
    }
    const epb = parsed.packets[picked];
    chunks.push({
      data: epb.data,
      origLen: epb.origLen,
      ts: packetTimestampSeconds(epb, parsed.interfaces),
    });
    kept.push(picked);
  }
  return { chunks, kept, skipped };
}
