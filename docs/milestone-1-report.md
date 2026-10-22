# Milestone 1 report — capture + independent verification

Goal: capture a controlled HTTPS exchange with in-box pktmon, export PCAPNG,
verify the trace with an independent tool (tshark 4.6.9). Status: **complete**
(verified 2026-10-21).

## What ran (exact commands)

| Purpose | Command | Result recorded |
|---|---|---|
| Install deps | `npm install --no-fund --no-audit` (in `strobe-packet-tracker/`) | 3 packages |
| Typecheck | `npm run typecheck` (`tsc --noEmit`) | clean |
| Capture (needs 1 UAC approval) | `node src/cli.ts m1-capture` | see actual results |
| Pick best per-component trace | `node src/cli.ts m1-pick` | selected comp 36 |
| Independent verification | `node src/cli.ts m1-verify` | PASS, 0 mismatches |

The elevated capture bundle (generated `out/m1.ps1`, one UAC prompt) does, in
order, with every step and its **real output** recorded to `out/m1.log`:

1. `pktmon stop` (clean state; prints "Packet Monitor is not running." first run)
2. `pktmon filter remove`
3. `pktmon list --json` → `out/components.json`
4. `Resolve-DnsName example.org` (A + AAAA) → 104.20.26.136, 172.66.157.237,
   2606:4700:90d6:6c5e:b142:56e:525:2b85
5. `pktmon filter add SPT_HTTP4_0/1 -i <ip> -t TCP -p 443`,
   `SPT_HTTP6_0 -i <v6> -t TCP -p 443`, `SPT_DNS -t UDP -p 53`
6. `pktmon filter list` (records all four filters active)
7. `pktmon start --capture --comp 33 36 74 75 --pkt-size 0 --log-mode
   multi-file --file-name <out>\m1.etl --file-size 64` (component IDs picked by
   the script from the JSON inventory for the up adapter, Ethernet-medium only,
   npcap.sys excluded)
8. `pktmon status --buffer-info`
9. `curl.exe -sS --max-time 20 --noproxy '*' https://example.org/` ×2
10. `pktmon counters`, `pktmon stop` ("Log file: ... m12.etl (No events lost)")
11. `pktmon etl2pcap` ×5: all-components (`m1_all.pcapng`) + one per component
    (`m1_comp33/36/74/75.pcapng`) using the documented `--component-id` switch

Endpoint = example.org (Cloudflare-fronted today), **informal verification only**
as the user approved; a self-owned endpoint will harden Test A later.

## Actual results

Run C (final; runs A/B were earlier revisions, their fixes are logged below):

- Capture steps: **all exit code 0**; `curl1`/`curl2` exit 0 (page fetched).
- `etl2pcap` totals: **Packets total: 144, Packet drop count: 2, Packets
  formatted: 144**; per component: 96 (comp 36) + 0 (comp 33) + 44 (comp 74) +
  4 (comp 75) = 144.
- Per-component decode quality (`m1-pick`, tshark `frame.protocols`):

  | component | packets | full-Ethernet L2 | bare L3 | decoded IP |
  |---|---|---|---|---|
  | 33 WFP 802.3 | 0 | 0 | 0 | 0 |
  | 36 nwifi.sys | **96** | **96** | 0 | 48 |
  | 74 TCPIP6 | 44 | 44* | (tshark reads as eth) | 44 |
  | 75 TCPIP | 4 | 4* | | 4 |

  \* 74/75 packets are bare IP payloads (no L2 header) — tshark only
  interprets them because the file claims LINKTYPE_ETHERNET; they decode as
  valid IP anyway.
- Primary trace selected: `out/m1.pcapng` = `m1_comp36.pcapng` (18,568 bytes in
  a first run; 96 frames in this run — see "facts" below).
- Independent verification (`m1-verify`, on the selected trace):
  - our pure-TS pcapng parse: SHB v1.0 little-endian; 1 IDB linkType=1
    (Ethernet), snaplen=0, tsresol=6 µs; **96 EPBs; 0 parse errors**; one
    Interface Statistics Block (type 0x05) skipped-not-dropped.
  - tshark: **96 frames**, and the frame-by-frame comparison (cap_len,
    frame.len, epoch timestamps) gives **0 mismatches, max time delta 0 µs**.
  - capinfos: strict time order, duration 1.197 s, "Capture application:
    Packet Monitor", 42→96 packets per run.
- Flows actually seen (tshark-decoded): 2× HTTPS (TCP 443) IPv6 flows
  `2401:4900:c008:e380:fd48:8174:c8ce:4a69:<ephemeral> ↔ 2606:4700:90d6:6c5e:...:443`
  (one per curl run) + 2 DNS UDP/53 exchanges to 10.66.52.203.
- **Drops:** pktmon's own counters say "Packet drop count: 2" for this run —
  recorded, will be tracked by the drop counters in later milestones.

## Facts this run proves (and how we know)

1. In-box pktmon + no Npcap/driver is sufficient for a **file-based** capture
   pipeline on this Wi-Fi machine: real packets (TLS handshake, DNS) recorded
   end-to-end (48 unique packets, 144 including cross-component copies).
2. **Capture point changes the framing.** Comp 36 (nwifi.sys) logs each packet
   twice: once as full Ethernet and once as **raw 802.11 data frames**
   (tshark's "eth.type" 0x4dba/0x5888 are actually 802.11 frame-control bytes;
   the raw variant contains LLC/SNAP + IP). Comps 74/75 log bare IP packets
   without an Ethernet header. Any production decoder must handle both —
   recorded for the Decoder module (Milestone 2).
3. **Cross-component duplicates are real** (by design in this run since
   4 components captured simultaneously): same logical packet appears in more
   than one component with different framing; timestamp-identical duplicate
   groups exist (etl2pcap `--component-id <id>` cleanly separates them).
4. WFP 802.3 Filter (comp 33) captured **nothing** on the active path here
   ("Opt Datapath" component not in the packet flow) — vantage selection needs
   empirical validation per machine, which is what `m1-pick` automates.
5. Our own PCAPNG parser (SHB/IDB/EPB/SPB subset, pure TS) agrees with tshark
   **frame-for-frame** on count/length/timestamps with zero tolerance needed.

## Fixes made during the milestone (all caused by real run output)

1. Generated PS wrapper for UAC joined statements without separators →
   PowerShell parser error; joined with `;`.
2. `pktmon start --file-name m1.etl` in **multi-file** mode renames the log to
   `m1%d.etl` (m12.etl observed; later m11.etl+m12.etl) → post-stop location by
   pattern and choose the largest segment.
3. `etl2pcap --out` had written a **0-byte** pcapng on failure → RESULT OK now
   requires size > 0.
4. First capture at `--comp nics` returned raw 802.11 frames nobody could
   decode → capture at Ethernet-medium components resolved via
   `pktmon list --json`; per-component conversions let the prototype pick the
   best vantage empirically (`m1-pick`, uses tshark `frame.protocols`).
5. JSON report crashed on BigInt (sectionLength) → replacer added.
6. `pktmon list --json` written by PowerShell contained a UTF-8 BOM →
   `-Encoding UTF8` + trim on the read side.

## Known limitations (v1)

- File-based only: capture → stop → convert → parse. There is no live stream
  in this milestone (real-time mode exists in pktmon, verified by help text
  only; its stdout format is unverified).
- Primary trace still contains 48 raw-802.11 copies of the 48 IP packets at
  comp 36 (mixed framing at a single capture point). tshark cannot decode the
  raw-802.11 variant as IP; our Milestone 2 decoder will handle it and then
  scope counts (Test D) get computed on our decode.
- Multi-file segments are converted per file; zero-event segment files show up
  and are ignored (largest wins). Merging segments beyond one is unverified.
- Client/driver-level info (interface labels, per-component epb metadata
  options) is partially skipped (ISB block counted as "skipped").
- ETL2PCAP drop counter (2) is read from stdout text; not parsed into a
  structured counter yet.
- Driving curls through an elevated shell means the traffic generator ran
  elevated; that does not affect capture (kernel-level), but staging the
  traffic generator non-elevated is planned for later milestones.
- example.org is Cloudflare shared-edge IP space; other tenants' traffic to
  the same IPs could enter a longer capture (not observed here — flows list
  shows only our 4 flows).

## Files created/changed (milestone 1)

```
strobe-packet-tracker/
├── package.json, tsconfig.json, .gitignore
├── src/
│   ├── cli.ts        — command dispatch (m1-capture/m1-pick/m1-verify)
│   ├── pktmon.ts     — argv-array process runner (spawn, never exec strings)
│   ├── elevated.ts   — single-UAC-prompt elevated script runner
│   ├── m1Capture.ts  — capture orchestration + .ps1 generator
│   ├── pcapng.ts     — pure-TS PCAPNG parser (SHB/IDB/EPB/SPB)
│   ├── m1Pick.ts     — per-component trace quality classifier & selector
│   └── m1Verify.ts   — frame-for-frame cross-check vs tshark + facts report
├── docs/step0-environment.md — environment verification record
├── docs/milestone-1-report.md — this file
└── out/ (artifacts: m1.ps1/.log/.exitcode, m1.etl, components.json,
        m1_all/comp33/36/74/75.pcapng, m1.pcapng (picked), m1-verify.json)
        — .gitignore'd, kept for the record
```
