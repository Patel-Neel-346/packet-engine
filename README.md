# strobe-packet-tracker

Windows capture prototype for Strobe's packet-tracking engine.
**Status: Milestones 1-3 COMPLETE (+ M3 report). Milestone 4 IN PROGRESS: engine ergonomics verified & wired; M4a loopback vantage DONE — Finding A closed (userspace tap, 3 local scenarios captured + verified vs engine and tshark). Next: story depth (HTTP/2+QUIC, IPv4 fragment reassembly) or dashboard capture integration.**
See `docs/milestone-1-report.md`, `docs/milestone-2-report.md`, `docs/milestone-3-report.md`, `docs/project-status.md` for evidence.

## Quick start (Windows)

```powershell
# Prereqs: Node.js v24+ (type stripping runs .ts directly), Wireshark
# (tshark) for independent verification, Administrator approval for capture.
cd strobe-packet-tracker
npm install

# --- ONE SHOT: run EVERY verification gate (offline, no UAC) ---
npm run test:all
# 8 gates: typecheck, 36 unit/integration tests, M1 frame-by-frame vs tshark,
# M2 parity regression (14 traces), M3 matrix (14/14), M4 dashboard + exports,
# M4a loopback tap (3 scenarios + tshark gate). Report: test-results\test-all.md
npm run typecheck

# --- Milestone 1 (capture path) ---
npm run m1:capture   # elevated pktmon capture bundle -- ONE UAC prompt; click Yes
npm run m1:pick      # select the best per-component trace -> out\m1.pcapng
npm run m1:verify    # cross-check out\m1.pcapng frame-by-frame vs tshark

# --- Milestone 2 (decoder + parity) ---
npm run m2:plan      # generate + syntax-check the M2 bundle script (no UAC)
npm run m2:core      # Milestone 2 CORE scenarios (9) -- one UAC prompt, ~5 min
npm run m2:ext       # Milestone 2 EXTENDED scenarios (6) -- one UAC prompt

# --- Milestone 3 (flow engine -- no elevation needed) ---
npm test                                              # 33/33 pass (16 decoder + 17 flow)
npm run m3:verify                                     # 14/14 traces fully pass vs tshark
npm run m3:flows out\scen\s1_https_all.pcapng         # flow story for the HTTPS trace
npm run m3:flows out\scen\s12_retrans_all.pcapng      # flow story for the flood/retrans trace

# --- Milestone 4 (ergonomics -- no elevation, live-speaking) ---
npm test                                                  # 36/36 pass (decoder + flows + tap)
npm run m4:report                                         # analyze out\scen -> HTML dashboard + 67 per-trace reports
npm run m4:report out\scen out\m4-reports                 # explicit dirs
npm run m4:watch                                          # live: regenerate dashboard when traces change
npm run m4:export out\scen\s3_dns_all.pcapng md           # exports: json | csv | md

# --- Milestone 4a (loopback vantage -- Finding A closed, no UAC, no drivers) ---
npm run m4:loopback                                       # tap-capture s2_local/s13_ws/s11_loopback + verify (app-truth + engine)
npm run m4:loopback -- --tshark                           # also run the full M3 tshark gate on the tap traces
```

- Artifacts land in `out\` (ETL, per-component pcapng, picked trace,
  verify JSON, capture log/ps1). `out\m1.pcapng` opens in Wireshark/tshark.
- M2 scenario artifacts land in `out\scen\` (one ETL per scenario in `out\`,
  per-scenario `_all.pcapng` + per-component `_c<id>.pcapng`, parity JSON,
  recorded bundle log). Summary table: `test-results\milestone2.md`.
- M3 results: `test-results\milestone3-checks.md` (per-trace per-check table vs
  tshark) and `out\scen\m3_results.json` (machine-readable JSON).
- Stop: every capture stops itself (`pktmon stop` inside the bundle). Manual
  stop: elevated `pktmon stop`; filters clear with elevated
  `pktmon filter remove`.

## Milestone status

| Milestone | Status | Score |
|---|---|---|
| M1 — capture path | **DONE** | 100% |
| M2 — decode + parity vs tshark | **DONE** | 9/9 core scenarios 100% parity |
| M3 — flow engine + TCP reassembly | **DONE** | 14/14 traces fully pass all checks |
| M4 — engine ergonomics (dashboard/watch/export) | **DONE — verified & wired** | 67 traces → dashboard; json/csv/md exports content-checked vs known values |
| M4a — loopback vantage (userspace tap) | **DONE — Finding A closed** | 3 local scenarios: 22 in-tap checks ALL PASS + tshark full gate on all 3 synthesized traces |

## What is honest and what is not yet

- Capture is **file-based** (pktmon ETL -> `etl2pcap` -> PCAPNG -> pure-TS
  parser). Not a live stream yet; pktmon's real-time mode exists but is
  unverified.
- No Npcap, no custom drivers, no TLS decryption. Metadata only.
- Capture requires **Administrator** (verified: exit 5 otherwise). The
  prototype handles this transparently with one UAC prompt per run.
- On Wi-Fi, capture-point choice matters; the bundle picks Ethernet-medium
  components from `pktmon list --json` and `m1:pick` selects the vantage with
  the most fully-decoded frames empirically (tshark `frame.protocols`).

## Privileges & dependencies checklist

| Item | Required version | License | Purpose |
|---|---|---|---|
| Windows | 10.0.19041+ (tested on 10.0.26200) | - | in-box pktmon |
| Node.js | >= 24 (tested v24.12.0) | MIT | engine + CLI |
| tshark (Wireshark) | tested 4.6.9 | GPL | independent verifier only |
| Administrator | session UAC approval once per capture | - | pktmon driver access |

No third-party runtime dependencies; dev deps: typescript, @types/node.

## Security

Authorized diagnostics only. The prototype records metadata (flows, timing,
addresses) to local files under `out\`. No payload storage beyond the packet
bytes needed for decoding; no TLS decryption; nothing is sent off-machine.
