# strobe-packet-tracker

Windows capture prototype for Strobe's packet-tracking engine. It captures real
traffic with the in-box Windows `pktmon` backend, decodes it from raw PCAPNG
bytes in pure TypeScript (zero runtime dependencies, no build step), and proves
every layer of the engine correct against **tshark as an independent oracle** —
milestone by milestone, never claiming anything that wasn't run.

**Status: Milestones 1-3 COMPLETE (+ M3 report). M4 (engine ergonomics) DONE —
verified & wired. M4a (loopback vantage) DONE — Finding A closed: userspace
tap, 3 local scenarios captured + verified vs engine and tshark. Next
candidates: story depth (HTTP/2+QUIC, IPv4 fragment reassembly) or dashboard
capture integration.**

Evidence: [`docs/history/`](docs/history/) (verbatim milestone reports) and
[`docs/project-status.md`](docs/project-status.md) (living status ledger).

## The pipeline

```
 real traffic ──► pktmon ──► ETL ──► etl2pcap ──► out\*.pcapng
                   (in-box Windows tools; ONE UAC prompt per capture run)

 local app traffic ──► src/tap/ userspace loopback tap (M4a; no UAC, no
                       drivers) — synthesizes PCAPNG traces of the loopback
                       traffic pktmon cannot see on this build (Finding A)

                                     out\*.pcapng traces on disk
                                                │
                                                ▼
            ┌──────────────────────────────────────────────────────┐
            │ src/engine/ — pure TypeScript, zero process/net I/O  │
            │   parsePcapng ─► decodePacket ─► dedupePackets ─►    │
            │   buildFlows                                         │
            │   (framing, IP/TCP/UDP/DNS/TLS metadata, copy-       │
            │    collapse, TCP reassembly, flow stories, DNS       │
            │    attribution, HTTP metadata)                       │
            └──────────────────────────────────────────────────────┘
                                                │
                 ┌──────────────────────────────┼────────────────┐
                 ▼                              ▼                ▼
          src/verify/                    src/reporting/      src/cli.ts
          prove every layer vs           HTML dashboard,     entry point:
          tshark (M1 frames, M2          per-trace reports,  every command +
          parity, M3 conv/DNS/HTTP/      json/csv/md         the 8-gate
          retrans matrix)                exports             suite
```

Three properties make this prototype verifiable rather than merely working:

1. **The engine is pure.** `src/engine/` turns bytes into values with zero
   process/network I/O — every harness feeds it buffers and reads back
   results, so all 36 unit tests run offline and non-elevated.
2. **Nothing is trusted without an oracle.** Frames (M1), a 21-column
   per-packet parity metric (M2), and conversation/DNS/HTTP/retransmission
   checks (M3) are compared against real tshark output; packets the engine
   cannot decode count as *unsupported*, never as matches.
3. **One command re-proves everything.** `npm run test:all` runs all 8
   verification gates in ~45 s, offline, no UAC.

## Milestone status

| Milestone | Status | Score |
|---|---|---|
| M1 — capture path | **DONE** | 100% |
| M2 — decode + parity vs tshark | **DONE** | 9/9 core scenarios 100% parity |
| M3 — flow engine + TCP reassembly | **DONE** | 14/14 traces fully pass all checks |
| M4 — engine ergonomics (dashboard/watch/export) | **DONE — verified & wired** | 67 traces → dashboard; json/csv/md exports content-checked vs known values |
| M4a — loopback vantage (userspace tap) | **DONE — Finding A closed** | 3 local scenarios: 22 in-tap checks ALL PASS + tshark full gate on all 3 synthesized traces |

## Prerequisites

| Item | Required version | License | Purpose |
|---|---|---|---|
| Windows | 10.0.19041+ (tested on 10.0.26200) | - | in-box pktmon |
| Node.js | >= 24 (tested v24.12.0) | MIT | engine + CLI |
| tshark (Wireshark) | tested 4.6.9 | GPL | independent verifier only |
| Administrator | session UAC approval once per capture | - | pktmon driver access |

- No third-party runtime dependencies; dev deps: `typescript`, `@types/node`.
- Node >= 24 runs `.ts` directly (type stripping) — there is **no build step**.
- tshark is used **only** as a verifier; the engine itself never depends on it.

## Quick start (Windows)

```powershell
# Prereqs: Node.js v24+ (type stripping runs .ts directly), Wireshark
# (tshark) for independent verification, Administrator approval for capture.
cd strobe-packet-tracker
npm install

# --- ONE SHOT: run EVERY verification gate (offline, no UAC, ~45 s) ---
npm run test:all
# 8 gates: typecheck, 36 unit/integration tests, M1 frame-by-frame vs tshark,
# M2 parity regression (14 traces), M3 matrix (14/14), M4 dashboard + exports,
# M4a loopback tap (3 scenarios + tshark gate). Report: test-results\test-all.md
```

## Command reference

All commands run from the repo root. Elevation: `1 UAC` = exactly one UAC
prompt for the whole run; `none` = fully offline and non-elevated.

### Verification

| Command | What it does | Elevation |
|---|---|---|
| `npm run test:all` | all 8 gates in sequence; exit 0 only when all pass; writes `test-results\test-all.md` | none |
| `npm run typecheck` | `tsc --noEmit` over `src/**` + `test/**` | none |
| `npm test` | Vitest run: 36 tests in 3 structured suites (16 decoder + 17 flows + 3 loopback tap) | none |
| `npm run test:watch` | Vitest watch mode — re-runs only affected tests as you edit | none |
| `npm run test:ui` | Vitest browser dashboard — inspect each suite/assertion visually | none |

### M1 — capture path

| Command | What it does | Elevation |
|---|---|---|
| `npm run m1:capture` | elevated pktmon capture bundle — prechecks, one generated `.ps1`, ETL → etl2pcap | 1 UAC |
| `npm run m1:pick` | select the best per-component trace → `out\m1.pcapng` | none |
| `npm run m1:verify` | cross-check `out\m1.pcapng` frame-by-frame vs tshark | none |

### M2 — decoder + parity

| Command | What it does | Elevation |
|---|---|---|
| `npm run m2:plan` | generate + syntax-check the M2 bundle script (offline dry-run) | none |
| `npm run m2:core` | Milestone 2 CORE scenarios (9) — live capture, decode, parity vs tshark | 1 UAC, ~5 min |
| `npm run m2:ext` | Milestone 2 EXTENDED scenarios (6) — live capture, decode, parity vs tshark | 1 UAC |

### M3 — flow engine

| Command | What it does | Elevation |
|---|---|---|
| `npm run m3:verify` | full matrix: 14/14 traces fully pass vs tshark (conv/DNS/HTTP/retrans) | none |
| `npm run m3:flows <trace>` | print the flow story for one trace, e.g. `npm run m3:flows out\scen\s1_https_all.pcapng` or `npm run m3:flows out\scen\s12_retrans_all.pcapng` | none |

### M4 — engine ergonomics

| Command | What it does | Elevation |
|---|---|---|
| `npm run m4:report` | analyze `out\scen` → `out\m4-reports\index.html` dashboard + per-trace HTML reports (67 traces); explicit dirs: `npm run m4:report out\scen out\m4-reports` | none |
| `npm run m4:watch` | same, then regenerate the dashboard when traces change (Ctrl+C to stop) | none |
| `npm run m4:export <trace> <fmt>` | one-trace exports — `json` \| `csv` \| `md`, e.g. `npm run m4:export out\scen\s3_dns_all.pcapng md` | none |

### M4a — loopback vantage (Finding A closed)

| Command | What it does | Elevation |
|---|---|---|
| `npm run m4:loopback` | tap-capture `s2_local_split` / `s13_ws` / `s11_loopback` + verify (app-truth + engine agreement); writes `out\m4\loopback\*_tap.pcapng` | none |
| `npm run m4:loopback -- --tshark` | also run the full M3 tshark gate on the synthesized tap traces | none |

### Artifacts

- `out\` — ETL files, per-component pcapng, picked trace, verify JSON, capture
  log/ps1. `out\m1.pcapng` opens in Wireshark/tshark.
- `out\scen\` — one ETL per scenario in `out\`, plus per-scenario
  `_all.pcapng`, per-component `_c<id>.pcapng`, parity JSON, recorded bundle
  logs.
- `out\m4-reports\` — dashboard + per-trace HTML; `out\m4\loopback\` — tap
  traces (openable in Wireshark/tshark).
- `test-results\` — committed written evidence: `milestone1.md`,
  `milestone2-core.md` + `milestone2-ext.md` (per-batch parity tables),
  `milestone3-checks.md` (machine-readable copy: `out\scen\m3_results.json`),
  `test-all.md` (the 8-gate report).
- Every capture stops itself (`pktmon stop` inside the bundle). Manual cleanup
  if interrupted: elevated `pktmon stop`; filters clear with elevated
  `pktmon filter remove`.

## The 8-gate verification model

`npm run test:all` (→ `src/testAll.ts`) runs every gate in sequence and exits
0 only when all 8 pass. This is the single command to run after ANY change —
every layer (decoder, parity, flows, ergonomics, tap) has its own gate inside,
so a regression anywhere surfaces as a named failure.

| # | Gate | What it proves | Verified result |
|---|---|---|---|
| 1 | typecheck | `tsc --noEmit` clean over `src/**` + `test/**` | clean |
| 2 | unit-tests | unit + integration tests on synthetic byte fixtures | 36/36 (16 decoder + 17 flows + 3 tap) |
| 3 | m1-verify | `out\m1.pcapng` frame-by-frame vs tshark | 96 frames, 0 mismatches |
| 4 | parity-regression | M2 21-column parity metric on every captured trace | 14 traces at thresholds (13×100% + s10 by design*) |
| 5 | m3-matrix | conv/DNS/HTTP/retransmission checks per trace vs tshark | 14/14 traces fully pass |
| 6 | m4-dashboard | dashboard regenerated over the whole corpus | index.html (43 KB) + 67 per-trace reports |
| 7 | m4-export-formats | json/csv/md exports produced | produced + content-sized |
| 8 | m4a-loopback | userspace-tap scenarios incl. the tshark gate | 3 scenarios pass (22 in-tap checks) |

\* s10_arpdhcp captured ARP with no DHCP DORA on this NIC (media-disconnected
`ipconfig /renew`); its non-IP packets decode as "unsupported" by design, so
its parity is below threshold on purpose — recorded as risk R4 in
[`docs/project-status.md`](docs/project-status.md).

## Repository layout

```
strobe-packet-tracker/
├── src/
│   ├── cli.ts            # entry point + dispatch (every npm script routes here)
│   ├── paths.ts          # shared out/-directory constants
│   ├── testAll.ts        # the 8-gate verification suite
│   ├── engine/           # PURE packet engine — parser, decoder, dedupe,
│   │                     # flows, pcap/pcapng writers (zero process/net I/O)
│   ├── capture/          # pktmon bundles, one-UAC elevated runner, m1/m2 commands
│   ├── traffic/          # scenario corpus + non-elevated traffic generators
│   ├── verify/           # tshark-oracle harnesses: M1 frames, M2 parity, M3 matrix
│   ├── reporting/        # HTML reports, dashboard/watch, json/csv/md exports
│   └── tap/              # M4a userspace loopback tap
├── test/                 # 36 unit tests (decoder, flows, loopback tap)
├── docs/                 # ARCHITECTURE, DEVELOPMENT, project-status, history/
├── test-results/         # committed written evidence (regenerated by gates)
└── out/                  # generated artifacts (gitignored)
```

The per-file responsibility table, layering rules (who may import whom), data
flow, design decisions, and the old→new path map for reading historical
reports live in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Documentation

| Document | Contents |
|---|---|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | source layout, layering rules, data flow, key design decisions, old→new path map |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) | environment setup, the run-`test:all`-after-any-change rule, code conventions, how to add a scenario / decoder protocol / report field / gate |
| [`docs/project-status.md`](docs/project-status.md) | living status ledger: milestone evidence, risk register, honest unknowns |
| [`docs/history/`](docs/history/) | verbatim dated evidence: step-0 environment inventory + milestone 1/2/3 reports |

## What is honest and what is not yet

- Capture is **file-based** (pktmon ETL → `etl2pcap` → PCAPNG → pure-TS
  parser). Not a live stream yet; pktmon's real-time mode exists but is
  unverified.
- No Npcap, no custom drivers, no TLS decryption. Metadata only.
- Capture requires **Administrator** (verified: exit 5 otherwise). The
  prototype handles this transparently with one UAC prompt per run.
- On Wi-Fi, capture-point choice matters; the bundle picks Ethernet-medium
  components from `pktmon list --json` and `m1:pick` selects the vantage with
  the most fully-decoded frames empirically (tshark `frame.protocols`).

## Security

Authorized diagnostics only. The prototype records metadata (flows, timing,
addresses) to local files under `out\`. No payload storage beyond the packet
bytes needed for decoding; no TLS decryption; nothing is sent off-machine.
