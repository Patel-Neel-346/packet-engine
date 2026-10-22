# Architecture

How the code is laid out, what each layer is allowed to do, and why the load-
bearing pieces are shaped the way they are. The living status ledger is
[`project-status.md`](project-status.md); the dated evidence records are in
[`history/`](history/).

## 1. Source layout

```
src/
├── cli.ts                 # entry point + dispatch ONLY (path fixed: every npm script routes here)
├── paths.ts               # OUT_DIR / SCEN_DIR / RESULTS_DIR — single source of truth
├── testAll.ts             # the 8-gate verification suite (spawns tsc/node/tshark)
├── engine/                # PURE packet engine — bytes in, values out
│   ├── pcapng.ts          # PCAPNG parser (SHB/IDB/EPB/SPB; skips+counts the rest)
│   ├── decoder.ts         # eth/VLAN/bare-IP/raw-802.11 → IP/TCP/UDP/DNS/TLS metadata
│   ├── dedupe.ts          # the shared copy-collapse rule (parity + flows both use it)
│   ├── flows.ts           # flow engine: EPB view + unique view, streams, stories
│   ├── pcapngwrite.ts     # minimal PCAPNG writer (tap traces; tshark-compatible)
│   └── pcapwrite.ts       # classic-pcap writer (deduped-oracle export for M3.3)
├── capture/               # pktmon capture layer + external-process helpers
│   ├── backend.ts         # CaptureBackend interface + signal-path contract (no I/O)
│   ├── pktmon.ts          # argv-array process runner (pktmon/powershell/tshark paths)
│   ├── elevated.ts        # one-UAC-prompt elevated script runner (.log/.exitcode readback)
│   ├── pktmonBackend.ts   # PktmonBackend: generates + runs the bundle .ps1
│   ├── m1Capture.ts       # m1-capture: prechecks + one elevated bundle
│   ├── m1Pick.ts          # m1-pick: best per-component trace → out/m1.pcapng
│   └── m2Run.ts           # m2-core/m2-ext batches + offline m2-plan; parity summary
├── traffic/               # M2 scenario corpus + non-elevated traffic generation
│   ├── scenarios.ts       # scenario definitions (s1..s15) + buildPlans
│   ├── traffic.ts         # generators: curl/ping/Edge/Node sockets, argv arrays only
│   ├── localservers.ts    # split-write HTTP, WebSocket echo, UDP echo servers
│   └── dnsgen.ts          # raw-socket DNS client (A/AAAA/NXDOMAIN, DNS-over-TCP)
├── verify/                # tshark-oracle verification harnesses
│   ├── m1Verify.ts        # frame-by-frame M1 cross-check
│   ├── parity.ts          # M2 parity metric (21-column tshark oracle)
│   ├── m3Verify.ts        # M3.3 single-trace checks (conv/DNS/HTTP/retrans)
│   └── m3Matrix.ts        # the 14-trace matrix loop (gate 5 parses its output)
├── reporting/             # M4 ergonomics outputs
│   ├── report.ts          # per-trace self-contained HTML (pure string building)
│   ├── watch.ts           # directory scan → dashboard; live watch mode
│   ├── export.ts          # toJson / toCsv / toMarkdown (pure serializers)
│   └── flowStories.ts     # m3-flows console printer
└── tap/                   # M4a userspace loopback tap
    ├── loopbacktap.ts     # in-process net/dgram interception + frame synthesis
    └── m4Loopback.ts      # runs the 3 local scenarios through the tap + verifies
```

Every file's header carries the same metadata block (`Layer / Milestone /
Verified / Exports`) with its own factual content.

## 2. Layering rules

| Layer | May import | Node builtins it uses | May spawn |
|---|---|---|---|
| `engine/` | only `engine/` | `crypto` (sha1 hashing in dedupe), `fs` (ONE `readFileSync` convenience: `analyzePcapFile` in flows.ts — the analysis core `buildFlows` stays pure) | **nothing** |
| `capture/` | `engine/`, `traffic/`, `paths.ts` | `fs`, `path`, `child_process` | pktmon, powershell (elevated bundles) |
| `traffic/` | `capture/backend.ts` (types), `capture/pktmon.ts` (runCommand) | `dns`, `net`, `os`, `fs`, `dgram`, `crypto` | curl, ping, arp, ipconfig, msedge — all non-elevated, argv arrays only |
| `verify/` | `engine/`, `capture/pktmon.ts`, `paths.ts` | `fs`, `path`, `crypto` | **tshark** (the oracle) |
| `reporting/` | `engine/` only | `fs`, `path`, `child_process` (openInBrowser uses `exec` with a fixed string — the one deliberate exception to the argv-array rule) | browser open (watch mode) |
| `tap/` | `engine/`, `traffic/` | `net`, `dgram`, `crypto`, `fs` | nothing (in-process interception) |
| `cli.ts` / `testAll.ts` / `paths.ts` | anything | dispatch + orchestration | testAll spawns tsc/node/tshark |

Two rules that have held since M1 and are checked by review + typecheck:

1. **The engine never does process/network I/O.** Every harness (verify,
   reporting, capture) feeds it buffers or file paths and gets values back.
   This is what makes the 36 unit tests possible without elevation or tshark.
2. **Processes are spawned with argv arrays, never shell strings.** No
   user-influenced string ever reaches a shell (the single `exec` in
   `reporting/watch.ts` opens a browser with a hard-coded `start` command).

## 3. Data flow

```
                       elevated (ONE UAC prompt per run)
                    ┌──────────────────────────────────────┐
                    │  capture/m2Run.ts ──► bundle .ps1     │
                    │       pktmon start ─► traffic runs ─► │
                    │       pktmon stop ─► etl2pcap         │
                    └──────────────┬───────────────────────┘
                                   ▼
            out/scen/<scenario>_all.pcapng   (PCAPNG, Ethernet + bare-IP +
                                             raw-802.11 copies, per component)
                                   ▼
     engine/pcapng.ts  parsePcapng          (EPBs, interfaces, skipped counts)
                                   ▼
     engine/decoder.ts decodePacket ×N      (framing → IP → transport → DNS/TLS)
                                   ▼
     engine/dedupe.ts  dedupePackets        (same IP-bytes hash + ≤2 ms ⇒ copies)
                         ├──────────────────────┐
                         ▼ (unique view)        ▼ (EPB view, copies included)
     engine/flows.ts buildFlows ──────────► FlowAnalysis
     (streams, reassembly, stories)   (packets/bytes per direction)
                                   ▼
        ┌──────────────────────────┼─────────────────────────────┐
        ▼                          ▼                             ▼
 verify/m3Verify.ts         reporting/report.ts          reporting/export.ts
 (vs tshark conv/DNS/       + watch.ts (dashboard)       (json/csv/md)
  HTTP/retrans; matrix      + flowStories.ts (console)
  in m3Matrix.ts)
```

The M4a tap path joins the same pipeline from the side: `tap/loopbacktap.ts`
intercepts in-process `net`/`dgram` traffic, records verbatim payloads, and
synthesizes Ethernet/IPv4 frames through `engine/pcapngwrite.ts` — the
resulting `<scenario>_tap.pcapng` files go through **the identical**
parse → decode → dedupe → flows path and the identical tshark gate.

## 4. Key design decisions

- **tshark as the independent oracle.** Nothing is claimed that wasn't
  compared against Wireshark 4.6.9: frame-by-frame (M1), a 21-column per-
  packet parity metric (M2), and conv/DNS/HTTP/retransmission checks (M3.3).
  Packets we cannot decode count as *unsupported*, never as matches — the
  parity metric cannot be inflated by ignorance.
- **One shared dedupe rule** (`engine/dedupe.ts`): "same IP-level bytes +
  capture timestamps within 2 ms = copies of one physical packet". Parity and
  the flow engine import the same function, so the notion of "one physical
  packet" can never drift between them.
- **Two views, deliberately separated** (`engine/flows.ts`): the EPB view
  counts every captured block (copies included — this is what tshark's conv
  tables see) and the unique view collapses copies (this is where reassembly,
  retransmission detection, DNS attribution and HTTP parsing run). Each view
  is verified against the oracle population that matches it.
- **One UAC prompt per capture run.** Elevated steps are bundled into a
  single generated `.ps1` launched with `Start-Process -Verb RunAs -Wait`;
  the non-elevated Node side drives traffic in lock-step via signal files and
  reads back the script's `.log` + `.exitcode`.
- **The tap honesty contract** (M4a): REAL = verbatim application bytes,
  order, ports, user-space timestamps; SYNTHESIZED (and claimed as such) =
  ISNs, pure-ACK placement, kernel segmentation boundaries, header cosmetics.
  pktmon sees zero loopback traffic on this Windows build (verified Finding
  A, M2) — the tap closes that gap without pretending to be a kernel capture.
- **Writers match the corpus, not the full spec.** `pcapngwrite.ts` emits
  exactly the shape every pktmon/etl2pcap trace has (one SHB, one IDB,
  linktype Ethernet(1), if_tsresol=6, no per-block CRCs — spec-optional);
  `pcapwrite.ts` exports the deduped view to classic pcap so tshark's
  retransmission analysis runs on exactly the population our engine analyzed.
- **Load-bearing console strings.** `testAll.ts` parses command output (e.g.
  the `done: N/N fully pass` line from `m3-verify`, `parity= X%` rows from the
  parity regression). Any code that moves must keep its output strings
  byte-identical — the m3Matrix/flowStories extractions from cli.ts were
  verbatim moves for exactly this reason.

## 5. Old → new path map

All `src/*.ts` files were flat before the restructure. Historical reports
(written against the flat layout) remain readable with this map:

| Old path | New path |
|---|---|
| `src/pcapng.ts` | `src/engine/pcapng.ts` |
| `src/decoder.ts` | `src/engine/decoder.ts` |
| `src/dedupe.ts` | `src/engine/dedupe.ts` |
| `src/flows.ts` | `src/engine/flows.ts` |
| `src/pcapngwrite.ts` | `src/engine/pcapngwrite.ts` |
| `src/pcapwrite.ts` | `src/engine/pcapwrite.ts` |
| `src/backend.ts` | `src/capture/backend.ts` |
| `src/pktmon.ts` | `src/capture/pktmon.ts` |
| `src/elevated.ts` | `src/capture/elevated.ts` |
| `src/pktmonBackend.ts` | `src/capture/pktmonBackend.ts` |
| `src/m1Capture.ts` | `src/capture/m1Capture.ts` |
| `src/m1Pick.ts` | `src/capture/m1Pick.ts` |
| `src/m2Run.ts` | `src/capture/m2Run.ts` |
| `src/scenarios.ts` | `src/traffic/scenarios.ts` |
| `src/traffic.ts` | `src/traffic/traffic.ts` |
| `src/localservers.ts` | `src/traffic/localservers.ts` |
| `src/dnsgen.ts` | `src/traffic/dnsgen.ts` |
| `src/m1Verify.ts` | `src/verify/m1Verify.ts` |
| `src/parity.ts` | `src/verify/parity.ts` |
| `src/m3Verify.ts` | `src/verify/m3Verify.ts` |
| `src/report.ts` | `src/reporting/report.ts` |
| `src/watch.ts` | `src/reporting/watch.ts` |
| `src/export.ts` | `src/reporting/export.ts` |
| `src/loopbacktap.ts` | `src/tap/loopbacktap.ts` |
| `src/m4Loopback.ts` | `src/tap/m4Loopback.ts` |
| `src/cli.ts` | `src/cli.ts` (path unchanged; now dispatch-only) |
| `src/testAll.ts` | `src/testAll.ts` (unchanged) |

New files with no old counterpart: `src/paths.ts` (consolidated the
duplicated `out` / `out/scen` / `test-results` path constants),
`src/verify/m3Matrix.ts` (the m3-verify matrix loop, extracted verbatim from
cli.ts), `src/reporting/flowStories.ts` (the m3-flows printer, extracted
verbatim from cli.ts).

`docs/step0-environment.md` and `docs/milestone-*-report.md` moved verbatim to
`docs/history/` (git renames — full history preserved).
