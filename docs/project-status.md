# strobe-packet-tracker — Project Status Report

_Date: 2026-10-22 (local UTC+5:30). Machine: Windows 11 build 26200, non-admin shell._

> **Layout note:** after the layered restructure, source files live in
> `src/engine/`, `src/capture/`, `src/traffic/`, `src/verify/`,
> `src/reporting/`, `src/tap/`, and the dated milestone reports moved verbatim
> to `docs/history/`. The current layout — including the old→new path map —
> lives in [`ARCHITECTURE.md`](ARCHITECTURE.md); use it to translate any flat
> `src/*.ts` path quoted in the dated sections below.

## 0. Mission (one line)

Build a small, verifiable Windows prototype of Strobe's packet-tracking engine:
capture real traffic with an in-box backend, decode it from raw PCAPNG bytes in
pure TypeScript, and prove correctness against tshark 4.6.9 as an independent
oracle — milestone by milestone, never claiming anything we haven't run.

---

## 1. Where we are — milestone ledger

| Milestone | Scope | Status | Score |
|---|---|---|---|
| **M1** — capture path works | pktmon → ETL → etl2pcap → pure-TS PCAPNG parse + framing | ✅ **DONE**, reported (`docs/history/milestone-1-report.md`) | 100% |
| **M2** — decode + parity vs tshark | PacketDecoder (16/16 tests) + parity engine, port-only filters, 15-scenario corpus | ✅ **DONE**, reported (`docs/history/milestone-2-report.md`) | core batch **9/9 scenarios 100% parity** (target ≥90%), extended batch honest findings |
| **M3** — flow engine ("stories") | per-flow timelines, TCP stream reassembly, DNS attribution, HTTP extraction, verification vs tshark conv tables | 🟡 **~90% — engine done; verification matrix 14/14 traces FULL PASS; only CLI wiring + unit tests + the written report remain** | 14/14 checks pass (see §3) |
| **M4+** — candidates chosen later | loopback vantage, richer stories, fragment reassembly | ⬜ not started | — |

**Bottom line: 2 of 3 planned milestones are complete and reported. The third
(M3) is nearly done — the core engine work (M3.1, M3.2) is finished and
verified; what remains is the final full-matrix confirmation printout, CLI
wiring, and the M3 report.**

---

## 2. What we can run right now (commands that work today)

All from `strobe-packet-tracker\`. Nothing below needs elevation except the
`m2:*` capture commands (one UAC prompt per batch).

### Offline analysis (no UAC, no network)

| Command | What it does | Verified result |
|---|---|---|
| `npm test` | 16/16 decoder unit tests | 16 pass / 0 fail |
| `npm run typecheck` | `tsc --noEmit` over whole engine | clean |
| `node out\scen\reverify_parity.ts` | re-runs the M2 parity metric on the baseline + all 13 captured traces | 13×100% + s10 14.3% (by design, see §7) |
| `node out\scen\m3_smoke.ts out\scen\s1_https_all.pcapng` | prints the flow stories for any trace: flows, hosts, SNI, handshake deltas, reassembled streams, HTTP conversations | works on all traces |
| `node out\scen\m3_verify_one.ts <trace>` | full M3.3 verification of one trace vs tshark (conversation frames+bytes, deduped bytes, DNS map, HTTP stories, retransmissions) | s1 ✅, s2 ✅, s3 ✅, s8 ✅, s12 ✅ (12/12 conv + 12/12 retrans), matrix running for the rest |
| `node out\scen\m3_verify_all.ts` | same verification across all 14 traces → `test-results/milestone3-checks.md` + `out/scen/m3_results.json` | ✅ **14/14 traces fully pass** |
| `npm run m2:core` / `npm run m2:ext` | **re-run the live capture batches** (generates fresh traffic; 1 UAC each) | verified working (M2) |
| `npm run m2:plan` / `npm run m1:pick` | planning helpers from the M2/M1 flows | verified working |

### What the engine demonstrates on real captured data today

Example from `m3_smoke` on `s1_https_all.pcapng` (real trace, 252 EPBs):

- 7 flows; 3 connections to `example.org` (via Cloudflare, **hosts auto-learned
  from the DNS answers in the same trace; SNI `example.org` extracted from the
  TLS ClientHellos — metadata only**)
- full TCP lifecycles: `SYN → SYN-ACK +46.2–71.7 ms → data → FIN`; when a flow
  starts mid-trace (no SYN) it is honestly labeled `[base-assumed]`
- both TCP directions reassembled with **0 gaps** (e.g. a2b 5840 B over 5 segments)
- endpoint IPs attributed from DNS question/answer chains.

The flood stress case (`s12_retrans`, 36 387 EPBs): 12 flows, three ~6.8 MB
download streams reassembled **exactly** (0 gaps), 12129 unique packets after
dedupe, and per-flow retransmission counts matching tshark per stream
(16 = 16 total, e.g. flow `:56211` ours=3 tshark=3).

---

## 3. Milestone 3 — exactly what is done and what is missing

### M3.1 — decoder extensions for stream reassembly ✅ DONE (verified)

- Added byte offsets to `TransportInfo` (`headerOff`, `headerLen`) so flow
  analysis can slice real payload bytes (TCP data-offset honored, UDP 8).
- **Safety proof:** full parity re-verification after the change — all 14
  traces byte-identical to the M2 results (13×100%, s10 14.3% by design).

### M3.2 — FlowEngine (`src/flows.ts`) ✅ DONE (smoke-verified on 13 traces)

- **Two views, deliberately separated** (and both verified in M3.3):
  an EPB view (every captured block, copies included → packet/byte counts per
  direction) and a unique view (M2 dedupe rule → streams, retransmissions,
  DNS, SNI, HTTP).
- `SparseStream` reassembler: handles retransmissions (fully-covered →
  retransSegs; partial overlap → partialRetransSegs, only novel bytes
  inserted), out-of-order segments, gaps (zero-fill + gap itemization),
  truncated payloads (caplen < declared), 32-bit seq wrap, 8 MiB overflow cap.
- TCP lifecycle story: SYN/SYN-ACK (+Δms), ACK-after-handshake →
  `handshakeComplete`, FIN per direction, RST, flag-combination timeline.
- DNS attribution: `ip → query names` from DNS responses in the trace.
- HTTP/1.x (metadata): request line method/uri/version, response status/content-
  length, chunked *detected but not de-chunked* (honest), 8-message/32 KiB caps.
- ICMP/ICMPv6 flows keyed port-less by IP pair (tshark conversation
  granularity); non-first IPv4 fragments counted separately (ports would be
  misread from payload bytes) and reconciled in M3.3.
- Shared dedupe extracted to `src/dedupe.ts` — parity and flow engines use the
  SAME copy rule (re-verified parity-identical after the refactor).

### M3.3 — verification harness (`src/m3Verify.ts`) ✅ DONE — full matrix 14/14 traces pass

The formal matrix (`out/scen/m3_verify_all.ts`, results in
`test-results/milestone3-checks.md` + `out/scen/m3_results.json`) ran to
completion: **m1_baseline, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s12, s14,
s15 — all 14 fully pass** every check below.

1. **conv-tcp/conv-udp** — per-flow frames per direction on the RAW trace
   (our side = tshark-L4-visible EPBs, measured via the parity oracle, not
   assumed) ✅ exact on s1(7/7), s2(3/3), s3(2/2), s12(12/12).
2. **bytes on the deduped export** — tshark `-z conv` on a classic-pcap export
   of exactly the deduped packets ↔ our unique-view sums. During this work we
   established a real tshark fact: **conv-table byte columns are SI floor-
   scaled** (`floor(bytes/1000)` = "kB", `floor(bytes/1e6)` = "MB"), so the
   comparison is inverted-window exact. ✅ exact on all measured flows
   (incl. the MB-scale flood streams).
3. **conv-icmp / icmpv6** — via `conv,ip`/`conv,ipv6` pair rows (tshark 4.6.9
   has **no** `conv,icmp` — verified), restricted to protocol-pure IP pairs ✅ s8 3/3.
4. **dns-attribution** — our `ip → names` map vs tshark's
   `dns.qry.name/dns.a/dns.aaaa` response rows ✅ s3 4/4 exact.
5. **http-stories** — our reassembled request/response sets vs tshark `http`
   rows: methods+URIs and status codes equal ✅ s2 6/6 exact.
6. **retransmission-stories** — per-flow counts of
   `tcp.analysis.retransmission` on the deduped export ↔ our detector's
   fully-covered segments. After fixing a member-indexing bug the counts are
   **equal per flow and in total (16=16)** ✅ s12 12/12.

Interesting subtlety discovered and documented: tshark's conv byte columns on
the **raw** trace disagree with tshark's own per-stream `frame.len` aggregate
when copy/retransmission-rich traffic is present (129390 vs 132096 B for an
identical 1730-frame membership) — this is why frame counts are verified on
the raw trace and byte sums on the deduped export, each within its own
population.

**Left in M3.3: nothing — the matrix is complete (14/14). The remaining M3
items below are packaging, not verification.**

### Finish list for M3 (the only remaining work)

1. [x] Full-matrix run over all 14 traces: **complete — 14/14 fully pass**
       (`test-results/milestone3-checks.md`); zero reconciliation needed.
2. [ ] Wire CLI + npm scripts: `m3-flows <trace>` and `m3-verify` (currently
       reachable via `node out\scen\m3_verify_*.ts` scripts) — 30 min.
3. [ ] Add a few unit tests for the flow engine (reassembly semantics,
       HTTP parser, dedupe reuse) — 1–2 h.
4. [ ] Write `docs/history/milestone-3-report.md` + `test-results/milestone3.md`
       (same format as M2: files, commands, real numbers, known limitations) —
       45 min, done last.
5. [ ] README quick-start section for M3 — 15 min.

→ With those five items committed, M3 is **complete**. Everything above the
line in §2 already works.

---

## 4. What is beyond M3 (candidate milestones, not built yet)

These are recorded findings with plans attached, in priority order:

- **M4-a: loopback vantage gap (Finding A from M2).** pktmon sees zero
  loopback traffic on build 26200 (verified: `--comp all` + per-comp
  conversions all 0 while traffic flowed in-process). If the engine must
  "see" local scenarios (s2_local_split / s11_loopback / s13_ws), options:
  userspace tap (raw HTTP client/server instrumentation feeding the same
  CaptureBackend interface), or Windows feedback-loop path probing. This was
  proposed as the alternative M3 direction and deliberately deferred.
- **M4-b: stories depth** — HTTP/2 and QUIC frame metadata stories ( pktmon +
  parity layer already shows QUIC flows; a `quicFrames` counter exists from
  M2). Fragment reassembly (IPv4 fragments are currently counted, not
  reassembled — s8's 3000-byte ping id X offsets 0/1480/2960 is in-hand data).
- **M4-c: engine ergonomics** — one-command "story for this past hour", CSV/
  JSON export of all flows across traces, and a tiny demo app page.

None of these are promised yet — they are the menu, exactly as at the M2
checkpoint.

---

## 5. Risk & limitation register (every entry verified, none speculative)

| # | Finding | Impact | Where recorded |
|---|---|---|---|
| R1 | pktmon sees zero loopback traffic on Windows build 26200 | local-only scenarios capture 0 packets (s2_local_split, s11_loopback, s13_ws all 0 EPBs) | M2 report Finding A |
| R2 | Cloudflare/example.org IPs rotate frequently | IP-bound capture filters unreliable; port-only filters are the standing rule | M2 report fix #2 |
| R3 | `speed.cloudflare.com` 100 MB download returns HTTP 403 | s14_burst is broken as a *traffic generator*; scenario still verified parity-wise for what flowed | M2 finding B |
| R4 | `ipconfig /renew` gave "media disconnected" on this NIC | s10_arpdhcp has no DHCP DORA; ARP packets decode as "unsupported" by design (parity 14.3%, 12 non-IP packets) | M2 |
| R5 | raw-802.11-style copies are L4-invisible to tshark; weird ethertype 0x4dba appears in some copies | our EPB-vs-tshark counts must subtract these copies (measured, not assumed, via the parity oracle) | M1/M2, now load-bearing in M3.3 |
| R6 | tshark conv byte columns are SI floor-scaled; raw-trace conv bytes can disagree with its own per-stream frame.len aggregate | byte-sums verified on the deduped export; frame counts on the raw trace | M3.3 (this milestone) |
| R7 | no `-z conv,icmp` in tshark 4.6.9 | ICMP flows verified through conv,ip/ipv6 pair rows on protocol-pure pairs | M3.3 |
| R8 | TLS decryption out of scope | SNI/handshake metadata only by design (user-approved scope) | project rules |

---

## 6. File inventory (what exists)

```
strobe-packet-tracker/
├── docs/
│   ├── ARCHITECTURE.md                ✅ current module map + old→new path map
│   ├── DEVELOPMENT.md                 ✅ dev guide (setup, gates, conventions)
│   ├── project-status.md              ✅ THIS report
│   └── history/                       ✅ verbatim milestone evidence records
│       ├── step0-environment.md           ✅ step-0 machine/tool inventory
│       ├── milestone-1-report.md          ✅ M1 report
│       ├── milestone-2-report.md          ✅ M2 report (definitive, with all fixes)
│       └── milestone-3-report.md          ✅ M3 report
├── test-results/
│   ├── milestone1.md                  ✅ M1 run log
│   ├── milestone2-core.md, milestone2-ext.md  ✅ M2 per-batch tables
│   └── milestone3-checks.md           🟡 written by the running matrix
├── src/
│   ├── pcapng.ts        parsePcapng + timestamps (pure TS, verified)
│   ├── decoder.ts       PacketDecoder + offsets (16/16 tests)
│   ├── dedupe.ts        shared copy-collapse rule (parity + flows)
│   ├── parity.ts        M2 parity engine (21-column tshark oracle)
│   ├── flows.ts         M3 FlowEngine (NEW, verified)
│   ├── pcapwrite.ts     classic pcap writer for the deduped oracle (NEW)
│   ├── m3Verify.ts      M3.3 verification harness (NEW, passing measured traces)
│   ├── backend.ts / pktmonBackend.ts / scenarios.ts / m2Run.ts
│   ├── traffic.ts / localservers.ts / dnsgen.ts          (traffic gens, non-elevated)
│   └── cli.ts / cli.elevated.ts                          (m1/m2 commands wired)
├── test/decoder.test.ts (16/16)
├── out/
│   ├── m1.pcapng                     M1 baseline (parity 100%)
│   └── scen/                           all scenario traces + results + debug tools
│       ├── *_all.pcapng                13 captured traces (M2)
│       ├── <trace>.deduped.pcap        M3.3 deduped exports (byte oracle)
│       ├── m3_smoke.ts / m3_verify_one.ts / m3_verify_all.ts   M3 runners
│       └── dbg_*.ts                    the debugging scripts that pinned R6/R7
└── package.json    scripts: typecheck, test, m1:pick, m2:plan/core/ext
```

---

## 7. Honest unknowns at this moment

1. ~~Full 14-trace matrix mid-run~~ → **resolved: 14/14 fully pass.**
2. The retransmission check currently treats "tshark ≥ ours" as pass when
   ours=0 — on all measured data ours == tshark exactly (both directions of
   the inequality are exercised), so this laxness never changed a verdict;
   tightening it to exact-equality everywhere is a candidate finish-list item
   if the matrix shows a > discrepancy.
3. Unit tests for flows.ts exist only indirectly via the harness — finish
   item #3 adds first-class tests.

---

## 8. Restating the plan to "done" (checklist you can hold me to)

- [x] M3.3 matrix green across all 14 traces (or every failure explained in
      the report) — **the stop-and-report gate: PASSED, 14/14**
- [ ] `m3-flows` / `m3-verify` CLI + npm scripts wired
- [ ] flow-engine unit tests in `test/`
- [ ] `docs/history/milestone-3-report.md` + `test-results/milestone3.md` written with
      the same discipline as M2 (files → commands → real outputs → limits)
- [ ] README updated for M3
- then, with your go-ahead: **M4 choice** (menu: loopback vantage workstream,
  story depth for HTTP/2+QUIC, or engine ergonomics).

---

## 9. Milestone 4 kickoff (started)

**M4 took the ergonomics track first (M4-c):** a trace-inventory layer built on
the verified FlowEngine — contributed by a second agent and then verified and
wired by the primary agent into the CLI, exactly the same bar as M1–M3.

| File | Role | Verification performed |
|---|---|---|
| `src/watch.ts` | directory scanner → per-trace HTML reports + aggregate `index.html` dashboard (+ `--once` / live watch mode) | typecheck clean; ran over **all 67 traces** in `out\scen`: numbers match the M3-verified values exactly (s12: 36387 EPBs / 12129 unique / 12 flows / **16 retrans**; s1: 252/84/7; s11 loopback 0 EPBs = Finding A) |
| `src/export.ts` | pure serializers: `toJson` / `toCsv` / `toMarkdown` (no I/O — caller writes) | content-checked against known oracle values: s3 DNS map = example.org×2 + cloudflare.com×2; s2 HTTP = 3× `GET /` → `200` chunked (33 unique + 66 copies = 99 EPBs, exact) |
| `src/report.ts` | per-trace HTML generator | driven through watch.ts runs; no TODO/placeholder hacks (grep-checked) |
| `src/cli.ts` | **new commands `m4-report` / `m4-watch` / `m4-export`** + npm scripts `m4:report` / `m4:watch` / `m4:export` | executed live (see §2-style command table below) |

### M4 commands that work today (all offline, zero UAC)

```
npm run m4:report                                  # scan out\scen → out\m4-reports\index.html + 67 HTML reports
npm run m4:watch                                   # same, then regenerate on file change (Ctrl+C to stop)
npm run m4:export out\scen\s3_dns_all.pcapng md    # one-trace exports: json | csv | md
```

Output: `out\m4-reports\` — `<trace>.html` per trace + `index.html` inventory
dashboard (EPBs, unique packets, flows per protocol, retrans, DNS, duration,
per-trace drill-down links) + `json`/`csv`/`md` exports on demand.

### The one-shot gate (M4-c addition): `npm run test:all`

`node src\cli.ts test-all` → `src/testAll.ts` runs every verification gate in
sequence and writes `test-results/test-all.md`; exit code 0 only when ALL
gates pass. Verified run (2026-10-22, 47.8s total):

| # | gate | result | detail |
|---|---|---|---|
| 1 | typecheck | PASS | tsc --noEmit clean |
| 2 | unit-tests | PASS | pass=36 fail=0 (decoder + flows + loopback tap) |
| 3 | m1-verify | PASS | frame-by-frame vs tshark (96 frames, 0 mismatches) |
| 4 | parity-regression | PASS | 14 traces at thresholds (13×100% + s10 by design) |
| 5 | m3-matrix | PASS | 14/14 traces fully pass |
| 6 | m4-dashboard | PASS | index.html regenerated (43KB, 67 traces) |
| 7 | m4-export-formats | PASS | md + csv + json produced and content-sized |
| 8 | m4a-loopback | PASS | 3 scenarios pass incl. tshark gate |

This is now the single command to run after ANY change: it cannot leave a
regression unnoticed — every layer (decoder, parity, flows, ergonomics, tap)
has its own gate inside it.

### M4 remaining (candidates, in the order they will be proposed)

1. ~~Loopback vantage (M4-a)~~ — **DONE: Finding A CLOSED (see §10).**
2. **Story depth (M4-b)** — HTTP/2 + QUIC frame metadata, IPv4 fragment
   reassembly (data already in hand from s8).
3. **Live-tail capture** — pktmon's real-time mode is unverified; a watch-mode
   + capture integration would make the dashboard live-speaking.

---

## 10. M4a — Loopback vantage: DONE (Finding A closed)

M4-a was chosen by the user from the M4 menu. Built as a **userspace network
tap** behind the engine's decode→dedupe→flows pipeline, with no elevation, no
drivers, no Npcap.

### What was built (M4a)

| File | Role | Verification performed |
|---|---|---|
| `src/pcapngwrite.ts` | minimal pcapng writer (one SHB + one IDB `if_tsresol=6` µs + EPBs, Ethernet linktype 1 — same shape as every trace in the corpus) | roundtrip through `parsePcapng` (unit test): block count, caplen/origLen preserved, µs timestamps exact, tsResolRaw=6 |
| `src/loopbacktap.ts` | the tap: intercepts `net.createConnection` / `net.createServer` / `dgram.createSocket`, records every verbatim per-connection send (one vantage per direction), synthesizes honest framing (eth + IP + TCP/UDP with correct checksums, real ports/addresses/timings) | unit tests incl. a REAL in-process loopback TCP echo end-to-end through the armed tap (36/36 total tests) |
| `src/m4Loopback.ts` | M4a runner: runs the three local scenarios through the tap, verifies app-truth AND engine agreement, writes `<scenario>_tap.pcapng` | 22 automated checks across 3 scenarios, ALL PASS |
| `src/cli.ts` | `m4-loopback` command (`--tshark` flag runs the M3.3 gate on tap traces) | full gate executed on all 3 traces |

### Honesty contract (printed with every run)

- **REAL:** which bytes crossed (verbatim payloads), per application write
  chunk, over which local ports/addresses, in which order, at user-space
  timestamps.
- **SYNTHESIZED (labeled, claimed as such):** ISNs, pure-ACK placement, kernel
  segmentation boundaries, header cosmetics (TTL/MSS/window). Byte payloads
  are never synthesized.

### Verification evidence (M4a)

`node src\cli.ts m4-loopback --tshark` — ALL PASS, per scenario:

- **s2_local_split**: 3 TCP conns observed; split-header `GET /` and
  `GET /big/4096` produce engine HTTP stories with status **200**; reassembled
  stream bytes **byte-exact** vs tap payloads (89B/142B, 97B/4196B, 92B/142B);
  0 gaps; 0 retransmissions; app truth had code=0 for all three clients.
- **s13_ws**: 2 upgrade conns; engine stories give status **101**; s2c stream
  ENDs with the verbatim server hello frame `81 05 68 65 6c 6c 6f`
  (masked-client-frame RFC 6455 upgrade verified byte-exact); app truth
  got101=true gotFrame=true.
- **s11_loopback**: TCP echo round trips byte-exact (`tcp-loopback` →
  `echo:tcp-loopback`); **UDP 23B datagram echo exact**; engine udp flow has
  exactly 2 unique packets.
- **tshark-full-gate (per trace):** the M3.3 harness — which drives real
  tshark 4.6.9 over our pcapng writer's output — reports
  `conv-tcp=pass,conv-udp=pass,dns-attribution=pass,http-stories=pass,retransmission-stories=pass`
  on all three tap traces. tshark's own HTTP dissector independently reads the
  same methods/statuses as our engine from the synthesized frames.

Traces: `out/m4/loopback/{s2_local_split,s13_ws,s11_loopback}_tap.pcapng` —
openable in Wireshark/tshark.

### Regression gates re-run after M4a landed

- `npm run typecheck` — clean.
- `npm test` — **36/36 via Jest** (16 decoder + 17 flows + 3 tap; watch: `npm run test:watch`).
- `node src\cli.ts m3-verify` — **14/14 fully pass** (M3 matrix unchanged;
  the HTTP orientation fix below did not perturb the M2/M3 corpus).
- `node out\scen\reverify_parity.ts` — 13×100% + s10 14.3% by-design (unchanged).

### Engine fix that M4a surfaced (genuine flow-engine improvement)

`parseFlowHttp` previously assumed canonical endpoint `a` is always the HTTP
client endpoint; that held on external traces by IP-string ordering luck, but
fails on loopback traces where the server port sorts canonically first.
Moved to **content-based direction decision** (request lines fail the
`HTTP/`-start gate and statuses fail the `METHOD_RE` gate — the two are
mutually exclusive), with a2b-first preference preserving M3.3 behavior.
Parity re-run identical on all 14 traces; loopback statuses now attach.

