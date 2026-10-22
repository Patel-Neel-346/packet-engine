# Development guide

Everything a new developer needs to pick this project up and change it safely.

## 1. Environment setup

| Requirement | Verified on | Why |
|---|---|---|
| Windows 10.0.19041+ | 10.0.26200 (Windows 11) | in-box `pktmon` + `etl2pcap` |
| Node.js ≥ 24 | v24.12.0 | runs `.ts` directly (type stripping) — no build step, ever |
| Wireshark/tshark | 4.6.9 at `C:\Program Files\Wireshark\` | the independent verification oracle |
| Administrator approval | one UAC prompt per capture run | pktmon driver access (non-admin `pktmon start` fails with exit 5) |

```powershell
npm install        # dev deps only: typescript + @types/node (zero runtime deps)
npm run test:all   # prove the baseline is green BEFORE you change anything
```

`tshark` is used **only** as a verifier — the engine itself never depends on
it. All 36 unit tests and all pure-engine code run without tshark, without
elevation, and without network access.

## 2. The one rule: run `npm run test:all` after ANY change

`npm run test:all` (→ `src/testAll.ts`) re-runs every verification gate in
sequence and writes `test-results/test-all.md`. Exit 0 only when all 8 pass:

| # | Gate | What it proves |
|---|---|---|
| 1 | typecheck | `tsc --noEmit` clean over `src/**` **and** `test/**` |
| 2 | unit-tests | 36/36 (16 decoder + 17 flows + 3 tap) |
| 3 | m1-verify | out/m1.pcapng frame-by-frame vs tshark (96 frames, 0 mismatches) |
| 4 | parity-regression | 14 traces at thresholds (13×100% + s10 by design) |
| 5 | m3-matrix | 14/14 traces fully pass conv/DNS/HTTP/retrans checks |
| 6 | m4-dashboard | index.html regenerated over the corpus |
| 7 | m4-export-formats | json/csv/md exports produced + content-sized |
| 8 | m4a-loopback | 3 tap scenarios incl. the tshark gate on synthesized traces |

Every layer (decoder, parity, flows, ergonomics, tap) has its own gate inside,
so a regression anywhere surfaces as a named failure. Offline, no UAC,
~45 s. **This is the single command to run after any change** — including
"just comments" refactors, because the gates also pin load-bearing console
strings (see §4).

## 3. Repository map

- `src/` — the code, in layers. Read [`ARCHITECTURE.md`](ARCHITECTURE.md)
  first: it has the per-file responsibility table, the layering rules (who may
  import whom), the data flow, and the old→new path map for reading
  historical reports.
- `test/` — 36 unit tests (`decoder.test.ts`, `flows.test.ts`,
  `loopbacktap.test.ts`); synthetic fixtures, byte layouts written inline.
- `docs/` — `ARCHITECTURE.md` (this system), `DEVELOPMENT.md` (this file),
  `project-status.md` (living status ledger), `history/` (verbatim milestone
  evidence records).
- `out/` — **generated, gitignored.** `out/m1.pcapng` (M1 baseline),
  `out/scen/*_all.pcapng` (M2 scenario corpus), `<trace>.deduped.pcap`
  (M3.3 oracle exports), `out/scen/m3_results.json`, `out/m4-reports/`
  (dashboard), `out/m4/loopback/*_tap.pcapng` (M4a traces), plus the
  gitignored `out/scen/*.ts` debug runners (see warning below).
- `test-results/` — committed written evidence (milestone run logs, parity
  tables, the matrix report, `test-all.md`). Don't hand-edit; the gates
  regenerate them.

> **Warning:** the `out/scen/*.ts` scripts (e.g. `reverify_parity.ts`,
> `m3_smoke.ts`, `m3_verify_one.ts`) are *load-bearing gitignored artifacts* —
> `testAll.ts` gate 4 spawns `out/scen/reverify_parity.ts`, and they import
> from `src/` by relative path. They were re-pointed during the layered
> restructure; if you move `src/` files again, patch them too or gate 4 breaks.

## 4. Code conventions

1. **Strict TypeScript, no build step.** `tsc --noEmit` must stay clean
   (src + tests). `verbatimModuleSyntax` + `erasableSyntaxOnly` keep the code
   compatible with Node's type stripping: no enums/namespaces/parameter
   properties, `import type` for type-only imports, `.ts` extensions in
   import specifiers.
2. **Zero runtime dependencies.** `npm ls --omit=dev` should print nothing.
   Anything the engine needs gets built in `src/` (pcapng parser, pcap
   writers, DNS client, HTTP server fixtures).
3. **Processes spawn with argv arrays only.** Never build a shell command
   string; `exec` is off-limits (the one deliberate exception:
   `reporting/watch.ts` `openInBrowser`, hard-coded `start`). External tools:
   runCommand in `capture/pktmon.ts` is the only spawn path.
4. **The engine never throws on bad input.** `decodePacket`,
   `parsePcapng`, `buildFlows` record problems in `errors` / `parseErrors` /
   `warnings` and return. Bounded loops everywhere. "Unsupported" is a
   first-class answer, never a crash.
5. **No placeholder hacks.** No TODO-stubs, no fake data, no invented
   outputs. If something isn't implemented, it is labeled honestly (see the
   tap's REAL vs SYNTHESIZED contract and the `[base-assumed]` flow labels).
6. **Console strings can be load-bearing.** `testAll.ts` parses command
   output (`done: N/N fully pass`, `parity= X%` rows). Do not "clean up"
   command output without checking `src/testAll.ts` first.
7. **Headers + JSDoc.** Every file starts with the standard metadata block
   (`Layer / Milestone / Verified / Exports`) after its purpose prose;
   exported functions carry a short JSDoc line. Keep claims factual — the
   header states how the code is *currently* verified, not how it will be.

## 5. How to add things

### A scenario (traffic + capture)

1. Write a generator in `src/traffic/traffic.ts` (or `localservers.ts` /
   `dnsgen.ts` for local-server/DNS cases) returning `TrafficResult` —
   record every spawned command's real exit code via `rec()`.
2. Add a `ScenarioDef` in `src/traffic/scenarios.ts` — core (≥90% parity
   threshold) or extended. Filters are pktmon filter args; **port-only
   filters are the standing rule** (cloud IPs rotate — verified finding).
3. `npm run m2:plan` regenerates + syntax-checks the bundle offline (no UAC).
4. Capture with `npm run m2:core` / `m2:ext` (ONE UAC prompt per batch).
   Parity vs tshark is computed automatically and appended to
   `test-results/milestone2-<batch>.md`.
5. `npm run test:all` — your trace joins the corpus checks automatically
   once it exists (parity gate + m3 matrix both scan the standing list).

### A decoder protocol

1. Extend `src/engine/decoder.ts` — follow the existing dispatch style;
   never throw, record `errors`; respect `erasableSyntaxOnly`.
2. Add unit tests in `test/decoder.test.ts` with inline byte fixtures.
3. `npm run test:all` — the parity gate re-runs the whole 14-trace corpus
   against tshark, so a decoder regression on real data cannot hide.

### A report field

1. Add the field to `FlowAnalysis` / `Flow` in `src/engine/flows.ts`.
2. Thread it through `reporting/export.ts` (`toJson`/`toCsv`/`toMarkdown`)
   and, if visible, `reporting/report.ts`.
3. Gate 7 content-checks the exports; gate 6 the dashboard — both re-run in
   `npm run test:all`.

### A verification gate

1. In `src/testAll.ts`, add a `gateSync("name", () => {...})` (or
   `await gateAsync(...)` for async work) inside `runTestAll`, following the
   eight existing gates. Return/pass on real success — never assume.
2. Keep the gate's `detail` string informative; it lands in the console
   table and `test-results/test-all.md`.

## 6. Elevations, honestly

Only `m1:capture`, `m2:core`, `m2:ext` elevate — each bundles everything
into ONE generated `.ps1` + ONE UAC prompt (`capture/elevated.ts`), with the
non-elevated Node side driving traffic via signal files. Everything else —
including every gate in `test:all` — runs offline and non-elevated. Capture
bundles stop pktmon themselves; manual cleanup if interrupted: elevated
`pktmon stop` + `pktmon filter remove`.
