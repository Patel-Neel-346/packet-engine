# AI Agent Handoff — strobe-packet-tracker

_Read this first. It tells you what this repo is, what verification already
exists, and the rules you must follow when writing new test cases._

## 1. What this project is (30 seconds)

Windows packet-tracking prototype for Strobe. It captures real traffic with the
in-box `pktmon` backend (ETL → `etl2pcap` → PCAPNG), decodes it from raw
PCAPNG bytes in **pure TypeScript with zero runtime dependencies**, and proves
every layer correct against **tshark 4.6.9 as an independent oracle** —
milestone by milestone, never claiming anything that wasn't run.

- **No build step.** Node ≥ 24 runs `.ts` directly (type stripping).
- **Engine is pure.** `src/engine/` does zero process/network I/O — bytes in,
  values out. This is why unit tests run offline, non-elevated, without tshark.
- **Status:** M1–M4a all DONE and verified (see `README.md` milestone table).

## 2. Protocol coverage right now

Decoded (in `src/engine/decoder.ts`): **Ethernet II** (incl. 802.1Q VLAN
stacking, bare-IP, raw 802.11/LLC-SNAP), **ARP** (described, not dissected),
**IPv4/IPv6** (fragment metadata described, NOT reassembled — v1 limitation;
IPv6 extension headers), **TCP** (ports, seq/ack, 8 flags, payload offsets),
**UDP**, **ICMP/ICMPv6** (IP-pair flows). Application metadata on top
(`src/engine/flows.ts`): **DNS over UDP and TCP** (A/AAAA/CNAME → hostname
attribution), **TLS ClientHello SNI** (metadata only, no decryption),
**HTTP/1.x** (method/URI/status/Content-Length; chunked detected, not
de-chunked), **WebSocket upgrade handshake**. QUIC/HTTP-3 is *identified* by
UDP/443 correlation but **not decoded**. Other IP protocols fall into a
`kind: "other"` bucket with the proto number recorded.

## 3. What verification/test infrastructure ALREADY exists

Do not rebuild these — understand them, then extend them:

| Layer | Where | What it is |
|---|---|---|
| Unit/integration tests | `test/*.test.ts` (3 suites, 36 tests) | Inline synthetic byte fixtures — every fixture layout is written in the test file itself. Run `npm test`. |
| tshark oracle: M1 | `src/verify/m1Verify.ts` (`npm run m1:verify`) | Frame-by-frame vs tshark on `out/m1.pcapng` (96 frames, 0 mismatches). |
| tshark oracle: M2 parity | `src/verify/parity.ts` (`src/verify/m3Matrix.ts` drives the corpus) | 21-column per-packet parity metric; 14 captured traces in `out/scen/` (13×100%, s10 low by design = risk R4). |
| tshark oracle: M3 matrix | `src/verify/m3Verify.ts` | conv/DNS/HTTP/retransmission checks per trace vs tshark. 14/14 full pass. |
| Gate suite | `src/testAll.ts` (`npm run test:all`) | All 8 gates in sequence (~45 s, offline, no UAC). **Run this after ANY change.** |

**tshark rules already established** (do not rediscover these):
- Packets the engine cannot decode count as *unsupported*, never as matches.
- tshark `-z conv` byte columns are SI floor-scaled (`floor(bytes/1000)`), so
  byte comparisons are inverted-window exact.
- Report src is in `docs/history/` + `docs/project-status.md` (living ledger
  with risk register). Read before claiming anything new is "proven".

## 4. Conventions you MUST follow (enforced by review + the gates)

1. **Engine stays pure.** `engine/` may import only `engine/`; garbage/truncated
   input never throws — failures go into `errors` arrays. New tests feed
   buffers and read values back. See layering table in `docs/ARCHITECTURE.md` §2.
2. **tshark is the oracle, never a dependency.** Engine code must not touch
   tshark; only `verify/` may spawn it (argv arrays, never shell strings).
3. **Fixtures are inline.** Byte layouts live in the test file (see
   `test/decoder.test.ts` builders `eth()`, `ip4()`, etc.) so failures can be
   diffed against exact bytes without reading engine code.
4. **Console output is load-bearing.** `testAll.ts` parses lines from commands
   (e.g. m3-verify's `done: N/N fully pass`). Do not reword existing strings.
5. **Honesty rule.** An "unsupported"/unverified result is reported as exactly
   that — never folded into a pass. Record new risks in `docs/project-status.md`.

## 5. Current test tooling note (important if you're switching frameworks)

- Present tests import `describe/it/expect` from **vitest** (devDependency) and
  run via `node --test test/decoder.test.ts test/flows.test.ts
  test/loopbacktap.test.ts` (`npm test`). It works today — 36/36 pass.
- **A separate agent is introducing Jest for the whole build.** If you take
  over mid-migration, check `package.json` first: whichever framework is
  wired into the `test` script is the source of truth. Keep the 36 existing
  cases green under `npm run test:all` regardless of the runner.

## 6. The current task — what the new test cases are for

Goal: write a **large set of new test cases** for the protocol coverage above,
cross-checked against tshark, and land them in `test/` (and, where they need
real captured traces, as named gates or scenario checks inside the existing
harnesses — see `docs/DEVELOPMENT.md` "how to add" recipes for a test, gate,
scenario, and report field). Suggested shape:

- New protocol-edge unit cases → extend the inline fixture builders, one test
  per behavior, name says what and why (existing style).
- Anything involving real traffic follows this loop:
  **generate traffic (non-elevated) → capture via pktmon (1 UAC) → decode with
  the engine → compare each claim vs tshark → record the comparison**, exactly
  like the M2/M3 harnesses. Nothing counts as passing because the code "looks
  right" — it passes because the oracle agrees.
- Bare-IP / raw-802.11 / VLAN / IPv6-ext-header / fragment-metadata /
  seq-wrap / retransmission-overlap are the highest-value edge areas.

## 7. Where to go deeper

| Doc | For |
|---|---|
| `docs/ARCHITECTURE.md` | layout, layering rules, data flow, design decisions |
| `docs/DEVELOPMENT.md` | setup, run-test:all-after-any-change rule, "how to add a scenario / decoder protocol / report field / gate" |
| `docs/project-status.md` | current ledger, risks (read §7 R4 before touching s10 parity), honest unknowns |
| `docs/history/` | verbatim dated milestone reports (evidence trail) |
