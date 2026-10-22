# Milestone 3 -- Flow Engine results

Run: 2026-10-22. Machine: Windows 11 build 26200.
Engine: Node.js v24.12.0, TypeScript 5.x (type-stripped, no transpile step).
Oracle: tshark 4.6.9.

## Test suite

| suite | pass | fail |
|---|---|---|
| decoder (synthetic) | 16 | 0 |
| flow-engine (synthetic) | 17 | 0 |
| total | 33 | 0 |

## M3.3 Verification matrix (14 traces vs tshark)

| trace | flows | EPBs | unique | conv-tcp | conv-udp | conv-icmp | dns | http | retrans | ok |
|---|---|---|---|---|---|---|---|---|---|---|
| m1_baseline | 4 | 96 | 48 | PASS 2/2 | PASS 2/2 | - | PASS 3/3 | - | PASS 2/2 | PASS |
| s1_https | 7 | 252 | 84 | PASS 7/7 | PASS 0/0 | - | - | - | PASS 7/7 | PASS |
| s2_http_external | 3 | 99 | 33 | PASS 3/3 | PASS 0/0 | - | - | PASS 6/6 | PASS 3/3 | PASS |
| s3_dns | 5 | 72 | 24 | PASS 2/2 | PASS 3/3 | - | PASS 4/4 | - | PASS 2/2 | PASS |
| s4_large | 6 | 4695 | 1565 | PASS | PASS | - | - | - | PASS | PASS |
| s5_tcp_lifecycle | 9 | 543 | 181 | PASS | PASS | - | - | - | PASS | PASS |
| s6_v4v6 | 10 | 198 | 66 | PASS | PASS | - | - | - | PASS | PASS |
| s7_parallel | 9 | 516 | 172 | PASS | PASS | - | - | - | PASS | PASS |
| s8_icmp | 4 | 30 | 10 | PASS | PASS | PASS 3/3 | - | - | PASS | PASS |
| s15_tlshello | 4 | 126 | 42 | PASS | PASS | - | - | - | PASS | PASS |
| s9_quic | 5 | 4320 | 1440 | PASS | PASS | - | - | - | PASS | PASS |
| s10_arpdhcp | 4 | 20 | 14 | PASS | PASS | - | - | - | PASS | PASS |
| s12_retrans | 12 | 36387 | 12129 | PASS | PASS | - | - | - | PASS 12/12 | PASS |
| s14_burst | 4 | 126 | 42 | PASS | PASS | - | - | - | PASS | PASS |
| TOTAL | | | | | | | | | | 14/14 |

Full per-check detail: test-results/milestone3-checks.md
Machine-readable JSON: out/scen/m3_results.json
