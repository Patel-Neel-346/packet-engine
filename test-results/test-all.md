# test-all — full verification suite

_run: 2026-10-23T15:50:50.860Z  |  total 46.1s  |  8/8 gates pass_

| gate | result | detail | time |
|---|---|---|---|
| typecheck | PASS | tsc --noEmit clean | 1.7s |
| unit-tests | PASS | pass=36 fail=0 across 3 files | 0.9s |
| parity-regression | PASS | 14 traces: 14 traces at thresholds, exceptions: none | 5.7s |
| m3-matrix | PASS | 14/14 traces fully pass | 22.3s |
| m4-dashboard | PASS | dashboard 43KB | 2.0s |
| m4-export-formats | PASS | md: ok csv: ok json: ok | 0.7s |
| m1-verify | PASS | frame-by-frame vs tshark: all pass | 30.9s |
| m4a-loopback | PASS | 3 scenarios (s2_local_split=pass,s13_ws=pass,s11_loopback=pass) | 12.8s |

**ALL GATES PASS**