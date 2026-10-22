# test-all — full verification suite

_run: 2026-10-22T17:41:56.582Z  |  total 47.8s  |  8/8 gates pass_

| gate | result | detail | time |
|---|---|---|---|
| typecheck | PASS | tsc --noEmit clean | 1.6s |
| unit-tests | PASS | pass=36 fail=0 | 4.3s |
| parity-regression | PASS | 14 traces: 14 traces at thresholds, exceptions: none | 6.1s |
| m3-matrix | PASS | 14/14 traces fully pass | 20.5s |
| m4-dashboard | PASS | dashboard 43KB | 2.0s |
| m4-export-formats | PASS | md: ok csv: ok json: ok | 0.8s |
| m1-verify | PASS | frame-by-frame vs tshark: all pass | 29.8s |
| m4a-loopback | PASS | 3 scenarios (s2_local_split=pass,s13_ws=pass,s11_loopback=pass) | 12.6s |

**ALL GATES PASS**