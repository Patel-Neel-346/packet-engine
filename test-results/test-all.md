# test-all — full verification suite

_run: 2026-10-22T18:27:27.228Z  |  total 48.4s  |  8/8 gates pass_

| gate | result | detail | time |
|---|---|---|---|
| typecheck | PASS | tsc --noEmit clean | 1.6s |
| unit-tests | PASS | pass=36 fail=0 | 4.3s |
| parity-regression | PASS | 14 traces: 14 traces at thresholds, exceptions: none | 5.3s |
| m3-matrix | PASS | 14/14 traces fully pass | 20.7s |
| m4-dashboard | PASS | dashboard 43KB | 1.9s |
| m4-export-formats | PASS | md: ok csv: ok json: ok | 0.6s |
| m1-verify | PASS | frame-by-frame vs tshark: all pass | 28.6s |
| m4a-loopback | PASS | 3 scenarios (s2_local_split=pass,s13_ws=pass,s11_loopback=pass) | 14.1s |

**ALL GATES PASS**