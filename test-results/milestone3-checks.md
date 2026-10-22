# Milestone 3.3 — flow-engine verification vs tshark 4.6.9

Per trace: frame-direction counts on the raw-trace conv tables; byte
sums on the deduped-export conv tables; DNS record map, HTTP story
aggregates, and per-flow retransmission counts (deduped export).

## m1_baseline — ALL PASS

- flows=4, EPBs=96, dedup export: unique=48 exported=48 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 2/2 |
> detail: our flows=2, tshark rows=2, exact-bytes rows=2
| conv-udp | PASS | 2/2 |
> detail: our flows=2, tshark rows=2, exact-bytes rows=2
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 3/3 |
> detail: tshark response records=2, keys compared=3
| retransmission-stories | PASS | 2/2 |
> detail: deduped export: unique=48 exported=48 skippedNoEthernet=0
> detail: total retrans flagged by tshark=2, ours=1

## s1_https — ALL PASS

- flows=7, EPBs=252, dedup export: unique=84 exported=84 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 7/7 |
> detail: our flows=7, tshark rows=7, exact-bytes rows=4
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 7/7 |
> detail: deduped export: unique=84 exported=84 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s2_http_external — ALL PASS

- flows=3, EPBs=99, dedup export: unique=33 exported=33 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 3/3 |
> detail: our flows=3, tshark rows=3, exact-bytes rows=3
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| http-stories | PASS | 6/6 |
> detail: requests: ours=3 tshark=3; responses: ours=3 tshark=3
| retransmission-stories | PASS | 3/3 |
> detail: deduped export: unique=33 exported=33 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s3_dns — ALL PASS

- flows=5, EPBs=72, dedup export: unique=24 exported=24 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 2/2 |
> detail: our flows=2, tshark rows=2, exact-bytes rows=2
| conv-udp | PASS | 3/3 |
> detail: our flows=3, tshark rows=3, exact-bytes rows=3
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 4/4 |
> detail: tshark response records=8, keys compared=4
| retransmission-stories | PASS | 2/2 |
> detail: deduped export: unique=24 exported=24 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s4_large — ALL PASS

- flows=6, EPBs=4695, dedup export: unique=1565 exported=1565 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 6/6 |
> detail: our flows=6, tshark rows=6, exact-bytes rows=4
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 6/6 |
> detail: deduped export: unique=1565 exported=1565 skippedNoEthernet=0
> detail: total retrans flagged by tshark=43, ours=43

## s5_tcp_lifecycle — ALL PASS

- flows=15, EPBs=543, dedup export: unique=181 exported=181 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 15/15 |
> detail: our flows=15, tshark rows=15, exact-bytes rows=12
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| http-stories | PASS | 4/4 |
> detail: requests: ours=2 tshark=2; responses: ours=2 tshark=2
| retransmission-stories | PASS | 15/15 |
> detail: deduped export: unique=181 exported=181 skippedNoEthernet=0
> detail: total retrans flagged by tshark=10, ours=0

## s6_v4v6 — ALL PASS

- flows=6, EPBs=198, dedup export: unique=66 exported=66 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 6/6 |
> detail: our flows=6, tshark rows=6, exact-bytes rows=4
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| http-stories | PASS | 4/4 |
> detail: requests: ours=2 tshark=2; responses: ours=2 tshark=2
| retransmission-stories | PASS | 6/6 |
> detail: deduped export: unique=66 exported=66 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s7_parallel — ALL PASS

- flows=10, EPBs=516, dedup export: unique=172 exported=172 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 10/10 |
> detail: our flows=10, tshark rows=10, exact-bytes rows=2
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 10/10 |
> detail: deduped export: unique=172 exported=172 skippedNoEthernet=0
> detail: total retrans flagged by tshark=3, ours=0

## s8_icmp — ALL PASS

- flows=3, EPBs=30, dedup export: unique=10 exported=10 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 3/3 |
> detail: icmp flows=3, compared=3, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 0/0 |
> detail: deduped export: unique=10 exported=10 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s15_tlshello — ALL PASS

- flows=4, EPBs=126, dedup export: unique=42 exported=42 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 4/4 |
> detail: our flows=4, tshark rows=4, exact-bytes rows=2
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 4/4 |
> detail: deduped export: unique=42 exported=42 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s9_quic — ALL PASS

- flows=45, EPBs=4320, dedup export: unique=1440 exported=1440 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 39/39 |
> detail: our flows=39, tshark rows=39, exact-bytes rows=15
| conv-udp | PASS | 6/6 |
> detail: our flows=6, tshark rows=6, exact-bytes rows=3
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 39/39 |
> detail: deduped export: unique=1440 exported=1440 skippedNoEthernet=0
> detail: total retrans flagged by tshark=3, ours=2

## s10_arpdhcp — ALL PASS

- flows=1, EPBs=20, dedup export: unique=14 exported=14 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-udp | PASS | 1/1 |
> detail: our flows=1, tshark rows=1, exact-bytes rows=1
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 0/0 |
> detail: deduped export: unique=14 exported=14 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

## s12_retrans — ALL PASS

- flows=12, EPBs=36387, dedup export: unique=12129 exported=12129 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 12/12 |
> detail: our flows=12, tshark rows=12, exact-bytes rows=7
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 12/12 |
> detail: deduped export: unique=12129 exported=12129 skippedNoEthernet=0
> detail: total retrans flagged by tshark=16, ours=16

## s14_burst — ALL PASS

- flows=4, EPBs=126, dedup export: unique=42 exported=42 skippedNoEthernet=0

| check | status | passes |
|---|---|---|
| conv-tcp | PASS | 4/4 |
> detail: our flows=4, tshark rows=4, exact-bytes rows=3
| conv-udp | PASS | 0/0 |
> detail: our flows=0, tshark rows=0, exact-bytes rows=0
| conv-icmp-pairs | PASS | 0/0 |
> detail: icmp flows=0, compared=0, protocol-mixed pairs excluded=0
| dns-attribution | PASS | 0/0 |
> detail: tshark response records=0, keys compared=0
| retransmission-stories | PASS | 4/4 |
> detail: deduped export: unique=42 exported=42 skippedNoEthernet=0
> detail: total retrans flagged by tshark=0, ours=0

---

**Summary: 14/14 traces fully pass; 0 with findings.**