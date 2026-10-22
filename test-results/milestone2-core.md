# Milestone 2 — scenario corpus results (batch: core)

Captured 2026-10-21 23:52 local (UTC+5:30), signal-handshake-fixed run.
Parity target: >= 90% for core scenarios (M2 addendum).

| scenario | uniquePkts | dupsMerged | parity | unsupported | traceEPBs | extras |
|---|---|---|---|---|---|---|
| s1_https | 84 | 168 | 100% | 0 | 252 |  |
| s2_http_external | 33 | 66 | 100% | 0 | 99 |  |
| s3_dns | 24 | 48 | 100% | 0 | 72 |  |
| s4_large | 1565 | 3130 | 100% | 0 | 4695 |  |
| s5_tcp_lifecycle | 181 | 362 | 100% | 0 | 543 |  |
| s6_v4v6 | 66 | 132 | 100% | 0 | 198 |  |
| s7_parallel | 172 | 344 | 100% | 0 | 516 |  |
| s8_icmp | 10 | 20 | 100% | 0 | 30 |  |
| s15_tlshello | 42 | 84 | 100% | 0 | 126 |  |

## detail

### s1_https
- trace: exists=True bytes=94996 epbs=252
- step: https_fetch_0:exit=0:200 577B
- step: https_fetch_1:exit=0:200 577B
- step: https_fetch_2:exit=0:200 577B
- parity: unique=84 matched=84 parity=100% unsupported=0 dupsMerged=168
- framing={"ethernet": 168, "raw80211": 84} protocolMatrix={"tcp": {"decoded": 84, "partial": 0, "unsupported": 0}}
- flows: ours=7 tshark=7 match=True
### s2_http_external
- trace: exists=True bytes=21056 epbs=99
- note: plain HTTP over TCP/80 to example.org (301 redirect expected from the edge)
- step: http_fetch_0:exit=0:200 577B
- step: http_fetch_1:exit=0:200 577B
- step: http_fetch_2:exit=0:200 577B
- parity: unique=33 matched=33 parity=100% unsupported=0 dupsMerged=66
- framing={"ethernet": 66, "raw80211": 33} protocolMatrix={"tcp": {"decoded": 33, "partial": 0, "unsupported": 0}}
- flows: ours=3 tshark=3 match=True
### s3_dns
- trace: exists=True bytes=8620 epbs=72
- step: dns_udp_A_example.org:exit=0:rcode=0 answers=2
- step: dns_udp_AAAA_cloudflare.com:exit=0:rcode=0 answers=2
- step: dns_udp_NXDOMAIN:exit=0:rcode=3 (3=NXDOMAIN expected)
- step: dns_tcp_A_example.org@1.1.1.1:exit=0:rcode=0 tcpUsed=true
- step: dns_tcp_AAAA@1.1.1.1:exit=0:rcode=0
- parity: unique=24 matched=24 parity=100% unsupported=0 dupsMerged=48
- framing={"ethernet": 48, "raw80211": 24} protocolMatrix={"udp": {"decoded": 6, "partial": 0, "unsupported": 0}, "tcp": {"decoded": 18, "partial": 0, "unsupported": 0}}
- flows: ours=5 tshark=5 match=True
### s4_large
- trace: exists=True bytes=26209544 epbs=4695
- step: s4_download:exit=0:200 8000000B 4157973Bps
- parity: unique=1565 matched=1565 parity=100% unsupported=0 dupsMerged=3130
- framing={"ethernet": 3130, "raw80211": 1565} protocolMatrix={"tcp": {"decoded": 1565, "partial": 0, "unsupported": 0}}
- flows: ours=6 tshark=6 match=True
### s5_tcp_lifecycle
- trace: exists=True bytes=152684 epbs=543
- note: expected: SYN then RST/ACK for 59999 (refused), FIN close for 443
- step: fin_close_via_443:exit=0:400
- step: rst_destroy_node:exit=0:(Node resetAndDestroy/destroy after partial request) code=0
- step: refused_port_59999:exit=28:curl: (28) Connection timed out after 10013 milliseconds
- parity: unique=181 matched=181 parity=100% unsupported=0 dupsMerged=362
- framing={"ethernet": 362, "raw80211": 181} protocolMatrix={"tcp": {"decoded": 181, "partial": 0, "unsupported": 0}}
- flows: ours=15 tshark=15 match=True
### s6_v4v6
- trace: exists=True bytes=66636 epbs=198
- step: curl4_https:exit=0:200 172.66.157.237
- step: curl6_https:exit=0:200 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: curl4_http:exit=0:200 172.66.157.237
- step: curl6_http:exit=0:200 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- parity: unique=66 matched=66 parity=100% unsupported=0 dupsMerged=132
- framing={"ethernet": 132, "raw80211": 66} protocolMatrix={"tcp": {"decoded": 66, "partial": 0, "unsupported": 0}}
- flows: ours=6 tshark=6 match=True
### s7_parallel
- trace: exists=True bytes=213436 epbs=516
- note: 8 concurrent HTTPS flows (independent source ports expected)
- step: parallel_curl_0:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: parallel_curl_1:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: parallel_curl_3:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: parallel_curl_5:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: parallel_curl_4:exit=0:200 via 172.66.157.237
- step: parallel_curl_7:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- step: parallel_curl_2:exit=0:200 via 172.66.157.237
- step: parallel_curl_6:exit=0:200 via 2606:4700:90d6:6c5e:b1c5:56d:525:2b85
- parity: unique=172 matched=172 parity=100% unsupported=0 dupsMerged=344
- framing={"ethernet": 344, "raw80211": 172} protocolMatrix={"tcp": {"decoded": 172, "partial": 0, "unsupported": 0}}
- flows: ours=10 tshark=10 match=True
### s8_icmp
- trace: exists=True bytes=21068 epbs=30
- note: 3000B payload against MTU 1500 forces IPv4 fragmentation (3 fragments)
- step: ping_v4_example.org:exit=0:Pinging example.org [172.66.157.237] with 32 bytes of data: Reply from 172.66.157.237: bytes=32 time=69ms TTL=54 Ping statistics for 172.66.157.237:
- step: ping_v6_example.org:exit=0:Pinging example.org [2606:4700:90d6:6c5e:b198:56e:525:2b85] with 32 bytes of data: Reply from 2606:4700:90d6:6c5e:b198:56e:525:2b85: time=57ms Ping s
- step: ping_v4_3000B_fragmented:exit=0:Pinging 10.66.52.203 with 3000 bytes of data: Reply from 10.66.52.203: bytes=3000 time=6ms TTL=64 Ping statistics for 10.66.52.203: Packets: Sent = 1
- parity: unique=10 matched=10 parity=100% unsupported=0 dupsMerged=20
- framing={"ethernet": 20, "raw80211": 10} protocolMatrix={"icmp": {"decoded": 8, "partial": 0, "unsupported": 0}, "icmpv6": {"decoded": 2, "partial": 0, "unsupported": 0}}
- flows: ours=0 tshark=0 match=True
### s15_tlshello
- trace: exists=True bytes=52100 epbs=126
- step: tls13_default:exit=0:200
- step: tls12_forced:exit=0:200
- parity: unique=42 matched=42 parity=100% unsupported=0 dupsMerged=84
- framing={"ethernet": 84, "raw80211": 42} protocolMatrix={"tcp": {"decoded": 42, "partial": 0, "unsupported": 0}}
- flows: ours=4 tshark=4 match=True
