# Milestone 2 — scenario corpus results (batch: ext)

Captured 2026-10-21 23:52 local (UTC+5:30), signal-handshake-fixed run.
Parity target: >= 90% for core scenarios (M2 addendum).

| scenario | uniquePkts | dupsMerged | parity | unsupported | traceEPBs | extras |
|---|---|---|---|---|---|---|
| s9_quic | 1440 | 2880 | 100% | 0 | 4320 | quicFrames=370, udp443=374 |
| s2_local_split | - | - | n/a | - | 0 |  |
| s10_arpdhcp | 14 | 6 | 14.3% | 12 | 20 | arpByComponent=comp13:arp=0 comp36:arp=3 comp74:arp=0 comp75:arp=3 |
| s11_loopback | - | - | n/a | - | 0 | epbsByComponent=c13=0 c33=0 c36=0 c74=0 c75=0, epbsAll=0, otherComponentsSaw=0 |
| s12_retrans | 12129 | 24258 | 100% | 0 | 36387 | tsharkRetransmissions=8421 |
| s13_ws | - | - | n/a | - | 0 |  |
| s14_burst | 42 | 84 | 100% | 0 | 126 | tsharkFrameCount=126 |

## detail

### s9_quic
- trace: exists=True bytes=6241104 epbs=4320
- note: using headless Edge against cloudflare-quic.com (QUIC-capable site)
- note: QUIC (UDP/443) presence is verified from the captured trace, not from the browser claim
- step: edge_headless_quic:exit=0:exit=0 dom=128152B
- parity: unique=1440 matched=1440 parity=100% unsupported=0 dupsMerged=2880
- framing={"ethernet": 2880, "raw80211": 1440} protocolMatrix={"udp": {"decoded": 187, "partial": 0, "unsupported": 0}, "tcp": {"decoded": 1253, "partial": 0, "unsupported": 0}}
- flows: ours=45 tshark=45 match=True
### s2_local_split
- trace: exists=True bytes=200 epbs=0
- note: split-http server bound on 127.0.0.1:41237
- note: split-http server bound on 10.66.52.167:41237
- note: loopback visibility is decided empirically by the capture, not assumed
- note: parity skipped: no packets captured
- step: local_http_loopback_client1:exit=0:status=200 bytes=142
- step: local_http_loopback_client2_big:exit=0:status=200 bytes=4196
- step: local_http_siteip_client:exit=0:status=200 bytes=142
### s10_arpdhcp
- trace: exists=True bytes=4320 epbs=20
- step: ping_arp_probe_10.66.52.254:exit=1:Pinging 10.66.52.254 with 32 bytes of data: Request timed out. Ping statistics for 10.66.52.254: Packets: Sent = 1, Rec
- step: ping_arp_probe_again_10.66.52.254:exit=0:Pinging 10.66.52.254 with 32 bytes of data: Reply from 10.66.52.167: Destination host unreachable. Ping statistics for
- step: arp_a_snapshot:exit=0:Interface: 10.66.52.167 --- 0x8 Internet Address Physical Address Type 10.66.52.203 0e-90-58-88-96-a5 dynamic 10.66.52.255 ff-ff-ff-ff-ff-ff static 224.0.0.22 01-00-5e-00-00-16 static 224.0.0.251 01-
- step: ipconfig_renew:exit=0:Windows IP Configuration No operation can be performed on Ethernet while it has its media disconnected. No operation can be performed on Local Area Connection*
- parity: unique=14 matched=2 parity=14.3% unsupported=12 dupsMerged=6
- framing={"ethernet": 16, "raw80211": 4} protocolMatrix={"arp": {"decoded": 0, "partial": 0, "unsupported": 6}, "no-ip": {"decoded": 0, "partial": 0, "unsupported": 6}, "udp": {"decoded": 2, "partial": 0, "unsupported": 0}}
- flows: ours=1 tshark=1 match=True
- sample: #0 (ethernet) unsupported: 
- sample: #1 (ethernet) unsupported: 
- sample: #2 (ethernet) unsupported: unknown ethertype 0x4dba (no IP payload found); no IP packet located
- sample: #3 (ethernet) unsupported: unknown ethertype 0x4dba (no IP payload found); no IP packet located
- sample: #4 (ethernet) unsupported: 
### s11_loopback
- trace: exists=True bytes=200 epbs=0
- note: parity skipped: no packets captured
- step: tcp_loopback_127.0.0.1:exit=0:roundtrip-ok
- step: tcp_loopback_10.66.52.167:exit=0:roundtrip-ok
- step: udp_loopback_127.0.0.1:exit=0:echoed=true
### s12_retrans
- trace: exists=True bytes=86632076 epbs=36387
- note: retransmission reality is checked against tshark tcp.analysis.retransmission on the captured trace
- step: saturation_curl_1:exit=0:200 8000000B
- step: saturation_curl_0:exit=0:200 8000000B
- step: saturation_curl_2:exit=0:200 8000000B
- step: saturation_curl_3:exit=0:200 8000000B
- parity: unique=12129 matched=12129 parity=100% unsupported=0 dupsMerged=24258
- framing={"ethernet": 24258, "raw80211": 12129} protocolMatrix={"tcp": {"decoded": 12129, "partial": 0, "unsupported": 0}}
- flows: ours=12 tshark=12 match=True
### s13_ws
- trace: exists=True bytes=200 epbs=0
- note: WS upgrade served over plain HTTP (RFC 6455 upgrade, no TLS)
- note: parity skipped: no packets captured
- step: ws_upgrade_127.0.0.1:exit=0:got101=true gotFrame=true
- step: ws_upgrade_10.66.52.167:exit=0:got101=true gotFrame=true
### s14_burst
- trace: exists=True bytes=44688 epbs=126
- step: s14_download:exit=0:403 1B 5Bps
- parity: unique=42 matched=42 parity=100% unsupported=0 dupsMerged=84
- framing={"raw80211": 42, "ethernet": 84} protocolMatrix={"tcp": {"decoded": 42, "partial": 0, "unsupported": 0}}
- flows: ours=4 tshark=4 match=True
