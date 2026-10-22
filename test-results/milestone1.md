# strobe-packet-tracker — Milestone 1 results (recorded 2026-10-21)

Everything below is **actual output** from runs on this Windows 11 (26200)
machine. Results in this file were produced with `node src/cli.ts m1-*`.

## C1. Privilege behavior (precheck, non-elevated)

Command: `node src/cli.ts m1-capture` (precheck phase)

```
pktmon status (non-elevated): exit=5 out="Failed to communicate with the PktMon driver: Access is denied."
Expected non-admin behavior observed (exit 5 + access denied): capture steps will run elevated.
```

Result: **PASS as specified** — clear, actionable, no crash. (Test F form:
without elevation the prototype still exits cleanly with guidance to approve
UAC or run elevated pktmon manually.)

## C2. Capture run (elevated, one UAC prompt)

Command: `node src/cli.ts m1-capture` (bundle)

Step table (exit codes are REAL pktmon exit codes from the elevated shell):

```
[stop]            code=0  "Packet Monitor is not running."
[filterRemove]    code=0  "Removed all filters."
[listJson]        code=0
[filterAdd4_0..1] code=0  "Filter added."   (TCP 104.20.26.136 / 172.66.157.237 :443)
[filterAdd6_0]    code=0  "Filter added."   (TCP 2606:4700:... :443)
[filterAddDns]    code=0  "Filter added."   (UDP 53)
[filterList]      code=0  4 filters active (recorded verbatim in out/m1.log)
[start]           code=0  --comp 33 36 74 75 --pkt-size 0 --log-mode multi-file
[curl1]           code=0  https://example.org/ fetched
[curl2]           code=0  https://example.org/ fetched
[counters]        code=0  NIC/per-component counters captured in log
[stopAfter]       code=0  "Log file: ...m12.etl (No events lost)"
[etl2pcapAll]     code=0  Packets total: 144, drop count: 2, formatted: 144
[etl2pcapComp36]  code=0  144 total -> 96 formatted
[etl2pcapComp33]  code=0  144 total -> 0 formatted        (not on active path)
[etl2pcapComp74]  code=0  144 total -> 44 formatted
[etl2pcapComp75]  code=0  144 total -> 4 formatted
[RESULT] OK size=57668
```

Result: **PASS** — real trace produced from an actual HTTPS exchange.

## C3. Independent verification

Command: `node src/cli.ts m1-verify` (non-elevated; parses the selected trace
and re-reads the same file with tshark 4.6.9)

```
SHB: v1.0 littleEndian=true
IDB#0: linkType=1 (Ethernet) snaplen=0 if_tsresol=6
EPBs: 96 | skipped blocks: [{"blockType":5,"count":1}] | parse errors: 0
TShark (Wireshark) 4.6.9 ...
tshark frames: 96
Compare: 96 frames, mismatches=0, max time delta=0us (tolerance 2us)
Truncation: capLen < origLen on 0 frames
Layer check: 96 frames decoded with a full Ethernet L2 stack
Port distribution: {"udp:56850,53":1,"udp:51324,53":1,"udp:53,56850":1,
                    "udp:53,51324":1,"tcp:65123,443":11,"tcp:443,65123":10,
                    "tcp:65131,443":11,"tcp:443,65131":12,"other:":48}
Distinct flows observed: 4
  flow udp 10.66.52.167:56850 <--> 10.66.52.203:53
  flow udp 10.66.52.167:51324 <--> 10.66.52.203:53
  flow tcp 2401:4900:c008:e380:fd48:8174:c8ce:4a69:65123 <--> 2606:4700:...:443
  flow tcp 2401:4900:c008:e380:fd48:8174:c8ce:4a69:65131 <--> 2606:4700:...:443
Duplicates: byte-identical groups=0; same-timestamp groups=1 covering 2 frames
[VERIFY] PASS (mismatches=0)
```

Result: **PASS** — our PCAPNG parse matches tshark exactly frame-for-frame.

## C4. Component pick (why comp 36 is the primary vantage)

Command: `node src/cli.ts m1-pick`

```
comp 33: packets=0   fullL2=0   bareL3=0  decodedIP=0
comp 36: packets=96  fullL2=96  bareL3=0  decodedIP=48
comp 74: packets=44  fullL2=44  bareL3=0  decodedIP=44
comp 75: packets=4   fullL2=4   bareL3=0  decodedIP=4
Selected component 36 (m1_comp36.pcapng) -> out/m1.pcapng
```

Facts recorded:
- Inside comp 36, 48 frames decode as IP; the other 48 are the SAME packets
  logged a second time in raw 802.11 form (tshark "eth.type" 0x4dba/0x5888 =
  802.11 frame-control bytes; hexdump shows LLC/SNAP `aa aa 03 00 00 00 86 dd`
  + IPv6). Milestone 2's decoder will handle this framing.
- Cross-component duplicates (the all-components file, 144 frames) split
  cleanly via documented `--component-id` conversions (96+0+44+4 = 144).

## What Test A proves so far (limited, informal)

Using the approved informal endpoint (example.org): packets of a real HTTPS
exchange (SYN, handshake, data, FIN) are captured and the TCP/TLS flows are
identifiable (IPs, ports, timing, direction). HTTPS content stays metadata
only by design. Hardening with a self-owned endpoint remains open (Test A full).

## Not yet claimed

- Real-time/live capture: unverified (pktmon has a real-time log mode in help
  text only); file-based pipeline is what was tested.
- Localhost capture: untested (Milestone 5 / Test C).
- Proxy correlation: untested (Milestone 5).
