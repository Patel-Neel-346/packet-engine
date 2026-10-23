# test-all — full verification suite

_run: 2026-10-23T17:36:25.280Z  |  total 46.7s  |  8/8 gates pass_

| gate | result | detail | time |
|---|---|---|---|
| typecheck | PASS | tsc --noEmit clean | 1.7s |
| unit-tests | PASS | pass=208 fail=0 across 14 files | 6.6s |
| parity-regression | PASS | 14 traces: 14 traces at thresholds, exceptions: none | 4.9s |
| m3-matrix | PASS | 14/14 traces fully pass | 19.0s |
| m4-dashboard | PASS | dashboard 43KB | 1.8s |
| m4-export-formats | PASS | md: ok csv: ok json: ok | 0.6s |
| m1-verify | PASS | frame-by-frame vs tshark: all pass | 26.5s |
| m4a-loopback | PASS | 3 scenarios (s2_local_split=pass,s13_ws=pass,s11_loopback=pass) | 12.0s |

**ALL GATES PASS**

## Case-by-Case Test Breakdown


### ✅ PASS: `test/hardening/framing.test.ts`

- [x] framing A1: plain Ethernet II + IPv4 -> EtherType 0x0800 detected, MACs decoded (RFC 894) (10 ms)
- [x] framing A2: Ethernet II + IPv6 -> EtherType 0x86DD detected, IPv6 parsed (RFC 8200) (2 ms)
- [x] framing A3: single 802.1Q tag (0x8100) -> VLAN id + PCP decoded, inner EtherType used (IEEE 802.1Q) (2 ms)
- [x] framing A4: double tag 802.1ad 0x88A8 + 0x8100 -> both tags recorded (IEEE 802.1ad Q-in-Q) (2 ms)
- [x] framing A5: triple-stacked VLAN -> decoded up to the documented 4-tag limit (decoder guard=4) (1 ms)
- [x] framing A6: VLAN tag truncated after TPID (no TCI bytes) -> error 'ethernet:', no throw (802.1Q) (1 ms)
- [x] framing A7: ARP request -> kind 'arp', opcode recorded, no flow created (RFC 826) (1 ms)
- [x] framing A7b: ARP reply -> opcode 2 decoded (RFC 826) (1 ms)
- [x] framing A8: bare IPv4 with no Ethernet header (non-Ethernet linkType) -> framing 'bareIP' (1 ms)
- [x] framing A9: bare IPv6 (no L2) -> framing 'bareIP', IPv6 fields decoded (1 ms)
- [x] framing A10: raw 802.11 data frame, non-QoS (LLC/SNAP at offset 24) -> IP decoded (IEEE 802.11) (2 ms)
- [x] framing A10b: raw 802.11 QoS data frame (LLC/SNAP at offset 26) -> IP decoded (1 ms)
- [x] framing A11: unknown EtherType 0x4dba WITH a consistent IP payload -> engine recovers (documented rule) (1 ms)
- [x] framing A11b: unknown EtherType with NO IP payload -> L2 fields kept, framing 'ethernet', counted unsupported (error recorded) (1 ms)
- [x] framing A12: frame shorter than 14 bytes -> error 'ethernet: frame too short', no throw (1 ms)
- [x] framing A13: empty and 1-byte buffers -> error recorded, no throw (1 ms)
- [x] framing A14: ambiguous first nibble 0x5 -> neither bare-IP nor recovered, framing 'unknown' (detection rule) (3 ms)

### ✅ PASS: `test/decoder.test.ts`

- [x] decodes Ethernet→IPv4→TCP fully and normalizes the flow id (direction-independent) (11 ms)
- [x] decodes a double VLAN tag and records both VLAN ids (2 ms)
- [x] decodes bare-IP framing when there is no Ethernet header (linktype 1 or 228) (1 ms)
- [x] decodes raw 802.11 QoS frames (LLC/SNAP payload starts at offset 26) (7 ms)
- [x] extracts questions + A + AAAA + CNAME (via compression pointer) over UDP (8 ms)
- [x] parses DNS carried inside TCP by skipping the 2-byte length prefix (1 ms)
- [x] terminates on a self-referencing DNS label pointer instead of hanging (1 ms)
- [x] records IPv4 fragment fields (MF bit + offset) but never fakes reassembly (1 ms)
- [x] walks the IPv6 hop-by-hop extension-header chain and still decodes TCP (1 ms)
- [x] describes the IPv6 fragment header without reassembling (M3 scope) (1 ms)
- [x] recovers packets with an unknown ethertype that still carry IP, recording the oddity (1 ms)
- [x] reports truncated headers, bad IP versions, corrupt checksums, mid-VLAN cuts (1 ms)
- [x] never throws on empty or 1–3 byte inputs
- [x] returns the documented DecodedPacket shape even for garbage (3 ms)
- [x] extracts SNI from a minimal TLS ClientHello — record version, legacy version, hostname (2 ms)
- [x] routes ARP to the arp kind and touches no IP decoder (1 ms)

### ✅ PASS: `test/hardening/ipv6.test.ts`

- [x] ipv6 C1: valid header -> addresses, hop limit, next header, traffic class, flow label (RFC 8200 §3) (10 ms)
- [x] ipv6 C2: payload length > captured -> truncation error, partial IP fields kept (RFC 8200 §3.5) (1 ms)
- [x] ipv6 C3: payload length 0 with hop-by-hop (jumbogram convention) -> documented v1 limit: L3+L4 decoded, payloadLen stays 0 (RFC 2675 §3) (2 ms)
- [x] ipv6 C4a: hop-by-hop header alone (0) -> chain walked, TCP found (RFC 8200 §4.3) (3 ms)
- [x] ipv6 C4b: routing header alone (43) -> chain walked, TCP found (RFC 8200 §4.4) (3 ms)
- [x] ipv6 C4c: fragment header alone (44) -> walked, TCP at the right offset (RFC 8200 §4.5) (1 ms)
- [x] ipv6 C4d: destination-options alone (60) -> chain walked, TCP found (RFC 8200 §4.6) (1 ms)
- [x] ipv6 C4e: AH alone (51) -> walked per RFC 4302 (NEXT HEADER IS AH BYTE 0; engine bug fixed here) (2 ms)
- [x] ipv6 C5: chain of 3 mixed extension headers -> TCP found at the correct offset (RFC 8200 §4) (5 ms)
- [x] ipv6 C6: extension header length field points past end -> error, no throw (RFC 8200 §4) (1 ms)
- [x] ipv6 C7: chain of MORE than 8 extension headers -> error 'ipv6: chain too long' (documented limit) (1 ms)
- [x] ipv6 C8: exactly 8 ext headers then TCP -> walks fully (bounded, at the documented limit); completes well under 250ms (7 ms)
- [x] ipv6 C9a: fragment header -> offset, M flag and identification recorded on ip (RFC 8200 §4.5)
- [x] ipv6 C9b: non-first fragment (offset > 0) -> NO L4 decode, metadata only (same rule as IPv4)
- [x] ipv6 C10: atomic fragment (offset 0, M=0) -> L4 decoded (RFC 8200 §4.5) (1 ms)
- [x] ipv6 C11: next header 59 (No Next Header) -> payload absent, transport 'other', no error (RFC 8200 §4.7)
- [x] ipv6 C12: version nibble not 6 (0x75) -> error, no throw (RFC 8200 §3.1) (1 ms)
- [x] ipv6 C13: link-local, loopback(::1), v4-mapped ::= text form per RFC 5952 (lowercase, longest zero run) (1 ms)
- [x] ipv6 C14: format roundtrip — parse(format(addr)) == addr for 20 seeded random addresses (RFC 5952 §2.1) (5 ms)

### ✅ PASS: `test/hardening/tcp.test.ts`

- [x] tcp D1: ports, seq, ack, window, urgent pointer decode (RFC 9293 §3.3.1) (12 ms)
- [x] tcp D2: each flag alone -> exactly that flag bitmask; all 8 together -> full byte (RFC 9293 §3.3.1.1) (3 ms)
- [x] tcp D3: data offset 5 and 15 -> payload offset correct (RFC 9293 §3.3.1) (3 ms)
- [x] tcp D4a: data offset < 5 -> error 'tcp: bad data offset', ports still returned (RFC 9293 §3.3.1) (1 ms)
- [x] tcp D4b: data offset beyond captured -> error 'tcp: bad data offset', ports still returned (1 ms)
- [x] tcp D5a: SAS/timestamp options parsed to metadata; unknown option kind skipped by its length (RFC 9293 §3.3.1) (1 ms)
- [x] tcp D5b: option length 1 (malformed, would loop) -> error 'tcp.bad-options', bounded walk stops (RFC 793 §3.1 minimum) (1 ms)
- [x] tcp D5c: option overruns the data-offset boundary -> error 'tcp.bad-options', no crash (1 ms)
- [x] tcp D6: payload length derives from IP total length, NOT captured bytes, when Ethernet padding exists (1 ms)
- [x] tcp D7: zero-length payload with ACK-only -> decoded, payloadLen 0 (RFC 9293 §3.3.1) (1 ms)
- [x] tcp D8: checksum valid -> flag true (IPv4 + IPv6 pseudo-header); corrupted -> false, and decode continues (RFC 9293 §2.2) (4 ms)
- [x] tcp D8b: UDP-style checksum 0 remains mandatory for TCP — stored 0 never counts as valid (RFC 9293 §2.2) (1 ms)
- [x] tcp D9a: header split at exactly 19 captured bytes -> error, no throw (truncation boundary)
- [x] tcp D9b: header split at exactly 20 captured bytes -> complete header, decoded (31 ms)
- [x] tcp D10: port 0 -> decodes cleanly with no error and no warning-side-effect (documented rule) (13 ms)
- [x] tcp D11: seq and ack 0xFFFFFFFF decode as unsigned (no negatives) (RFC 9293 §3.3.3)
- [x] tcp D12: segment inside the FIRST fragment of a fragmented datagram -> decoded AND flagged fragmented (RFC 791 §3.2)

### ✅ PASS: `test/hardening/ipv4.test.ts`

- [x] ipv4 B1: valid header -> addresses, TTL, protocol, total length, identification, checksum flag (RFC 791 §3.1) (10 ms)
- [x] ipv4 B2a: IHL=4 (<20 bytes) -> error 'ipv4: bad IHL', no throw, no IP fields returned (RFC 791 §3.1) (2 ms)
- [x] ipv4 B2b: IHL=5 -> OK; IHL=15 (60B header with options) -> OK with options length 40 (2 ms)
- [x] ipv4 B3: options present -> payload (L4) starts after the options block (RFC 791 §3.1.2) (2 ms)
- [x] ipv4 B4: total length > captured bytes -> error 'ipv4.truncated', partial L3 fields kept (RFC 791 §3.1) (24 ms)
- [x] ipv4 B5: total length < IHL*4 (nonzero) -> error 'ipv4.bad-total-length' (RFC 791 §3.1) (8 ms)
- [x] ipv4 B6: total length < captured (Ethernet padding) -> trailing pad NOT counted as payload (RFC 894 §3.2.1) (2 ms)
- [x] ipv4 B7: version nibble not 4 (0x55) on a bare frame -> error, no throw (RFC 791 §3.1) (1 ms)
- [x] ipv4 B8: checksum valid -> flag true; one flipped bit -> flag false but decode CONTINUES (RFC 791) (6 ms)
- [x] ipv4 B9a: first fragment (MF=1, offset 0) -> transport decoded AND fragment metadata present (RFC 791 §3.2) (1 ms)
- [x] ipv4 B9b: middle fragment (MF=1, offset > 0) -> NO L4 decode (metadata only); tcp ports absent (no reassembly in v1) (1 ms)
- [x] ipv4 B9c: last fragment (MF=0, offset > 0) -> metadata only, unique-host bytes intact (1 ms)
- [x] ipv4 B10: DF flag set -> recorded; reserved bit set -> still decoded, metadata kept (RFC 791/9293 note)
- [x] ipv4 B11: fragment offset + length overflow past 65535 -> fragment byte-offset recorded as-is, no throw (RFC 791)
- [x] ipv4 B12: fragments out of order -> each fragment described independently, no silent reassembly (v1 documented limit) (3 ms)
- [x] ipv4 B13a: TTL=0 -> decodes with TTL recorded (RFC 791)
- [x] ipv4 B13b: TTL=255 -> decodes with TTL recorded (RFC 791) (1 ms)
- [x] ipv4 B14: protocol numbers 1/6/17/47/50/89 -> kind mapped, others carry the proto number (RFC 790) (1 ms)

### ✅ PASS: `test/hardening/dns.test.ts`

- [x] dns F1: question types A/AAAA/CNAME/MX/TXT/PTR -> name+type recorded for each (RFC 1035 §3.4) (11 ms)
- [x] dns F2a: response with a CNAME chain -> answerNames holds the alias chain, aRecords the A value (RFC 1035 §3.4.1) (2 ms)
- [x] dns F3: rcode 3, 2, 5 decoded from flags (RFC 1035 §4.1.1) (1 ms)
- [x] dns F4a: name compression pointer to an EARLIER name -> resolved, bounded (RFC 1035 §4.1.4) (1 ms)
- [x] dns F4b: self-referencing pointer (0xc00c at offset 12) -> terminates with a NAMED error, bounded (RFC 1035 §4.1.4) (1 ms)
- [x] dns F4c: mutual pointer pair (A->B, B->A) -> terminates with error, bounded (1 ms)
- [x] dns F4d: pointer past end of message -> error 'dns.pointer-target', partial fields kept (1 ms)
- [x] dns F4e: pointer INTO the 12-byte header (target 0) -> error 'dns.pointer-target' (RFC 1035 §4.1.4)
- [x] dns F5a: label length exactly 63 -> decodes (boundary, RFC 1035 §2.3.4)
- [x] dns F5b: label length 64 -> error 'dns.label-too-long', no bogus question recorded (RFC 1035 §2.3.4) (1 ms)
- [x] dns F5c: name exceeding 255 bytes -> error 'dns.name-too-long' (RFC 1035 §2.3.4) (1 ms)
- [x] dns F7: ANCOUNT 5 but only 2 answers present -> 2 parsed + truncation error 'dns.truncated-answers' (1 ms)
- [x] dns F8: A record with rdata length 3 (not 4) -> error 'dns.bad-rdata-length' (RFC 1035 §3.4.1) (3 ms)
- [x] dns F9: TC flag set on a truncated response -> truncated: true decoded (RFC 1035 §4.1.1) (1 ms)
- [x] dns F10a: SYN or port-53 TCP packet with no payload -> no DNS parse, no phantom error (17 ms)
- [x] dns F11: random garbage on port 53 -> bounded named errors, no throw, no bogus names (1 ms)
- [x] dns F12: EDNS0 OPT record (type 41) in answers -> flagged as edns, NEVER counted as an A record (RFC 6891 §6.1.2) (1 ms)
- [x] dns F13: case mixing (ExamPLE.orG) -> preserved verbatim (attribution lowercases later, RFC 1035 §2.3.3)
- [x] dns F15: QDCOUNT 2 -> both questions parsed within the bounded ≤10 question walk (engine rule) (1 ms)
- [x] dns F2b: response over IPv6 -> identical DNS fields (UDP transport is family-neutral, RFC 3596 §2.1) (9 ms)
- [x] dns F4f: pointer to a pointer -> chained compression resolves cleanly (RFC 1035 §4.1.4) (1 ms)
- [x] dns F6: root name '.' -> decoded as '.' (RFC 1035 §3.1) (10 ms)
- [x] dns F14: internationalized / punycode names (xn--) -> decoded as-is (RFC 5890 §2.3.2.1) (7 ms)
- [x] dns F16: response whose ID does not match any query -> still decoded without throwing (RFC 1035 §4.1.1) (1 ms)

### ✅ PASS: `test/hardening/http-flows.test.ts`

- [x] http H1: GET/200 over a NON-standard port (8080) -> parsed identically (content decides, not the port) (18 ms)
- [x] http H2: three pipelined requests -> requests.length 3 in order (RFC 9112 §9.3) (4 ms)
- [x] http H3: >8 pipelined requests -> parse stops at the 8-cap with parsingStopped 'limit' (engine bound) (3 ms)
- [x] http H4: response WITHOUT content-length -> body runs to end of stream, bodyComplete true (RFC 9112 §6.3) (20 ms)
- [x] http H5: header names are lowercased; duplicate headers join with ', ' (RFC 9110 §5.5) (3 ms)
- [x] http H6: request-only flow (no response bytes) -> no http block fabricated (3 ms)
- [x] http H7: binary garbage both directions -> no http block, no throw (14 ms)
- [x] http H8: declared body longer than captured -> bodyComplete false (capture truncation, reported honestly) (2 ms)
- [x] http H2b: request split at EVERY byte boundary -> identical decoded request each time (RFC 9112 §2.1) (48 ms)
- [x] http H3b: request line only, headers arrive in next segment -> method, uri, headers decoded (RFC 9112 §2.1) (1 ms)
- [x] http H4b: headers end split across segments inside CRLFCRLF -> header boundary recognized (RFC 9112 §2.1) (1 ms)
- [x] http H12: methods POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT -> method extracted correctly (RFC 9110 §9) (5 ms)
- [x] http H13: HTTP/1.0 vs 1.1 version captured; HTTP/2 preface ignored (RFC 9113 §3.4) (2 ms)
- [x] http H15: retransmitted segment inside a request -> request is not duplicated (sparse-stream dedupe) (1 ms)
- [x] http H16: out-of-order segments of one request -> reassembled in sequence order (sparse-stream order) (1 ms)

### ✅ PASS: `test/hardening/tls.test.ts`

- [x] tls G1: ClientHello with SNI -> recordVersion/legacyVersion/handshake/sni decoded, no error (3 ms)
- [x] tls G2: SNI over IPv6 port 443 -> same metadata (transport family is neutral) (1 ms)
- [x] tls G4a: supported_versions -> ['0304','0303'] entries preserved (RFC 8446 §4.2.1) (1 ms)
- [x] tls G5: ECH extension (0xfe0d / GREASE 0xfe0e) -> ech flag; the OUTER SNI is what is reported (draft-esni) (1 ms)
- [x] tls G6: ServerHello (type 0x02) -> handshake 'serverHello', no SNI invented (1 ms)
- [x] tls G7: ClientHello with NO SNI extension -> tls info present, sni undefined, no error (1 ms)
- [x] tls G8a: extension list overrun AND SNI found -> named error 'tls.truncated-extensions' with partial decode kept (1 ms)
- [x] tls G8b: extension overrun WITHOUT a real SNI -> stays silent (encrypted-port probe must not misclassify QUIC, learned on s9)
- [x] tls G9: random encrypted-looking payload on port 443 -> no tls block, NO errors, no throw (s9 QUIC silence rule) (1 ms)
- [x] tls G10: app-data record (0x17) on 443 -> no tls block, no phantom error (only hello records are dissected)
- [x] tls G12: static scan — engine never spawns processes, never tshark outside comments, never imports crypto except local hashing (5 ms)
- [x] tls G3: SNI with trailing dot or IP literal -> recorded as-is (RFC 6066 §3) (1 ms)
- [x] tls G5b: extension list length 0 -> decoded cleanly with no extensions, no error (RFC 8446 §4.1.2) (1 ms)
- [x] tls G9b: TLS alert record (0x15) -> no TLS handshake/SNI decoded, no errors, no throw (RFC 8446 §5.1)
- [x] tls G14: even-length supported_versions extension (missing 1-byte list length) -> safely skipped, no throw (RFC 8446 §4.2.1)

### ✅ PASS: `test/hardening/flows.test.ts`

- [x] flow I1: TLS SNI from a ClientHello inside a flow is attributed to that flow's tlsSni (27 ms)
- [x] flow I2: canonical endpoints are ordered (a = the lower ip:port string) regardless of who spoke first (6 ms)
- [x] flow I3: duplicate EPBs count in packets/bytes (EPB view) but merge in the deduped view (7 ms)
- [x] flow I4: same 4-tuple on UDP vs TCP = two different flows (proto is part of the key) (16 ms)
- [x] flow I5: DNS answer attribution maps the queried name onto the answer IP (dnsHostByIp + flow hosts) (3 ms)
- [x] flow I6: flow time span uses the packet timestamps (lastTs - firstTs = spacing over the span) (4 ms)
- [x] flow I7: ICMP request+reply map to ONE IP-pair flow (port-free keying, both directions counted) (1 ms)
- [x] flow I9: SYN/ACK without captured SYN (late capture) -> flow created, synAck recorded (catalog I9) (4 ms)
- [x] flow I10: mid-stream capture with no SYN -> baseAssumed flag set on stream (catalog I10) (1 ms)
- [x] flow I14: same ports on different IPs -> distinct flows (5-tuple uniqueness) (1 ms)
- [x] flow I15: 32-bit sequence wraparound (RFC 9293 §3.4) -> reassembles across 0xFFFFFFFF boundary with 0 gaps (1 ms)
- [x] flow I19: overlapping retransmission (partial overlap) -> partialRetransSegs recorded, novel bytes appended (1 ms)
- [x] flow I25: bytes and packets per direction are exact for multi-packet exchange (catalog I25) (2 ms)

### ✅ PASS: `test/flows.test.ts`

- [x] formats 0B / B / KB / MB with the SI-scaled scheme used in reports (30 ms)
- [x] a clean handshake?data?FIN connection sets handshakeComplete and both FINs, with no RST (16 ms)
- [x] an RST is recorded and blocks handshakeComplete (1 ms)
- [x] three simultaneous connections (2 TCP-style + 1 UDP) become three distinct flows (14 ms)
- [x] out-of-order segments are placed in sequence order, gap-free (2 ms)
- [x] a missing segment is recorded as a gap and zeroed in the stream bytes (2 ms)
- [x] a fully-covered retransmitted segment counts once in retransSegs (dedupe uses 5000us spacing) (1 ms)
- [x] UDP flows keep per-direction packet counts (1 ms)
- [x] ICMP is keyed by the IP pair alone (no ports involved) (1 ms)
- [x] GET + 200 with Content-Length parses head AND body completeness (7 ms)
- [x] chunked Transfer-Encoding is detected and stops parsing as 'chunked', not 'end' (3 ms)
- [x] an A record maps the answered IP to the queried name (dnsHostByIp) (2 ms)
- [x] same-hash packets within the 2000us tolerance collapse into one unique group (12 ms)
- [x] same-hash packets OUTSIDE the tolerance are two separate uniques (not a copy) (1 ms)
- [x] victim of fragmentation: a non-first IPv4 fragment goes to fragments[], NOT flows[] (1 ms)
- [x] non-IP frames (ARP ethertype) are counted as nonFlowEpbs
- [x] an empty PCAPNG produces zero flows and zero warnings

### ✅ PASS: `test/loopbacktap.test.ts`

- [x] writes SHB + one IDB (tsresol=6 µs) + EPBs that parsePcapng reads back byte-exactly (34 ms)
- [x] replays a hand-built connection story with consistent seq/ack ordering and exact frame sizes (10 ms)
- [x] records the echo conversation verbatim and synthesizes checkable frames with valid checksums (65 ms)

### ✅ PASS: `test/hardening/udp-icmp.test.ts`

- [x] udp E1a: ports + declared datagram length decode; payload length = len - 8 (RFC 768 §3) (2 ms)
- [x] udp E1b: declared length 1-7 -> error 'udp.bad-length' (RFC 768 minimum is 8) (1 ms)
- [x] udp E1c: declared length beyond captured -> error 'udp.truncated', partial fields kept (1 ms)
- [x] udp E1d: declared length 0 -> tolerated as the IPv6 jumbogram convention (RFC 2675 §3.1, documented) (1 ms)
- [x] udp E2a: correct checksum over IPv4 pseudo-header -> checksumValid true (RFC 768 §4) (1 ms)
- [x] udp E2b: checksum 0 over IPv4 -> ALLOWED (RFC 768), flagged via checksumZero (catalog E2) (1 ms)
- [x] udp E2c: checksum 0 over IPv6 -> flagged as a DEFECT (RFC 8200 §8.1 requires the checksum)
- [x] udp E2d: corrupted checksum over IPv6 -> checksumValid false, decode continues
- [x] icmp E3a: echo request (type 8 code 0) -> type/code/id/seq decoded as metadata (RFC 792) (1 ms)
- [x] icmp E3b: echo reply (type 0) -> id/seq decoded (RFC 792) (1 ms)
- [x] icmp E3c: destination unreachable (type 3) -> type/code decoded; embedded original header stays UNDECODED (documented v1 limit) (1 ms)
- [x] icmp E4: ICMPv6 echo request/reply (128/129) -> type/code + echo id/seq (RFC 4443 §4.1) (1 ms)
- [x] icmp E5a: ICMP truncated below type+code -> error 'icmp.truncated', no throw (RFC 792 §2) (1 ms)
- [x] icmp E5b: ICMPv6 truncated below type+code -> error 'icmpv6.truncated' (RFC 4443 §2.1)
- [x] icmp E6: ICMP inside the fragment stream (first fragment) -> decoded and pair-consistent (design note, s8 parity rule)

### ✅ PASS: `test/hardening/dedupe-fuzz.test.ts`

- [x] dedupe J1: the same IP packet as bare-IP and ethernet copies -> IDENTICAL ipHash (framing tolerance) (13 ms)
- [x] dedupe J2: representative = FIRST member (reprIdx stable), every EPB index survives in members (4 ms)
- [x] dedupe J3: a non-IP packet (arp etc.) has ipHash null and forms its OWN group (2 ms)
- [x] dedupe J4: tolerance compares against the REPRESENTATIVE (first) ts — chains beyond the window do NOT merge (2 ms)
- [x] dedupe J5: tolerance edge — copies 1999µs and 2001µs apart -> merged and not merged respectively (M2 dedupe rule) (4 ms)
- [x] dedupe J6: genuine retransmission (200ms apart) -> NOT merged (catalog J2) (22 ms)
- [x] dedupe J7: different IP payloads with identical timestamp -> distinct groups (content-based hashing) (6 ms)
- [x] fuzz K1: 25k fully-random buffers (len 0..150) never throw and always return an errors ARRAY (3261 ms)
- [x] fuzz K2: every prefix truncation of structured frames decodes without throwing (partial state honest) (168 ms)
- [x] fuzz K3: single-bit flips across 5k variants never throw (decode continues or names the failure) (185 ms)
- [x] fuzz K4: deterministic — the same seed replays the identical error sequence (mulberry32 replay, catalog K) (341 ms)
- [x] fuzz K5: valid packet with each length field set to 0, 1, max, max-1 -> bounded errors, never throws (catalog K5) (1 ms)
- [x] fuzz K6: round-trip property test — generated valid packets decode back to identical input fields (500 cases, catalog K6) (104 ms)
- [x] fuzz K7: flow tracker fed a random shuffle of segments -> never throws, totals invariant (catalog K7) (3 ms)
- [x] fuzz K8: DNS parser fed random cyclic pointer graphs -> always terminates in bounded time (<100ms, catalog K8) (5 ms)

### ✅ PASS: `test/tshark-oracle.test.ts (5.231 s)`

- [x] tshark oracle: s1_https_all.pcapng -> TCP conversations & retransmissions match tshark 4.6.9 (1341 ms)
- [x] tshark oracle: s3_dns_all.pcapng -> DNS attribution, TCP/UDP conversations match tshark 4.6.9 (1171 ms)
- [x] tshark oracle: s8_icmp_all.pcapng -> ICMP pair conversations match tshark 4.6.9 (1052 ms)
- [x] tshark oracle: s2_http_external_all.pcapng -> HTTP stories & conversations match tshark 4.6.9 (1292 ms)