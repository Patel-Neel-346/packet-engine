# strobe-packet-tracker

High-performance, pure TypeScript network packet decoding and stateful flow-tracking engine. Designed for Windows (`pktmon` capture backend) and standard PCAP/PCAPNG capture workflows.

The engine operates with **zero runtime dependencies**, performs **no TLS decryption** (metadata only), and is formally verified against **Wireshark's `tshark 4.6.9` as an independent ground-truth oracle** across real network traces.

---

## Architecture Overview

```
 real traffic ──► pktmon ──► ETL ──► etl2pcap ──► out\*.pcapng
                   (in-box Windows tools; ONE UAC prompt per capture run)

 local app traffic ──► src/tap/ userspace loopback tap (no UAC, no drivers)
                       synthesizes PCAPNG traces of local socket traffic (Finding A)

                                     out\*.pcapng traces on disk
                                                │
                                                ▼
            ┌───────────────────────────────────────────────────────────────┐
            │ src/engine/ — Pure TypeScript Engine (Zero Process/Net I/O)   │
            │   parsePcapng ─► decodePacket ─► dedupePackets ─► buildFlows  │
            │   • Layered L2-L7 Dissection (Eth, IP, TCP, UDP, DNS, TLS)    │
            │   • Capture copy deduplication (content-hash + timestamp)     │
            │   • TCP sparse stream reassembly & sequence wraparound math   │
            │   • Conversation lifecycle & DNS attribution                  │
            │   • HTTP/1.x message parsing (pipelining & chunking)          │
            └───────────────────────────────────────────────────────────────┘
                                                │
                 ┌──────────────────────────────┼────────────────┐
                 ▼                              ▼                ▼
          src/verify/                    src/reporting/      src/cli.ts
          Continuous tshark oracle       HTML dashboard,     Single CLI entry:
          validation (M1 frames,         per-trace reports,  all scripts +
          M2 21-col parity, M3 matrix)   json/csv/md export  8-gate verifier
```

---

## Core Protocol & Engine Capabilities

### 1. Layer 2: Framing & Link Layer

- **Ethernet II** ([RFC 894](https://www.rfc-editor.org/rfc/rfc894)): MAC address parsing (`srcMac`, `dstMac`), EtherType resolution.
- **VLAN Tagging** (IEEE 802.1Q & IEEE 802.1ad QinQ): Parses single and stacked outer/inner VLAN tags (`0x8100`, `0x88a8`) up to 4 layers deep.
- **Address Resolution Protocol (ARP)** ([RFC 826](https://www.rfc-editor.org/rfc/rfc826)): Opcode detection (Request vs Reply), hardware/protocol addressing.
- **Bare IP Framing**: Recovers L3 packets lacking an L2 header (e.g. from Windows TCPIP pktmon provider components).
- **Raw 802.11 Wi-Fi Data Frames**: Automatically detects LLC/SNAP encapsulation (`0xAA 0xAA 0x03`) on Wi-Fi adapter components (`nwifi.sys`).

### 2. Layer 3: Network Layer

- **IPv4** ([RFC 791](https://www.rfc-editor.org/rfc/rfc791)):
  - Variable IHL options walk (up to 60 bytes).
  - One's-complement header checksum verification ([RFC 1071](https://www.rfc-editor.org/rfc/rfc1071)).
  - Identification and fragmentation handling (Flags: MF, DF, Fragment offset in bytes).
  - TSO zero-length tolerance & Ethernet trailing padding adjustment ([RFC 894](https://www.rfc-editor.org/rfc/rfc894)).
- **IPv6** ([RFC 8200](https://www.rfc-editor.org/rfc/rfc8200)):
  - Traffic Class & 20-bit Flow Label extraction.
  - Bounded extension header chain walking: Hop-by-Hop (0), Routing (43), Fragment (44), AH ([RFC 4302](https://www.rfc-editor.org/rfc/rfc4302)), Destination Options (60).
  - Canonical text formatting and zero-run compression ([RFC 5952](https://www.rfc-editor.org/rfc/rfc5952)), including IPv4-mapped addresses (`::ffff:a.b.c.d`).

### 3. Layer 4: Transport Layer

- **TCP** ([RFC 9293](https://www.rfc-editor.org/rfc/rfc9293)):
  - Full header dissection: sport, dport, 32-bit seq, ack, data offset, window size, urgent pointer.
  - Flag parsing: SYN, FIN, RST, PSH, ACK, URG.
  - Options parsing: Maximum Segment Size (MSS), Window Scale, SACK Permitted, Timestamps ([RFC 1323](https://www.rfc-editor.org/rfc/rfc1323)).
  - Transport checksum verification across IPv4/IPv6 pseudo-headers.
- **UDP** ([RFC 768](https://www.rfc-editor.org/rfc/rfc768)):
  - Length and port extraction, payload truncation detection, IPv6 jumbogram convention support ([RFC 2675](https://www.rfc-editor.org/rfc/rfc2675)).
  - Checksum validation: 0 allowed on IPv4, flagged on IPv6 ([RFC 8200 §8.1](https://www.rfc-editor.org/rfc/rfc8200#section-8.1)).
- **ICMP / ICMPv6** ([RFC 792](https://www.rfc-editor.org/rfc/rfc792) / [RFC 4443](https://www.rfc-editor.org/rfc/rfc4443)):
  - Message type, code, ping echo ID and sequence tracking.

### 4. Layer 7: Application Layer Metadata

- **DNS** ([RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)):
  - Parsed over both **UDP** and **TCP** (with 2-byte length prefix handling).
  - Question records (A, AAAA, CNAME, MX, TXT, PTR).
  - Answer records (A IPv4 literals, AAAA IPv6 literals, CNAME aliases, EDNS0 OPT metadata [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)).
  - Bounded compression pointer resolution with cycle detection to prevent infinite pointer loops.
- **TLS Handshake Metadata** ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)):
  - Dissects ClientHello and ServerHello records (metadata only; zero crypto/decryption).
  - Extracts Server Name Indication (SNI) ([RFC 6066](https://www.rfc-editor.org/rfc/rfc6066)).
  - Extracts `supported_versions` (e.g. TLS 1.3 `0x0304`, TLS 1.2 `0x0303`) and Encrypted ClientHello (ECH) presence.
- **HTTP/1.x Reconstruction** ([RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)):
  - Request methods (GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT), URI, version.
  - Response status code, reason phrase, header normalization (lowercase, comma-joined duplicates).
  - Pipelined request sequence handling, `Content-Length` bounds, and chunked transfer encoding detection.

### 5. Stateful Flow Tracking & Reassembly

- **Canonical Flow Keying**: Normalizes bidirectional 5-tuples (`canonicalFlow`) into `p<proto> <ipA>:<portA> <--> <ipB>:<portB>`.
- **Sparse Stream TCP Reassembly**: Reassembles out-of-order segments, tracks gaps (with 0x00 zero-padding), identifies retransmissions, and handles 32-bit unsigned sequence wraparound via modular signed distance arithmetic.
- **DNS Attribution**: Automatically attributes queried domain names to destination IPs and conversations.

---

## How to Use the Engine (API)

The packet engine is pure TypeScript and can be imported directly into any Node.js (>= 24) or TypeScript project:

### 1. Decode a Single Raw Packet

```typescript
import { decodePacket, flowIdOf } from "./src/engine/decoder.ts";

// linkType 1 = Ethernet II
const decoded = decodePacket(1, packetBuffer, packetBuffer.length);

console.log("Framing:", decoded.framing); // "ethernet" | "vlan" | "bareIP" | ...
console.log("L3 IP:", decoded.ip?.src, "->", decoded.ip?.dst);
console.log(
  "L4 Transport:",
  decoded.transport?.kind,
  decoded.transport?.sport,
  "->",
  decoded.transport?.dport,
);

// If DNS payload was present:
if (decoded.dns) {
  console.log(
    "DNS Queries:",
    decoded.dns.questions.map((q) => q.name),
  );
  console.log("A Records:", decoded.dns.aRecords);
}

// If TLS ClientHello was present:
if (decoded.tls?.sni) {
  console.log("TLS SNI:", decoded.tls.sni);
}

// Canonical flow conversation ID:
console.log("Flow ID:", flowIdOf(decoded));
// e.g. "p6 10.0.0.1:54321 <--> 93.184.216.34:443"
```

### 2. Analyze a Complete PCAPNG File & Build Flows

```typescript
import { analyzePcapFile } from "./src/engine/flows.ts";

const analysis = analyzePcapFile("out/scen/s1_https_all.pcapng");

console.log(`Total EPB Frames: ${analysis.totalEpbs}`);
console.log(`Duplicates Merged: ${analysis.duplicatesMerged}`);
console.log(`Unique Flows: ${analysis.flows.length}`);

for (const flow of analysis.flows) {
  console.log(`\nFlow: ${flow.id} (${flow.kind.toUpperCase()})`);
  console.log(`  Endpoints: ${flow.a.ip}:${flow.a.port} <--> ${flow.b.ip}:${flow.b.port}`);
  console.log(`  Packets: A->B: ${flow.packets.a2b}, B->A: ${flow.packets.b2a}`);
  console.log(`  Attributed Hostnames: ${flow.hosts.join(", ") || "none"}`);
  if (flow.tlsSni.length > 0) {
    console.log(`  TLS SNI: ${flow.tlsSni.join(", ")}`);
  }
  if (flow.tcp) {
    console.log(`  Handshake Complete: ${flow.tcp.handshakeComplete}`);
    console.log(`  Retransmitted Segments: ${flow.uniqueRetransSegs}`);
  }
}
```

---

## Command Reference

### 1. Testing & Verification

| Command                     | Description                                                                              | Duration    |
| :-------------------------- | :--------------------------------------------------------------------------------------- | :---------- |
| **`npm test`**              | Runs **Jest** across all 14 test suites (208 unit/fuzz/oracle tests) with verbose output | ~8 seconds  |
| **`npm run test:watch`**    | Interactive Jest watcher for rapid TDD development                                       | Live        |
| **`npm run test:coverage`** | Generates code coverage report via Istanbul                                              | ~10 seconds |
| **`npm run test:all`**      | Runs the full **8-gate release verification suite** (see table below) against `tshark`   | ~55 seconds |
| **`npm run typecheck`**     | Strict TypeScript compilation check (`tsc --noEmit`)                                     | ~2 seconds  |
| **`npm run format`**        | Formats all code using Prettier                                                          | ~1 second   |
| **`npm run format:check`**  | Validates code style against Prettier                                                    | ~1 second   |

### 2. Reporting & Exports

```powershell
# Generate interactive HTML dashboard over all captured traces:
npm run m4:report

# Continuously watch out/scen/ and regenerate the dashboard on changes:
npm run m4:watch

# Export trace analysis to Markdown, CSV, or JSON:
npm run m4:export out/scen/s3_dns_all.pcapng md
npm run m4:export out/scen/s3_dns_all.pcapng csv
npm run m4:export out/scen/s2_http_external_all.pcapng json
```

### 3. Capture Workflow (Windows Administrator)

```powershell
# Milestone 1: Elevated pktmon single-session capture
npm run m1:capture
npm run m1:pick
npm run m1:verify

# Milestone 2: Live scenario batches with automatic tshark parity cross-checking
npm run m2:core
npm run m2:ext

# Milestone 4a: Non-elevated userspace loopback tap verification
npm run m4:loopback
```

---

## The 8-Gate Verification Model (`npm run test:all`)

Every layer of the engine is validated against an independent oracle (`tshark 4.6.9`). `npm run test:all` executes all 8 gates in sequence and exits `0` only when all pass:

| Gate  | Name                    | What It Proves                                            | Oracle Verification                                         |
| :---: | :---------------------- | :-------------------------------------------------------- | :---------------------------------------------------------- |
| **1** | **`typecheck`**         | Whole-project TypeScript type-safety                      | `tsc --noEmit` clean                                        |
| **2** | **`unit-tests`**        | 208 unit, edge-case, and fuzz tests across 14 test suites | Real capture oracle checks against `tshark`                 |
| **3** | **`m1-verify`**         | Frame-by-frame 1:1 cross-check of captured frames         | Compared against `tshark -r <trace> -T json` (0 mismatches) |
| **4** | **`parity-regression`** | 14 real-world network scenario traces                     | 21-column parity matrix compared against tshark baselines   |
| **5** | **`m3-matrix`**         | 14/14 trace full conversation matrix                      | Verifies conversations & bytes against `tshark -z conv,*`   |
| **6** | **`m4-dashboard`**      | HTML dashboard generation across entire corpus            | Renders `out/m4-reports/index.html` (43 KB)                 |
| **7** | **`m4-export-formats`** | Data serialization validation                             | Validates JSON, CSV, and Markdown exports                   |
| **8** | **`m4a-loopback`**      | Userspace loopback tap (HTTP, WS, TCP Echo)               | Proves application ground truth + `tshark` gate pass        |

---

## Repository Structure

```
strobe-packet-tracker/
├── src/
│   ├── cli.ts                # Main CLI command dispatcher
│   ├── paths.ts              # Output directory paths
│   ├── testAll.ts            # The 8-gate verification orchestrator
│   ├── engine/               # PURE packet engine (zero external dependencies)
│   │   ├── decoder.ts        # Layered packet dissector (L2 through L7)
│   │   ├── dedupe.ts         # IP hash deduplication
│   │   ├── flows.ts          # Stateful flow analysis & TCP stream reassembly
│   │   ├── pcapng.ts         # Raw PCAPNG parser
│   │   └── pcapngwrite.ts    # Synthetic PCAPNG writer
│   ├── capture/              # Windows pktmon runner & ETL conversion
│   ├── traffic/              # Scenario generators & test server fixtures
│   ├── verify/               # Independent tshark oracle validation harnesses
│   ├── reporting/            # HTML dashboard, watch daemon, and exports
│   └── tap/                  # Userspace loopback tap
├── test/                     # 208 Jest unit & hardening tests (14 suites)
│   ├── decoder.test.ts
│   ├── flows.test.ts
│   ├── loopbacktap.test.ts
│   ├── tshark-oracle.test.ts # Direct tshark oracle assertions
│   └── hardening/            # RFC compliance catalog test suites (A through K)
├── docs/                     # Architecture, Development Guide, and History
├── test-results/             # Verified gate reports (test-all.md)
└── out/                      # Generated traces, dashboards, and reports
```

---

## Prerequisites

- **OS**: Windows 10/11 (for `pktmon` live capture). Offline parsing & tests run on any platform.
- **Node.js**: `>= 24.0.0` (supports native TypeScript execution).
- **Wireshark / tshark**: Tested on `4.6.9` (used strictly as an independent verifier).
- **Permissions**: Standard user for parsing, analysis, and testing. Administrator (1 UAC prompt) only needed when running live `pktmon` packet capture.
