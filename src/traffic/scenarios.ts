// Milestone 2 scenario corpus (addendum): one trace + one results row per
// scenario. Core scenarios must reach >=90% packet parity vs tshark.
// Traffic generation is non-elevated; capture is elevated (one UAC click
// per batch, not per scenario).
//
// Layer:     traffic — scenario definitions (data + plan building; no direct I/O)
// Milestone: M2 addendum — scenario corpus (docs/history/milestone-2-report.md)
// Verified:  each definition produced its captured trace + parity row in test-results/milestone2-*.md
// Exports:   coreScenarios, extendedScenarios, buildPlans, ScenarioDef

import type { CapturePlan, CaptureFilterSpec, ComponentSelection } from "../capture/backend.ts";
import type { TrafficContext } from "./traffic.ts";
import {
  httpsFetch,
  httpExternalFetch,
  localHttpScenario,
  dnsMixed,
  httpsDownload,
  tcpLifecycleScenario,
  v4v6Scenario,
  parallelCurls,
  icmpScenario,
  quicScenario,
  arpDhcpScenario,
  loopbackScenario,
  wsScenario,
  retransmissionScenario,
  tlsHelloScenario,
  type TrafficResult,
} from "./traffic.ts";

const DEFAULT_COMPS: ComponentSelection = { kind: "ids", ids: [36, 74, 75] };
const NIC_STACK_COMPS: ComponentSelection = { kind: "ids", ids: [13, 36, 74, 75] };
/** Components whose per-comp pcapngs reveal loopback visibility. */
const ALL_CONV_IDS = [13, 33, 36, 74, 75];

/**
 * Filters are port/protocol-bound only. IP-bound filters were verified
 * working (`pktmon filter add ... -i <ip>` exit 0), but example.org /
 * cloudflare IPs ROTATE between resolutions (observed mid-batch: the trace
 * showed a different address than the resolved filter list), so IP binding
 * races the DNS rotation. Extra background traffic on port filters stays
 * parity-neutral: every captured packet is parsed by both decoders.
 */
function portFilter(
  name: string,
  transport: "TCP" | "UDP",
  port: number,
): CaptureFilterSpec[] {
  return [{ name, args: ["-t", transport, "-p", String(port)] }];
}

function portOnly(name: string, transport: "TCP" | "UDP", port: number): CaptureFilterSpec[] {
  return [{ name, args: ["-t", transport, "-p", String(port)] }];
}

export interface ScenarioDef {
  id: string;
  title: string;
  core: boolean;
  maxMB?: number;
  timeoutSec?: number;
  comps: ComponentSelection;
  convertIds?: number[];
  filters(ctx: TrafficContext): CaptureFilterSpec[];
  run(ctx: TrafficContext): Promise<TrafficResult>;
}

async function toResult(p: Promise<TrafficResult>): Promise<TrafficResult> {
  return p;
}

/** Core scenario definitions — each must reach the >=90% packet-parity threshold vs tshark. */
export function coreScenarios(): ScenarioDef[] {
  return [
    {
      id: "s1_https",
      title: "HTTPS TLS 1.3 download (stable endpoint example.org, informal)",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: (c) => [
        ...portFilter("https_v4", "TCP", 443),
        ...portFilter("https_v6", "TCP", 443),
      ],
      run: (c) => toResult(httpsFetch(c, 3)),
    },
    {
      id: "s2_http_external",
      title: "Plain HTTP request/response (external, TCP/80; captureable variant)",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: (c) => [
        ...portFilter("http_v4", "TCP", 80),
        ...portFilter("http_v6", "TCP", 80),
      ],
      run: (c) => toResult(httpExternalFetch(c, 3)),
    },
    {
      id: "s3_dns",
      title: "DNS: A, AAAA, NXDOMAIN (UDP/53) + DNS over TCP",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: () => [...portOnly("dns_udp_any", "UDP", 53), ...portOnly("dns_tcp_any", "TCP", 53)],
      run: (c) => toResult(dnsMixed(c)),
    },
    {
      id: "s4_large",
      title: "Several-MB download (speed.cloudflare.com, stable): segmentation/window",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 90,
      filters: (c) => [
        ...portFilter("dl_v4", "TCP", 443),
        ...portFilter("dl_v6", "TCP", 443),
      ],
      run: (c) => toResult(httpsDownload(c, 8_000_000, "s4")),
    },
    {
      id: "s5_tcp_lifecycle",
      title: "TCP lifecycle: connect, FIN close, RST, connection refused",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 75,
      filters: (c) => [
        ...portFilter("s5_443_v4", "TCP", 443),
        ...portFilter("s5_443_v6", "TCP", 443),
        ...portFilter("s5_59999_v4", "TCP", 59999),
        ...portFilter("s5_59999_v6", "TCP", 59999),
      ],
      run: (c) => toResult(tcpLifecycleScenario(c)),
    },
    {
      id: "s6_v4v6",
      title: "IPv4-only and IPv6-only runs (curl -4 / -6, HTTP+HTTPS)",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 75,
      filters: (c) => [
        ...portFilter("s6_443_v4", "TCP", 443),
        ...portFilter("s6_443_v6", "TCP", 443),
        ...portFilter("s6_80_v4", "TCP", 80),
        ...portFilter("s6_80_v6", "TCP", 80),
      ],
      run: (c) => toResult(v4v6Scenario(c)),
    },
    {
      id: "s7_parallel",
      title: "8 concurrent HTTPS curls: flow separation",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 80,
      filters: (c) => [
        ...portFilter("s7_v4", "TCP", 443),
        ...portFilter("s7_v6", "TCP", 443),
      ],
      run: (c) => toResult(parallelCurls(c, 8)),
    },
    {
      id: "s8_icmp",
      title: "ICMP echo (v4+v6) + 3000B ping forcing IPv4 fragmentation",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: () => [
        { name: "s8_icmp4", args: ["-t", "ICMP"] },
        { name: "s8_icmp6", args: ["-t", "ICMPv6"] },
      ],
      run: (c) => toResult(icmpScenario(c)),
    },
    {
      id: "s15_tlshello",
      title: "TLS 1.2 vs 1.3 ClientHello identification (SNI metadata only)",
      core: true,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: (c) => [
        ...portFilter("s15_v4", "TCP", 443),
        ...portFilter("s15_v6", "TCP", 443),
      ],
      run: (c) => toResult(tlsHelloScenario(c)),
    },
  ];
}

/** Extended/addendum scenario definitions (exploratory checks; the loopback
 * probes s2_local_split / s11_loopback / s13_ws live here — pktmon cannot see
 * them, which is the verified Finding A behind the M4a tap). */
export function extendedScenarios(): ScenarioDef[] {
  return [
    {
      id: "s9_quic",
      title: "QUIC/HTTP3 via headless Edge (UDP/443 identification, no decryption)",
      core: false,
      comps: DEFAULT_COMPS,
      timeoutSec: 90,
      filters: () => [...portOnly("s9_udp443", "UDP", 443), ...portOnly("s9_tcp443", "TCP", 443)],
      run: (c) => toResult(quicScenario(c)),
    },
    {
      id: "s2_local_split",
      title: "Plain HTTP with LOCALLY split header segments (loopback visibility probe)",
      core: false,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: () => portOnly("s2l_http_port", "TCP", 41237),
      run: (c) => toResult(localHttpScenario(c)),
    },
    {
      id: "s10_arpdhcp",
      title: "ARP (ping a fresh LAN address) + DHCP renewal attempt",
      core: false,
      comps: NIC_STACK_COMPS,
      timeoutSec: 75,
      filters: () => [
        { name: "s10_arp", args: ["-d", "ARP"] },
        ...portOnly("s10_dhcp67", "UDP", 67),
        ...portOnly("s10_dhcp68", "UDP", 68),
        { name: "s10_icmp4", args: ["-t", "ICMP"] },
      ],
      run: (c) => toResult(arpDhcpScenario(c)),
    },
    {
      id: "s11_loopback",
      title: "Localhost TCP + UDP between two processes (Test C): which component sees loopback",
      core: false,
      comps: { kind: "all" },
      convertIds: ALL_CONV_IDS,
      timeoutSec: 60,
      filters: () => [
        ...portOnly("s11_tcp41234", "TCP", 41234),
        ...portOnly("s11_udp41235", "UDP", 41235),
        ...portOnly("s11_tcp41237", "TCP", 41237),
      ],
      run: (c) => toResult(loopbackScenario(c)),
    },
    {
      id: "s12_retrans",
      title: "Retransmission probe: saturate Wi-Fi with concurrent TLS downloads",
      core: false,
      comps: DEFAULT_COMPS,
      timeoutSec: 90,
      filters: (c) => [
        ...portFilter("s12_v4", "TCP", 443),
        ...portFilter("s12_v6", "TCP", 443),
      ],
      run: (c) => toResult(retransmissionScenario(c)),
    },
    {
      id: "s13_ws",
      title: "WebSocket upgrade over plain HTTP (local server)",
      core: false,
      comps: DEFAULT_COMPS,
      timeoutSec: 60,
      filters: () => portOnly("s13_ws_port", "TCP", 41236),
      run: (c) => toResult(wsScenario(c)),
    },
    {
      id: "s14_burst",
      title: "Burst: 100 MB download, drop counters vs tshark packet count",
      core: false,
      comps: DEFAULT_COMPS,
      maxMB: 256,
      timeoutSec: 150,
      filters: (c) => [
        ...portFilter("s14_v4", "TCP", 443),
        ...portFilter("s14_v6", "TCP", 443),
      ],
      run: (c) => httpsDownload(c, 100_000_000, "s14"),
    },
  ];
}

/** Turn scenario definitions + the resolved traffic context into ordered
 * CapturePlans for the capture backend. */
export function buildPlans(
  scenarios: ScenarioDef[],
  ctx: TrafficContext,
): CapturePlan[] {
  return scenarios.map((s) => ({
    id: s.id,
    comps: s.comps,
    filters: s.filters(ctx),
    maxFileMB: s.maxMB ?? 64,
    trafficTimeoutSec: s.timeoutSec ?? 75,
    ...(s.convertIds ? { convertIds: s.convertIds } : {}),
  }));
}
