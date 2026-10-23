// Non-elevated traffic generators for Milestone 2 scenarios.
// Every generator spawns REAL tools present on this machine (in-box curl,
// ping, PowerShell) or uses Node sockets directly — argv arrays only, no
// shell strings. Results are recorded verbatim for the milestone report.
//
// Layer:     traffic — real-network I/O (curl/ping/Edge + raw sockets; non-elevated)
// Milestone: M2 — scenario traffic generators (docs/history/milestone-2-report.md)
// Verified:  generated the traffic behind all 14 captured traces; step results recorded verbatim in the milestone reports
// Exports:   one generator per scenario (s1..s15) + buildTrafficContext, resolveBoth, ipFilters, curl

import dns from "node:dns";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { runCommand } from "../capture/pktmon.ts";
import { dnsQueryUdp, dnsQueryTcp } from "./dnsgen.ts";
import {
  startSplitHttpServer,
  splitHttpRequest,
  startWsEchoServer,
  wsClientUpgrade,
  udpEchoRound,
} from "./localservers.ts";

export interface StepRecord {
  step: string;
  code: number | null;
  detail: string;
}

export interface TrafficContext {
  exampleV4: string[];
  exampleV6: string[];
  speedV4: string[];
  speedV6: string[];
  quicV4: string[];
  quicV6: string[];
  resolver: string;
  localIp: string;
  /** Loopback-local ports chosen for servers. */
  httpPort: number;
  wsPort: number;
  udpPort: number;
}

export interface TrafficResult {
  steps: StepRecord[];
  notes: string[];
}

function note(res: TrafficResult, s: string): void {
  res.notes.push(s);
}

function rec(res: TrafficResult, step: string, code: number | null, out: string, keep = 200): void {
  res.steps.push({ step, code, detail: out.replace(/\s+/g, " ").trim().slice(0, keep) });
}

// ------------------------------------------------------------- environment

/** Resolve a hostname to its IPv4 and IPv6 address lists (empty on failure; never throws). */
export async function resolveBoth(host: string): Promise<{ v4: string[]; v6: string[] }> {
  const out = { v4: [] as string[], v6: [] as string[] };
  await dns.promises.resolve4(host).then(
    (a) => (out.v4 = a),
    () => {
      /* NXDOMAIN-ish */
    },
  );
  await dns.promises.resolve6(host).then(
    (a) => (out.v6 = a),
    () => {
      /* NXDOMAIN-ish */
    },
  );
  return out;
}

function firstLocalSiteIp(): string {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const ni of interfaces[name] ?? []) {
      if (ni.family === "IPv4" && !ni.internal) return ni.address;
    }
  }
  return "127.0.0.1";
}

/** Resolve every endpoint the scenarios need, plus local IPs/ports, once per batch run. */
export async function buildTrafficContext(): Promise<TrafficContext> {
  const example = await resolveBoth("example.org");
  const speed = await resolveBoth("speed.cloudflare.com");
  const quic = await resolveBoth("cloudflare-quic.com");
  let resolver = dns.getServers()[0] ?? "10.66.52.203";
  if (resolver.includes(":")) resolver = "10.66.52.203"; // need v4 literal for ping/udp4
  return {
    exampleV4: example.v4,
    exampleV6: example.v6,
    speedV4: speed.v4,
    speedV6: speed.v6,
    quicV4: quic.v4,
    quicV6: quic.v6,
    resolver,
    localIp: firstLocalSiteIp(),
    httpPort: 41237,
    wsPort: 41236,
    udpPort: 41235,
  };
}

// ------------------------------------------------------------------ helpers

/** Run in-box curl.exe with an argv array and record the step result (re-exported). */
async function curl(res: TrafficResult, args: string[], step: string): Promise<void> {
  const r = await runCommand("C:\\Windows\\System32\\curl.exe", args, { timeoutMs: 120_000 });
  rec(res, step, r.code, `${(r.stdout || r.stderr).slice(0, 120)}`);
}

/** Build one pktmon CaptureFilterSpec per IP (`-i <ip> -t <transport> -p <port>`). */
export function ipFilters(
  ips: string[],
  port: number,
  transport: "TCP" | "UDP",
  namePrefix: string,
): Array<{ name: string; args: string[] }> {
  return ips.map((ip, i) => ({
    name: `${namePrefix}_${i}`,
    args: ["-i", ip, "-t", transport, "-p", String(port)],
  }));
}

// --------------------------------------------------------------- generators

/** s1: n sequential HTTPS fetches from example.org (TLS 1.3 by default). */
export async function httpsFetch(ctx: TrafficContext, n = 3): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  for (let i = 0; i < n; i++) {
    await curl(
      res,
      [
        "--noproxy",
        "*",
        "-s",
        "-S",
        "-o",
        "NUL",
        "--max-time",
        "20",
        "-w",
        "%{http_code} %{size_download}B",
        `https://example.org/`,
      ],
      `https_fetch_${i}`,
    );
  }
  return res;
}

/** s2: n sequential plain-HTTP fetches to example.org:80 (301 redirect expected). */
export async function httpExternalFetch(ctx: TrafficContext, n = 3): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  for (let i = 0; i < n; i++) {
    await curl(
      res,
      [
        "--noproxy",
        "*",
        "-s",
        "-S",
        "-o",
        "NUL",
        "--max-time",
        "20",
        "-w",
        "%{http_code} %{size_download}B",
        `http://example.org/`,
      ],
      `http_fetch_${i}`,
    );
  }
  note(res, `plain HTTP over TCP/80 to example.org (301 redirect expected from the edge)`);
  return res;
}

/** s2_local_split: split-write HTTP server + clients on loopback and the site IP. */
export async function localHttpScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  const hosts = ["127.0.0.1", ctx.localIp];
  for (const host of hosts) {
    try {
      const h = await startSplitHttpServer(host, ctx.httpPort);
      await new Promise<void>((done) => h.server.close(() => done()));
      note(res, `split-http server bound on ${host}:${ctx.httpPort}`);
    } catch (e) {
      note(res, `split-http server bind FAILED on ${host}: ${String(e).slice(0, 100)}`);
    }
  }
  // Start one server on loopback, run two clients (response split + request split).
  try {
    const h = await startSplitHttpServer("127.0.0.1", ctx.httpPort);
    const a = await splitHttpRequest("127.0.0.1", ctx.httpPort, "/");
    rec(
      res,
      `local_http_loopback_client1`,
      a.status === "200" ? 0 : 1,
      `status=${a.status} bytes=${a.bytes}`,
    );
    const b = await splitHttpRequest("127.0.0.1", ctx.httpPort, "/big/4096");
    rec(res, `local_http_loopback_client2_big`, 0, `status=${b.status} bytes=${b.bytes}`);
    await new Promise<void>((done) => h.server.close(() => done()));
  } catch (e) {
    rec(res, `local_http_loopback`, 1, String(e).slice(0, 120));
  }
  // Same against the machine's site IP (still loopback semantics on Windows,
  // but exercises the "local IP destination" path).
  try {
    const h = await startSplitHttpServer(ctx.localIp, ctx.httpPort - 1);
    const a = await splitHttpRequest(ctx.localIp, ctx.httpPort - 1, "/");
    rec(
      res,
      `local_http_siteip_client`,
      a.status === "200" ? 0 : 1,
      `status=${a.status} bytes=${a.bytes}`,
    );
    await new Promise<void>((done) => h.server.close(() => done()));
  } catch (e) {
    rec(res, `local_http_siteip`, 1, String(e).slice(0, 120));
  }
  note(res, `loopback visibility is decided empirically by the capture, not assumed`);
  return res;
}

/** s3: A + AAAA + NXDOMAIN over UDP and A/AAAA over TCP/53 (own transaction ids). */
export async function dnsMixed(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  const rnd = Math.random().toString(36).slice(2, 10);
  const a = await dnsQueryUdp(ctx.resolver, "example.org", 1);
  rec(
    res,
    `dns_udp_A_example.org`,
    a.rcode === 0 ? 0 : 1,
    `rcode=${a.rcode} answers=${a.answerCount}`,
  );
  const aaaa = await dnsQueryUdp(ctx.resolver, "cloudflare.com", 28);
  rec(
    res,
    `dns_udp_AAAA_cloudflare.com`,
    aaaa.rcode === 0 ? 0 : 1,
    `rcode=${aaaa.rcode} answers=${aaaa.answerCount}`,
  );
  const nx = await dnsQueryUdp(ctx.resolver, `does-not-exist-${rnd}.invalid`, 1);
  rec(res, `dns_udp_NXDOMAIN`, nx.rcode === 3 ? 0 : 1, `rcode=${nx.rcode} (3=NXDOMAIN expected)`);
  const tcp = await dnsQueryTcp("1.1.1.1", "example.org", 1);
  rec(
    res,
    `dns_tcp_A_example.org@1.1.1.1`,
    tcp.rcode === 0 ? 0 : 1,
    `rcode=${tcp.rcode} tcpUsed=${tcp.tcpUsed}`,
  );
  const tcpAgain = await dnsQueryTcp("1.1.1.1", "cloudflare.com", 28);
  rec(res, `dns_tcp_AAAA@1.1.1.1`, tcpAgain.rcode === 0 ? 0 : 1, `rcode=${tcpAgain.rcode}`);
  return res;
}

/** s4/s14: one large HTTPS download from speed.cloudflare.com (size set by caller). */
export async function httpsDownload(
  ctx: TrafficContext,
  bytes: number,
  stepPrefix: string,
): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "90",
      "-w",
      "%{http_code} %{size_download}B %{speed_download}Bps",
      `https://speed.cloudflare.com/__down?bytes=${bytes}`,
    ],
    `${stepPrefix}_download`,
  );
  return res;
}

/** s5: normal FIN close, a hard socket RST, and a refused-port connect. */
export async function tcpLifecycleScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  // (a+b): normal connect + FIN-close (curl completes and closes cleanly)
  await httpsFetch(ctx, 1);
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "5",
      "-w",
      "%{http_code}",
      "http://example.org:443/",
    ],
    `fin_close_via_443`,
  );
  // (b) RST: destroy an established socket without reading the response.
  await runCommand(
    process.execPath,
    [
      "--input-type=module",
      "-e",
      `
import net from 'node:net';
const s = net.createConnection({ host: 'example.org', port: 443 }, () => {
  s.write('GET / HTTP/1.1\\r\\nHost: example.org\\r\\nConnection: close\\r\\n\\r\\n');
  setTimeout(() => s.resetAndDestroy ? s.resetAndDestroy() : s.destroy(), 120);
});
s.on('error', () => {});`,
    ],
    { timeoutMs: 10_000 },
  ).then((r) => {
    rec(
      res,
      `rst_destroy_node`,
      r.code,
      `(Node resetAndDestroy/destroy after partial request) code=${r.code}`,
    );
  });
  // (c) connection refused on a filtered-unused port of a real host
  await curl(
    res,
    ["--noproxy", "*", "-s", "-S", "-o", "NUL", "--max-time", "10", `http://example.org:59999/`],
    `refused_port_59999`,
  );
  note(res, `expected: SYN then RST/ACK for 59999 (refused), FIN close for 443`);
  return res;
}

/** s6: forced -4/-6 curl fetches over HTTPS and HTTP. */
export async function v4v6Scenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-4",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code} %{remote_ip}",
      "https://example.org/",
    ],
    `curl4_https`,
  );
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-6",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code} %{remote_ip}",
      "https://example.org/",
    ],
    `curl6_https`,
  );
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-4",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code} %{remote_ip}",
      "http://example.org/",
    ],
    `curl4_http`,
  );
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-6",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code} %{remote_ip}",
      "http://example.org/",
    ],
    `curl6_http`,
  );
  return res;
}

/** s7: n concurrent HTTPS fetches (independent source ports expected). */
export async function parallelCurls(ctx: TrafficContext, n = 8): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  const jobs = [];
  for (let i = 0; i < n; i++) {
    jobs.push(
      runCommand(
        "C:\\Windows\\System32\\curl.exe",
        [
          "--noproxy",
          "*",
          "-s",
          "-S",
          "-o",
          "NUL",
          "--max-time",
          "30",
          "-w",
          `%{http_code} via %{remote_ip}`,
          "https://example.org/",
        ],
        { timeoutMs: 60_000 },
      ).then((r) => rec(res, `parallel_curl_${i}`, r.code, (r.stdout || r.stderr).slice(0, 60))),
    );
  }
  await Promise.allSettled(jobs);
  note(res, `${n} concurrent HTTPS flows (independent source ports expected)`);
  return res;
}

/** s8: ping v4/v6 plus a 3000-byte ping that must fragment (MTU 1500). */
export async function icmpScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  await runCommand(
    "C:\\Windows\\System32\\ping.exe",
    ["-n", "1", "-4", "-w", "2000", "example.org"],
    { timeoutMs: 15_000 },
  ).then((r) =>
    rec(res, `ping_v4_example.org`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 150)),
  );
  await runCommand(
    "C:\\Windows\\System32\\ping.exe",
    ["-n", "1", "-6", "-w", "2000", "example.org"],
    { timeoutMs: 15_000 },
  ).then((r) =>
    rec(res, `ping_v6_example.org`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 150)),
  );
  // IPv4 fragmentation: 3000-byte payload -> 3 fragments on the LAN link.
  await runCommand(
    "C:\\Windows\\System32\\ping.exe",
    ["-n", "1", "-4", "-l", "3000", "-w", "3000", ctx.resolver],
    { timeoutMs: 15_000 },
  ).then((r) =>
    rec(res, `ping_v4_3000B_fragmented`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 150)),
  );
  note(res, `3000B payload against MTU 1500 forces IPv4 fragmentation (3 fragments)`);
  return res;
}

/** s9: headless Edge against cloudflare-quic.com — QUIC presence is verified
 * from the captured trace, not from the browser claim. */
export async function quicScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  const candidates = [
    "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
  ];
  const edge = candidates.find((p) => fs.existsSync(p));
  if (!edge) {
    note(res, `msedge.exe not found; no local HTTP/3 initiator available on this machine`);
    return res;
  }
  note(res, `using headless Edge against cloudflare-quic.com (QUIC-capable site)`);
  const tmp = path.join(os.tmpdir(), `m2-edge-${Date.now()}`);
  fs.mkdirSync(tmp, { recursive: true });
  const r = await runCommand(
    edge,
    [
      "--headless",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      `--user-data-dir=${tmp}`,
      "--dump-dom",
      "https://cloudflare-quic.com/",
    ],
    { timeoutMs: 45_000 },
  );
  rec(res, `edge_headless_quic`, r.code, `exit=${r.code} dom=${(r.stdout || "").length}B`);
  fs.rmSync(tmp, { recursive: true, force: true });
  note(
    res,
    `QUIC (UDP/443) presence is verified from the captured trace, not from the browser claim`,
  );
  return res;
}

/** s10: ARP probe (ping an unused LAN address) + read-only `arp -a` + an
 * `ipconfig /renew` attempt (may be denied non-elevated — recorded either way). */
export async function arpDhcpScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  // Ping a nonexistent LAN address to force an ARP request while capturing.
  const base = ctx.localIp.split(".").slice(0, 3).join(".");
  const probe = `${base}.254`;
  await runCommand("C:\\Windows\\System32\\ping.exe", ["-n", "1", "-w", "1500", probe], {
    timeoutMs: 10_000,
  }).then((r) =>
    rec(res, `ping_arp_probe_${probe}`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 120)),
  );
  await runCommand("C:\\Windows\\System32\\PING.EXE", ["-n", "1", "-w", "1500", probe], {
    timeoutMs: 10_000,
  }).then((r) =>
    rec(res, `ping_arp_probe_again_${probe}`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 120)),
  );
  // arp -a records the cache state (read-only, allowed non-elevated).
  await runCommand("C:\\Windows\\System32\\arp.exe", ["-a"], { timeoutMs: 10_000 }).then((r) =>
    rec(res, `arp_a_snapshot`, r.code, r.stdout.replace(/\s+/g, " ").slice(0, 200)),
  );
  // DHCP renewal attempt (records the outcome honestly; may require admin).
  await runCommand("C:\\Windows\\System32\\IPCONFIG.EXE", ["/renew"], { timeoutMs: 30_000 }).then(
    (r) => {
      const denied = /elevat|denied|requires/i.test(r.stdout + r.stderr);
      rec(
        res,
        `ipconfig_renew`,
        r.code,
        denied
          ? "denied non-elevated (finding recorded)"
          : r.stdout.replace(/\s+/g, " ").slice(0, 160),
      );
      if (denied)
        note(
          res,
          `ipconfig /renew needs elevation in this prototype: DHCP DORA capture skipped (finding)`,
        );
    },
  );
  return res;
}

/** s11: TCP + UDP echo conversations between local processes. */
export async function loopbackScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  // TCP: two full client/server conversations on 127.0.0.1 and the site IP.
  for (const host of ["127.0.0.1", ctx.localIp]) {
    const srv = await new Promise<{ server: net.Server }>((resolve, reject) => {
      const server = net.createServer((socket) => {
        socket.setNoDelay(true);
        socket.on("data", (c: Buffer) => {
          socket.write(Buffer.concat([Buffer.from("echo:"), c]));
          socket.end();
        });
        socket.on("error", () => {
          /* noop */
        });
      });
      server.once("error", reject);
      server.listen(41234, host, () => resolve({ server }));
    });
    const client = await new Promise<string>((resolve) => {
      const s = net.createConnection({ host, port: 41234 });
      s.on("connect", () => s.write("tcp-loopback"));
      s.on("data", () => {
        s.end();
        resolve("roundtrip-ok");
      });
      s.on("error", () => resolve("error"));
      setTimeout(() => resolve("timeout"), 4000);
    });
    rec(res, `tcp_loopback_${host}`, client === "roundtrip-ok" ? 0 : 1, client);
    await new Promise<void>((r2) => srv.server.close(() => r2()));
  }
  // UDP round trip.
  const udp = await udpEchoRound("127.0.0.1", ctx.udpPort, Buffer.from("udp-loopback-0123456789"));
  rec(res, `udp_loopback_127.0.0.1`, udp.echoed ? 0 : 1, `echoed=${udp.echoed}`);
  return res;
}

/** s13: RFC 6455 WebSocket upgrade + one echo frame, over plain HTTP. */
export async function wsScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  for (const host of ["127.0.0.1", ctx.localIp]) {
    const s = await startWsEchoServer(host, ctx.wsPort);
    const c = await wsClientUpgrade(host, ctx.wsPort, "/");
    rec(
      res,
      `ws_upgrade_${host}`,
      c.got101 && c.gotFrame ? 0 : 1,
      `got101=${c.got101} gotFrame=${c.gotFrame}`,
    );
    await new Promise<void>((done) => s.server.close(() => done()));
  }
  note(res, `WS upgrade served over plain HTTP (RFC 6455 upgrade, no TLS)`);
  return res;
}

/** s14: one burst download (thin wrapper over httpsDownload). */
export async function burstScenario(ctx: TrafficContext, bytes: number): Promise<TrafficResult> {
  return httpsDownload(ctx, bytes, "burst");
}

/** s12: saturate the Wi-Fi path with concurrent multi-MB TLS downloads. */
export async function retransmissionScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  // Saturate the Wi-Fi path with concurrent multi-MB TLS downloads.
  const jobs = [0, 1, 2, 3].map((i) =>
    runCommand(
      "C:\\Windows\\System32\\curl.exe",
      [
        "--noproxy",
        "*",
        "-s",
        "-S",
        "-o",
        "NUL",
        "--max-time",
        "45",
        "-w",
        `%{http_code} %{size_download}B`,
        `https://speed.cloudflare.com/__down?bytes=8000000`,
      ],
      { timeoutMs: 60_000 },
    ).then((r) => rec(res, `saturation_curl_${i}`, r.code, `${(r.stdout || "").slice(0, 60)}`)),
  );
  await Promise.allSettled(jobs);
  note(
    res,
    `retransmission reality is checked against tshark tcp.analysis.retransmission on the captured trace`,
  );
  return res;
}

/** s15: TLS 1.3 (default) + forced TLS 1.2 handshakes against example.org. */
export async function tlsHelloScenario(ctx: TrafficContext): Promise<TrafficResult> {
  const res: TrafficResult = { steps: [], notes: [] };
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code}",
      "https://example.org/",
    ],
    `tls13_default`,
  );
  await curl(
    res,
    [
      "--noproxy",
      "*",
      "--tlsv1.2",
      "--tls-max",
      "1.2",
      "-s",
      "-S",
      "-o",
      "NUL",
      "--max-time",
      "20",
      "-w",
      "%{http_code}",
      "https://example.org/",
    ],
    `tls12_forced`,
  );
  return res;
}

export { curl };
