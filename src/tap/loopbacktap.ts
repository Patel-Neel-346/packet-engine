// M4-a: userspace loopback tap ("loopback vantage").
//
// Problem (verified Finding A, M2): pktmon observes ZERO loopback traffic on
// this Windows build, so pktmon-based capture cannot see the local scenarios
// (s2_local_split, s11_loopback, s13_ws) even with traffic flowing.
//
// Solution: a USER-LEVEL tap behind the engine's existing pipeline. While a
// scenario runs, the tap intercepts net.createConnection / net.createServer /
// dgram.createSocket in the scenario process and records every byte the
// application actually sends per connection, plus receive observations.
//
// Honesty contract (printed by the CLI with every run):
//   REAL — which bytes crossed, in which application write chunks, over which
//          local ports/addresses, in which order, at real user-space
//          timestamps.
//   SYNTHESIZED — what userland cannot observe: ISNs, pure-ACK placement,
//          kernel segmentation boundaries, header cosmetics (TTL/MSS/window).
//          Byte payloads are NOT synthesized — they are recorded verbatim.
//
// One vantage per direction: a connection's client->server bytes are recorded
// at the CLIENT socket's send side, server->client bytes at the SERVER
// socket's send side. Receive observations synthesize pure ACKs only, so each
// payload byte appears in the trace exactly once (no copy/duplicate artifacts).
//
// Layer:     tap — in-process net/dgram interception (userland vantage; no elevation)
// Milestone: M4a — loopback tap (docs/project-status.md)
// Verified:  test/loopbacktap.test.ts (writer roundtrip + seq/ack math) + gate 8 (3 scenarios)
// Exports:   LoopbackTap

import net from "node:net";
import dgram from "node:dgram";
import crypto from "node:crypto";
import fs from "node:fs";
import { writePcapng, type PcapngChunk } from "../engine/pcapngwrite.ts";

export type Dir = "c2s" | "s2c";

/** µs since epoch; strings strictly increasing inside one tap run. */
type UsTs = number;

const EPHEMERAL_MIN = 49152; // Windows dynamic port range start
const MAC_CLIENT = Buffer.from([0x02, 0x7f, 0x00, 0x00, 0x00, 0x01]);
const MAC_SERVER = Buffer.from([0x02, 0x7f, 0x00, 0x00, 0x00, 0x02]);
const TCP_WIN = 0x2000;
const TCP_SYN = 0x02;
const TCP_SYN_ACK = 0x12;
const TCP_ACK = 0x10;
const TCP_PSH_ACK = 0x18;
const TCP_FIN_ACK = 0x11;
const TCP_RST_ACK = 0x14;

interface TcpEvent {
  k: "tx" | "ackObs" | "fin" | "rst";
  ts: UsTs;
  dir: Dir;
  payload?: Buffer;
}

/** Internal record; the public output shape is TcpStory. */
interface TcpTapConn {
  id: number;
  proto4: boolean;
  t0: UsTs;
  t1: UsTs;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  events: TcpEvent[];
  c2sData: Buffer;
  s2cData: Buffer;
  ends: { dir: Dir; ts: UsTs }[];
  resets: number;
  finalized: boolean;
}

/** Observed story of ONE TCP connection — returned by tcpTales(). */
export interface TcpStory {
  id: number;
  proto4: boolean;
  clientIp: string;
  clientPort: number;
  serverIp: string;
  serverPort: number;
  /** ms between socket creation and handshake-complete ('connect'). */
  handshakeDeltaMs: number;
  /** Verbatim concatenated client->server application bytes. */
  c2sPayload: Buffer;
  /** Verbatim concatenated server->client application bytes. */
  s2cPayload: Buffer;
  endCalls: { dir: Dir; ts: UsTs }[];
  destroyed: boolean;
  frames: number;
}

interface UdpDatum {
  ts: UsTs;
  dir: Dir;
  /** send-side local port; 0 until the post-send snapshot resolves it. */
  sport: number;
  dport: number;
  dstIp: string;
  payload: Buffer;
}

/** Observed story of ONE UDP socket — returned by udpTales(). */
export interface UdpStory {
  id: number;
  proto4: boolean;
  localIp: string;
  localPort: number;
  events: UdpDatum[];
}

const tapConnSym = Symbol("strobe.tap.conn");
const tapRoleSym = Symbol("strobe.tap.role");

function randomIsn(): number {
  // prototype-grade ISN: nonzero, halved entropy (avoid near-wrap values)
  return crypto.randomBytes(4).readUInt32BE(0) >>> 1 || 0x10000;
}

/** "::ffff:127.0.0.1" ↔ "127.0.0.1" normalization for tuple matching. */
function normIp(ip: string | undefined): string {
  return (ip ?? "").replace(/^::ffff:/i, "");
}

function randIpId(): number {
  return 0x4000 | Math.floor(Math.random() * 0x2000);
}

/** In-process traffic tap: while armed it intercepts net (TCP) and dgram
 * (UDP) calls, records per-connection application-level byte truth, and
 * synthesizes Ethernet/IPv4-framed chunks for pcapng export. */
export class LoopbackTap {
  private tcpSeq = 0;
  private udpSeq = 0;
  private lastUs: UsTs = 0;
  private armed = false;

  private conns: TcpTapConn[] = [];
  private udpStoriesInt: UdpStory[] = [];
  private byClientTuple = new Map<string, TcpTapConn>();
  private pendingAccepted: net.Socket[] = [];

  private warnings: string[] = [];
  private origCreateConnection: ((...a: unknown[]) => net.Socket) | null = null;
  private origCreateServer: ((...a: unknown[]) => net.Server) | null = null;
  private origCreateSocket: ((...a: unknown[]) => dgram.Socket) | null = null;

  // ── lifecycle ────────────────────────────────────────────────────────────

  arm(): void {
    if (this.armed) return;
    this.armed = true;
    const tap = this;

    // The originals are plain standalone functions in node's net/dgram
    // modules (no internal `this` needed); the loose rest-parameter casts
    // exist because their public typings are overload unions.
    const origCC = net.createConnection.bind(net) as unknown as (...a: unknown[]) => net.Socket;
    this.origCreateConnection = origCC;
    (net as unknown as { createConnection: unknown }).createConnection =
      function tappedCreateConnection(...args: unknown[]): net.Socket {
        const sock = origCC(...args);
        tap.instrumentOutbound(sock);
        return sock;
      };

    const origCS = net.createServer.bind(net) as unknown as (...a: unknown[]) => net.Server;
    this.origCreateServer = origCS;
    (net as unknown as { createServer: unknown }).createServer = function tappedCreateServer(
      ...args: unknown[]
    ): net.Server {
      let handler: unknown;
      let hasHandler = false;
      for (const a of args) {
        if (typeof a === "function") {
          handler = a;
          hasHandler = true;
          break;
        }
      }
      if (!hasHandler) return origCS(...args);
      // Arrow wrapper: node calls connection handlers with the server as
      // `this`, but the local scenario handlers never use it (verified in
      // traffic.ts/localservers.ts).
      const wrapped = (...cell: unknown[]): void => {
        tap.instrumentAccepted(cell[0] as net.Socket);
        (handler as (...a: unknown[]) => void)(...cell);
      };
      if (typeof args[0] === "function") return origCS(wrapped);
      return origCS(args[0], wrapped);
    };

    const origDS = dgram.createSocket.bind(dgram) as unknown as (...a: unknown[]) => dgram.Socket;
    this.origCreateSocket = origDS;
    (dgram as unknown as { createSocket: unknown }).createSocket = function tappedCreateSocket(
      ...args: unknown[]
    ): dgram.Socket {
      const sock = origDS(...args);
      tap.instrumentUdpSocket(sock);
      return sock;
    };
  }

  disarm(): void {
    if (!this.armed) return;
    this.armed = false;
    if (this.origCreateConnection) {
      (net as unknown as { createConnection: unknown }).createConnection =
        this.origCreateConnection;
    }
    if (this.origCreateServer) {
      (net as unknown as { createServer: unknown }).createServer = this.origCreateServer;
    }
    if (this.origCreateSocket) {
      (dgram as unknown as { createSocket: unknown }).createSocket = this.origCreateSocket;
    }
    this.origCreateConnection = null;
    this.origCreateServer = null;
    this.origCreateSocket = null;
  }

  get isArmed(): boolean {
    return this.armed;
  }

  nowUs(): UsTs {
    const t = Math.max(Date.now() * 1000, this.lastUs + 1);
    this.lastUs = t;
    return t;
  }

  get warningLines(): string[] {
    return [...this.warnings];
  }

  /** Record a non-fatal tap anomaly (never throws). */
  warn(msg: string): void {
    this.warnings.push(msg);
  }

  // ── story accessors (post-run inspection) ────────────────────────────────

  get tcpTales(): TcpStory[] {
    return this.conns.map((c) => {
      if (!c.finalized) this.warn(`conn#${c.id} read before close; payload partial`);
      return {
        id: c.id,
        proto4: c.proto4,
        clientIp: c.clientIp,
        clientPort: c.clientPort,
        serverIp: c.serverIp,
        serverPort: c.serverPort,
        handshakeDeltaMs: c.t0 && c.t1 > c.t0 ? (c.t1 - c.t0) / 1000 : 0,
        c2sPayload: Buffer.from(c.c2sData),
        s2cPayload: Buffer.from(c.s2cData),
        endCalls: c.ends.map((e) => ({ ...e })),
        destroyed: c.resets > 0,
        frames: 0,
      };
    });
  }

  get udpTales(): UdpStory[] {
    return this.udpStoriesInt.map((u) => ({
      id: u.id,
      proto4: u.proto4,
      localIp: u.localIp,
      localPort: u.localPort,
      events: u.events.map((e) => ({ ...e, payload: Buffer.from(e.payload) })),
    }));
  }

  get tcpConnCount(): number {
    return this.conns.length;
  }

  get udpFlowCount(): number {
    return this.udpStoriesInt.length;
  }

  // ── TCP instrumentation ──────────────────────────────────────────────────

  private instrumentOutbound(sock: net.Socket): void {
    const c: TcpTapConn = {
      id: ++this.tcpSeq,
      proto4: true,
      t0: this.nowUs(),
      t1: 0,
      clientIp: "",
      clientPort: 0,
      serverIp: "",
      serverPort: 0,
      events: [],
      c2sData: Buffer.alloc(0),
      s2cData: Buffer.alloc(0),
      ends: [],
      resets: 0,
      finalized: false,
    };
    this.conns.push(c);
    const tap = this;

    sock.on("connect", () => {
      c.t1 = tap.nowUs();
      c.clientIp = normIp(sock.localAddress);
      c.clientPort = sock.localPort ?? 0;
      c.serverIp = normIp(sock.remoteAddress);
      c.serverPort = sock.remotePort ?? 0;
      c.proto4 = !c.serverIp.includes(":");
      tap.byClientTuple.set(`${c.clientIp}:${c.clientPort}`, c);
      tap.resolvePendingAccepted();
    });

    sock.on("close", () => tap.finalizeConn(c));
    sock.on("error", (e: Error) => tap.warn(`conn#${c.id} client-side error: ${e.message}`));

    this.wrapTcpSend(sock, c, "client");
    this.observeTcpReceive(sock, c, "client");
  }

  private instrumentAccepted(socket: net.Socket): void {
    const remote = `${normIp(socket.remoteAddress)}:${socket.remotePort}`;
    const c = this.byClientTuple.get(remote);
    if (!c) {
      // accepted before the client announced its tuple; resolve on connect
      this.pendingAccepted.push(socket);
      return;
    }
    this.attachServerSide(socket, c);
  }

  private resolvePendingAccepted(): void {
    const still: net.Socket[] = [];
    for (const s of this.pendingAccepted) {
      const remote = `${normIp(s.remoteAddress)}:${s.remotePort}`;
      const c = this.byClientTuple.get(remote);
      if (c) this.attachServerSide(s, c);
      else still.push(s);
    }
    this.pendingAccepted = still;
  }

  private attachServerSide(socket: net.Socket, c: TcpTapConn): void {
    (socket as unknown as Record<symbol, unknown>)[tapConnSym] = c;
    (socket as unknown as Record<symbol, unknown>)[tapRoleSym] = "server";
    c.serverIp = c.serverIp || normIp(socket.localAddress);
    c.serverPort = c.serverPort || socket.localPort || 0;
    const tap = this;
    socket.on("close", () => tap.finalizeConn(c));
    socket.on("error", (e: Error) => tap.warn(`conn#${c.id} server-side error: ${e.message}`));
    this.wrapTcpSend(socket, c, "server");
    this.observeTcpReceive(socket, c, "server");
  }

  /** Record every byte this socket SENDS (verbatim, timestamped). */
  private wrapTcpSend(sock: net.Socket, c: TcpTapConn, role: "client" | "server"): void {
    const tap = this;
    const dir: Dir = role === "client" ? "c2s" : "s2c";
    const origWrite = sock.write.bind(sock);
    const origEnd = sock.end.bind(sock);
    const origDestroy = sock.destroy.bind(sock);
    (sock as unknown as Record<symbol, unknown>)[tapConnSym] = c;
    (sock as unknown as Record<symbol, unknown>)[tapRoleSym] = role;

    (sock as unknown as { write: unknown }).write = function tappedWrite(
      ...args: unknown[]
    ): boolean {
      const chunk = args[0];
      if (
        chunk !== null &&
        chunk !== undefined &&
        (Buffer.isBuffer(chunk) || typeof chunk === "string" || chunk instanceof Uint8Array)
      ) {
        tap.recordTcpTx(c, dir, toBuf(chunk as Buffer | string | Uint8Array), tap.nowUs());
      }
      return (origWrite as (...a: unknown[]) => boolean)(...args);
    };

    (sock as unknown as { end: unknown }).end = function tappedEnd(...args: unknown[]): net.Socket {
      const chunk = args[0];
      if (
        chunk !== null &&
        chunk !== undefined &&
        (Buffer.isBuffer(chunk) || typeof chunk === "string" || chunk instanceof Uint8Array)
      ) {
        tap.recordTcpTx(c, dir, toBuf(chunk as Buffer | string | Uint8Array), tap.nowUs());
      }
      c.ends.push({ dir, ts: tap.nowUs() });
      return (origEnd as (...a: unknown[]) => net.Socket)(...args);
    };

    (sock as unknown as { destroy: unknown }).destroy = function tappedDestroy(
      ...args: unknown[]
    ): net.Socket {
      c.resets++;
      return (origDestroy as (...a: unknown[]) => net.Socket)(...args);
    };
  }

  /** Receive side: observed data synthesizes a pure ACK from this side only. */
  private observeTcpReceive(sock: net.Socket, c: TcpTapConn, role: "client" | "server"): void {
    const tap = this;
    const ackDir: Dir = role === "client" ? "c2s" : "s2c";
    sock.on("data", (chunk: Buffer) => {
      if (chunk.length > 0) {
        c.events.push({ k: "ackObs", ts: tap.nowUs(), dir: ackDir });
      }
    });
  }

  private recordTcpTx(c: TcpTapConn, dir: Dir, payload: Buffer, ts: UsTs): void {
    if (payload.length === 0) return;
    c.events.push({ k: "tx", ts, dir, payload });
    if (dir === "c2s") c.c2sData = Buffer.concat([c.c2sData, payload]);
    else c.s2cData = Buffer.concat([c.s2cData, payload]);
  }

  private finalizeConn(c: TcpTapConn): void {
    if (c.finalized) return;
    c.finalized = true;
    const key = `${c.clientIp}:${c.clientPort}`;
    if (this.byClientTuple.get(key) === c) this.byClientTuple.delete(key);
  }

  // ── UDP instrumentation ──────────────────────────────────────────────────

  private instrumentUdpSocket(sock: dgram.Socket): void {
    const u: UdpStory = {
      id: ++this.udpSeq,
      proto4: true,
      localIp: "",
      localPort: 0,
      events: [],
    };
    this.udpStoriesInt.push(u);
    const tap = this;
    const origSend = sock.send.bind(sock);

    (sock as unknown as { send: unknown }).send = function tappedSend(...args: unknown[]): unknown {
      const parsed = parseSendArgs(args);
      if (parsed) {
        u.events.push({
          ts: tap.nowUs(),
          dir: parsed.dport < EPHEMERAL_MIN ? "c2s" : "s2c",
          sport: 0, // post-send snapshot sets the send-side local port
          dport: parsed.dport,
          dstIp: normIp(parsed.dstIp) || "127.0.0.1",
          payload: toBuf(args[0] as Buffer | string | Uint8Array),
        });
        // the kernel binds within send(); snapshot on the next tick is valid
        setImmediate(() => tap.snapshotUdp(sock, u));
      } else {
        tap.warn(`udp send args not parsed (${JSON.stringify(args.map((a) => typeof a))})`);
      }
      return (origSend as (...a: unknown[]) => unknown)(...args);
    };

    sock.on("close", () => tap.snapshotUdp(sock, u));
  }

  private snapshotUdp(sock: dgram.Socket, u: UdpStory): void {
    try {
      const a = sock.address();
      u.localIp = u.localIp || normIp(a.address);
      u.localPort = u.localPort || a.port;
      u.proto4 = !u.localIp.includes(":");
    } catch {
      /* socket already gone */
    }
  }

  // ── synthesis ────────────────────────────────────────────────────────────

  /** Rebuild honest TCP frames from the observed event list.
   * Payloads verbatim; seq/ack math consistent; SYN at socket-create and
   * SYN-ACK at handshake-complete timestamps. */
  synthesizeTcpFrames(c: TcpTapConn): { chunks: PcapngChunk[]; story: TcpStory } {
    const chunks: PcapngChunk[] = [];
    const storyEnds = () => c.ends.map((e) => ({ dir: e.dir, ts: e.ts }));
    const story: TcpStory = {
      id: c.id,
      proto4: c.proto4,
      clientIp: c.clientIp,
      clientPort: c.clientPort,
      serverIp: c.serverIp,
      serverPort: c.serverPort,
      handshakeDeltaMs: c.t0 && c.t1 > c.t0 ? (c.t1 - c.t0) / 1000 : 0,
      c2sPayload: Buffer.from(c.c2sData),
      s2cPayload: Buffer.from(c.s2cData),
      endCalls: storyEnds(),
      destroyed: c.resets > 0,
      frames: 0,
    };

    if (!c.clientPort || !c.clientIp || !c.serverIp || !c.serverPort) {
      this.warn(
        `conn#${c.id} incomplete endpoints (${c.clientIp}:${c.clientPort} -> ${c.serverIp}:${c.serverPort}); no frames synthesized`,
      );
      return { chunks, story };
    }

    const isnC = randomIsn();
    const isnS = randomIsn();
    let cNext = (isnC + 1) >>> 0;
    let sNext = (isnS + 1) >>> 0;
    const push = (ts: UsTs, dir: Dir, flags: number, payload: Buffer, seq: number, ack: number) => {
      const data = ethernetTcpFrame(c, dir, flags, payload, seq, ack);
      chunks.push({ data, origLen: data.length, ts: ts / 1e6 });
    };

    push(c.t0, "c2s", TCP_SYN, Buffer.alloc(0), isnC, 0);
    push(c.t1 || c.t0 + 1, "s2c", TCP_SYN_ACK, Buffer.alloc(0), isnS, cNext);

    for (const ev of c.events) {
      if (ev.k === "tx") {
        const p = ev.payload ?? Buffer.alloc(0);
        if (p.length === 0) continue;
        const seq = ev.dir === "c2s" ? cNext : sNext;
        const ackv = ev.dir === "c2s" ? sNext : cNext;
        push(ev.ts, ev.dir, TCP_PSH_ACK, p, seq, ackv);
        if (ev.dir === "c2s") cNext = (cNext + p.length) >>> 0;
        else sNext = (sNext + p.length) >>> 0;
      } else if (ev.k === "ackObs") {
        const seq = ev.dir === "c2s" ? cNext : sNext;
        const ackv = ev.dir === "c2s" ? sNext : cNext;
        push(ev.ts, ev.dir, TCP_ACK, Buffer.alloc(0), seq, ackv);
      } else if (ev.k === "fin") {
        const seq = ev.dir === "c2s" ? cNext : sNext;
        const ackv = ev.dir === "c2s" ? sNext : cNext;
        push(ev.ts, ev.dir, TCP_FIN_ACK, Buffer.alloc(0), seq, ackv);
        if (ev.dir === "c2s") cNext = (cNext + 1) >>> 0;
        else sNext = (sNext + 1) >>> 0;
        const aseq = ev.dir === "c2s" ? sNext : cNext;
        const aack = ev.dir === "c2s" ? cNext : sNext;
        push(ev.ts, ev.dir === "c2s" ? "s2c" : "c2s", TCP_ACK, Buffer.alloc(0), aseq, aack);
      } else if (ev.k === "rst") {
        const seq = ev.dir === "c2s" ? cNext : sNext;
        const ackv = ev.dir === "c2s" ? sNext : cNext;
        push(ev.ts, ev.dir, TCP_RST_ACK, Buffer.alloc(0), seq, ackv);
      }
    }

    story.frames = chunks.length;
    return { chunks, story };
  }

  /** Rebuild honest UDP datagrams (verbatim payload, one per real send). */
  synthesizeUdpFrames(u: UdpStory): PcapngChunk[] {
    const out: PcapngChunk[] = [];
    for (const ev of u.events) {
      if (!ev.sport && u.localPort) ev.sport = u.localPort;
      if (!ev.sport) {
        this.warn(`udp#${u.id} local port unresolved; datum skipped`);
        continue;
      }
      const data = ethernetUdpFrame(u, ev);
      out.push({ data, origLen: data.length, ts: ev.ts / 1e6 });
    }
    return out;
  }

  /** All frames (TCP + UDP), stable order: timestamp, then insertion. */
  synthesizeAll(): { chunks: PcapngChunk[]; tcp: TcpStory[]; udp: UdpStory[] } {
    const chunks: PcapngChunk[] = [];
    const tcpOut: TcpStory[] = [];
    for (const c of this.conns) {
      const r = this.synthesizeTcpFrames(c);
      for (const ck of r.chunks) chunks.push(ck);
      tcpOut.push(r.story);
    }
    const udpOut = this.udpTales;
    for (let i = 0; i < this.udpStoriesInt.length; i++) {
      for (const ck of this.synthesizeUdpFrames(this.udpStoriesInt[i])) chunks.push(ck);
    }
    const merged = chunks.map((c, i) => ({ c, i }));
    merged.sort((a, b) => a.c.ts - b.c.ts || a.i - b.i);
    return { chunks: merged.map((m) => m.c), tcp: tcpOut, udp: udpOut };
  }

  /** Write the tap's observed traffic as a PCAPNG file; returns frame count. */
  exportTrace(file: string, userAppl = "strobe-packet-tracker m4a loopback tap"): number {
    const built = this.synthesizeAll();
    const buf = writePcapng(built.chunks, { linkType: 1, userAppl });
    fs.writeFileSync(file, buf);
    return built.chunks.length;
  }
}

// ── module-level helpers (no hidden state) ─────────────────────────────────

function toBuf(v: Buffer | string | Uint8Array): Buffer {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v);
  return Buffer.from(String(v), "utf8");
}

/** Locate the destination port in dgram send() arguments.
 * Forms: send(msg[, port[, addr]][, cb]) and
 * send(msg, offset, length, port[, addr][, cb]). */
function parseSendArgs(args: unknown[]): { dport: number; dstIp: string } | null {
  let portIdx: number | null = null;
  if (typeof args[1] === "number" && typeof args[2] === "number" && typeof args[3] === "number") {
    portIdx = 3; // msg, offset, length, port
  } else if (typeof args[1] === "number") {
    portIdx = 1; // msg, port
  }
  if (portIdx === null) return null;
  const dport = args[portIdx] as number;
  if (!Number.isFinite(dport) || dport <= 0) return null;
  let dstIp = "";
  for (let j = portIdx + 1; j < args.length; j++) {
    if (typeof args[j] === "string") {
      dstIp = args[j] as string;
      break;
    }
  }
  return { dport, dstIp };
}

function ipBytes(addr: string, proto4: boolean): Buffer {
  if (proto4) {
    const p = addr.split(".").map((x) => Number(x) & 0xff);
    const b = Buffer.alloc(4);
    for (let i = 0; i < 4; i++) b[i] = (p[i] || 0) & 0xff;
    return b;
  }
  const clean = (addr.split("%")[0] || "::").trim();
  const b = Buffer.alloc(16);
  const halves = clean.split("::");
  if (halves.length === 2) {
    const left = halves[0].split(":").filter(Boolean);
    const right = halves[1].split(":").filter(Boolean);
    for (let i = 0; i < Math.min(8, left.length); i++) {
      b.writeUInt16BE(parseInt(left[i], 16), i * 2);
    }
    const rBase = 16 - right.length * 2;
    for (let i = 0; i < Math.min(8, right.length); i++) {
      b.writeUInt16BE(parseInt(right[i], 16), rBase + i * 2);
    }
  } else {
    const parts = clean.split(":").filter(Boolean);
    for (let i = 0; i < Math.min(8, parts.length); i++) {
      b.writeUInt16BE(parseInt(parts[i], 16), i * 2);
    }
  }
  return b;
}

function checksum16(buf: Buffer): number {
  let sum = 0;
  const odd = buf.length % 2;
  const evenLen = buf.length - odd;
  for (let i = 0; i < evenLen; i += 2) sum += buf.readUInt16BE(i);
  if (odd) sum += buf[buf.length - 1] << 8;
  while (sum > 0xffff) sum = (sum & 0xffff) + (sum >>> 16);
  return ~sum & 0xffff;
}

/** Attach pseudo-header checksum to an L4 header. `sumOff` = field offset in
 * the header (16 for TCP, 6 for UDP). The field must be zero at call time. */
function applyL4Checksum(
  srcIp: string,
  dstIp: string,
  proto4: boolean,
  ipProto: number,
  header: Buffer,
  payload: Buffer,
  sumOff: number,
): void {
  const len = header.length + payload.length;
  const pseudo = Buffer.concat([
    ipBytes(srcIp, proto4),
    ipBytes(dstIp, proto4),
    Buffer.from([0, ipProto, (len >> 8) & 0xff, len & 0xff]),
  ]);
  const sum = checksum16(Buffer.concat([pseudo, header, payload]));
  header.writeUInt16BE(sum, sumOff);
}

function buildEth(src: Buffer, dst: Buffer, etherType: number): Buffer {
  const b = Buffer.alloc(14);
  dst.copy(b, 0);
  src.copy(b, 6);
  b.writeUInt16BE(etherType, 12);
  return b;
}

function buildIp(
  srcIp: string,
  dstIp: string,
  proto4: boolean,
  ipProto: number,
  l4Len: number,
): Buffer {
  if (!proto4) {
    const h = Buffer.alloc(40);
    h[0] = 0x60;
    h.writeUInt16BE(l4Len, 4);
    h[6] = ipProto;
    h[7] = 64;
    ipBytes(srcIp, false).copy(h, 8);
    ipBytes(dstIp, false).copy(h, 24);
    return h;
  }
  const h = Buffer.alloc(20);
  h[0] = 0x45;
  h.writeUInt16BE(20 + l4Len, 2);
  h.writeUInt16BE(randIpId(), 4);
  h[8] = 128; // TTL (cosmetic)
  h[9] = ipProto;
  ipBytes(srcIp, true).copy(h, 12);
  ipBytes(dstIp, true).copy(h, 16);
  // IPv4 header checksum: field zeroed when computing
  h.writeUInt16BE(0, 10);
  const hexSum = checksum16(h);
  h.writeUInt16BE(hexSum, 10);
  return h;
}

/** Ethernet + IPv4/IPv6 + TCP frame for one synthesized TCP packet. */
function ethernetTcpFrame(
  c: TcpTapConn,
  dir: Dir,
  flags: number,
  payload: Buffer,
  seq: number,
  ack: number,
): Buffer {
  const toServer = dir === "c2s";
  const macSrc = toServer ? MAC_CLIENT : MAC_SERVER;
  const macDst = toServer ? MAC_SERVER : MAC_CLIENT;
  const sport = toServer ? c.clientPort : c.serverPort;
  const dport = toServer ? c.serverPort : c.clientPort;
  const srcIp = toServer ? c.clientIp : c.serverIp;
  const dstIp = toServer ? c.serverIp : c.clientIp;

  const opts = Buffer.alloc(flags & TCP_SYN ? 4 : 0);
  if (flags & TCP_SYN) {
    opts[0] = 2; // MSS option kind
    opts[1] = 4; // MSS option length
    opts.writeUInt16BE(1460, 2);
  }
  const off = 20 + opts.length;
  const header = Buffer.alloc(off);
  header.writeUInt16BE(sport, 0);
  header.writeUInt16BE(dport, 2);
  header.writeUInt32BE(seq >>> 0, 4);
  header.writeUInt32BE(ack >>> 0, 8);
  header[12] = (off >> 2) << 4;
  header[13] = flags;
  header.writeUInt16BE(TCP_WIN, 14);
  header.writeUInt16BE(0, 16); // checksum (set below)
  header.writeUInt16BE(0, 18); // urgent ptr
  if (opts.length) opts.copy(header, 20);

  applyL4Checksum(srcIp, dstIp, c.proto4, 6, header, payload, 16);
  const l4 = Buffer.concat([header, payload]);
  const ip = buildIp(srcIp, dstIp, c.proto4, 6, l4.length);
  const eth = buildEth(macSrc, macDst, c.proto4 ? 0x0800 : 0x86dd);
  return Buffer.concat([eth, ip, l4]);
}

/** Ethernet + IPv4/IPv6 + UDP frame for one observed UDP datagram. */
function ethernetUdpFrame(u: UdpStory, ev: UdpDatum): Buffer {
  const dstIp = normIp(ev.dstIp) || "127.0.0.1";
  const toServer = ev.dir === "c2s";
  const macSrc = toServer ? MAC_CLIENT : MAC_SERVER;
  const macDst = toServer ? MAC_SERVER : MAC_CLIENT;
  const srcIp = u.localIp || "127.0.0.1";
  const sport = ev.sport;

  const header = Buffer.alloc(8);
  header.writeUInt16BE(sport, 0);
  header.writeUInt16BE(ev.dport, 2);
  header.writeUInt16BE(8 + ev.payload.length, 4);
  header.writeUInt16BE(0, 6); // checksum (set below)

  applyL4Checksum(srcIp, dstIp, u.proto4, 17, header, ev.payload, 6);
  const ip = buildIp(srcIp, dstIp, u.proto4, 17, 8 + ev.payload.length);
  const eth = buildEth(macSrc, macDst, u.proto4 ? 0x0800 : 0x86dd);
  return Buffer.concat([eth, ip, header, ev.payload]);
}
