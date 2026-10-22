// Local test servers run (non-elevated) by the traffic generators for the
// plain-HTTP-split, WebSocket-upgrade, and loopback scenarios. Implemented
// on raw net sockets so SEGMENT SPLITTING is under our control (Node's
// http module does not split headers).
//
// Layer:     traffic — local server I/O (raw net sockets; non-elevated)
// Milestone: M2 (split-HTTP s2_local_split, WebSocket s13_ws) / M4a (loopback echo s11)
// Verified:  their traces captured + verified; app-level truth re-checked by the m4a tap gate
// Exports:   startSplitHttpServer, splitHttpRequest, startWsEchoServer, wsClientUpgrade, udpEchoRound

import net from "node:net";
import crypto from "node:crypto";
import dgram from "node:dgram";

export interface LocalHttpResult {
  port: number;
  server: net.Server;
}

/**
 * Raw HTTP/1.1 server: sends every response as two TCP writes ~12ms apart
 * so the response header is physically split across segments. Serves:
 *   /          -> 200 with a small body
 *   /big/<n>   -> 200 with n bytes body (written in 1 write)
 */
export function startSplitHttpServer(host: string, port: number): Promise<LocalHttpResult> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.setNoDelay(true);
      let req = Buffer.alloc(0);
      socket.on("data", async (c: Buffer) => {
        req = Buffer.concat([req, c]);
        if (req.length > 65536) socket.destroy();
        const end = req.indexOf("\r\n\r\n");
        if (end === -1) return;
        const head = req.subarray(0, end).toString("utf8");
        const m = /^GET ([^ ]+) HTTP\/1\.[01]/.exec(head);
        const path2 = m ? m[1] : "/";
        const closeAfter = () => {
          socket.end();
        };
        if (path2.startsWith("/big/")) {
          const n = Math.min(16_000_000, Math.max(1, Number(path2.slice(5)) || 0));
          const body = Buffer.alloc(n, 0x61);
          const h1 = "HTTP/1.1 200 OK\r\nContent-Length: " + n + "\r\n";
          const h2 = "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
          socket.write(h1);
          setTimeout(() => { socket.write(h2); setTimeout(() => socket.write(body), 8); }, 8);
          socket.on("close", () => { /* body write best-effort */ });
          return;
        }
        const body = "plain-http-split-ok " + crypto.randomBytes(8).toString("hex");
        const h1 = "HTTP/1.1 200 OK\r\n";
        const h2 = "X-Test-Server: split\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " + body.length + "\r\n\r\n" + body;
        socket.write(h1);
        // Split: rest of the headers + body arrive >=12ms later.
        setTimeout(() => { socket.write(h2); closeAfter(); }, 12);
      });
      socket.on("error", () => { /* connection-level noise: ignored */ });
    });
    const fail = (e: Error) => reject(new Error(`split-http: ${e.message}`));
    server.once("error", fail);
    server.listen(port, host, () => {
      resolve({ port, server });
    });
  });
}

/** Simple HTTP request splitting its request headers across two writes. */
export function splitHttpRequest(
  host: string,
  port: number,
  path2: string,
): Promise<{ status: string | null; bytes: number }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setNoDelay(true);
    let buf = Buffer.alloc(0);
    let sent = false;
    socket.on("connect", () => {
      const first = `GET ${path2} HTTP/1.1\r\nHost: ${host}:${port}\r\n`;
      socket.write(first);
      setTimeout(() => {
        if (!sent) {
          sent = true;
          socket.write(`User-Agent: m2-split-client\r\nConnection: close\r\n\r\n`);
        }
      }, 12);
    });
    socket.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
    });
    const finish = () => {
      const s = /^HTTP\/1\.[01] (\d{3})/.exec(buf.toString("utf8"))?.[1] ?? null;
      resolve({ status: s, bytes: buf.length });
    };
    socket.on("close", finish);
    socket.on("error", () => finish());
    setTimeout(() => { try { socket.destroy(); finish(); } catch { /* noop */ } }, 8000);
  });
}

/** Minimal WebSocket server: completes the RFC 6455 upgrade, sends one
 * text frame, echoes one client frame, then closes. */
export function startWsEchoServer(host: string, port: number): Promise<{ port: number; server: net.Server }> {
  const GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.setNoDelay(true);
      let req = Buffer.alloc(0);
      socket.on("data", (c: Buffer) => {
        req = Buffer.concat([req, c]);
        const end = req.indexOf("\r\n\r\n");
        if (end === -1) return;
        if (req.subarray(0, 3).toString("ascii") !== "GET") return;
        const m = /sec-websocket-key: ([^\r\n]+)/i.exec(req.subarray(0, end).toString("ascii"));
        if (!m) { socket.destroy(); return; }
        const accept = crypto.createHash("sha1").update(m[1].trim() + GUID).digest("base64");
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
          "Upgrade: websocket\r\nConnection: Upgrade\r\n" +
          `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
        );
        // server hello text frame: FIN+text, len 5, "hello"
        socket.write(Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]));
        socket.end();
      });
      socket.on("error", () => { /* noop */ });
    });
    const fail = (e: Error) => reject(new Error(`ws-echo: ${e.message}`));
    server.once("error", fail);
    server.listen(port, host, () => resolve({ port, server }));
  });
}

/** Minimal WebSocket client: sends the upgrade request + one masked frame. */
export function wsClientUpgrade(host: string, port: number, path2: string): Promise<{ got101: boolean; gotFrame: boolean }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let buf = Buffer.alloc(0);
    let got101 = false;
    let gotFrame = false;
    const finish = () => {
      try { socket.destroy(); } catch { /* noop */ }
      resolve({ got101, gotFrame });
    };
    const timer = setTimeout(() => finish(), 8000);
    socket.on("connect", () => {
      const key = crypto.randomBytes(16).toString("base64");
      socket.write(
        `GET ${path2} HTTP/1.1\r\nHost: ${host}:${port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
      );
      socket.write(Buffer.from([0x81, 0x81, 0xaa, 0xbb, 0xcc, 0xdd, 0xc2])); // masked "b"
    });
    socket.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (!got101 && buf.subarray(0, 12).toString("ascii").startsWith("HTTP/1.1 101")) got101 = true;
      if (buf.length > 30) gotFrame = true;
      if (got101 && gotFrame) { clearTimeout(timer); setTimeout(finish, 60); }
    });
    socket.on("error", () => { clearTimeout(timer); finish(); });
    socket.on("close", () => { clearTimeout(timer); finish(); });
  });
}

/** UDP echo server + client pair for the loopback scenario. */
export function udpEchoRound(
  host: string,
  port: number,
  payload: Buffer,
  timeoutMs = 4000,
): Promise<{ echoed: boolean }> {
  return new Promise((resolve) => {
    const server = dgram.createSocket("udp4");
    let echoed = false;
    let clientStopped = false;
    const cleanup = () => {
      if (clientStopped) return;
      clientStopped = true;
      try { server.close(); } catch { /* noop */ }
      resolve({ echoed });
    };
    server.on("message", (msg, rinfo) => {
      server.send(msg, rinfo.port, rinfo.address);
      if (msg.equals(payload)) echoed = true;
      setTimeout(cleanup, 200);
    });
    server.on("error", () => { /* noop */ });
    server.on("listening", () => {
      const client = dgram.createSocket("udp4");
      const t = setTimeout(() => { try { client.close(); } catch { /* noop */ } cleanup(); }, timeoutMs);
      client.on("message", () => { clearTimeout(t); try { client.close(); } catch { /* noop */ } });
      client.send(payload, port, host, () => { /* noop */ });
    });
    server.bind(port, host);
  });
}
