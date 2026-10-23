// ============================================================================
// Local Test Traffic Generators & Socket Fixtures
//
// Non-elevated local test servers used for network edge-case verification:
//   1. Split HTTP Server: sends response headers across physical TCP segment
//      boundaries with delayed writes (~12ms apart).
//   2. Split HTTP Request: sends HTTP request lines and headers across separate
//      TCP writes to test reassembly in the packet engine.
//   3. Minimal WebSocket Server & Client: implements RFC 6455 handshake
//      and masked framing over raw TCP sockets.
//   4. UDP Echo Server & Client: validates UDP roundtrip conversation tracking.
//
// Layer:     traffic — local server I/O (raw net/dgram sockets; non-elevated)
// Milestone: M2 (split-HTTP s2_local_split, WebSocket s13_ws) / M4a (loopback echo s11)
// Exports:   startSplitHttpServer, splitHttpRequest, startWsEchoServer, wsClientUpgrade, udpEchoRound
// ============================================================================

import net from "node:net";
import crypto from "node:crypto";
import dgram from "node:dgram";

export interface LocalHttpResult {
  port: number;
  server: net.Server;
}

/**
 * Starts a raw HTTP/1.1 server that intentionally splits headers across multiple
 * TCP segment writes ~12ms apart. This forces real-world TCP packet segmentation
 * for decoder stream reassembly testing.
 *
 * Supported paths:
 *   - `/`       -> 200 OK with small body
 *   - `/big/<n>` -> 200 OK with <n> bytes of body payload
 */
export function startSplitHttpServer(host: string, port: number): Promise<LocalHttpResult> {
  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.setNoDelay(true);
      let req = Buffer.alloc(0);

      socket.on("data", async (chunk: Buffer) => {
        req = Buffer.concat([req, chunk]);
        if (req.length > 65536) {
          socket.destroy();
          return;
        }

        const endOfHead = req.indexOf("\r\n\r\n");
        if (endOfHead === -1) return;

        const head = req.subarray(0, endOfHead).toString("utf8");
        const match = /^GET ([^ ]+) HTTP\/1\.[01]/.exec(head);
        const reqPath = match ? match[1] : "/";

        if (reqPath.startsWith("/big/")) {
          const bodySize = Math.min(16_000_000, Math.max(1, Number(reqPath.slice(5)) || 0));
          const body = Buffer.alloc(bodySize, 0x61);
          const headerPart1 = `HTTP/1.1 200 OK\r\nContent-Length: ${bodySize}\r\n`;
          const headerPart2 = "Content-Type: application/octet-stream\r\nConnection: close\r\n\r\n";

          // Write header part 1 immediately
          socket.write(headerPart1);

          // Write header part 2 and body after small intentional delays to split TCP segments
          setTimeout(() => {
            socket.write(headerPart2);
            setTimeout(() => {
              socket.write(body);
            }, 8);
          }, 8);

          return;
        }

        // Standard small body path
        const body = `plain-http-split-ok ${crypto.randomBytes(8).toString("hex")}`;
        const headerPart1 = "HTTP/1.1 200 OK\r\n";
        const headerPart2 =
          `X-Test-Server: split\r\nContent-Type: text/plain\r\nConnection: close\r\n` +
          `Content-Length: ${body.length}\r\n\r\n${body}`;

        socket.write(headerPart1);
        setTimeout(() => {
          socket.write(headerPart2);
          socket.end();
        }, 12);
      });

      socket.on("error", () => {
        // Suppress expected client teardown errors
      });
    });

    server.once("error", (err: Error) => reject(new Error(`split-http: ${err.message}`)));
    server.listen(port, host, () => {
      resolve({ port, server });
    });
  });
}

/**
 * Issues an HTTP GET request that splits request headers across two separate TCP writes.
 */
export function splitHttpRequest(
  host: string,
  port: number,
  reqPath: string,
): Promise<{ status: string | null; bytes: number }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    socket.setNoDelay(true);

    let received = Buffer.alloc(0);
    let secondWriteSent = false;

    const finish = () => {
      const statusMatch = /^HTTP\/1\.[01] (\d{3})/.exec(received.toString("utf8"));
      resolve({
        status: statusMatch ? statusMatch[1] : null,
        bytes: received.length,
      });
    };

    socket.on("connect", () => {
      // Send first half of the request
      const firstSegment = `GET ${reqPath} HTTP/1.1\r\nHost: ${host}:${port}\r\n`;
      socket.write(firstSegment);

      // Send second half after 12ms to test TCP segment reassembly
      setTimeout(() => {
        if (!secondWriteSent) {
          secondWriteSent = true;
          socket.write("User-Agent: m2-split-client\r\nConnection: close\r\n\r\n");
        }
      }, 12);
    });

    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
    });

    socket.on("close", finish);
    socket.on("error", () => finish());

    // 8-second safety timeout
    setTimeout(() => {
      try {
        socket.destroy();
        finish();
      } catch {
        // noop
      }
    }, 8000);
  });
}

/**
 * Minimal RFC 6455 WebSocket echo server over raw TCP.
 * Accepts handshake upgrade, sends server greeting frame, echoes client frame, and terminates.
 */
export function startWsEchoServer(
  host: string,
  port: number,
): Promise<{ port: number; server: net.Server }> {
  const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

  return new Promise((resolve, reject) => {
    const server = net.createServer((socket) => {
      socket.setNoDelay(true);
      let req = Buffer.alloc(0);

      socket.on("data", (chunk: Buffer) => {
        req = Buffer.concat([req, chunk]);
        const endOfHead = req.indexOf("\r\n\r\n");
        if (endOfHead === -1) return;

        const headerStr = req.subarray(0, endOfHead).toString("ascii");
        if (!headerStr.startsWith("GET")) return;

        const keyMatch = /sec-websocket-key: ([^\r\n]+)/i.exec(headerStr);
        if (!keyMatch) {
          socket.destroy();
          return;
        }

        const secWebSocketAccept = crypto
          .createHash("sha1")
          .update(keyMatch[1].trim() + WS_GUID)
          .digest("base64");

        // Send 101 Switching Protocols response
        socket.write(
          "HTTP/1.1 101 Switching Protocols\r\n" +
            "Upgrade: websocket\r\n" +
            "Connection: Upgrade\r\n" +
            `Sec-WebSocket-Accept: ${secWebSocketAccept}\r\n\r\n`,
        );

        // Server hello text frame: FIN(0x80)|TEXT(0x01), length 5, payload "hello"
        socket.write(Buffer.from([0x81, 0x05, 0x68, 0x65, 0x6c, 0x6c, 0x6f]));
        socket.end();
      });

      socket.on("error", () => {
        // Ignore connection teardown errors
      });
    });

    server.once("error", (err: Error) => reject(new Error(`ws-echo: ${err.message}`)));
    server.listen(port, host, () => resolve({ port, server }));
  });
}

/**
 * Minimal RFC 6455 WebSocket client issuing the upgrade handshake and masked frame.
 */
export function wsClientUpgrade(
  host: string,
  port: number,
  reqPath: string,
): Promise<{ got101: boolean; gotFrame: boolean }> {
  return new Promise((resolve) => {
    const socket = net.createConnection({ host, port });
    let received = Buffer.alloc(0);
    let got101 = false;
    let gotFrame = false;

    const finish = () => {
      try {
        socket.destroy();
      } catch {
        // noop
      }
      resolve({ got101, gotFrame });
    };

    const timer = setTimeout(() => finish(), 8000);

    socket.on("connect", () => {
      const clientKey = crypto.randomBytes(16).toString("base64");
      socket.write(
        `GET ${reqPath} HTTP/1.1\r\n` +
          `Host: ${host}:${port}\r\n` +
          "Upgrade: websocket\r\n" +
          "Connection: Upgrade\r\n" +
          `Sec-WebSocket-Key: ${clientKey}\r\n` +
          "Sec-WebSocket-Version: 13\r\n\r\n",
      );

      // Masked WebSocket text frame payload: masked "b"
      socket.write(Buffer.from([0x81, 0x81, 0xaa, 0xbb, 0xcc, 0xdd, 0xc2]));
    });

    socket.on("data", (chunk: Buffer) => {
      received = Buffer.concat([received, chunk]);
      if (!got101 && received.subarray(0, 12).toString("ascii").startsWith("HTTP/1.1 101")) {
        got101 = true;
      }
      if (received.length > 30) {
        gotFrame = true;
      }
      if (got101 && gotFrame) {
        clearTimeout(timer);
        setTimeout(finish, 60);
      }
    });

    socket.on("error", () => {
      clearTimeout(timer);
      finish();
    });

    socket.on("close", () => {
      clearTimeout(timer);
      finish();
    });
  });
}

/**
 * UDP echo server and client roundtrip for loopback scenario verification.
 */
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
      try {
        server.close();
      } catch {
        // noop
      }
      resolve({ echoed });
    };

    server.on("message", (msg, rinfo) => {
      server.send(msg, rinfo.port, rinfo.address);
      if (msg.equals(payload)) {
        echoed = true;
      }
      setTimeout(cleanup, 200);
    });

    server.on("error", () => {
      // noop
    });

    server.on("listening", () => {
      const client = dgram.createSocket("udp4");
      const timer = setTimeout(() => {
        try {
          client.close();
        } catch {
          // noop
        }
        cleanup();
      }, timeoutMs);

      client.on("message", () => {
        clearTimeout(timer);
        try {
          client.close();
        } catch {
          // noop
        }
      });

      client.send(payload, port, host, () => {
        // noop
      });
    });

    server.bind(port, host);
  });
}
