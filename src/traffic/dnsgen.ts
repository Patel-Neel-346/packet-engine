// Minimal DNS client used by the traffic generators (non-elevated).
// Builds real DNS wire messages with its own transaction IDs so the
// capture has deterministic queries to verify: A, AAAA, NXDOMAIN, and
// DNS over TCP (2-byte length prefix on a TCP/53 socket).
//
// Layer:     traffic — DNS client I/O (raw dgram/net sockets; non-elevated)
// Milestone: M2 — deterministic DNS queries for the s3 scenario (docs/history/milestone-2-report.md)
// Verified:  s3_dns trace decoded + DNS attribution cross-checked vs tshark in M3.3
// Exports:   buildDnsQuery, dnsQueryUdp, dnsQueryTcp

import dgram from "node:dgram";
import net from "node:net";

/** Build a one-question DNS query wire message (RD set, class IN). */
export function buildDnsQuery(id: number, name: string, qtype: number): Buffer {
  const parts: Buffer[] = [];
  const h = Buffer.alloc(12);
  h.writeUInt16BE(id, 0);
  h.writeUInt16BE(0x0100, 2); // RD
  h.writeUInt16BE(1, 4); // one question
  parts.push(h);
  for (const label of name.split(".")) {
    if (label === "") continue;
    const one = Buffer.alloc(1 + label.length);
    one[0] = label.length;
    one.write(label, 1, "ascii");
    parts.push(one);
  }
  parts.push(Buffer.from([0]));
  const t = Buffer.alloc(4);
  t.writeUInt16BE(qtype, 0);
  t.writeUInt16BE(1, 2); // IN
  parts.push(t);
  return Buffer.concat(parts);
}

/** Send one UDP/53 query and wait for the reply with the matching
 * transaction id (null fields on timeout/error — never throws). */
export async function dnsQueryUdp(
  server: string,
  name: string,
  qtype: number,
  timeoutMs = 5000,
): Promise<{ rcode: number | null; answerCount: number | null; raw: Buffer | null }> {
  const id = Math.floor(Math.random() * 65535);
  const q = buildDnsQuery(id, name, qtype);
  return new Promise((resolve) => {
    const sock = dgram.createSocket("udp4");
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (rcode: number | null, count: number | null, raw: Buffer | null) => {
      clearTimeout(timer);
      try {
        sock.close();
      } catch {
        /* already closed */
      }
      resolve({ rcode, answerCount: count, raw });
    };
    timer = setTimeout(() => finish(null, null, null), timeoutMs);
    sock.on("message", (msg) => {
      if (msg.length < 12) return finish(null, null, msg);
      const rid = msg.readUInt16BE(0);
      if (rid !== id) return; // ignore other id (should not happen on fresh socket)
      const flags = msg.readUInt16BE(2);
      finish(flags & 0x0f, msg.readUInt16BE(6), msg);
    });
    sock.send(q, 53, server, (err) => {
      if (err) finish(null, null, null);
    });
  });
}

/** Send one query over TCP/53 with the 2-byte length prefix (RFC 1035 §4.2.2). */
export async function dnsQueryTcp(
  server: string,
  name: string,
  qtype: number,
  timeoutMs = 5000,
): Promise<{ rcode: number | null; answerCount: number | null; tcpUsed: boolean }> {
  const id = Math.floor(Math.random() * 65535);
  const q = buildDnsQuery(id, name, qtype);
  const lenPrefix = Buffer.alloc(2);
  lenPrefix.writeUInt16BE(q.length, 0);
  return new Promise((resolve) => {
    const socket = net.createConnection({ host: server, port: 53 });
    let buf = Buffer.alloc(0);
    let done = false;
    const finish = (rcode: number | null, count: number | null) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve({ rcode, answerCount: count, tcpUsed: true });
    };
    const timer = setTimeout(() => finish(null, null), timeoutMs);
    socket.on("connect", () => socket.write(Buffer.concat([lenPrefix, q])));
    socket.on("data", (c: Buffer) => {
      buf = Buffer.concat([buf, c]);
      if (buf.length < 2) return;
      const need = buf.readUInt16BE(0) + 2;
      if (buf.length >= need) {
        clearTimeout(timer);
        const msg = buf.subarray(2, need);
        if (msg.length >= 12 && msg.readUInt16BE(0) === id) {
          finish(msg.readUInt16BE(2) & 0x0f, msg.readUInt16BE(6));
        } else {
          finish(null, null);
        }
      }
    });
    socket.on("error", () => {
      clearTimeout(timer);
      finish(null, null);
    });
  });
}
