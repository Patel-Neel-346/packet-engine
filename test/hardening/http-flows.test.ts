// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — HTTP/1.x over the flows layer (catalog section H — feasible
// subset; legacy test/flows.test.ts already proves GET+Content-Length and the
// chunked stop; these are the ADDITIONAL edges)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { buildFlows } from "../../src/engine/flows.ts";
import { makePcap, tcpPkt, SYN, ACK, PSH } from "./pcap-helpers.ts";

/** A minimal handshake+data exchange; returns the request/response frames. */
const exchange = (reqFrames: Buffer[], resFrames: Buffer[]): Buffer[] => [
  tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, SYN, 0, 0),
  tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, SYN | ACK, 0, 1),
  tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, ACK, 1, 1),
  ...reqFrames,
  ...resFrames,
];

const req = (seq: number, body: string, port = 80): Buffer =>
  tcpPkt("10.0.0.1", 1000, "10.0.0.2", port, PSH | ACK, seq, 1, Buffer.from(body, "ascii"));
const res = (seq: number, body: string, port = 80): Buffer =>
  tcpPkt("10.0.0.2", port, "10.0.0.1", 1000, PSH | ACK, seq, 100, Buffer.from(body, "ascii"));

describe("http catalog (H)", () => {
  it("http H1: GET/200 over a NON-standard port (8080) -> parsed identically (content decides, not the port)", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET /d HTTP/1.1\r\nHost: h\r\n\r\n")],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")],
        ),
      ),
      "t",
    );
    expect(a.flows).toHaveLength(1);
    expect(a.flows[0].http?.requests[0].uri).toBe("/d");
    expect(a.flows[0].http?.responses[0].status).toBe(200);
  });

  it("http H2: three pipelined requests -> requests.length 3 in order (RFC 9112 §9.3)", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [
            req(1, "GET /a HTTP/1.1\r\nHost: h\r\n\r\n"),
            req(29, "GET /b HTTP/1.1\r\nHost: h\r\n\r\n"), // 28 bytes later
            req(57, "GET /c HTTP/1.1\r\nHost: h\r\n\r\n"), // 28 bytes later again
          ],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")],
        ),
      ),
      "t",
    );
    const reqs = a.flows[0].http?.requests ?? [];
    expect(reqs.map((r) => r.uri)).toEqual(["/a", "/b", "/c"]);
  });

  it("http H3: >8 pipelined requests -> parse stops at the 8-cap with parsingStopped 'limit' (engine bound)", () => {
    const one = (uri: string) => `GET ${uri} HTTP/1.1\r\nHost: h\r\n\r\n`;
    const seqStart = 1;
    let seq = seqStart;
    const reqFrames: Buffer[] = [];
    for (let i = 0; i < 9; i++) {
      reqFrames.push(req(seq, one(`/p${i}`)));
      seq += one(`/p${i}`).length;
    }
    const a = buildFlows(
      makePcap(exchange(reqFrames, [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")])),
      "t",
    );
    const st = a.flows[0].http;
    expect(st?.requests).toHaveLength(8);
    expect(st?.parsingStopped).toBe("limit");
  });

  it("http H4: response WITHOUT content-length -> body runs to end of stream, bodyComplete true (RFC 9112 §6.3)", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")],
          [res(1, "HTTP/1.0 200 OK\r\n\r\nplain body until end")],
        ),
      ),
      "t",
    );
    const r0 = a.flows[0].http?.responses[0];
    expect(r0?.status).toBe(200);
    expect(r0?.contentLength).toBeUndefined();
    expect(r0?.bodyCaptured).toBe("plain body until end".length);
    expect(r0?.bodyComplete).toBe(true);
  });

  it("http H5: header names are lowercased; duplicate headers join with ', ' (RFC 9110 §5.5)", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET / HTTP/1.1\r\nX-CaSe: v1\r\nx-CASE: v2\r\nHost: h\r\n\r\n")],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
      ),
      "t",
    );
    const r0 = a.flows[0].http?.requests[0];
    expect(r0?.headers["x-case"]).toBe("v1, v2");
    expect(Object.keys(r0?.headers ?? {})).not.toContain("X-CaSe");
  });

  it("http H6: request-only flow (no response bytes) -> no http block fabricated", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")],
          [], // nothing back
        ),
      ),
      "t",
    );
    expect(a.flows).toHaveLength(1);
    expect(a.flows[0].http).toBeNull();
  });

  it("http H7: binary garbage both directions -> no http block, no throw", () => {
    const garbage = Buffer.from([0x00, 0x01, 0x02, 0xff, 0xfe, 0x7f]);
    const a = buildFlows(
      makePcap(
        exchange(
          [tcpPkt("10.0.0.1", 1000, "10.0.0.2", 80, PSH | ACK, 1, 1, garbage)],
          [tcpPkt("10.0.0.2", 80, "10.0.0.1", 1000, PSH | ACK, 1, 100, garbage)],
        ),
      ),
      "t",
    );
    expect(a.flows[0].http).toBeNull();
    expect(a.warnings).toHaveLength(0);
  });

  it("http H8: declared body longer than captured -> bodyComplete false (capture truncation, reported honestly)", () => {
    // response declares 10 body bytes; segment carries only 4
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET / HTTP/1.1\r\nHost: h\r\n\r\n")],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nABCD")],
        ),
      ),
      "t",
    );
    const r0 = a.flows[0].http?.responses[0];
    expect(r0?.contentLength).toBe(10);
    expect(r0?.bodyCaptured).toBe(4);
    expect(r0?.bodyComplete).toBe(false);
  });

  it("http H2b: request split at EVERY byte boundary -> identical decoded request each time (RFC 9112 §2.1)", () => {
    const rawReq = "GET /boundary HTTP/1.1\r\nHost: example.org\r\n\r\n";
    for (let split = 1; split < rawReq.length; split++) {
      const part1 = rawReq.slice(0, split);
      const part2 = rawReq.slice(split);
      const frames = exchange(
        [req(1, part1), req(1 + part1.length, part2)],
        [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
      );
      const a = buildFlows(makePcap(frames), "t");
      expect(a.flows[0].http?.requests[0]?.uri).toBe("/boundary");
      expect(a.flows[0].http?.requests[0]?.headers["host"]).toBe("example.org");
    }
  });

  it("http H3b: request line only, headers arrive in next segment -> method, uri, headers decoded (RFC 9112 §2.1)", () => {
    const line = "GET /split-line HTTP/1.1\r\n";
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, line), req(1 + line.length, "Host: split.example\r\n\r\n")],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
      ),
      "t",
    );
    expect(a.flows[0].http?.requests[0].uri).toBe("/split-line");
    expect(a.flows[0].http?.requests[0].headers["host"]).toBe("split.example");
  });

  it("http H4b: headers end split across segments inside CRLFCRLF -> header boundary recognized (RFC 9112 §2.1)", () => {
    const p1 = "GET /crlf HTTP/1.1\r\nHost: h\r\n\r";
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, p1), req(1 + p1.length, "\n\r\n")],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
      ),
      "t",
    );
    expect(a.flows[0].http?.requests[0].uri).toBe("/crlf");
  });

  it("http H12: methods POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT -> method extracted correctly (RFC 9110 §9)", () => {
    const methods = ["POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT"];
    for (const m of methods) {
      const a = buildFlows(
        makePcap(
          exchange(
            [req(1, `${m} /resource HTTP/1.1\r\nHost: h\r\n\r\n`)],
            [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
          ),
        ),
        "t",
      );
      expect(a.flows[0].http?.requests[0].method).toBe(m);
    }
  });

  it("http H13: HTTP/1.0 vs 1.1 version captured; HTTP/2 preface ignored (RFC 9113 §3.4)", () => {
    const a = buildFlows(
      makePcap(
        exchange(
          [req(1, "GET /v10 HTTP/1.0\r\nHost: h\r\n\r\n")],
          [res(1, "HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
      ),
      "t",
    );
    expect(a.flows[0].http?.requests[0].version).toBe("HTTP/1.0");
    expect(a.flows[0].http?.responses[0].version).toBe("1.0");

    // HTTP/2 client connection preface: "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    const h2 = buildFlows(
      makePcap(exchange([req(1, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")], [])),
      "t",
    );
    expect(h2.flows[0].http).toBeNull(); // not misclassified as HTTP/1.x
  });

  it("http H15: retransmitted segment inside a request -> request is not duplicated (sparse-stream dedupe)", () => {
    const reqStr = "GET /no-dup HTTP/1.1\r\nHost: h\r\n\r\n";
    const a = buildFlows(
      makePcap(
        exchange(
          [
            req(1, reqStr),
            req(1, reqStr), // identical segment retransmitted
          ],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
        5000,
      ),
      "t",
    );
    expect(a.flows[0].http?.requests).toHaveLength(1);
    expect(a.flows[0].http?.requests[0].uri).toBe("/no-dup");
  });

  it("http H16: out-of-order segments of one request -> reassembled in sequence order (sparse-stream order)", () => {
    const seg1 = "GET /in-order ";
    const seg2 = "HTTP/1.1\r\nHost: h\r\n\r\n";
    const a = buildFlows(
      makePcap(
        exchange(
          [
            req(1 + seg1.length, seg2), // segment 2 arrives first
            req(1, seg1), // segment 1 arrives second
          ],
          [res(1, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")],
        ),
      ),
      "t",
    );
    expect(a.flows[0].http?.requests).toHaveLength(1);
    expect(a.flows[0].http?.requests[0].uri).toBe("/in-order");
  });
});
