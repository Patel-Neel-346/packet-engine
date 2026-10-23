// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — DNS (catalog section F — feasible subset; gap items carry
// it.skip with the reason, never a fake pass)
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { eth, ip4, ip6, udp, tcp, decode, hasError, dnsMsg } from "./helpers.ts";

/** Wrap a complete DNS message in Ethernet+IPv4+UDP dst-53. */
const dnsFrame = (msg: Buffer, over: "v4" | "v6" = "v4"): Buffer =>
  over === "v4"
    ? eth(ip4(udp(msg, { sport: 40000, dport: 53, lenOverride: 8 + msg.length }), { proto: 17 }), { ethertype: 0x0800 })
    : eth(ip6(udp(msg, { sport: 40000, dport: 53, lenOverride: 8 + msg.length }), { nh: 17 }), { ethertype: 0x86dd });

/** Encode a DNS name on the wire (uncompressed). */
const nameWire = (n: string): Buffer => {
  const parts: Buffer[] = [];
  for (const label of n.split(".")) {
    const one = Buffer.alloc(1 + label.length);
    one[0] = label.length;
    one.write(label, 1);
    parts.push(one);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
};

/** Fixed 10-byte record header (type@0 class@2 ttl@4 rdlen@8) + rdata. */
const rec = (type: number, rdata: Buffer, cls = 1, ttl = 60): Buffer => {
  const r = Buffer.alloc(10);
  r.writeUInt16BE(type, 0);
  r.writeUInt16BE(cls, 2);
  r.writeUInt32BE(ttl, 4);
  r.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([r, rdata]);
};

/** Compression pointer to offset 12 (the first question name). */
const ptr12 = (): Buffer => Buffer.from([0xc0, 0x0c]);

describe("dns catalog (F)", () => {
  it("dns F1: question types A/AAAA/CNAME/MX/TXT/PTR -> name+type recorded for each (RFC 1035 §3.4)", () => {
    const types = [1, 28, 5, 15, 16, 12];
    const qs = types.map((t) => ({ name: "example.org", type: t }));
    const r = decode(1, dnsFrame(dnsMsg({ questions: qs })));
    expect(r.dns?.questions.map((q) => q.type)).toEqual(types);
    expect(r.dns?.questions.every((q) => q.name === "example.org")).toBe(true);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F2a: response with a CNAME chain -> answerNames holds the alias chain, aRecords the A value (RFC 1035 §3.4.1)", () => {
    const q = dnsMsg({ isResponse: true, an: 2, questions: [{ name: "example.org", type: 1 }] });
    const wwwAndPtr = Buffer.concat([Buffer.from([3]), Buffer.from("www"), ptr12()]); // www.<ptr to example.org>
    const a1 = Buffer.concat([wwwAndPtr, rec(5, Buffer.from(wwwAndPtr))]); // CNAME answer
    const a2 = Buffer.concat([ptr12(), rec(1, Buffer.from([93, 184, 216, 8]))]); // A answer
    const r = decode(1, dnsFrame(Buffer.concat([q, a1, a2])));
    expect(r.dns?.answerNames).toContain("www.example.org");
    expect(r.dns?.aRecords).toContain("93.184.216.8");
    expect(r.errors).toHaveLength(0);
  });

  it("dns F3: rcode 3, 2, 5 decoded from flags (RFC 1035 §4.1.1)", () => {
    for (const rc of [3, 2, 5]) {
      const r = decode(1, dnsFrame(dnsMsg({ isResponse: true, rcode: rc })));
      expect(r.dns?.rcode).toBe(rc);
    }
  });

  it("dns F4a: name compression pointer to an EARLIER name -> resolved, bounded (RFC 1035 §4.1.4)", () => {
    const q = dnsMsg({ isResponse: true, an: 1, questions: [{ name: "example.org", type: 1 }] });
    const ans = Buffer.concat([ptr12(), rec(1, Buffer.from([1, 2, 3, 4]))]);
    const r = decode(1, dnsFrame(Buffer.concat([q, ans])));
    expect(r.dns?.aRecords).toEqual(["1.2.3.4"]);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F4b: self-referencing pointer (0xc00c at offset 12) -> terminates with a NAMED error, bounded (RFC 1035 §4.1.4)", () => {
    const msg = dnsMsg({ questions: [{ name: "example.org", type: 1 }] });
    msg[12] = 0xc0; msg[13] = 0x0c; // question name points at itself
    const dstCopy = Buffer.from(msg);
    dstCopy[12] = 0xc0; dstCopy[13] = 0x0c;
    const t0 = Date.now();
    const r = decode(1, dnsFrame(dstCopy));
    expect(Date.now() - t0).toBeLessThan(250); // bounded time
    expect(hasError(r, "dns.pointer-loop")).toBe(true);
    expect(r.dns?.questions).toHaveLength(0); // bogus name never recorded
  });

  it("dns F4c: mutual pointer pair (A->B, B->A) -> terminates with error, bounded", () => {
    const msg = dnsMsg({ questions: [{ name: "example.org", type: 1 }] }); // 25 bytes total
    msg[12] = 0xc0; msg[13] = 0x10; // A(12) -> 16
    msg[16] = 0xc0; msg[17] = 0x0c; // B(16) -> 12  (both offsets inside the message)
    const r = decode(1, dnsFrame(msg));
    expect(hasError(r, "dns.pointer-loop")).toBe(true);
    expect(r.errors.some((e) => e.startsWith("dns"))).toBe(true);
  });

  it("dns F4d: pointer past end of message -> error 'dns.pointer-target', partial fields kept", () => {
    const msg = dnsMsg({ questions: [{ name: "example.org", type: 1 }] });
    msg[12] = 0xc0; msg[13] = 0xff; // target 255 > message length (25)
    const r = decode(1, dnsFrame(msg));
    expect(hasError(r, "dns.pointer-target")).toBe(true);
    expect(r.dns?.questions).toHaveLength(0);
  });

  it("dns F4e: pointer INTO the 12-byte header (target 0) -> error 'dns.pointer-target' (RFC 1035 §4.1.4)", () => {
    const msg = dnsMsg({ questions: [{ name: "example.org", type: 1 }] });
    msg[12] = 0xc0; msg[13] = 0x00; // target 0 = header
    const r = decode(1, dnsFrame(msg));
    expect(hasError(r, "dns.pointer-target")).toBe(true);
  });

  it("dns F5a: label length exactly 63 -> decodes (boundary, RFC 1035 §2.3.4)", () => {
    const long = "a".repeat(63);
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name: `${long}.example.org`, type: 1 }] })));
    expect(r.dns?.questions[0].name).toBe(`${long}.example.org`);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F5b: label length 64 -> error 'dns.label-too-long', no bogus question recorded (RFC 1035 §2.3.4)", () => {
    const msg = dnsMsg({ questions: [{ name: "example.org", type: 1 }] });
    msg[12] = 64; // label length 64 (not a pointer, not a legal label)
    const r = decode(1, dnsFrame(msg));
    expect(hasError(r, "dns.label-too-long")).toBe(true);
    expect(r.dns?.questions).toHaveLength(0); // no fraudulent name+type invented
  });

  it("dns F5c: name exceeding 255 bytes -> error 'dns.name-too-long' (RFC 1035 §2.3.4)", () => {
    const labels = Array.from({ length: 8 }, () => "a".repeat(40)); // 8×41 = 328 wire bytes > 255
    const name = [...labels, "example.org"].join(".");
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name, type: 1 }] })));
    expect(hasError(r, "dns.name-too-long")).toBe(true);
    expect(r.dns?.questions).toHaveLength(0);
  });

  it("dns F7: ANCOUNT 5 but only 2 answers present -> 2 parsed + truncation error 'dns.truncated-answers'", () => {
    const q = dnsMsg({ isResponse: true, an: 5, questions: [{ name: "example.org", type: 1 }] });
    const ans = Buffer.concat([ptr12(), rec(1, Buffer.from([1, 2, 3, 4]))]);
    const msg = Buffer.concat([q, ans, ans]); // 2 answers only
    const r = decode(1, dnsFrame(msg));
    expect(r.dns?.aRecords).toHaveLength(2);
    expect(hasError(r, "dns.truncated-answers")).toBe(true);
  });

  it("dns F8: A record with rdata length 3 (not 4) -> error 'dns.bad-rdata-length' (RFC 1035 §3.4.1)", () => {
    const q = dnsMsg({ isResponse: true, an: 1, questions: [{ name: "example.org", type: 1 }] });
    const ans = Buffer.concat([ptr12(), rec(1, Buffer.alloc(3))]); // rdlen 3, never a 4-byte address
    const r = decode(1, dnsFrame(Buffer.concat([q, ans])));
    expect(hasError(r, "dns.bad-rdata-length")).toBe(true);
    expect(r.dns?.aRecords).toHaveLength(0); // never fabricate a 3-byte address
  });

  it("dns F9: TC flag set on a truncated response -> truncated: true decoded (RFC 1035 §4.1.1)", () => {
    const q = dnsMsg({ isResponse: true, questions: [{ name: "example.org", type: 1 }] });
    q.writeUInt16BE(0x8200, 2); // response + TC
    const cut = q.subarray(0, 16); // cut mid-question -> forced truncation
    const r = decode(1, dnsFrame(cut));
    expect(r.dns?.truncated).toBe(true);
    expect(r.errors.some((e) => e.startsWith("dns"))).toBe(true);
  });

  it("dns F10a: SYN or port-53 TCP packet with no payload -> no DNS parse, no phantom error", () => {
    const r = decode(1, eth(ip4(tcp({ sport: 40000, dport: 53, flags: 0x02 })), { ethertype: 0x0800 }));
    expect(r.dns).toBeUndefined();
    expect(r.errors).toHaveLength(0);
  });

  it("dns F11: random garbage on port 53 -> bounded named errors, no throw, no bogus names", () => {
    const garbage = Buffer.alloc(30, 0x66);
    const r = decode(1, dnsFrame(garbage));
    expect(r.transport?.kind).toBe("udp");
    // Bounded failure: a small number of named errors (label-too-long), never
    // a runaway loop and never fabricated DNS names.
    expect(r.errors.length).toBeGreaterThanOrEqual(1);
    expect(r.errors.length).toBeLessThanOrEqual(40);
    expect(hasError(r, "dns.label-too-long")).toBe(true);
    expect(r.dns?.questions).toHaveLength(0);
    expect(r.dns?.aRecords).toHaveLength(0);
  });

  it("dns F12: EDNS0 OPT record (type 41) in answers -> flagged as edns, NEVER counted as an A record (RFC 6891 §6.1.2)", () => {
    const q = dnsMsg({ isResponse: true, an: 1, questions: [{ name: "example.org", type: 1 }] });
    const opt = rec(41, Buffer.alloc(0), 4096); // class field = UDP payload size per RFC 6891
    const r = decode(1, dnsFrame(Buffer.concat([q, Buffer.from([0]), opt]))); // root owner name + OPT
    expect(r.dns?.edns).toBe(true);
    expect(r.dns?.aRecords).toHaveLength(0);
  });

  it("dns F13: case mixing (ExamPLE.orG) -> preserved verbatim (attribution lowercases later, RFC 1035 §2.3.3)", () => {
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name: "ExamPLE.orG", type: 1 }] })));
    expect(r.dns?.questions[0].name).toBe("ExamPLE.orG");
  });

  it("dns F15: QDCOUNT 2 -> both questions parsed within the bounded ≤10 question walk (engine rule)", () => {
    const r = decode(1, dnsFrame(dnsMsg({
      questions: [{ name: "a.example.org", type: 1 }, { name: "b.example.org", type: 28 }],
    })));
    expect(r.dns?.questions).toHaveLength(2);
    expect(r.dns?.questions[1].type).toBe(28);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F2b: response over IPv6 -> identical DNS fields (UDP transport is family-neutral, RFC 3596 §2.1)", () => {
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name: "example.org", type: 28 }] }), "v6"));
    expect(r.dns?.questions[0].type).toBe(28);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F4f: pointer to a pointer -> chained compression resolves cleanly (RFC 1035 §4.1.4)", () => {
    // Question for example.org is at offset 12..28
    const q = dnsMsg({ isResponse: true, an: 2, questions: [{ name: "example.org", type: 1 }] });
    // Answer 0 starts at offset 29: name points to offset 12 (example.org)
    const a0 = Buffer.concat([ptr12(), rec(5, Buffer.from(ptr12()))]);
    // Answer 1 starts after a0: name points to offset 29 (which points to offset 12)
    const ptrToA0 = Buffer.from([0xc0, 0x1d]); // pointer to offset 29
    const a1 = Buffer.concat([ptrToA0, rec(1, Buffer.from([10, 0, 0, 1]))]);
    const r = decode(1, dnsFrame(Buffer.concat([q, a0, a1])));
    expect(r.dns?.aRecords).toEqual(["10.0.0.1"]);
    expect(r.errors).toHaveLength(0);
  });

  it("dns F6: root name '.' -> decoded as '.' (RFC 1035 §3.1)", () => {
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name: ".", type: 1 }] })));
    expect(r.dns?.questions[0].name).toBe(".");
    expect(r.errors).toHaveLength(0);
  });

  it("dns F14: internationalized / punycode names (xn--) -> decoded as-is (RFC 5890 §2.3.2.1)", () => {
    const r = decode(1, dnsFrame(dnsMsg({ questions: [{ name: "xn--bcher-kva.example", type: 1 }] })));
    expect(r.dns?.questions[0].name).toBe("xn--bcher-kva.example");
    expect(r.errors).toHaveLength(0);
  });

  it("dns F16: response whose ID does not match any query -> still decoded without throwing (RFC 1035 §4.1.1)", () => {
    const r = decode(1, dnsFrame(dnsMsg({ id: 0x9876, isResponse: true, an: 0, questions: [{ name: "example.org", type: 1 }] })));
    expect(r.dns?.transactionId).toBe(0x9876);
    expect(r.dns?.isResponse).toBe(true);
    expect(r.errors).toHaveLength(0);
  });
});
