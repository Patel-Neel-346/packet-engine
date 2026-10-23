// ─────────────────────────────────────────────────────────────────────────────
// HARDENING SUITE — TLS ClientHello metadata (catalog section G — feasible
// subset) + G12 static no-decryption/no-tshark scan of src/engine.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { eth, ip4, ip6, tcp, decode, hasError } from "./helpers.ts";

/* Minimal hand-rolled TLS hello record (RFC 8446 §4.1.2 field layout):
 *   record: type(1) | ver(2) | len(2)
 *   handshake: type(1) | len(3) | legacyVer(2) | random(32)
 *   | sidLen(1) [+sid] | csLen(2) [ciphers] | compLen(1) [comps]
 *   | extLen(2) [extensions]
 * extLenOverride: lie about the extension-list length (illegal-value test).
 * truncate: cut n bytes off the END of the frame (capture-cut realism).     */
function tlsFrame(opts: {
  handshakeType?: number;
  recordType?: number;
  recordVer?: string;
  legacyVer?: string;
  exts?: Buffer[];
  extLenOverride?: number;
  tail?: number;
  ip6?: boolean;
  truncate?: number;
}): Buffer {
  const exts = opts.exts ?? [];
  const extBody = Buffer.concat(exts);
  const hsBody = Buffer.concat([
    Buffer.from(opts.legacyVer ?? "0303", "hex"),
    Buffer.alloc(32), // random
    Buffer.from([0]), // session id length 0
    Buffer.from([0x00, 0x02]), // cipher-suites list length = 2 (one suite)
    Buffer.from([0x00, 0x2f]), // TLS_RSA_WITH_AES_128_CBC_SHA (filler, not asserted)
    Buffer.from([0x00]), // compression methods: one null compression
    (() => {
      const e = Buffer.alloc(2);
      e.writeUInt16BE(opts.extLenOverride ?? extBody.length);
      return e;
    })(),
    extBody,
  ]);
  const hi = Buffer.alloc(4);
  hi[0] = opts.handshakeType ?? 0x01;
  hi.writeUIntBE(hsBody.length, 1, 3);
  const rec = Buffer.alloc(5);
  rec[0] = opts.recordType ?? 0x16;
  rec.write(opts.recordVer ?? "0303", 1, "hex");
  rec.writeUInt16BE(hi.length + hsBody.length, 3);
  let payload = Buffer.concat([rec, hi, hsBody]);
  if (opts.tail) payload = Buffer.concat([payload, Buffer.alloc(opts.tail)]);
  const ip = opts.ip6
    ? ip6(tcp({ sport: 46600, dport: 443 }, payload), { nh: 6 })
    : ip4(tcp({ sport: 46600, dport: 443 }, payload), { proto: 6 });
  const frame = Buffer.concat([eth(ip, { ethertype: opts.ip6 ? 0x86dd : 0x0800 })]);
  return opts.truncate ? frame.slice(0, frame.length - opts.truncate) : frame;
}

const ext = (type: number, body: Buffer): Buffer => {
  const h = Buffer.alloc(4);
  h.writeUInt16BE(type, 0);
  h.writeUInt16BE(body.length, 2);
  return Buffer.concat([h, body]);
};

/** server_name (0x0000) extension for one host (RFC 6066 §3). */
const sniExt = (host: string): Buffer => {
  const name = Buffer.from(host, "ascii");
  const listLen = Buffer.alloc(2);
  listLen.writeUInt16BE(1 + 2 + name.length); // entry: type(1)+len(2)+name
  const nameLen = Buffer.alloc(2);
  nameLen.writeUInt16BE(name.length);
  return ext(0x0000, Buffer.concat([listLen, Buffer.from([0]), nameLen, name]));
};

const supportedVersionsExt = (): Buffer =>
  // listLen(1) + 2-byte version entries (RFC 8446 §4.2.1)
  ext(
    0x002b,
    Buffer.concat([Buffer.from([0x04]), Buffer.from("0304", "hex"), Buffer.from("0303", "hex")]),
  );

const echExt = (type = 0xfe0d): Buffer => ext(type, Buffer.from([1, 2, 3, 4]));

describe("tls catalog (G)", () => {
  it("tls G1: ClientHello with SNI -> recordVersion/legacyVersion/handshake/sni decoded, no error", () => {
    const r = decode(1, tlsFrame({ exts: [sniExt("example.org")] }));
    expect(r.tls?.handshake).toBe("clientHello");
    expect(r.tls?.recordVersion).toBe("0303");
    expect(r.tls?.legacyVersion).toBe("0303");
    expect(r.tls?.sni).toBe("example.org");
    expect(r.errors).toHaveLength(0);
  });

  it("tls G2: SNI over IPv6 port 443 -> same metadata (transport family is neutral)", () => {
    const r = decode(1, tlsFrame({ exts: [sniExt("v6.example.net")], ip6: true }));
    expect(r.tls?.sni).toBe("v6.example.net");
    expect(r.errors).toHaveLength(0);
  });

  it("tls G4a: supported_versions -> ['0304','0303'] entries preserved (RFC 8446 §4.2.1)", () => {
    const r = decode(1, tlsFrame({ exts: [supportedVersionsExt(), sniExt("example.org")] }));
    expect(r.tls?.supportedVersions).toEqual(["0304", "0303"]);
    expect(r.tls?.sni).toBe("example.org");
  });

  it("tls G5: ECH extension (0xfe0d / GREASE 0xfe0e) -> ech flag; the OUTER SNI is what is reported (draft-esni)", () => {
    const r = decode(1, tlsFrame({ exts: [sniExt("outer.example.com"), echExt()] }));
    expect(r.tls?.ech).toBe(true);
    expect(r.tls?.sni).toBe("outer.example.com");
    const r2 = decode(1, tlsFrame({ exts: [sniExt("outer.example.com"), echExt(0xfe0e)] }));
    expect(r2.tls?.ech).toBe(true);
    expect(r2.tls?.sni).toBe("outer.example.com");
  });

  it("tls G6: ServerHello (type 0x02) -> handshake 'serverHello', no SNI invented", () => {
    const r = decode(1, tlsFrame({ exts: [], handshakeType: 0x02 }));
    expect(r.tls?.handshake).toBe("serverHello");
    expect(r.tls?.sni).toBeUndefined();
  });

  it("tls G7: ClientHello with NO SNI extension -> tls info present, sni undefined, no error", () => {
    const r = decode(1, tlsFrame({ exts: [supportedVersionsExt()] }));
    expect(r.tls?.handshake).toBe("clientHello");
    expect(r.tls?.sni).toBeUndefined();
    expect(r.errors).toHaveLength(0);
  });

  it("tls G8a: extension list overrun AND SNI found -> named error 'tls.truncated-extensions' with partial decode kept", () => {
    // capture cut into the extension area: declared extLen now exceeds
    // the captured bytes, but the SNI extension was already parsed
    const full = tlsFrame({ exts: [sniExt("example.org"), echExt()] });
    const r = decode(1, tlsFrame({ exts: [sniExt("example.org"), echExt()], truncate: 6 }));
    void full;
    expect(hasError(r, "tls.truncated-extensions")).toBe(true);
    expect(r.tls?.sni).toBe("example.org");
  });

  it("tls G8b: extension overrun WITHOUT a real SNI -> stays silent (encrypted-port probe must not misclassify QUIC, learned on s9)", () => {
    const r = decode(1, tlsFrame({ exts: [], extLenOverride: 0x40, tail: 8 }));
    expect(hasError(r, "tls.truncated-extensions")).toBe(false);
    expect(Array.isArray(r.errors)).toBe(true);
  });

  it("tls G9: random encrypted-looking payload on port 443 -> no tls block, NO errors, no throw (s9 QUIC silence rule)", () => {
    const garbage = Buffer.from("cae66bec1b3f29b0a4d7", "hex");
    const r = decode(
      1,
      eth(ip4(tcp({ sport: 30000, dport: 443 }, garbage), { proto: 6 }), { ethertype: 0x0800 }),
    );
    expect(r.errors).toHaveLength(0);
    expect(r.transport?.sport).toBe(30000);
  });

  it("tls G10: app-data record (0x17) on 443 -> no tls block, no phantom error (only hello records are dissected)", () => {
    const r = decode(1, tlsFrame({ exts: [sniExt("example.org")], recordType: 0x17 }));
    expect(r.tls).toBeUndefined();
    expect(r.errors).toHaveLength(0);
  });

  it("tls G12: static scan — engine never spawns processes, never tshark outside comments, never imports crypto except local hashing", () => {
    const dir = join(process.cwd(), "src", "engine");
    for (const f of readdirSync(dir).filter((n) => n.endsWith(".ts"))) {
      const text = readFileSync(join(dir, f), "utf8");
      // code-only view: strip comment lines so documented verification history
      // (e.g. "verified against tshark") cannot shadow a real invocation
      const code = text
        .split("\n")
        .filter((line) => {
          const t = line.trim();
          return t !== "" && !t.startsWith("//") && !t.startsWith("*") && !t.startsWith("/*");
        })
        .join("\n");
      expect(/\bchild_process\b/.test(code)).toBe(false); // ${f}: no child_process
      expect(/tshark/i.test(code)).toBe(false); // ${f}: no tshark invocation
      expect(/\brequire\s*\(/.test(code)).toBe(false); // ${f}: no require (pure ESM)
      // node:crypto is allowed ONLY in dedupe.ts (sha1 for the M2 duplicate
      // rule); no encryption/decryption anywhere in the engine.
      if (f === "dedupe.ts") {
        expect(/createCipheriv|createDecipheriv|createSecretKey|generateKey/.test(code)).toBe(
          false,
        );
      } else {
        expect(/\bnode:crypto\b/.test(code)).toBe(false); // ${f}: crypto import
      }
    }
  });

  it("tls G3: SNI with trailing dot or IP literal -> recorded as-is (RFC 6066 §3)", () => {
    const rDot = decode(1, tlsFrame({ exts: [sniExt("example.org.")] }));
    expect(rDot.tls?.sni).toBe("example.org.");
    expect(rDot.errors).toHaveLength(0);

    const rIp = decode(1, tlsFrame({ exts: [sniExt("192.0.2.1")] }));
    expect(rIp.tls?.sni).toBe("192.0.2.1");
    expect(rIp.errors).toHaveLength(0);
  });

  it("tls G5b: extension list length 0 -> decoded cleanly with no extensions, no error (RFC 8446 §4.1.2)", () => {
    const r = decode(1, tlsFrame({ exts: [], extLenOverride: 0 }));
    expect(r.tls?.handshake).toBe("clientHello");
    expect(r.tls?.sni).toBeUndefined();
    expect(r.errors).toHaveLength(0);
  });

  it("tls G9b: TLS alert record (0x15) -> no TLS handshake/SNI decoded, no errors, no throw (RFC 8446 §5.1)", () => {
    const alertRecord = Buffer.from([0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x32]); // Fatal (2), Decode error (50)
    const ip = ip4(tcp({ sport: 443, dport: 46600 }, alertRecord), { proto: 6 });
    const r = decode(1, eth(ip, { ethertype: 0x0800 }));
    expect(r.tls).toBeUndefined();
    expect(r.errors).toHaveLength(0);
  });

  it("tls G14: even-length supported_versions extension (missing 1-byte list length) -> safely skipped, no throw (RFC 8446 §4.2.1)", () => {
    const malformed = ext(0x002b, Buffer.from("03040303", "hex")); // 4 bytes (even length)
    const r = decode(1, tlsFrame({ exts: [malformed, sniExt("example.org")] }));
    expect(r.tls?.supportedVersions).toBeUndefined();
    expect(r.tls?.sni).toBe("example.org");
    expect(Array.isArray(r.errors)).toBe(true);
  });
});
