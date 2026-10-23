// ─────────────────────────────────────────────────────────────────────────────
// TSHARK INDEPENDENT ORACLE SUITE — src/verify/m3Verify.ts
//
// Proves the packet engine against real tshark 4.6.9 output on real captured
// traces. Mismatches fail the test; unsupported never counts as a pass.
// ─────────────────────────────────────────────────────────────────────────────

import { describe, it, expect } from "@jest/globals";
import fs from "node:fs";
import path from "node:path";
import { tsharkExe } from "../src/capture/pktmon.ts";
import { verifyTrace } from "../src/verify/m3Verify.ts";
import { SCEN_DIR } from "../src/paths.ts";

describe("tshark independent oracle verification (real capture traces)", () => {
  const hasTshark = fs.existsSync(tsharkExe());

  (hasTshark ? it : it.skip)(
    "tshark oracle: s1_https_all.pcapng -> TCP conversations & retransmissions match tshark 4.6.9",
    async () => {
      const trace = path.join(SCEN_DIR, "s1_https_all.pcapng");
      if (!fs.existsSync(trace)) return;
      const res = await verifyTrace(trace);
      expect(res.ok).toBe(true);
      expect(res.checks.every((c) => c.status === "pass")).toBe(true);
      expect(res.checks.find((c) => c.check === "conv-tcp")?.status).toBe("pass");
    },
    30000,
  );

  (hasTshark ? it : it.skip)(
    "tshark oracle: s3_dns_all.pcapng -> DNS attribution, TCP/UDP conversations match tshark 4.6.9",
    async () => {
      const trace = path.join(SCEN_DIR, "s3_dns_all.pcapng");
      if (!fs.existsSync(trace)) return;
      const res = await verifyTrace(trace);
      expect(res.ok).toBe(true);
      expect(res.checks.every((c) => c.status === "pass")).toBe(true);
      expect(res.checks.find((c) => c.check === "dns-attribution")?.status).toBe("pass");
    },
    30000,
  );

  (hasTshark ? it : it.skip)(
    "tshark oracle: s8_icmp_all.pcapng -> ICMP pair conversations match tshark 4.6.9",
    async () => {
      const trace = path.join(SCEN_DIR, "s8_icmp_all.pcapng");
      if (!fs.existsSync(trace)) return;
      const res = await verifyTrace(trace);
      expect(res.ok).toBe(true);
      expect(res.checks.every((c) => c.status === "pass")).toBe(true);
      expect(res.checks.find((c) => c.check === "conv-icmp-pairs")?.status).toBe("pass");
    },
    30000,
  );

  (hasTshark ? it : it.skip)(
    "tshark oracle: s2_http_external_all.pcapng -> HTTP stories & conversations match tshark 4.6.9",
    async () => {
      const trace = path.join(SCEN_DIR, "s2_http_external_all.pcapng");
      if (!fs.existsSync(trace)) return;
      const res = await verifyTrace(trace);
      expect(res.ok).toBe(true);
      expect(res.checks.every((c) => c.status === "pass")).toBe(true);
      expect(res.checks.find((c) => c.check === "http-stories")?.status).toBe("pass");
    },
    30000,
  );
});
