// M4-c: HTML report generator — produces a self-contained single-file report
// for any FlowAnalysis. No runtime dependencies; all CSS and JS are inlined.
// The report includes:
//   - Summary banner (EPBs, unique pkts, flows, duration)
//   - Interactive sortable flow table with sparkline bars
//   - Per-flow expandable detail panel: TCP lifecycle, reassembly stats, HTTP
//   - DNS attribution table
//   - IPv4 fragment list
//   - Raw JSON data embedded as window.__data for scripting
//
// Layer:     reporting — pure HTML generation (string building; no I/O)
// Milestone: M4c — per-trace HTML report (docs/project-status.md)
// Verified:  gate 6 of `npm run test:all` (dashboard regeneration)
// Exports:   generateHtml

import type { FlowAnalysis, Flow } from "../engine/flows.ts";
import { bytesLabel } from "../engine/flows.ts";

// ─── mini template helpers ───────────────────────────────────────────────────

function h(tag: string, attrs: Record<string, string | number | boolean>, ...children: string[]): string {
  const attrStr = Object.entries(attrs)
    .map(([k, v]) => (typeof v === "boolean" ? (v ? k : "") : `${k}="${esc(String(v))}"`))
    .filter(Boolean)
    .join(" ");
  const inner = children.join("");
  return `<${tag}${attrStr ? " " + attrStr : ""}>${inner}</${tag}>`;
}

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function e(s: string | number | null | undefined): string {
  return esc(String(s ?? ""));
}

// ─── data helpers ─────────────────────────────────────────────────────────────

function flowLabel(f: Flow): string {
  if (f.tlsSni.length) return f.tlsSni.join(", ");
  if (f.hosts.length) return f.hosts.join(", ");
  return "";
}

function tcpBadge(f: Flow): string {
  if (!f.tcp) return "";
  const t = f.tcp;
  const parts: string[] = [];
  if (t.handshakeComplete) parts.push('<span class="badge ok">3WHS</span>');
  if (t.rst) parts.push('<span class="badge warn">RST</span>');
  if (t.finA2b && t.finB2a) parts.push('<span class="badge info">FIN</span>');
  if (f.uniqueRetransSegs > 0) parts.push(`<span class="badge warn">RT:${f.uniqueRetransSegs}</span>`);
  return parts.join(" ");
}

// ─── flow detail panel ────────────────────────────────────────────────────────

function renderFlowDetail(f: Flow, idx: number): string {
  const parts: string[] = [];

  if (f.tcp) {
    const t = f.tcp;
    parts.push('<div class="section-title">TCP Lifecycle</div>');
    const cells: [string, string][] = [
      ["Handshake", t.handshakeComplete ? "✅ Complete" : "❌ Incomplete"],
      ["SYN time", t.syn ? t.syn.ts.toFixed(3) + "s" : "—"],
      ["SYN-ACK Δ", t.synAck?.deltaMs != null ? t.synAck.deltaMs.toFixed(1) + " ms" : "—"],
      ["RST", t.rst ? "Yes at " + t.rst.ts.toFixed(3) + "s" : "No"],
      ["FIN a→b", t.finA2b ? "Yes" : "No"],
      ["FIN b→a", t.finB2a ? "Yes" : "No"],
      ["Data segs", String(t.dataSegs)],
    ];
    parts.push('<table class="detail-table">');
    for (const [k, v] of cells)
      parts.push(`<tr><th>${e(k)}</th><td>${e(v)}</td></tr>`);
    parts.push("</table>");

    for (const dir of ["a2b", "b2a"] as const) {
      const s = t[dir];
      if (!s || s.segments === 0) continue;
      const label = dir === "a2b"
        ? `→ ${e(f.a.ip)}:${f.a.port} → ${e(f.b.ip)}:${f.b.port}`
        : `← ${e(f.b.ip)}:${f.b.port} → ${e(f.a.ip)}:${f.a.port}`;
      parts.push(`<div class="section-title">Stream ${label}</div>`);
      parts.push('<table class="detail-table">');
      parts.push(`<tr><th>Segments</th><td>${s.segments}</td></tr>`);
      parts.push(`<tr><th>Reassembled bytes</th><td>${bytesLabel(s.bytes.length)}</td></tr>`);
      parts.push(`<tr><th>Gaps</th><td>${s.gapCount} (${bytesLabel(s.gapBytes)} zero-filled)</td></tr>`);
      parts.push(`<tr><th>Retransmissions</th><td>${s.retransSegs} (${bytesLabel(s.retransBytes)})</td></tr>`);
      if (s.partialRetransSegs) parts.push(`<tr><th>Partial retrans</th><td>${s.partialRetransSegs}</td></tr>`);
      if (s.truncatedPayloads) parts.push(`<tr><th>Truncated payloads</th><td>${s.truncatedPayloads}</td></tr>`);
      parts.push(`<tr><th>Base assumed</th><td>${s.baseAssumed ? "Yes (no SYN seen)" : "No"}</td></tr>`);
      parts.push(`<tr><th>Overflowed (>8MiB)</th><td>${s.overflowed}</td></tr>`);
      parts.push("</table>");
    }
  }

  if (f.http) {
    parts.push('<div class="section-title">HTTP/1.x Messages</div>');
    parts.push('<table class="detail-table"><tr><th>Dir</th><th>Method</th><th>URI</th><th>Status</th><th>Len</th><th>Complete</th></tr>');
    for (const r of f.http.requests)
      parts.push(`<tr><td>→</td><td>${e(r.method)}</td><td class="uri">${e(r.uri)}</td><td>—</td><td>${r.contentLength ?? "—"}</td><td>${r.bodyComplete ? "✅" : "❌"}</td></tr>`);
    for (const r of f.http.responses)
      parts.push(`<tr><td>←</td><td>—</td><td>—</td><td>${r.status}</td><td>${r.contentLength ?? (r.chunked ? "chunked" : "—")}</td><td>${r.bodyComplete ? "✅" : "❌"}</td></tr>`);
    parts.push("</table>");
    parts.push(`<p class="small">Parsing stopped: <code>${e(f.http.parsingStopped)}</code></p>`);
  }

  return `<div class="detail" id="d${idx}">${parts.join("")}</div>`;
}

// ─── main generator ───────────────────────────────────────────────────────────

/** Render one complete self-contained HTML report (a single string) for a
 * FlowAnalysis. */
export function generateHtml(a: FlowAnalysis): string {
  const ts = new Date().toISOString();
  const totalUnique = a.flows.reduce((s, f) => s + f.uniquePackets, 0);
  const maxBytes = Math.max(...a.flows.map((f) => f.bytes.a2b + f.bytes.b2a), 1);

  // Summary cards
  const cards = [
    ["EPBs captured", a.totalEpbs],
    ["Copies merged", a.duplicatesMerged],
    ["Unique packets", totalUnique],
    ["Flows", a.flows.length],
    ["Non-flow EPBs", a.nonFlowEpbs],
    ["Retrans segs", a.retransSegsTotal],
  ].map(([label, val]) =>
    `<div class="card"><div class="card-val">${e(val)}</div><div class="card-label">${e(label)}</div></div>`
  ).join("");

  // Flow rows
  const flowRows = a.flows.map((f, i) => {
    const totalBytes = f.bytes.a2b + f.bytes.b2a;
    const barW = Math.round((totalBytes / maxBytes) * 100);
    const label = flowLabel(f);
    return `
    <tr class="flow-row" onclick="toggle(${i})">
      <td class="mono">${i + 1}</td>
      <td><span class="kind-badge ${e(f.kind)}">${e(f.kind.toUpperCase())}</span></td>
      <td class="mono small">${e(f.a.ip)}:${f.a.port} ↔ ${e(f.b.ip)}:${f.b.port}</td>
      <td>${e(label)}</td>
      <td>${tcpBadge(f)}</td>
      <td class="num">${f.packets.a2b + f.packets.b2a}</td>
      <td class="num">${f.uniquePackets}</td>
      <td>
        <div class="bar-cell">
          <div class="bar" style="width:${barW}%"></div>
          <span class="bar-label">${e(bytesLabel(totalBytes))}</span>
        </div>
      </td>
      <td class="num">${Math.round((f.lastTs - f.firstTs) * 1000)} ms</td>
    </tr>
    <tr class="detail-row" id="dr${i}"><td colspan="9">${renderFlowDetail(f, i)}</td></tr>`;
  }).join("");

  // DNS table
  const dnsTable = a.dnsHostByIp.length
    ? `<h2>DNS Attribution</h2>
    <table class="detail-table">
      <tr><th>IP</th><th>Hostnames</th></tr>
      ${a.dnsHostByIp.map((r) => `<tr><td class="mono">${e(r.ip)}</td><td>${e(r.names.join(", "))}</td></tr>`).join("")}
    </table>`
    : "";

  const fragTable = a.fragments.length
    ? `<h2>IPv4 Fragment Groups</h2>
    <table class="detail-table">
      <tr><th>Flow pair</th><th>Fragments</th><th>Bytes</th></tr>
      ${a.fragments.map((fr) => `<tr><td class="mono">${e(fr.id)}</td><td>${fr.count}</td><td>${e(bytesLabel(fr.bytes))}</td></tr>`).join("")}
    </table>`
    : "";

  // Inline JSON for scripting
  const jsonBlob = JSON.stringify({ file: a.file, flows: a.flows.length, totalEpbs: a.totalEpbs });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Packet Engine — ${esc(a.file)}</title>
<style>
:root{--bg:#0f1117;--surface:#1a1d27;--surface2:#22263a;--border:#2e3250;
--accent:#6c8fff;--accent2:#4ecca3;--warn:#ffca28;--err:#ff5252;
--text:#e8eaf6;--muted:#7b82b0;--font:'Inter',system-ui,sans-serif}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.5}
a{color:var(--accent)}
h1{font-size:1.3rem;font-weight:700;letter-spacing:-.5px}
h2{font-size:1rem;font-weight:600;color:var(--accent2);margin:1.5rem 0 .6rem}
.topbar{background:var(--surface);border-bottom:1px solid var(--border);
  padding:.75rem 1.25rem;display:flex;align-items:center;gap:1rem}
.topbar .badge-title{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
.main{padding:1.25rem 1.5rem}
.cards{display:flex;flex-wrap:wrap;gap:.75rem;margin-bottom:1.5rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:8px;
  padding:.75rem 1rem;min-width:120px;text-align:center}
.card-val{font-size:1.6rem;font-weight:700;color:var(--accent)}
.card-label{font-size:.7rem;color:var(--muted);text-transform:uppercase;margin-top:.1rem}
table.flow-table{width:100%;border-collapse:collapse}
table.flow-table th{background:var(--surface2);color:var(--muted);font-size:.7rem;
  text-transform:uppercase;letter-spacing:.06em;padding:.5rem .75rem;text-align:left;
  border-bottom:1px solid var(--border)}
table.flow-table td{padding:.4rem .75rem;border-bottom:1px solid var(--border)}
.flow-row{cursor:pointer;transition:background .12s}
.flow-row:hover{background:var(--surface2)}
.detail-row{display:none}
.detail-row.open{display:table-row}
.detail{background:var(--surface2);padding:1rem 1.25rem;border-radius:6px}
.section-title{font-size:.75rem;font-weight:700;color:var(--accent2);text-transform:uppercase;
  letter-spacing:.07em;margin:1rem 0 .4rem}
.section-title:first-child{margin-top:0}
table.detail-table{border-collapse:collapse;font-size:.85rem;width:100%;max-width:800px}
table.detail-table th{color:var(--muted);padding:.25rem .75rem;text-align:left;white-space:nowrap;width:180px}
table.detail-table td{padding:.25rem .75rem;font-family:monospace}
table.detail-table tr:nth-child(even){background:rgba(255,255,255,.03)}
.mono{font-family:'Cascadia Code','Fira Code',monospace;font-size:.82rem}
.num{text-align:right;font-variant-numeric:tabular-nums}
.small{font-size:.78rem;color:var(--muted);margin-top:.4rem}
.uri{max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.kind-badge{font-size:.65rem;font-weight:700;padding:.15rem .45rem;border-radius:4px;text-transform:uppercase;letter-spacing:.06em}
.kind-badge.tcp{background:#1e3a5f;color:#6c8fff}
.kind-badge.udp{background:#1a3d2e;color:#4ecca3}
.kind-badge.icmp,.kind-badge.icmpv6{background:#3d2a1a;color:#ffca28}
.badge{font-size:.65rem;padding:.1rem .35rem;border-radius:3px}
.badge.ok{background:#1a3d2e;color:#4ecca3}
.badge.warn{background:#3d2a1a;color:#ffca28}
.badge.info{background:#1e3a5f;color:#6c8fff}
.bar-cell{display:flex;align-items:center;gap:.4rem;min-width:120px}
.bar{height:6px;border-radius:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));flex-shrink:0}
.bar-label{font-size:.78rem;color:var(--muted);white-space:nowrap}
footer{text-align:center;padding:1.5rem;color:var(--muted);font-size:.75rem;margin-top:1rem}
code{background:rgba(255,255,255,.07);padding:.1rem .3rem;border-radius:3px;font-family:monospace}
</style>
</head>
<body>
<div class="topbar">
  <div>
    <div class="badge-title">Strobe Packet Engine — Flow Report</div>
    <h1>${esc(a.file)}</h1>
  </div>
  <div style="margin-left:auto;text-align:right">
    <div class="badge-title">Generated</div>
    <div class="mono" style="font-size:.82rem">${ts}</div>
  </div>
</div>
<div class="main">
  <div class="cards">${cards}</div>
  <h2>Flows</h2>
  <table class="flow-table">
    <thead>
      <tr>
        <th>#</th><th>Kind</th><th>Endpoints</th><th>Host / SNI</th>
        <th>Badges</th><th>Pkts</th><th>Uniq</th><th>Bytes</th><th>Duration</th>
      </tr>
    </thead>
    <tbody>${flowRows}</tbody>
  </table>
  ${dnsTable}
  ${fragTable}
  ${a.warnings.length ? `<h2>Warnings</h2><ul>${a.warnings.map((w) => `<li>${e(w)}</li>`).join("")}</ul>` : ""}
</div>
<footer>strobe-packet-tracker M4 &bull; <a href="https://github.com">source</a></footer>
<script>
window.__data = ${jsonBlob};
function toggle(i) {
  const dr = document.getElementById('dr'+i);
  dr.classList.toggle('open');
}
// Simple column sort
document.querySelectorAll('.flow-table th').forEach((th, col) => {
  th.style.cursor = 'pointer';
  th.title = 'Click to sort';
  th.addEventListener('click', () => {
    const tbody = th.closest('table').querySelector('tbody');
    const rows = [...tbody.querySelectorAll('.flow-row')];
    const details = [...tbody.querySelectorAll('.detail-row')];
    const asc = th.dataset.asc !== 'true';
    th.dataset.asc = asc;
    rows.sort((a, b) => {
      const av = a.cells[col]?.textContent?.trim() ?? '';
      const bv = b.cells[col]?.textContent?.trim() ?? '';
      const an = parseFloat(av), bn = parseFloat(bv);
      if (!isNaN(an) && !isNaN(bn)) return asc ? an - bn : bn - an;
      return asc ? av.localeCompare(bv) : bv.localeCompare(av);
    });
    rows.forEach((r, i) => {
      tbody.appendChild(r);
      tbody.appendChild(details[parseInt(r.cells[0].textContent)-1]);
    });
  });
});
</script>
</body>
</html>`;
}
