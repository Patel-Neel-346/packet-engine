# History — dated evidence records

These documents are the project's milestone evidence, written at the time each
milestone completed. They are preserved **verbatim**: commands, outputs, file
paths, and findings are exactly what was recorded then.

| File | What it documents |
|---|---|
| `step0-environment.md` | Machine/tool inventory and ground rules established before any code (pktmon/tshark/Node versions, privilege facts, licensing constraints). |
| `milestone-1-report.md` | M1 — the pktmon → ETL → etl2pcap → PCAPNG capture path, frame-by-frame cross-check vs tshark. |
| `milestone-2-report.md` | M2 — the packet decoder, the parity metric vs tshark, the scenario corpus, and the verified findings (loopback blindness, IP rotation, raw-802.11 copies). |
| `milestone-3-report.md` | M3 — the flow engine (reassembly, stories, DNS attribution, HTTP) and the 14/14 verification matrix vs tshark. |

> **Path note:** file paths inside these documents reflect the repository
> layout *at the time of writing* — notably `src/*.ts` files were flat before
> the layered restructure (`src/engine/`, `src/capture/`, `src/traffic/`,
> `src/verify/`, `src/reporting/`, `src/tap/`). The old→new path map lives in
> [`docs/ARCHITECTURE.md`](../ARCHITECTURE.md). The living status ledger is
> [`docs/project-status.md`](../project-status.md).
