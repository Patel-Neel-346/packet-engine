# Step 0 — Environment check (recorded before any code was written)

All results below were **actually run on this machine** on 2026-10-21.

## Machine

| Item           | Value                                                                                                                  |
| -------------- | ---------------------------------------------------------------------------------------------------------------------- |
| OS             | Microsoft Windows 11 Home Single Language, **build 10.0.26200** (`Get-ComputerInfo`)                                   |
| CPU            | 11th Gen Intel(R) Core(TM) i5-11400H @ 2.70GHz                                                                         |
| Admin status   | **Not elevated** — `whoami` = `msi\neelp`                                                                              |
| Active adapter | **Wi-Fi** — Intel(R) Wi-Fi 6 AX201 160MHz, ifIndex 8 (Up); Ethernet (ifIndex 6) and Bluetooth (ifIndex 4) disconnected |
| WinHTTP proxy  | "Direct access (no proxy server)" (`netsh winhttp show proxy`); no HTTP(S)_PROXY env vars                              |

## Toolchain

| Tool               | Version (verified by running)                                           |
| ------------------ | ----------------------------------------------------------------------- |
| Node.js            | **v24.12.0**, npm 11.6.2                                                |
| Go                 | **1.26.5 windows/amd64**                                                |
| tshark             | **TShark (Wireshark) 4.6.9** at `C:\Program Files\Wireshark\tshark.exe` |
| dumpcap / capinfos | present in the same Wireshark install                                   |
| curl               | in-box `C:\Windows\System32\curl.exe`                                   |
| pktmon             | in-box `C:\Windows\System32\pktmon.exe`                                 |

## pktmon surface (as printed by `pktmon help`, plus sub-command help)

Commands: `filter` (`add`/`list`/`remove`), `list`, `start`, `stop`, `status`,
`unload`, `counters`, `reset`, `etl2txt`, `etl2pcap`, `hex2pkt`.

Notes verified on this machine:

- `pktmon --help` is **not** valid on this build; correct form is `pktmon help`
  (first attempt failed: "Unknown command '--help'").
- Non-elevated `pktmon list` / `pktmon status` / `pktmon start --capture`: **
  exit code 5**, message `Failed to communicate with the PktMon driver: Access is denied.`
  → **capture is Administrator-only**, confirmed in both Step 0 and by the
  `m1-capture` precheck.
- `pktmon start ... --log-mode real-time` exists in the built-in help
  ("Display events and packets on screen at real time. No log file is created").
  It is the candidate for a genuine live stream; still unverified — milestone 4/5.
- `pktmon etl2pcap <file> [--out <name>] [--drop-only] [--component-id <id>]`
  converts ETL to pcapng; `--component-id` splits a multi-component capture
  per capture point (used in milestone 1).
- Microsoft Learn confirms (Packet Monitor (Pktmon) overview page, in-box tool,
  available since build 19041): cross-component capture, drop reporting,
  filtering, real-time/multi-file/circular/memory modes, PCAPNG export.

## Component inventory (from `pktmon list --json`, elevated, saved to `out/components.json`)

Wi-Fi AX201 group (Miniport Id 13, **NdisMedium=Wi-Fi**) contains Ethernet-medium
components we can capture from instead of the raw NIC:

| Component                             | Id  | Medium / role                   |
| ------------------------------------- | --- | ------------------------------- |
| WFP 802.3 Filter (wfplwfs.sys)        | 33  | filter — Ethernet               |
| Native WiFi Filter Driver (nwifi.sys) | 36  | filter — Ethernet               |
| Npcap Packet Driver (npcap.sys)       | 35  | filter — NOT used (ground rule) |
| TCPIP6 protocol (tcpip.sys)           | 74  | protocol — IPv6                 |
| TCPIP protocol (tcpip.sys)            | 75  | protocol — IPv4                 |

Empirically in milestone 1: miniport/13 gives raw 802.11 frames; 36 gives a mix
of full-Ethernet + raw-802.11; 74/75 give bare IP packets without L2 header;
33 records nothing on the active path. Details in `milestone-1-report.md`.
