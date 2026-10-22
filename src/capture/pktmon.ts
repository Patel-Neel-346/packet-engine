// Thin process runner for pktmon.exe and other system tools.
//
// Rules enforced here (from the project ground rules):
// - Executables are spawned with an argument ARRAY. We never build a shell
//   command string with user input (`exec` is deliberately not used).
// - Results are returned with exit code + captured stdout/stderr so callers
//   can record real output instead of assuming success.
//
// Layer:     capture — external-process I/O (also used by verify/ and traffic/)
// Milestone: M1 — process helpers (docs/history/milestone-1-report.md)
// Verified:  every capture and verification run records these commands' real output
// Exports:   runCommand, runPktmon, pktmonExe, powershellExe, tsharkExe, CommandResult

import { spawn } from "node:child_process";
import path from "node:path";

export interface CommandResult {
  /** Process exit code (-1 if it died without reporting one). */
  code: number;
  stdout: string;
  stderr: string;
  command: string;
  args: readonly string[];
  timedOut: boolean;
}

function systemRoot(): string {
  return process.env.SystemRoot ?? "C:\\Windows";
}

/** Absolute path to the in-box pktmon.exe under System32. */
export function pktmonExe(): string {
  return path.join(systemRoot(), "System32", "pktmon.exe");
}

/** Absolute path to the in-box Windows PowerShell 5.1 executable. */
export function powershellExe(): string {
  return path.join(
    systemRoot(),
    "System32",
    "WindowsPowerShell",
    "v1.0",
    "powershell.exe",
  );
}

/** Absolute path of the tshark install recorded in Step 0 (Wireshark 4.6.9). */
export function tsharkExe(): string {
  return path.join("C:\\Program Files\\Wireshark", "tshark.exe");
}

/** Spawn a tool with an argv array, capture all output, no shell involved. */
export async function runCommand(
  command: string,
  args: readonly string[],
  opts: { timeoutMs?: number } = {},
): Promise<CommandResult> {
  const { timeoutMs = 120_000 } = opts;
  return new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
      timeout: timeoutMs,
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    child.on("error", (e) =>
      reject(new Error(`failed to spawn ${command}: ${e.message}`)),
    );
    child.on("close", (code, signal) => {
      resolve({
        code: code ?? -1,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
        command,
        args,
        timedOut: code === null && signal !== null,
      });
    });
  });
}

/** Run pktmon.exe with an argv array (see runCommand for the result contract). */
export function runPktmon(
  args: readonly string[],
  opts?: { timeoutMs?: number },
): Promise<CommandResult> {
  return runCommand(pktmonExe(), args, opts);
}
