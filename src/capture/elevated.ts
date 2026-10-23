// Elevated execution helper.
//
// pktmon captures require Administrator (verified in Step 0: non-admin
// `pktmon start` fails with exit code 5, "Failed to communicate with the
// PktMon driver: Access is denied."). To keep UAC prompts to one per capture
// run, every elevated pktmon step is bundled into a single generated .ps1
// script that is launched with Start-Process -Verb RunAs -Wait.
//
// The elevated script writes:
//   <ps1>.log        every step marker + captured output (Add-Content)
//   <ps1>.exitcode   the script's own final exit code
// The non-elevated Node process reads both back.
//
// Layer:     capture — elevated (UAC) process I/O
// Milestone: M1 — one-UAC-prompt runner (docs/history/milestone-1-report.md)
// Verified:  used by every real capture run (M1 + both M2 batches); logs recorded in the milestone reports
// Exports:   runElevatedScript, ElevatedResult

import { spawn } from "node:child_process";
import fs from "node:fs";
import type { ChildProcess } from "node:child_process";
import { powershellExe } from "./pktmon.ts";

export interface ElevatedResult {
  /** Exit code of the elevated script itself (null if we couldn't get one). */
  exitCode: number | null;
  outerStdout: string;
  outerStderr: string;
  logFile: string | null;
  logContent: string;
  exitCodeFile: string | null;
  recordedExitCode: number | null;
}

function assertSafePath(p: string): void {
  if (p.includes(" ") || p.includes("'") || p.includes('"')) {
    throw new Error(`elevated runner: path has spaces/quotes, unsupported in this prototype: ${p}`);
  }
}

/**
 * Build the PowerShell wrapper command for one UAC prompt.
 * -FilePath powershell (child) runs the script; -PassThru gives us its
 *   process object so the wrapper can exit with the child's exit code.
 * This uses Start-Process -Verb RunAs, which triggers the UAC prompt.
 * Verified behavior of Start-Process: -Wait, -PassThru, -Verb RunAs are
 * documented PowerShell parameters (PowerShell 5.1 docs, Start-Process cmdlet).
 */
function wrapperCommand(scriptPath: string): string {
  assertSafePath(scriptPath);
  return [
    "$ErrorActionPreference = 'Stop'",
    "$sp = Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','" +
      scriptPath +
      "' -Verb RunAs -Wait -PassThru",
    "exit $sp.ExitCode",
  ].join("; ");
}

/** Launch one generated .ps1 elevated (Start-Process -Verb RunAs — a single
 * UAC prompt) and read back its .log and .exitcode sidecar files. */
export async function runElevatedScript(ps1: string): Promise<ElevatedResult> {
  for (const p of [ps1]) assertSafePath(p);
  const logFile = ps1.replace(/\.ps1$/, ".log");
  const exitCodeFile = ps1.replace(/\.ps1$/, ".exitcode");
  fs.rmSync(logFile, { force: true });
  fs.rmSync(exitCodeFile, { force: true });

  const outer = await new Promise<{
    code: number | null;
    stdout: string;
    stderr: string;
  }>((resolve, reject) => {
    const child: ChildProcess = spawn(
      powershellExe(),
      ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", wrapperCommand(ps1)],
      { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
    );
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout!.on("data", (c: Buffer) => out.push(c));
    child.stderr!.on("data", (c: Buffer) => err.push(c));
    child.on("error", (e) => reject(new Error(`failed to spawn elevated wrapper: ${e.message}`)));
    child.on("close", (code) => {
      resolve({
        code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });

  const logContent = fs.existsSync(logFile) ? fs.readFileSync(logFile, "utf8") : "";
  let recordedExitCode: number | null = null;
  if (fs.existsSync(exitCodeFile)) {
    const raw = fs.readFileSync(exitCodeFile, "utf8").trim();
    const n = Number.parseInt(raw, 10);
    if (Number.isFinite(n)) recordedExitCode = n;
  }

  return {
    exitCode: outer.code,
    outerStdout: outer.stdout,
    outerStderr: outer.stderr,
    logFile: fs.existsSync(logFile) ? logFile : null,
    logContent,
    exitCodeFile: fs.existsSync(exitCodeFile) ? exitCodeFile : null,
    recordedExitCode,
  };
}
