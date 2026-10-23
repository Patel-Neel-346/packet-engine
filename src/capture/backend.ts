// CaptureBackend interface — the seam that hides pktmon behind an
// abstraction so Npcap (or another backend) can be added later without
// touching the decoder or flow tracking.
//
// Layer:     capture — interface layer (types + signal-path contract; no I/O)
// Milestone: M2 — backend seam (docs/history/milestone-2-report.md)
// Verified:  implemented by PktmonBackend (produced the whole 14-trace corpus)
// Exports:   CaptureBackend, CapturePlan, CaptureFilterSpec, ComponentSelection, ScenarioBundle, signalPaths

export interface CaptureFilterSpec {
  /** Filter name (positional). */
  name: string;
  /** Remaining pktmon filter add args, e.g. ["-i","1.2.3.4","-t","TCP","-p","443"]. */
  args: string[];
}

export type ComponentSelection = { kind: "ids"; ids: number[] } | { kind: "all" };

export interface CapturePlan {
  id: string;
  comps: ComponentSelection;
  filters: CaptureFilterSpec[];
  maxFileMB?: number;
  /** How long the capture runs at most if the traffic signal never arrives. */
  trafficTimeoutSec?: number;
  /**
   * Component IDs to convert into per-component pcapngs after the capture
   * (defaults to comps.ids when comps is {ids}; required when comps is
   * {all} so loopback-visibility can still be measured per component).
   */
  convertIds?: number[];
}

export interface ScenarioBundle {
  bundleId: string;
  plans: CapturePlan[];
}

export interface CaptureBundleResult {
  exitCode: number | null;
  logFile: string | null;
  logContent: string;
}

export interface CaptureBackend {
  readonly id: string;
  /** Report whether capture is possible from the current process. */
  checkAvailableNonElevated(): Promise<{ ok: boolean; detail: string }>;
  /** Runs a whole bundle of captures (one UAC prompt for the bundle). */
  runBundle(bundle: ScenarioBundle): Promise<CaptureBundleResult>;
}

/** File naming contract used by signal handshakes (documented for tests). */
export function signalPaths(
  outDir: string,
  planId: string,
): {
  started: string;
  trafficDone: string;
  done: string;
} {
  return {
    started: path.join(outDir, `${planId}.capturestarted`),
    trafficDone: path.join(outDir, `${planId}.trafficdone`),
    done: path.join(outDir, `${planId}.capturedone`),
  };
}

import path from "node:path";
