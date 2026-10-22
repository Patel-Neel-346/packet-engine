// Shared filesystem locations for generated artifacts and reports.
// Single source of truth so capture runners, the CLI, and the verification
// gates never disagree about where outputs land. All consumers run from the
// repository root (npm scripts guarantee this).
//
// Layer:     shared constants (single source of truth for artifact locations)
// Milestone: repo restructure — replaced per-file duplicated path constants
// Verified:  every gate consumes these paths (`npm run test:all` 8/8)
// Exports:   OUT_DIR, SCEN_DIR, RESULTS_DIR

import path from "node:path";

/** Root for all generated artifacts (gitignored). */
export const OUT_DIR = path.resolve("out");

/** M2/M3 scenario traces and per-scenario artifacts (out/scen). */
export const SCEN_DIR = path.join(OUT_DIR, "scen");

/** Written verification reports (test-results). */
export const RESULTS_DIR = path.resolve("test-results");
