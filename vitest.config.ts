// Vitest configuration. Kept explicit-import style (no `globals: true`) so
// `tsc --noEmit` needs no extra type packages — `import { describe, it, expect }
// from "vitest"` gives full types in editors and typecheck alike.
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    // The loopback-tap tests spin up REAL in-process sockets; give them room.
    testTimeout: 15000,
    // Fail (loudly) if a test file leaves sockets/handles open.
    pool: "forks",
  },
});
