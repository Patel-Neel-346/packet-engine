/**
 * Jest configuration for strobe-packet-tracker.
 *
 * The codebase is ESM ("type": "module") with explicit `.ts` import
 * extensions (Node 24 type-stripping style) and erasableSyntaxOnly. Jest runs
 * tests in CommonJS, so ts-jest transpiles each file to CJS in isolation:
 *   - `isolatedModules: true`  → transpile-only (no cross-file type checking;
 *     type safety stays the job of `npm run typecheck` = tsc --noEmit)
 *   - inline tsconfig override → module:"commonjs" so import statements are
 *     lowered to require() (the project tsconfig's NodeNext setting stays
 *     untouched for typecheck)
 *   - moduleNameMapper strips the `.ts` extensions at require() time so the
 *     `.ts`-extension specifiers resolve after transformation.
 * Fixtures stay inline per DEVELOPMENT.md §4/§6 (byte layouts in test files).
 */
/** @type {import('jest').Config} */
module.exports = {
  testEnvironment: "node",
  verbose: true,
  testMatch: ["<rootDir>/test/**/*.test.ts"],
  transform: {
    "^.+\\.ts$": [
      "ts-jest",
      {
        tsconfig: {
          target: "es2023",
          module: "commonjs",
          esModuleInterop: true,
          verbatimModuleSyntax: false,
          erasableSyntaxOnly: true,
          isolatedModules: true,
          strict: true,
          skipLibCheck: true,
          types: ["node"],
        },
      },
    ],
  },
  moduleNameMapper: {
    "^(\\.{1,2}/.*)\\.ts$": "$1",
  },
  // Jest 30: child_process workers instead of worker threads — same behavior
  // as Vitest's "forks" pool, keeps the loopback socket teardown clean.
  workerThreads: false,
  // The loopback-tap suites spin up REAL in-process sockets.
  testTimeout: 15000,
};
