import { defineConfig } from "vitest/config";

// Coverage is measured on cli/src and the bin stub (the adapters' files it imports are measured by
// their own suites) and written as lcov. tests/bin.test.ts imports the stub in-process so its lines
// are counted; main.test.ts's spawned run of it is a real process coverage cannot see. The
// thresholds are the il6 profile's bar for changed lines (docs/PRD.md § Compliance profiles),
// applied to the whole package because every line of it is new.
export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    testTimeout: 30000,
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts", "bin/*.js"],
      reporter: ["text", "lcov"],
      reportsDirectory: "coverage",
      thresholds: { lines: 90, functions: 90, branches: 80, statements: 90 },
    },
  },
});
