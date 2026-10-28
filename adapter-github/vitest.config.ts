import { defineConfig } from 'vitest/config';

// Coverage is measured on src/ and written as lcov, the same shape core's Python coverage takes.
// The thresholds are the il6 profile's bar for changed lines (docs/PRD.md § Compliance profiles),
// applied to the whole package because every line of it is new.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      include: ['src/**/*.ts'],
      reporter: ['text', 'lcov'],
      reportsDirectory: 'coverage',
      thresholds: { lines: 90, functions: 90, branches: 80, statements: 90 },
    },
  },
});
