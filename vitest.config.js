import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      enabled: false,
      include: ["web/**/*.js"],
      provider: "v8",
      reporter: ["text-summary", "json-summary", "lcov"],
      reportOnFailure: true,
      reportsDirectory: "coverage/frontend",
    },
    environment: "node",
    include: ["tests/frontend/**/*.test.js"],
  },
});
