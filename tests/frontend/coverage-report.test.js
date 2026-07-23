import { describe, expect, test } from "vitest";
import {
  buildCoverageSummary,
  findCoverageFloorFailures,
  renderCoverageMarkdown,
} from "../../scripts/report-coverage.mjs";

const llvmMetric = (count, covered) => ({ count, covered, percent: 0 });
const llvmSummary = (count, covered) => ({
  functions: llvmMetric(count, covered),
  lines: llvmMetric(count, covered),
  regions: llvmMetric(count, covered),
});
const llvmFile = (filename, count, covered) => ({
  filename,
  summary: llvmSummary(count, covered),
});

const rustCoverage = {
  data: [{
    files: [
      llvmFile("/repo/src/auth/mod.rs", 10, 9),
      llvmFile("/repo/src/auth/acl.rs", 2, 1),
      llvmFile("/repo/src/auth/basic.rs", 2, 1),
      llvmFile("/repo/src/auth/digest.rs", 2, 1),
      llvmFile("/repo/src/auth/rate_limit.rs", 2, 1),
      llvmFile("/repo/src/auth/token.rs", 2, 1),
      llvmFile("/repo/src/auth/test_suite/mod.rs", 10, 10),
      llvmFile("/repo/src/server/filesystem/mod.rs", 18, 10),
      llvmFile("/repo/src/server/filesystem/stale_upload_cleanup_tests.rs", 4, 3),
      llvmFile("/repo/src/server/filesystem/mutation_transaction_tests.rs", 4, 2),
      llvmFile("/repo/src/server/filesystem/root_identity_tests.rs", 2, 2),
      llvmFile("/repo/src/server/filesystem/blocking_admission_tests.rs", 2, 1),
      llvmFile("/repo/src/identity/path.rs", 10, 8),
      llvmFile("/repo/src/identity/source.rs", 10, 10),
      llvmFile("/repo/src/server/write/mod.rs", 15, 12),
      llvmFile("/repo/src/server/write/storage_tests.rs", 5, 4),
      llvmFile("/repo/src/server/preconditions.rs", 10, 9),
      llvmFile("/repo/src/server/webdav/mod.rs", 8, 6),
      llvmFile("/repo/src/server/webdav/tests.rs", 2, 2),
      llvmFile("/repo/src/server/range.rs", 10, 9),
      llvmFile("/repo/src/utils/mod.rs", 10, 7),
    ],
    totals: llvmSummary(130, 104),
  }],
};

const frontendCoverage = {
  total: {
    branches: { total: 20, covered: 10, pct: 50 },
    functions: { total: 10, covered: 8, pct: 80 },
    lines: { total: 100, covered: 75, pct: 75 },
    statements: { total: 100, covered: 75, pct: 75 },
  },
};

describe("coverage trend report", () => {
  test("weights security groups by covered and total counts", () => {
    const summary = buildCoverageSummary(rustCoverage, frontendCoverage);

    expect(summary.rust.total.lines.percent).toBe(80);
    expect(summary.rust.groups.filesystem.lines).toEqual({
      covered: 36,
      percent: 72,
      total: 50,
    });
    expect(summary.rust.groups.auth.lines.percent).toBe(80);
    expect(summary.rust.groups["write-preconditions"].lines.percent).toBe(83.33);
    expect(summary.frontend.total.branches.percent).toBe(50);
  });

  test("reports trends without enforcing aspirational targets", () => {
    const summary = buildCoverageSummary(rustCoverage, frontendCoverage);
    const policy = {
      schema: 1,
      mode: "trend",
      baseline: summary,
      floors: null,
      targets: {
        rust: {
          total: { lines: 90 },
          groups: {},
        },
        frontend: { total: {} },
      },
    };

    expect(findCoverageFloorFailures(summary, policy)).toEqual([]);
    expect(renderCoverageMarkdown(summary, policy)).toContain("Policy mode: **trend**");
    expect(renderCoverageMarkdown(summary, policy)).toContain("0.00pp");
  });

  test("fails only configured floors in enforcement mode", () => {
    const summary = buildCoverageSummary(rustCoverage, frontendCoverage);
    const policy = {
      schema: 1,
      mode: "enforce",
      baseline: summary,
      targets: {},
      floors: {
        rust: { total: { lines: 81 } },
      },
    };

    expect(findCoverageFloorFailures(summary, policy)).toEqual([
      "Rust total lines is 80.00%, below 81.00%",
    ]);
  });
});
