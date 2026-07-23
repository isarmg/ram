import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RUST_METRICS = ["lines", "functions", "regions"];
const FRONTEND_METRICS = ["lines", "functions", "branches", "statements"];

const RUST_GROUPS = {
  auth: [
    "src/auth/mod.rs",
    "src/auth/acl.rs",
    "src/auth/basic.rs",
    "src/auth/digest.rs",
    "src/auth/rate_limit.rs",
    "src/auth/token.rs",
    // 中文：审阅基线生成时这段代码位于 auth/mod.rs；机械拆分模块后仍放在同一趋势组，
    // 防止文件移动伪装成覆盖率回退或提升。
    // English: This code lived in auth/mod.rs at baseline capture. Keep it in
    // the same trend group so a mechanical move cannot mimic a coverage change.
    "src/auth/test_suite/mod.rs",
  ],
  filesystem: [
    "src/server/filesystem/mod.rs",
    "src/server/filesystem/stale_upload_cleanup_tests.rs",
    "src/server/filesystem/mutation_transaction_tests.rs",
    "src/server/filesystem/root_identity_tests.rs",
    "src/server/filesystem/blocking_admission_tests.rs",
    "src/identity/path.rs",
    "src/identity/source.rs",
  ],
  "write-preconditions": [
    "src/server/write/mod.rs",
    "src/server/write/storage_tests.rs",
    "src/server/preconditions.rs",
  ],
  webdav: ["src/server/webdav/mod.rs", "src/server/webdav/tests.rs"],
  range: ["src/server/range.rs", "src/utils/mod.rs"],
};

function requireObject(value, label) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} must be an object`);
  }
  return value;
}

function requireFiniteNonNegative(value, label) {
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new TypeError(`${label} must be a finite non-negative number`);
  }
  return value;
}

function roundPercent(value) {
  return Math.round((value + Number.EPSILON) * 100) / 100;
}

function metricFromCounts(totalValue, coveredValue, label) {
  const total = requireFiniteNonNegative(totalValue, `${label}.total`);
  const covered = requireFiniteNonNegative(coveredValue, `${label}.covered`);
  if (covered > total) {
    throw new RangeError(`${label}.covered cannot exceed ${label}.total`);
  }
  const percent = total === 0 ? 100 : roundPercent(covered * 100 / total);
  return { total, covered, percent };
}

function llvmMetric(value, label) {
  const metric = requireObject(value, label);
  return metricFromCounts(metric.count, metric.covered, label);
}

function istanbulMetric(value, label) {
  const metric = requireObject(value, label);
  return metricFromCounts(metric.total, metric.covered, label);
}

function normalizeSourcePath(filename) {
  if (typeof filename !== "string" || filename.length === 0) {
    throw new TypeError("LLVM coverage filename must be a non-empty string");
  }
  const normalized = filename.replaceAll("\\", "/");
  const sourceMarker = "/src/";
  const sourceIndex = normalized.lastIndexOf(sourceMarker);
  if (sourceIndex !== -1) return normalized.slice(sourceIndex + 1);
  return normalized.replace(/^\.\//, "").replace(/^\//, "");
}

function normalizeMetricSet(summary, names, parser, label) {
  const value = requireObject(summary, label);
  return Object.fromEntries(names.map(name => [
    name,
    parser(value[name], `${label}.${name}`),
  ]));
}

function aggregateMetricSets(metricSets, names, label) {
  if (metricSets.length === 0) throw new Error(`${label} has no source files`);
  return Object.fromEntries(names.map(name => {
    const counts = metricSets.reduce(
      (current, metrics) => ({
        total: current.total + metrics[name].total,
        covered: current.covered + metrics[name].covered,
      }),
      { total: 0, covered: 0 },
    );
    return [name, metricFromCounts(counts.total, counts.covered, `${label}.${name}`)];
  }));
}

/**
 * 把 cargo-llvm-cov 与 Vitest 摘要规范化为稳定仓库模式；模块组百分比按覆盖/总数
 * 汇总计算，而不平均各文件百分比。
 *
 * Normalize cargo-llvm-cov and Vitest summaries into a stable repository
 * schema. Group percentages use covered/count totals, not per-file averages.
 */
export function buildCoverageSummary(rustInput, frontendInput) {
  const rust = requireObject(rustInput, "Rust coverage");
  if (!Array.isArray(rust.data) || rust.data.length !== 1) {
    throw new Error("Rust coverage must contain exactly one LLVM export data set");
  }
  const llvmData = requireObject(rust.data[0], "Rust coverage data set");
  if (!Array.isArray(llvmData.files)) {
    throw new TypeError("Rust coverage data set files must be an array");
  }

  const files = new Map();
  for (const [index, rawFile] of llvmData.files.entries()) {
    const file = requireObject(rawFile, `Rust coverage file ${index}`);
    const filename = normalizeSourcePath(file.filename);
    if (files.has(filename)) {
      throw new Error(`Rust coverage contains duplicate source file ${filename}`);
    }
    files.set(filename, normalizeMetricSet(
      file.summary,
      RUST_METRICS,
      llvmMetric,
      `Rust coverage file ${filename}`,
    ));
  }

  const groups = Object.fromEntries(Object.entries(RUST_GROUPS).map(([name, paths]) => {
    const metricSets = paths.map(path => {
      const metrics = files.get(path);
      if (!metrics) throw new Error(`Rust coverage is missing required source file ${path}`);
      return metrics;
    });
    return [name, aggregateMetricSets(metricSets, RUST_METRICS, `Rust group ${name}`)];
  }));

  const frontend = requireObject(frontendInput, "Frontend coverage");
  return {
    schema: 1,
    rust: {
      total: normalizeMetricSet(
        requireObject(llvmData.totals, "Rust coverage totals"),
        RUST_METRICS,
        llvmMetric,
        "Rust total",
      ),
      groups,
    },
    frontend: {
      total: normalizeMetricSet(
        frontend.total,
        FRONTEND_METRICS,
        istanbulMetric,
        "Frontend total",
      ),
    },
  };
}

function nestedValue(value, path) {
  let current = value;
  for (const part of path) {
    if (current === null || typeof current !== "object") return undefined;
    current = current[part];
  }
  return current;
}

function coverageRows(summary, policy) {
  const specifications = [
    ...RUST_METRICS.map(metric => ({
      label: "Rust total",
      metric,
      path: ["rust", "total", metric],
    })),
    ...Object.keys(RUST_GROUPS).map(group => ({
      label: `Rust ${group}`,
      metric: "lines",
      path: ["rust", "groups", group, "lines"],
    })),
    ...FRONTEND_METRICS.map(metric => ({
      label: "Frontend total",
      metric,
      path: ["frontend", "total", metric],
    })),
  ];

  return specifications.map(specification => {
    const current = nestedValue(summary, specification.path);
    if (!current) throw new Error(`Coverage summary is missing ${specification.path.join(".")}`);
    const baseline = nestedValue(policy.baseline, specification.path);
    const target = nestedValue(policy.targets, specification.path);
    const floor = nestedValue(policy.floors, specification.path);
    for (const [name, value] of [["target", target], ["floor", floor]]) {
      if (value !== undefined && value !== null) {
        requireFiniteNonNegative(value, `${specification.path.join(".")} ${name}`);
        if (value > 100) throw new RangeError(`${name} coverage cannot exceed 100`);
      }
    }
    return { ...specification, current, baseline, target, floor };
  });
}

function displayMetric(metric) {
  return `${metric.percent.toFixed(2)}% (${metric.covered}/${metric.total})`;
}

function displayDelta(current, baseline) {
  if (!baseline || typeof baseline.percent !== "number") return "—";
  const delta = roundPercent(current.percent - baseline.percent);
  return `${delta > 0 ? "+" : ""}${delta.toFixed(2)}pp`;
}

function displayThreshold(value) {
  return typeof value === "number" ? `${value.toFixed(2)}%` : "—";
}

/** 渲染当前趋势、目标与未来强制下限。 / Render the current trend, goals, and future enforced floors. */
export function renderCoverageMarkdown(summary, policyInput) {
  const policy = requireObject(policyInput, "Coverage policy");
  if (policy.schema !== 1) throw new Error("Coverage policy schema must be 1");
  if (policy.mode !== "trend" && policy.mode !== "enforce") {
    throw new Error("Coverage policy mode must be trend or enforce");
  }
  const rows = coverageRows(summary, policy);
  const lines = [
    "## Coverage trend",
    "",
    `Policy mode: **${policy.mode}**. ${policy.mode === "trend"
      ? "Percentages are reported but do not fail the build."
      : "Configured coverage floors are enforced."}`,
    "",
    "| Scope | Metric | Current | Baseline delta | Target | Floor |",
    "|---|---:|---:|---:|---:|---:|",
  ];
  for (const row of rows) {
    lines.push(`| ${row.label} | ${row.metric} | ${displayMetric(row.current)} | ${displayDelta(row.current, row.baseline)} | ${displayThreshold(row.target)} | ${displayThreshold(row.floor)} |`);
  }
  lines.push("");
  return `${lines.join("\n")}\n`;
}

/** 返回可读的下限失败；趋势模式始终为空。 / Return readable floor failures; trend mode always returns an empty list. */
export function findCoverageFloorFailures(summary, policyInput) {
  const policy = requireObject(policyInput, "Coverage policy");
  if (policy.mode !== "enforce") return [];
  return coverageRows(summary, policy)
    .filter(row => typeof row.floor === "number" && row.current.percent < row.floor)
    .map(row => `${row.label} ${row.metric} is ${row.current.percent.toFixed(2)}%, below ${row.floor.toFixed(2)}%`);
}

function parseArguments(argv) {
  const options = {
    rust: "coverage/rust-summary.json",
    frontend: "coverage/frontend/coverage-summary.json",
    policy: "tests/coverage/policy.json",
    output: "coverage/summary.json",
    updateBaseline: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (argument === "--update-baseline") {
      options.updateBaseline = true;
      continue;
    }
    const key = argument.startsWith("--") ? argument.slice(2) : "";
    if (!["rust", "frontend", "policy", "output"].includes(key)) {
      throw new Error(`Unknown coverage report argument: ${argument}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`Coverage report argument ${argument} requires a path`);
    }
    options[key] = value;
    index += 1;
  }
  return options;
}

async function readJson(path, label) {
  let value;
  try {
    value = JSON.parse(await readFile(path, "utf8"));
  } catch (error) {
    throw new Error(`Unable to read ${label} from ${path}`, { cause: error });
  }
  return value;
}

async function writeJson(path, value) {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const rustPath = resolve(options.rust);
  const frontendPath = resolve(options.frontend);
  const policyPath = resolve(options.policy);
  const outputPath = resolve(options.output);
  const [rust, frontend, policyInput] = await Promise.all([
    readJson(rustPath, "Rust coverage"),
    readJson(frontendPath, "frontend coverage"),
    readJson(policyPath, "coverage policy"),
  ]);
  const policy = requireObject(policyInput, "Coverage policy");
  const summary = buildCoverageSummary(rust, frontend);

  if (options.updateBaseline) {
    if (process.env.CI) throw new Error("Coverage baseline cannot be updated in CI");
    policy.baseline = summary;
    await writeJson(policyPath, policy);
  }

  const markdown = renderCoverageMarkdown(summary, policy);
  await writeJson(outputPath, summary);
  process.stdout.write(markdown);
  if (process.env.GITHUB_STEP_SUMMARY) {
    await appendFile(process.env.GITHUB_STEP_SUMMARY, markdown, "utf8");
  }

  const failures = findCoverageFloorFailures(summary, policy);
  if (failures.length > 0) {
    throw new Error(`Coverage floors failed:\n${failures.join("\n")}`);
  }
}

const entrypoint = process.argv[1]
  ? pathToFileURL(resolve(process.argv[1])).href
  : "";
if (import.meta.url === entrypoint) {
  main().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
