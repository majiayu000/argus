"use strict";

const fs = require("node:fs");
const path = require("node:path");

const VERSION_RE = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const TARGETS = Object.freeze({
  "linux-x64": "x86_64-unknown-linux-gnu",
  "linux-arm64": "aarch64-unknown-linux-gnu",
  "darwin-x64": "x86_64-apple-darwin",
  "darwin-arm64": "aarch64-apple-darwin",
  "win32-x64": "x86_64-pc-windows-msvc",
});

function parseVersion(value) {
  const match = VERSION_RE.exec(value);
  if (!match) throw new Error("argusVersion must be an exact canonical X.Y.Z version");
  return match.slice(1).map(Number);
}

function inCompatibilityRange(value, config) {
  const [major, minor] = parseVersion(value);
  const lower = parseVersion(config.defaultBinaryVersion);
  if (config.schemaVersion !== 1 || config.compatibilityRange !== `>=${lower.join(".")},<${lower[0]}.${lower[1] + 1}.0`) {
    throw new Error("action release compatibility contract is malformed");
  }
  return major === lower[0] && minor === lower[1];
}

function readInputs(env, config) {
  const scanType = (env.INPUT_SCANTYPE || "").trim();
  const inputPath = (env.INPUT_PATH || "").trim();
  const githubToken = (env.INPUT_GITHUBTOKEN || "").trim();
  const format = (env.INPUT_FORMAT || "text").trim();
  const version = (env.INPUT_ARGUSVERSION || config.defaultBinaryVersion || "").trim();
  const failOn = (env.INPUT_FAILON || "block").trim();
  const base = (env.INPUT_BASE || "").trim();
  const baseLockfileFormat = (env.INPUT_BASELOCKFILEFORMAT || "").trim();
  const maliciousDb = (env.INPUT_MALICIOUSDB || "").trim();
  const approvalLedger = (env.INPUT_APPROVALLEDGER || "").trim();
  if (!["package", "lockfile", "agent"].includes(scanType)) throw new Error("scanType must be package, lockfile, or agent");
  if (!inputPath) throw new Error("path is required");
  if (!githubToken) throw new Error("githubToken is required");
  if (!["text", "json", "sarif"].includes(format)) throw new Error("format must be text, json, or sarif");
  if (!["block", "approval"].includes(failOn)) throw new Error("failOn must be block or approval");
  if (scanType !== "lockfile" && [base, baseLockfileFormat, maliciousDb, approvalLedger].some(Boolean)) throw new Error("lockfile admission inputs require scanType=lockfile");
  if (baseLockfileFormat && !base) throw new Error("baseLockfileFormat requires base");
  if (baseLockfileFormat && !["package-lock", "yarn", "pnpm", "poetry", "uv", "cargo", "go-sum", "bundler", "composer"].includes(baseLockfileFormat)) throw new Error("baseLockfileFormat is unsupported");
  if (!inCompatibilityRange(version, config)) throw new Error(`argusVersion ${version} is outside the tested compatibility range`);
  return { scanType, inputPath, githubToken, format, version, failOn, base, baseLockfileFormat, maliciousDb, approvalLedger };
}

function targetFor(platform = process.platform, arch = process.arch) {
  const target = TARGETS[`${platform}-${arch}`];
  if (!target) throw new Error(`unsupported runner platform: ${platform}-${arch}`);
  return target;
}

function resolveWorkspacePath(workspace, requested, scanType) {
  if (!workspace) throw new Error("GITHUB_WORKSPACE is required");
  const root = fs.realpathSync(workspace);
  const candidate = fs.realpathSync(path.resolve(root, requested));
  const relative = path.relative(root, candidate);
  if (relative === ".." || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
    throw new Error("path resolves outside GITHUB_WORKSPACE");
  }
  const stat = fs.statSync(candidate);
  if (scanType === "package" && !stat.isDirectory()) throw new Error("package path must be a directory");
  if (scanType === "lockfile" && !stat.isFile()) throw new Error("lockfile path must be a regular file");
  return candidate;
}

function validateManifest(value, version, commit) {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("release manifest must be an object");
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["assets", "binaryVersion", "commit", "schemaVersion", "tag"])) throw new Error("release manifest keys do not match schema v1");
  if (value.schemaVersion !== 1 || value.binaryVersion !== version || value.tag !== `v${version}` || value.commit !== commit || !Array.isArray(value.assets)) throw new Error("release manifest identity does not match release");
  const names = new Set();
  const pairs = new Set();
  for (const item of value.assets) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("manifest asset entry must be an object");
    if (JSON.stringify(Object.keys(item).sort()) !== JSON.stringify(["kind", "name", "runner", "sha256", "size", "target"])) throw new Error("manifest asset keys do not match schema v1");
    if (typeof item.name !== "string" || path.basename(item.name) !== item.name || names.has(item.name)) throw new Error("manifest asset name is invalid or duplicated");
    if (item.kind === "documentation") {
      if (!["LICENSE", "README.md"].includes(item.name) || item.target !== null || item.runner !== null) throw new Error("manifest documentation identity is invalid");
    } else {
      const expectedRunners = {
        "x86_64-unknown-linux-gnu": "ubuntu-24.04",
        "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm",
        "x86_64-apple-darwin": "macos-15-intel",
        "aarch64-apple-darwin": "macos-15",
        "x86_64-pc-windows-msvc": "windows-2025",
      };
      const pair = `${item.target}/${item.kind}`;
      if (!Object.values(TARGETS).includes(item.target) || expectedRunners[item.target] !== item.runner || !["binary", "archive"].includes(item.kind) || pairs.has(pair)) throw new Error("manifest target, runner, or kind is invalid or duplicated");
      const windowsSuffix = item.target.endsWith("windows-msvc") ? ".exe" : "";
      const expectedName = item.kind === "binary" ? `argus-v${version}-${item.target}${windowsSuffix}` : `argus-v${version}-${item.target}.${windowsSuffix ? "zip" : "tar.gz"}`;
      if (item.name !== expectedName) throw new Error("manifest asset name differs from target/kind identity");
      pairs.add(pair);
    }
    if (!Number.isSafeInteger(item.size) || item.size < 1 || item.size > 128 * 1024 * 1024 || !SHA256_RE.test(item.sha256)) throw new Error("manifest asset size or digest is invalid");
    names.add(item.name);
  }
  const expectedPairs = new Set(Object.values(TARGETS).flatMap((target) => ["binary", "archive"].map((kind) => `${target}/${kind}`)));
  if (pairs.size !== expectedPairs.size || [...expectedPairs].some((pair) => !pairs.has(pair)) || !names.has("LICENSE") || !names.has("README.md")) throw new Error("manifest asset matrix is incomplete");
  return value;
}

function decisionForExit(code) {
  if (code === 0) return "allow";
  if (code === 1) return "block";
  if (code === 2) return "allow-with-approval";
  throw new Error(`argus returned unsupported exit code ${code}`);
}

function validateReport(format, text, code, version, scanType) {
  const decision = decisionForExit(code);
  if (!text || Buffer.byteLength(text) > 64 * 1024 * 1024) throw new Error("argus report is empty or oversized");
  if (format === "text") {
    const expression = scanType === "lockfile"
      ? /^decision: (allow|block|allow-with-approval)  lockfile: .+\ncoverage: scanned \d+ of \d+ resolved targets \(\d+ skipped, \d+ failed\)\n[\s\S]*$/u
      : /^decision: (allow|block|allow-with-approval)  package: .+\npath: .+\n(?:[\s\S]*\n)?findings:(?: none|\n[\s\S]+)\n$/u;
    const match = expression.exec(text);
    if (!match || match[1] !== decision) throw new Error("text report contract does not match exit code");
  } else if (format === "json") {
    let report;
    try { report = JSON.parse(text); } catch (error) { throw new Error("JSON report is malformed", { cause: error }); }
    if (scanType === "lockfile") {
      const required = ["lockfile", "decision", "targets_total", "scanned", "reports", "skipped", "failed", "comparisons_total", "version_changes", "comparison_failed", "approvals"];
      const keys = report && typeof report === "object" && !Array.isArray(report) ? Object.keys(report) : [];
      if (required.some((key) => !keys.includes(key)) || report.decision !== decision || typeof report.lockfile !== "string" || ![report.targets_total, report.scanned, report.comparisons_total].every(Number.isSafeInteger) || ![report.reports, report.skipped, report.failed, report.version_changes, report.comparison_failed, report.approvals].every(Array.isArray) || report.reports.some((item) => !item || typeof item !== "object" || Array.isArray(item))) throw new Error("lockfile JSON report contract does not match exit code");
      return decision;
    }
    const required = ["artifact", "decision", "findings", "package_name", "package_version", "path"];
    const keys = report && typeof report === "object" && !Array.isArray(report) ? Object.keys(report) : [];
    const optionalObject = (key) => report[key] === undefined || report[key] === null || (typeof report[key] === "object" && !Array.isArray(report[key]));
    if (required.some((key) => !keys.includes(key)) || report.decision !== decision || !Array.isArray(report.findings) || report.findings.some((finding) => !finding || typeof finding !== "object" || Array.isArray(finding)) || typeof report.artifact !== "string" || typeof report.path !== "string" || ![report.package_name, report.package_version].every((value) => value === null || typeof value === "string") || !optionalObject("coordinate") || !optionalObject("intelligence") || !optionalObject("vulnerability")) throw new Error("JSON report contract does not match exit code");
    if ((decision === "allow") !== (report.findings.length === 0)) throw new Error("JSON report findings do not match decision");
  } else {
    let report;
    try { report = JSON.parse(text); } catch (error) { throw new Error("SARIF report is malformed", { cause: error }); }
    const runs = report?.version === "2.1.0" && Array.isArray(report.runs) ? report.runs : null;
    if (!runs || runs.some((run) => run.tool?.driver?.name !== "argus" || run.tool.driver.version !== version || run.invocations?.[0]?.executionSuccessful !== true || !Array.isArray(run.results))) throw new Error("SARIF report contract is incomplete");
    if (scanType === "lockfile") {
      const valid = new Set(["allow", "block", "allow-with-approval"]);
      if (runs.some((run) => run.results.some((result) => !valid.has(result?.properties?.decision)))) throw new Error("lockfile SARIF result decision is invalid");
    } else {
      if (runs.length !== 1) throw new Error("SARIF report contract is incomplete");
      const run = runs[0];
      if (decision === "allow" && run.results.length !== 0) throw new Error("clean SARIF contains findings");
      if (decision !== "allow" && run.results.length === 0) throw new Error("non-clean SARIF contains no findings");
      if (run.results.some((result) => result?.properties?.decision !== decision)) throw new Error("SARIF result decision does not match exit code");
    }
  }
  return decision;
}

function shouldFail(decision, failOn) {
  return decision === "block" || (decision === "allow-with-approval" && failOn === "approval");
}

module.exports = { TARGETS, decisionForExit, readInputs, resolveWorkspacePath, shouldFail, targetFor, validateManifest, validateReport };
