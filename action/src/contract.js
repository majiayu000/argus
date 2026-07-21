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
  const format = (env.INPUT_FORMAT || "text").trim();
  const version = (env.INPUT_ARGUSVERSION || config.defaultBinaryVersion || "").trim();
  const failOn = (env.INPUT_FAILON || "block").trim();
  if (!["package", "lockfile", "agent"].includes(scanType)) throw new Error("scanType must be package, lockfile, or agent");
  if (!inputPath) throw new Error("path is required");
  if (!["text", "json", "sarif"].includes(format)) throw new Error("format must be text, json, or sarif");
  if (!["block", "approval"].includes(failOn)) throw new Error("failOn must be block or approval");
  if (!inCompatibilityRange(version, config)) throw new Error(`argusVersion ${version} is outside the tested compatibility range`);
  return { scanType, inputPath, format, version, failOn };
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
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(["assets", "commit", "schemaVersion", "version"])) throw new Error("release manifest keys do not match schema v1");
  if (value.schemaVersion !== 1 || value.version !== version || value.commit !== commit || !Array.isArray(value.assets)) throw new Error("release manifest identity does not match release");
  const names = new Set();
  for (const item of value.assets) {
    if (!item || typeof item !== "object" || Array.isArray(item)) throw new Error("manifest asset entry must be an object");
    if (JSON.stringify(Object.keys(item).sort()) !== JSON.stringify(["kind", "name", "sha256", "size", "target"])) throw new Error("manifest asset keys do not match schema v1");
    if (typeof item.name !== "string" || path.basename(item.name) !== item.name || names.has(item.name)) throw new Error("manifest asset name is invalid or duplicated");
    if (!Object.values(TARGETS).includes(item.target) || !["binary", "archive"].includes(item.kind)) throw new Error("manifest target or kind is invalid");
    if (!Number.isSafeInteger(item.size) || item.size < 1 || item.size > 128 * 1024 * 1024 || !SHA256_RE.test(item.sha256)) throw new Error("manifest asset size or digest is invalid");
    names.add(item.name);
  }
  return value;
}

function decisionForExit(code) {
  if (code === 0) return "allow";
  if (code === 1) return "block";
  if (code === 2) return "allow-with-approval";
  throw new Error(`argus returned unsupported exit code ${code}`);
}

function validateReport(format, text, code, version) {
  const decision = decisionForExit(code);
  if (!text || Buffer.byteLength(text) > 64 * 1024 * 1024) throw new Error("argus report is empty or oversized");
  if (format === "text") {
    const match = /^decision: (allow|block|allow-with-approval)\s+/u.exec(text);
    if (!match || match[1] !== decision) throw new Error("text report decision does not match exit code");
  } else if (format === "json") {
    let report;
    try { report = JSON.parse(text); } catch (error) { throw new Error("JSON report is malformed", { cause: error }); }
    if (!report || typeof report !== "object" || report.decision !== decision || !Array.isArray(report.findings)) throw new Error("JSON report contract does not match exit code");
  } else {
    let report;
    try { report = JSON.parse(text); } catch (error) { throw new Error("SARIF report is malformed", { cause: error }); }
    const run = report?.version === "2.1.0" && Array.isArray(report.runs) && report.runs.length === 1 ? report.runs[0] : null;
    if (!run || run.tool?.driver?.name !== "argus" || run.tool.driver.version !== version || run.invocations?.[0]?.executionSuccessful !== true || !Array.isArray(run.results)) throw new Error("SARIF report contract is incomplete");
    if (decision === "allow" && run.results.length !== 0) throw new Error("clean SARIF contains findings");
    if (decision !== "allow" && run.results.length === 0) throw new Error("non-clean SARIF contains no findings");
  }
  return decision;
}

function shouldFail(decision, failOn) {
  return decision === "block" || (decision === "allow-with-approval" && failOn === "approval");
}

module.exports = { TARGETS, decisionForExit, readInputs, resolveWorkspacePath, shouldFail, targetFor, validateManifest, validateReport };
