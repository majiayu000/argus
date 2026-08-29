"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { readInputs, resolveWorkspacePath, shouldFail, targetFor, validateManifest, validateReport } = require("./contract");
const { materializeRelease } = require("./download");
const { runBounded } = require("./run");
const releaseConfig = require("../release.json");

function appendOutput(name, value, env = process.env) {
  if (!env.GITHUB_OUTPUT) return;
  fs.appendFileSync(env.GITHUB_OUTPUT, `${name}=${value}\n`, { encoding: "utf8" });
}

function writeOutputs(values, env = process.env) {
  for (const name of ["decision", "exitCode", "reportPath", "sarifFile", "argusVersion"]) appendOutput(name, values[name] || "", env);
}

async function main(env = process.env, dependencies = {}) {
  const materialize = dependencies.materializeRelease || materializeRelease;
  const run = dependencies.runBounded || runBounded;
  const selectTarget = dependencies.targetFor || targetFor;
  const outputs = { decision: "", exitCode: "", reportPath: "", sarifFile: "", argusVersion: "" };
  let tempDir;
  let outputsWritten = false;
  try {
    const inputs = readInputs(env, releaseConfig);
    outputs.argusVersion = inputs.version;
    const scanPath = resolveWorkspacePath(env.GITHUB_WORKSPACE, inputs.inputPath, inputs.scanType);
    const basePath = inputs.base ? resolveWorkspacePath(env.GITHUB_WORKSPACE, inputs.base, "lockfile") : "";
    const maliciousDbPath = inputs.maliciousDb ? resolveWorkspacePath(env.GITHUB_WORKSPACE, inputs.maliciousDb, "lockfile") : "";
    const approvalLedgerPath = inputs.approvalLedger ? resolveWorkspacePath(env.GITHUB_WORKSPACE, inputs.approvalLedger, "lockfile") : "";
    const target = selectTarget();
    tempDir = fs.mkdtempSync(path.join(env.RUNNER_TEMP || os.tmpdir(), "argus-action-"));
    const binary = await materialize(inputs.version, target, tempDir, validateManifest);
    const versionResult = await run(binary, ["--version"], { timeoutMs: 30_000, stdoutLimit: 1024, stderrLimit: 1024 });
    if (versionResult.code !== 0 || versionResult.stdout !== `argus ${inputs.version}\n` || versionResult.stderr !== "") throw new Error("downloaded binary failed exact version self-check");
    const args = inputs.scanType === "agent"
      ? ["agent", "scan", scanPath, "--format", inputs.format]
      : inputs.scanType === "package"
        ? ["scan", scanPath, "--format", inputs.format]
        : ["lockfile-scan", scanPath, "--format", inputs.format];
    if (basePath) args.push("--base", basePath);
    if (inputs.baseLockfileFormat) args.push("--base-lockfile-format", inputs.baseLockfileFormat);
    if (maliciousDbPath) args.push("--malicious-db", maliciousDbPath);
    if (approvalLedgerPath) args.push("--approval-ledger", approvalLedgerPath);
    const result = await run(binary, args, { timeoutMs: 180_000 });
    outputs.exitCode = String(result.code);
    if (result.stderr !== "") throw new Error("argus wrote stderr while producing a report");
    const decision = validateReport(inputs.format, result.stdout, result.code, inputs.version, inputs.scanType);
    const extension = inputs.format === "sarif" ? "sarif" : inputs.format === "json" ? "json" : "txt";
    const reportPath = path.join(tempDir, `argus-report.${extension}`);
    const pendingPath = `${reportPath}.tmp`;
    fs.writeFileSync(pendingPath, result.stdout, { flag: "wx", encoding: "utf8" });
    fs.renameSync(pendingPath, reportPath);
    outputs.decision = decision;
    outputs.reportPath = reportPath;
    if (inputs.format === "sarif") outputs.sarifFile = reportPath;
    writeOutputs(outputs, env);
    outputsWritten = true;
    if (shouldFail(decision, inputs.failOn)) throw new Error(`Argus decision ${decision} violates failOn=${inputs.failOn}`);
    return outputs;
  } catch (error) {
    if (!outputsWritten) writeOutputs(outputs, env);
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`argus-action: ${message}\n`);
    process.exitCode = 1;
    return outputs;
  }
}

if (require.main === module) void main();

module.exports = { appendOutput, main, writeOutputs };
