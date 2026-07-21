"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { decisionForExit, readInputs, resolveWorkspacePath, shouldFail, targetFor, validateManifest, validateReport } = require("../src/contract");
const { main } = require("../src/main");

const config = { schemaVersion: 1, defaultBinaryVersion: "0.1.0", compatibilityRange: ">=0.1.0,<0.2.0" };

test("input contract rejects empty and open-ended values", () => {
  assert.throws(() => readInputs({}, config), /scanType/);
  assert.throws(() => readInputs({ INPUT_SCANTYPE: "package", INPUT_PATH: ".", INPUT_ARGUSVERSION: "latest" }, config), /canonical/);
  assert.throws(() => readInputs({ INPUT_SCANTYPE: "package", INPUT_PATH: ".", INPUT_ARGUSVERSION: "0.2.0" }, config), /outside/);
  assert.deepEqual(readInputs({ INPUT_SCANTYPE: "agent", INPUT_PATH: "." }, config), { scanType: "agent", inputPath: ".", format: "text", version: "0.1.0", failOn: "block" });
});

test("platform matrix is closed", () => {
  assert.equal(targetFor("linux", "x64"), "x86_64-unknown-linux-gnu");
  assert.equal(targetFor("linux", "arm64"), "aarch64-unknown-linux-gnu");
  assert.equal(targetFor("darwin", "x64"), "x86_64-apple-darwin");
  assert.equal(targetFor("darwin", "arm64"), "aarch64-apple-darwin");
  assert.equal(targetFor("win32", "x64"), "x86_64-pc-windows-msvc");
  assert.throws(() => targetFor("freebsd", "x64"), /unsupported/);
});

test("workspace paths cannot escape through traversal or symlink", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "argus-action-contract-"));
  const pkg = path.join(root, "pkg");
  fs.mkdirSync(pkg);
  assert.equal(resolveWorkspacePath(root, "pkg", "package"), fs.realpathSync(pkg));
  assert.throws(() => resolveWorkspacePath(root, "pkg", "lockfile"), /regular file/);
  const link = path.join(root, "escape");
  fs.symlinkSync(os.tmpdir(), link);
  assert.throws(() => resolveWorkspacePath(root, "escape", "agent"), /outside/);
});

test("manifest validates identity and complete asset matrix", () => {
  const runners = { "x86_64-unknown-linux-gnu": "ubuntu-24.04", "aarch64-unknown-linux-gnu": "ubuntu-24.04-arm", "x86_64-apple-darwin": "macos-15-intel", "aarch64-apple-darwin": "macos-15", "x86_64-pc-windows-msvc": "windows-2025" };
  const assets = Object.entries(runners).flatMap(([target, runner]) => ["binary", "archive"].map((kind) => ({ name: kind === "binary" ? `argus-v0.1.0-${target}${target.endsWith("windows-msvc") ? ".exe" : ""}` : `argus-v0.1.0-${target}.${target.endsWith("windows-msvc") ? "zip" : "tar.gz"}`, target, runner, kind, size: 1, sha256: "b".repeat(64) })));
  assets.push({ name: "LICENSE", target: null, runner: null, kind: "documentation", size: 1, sha256: "c".repeat(64) });
  assets.push({ name: "README.md", target: null, runner: null, kind: "documentation", size: 1, sha256: "d".repeat(64) });
  const value = { schemaVersion: 1, binaryVersion: "0.1.0", tag: "v0.1.0", commit: "a".repeat(40), assets };
  assert.equal(validateManifest(value, "0.1.0", "a".repeat(40)), value);
  assert.throws(() => validateManifest({ ...value, extra: true }, "0.1.0", "a".repeat(40)), /keys/);
  assert.throws(() => validateManifest({ ...value, assets: assets.slice(1) }, "0.1.0", "a".repeat(40)), /incomplete/);
});

test("reports bind decision to exit code and format", () => {
  assert.equal(validateReport("text", "decision: allow  package: x\npath: .\nfindings: none\n", 0, "0.1.0"), "allow");
  const blocked = JSON.stringify({ artifact: "package-dir", path: ".", package_name: "x", package_version: "1.0.0", decision: "block", findings: [{}] });
  assert.equal(validateReport("json", blocked, 1, "0.1.0"), "block");
  const sarif = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "argus", version: "0.1.0" } }, invocations: [{ executionSuccessful: true }], results: [] }] });
  assert.equal(validateReport("sarif", sarif, 0, "0.1.0"), "allow");
  assert.throws(() => validateReport("json", JSON.stringify({ ...JSON.parse(blocked), decision: "allow" }), 1, "0.1.0"), /contract/);
  assert.throws(() => decisionForExit(3), /unsupported/);
});

test("main preserves blank outputs on early failure and only exitCode on invalid report", async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "argus-action-main-"));
  const output = path.join(root, "output");
  const env = { GITHUB_WORKSPACE: root, RUNNER_TEMP: root, GITHUB_OUTPUT: output, INPUT_SCANTYPE: "package", INPUT_PATH: "." };
  const originalExitCode = process.exitCode;
  process.exitCode = 0;
  await main(env, { targetFor: () => "x86_64-unknown-linux-gnu", materializeRelease: async () => { throw new Error("download failed"); } });
  let values = Object.fromEntries(fs.readFileSync(output, "utf8").trimEnd().split("\n").map((line) => line.split("=", 2)));
  assert.deepEqual(values, { decision: "", exitCode: "", reportPath: "", sarifFile: "", argusVersion: "0.1.0" });
  fs.writeFileSync(output, "");
  let calls = 0;
  await main(env, { targetFor: () => "x86_64-unknown-linux-gnu", materializeRelease: async () => "/tmp/argus", runBounded: async () => (++calls === 1 ? { code: 0, stdout: "argus 0.1.0\n", stderr: "" } : { code: 1, stdout: "{}", stderr: "" }) });
  values = Object.fromEntries(fs.readFileSync(output, "utf8").trimEnd().split("\n").map((line) => line.split("=", 2)));
  assert.deepEqual(values, { decision: "", exitCode: "1", reportPath: "", sarifFile: "", argusVersion: "0.1.0" });
  process.exitCode = originalExitCode;
});

test("failOn truth table preserves approval", () => {
  assert.equal(shouldFail("allow", "approval"), false);
  assert.equal(shouldFail("block", "block"), true);
  assert.equal(shouldFail("allow-with-approval", "block"), false);
  assert.equal(shouldFail("allow-with-approval", "approval"), true);
});
