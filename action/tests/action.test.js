"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { decisionForExit, readInputs, resolveWorkspacePath, shouldFail, targetFor, validateManifest, validateReport } = require("../src/contract");

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

test("manifest validates identity and exact asset shape", () => {
  const value = { schemaVersion: 1, version: "0.1.0", commit: "a".repeat(40), assets: [{ name: "argus", target: "x86_64-unknown-linux-gnu", kind: "binary", size: 1, sha256: "b".repeat(64) }] };
  assert.equal(validateManifest(value, "0.1.0", "a".repeat(40)), value);
  assert.throws(() => validateManifest({ ...value, extra: true }, "0.1.0", "a".repeat(40)), /keys/);
});

test("reports bind decision to exit code and format", () => {
  assert.equal(validateReport("text", "decision: allow  package: x\n", 0, "0.1.0"), "allow");
  assert.equal(validateReport("json", '{"decision":"block","findings":[]}', 1, "0.1.0"), "block");
  const sarif = JSON.stringify({ version: "2.1.0", runs: [{ tool: { driver: { name: "argus", version: "0.1.0" } }, invocations: [{ executionSuccessful: true }], results: [] }] });
  assert.equal(validateReport("sarif", sarif, 0, "0.1.0"), "allow");
  assert.throws(() => validateReport("json", '{"decision":"allow","findings":[]}', 1, "0.1.0"), /contract/);
  assert.throws(() => decisionForExit(3), /unsupported/);
});

test("failOn truth table preserves approval", () => {
  assert.equal(shouldFail("allow", "approval"), false);
  assert.equal(shouldFail("block", "block"), true);
  assert.equal(shouldFail("allow-with-approval", "block"), false);
  assert.equal(shouldFail("allow-with-approval", "approval"), true);
});
