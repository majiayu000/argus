"use strict";

const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const https = require("node:https");
const { PassThrough } = require("node:stream");
const test = require("node:test");
const { downloadVerifiedAsset, fetchRelease, fetchTagCommit, parseJson, requestBytes, sha256, uniqueAsset, verifyAttestation } = require("../src/download");
const { runBounded } = require("../src/run");

test("sha256 and JSON parsing are deterministic", () => {
  assert.equal(sha256(Buffer.from("argus")), "444b759c5264422ea582403ae2083d2447fd226a2e40795968dd740e9202cb97");
  assert.deepEqual(parseJson(Buffer.from('{"ok":true}'), "fixture"), { ok: true });
  assert.throws(() => parseJson(Buffer.from([0xff]), "fixture"), /UTF-8/);
});

function mockGet(responses, requests = []) {
  const original = https.get;
  https.get = (url, options, callback) => {
    requests.push({ url: String(url), options });
    const request = new EventEmitter();
    request.destroy = (error) => request.emit("error", error);
    const fixture = responses.shift();
    process.nextTick(() => {
      const response = new PassThrough();
      response.statusCode = fixture.status;
      response.headers = fixture.headers || {};
      callback(response);
      if (fixture.body) response.end(fixture.body); else response.end();
    });
    return request;
  };
  return () => { https.get = original; };
}

test("bounded GitHub request accepts one approved redirect", async () => {
  const requests = [];
  const restore = mockGet([
    { status: 302, headers: { location: "https://release-assets.githubusercontent.com/file" } },
    { status: 200, headers: { "content-length": "2" }, body: Buffer.from("ok") },
  ], requests);
  try {
    assert.equal((await requestBytes("https://api.github.com/assets/1", 2, 0, "application/octet-stream")).toString(), "ok");
    assert.equal(requests[0].options.headers.Accept, "application/octet-stream");
    assert.equal(requests[1].options.headers.Accept, "application/octet-stream");
  }
  finally { restore(); }
});

test("bounded GitHub request rejects origins, status, and declared oversize", async () => {
  assert.throws(() => requestBytes("https://example.com/file", 10), /origin/);
  let restore = mockGet([{ status: 500 }]);
  try { await assert.rejects(requestBytes("https://api.github.com/file", 10), /HTTP 500/); } finally { restore(); }
  restore = mockGet([{ status: 200, headers: { "content-length": "11" } }]);
  try { await assert.rejects(requestBytes("https://api.github.com/file", 10), /size limit/); } finally { restore(); }
});

test("release and asset metadata stay immutable and digest-bound", async () => {
  const release = { draft: false, prerelease: false, immutable: true, tag_name: "v0.1.0", target_commitish: "main", assets: [] };
  let restore = mockGet([{ status: 200, headers: { "content-type": "application/json; charset=utf-8" }, body: Buffer.from(JSON.stringify(release)) }]);
  try { assert.deepEqual(await fetchRelease("0.1.0"), release); } finally { restore(); }
  await assert.rejects((async () => {
    restore = mockGet([{ status: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ ...release, immutable: false })) }]);
    try { await fetchRelease("0.1.0"); } finally { restore(); }
  })(), /not immutable/);
  const body = Buffer.from("asset");
  const asset = { name: "asset", digest: `sha256:${sha256(body)}`, url: "https://api.github.com/assets/1", size: body.length };
  const requests = [];
  restore = mockGet([{ status: 200, headers: { "content-length": String(body.length) }, body }], requests);
  try {
    assert.deepEqual(await downloadVerifiedAsset({ assets: [asset] }, "asset", 10), body);
    assert.equal(requests[0].options.headers.Accept, "application/octet-stream");
  } finally { restore(); }
});

test("release metadata requires JSON and tag refs resolve to commit identity", async () => {
  let restore = mockGet([{ status: 200, headers: { "content-type": "text/plain" }, body: Buffer.from("{}") }]);
  try { await assert.rejects(fetchRelease("0.1.0"), /content type/); } finally { restore(); }
  restore = mockGet([{ status: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ ref: "refs/tags/v0.1.0", object: { type: "commit", sha: "a".repeat(40) } })) }]);
  try { assert.equal(await fetchTagCommit("0.1.0"), "a".repeat(40)); } finally { restore(); }
  restore = mockGet([
    { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ ref: "refs/tags/v0.1.0", object: { type: "tag", sha: "b".repeat(40) } })) },
    { status: 200, headers: { "content-type": "application/json" }, body: Buffer.from(JSON.stringify({ sha: "b".repeat(40), object: { type: "commit", sha: "c".repeat(40) } })) },
  ]);
  try { assert.equal(await fetchTagCommit("0.1.0"), "c".repeat(40)); } finally { restore(); }
});

test("attestation verifier requires flags and one JSON result", async () => {
  const flags = ["--bundle", "--signer-workflow", "--source-ref", "--source-digest", "--deny-self-hosted-runners", "--format"].join(" ");
  const calls = [];
  const runner = async (_exe, args) => { calls.push(args); return calls.length === 1 ? { code: 0, stdout: flags, stderr: "" } : { code: 0, stdout: '{"verificationResult":"success"}', stderr: "" }; };
  await verifyAttestation("subject", "bundle", "0.1.0", "a".repeat(40), runner);
  assert.equal(calls.length, 2);
  await assert.rejects(verifyAttestation("subject", "bundle", "0.1.0", "a".repeat(40), async () => ({ code: 0, stdout: "--bundle", stderr: "" })), /lacks required/);
});

test("bounded process captures success, nonzero, timeout, and output limits", async () => {
  const ok = await runBounded(process.execPath, ["-e", "process.stdout.write('ok')"]);
  assert.deepEqual(ok, { code: 0, stdout: "ok", stderr: "" });
  const bad = await runBounded(process.execPath, ["-e", "process.stderr.write('bad');process.exit(2)"]);
  assert.deepEqual(bad, { code: 2, stdout: "", stderr: "bad" });
  await assert.rejects(runBounded(process.execPath, ["-e", "setTimeout(()=>{},1000)"], { timeoutMs: 20 }), /timed out/);
  await assert.rejects(runBounded(process.execPath, ["-e", "process.stdout.write('long')"], { stdoutLimit: 2 }), /exceeded/);
});

test("asset selection rejects missing duplicate and incomplete metadata", () => {
  const good = { name: "asset", digest: `sha256:${"a".repeat(64)}`, url: "https://api.github.com/assets/1", size: 1 };
  assert.equal(uniqueAsset({ assets: [good] }, "asset"), good);
  assert.throws(() => uniqueAsset({ assets: [] }, "asset"), /exactly one/);
  assert.throws(() => uniqueAsset({ assets: [good, good] }, "asset"), /exactly one/);
  assert.throws(() => uniqueAsset({ assets: [{ ...good, digest: null }] }, "asset"), /incomplete/);
});
