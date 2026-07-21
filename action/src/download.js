"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { runBounded } = require("./run");

const API_HEADERS = Object.freeze({ Accept: "application/vnd.github+json", "User-Agent": "argus-action-v1", "X-GitHub-Api-Version": "2026-03-10" });

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

function requestBytes(url, limit, redirects = 0) {
  const parsed = new URL(url);
  const expectedHost = redirects === 0 ? "api.github.com" : "release-assets.githubusercontent.com";
  if (parsed.protocol !== "https:" || parsed.hostname !== expectedHost || parsed.username || parsed.password) throw new Error(`download origin is not allowed: ${parsed.origin}`);
  return new Promise((resolve, reject) => {
    const request = https.get(parsed, { headers: API_HEADERS, timeout: 30_000 }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        response.resume();
        if (redirects !== 0 || !response.headers.location) return reject(new Error("asset download redirect is missing or excessive"));
        return requestBytes(new URL(response.headers.location, parsed).toString(), limit, 1).then(resolve, reject);
      }
      if (response.statusCode !== 200) { response.resume(); return reject(new Error(`GitHub request failed with HTTP ${response.statusCode}`)); }
      const declared = Number(response.headers["content-length"] || 0);
      if (declared > limit) { response.resume(); return reject(new Error("GitHub response exceeds size limit")); }
      const chunks = [];
      let size = 0;
      response.on("data", (chunk) => { size += chunk.length; if (size > limit) { request.destroy(new Error("GitHub response exceeds size limit")); } else chunks.push(chunk); });
      response.on("end", () => resolve(Buffer.concat(chunks)));
    });
    request.on("timeout", () => request.destroy(new Error("GitHub request timed out")));
    request.on("error", reject);
  });
}

function parseJson(bytes, label) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (error) { throw new Error(`${label} is not UTF-8`, { cause: error }); }
  try { return JSON.parse(text); } catch (error) { throw new Error(`${label} is malformed JSON`, { cause: error }); }
}

async function fetchRelease(version) {
  const bytes = await requestBytes(`https://api.github.com/repos/majiayu000/argus/releases/tags/v${version}`, 1024 * 1024);
  const release = parseJson(bytes, "GitHub release response");
  if (!release || release.draft !== false || release.prerelease !== false || release.immutable !== true || release.tag_name !== `v${version}` || !/^[0-9a-f]{40}$/.test(release.target_commitish) || !Array.isArray(release.assets)) throw new Error("release is not immutable or has an invalid identity");
  return release;
}

function uniqueAsset(release, name) {
  const matches = release.assets.filter((item) => item?.name === name);
  if (matches.length !== 1) throw new Error(`release must contain exactly one ${name}`);
  const asset = matches[0];
  if (!/^sha256:[0-9a-f]{64}$/.test(asset.digest || "") || typeof asset.url !== "string" || !Number.isSafeInteger(asset.size) || asset.size < 1) throw new Error(`release asset metadata is incomplete: ${name}`);
  return asset;
}

async function downloadVerifiedAsset(release, name, limit) {
  const asset = uniqueAsset(release, name);
  if (asset.size > limit) throw new Error(`release asset exceeds size limit: ${name}`);
  const bytes = await requestBytes(asset.url, limit);
  if (bytes.length !== asset.size || `sha256:${sha256(bytes)}` !== asset.digest) throw new Error(`GitHub asset digest mismatch: ${name}`);
  return bytes;
}

async function verifyAttestation(subject, bundle, version, commit, runner = runBounded) {
  const help = await runner("gh", ["attestation", "verify", "--help"], { timeoutMs: 15_000, stdoutLimit: 1024 * 1024 });
  if (help.code !== 0 || !["--bundle", "--signer-workflow", "--source-ref", "--source-digest", "--deny-self-hosted-runners", "--format"].every((flag) => help.stdout.includes(flag))) throw new Error("installed gh lacks required attestation verification flags");
  const result = await runner("gh", ["attestation", "verify", subject, "--bundle", bundle, "--repo", "majiayu000/argus", "--signer-workflow", "majiayu000/argus/.github/workflows/release.yml", "--source-ref", `refs/tags/v${version}`, "--source-digest", commit, "--deny-self-hosted-runners", "--format", "json"], { timeoutMs: 180_000, stdoutLimit: 4 * 1024 * 1024 });
  if (result.code !== 0 || result.stderr) throw new Error("GitHub attestation verification failed");
  const verified = parseJson(Buffer.from(result.stdout), "gh attestation output");
  const entries = Array.isArray(verified) ? verified : [verified];
  if (entries.length !== 1 || !entries[0] || typeof entries[0] !== "object") throw new Error("gh attestation output must contain one verified attestation");
}

async function materializeRelease(version, target, tempDir, validateManifest) {
  const release = await fetchRelease(version);
  const manifestBytes = await downloadVerifiedAsset(release, "release_manifest.json", 1024 * 1024);
  const manifestBundle = await downloadVerifiedAsset(release, "release_manifest.sigstore.json", 4 * 1024 * 1024);
  const manifestPath = path.join(tempDir, "release_manifest.json");
  const manifestBundlePath = path.join(tempDir, "release_manifest.sigstore.json");
  fs.writeFileSync(manifestPath, manifestBytes, { flag: "wx" });
  fs.writeFileSync(manifestBundlePath, manifestBundle, { flag: "wx" });
  await verifyAttestation(manifestPath, manifestBundlePath, version, release.target_commitish);
  const manifest = validateManifest(parseJson(manifestBytes, "release manifest"), version, release.target_commitish);
  const suffix = target.endsWith("windows-msvc") ? ".exe" : "";
  const binaryName = `argus-${version}-${target}${suffix}`;
  const entry = manifest.assets.find((item) => item.name === binaryName && item.target === target && item.kind === "binary");
  if (!entry) throw new Error(`manifest lacks binary for ${target}`);
  const binary = await downloadVerifiedAsset(release, binaryName, 128 * 1024 * 1024);
  if (binary.length !== entry.size || sha256(binary) !== entry.sha256) throw new Error("binary does not match release manifest");
  const bundleName = `${binaryName}.sigstore.json`;
  const bundle = await downloadVerifiedAsset(release, bundleName, 4 * 1024 * 1024);
  const binaryPath = path.join(tempDir, suffix ? "argus.exe" : "argus");
  const bundlePath = path.join(tempDir, bundleName);
  fs.writeFileSync(binaryPath, binary, { flag: "wx", mode: 0o755 });
  fs.writeFileSync(bundlePath, bundle, { flag: "wx" });
  await verifyAttestation(binaryPath, bundlePath, version, release.target_commitish);
  return binaryPath;
}

module.exports = { downloadVerifiedAsset, fetchRelease, materializeRelease, parseJson, requestBytes, sha256, uniqueAsset, verifyAttestation };
