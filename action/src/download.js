"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const https = require("node:https");
const path = require("node:path");
const { runBounded } = require("./run");

const API_ACCEPT = "application/vnd.github+json";
const ASSET_ACCEPT = "application/octet-stream";
const BASE_HEADERS = Object.freeze({ "User-Agent": "argus-action-v1", "X-GitHub-Api-Version": "2026-03-10" });

function sha256(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }

function requestBytes(url, limit, redirects = 0, accept = API_ACCEPT, expectedContentType = null) {
  const parsed = new URL(url);
  const expectedHost = redirects === 0 ? "api.github.com" : "release-assets.githubusercontent.com";
  if (parsed.protocol !== "https:" || parsed.hostname !== expectedHost || parsed.username || parsed.password) throw new Error(`download origin is not allowed: ${parsed.origin}`);
  return new Promise((resolve, reject) => {
    const request = https.get(parsed, { headers: { ...BASE_HEADERS, Accept: accept }, timeout: 30_000 }, (response) => {
      if ([301, 302, 303, 307, 308].includes(response.statusCode)) {
        response.resume();
        if (redirects !== 0 || !response.headers.location) return reject(new Error("asset download redirect is missing or excessive"));
        return requestBytes(new URL(response.headers.location, parsed).toString(), limit, 1, accept, expectedContentType).then(resolve, reject);
      }
      if (response.statusCode !== 200) { response.resume(); return reject(new Error(`GitHub request failed with HTTP ${response.statusCode}`)); }
      if (expectedContentType && String(response.headers["content-type"] || "").split(";", 1)[0].trim().toLowerCase() !== expectedContentType) {
        response.resume();
        return reject(new Error(`GitHub response has unexpected content type; expected ${expectedContentType}`));
      }
      const declared = Number(response.headers["content-length"] || 0);
      if (!Number.isSafeInteger(declared) || declared < 0) { response.resume(); return reject(new Error("GitHub response has invalid content length")); }
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
  const bytes = await requestBytes(`https://api.github.com/repos/majiayu000/argus/releases/tags/v${version}`, 1024 * 1024, 0, API_ACCEPT, "application/json");
  const release = parseJson(bytes, "GitHub release response");
  if (!release || release.draft !== false || release.prerelease !== false || release.immutable !== true || release.tag_name !== `v${version}` || typeof release.target_commitish !== "string" || !release.target_commitish || !Array.isArray(release.assets)) throw new Error("release is not immutable or has an invalid identity");
  return release;
}

async function fetchTagCommit(version) {
  const refBytes = await requestBytes(`https://api.github.com/repos/majiayu000/argus/git/ref/tags/v${version}`, 1024 * 1024, 0, API_ACCEPT, "application/json");
  const ref = parseJson(refBytes, "GitHub tag ref response");
  if (!ref || ref.ref !== `refs/tags/v${version}` || !ref.object || !/^[0-9a-f]{40}$/.test(ref.object.sha || "") || !["commit", "tag"].includes(ref.object.type)) throw new Error("tag ref has an invalid identity");
  if (ref.object.type === "commit") return ref.object.sha;
  const tagBytes = await requestBytes(`https://api.github.com/repos/majiayu000/argus/git/tags/${ref.object.sha}`, 1024 * 1024, 0, API_ACCEPT, "application/json");
  const tag = parseJson(tagBytes, "GitHub annotated tag response");
  if (!tag || tag.sha !== ref.object.sha || !tag.object || tag.object.type !== "commit" || !/^[0-9a-f]{40}$/.test(tag.object.sha || "")) throw new Error("annotated tag does not resolve directly to a commit");
  return tag.object.sha;
}

function uniqueAsset(release, name) {
  const matches = release.assets.filter((item) => item?.name === name);
  if (matches.length !== 1) throw new Error(`release must contain exactly one ${name}`);
  const asset = matches[0];
  if (!/^sha256:[0-9a-f]{64}$/.test(asset.digest || "") || !/^https:\/\/api\.github\.com\/repos\/majiayu000\/argus\/releases\/assets\/[1-9][0-9]*$/.test(asset.url || "") || !Number.isSafeInteger(asset.size) || asset.size < 1) throw new Error(`release asset metadata is incomplete: ${name}`);
  return asset;
}

async function downloadVerifiedAsset(release, name, limit) {
  const asset = uniqueAsset(release, name);
  if (asset.size > limit) throw new Error(`release asset exceeds size limit: ${name}`);
  const bytes = await requestBytes(asset.url, limit, 0, ASSET_ACCEPT);
  if (bytes.length !== asset.size || `sha256:${sha256(bytes)}` !== asset.digest) throw new Error(`GitHub asset digest mismatch: ${name}`);
  return bytes;
}

async function verifyAttestation(subject, bundle, version, commit, runner = runBounded) {
  const help = await runner("gh", ["attestation", "verify", "--help"], { timeoutMs: 15_000, stdoutLimit: 1024 * 1024 });
  if (help.code !== 0 || !["--bundle", "--cert-oidc-issuer", "--signer-workflow", "--source-ref", "--source-digest", "--deny-self-hosted-runners", "--format"].every((flag) => help.stdout.includes(flag))) throw new Error("installed gh lacks required attestation verification flags");
  const ref = `refs/tags/v${version}`;
  const workflow = "majiayu000/argus/.github/workflows/release.yml";
  const result = await runner("gh", ["attestation", "verify", subject, "--bundle", bundle, "--repo", "majiayu000/argus", "--cert-oidc-issuer", "https://token.actions.githubusercontent.com", "--signer-workflow", workflow, "--source-ref", ref, "--source-digest", commit, "--deny-self-hosted-runners", "--format", "json"], { timeoutMs: 180_000, stdoutLimit: 4 * 1024 * 1024 });
  if (result.code !== 0 || result.stderr) throw new Error("GitHub attestation verification failed");
  const verified = parseJson(Buffer.from(result.stdout), "gh attestation output");
  const entries = Array.isArray(verified) ? verified : [verified];
  if (entries.length !== 1 || !entries[0] || typeof entries[0] !== "object") throw new Error("gh attestation output must contain one verified attestation");
  const verification = entries[0].verificationResult;
  const certificate = verification?.signature?.certificate;
  const statement = verification?.statement;
  const subjects = Array.isArray(statement?.subject) ? statement.subject : [];
  const expectedDigest = sha256(fs.readFileSync(subject));
  const matchingSubjects = subjects.filter((item) => item && item.digest?.sha256 === expectedDigest);
  if (statement?.predicateType !== "https://slsa.dev/provenance/v1" || matchingSubjects.length !== 1 || !Array.isArray(verification?.verifiedTimestamps) || verification.verifiedTimestamps.length < 1) throw new Error("attestation statement or subject is invalid");
  const expectedWorkflowUri = `https://github.com/${workflow}@${ref}`;
  if (!certificate || certificate.issuer !== "https://token.actions.githubusercontent.com" || certificate.runnerEnvironment !== "github-hosted" || certificate.sourceRepositoryURI !== "https://github.com/majiayu000/argus" || certificate.sourceRepositoryDigest !== commit || certificate.sourceRepositoryRef !== ref || certificate.buildConfigURI !== expectedWorkflowUri || certificate.buildSignerURI !== expectedWorkflowUri) throw new Error("attestation certificate identity is invalid");
}

async function materializeRelease(version, target, tempDir, validateManifest, dependencies = {}) {
  const fetchReleaseFn = dependencies.fetchRelease || fetchRelease;
  const fetchTagCommitFn = dependencies.fetchTagCommit || fetchTagCommit;
  const downloadFn = dependencies.downloadVerifiedAsset || downloadVerifiedAsset;
  const verifyFn = dependencies.verifyAttestation || verifyAttestation;
  const [release, commit] = await Promise.all([fetchReleaseFn(version), fetchTagCommitFn(version)]);
  const manifestBytes = await downloadFn(release, "release_manifest.json", 1024 * 1024);
  const manifestBundle = await downloadFn(release, "release_manifest.sigstore.json", 4 * 1024 * 1024);
  const manifestPath = path.join(tempDir, "release_manifest.json");
  const manifestBundlePath = path.join(tempDir, "release_manifest.sigstore.json");
  fs.writeFileSync(manifestPath, manifestBytes, { flag: "wx" });
  fs.writeFileSync(manifestBundlePath, manifestBundle, { flag: "wx" });
  await verifyFn(manifestPath, manifestBundlePath, version, commit);
  const manifest = validateManifest(parseJson(manifestBytes, "release manifest"), version, commit);
  const suffix = target.endsWith("windows-msvc") ? ".exe" : "";
  const binaryName = `argus-v${version}-${target}${suffix}`;
  const entry = manifest.assets.find((item) => item.name === binaryName && item.target === target && item.kind === "binary");
  if (!entry) throw new Error(`manifest lacks binary for ${target}`);
  const binary = await downloadFn(release, binaryName, 128 * 1024 * 1024);
  if (binary.length !== entry.size || sha256(binary) !== entry.sha256) throw new Error("binary does not match release manifest");
  const bundleName = `${target}.sigstore.json`;
  const bundle = await downloadFn(release, bundleName, 4 * 1024 * 1024);
  const binaryPath = path.join(tempDir, suffix ? "argus.exe" : "argus");
  const bundlePath = path.join(tempDir, bundleName);
  fs.writeFileSync(binaryPath, binary, { flag: "wx", mode: 0o755 });
  fs.writeFileSync(bundlePath, bundle, { flag: "wx" });
  await verifyFn(binaryPath, bundlePath, version, commit);
  return binaryPath;
}

module.exports = { downloadVerifiedAsset, fetchRelease, fetchTagCommit, materializeRelease, parseJson, requestBytes, sha256, uniqueAsset, verifyAttestation };
