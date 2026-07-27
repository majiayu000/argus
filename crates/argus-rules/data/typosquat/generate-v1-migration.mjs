#!/usr/bin/env node

import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repository = resolve(scriptDirectory, "../../../..");
const outputDirectory = join(scriptDirectory, "v1");
const confusablesInput = process.argv[2];

if (!confusablesInput) {
  throw new Error(
    "usage: generate-v1-migration.mjs /path/to/unicode-17.0.0-confusables.txt",
  );
}

const ecosystems = [
  {
    id: "npm",
    file: "npm.json",
    source: "crates/argus-rules/src/name.rs",
    constant: "POPULAR_PACKAGES",
    expectedCount: 35,
    expectedHash:
      "46b563acfdf05b6e097e7fcb5ba03fded0391f06ddbe9f1995b3309d368c7cf2",
    normalization: "npm-v1",
    namespace: "npm-scope-exact-leaf",
  },
  {
    id: "pypi",
    file: "pypi.json",
    source: "crates/argus-pypi/src/rules.rs",
    constant: "POPULAR_PYTHON_PACKAGES",
    expectedCount: 67,
    expectedHash:
      "a672d8930f68a9beee9b3ba476b3816c7dd14a08907f3111999d8096c5d80749",
    normalization: "pep503-v1",
    namespace: "registry-identity",
  },
  {
    id: "crates-io",
    file: "crates-io.json",
    source: "crates/argus-crates/src/rules.rs",
    constant: "POPULAR_CRATES",
    expectedCount: 75,
    expectedHash:
      "0ba2ff38211605dbd6e1b1a71c404c453fcf37a57eaee54390b09ab5382ba184",
    normalization: "crates-io-v1",
    namespace: "registry-identity",
  },
  {
    id: "go",
    file: "go.json",
    source: "crates/argus-go/src/rules.rs",
    constant: "POPULAR_GO_MODULES",
    expectedCount: 26,
    expectedHash:
      "1435fca2cf4b74eea39605bae938f6a86f1ca90cb6970834b0ce85bc764e1809",
    normalization: "go-module-v1",
    namespace: "go-equal-depth-one-segment",
  },
  {
    id: "nuget",
    file: "nuget.json",
    source: "crates/argus-nuget/src/rules.rs",
    constant: "POPULAR_NUGET_PACKAGES",
    expectedCount: 35,
    expectedHash:
      "14e4c9bc60e78507b992a3276ba405bfd1c7bf388a17bf126fe7cb1c42ed2084",
    normalization: "nuget-v1",
    namespace: "registry-identity",
  },
  {
    id: "maven",
    file: "maven.json",
    source: "crates/argus-maven/src/rules.rs",
    constant: "POPULAR_MAVEN_ARTIFACTS",
    expectedCount: 38,
    expectedHash:
      "63fa2574c8613da2fc1cb8f49f8fc475745e69d93d36cc59ec229dfaf369ed7f",
    normalization: "maven-v1",
    namespace: "maven-legacy-leaf-any-group",
  },
  {
    id: "rubygems",
    file: "rubygems.json",
    source: "crates/argus-rubygems/src/rules.rs",
    constant: "POPULAR_RUBY_GEMS",
    expectedCount: 54,
    expectedHash:
      "b6f7a4f77fca1ea1028df6686ae5ccd4f9d6f38d6a76faa94d7003b94e41bde7",
    normalization: "rubygems-v1",
    namespace: "registry-identity",
  },
  {
    id: "composer",
    file: "composer.json",
    source: "crates/argus-composer/src/rules.rs",
    constant: "POPULAR_COMPOSER_PACKAGES",
    expectedCount: 52,
    expectedHash:
      "7277604ad1b34e3ddbaa709b7e22c6681bf5865e126b2b561fb49a1f5e2d7692",
    normalization: "composer-v1",
    namespace: "composer-vendor-package",
  },
];

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const encode = (value) => `${JSON.stringify(value)}\n`;

function canonicalKey(ecosystem, name) {
  if (ecosystem === "pypi") {
    return name.toLowerCase().replace(/[-_.]+/g, "-");
  }
  return name.toLowerCase();
}

function keyboardEdges() {
  const rows = [
    { keys: "1234567890", offset: 0 },
    { keys: "qwertyuiop", offset: 0.25 },
    { keys: "asdfghjkl", offset: 0.5 },
    { keys: "zxcvbnm", offset: 0.75 },
  ];
  const keys = rows.flatMap(({ keys, offset }, row) =>
    [...keys].map((key, column) => ({ key, x: column + offset, y: row })),
  );
  const edges = [];
  for (let left = 0; left < keys.length; left += 1) {
    for (let right = left + 1; right < keys.length; right += 1) {
      const dx = keys[left].x - keys[right].x;
      const dy = keys[left].y - keys[right].y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      if (distance <= 1.15) {
        edges.push([keys[left].key, keys[right].key].sort());
      }
    }
  }
  return edges.sort(([a1, a2], [b1, b2]) =>
    `${a1}${a2}`.localeCompare(`${b1}${b2}`, "en"),
  );
}

function unicodeMappings(source) {
  const mappings = [];
  for (const line of source.split(/\r?\n/)) {
    const data = line.replace(/#.*/, "").trim();
    if (!data) continue;
    const [sourceHex, targetHex, mappingType] = data
      .split(";")
      .map((field) => field.trim());
    if (mappingType !== "MA") {
      throw new Error(`unexpected confusables mapping type ${mappingType}`);
    }
    const sourcePoints = sourceHex.split(/\s+/);
    if (sourcePoints.length !== 1) {
      throw new Error(`expected a single source scalar: ${sourceHex}`);
    }
    const sourceScalar = String.fromCodePoint(Number.parseInt(sourcePoints[0], 16));
    const target = targetHex
      .split(/\s+/)
      .map((point) => String.fromCodePoint(Number.parseInt(point, 16)))
      .join("");
    mappings.push({ source: sourceScalar, target });
  }
  mappings.sort((left, right) => left.source.codePointAt(0) - right.source.codePointAt(0));
  return mappings;
}

await mkdir(outputDirectory, { recursive: true });

const manifestDatasets = [];
let combinedSourceOrder = "";
for (const ecosystem of ecosystems) {
  const migrationSnapshot = JSON.parse(
    await readFile(join(outputDirectory, ecosystem.file), "utf8"),
  );
  const names = [...migrationSnapshot.entries]
    .sort((left, right) => left.popularity.value - right.popularity.value)
    .map((entry) => entry.canonical_name);
  const sourceOrderBytes = names.map((name) => `${name}\n`).join("");
  if (names.length !== ecosystem.expectedCount) {
    throw new Error(`${ecosystem.id}: expected ${ecosystem.expectedCount}, got ${names.length}`);
  }
  if (sha256(sourceOrderBytes) !== ecosystem.expectedHash) {
    throw new Error(`${ecosystem.id}: frozen source-order hash mismatch`);
  }
  combinedSourceOrder += `${ecosystem.id === "crates-io" ? "crates" : ecosystem.id}\n`;
  combinedSourceOrder += sourceOrderBytes;

  const sourceId = `argus-frozen-${ecosystem.id}-const`;
  const entries = names
    .map((canonicalName, index) => ({
      canonical_name: canonicalName,
      aliases: [],
      popularity: {
        source_id: sourceId,
        metric: "legacy-priority",
        value: index + 1,
      },
    }))
    .sort((left, right) =>
      canonicalKey(ecosystem.id, left.canonical_name).localeCompare(
        canonicalKey(ecosystem.id, right.canonical_name),
        "en",
      ),
    );
  const dataset = {
    schema_version: 1,
    ecosystem: ecosystem.id,
    dataset_id: `argus-popular-${ecosystem.id}-v1`,
    dataset_version: 1,
    as_of: "2026-07-27",
    normalization: ecosystem.normalization,
    namespace_semantics: ecosystem.namespace,
    sources: [
      {
        id: sourceId,
        kind: "legacy-rust-const",
        uri: `repo://${ecosystem.source}#${ecosystem.constant}`,
        retrieved_at: "2026-07-27T10:19:38Z",
        artifact_sha256: ecosystem.expectedHash,
        method:
          "Frozen source-order migration; value is the original one-based array position.",
        license: "Apache-2.0",
      },
    ],
    entries,
  };
  const bytes = encode(dataset);
  await writeFile(join(outputDirectory, ecosystem.file), bytes);
  manifestDatasets.push({
    ecosystem: ecosystem.id,
    file: ecosystem.file,
    count: entries.length,
    raw_sha256: sha256(bytes),
    legacy_source_count: names.length,
    legacy_source_order_sha256: ecosystem.expectedHash,
  });
}

const expectedCombined =
  "f31adaca86d5df50ab15216ea677be24499552979963227878a45ac8f22765a5";
if (sha256(combinedSourceOrder) !== expectedCombined) {
  throw new Error("combined frozen source-order hash mismatch");
}

const keyboard = {
  schema_version: 1,
  layout_id: "qwerty-us-v1",
  layout_version: 1,
  alphabet: "1234567890abcdefghijklmnopqrstuvwxyz",
  edge_semantics: "unique-unordered-physical-neighbors-distance-lte-1.15",
  edges: keyboardEdges(),
};
const keyboardBytes = encode(keyboard);
await writeFile(join(outputDirectory, "keyboard-qwerty-us.json"), keyboardBytes);

const confusablesSource = await readFile(confusablesInput, "utf8");
const confusablesSourceHash = sha256(confusablesSource);
const expectedConfusablesHash =
  "091c7f82fc39ef208faf8f94d29c244de99254675e09de163160c810d13ef22a";
if (confusablesSourceHash !== expectedConfusablesHash) {
  throw new Error("Unicode 17.0.0 confusables.txt hash mismatch");
}
const confusables = {
  schema_version: 1,
  profile_id: "uts39-v1",
  unicode_version: "17.0.0",
  source_uri: "https://www.unicode.org/Public/17.0.0/security/confusables.txt",
  retrieved_at: "2026-07-27T10:19:38Z",
  source_sha256: confusablesSourceHash,
  source_date: "2025-07-22T05:49:37Z",
  generator_version: "argus-typosquat-data-v1",
  normalization:
    "Unicode scalar substitution from UTS39 MA mappings; no byte indexing or implicit case folding",
  mappings: unicodeMappings(confusablesSource),
};
const confusablesBytes = encode(confusables);
await writeFile(join(outputDirectory, "unicode-confusables.json"), confusablesBytes);

const manifest = {
  schema_version: 1,
  manifest_id: "argus-typosquat-v1",
  dataset_version: 1,
  generator_version: "argus-typosquat-data-v1",
  generated_at: "2026-07-27T10:19:38Z",
  combined_legacy_source_order_sha256: expectedCombined,
  datasets: manifestDatasets,
  keyboard: {
    file: "keyboard-qwerty-us.json",
    layout_id: keyboard.layout_id,
    raw_sha256: sha256(keyboardBytes),
    edge_count: keyboard.edges.length,
  },
  confusables: {
    file: "unicode-confusables.json",
    profile_id: confusables.profile_id,
    unicode_version: confusables.unicode_version,
    raw_sha256: sha256(confusablesBytes),
    source_sha256: confusablesSourceHash,
    mapping_count: confusables.mappings.length,
  },
};
await writeFile(join(outputDirectory, "manifest.json"), encode(manifest));
