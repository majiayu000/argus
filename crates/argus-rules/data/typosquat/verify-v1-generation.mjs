#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { cp, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const directory = dirname(fileURLToPath(import.meta.url));
const generator = join(directory, "generate-v1-migration.mjs");
const sources = join(directory, "sources");
const expected = join(directory, "v1");
const temporaryRoot = await mkdtemp(join(tmpdir(), "argus-typosquat-v1-"));

try {
  const inputArchive = join(temporaryRoot, "input-archive");
  const cleanOutput = join(temporaryRoot, "clean-output");
  const shuffledOutput = join(temporaryRoot, "shuffled-output");
  await mkdir(inputArchive);
  for (const file of [
    "migration-v1.json",
    "qwerty-us-v1.json",
    "unicode-17.0.0-confusables.txt.gz",
  ]) {
    await cp(join(sources, file), join(inputArchive, file));
  }

  generate(join(inputArchive, "migration-v1.json"), cleanOutput);
  await assertDirectoriesEqual(expected, cleanOutput);

  const migration = JSON.parse(
    await readFile(join(inputArchive, "migration-v1.json"), "utf8"),
  );
  migration.ecosystems.reverse();
  for (const ecosystem of migration.ecosystems) ecosystem.entries.reverse();
  const shuffledSource = join(inputArchive, "migration-v1-shuffled.json");
  await writeFile(shuffledSource, `${JSON.stringify(migration)}\n`);
  generate(shuffledSource, shuffledOutput);
  await assertDirectoriesEqual(cleanOutput, shuffledOutput);

  process.stdout.write(
    "typosquat v1 clean rebuild and shuffled-source determinism: PASS\n",
  );
} finally {
  await rm(temporaryRoot, { recursive: true, force: true });
}

function generate(migrationSource, outputDirectory) {
  execFileSync(
    process.execPath,
    [
      generator,
      "--migration-source",
      migrationSource,
      "--qwerty-source",
      join(temporaryRoot, "input-archive", "qwerty-us-v1.json"),
      "--confusables-source",
      join(
        temporaryRoot,
        "input-archive",
        "unicode-17.0.0-confusables.txt.gz",
      ),
      "--output-dir",
      outputDirectory,
    ],
    { stdio: "inherit" },
  );
}

async function assertDirectoriesEqual(leftDirectory, rightDirectory) {
  const leftFiles = (await readdir(leftDirectory)).sort();
  const rightFiles = (await readdir(rightDirectory)).sort();
  if (JSON.stringify(leftFiles) !== JSON.stringify(rightFiles)) {
    throw new Error("generated file set differs from the frozen v1 output");
  }
  for (const file of leftFiles) {
    const left = await readFile(join(leftDirectory, file));
    const right = await readFile(join(rightDirectory, file));
    if (!left.equals(right)) {
      throw new Error(`${file} is not byte-identical`);
    }
  }
}
