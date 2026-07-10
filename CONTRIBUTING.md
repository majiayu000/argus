# Contributing to argus

Thank you for helping improve argus. Because argus is a security tool, reports
and changes should include concrete, reproducible evidence and should not
execute untrusted package code.

## Reporting issues

Search the [existing issues](https://github.com/majiayu000/argus/issues) before
opening a new one.

- Use the [bug report](https://github.com/majiayu000/argus/issues/new?template=bug_report.yml)
  for CLI, library, or rule behavior that is broken. Include the exact command
  and output, expected behavior, argus version or commit, OS, and Rust version.
- Use the [false-positive form](https://github.com/majiayu000/argus/issues/new?template=false_positive.yml)
  when a legitimate package is blocked or requires approval. Include the
  ecosystem, package and version, complete output and rule IDs, and specific
  source or upstream evidence that the behavior is benign.
- Use the [false-negative form](https://github.com/majiayu000/argus/issues/new?template=false_negative.yml)
  when a package with concrete malicious behavior is not blocked. Include the
  ecosystem, package and version, complete output, relevant file paths and
  lines, and any public advisories or analyses. Suspicion alone is not enough.

Do not commit real malicious archives. Prefer a minimal synthetic reproducer.
Hosts in the main package corpus and synthetic hosts used by network-capable
fixture code must use `.example.invalid`. A pure-text benign regression fixture
may quote a verifiable official host only when it cannot execute or request it.

For a vulnerability in argus itself or one of its dependencies, do not open a
public issue. Submit a
[private GitHub security advisory](https://github.com/majiayu000/argus/security/advisories/new).

## Suggesting features

After searching existing issues, open a
[new issue](https://github.com/majiayu000/argus/issues/new) describing the user
problem, expected behavior, and relevant threat model. For ecosystem support,
include the registry, package formats, integrity or provenance data available,
and representative package metadata or attack patterns.

## Development setup and style

The workspace uses Rust 2021 and declares Rust 1.75 as its minimum supported
version. CI builds with the stable toolchain and requires `rustfmt` and
`clippy`. If you use `rustup`, install those components with:

```sh
rustup component add rustfmt clippy
```

Install the repository hooks once per clone:

```sh
uv tool install pre-commit        # or: pipx install pre-commit
pre-commit install
pre-commit install -t pre-push
```

Use `cargo fmt` for Rust formatting and keep the workspace free of Clippy
warnings. Run all configured hooks with `pre-commit run --all-files`.

## Tests and corpus fixtures

New code must include tests for the changed behavior. Before opening a pull
request, run the same checks as CI:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
cargo run -q -p argus-cli -- corpus test --corpus corpus
```

If a change touches the Sigstore path, also run the relevant tests with the
`sigstore` feature enabled and record the command in the pull request.

Every new or changed detection rule also needs a harmless regression fixture
in the applicable corpus. For the main corpus:

1. Add a synthetic package under `corpus/fixtures/<id>/`, or a lockfile under
   `corpus/lockfiles/`.
2. Add the case to the applicable `index.json` with its ID, path, package name,
   expected decision, and expected rule IDs.
3. Use `.example.invalid` for every main-corpus host and for any synthetic host
   that network-capable fixture code can request. A pure-text benign regression
   fixture may quote a verifiable official host only when it cannot execute or
   request it. No fixture may download, execute, or exfiltrate anything in tests.
4. Cover the intended detection and, when relevant, the benign behavior that
   must not become a false positive.
5. Run the corpus command above. Agent-surface fixtures belong under
   `corpus/agent/` and use that directory's `index.json`.

## Commits and pull requests

Every commit must include a Developer Certificate of Origin sign-off. Create
signed commits with:

```sh
git commit -s
```

Verify that each commit message contains a `Signed-off-by: Name <email>`
trailer. Do not add `Co-Authored-By` trailers or AI-generation markers.

When opening a pull request:

1. Explain what changed and why, choose the change type, and link the related
   issue using `Closes #<number>` for completed work or `Tracks #<number>` for
   partial work.
2. Add or update tests and corpus fixtures required by the change.
3. Update user-facing documentation or the relevant design document when
   behavior, architecture, commands, or security guarantees change. Add
   notable user-visible changes to the `CHANGELOG.md` `[Unreleased]` section.
4. Run fresh verification, complete the pull request test plan with the exact
   commands executed, and let the authoritative CI checks pass.
