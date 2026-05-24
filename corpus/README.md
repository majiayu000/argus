# argus regression corpus

Static, harmless fixtures used by `argus corpus test` to lock in detection-rule behaviour. Every fixture is **synthetic** — file contents look like a real npm attack pattern but never download, execute, or send anything real.

## Layout

- `index.json` — list of cases, each with `id`, `path`, `packageName`, `expectedDecision`, and `rules`.
- `fixtures/` — package directories. Each is a self-contained npm-style package with `package.json` + minimal `*.js`.
- `lockfiles/` — single-file lockfile cases (e.g. plain-HTTP `resolved` poisoning).
- `quarantine/` — empty by default; intended for *real* malicious tarballs the contributor downloads locally for static-only inspection. Not committed.

## Adding a case

1. Create the fixture under `fixtures/<id>/` (or a lockfile under `lockfiles/`).
2. Make sure every URL and host points at `.example.invalid` so DNS cannot resolve.
3. Append an entry to `index.json` with the expected decision + rule ids.
4. `cargo run -p argus-cli -- corpus test` must pass.
