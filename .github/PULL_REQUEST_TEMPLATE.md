<!--
Thanks for contributing to argus!

A few project conventions before you open this PR:

- Every commit must carry a DCO `Signed-off-by` trailer (`git commit -s`).
- Do NOT add `Co-Authored-By` lines or any AI-generation markers.
- Run `pre-commit run --all-files` locally (see README "Development").
- New code must come with tests. Detection rules also need a corpus
  fixture under `corpus/`.
-->

## Summary

<!-- One or two sentences. What does this PR change and why? -->

## Type of change

<!-- Pick the closest match; delete the rest. -->

- feature
- bug fix
- detection rule
- refactor / cleanup
- docs

## Test plan

<!--
List the verification you ran in this session. Fresh evidence only —
"it passed earlier" does not count.
-->

- [ ] `cargo test --workspace`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo run -p argus-cli -- corpus test --corpus corpus`
- [ ] If this PR adds or changes a detection rule: matching corpus
      fixture added under `corpus/<name>/` with `expected.json`.
- [ ] If this PR touches the Sigstore path: tests run with
      `--features sigstore` enabled.

## Related issues

<!-- e.g. Closes #42, Tracks #22 -->
