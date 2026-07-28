# GH143 OSV bounded-concurrency benchmark

Generated on 2026-07-27 with:

```text
cargo run --locked --release -p argus-osv --example osv_parallel_benchmark
```

The harness performs one warmup followed by five measured runs for every jobs
value. Wall-clock results are reviewer evidence, not a CI threshold. Output
digest equality and the configured peak-concurrency bounds are hard assertions
inside the harness.

## Source identity

- Git HEAD: `8f292ec98665e1a47aa5f7a0654e6f229cf687d4`
- Worktree state: clean detached worktree at that exact implementation commit

## Environment

- OS: macOS
- Architecture: aarch64
- Available CPUs: 12
- Rust: `rustc 1.97.0 (2d8144b78 2026-07-07)`
- Peak RSS: unavailable (`null`)

Peak RSS is not emitted because the portable in-process harness does not have a
cross-platform RSS sampler. On macOS, an optional external run under
`/usr/bin/time -l` can provide it without changing benchmark semantics.

## Fixture and deterministic output

- Coordinate queries: 4,000
- Querybatch chunks: 4
- Advisory details: 32
- Deterministic service delay: 15 ms per request
- Fixture SHA-256:
  `6c0d0db205e54f6bb7554bb9ba2367af3c4685da3327185d4d7e01517b7cd08f`
- Output SHA-256:
  `8d63a8582d68ccc499af181e086db684a4ce944b9a88e3badcce7bb11bd48b95`

Independent release-process executions produced the same fixture and output
digests. Within each execution, the harness also checks every warmup and
measured run at jobs 1, 2, 4, and 8 against the same output digest.

## Results

Times are milliseconds.

| jobs | warmup | five measured runs | median | range | observed/expected peak | speedup vs jobs=1 |
|---:|---:|---|---:|---:|---:|---:|
| 1 | 746.745 | 717.565, 745.337, 753.327, 757.738, 772.101 | 753.327 | 717.565–772.101 | 1/1 | 1.000x |
| 2 | 401.154 | 392.752, 396.227, 400.281, 404.727, 408.612 | 400.281 | 392.752–408.612 | 2/2 | 1.882x |
| 4 | 224.791 | 216.724, 221.297, 223.862, 224.934, 225.842 | 223.862 | 216.724–225.842 | 4/4 | 3.365x |
| 8 | 135.522 | 129.981, 130.313, 132.884, 133.153, 134.054 | 132.884 | 129.981–134.054 | 8/8 | 5.669x |

The measured peak equals `min(jobs, 8)` for every jobs value. The timing
improvement is consistent with bounded window execution, while digest equality
proves that concurrency did not change the normalized snapshot.
