# Provenance benchmarks

`provenance_paths.rs` separates graph construction, single comparisons,
finite-composition construction, and provenance-qualified composition. Fixture
construction and semantic assertions stay outside the timed loops.

Run the complete benchmark with:

```sh
cd rust
cargo bench --bench provenance_paths
```

For a saved comparison:

```sh
cargo bench --bench provenance_paths -- --save-baseline before
# make one change
cargo bench --bench provenance_paths -- --baseline before
```

## Sorted-record lookup

Baseline commit `67b4d11` rebuilt a `BTreeMap` over every graph record during
each ancestry query. Commit `48d7d1c` instead binary-searches the graph's
already-canonical sorted record array. Both runs used Criterion 0.8.2, Rust
1.97.1 on `aarch64-apple-darwin`, 30 samples, a one-second warmup, and a
two-second measurement window:

```sh
cargo bench --bench provenance_paths -- \
  --save-baseline before --sample-size 30 \
  --warm-up-time 1 --measurement-time 2
cargo bench --bench provenance_paths -- \
  --baseline before --sample-size 30 \
  --warm-up-time 1 --measurement-time 2
```

The table reports Criterion's point estimates from that run.

| Workload | Before | After | Criterion comparison |
|---|---:|---:|---:|
| Build a 1,024-record chain | 158.22 us | 158.16 us | no change |
| Same-reference comparison, 1,024 records | 18.433 ns | 18.714 ns | +1.70% |
| Deep-chain comparison, 1,024 records | 327.74 us | 294.99 us | -10.16% |
| External disjoint comparison, 1,024 records | 31.400 us | 556.84 ns | -98.23% |
| Construct 16 two-input claims | 1.1877 us | 1.1792 us | no change |
| Qualify 16 claims, empty graph | 192.73 us | 186.23 us | -3.19% |
| Qualify 16 claims, unrelated 1,024-record graph | 15.016 ms | 275.15 us | -98.16% |

The same-reference shift is below the five-percent microbenchmark threshold;
the graph-build and composition-only controls were flat. The binary-search
change was retained. A runtime ancestry cache was not added; it would add state
and invalidation concerns without evidence that the remaining deep-chain cost
matters to a consumer.
