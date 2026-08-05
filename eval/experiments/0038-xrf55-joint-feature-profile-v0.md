# Experiment 0038: XRF55 joint-feature reduction profile v0

## Hypothesis

Separating the shared publisher-array validation contract from the marginal
feature reducer will reduce median joint-feature wall time by at least 20% for
each XRF55 modality without changing the 512-value output or accepted input
contract.

## Method

From the pre-implementation revision `a455264`, run:

```sh
uv run --script eval/benchmark-xrf55-joint-features.py --rounds 3
just xrf55-joint-role-cache-check
```

The benchmark alternates the optimized reducer with a legacy-equivalent path
that computes and discards the 96 marginal features before computing the same
joint vector. Both paths consume one publisher-shaped in-memory array per
modality and must produce byte-identical binary64 vectors. The hermetic feature
suite remains the input-contract and exact-moment oracle.

## Data provenance

The timing input is generated in memory from the public publisher layout
contract and contains constant values only. It contains no downloaded corpus
rows, labels, identifiers, paths, or private data. The role-cache check uses
only authored synthetic arrays.

## Results

The benchmark produced byte-identical vectors for both paths. Median wall-time
reductions over three alternating rounds were 43.5% for Wi-Fi, 16.1% for RFID,
and 45.3% for mmWave. The corresponding optimized and legacy-equivalent median
seconds were:

| modality | optimized | with discarded marginal | reduction |
|---|---:|---:|---:|
| Wi-Fi | `0x1.0a403a0000000p-9` | `0x1.d738600000000p-9` | 43.5% |
| RFID | `0x1.3d8b400000000p-10` | `0x1.7ab3240000000p-10` | 16.1% |
| mmWave | `0x1.8c47a20000000p-9` | `0x1.6a704c0000000p-8` | 45.3% |

The five joint-feature tests passed, including the exact 512-value
channel-major moment oracle and a guard proving the marginal reducer is not
called. The nine joint-role-cache compiler tests also passed.

## Conclusion

The hypothesis held for Wi-Fi and mmWave but not for RFID's 20% threshold. The
shared validation seam removes real repeated work without changing the feature
contract, but this microbenchmark does not claim the same percentage for a
whole cache build, where archive access and publication also contribute. The
arrays are already compatible with read-only memory mapping; mapping cannot
remove arithmetic performed after access.
