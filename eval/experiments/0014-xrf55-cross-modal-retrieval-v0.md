# Experiment 0014: XRF55 cross-modal retrieval v0

## Hypothesis

A train-only linear alignment of the geometry-aware XRF55 feature cache will
beat both the theoretical six-candidate chance rate and the unaligned-feature
control on exact-event top-1 retrieval in at least four of six ordered modality
directions.

## Method

Pre-implementation base revision: `135b850`.

The canonical real-data run is:

```sh
just xrf55-cross-modal-retrieval
```

The target first compiles experiment 0013's ignored private cache twice. The
evaluator verifies the path-free adapter, complete 8-group by 20-repetition
grid, artifact sizes and SHA-256 digests, then opens each matrix with
`np.load(..., mmap_mode="r", allow_pickle=False)`. A symlink, changed file,
digest mismatch, dtype/shape drift, nonfinite value, split drift, or incomplete
candidate group fails closed.

For each of the six ordered Wi-Fi/RFID/mmWave directions:

1. Fit source and target means, population standard deviations, and active
   feature sets using only publisher repetitions 1–14 (112 paired events).
2. Fit a ridge map from standardized source features to standardized target
   features with fixed alpha 0.1 and no test-data selection.
3. For each repetition 15–20, rank only the six target events in the same
   opaque performer/action group by squared Euclidean distance in the
   train-standardized target space.
4. Report exact-event top-1 rate and mean reciprocal rank over 48 queries, plus
   the same metrics for every opaque group.

The unaligned control directly compares separately train-standardized source
and target 96-value vectors without a learned map. The theoretical chance
references are top-1 `1/6` and MRR `H_6/6`. Directions remain separate; no
macro-average can hide a weak modality pair.

Alpha 0.1 was fixed before opening real cache rows. On an exactly linear
synthetic oracle, alpha 1.0 over-shrank held-out predictions to 32–40 correct
queries per direction; a one-variable diagnostic showed alpha 0.1 restored
48/48 in every direction. This numerical sanity choice is not a real-data
hyperparameter sweep.

## Data provenance

The input adapter and matrices are the ignored outputs of experiment 0013.
They derive from 160 synchronized XRF55 events: eight deterministic complete
performer/action groups, all 20 publisher repetitions, and all three RF
modalities. No raw scene, performer, action, archive, member, or local-path
value is retained in the evaluator report.

## Results

The six-test hermetic evaluator suite passes. It covers exact recovery in all
six directions for an independently transformed linear latent fixture,
read-only mmap loading, byte-deterministic private reports, matrix tamper
rejection before mmap, split/candidate drift rejection, all-constant feature
rejection, and deterministic opaque-ID tie breaking.

Real XRF55 metrics are not recorded yet because the concurrent Oregon State
LoRa fetch remains the sole heavy-I/O lane.

## Conclusion

Pending the real campaign. The hypothesis is supported only if at least four
ordered directions beat both controls on top-1. MRR and per-group results are
diagnostics, not substitutes for that preregistered gate. A failure would
motivate revisiting the feature representation or a nonlinear alignment only
after inspecting which directions and groups fail; it would not justify tuning
against repetitions 15–20.
