# Experiment 0022: finite hypothesis belief metrics v0

## Hypothesis

A strict source-agnostic evaluator can measure finite relation beliefs without
collapsing relation axes or treating normalized heuristic weights as calibrated
probabilities. Exact multiclass Brier totals and raw confidence-bin counts
should distinguish better from worse held-out predictions, while unknown
references, solver abstentions, and infeasible components remain separate and
unscored.

## Method

Pre-implementation revision: `655e25c`.

The canonical hermetic contract check will be:

```sh
just hypothesis-belief-metrics-check
```

The input will contain one content-bound profile reference, validated v2
hypothesis frames, and bounded per-frame relation predictions. An exact
prediction must assign integer parts-per-billion mass to every non-unknown
state of exactly one declared relation axis, summing to one billion. Abstained
and no-feasible-assignment outcomes cannot carry beliefs.

References will be derived from the validated hypothesis frames rather than
copied into prediction rows. Per-axis reports will retain raw outcome and
reference counts, exact multiclass Brier numerators and denominators, unique and
tied maximum-state counts, and fixed-bin confidence sums. Brier is the primary
proper score. Confidence bins are diagnostic only; no expected calibration
error or aggregate cross-axis score will be reported.

## Data provenance

The contract test uses only small authored frames with documentation
identifiers and hand-computed integer beliefs. It contains no captures, signal
arrays, paths, addresses, publisher identifiers, or local data. Dataset-backed
campaigns remain separate consumers and must retain their own fit,
calibration, validation, and test provenance.

## Results

The hermetic contract check passed eight tests. The hand-computed binary oracle
has a total multiclass Brier numerator of
`400000000000000000` over denominator `2000000000000000000`, with one unique
correct prediction in the 0.6 confidence bin and one in the 0.8 bin. A separate
multiclass fixture retains a tied maximum instead of choosing a class by
serialization order.

The remaining tests prove that unknown references, assignment-budget
abstentions, and infeasible components are distinct and excluded from proper
scoring; exact rows require the complete axis-specific non-unknown state set and
one-billion PPB sum; non-exact outcomes cannot carry beliefs; profile, stratum,
row, duplicate-key, nonfinite-JSON, and input-byte bounds fail closed; reports
are input-order invariant and aggregate-only; and CLI failure emits no partial
report.

## Conclusion

The hypothesis held for the synthetic contract. The evaluator can compare
finite relation beliefs without asserting calibration or collapsing unlike
axes. No dataset-backed model result was measured, so this checkpoint admits no
probabilistic relation family. A real campaign must supply its own content-bound
profile, leakage-safe roles, and held-out frames before these metrics carry
empirical weight.
