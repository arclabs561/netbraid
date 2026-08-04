# Experiment 0023: finite hypothesis belief metrics v1

## Hypothesis

Binding the belief-evaluation profile to canonical content and separating
heuristic Brier diagnostics from probability-forecast scoring will close the v0
provenance and interpretation gaps without changing the hand-computed metric.

## Method

Pre-implementation revision: `8800660`.

The canonical hermetic contract check is:

```sh
just hypothesis-belief-metrics-check
```

The v1 input carries an exact profile document plus its domain-separated
SHA-256. The document includes bounded family-specific configuration slots;
their completeness remains the caller's responsibility. The evaluator derives
the profile identifier and belief semantics from that document and rejects a
stale digest. The report retains only the profile identifier, digest, and
semantics. Per-axis output names the multiclass Brier measurement directly.
Heuristic-relative and model-posterior inputs use the same arithmetic but
receive different interpretations; selective scoring is reported with coverage
and outcome counts.

## Data provenance

The contract uses only authored hypothesis frames, integer belief vectors, and
one small profile document. It contains no captures, signal arrays, paths,
addresses, publisher identifiers, or local data.

## Results

The canonical contract check passed 11 tests. The fixed profile document
canonicalizes to one asserted byte string and its fixed SHA-256 vector is
`bf19a72d845b62b1755870e4d410378ad53283ba9b2d9c99f7a714d0c64a7134`.
Changing the profile identifier, belief semantics, or one configuration slot
while retaining the old digest fails closed. The report omits the profile
document.

The hand-computed Brier numerator and denominator are unchanged. Declaring the
same vector heuristic-relative or model-posterior leaves the arithmetic
identical while changing its report interpretation from
`heuristic_quadratic_diagnostic` to `probability_forecast_score`. The output no
longer contains a universal `proper_score` label. A non-hypothesis-frame RSSI
observer axis is rejected explicitly rather than implying generic variable
support.

## Conclusion

The hypothesis held for the hermetic contract. V1 binds the evaluation profile
to supplied canonical content and narrows the evaluator's genericity claim to
the relation ontology it actually validates. It still admits no probabilistic
family and measures no dataset-backed result. Probability-forecast Brier values
must be read with exact-row coverage and abstention counts because scoring is
selective.
