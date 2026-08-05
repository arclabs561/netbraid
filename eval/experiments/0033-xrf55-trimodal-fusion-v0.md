# Experiment 0033: XRF55 trimodal fusion v0

## Hypothesis

An equal-weight fusion of reciprocal Wi-Fi, RFID, and mmWave event-relation
scores will have lower selective risk than each of its three constituent
modality-pair baselines on unseen complete performer/action groups, without
using a raw identifier, label, source value, or path as a model input.

The locked test is scored once only if the fused validation profile has ordered
thresholds, at least 50% decided coverage, no more than 5% false links, no more
than 10% false nonmatches, and strictly lower selective risk than every pair
baseline at no lower coverage, both overall and within each validation group.
The same comparisons are the descriptive test gate; no independent-row
significance claim will be made because pairs within a group share events and
fitted models.

## Method

Pre-implementation base revision: `e76895b`.

Preparation is hermetically checked with:

```sh
just xrf55-feature-cache-check
```

Before validation passes, private role caches will be compiled with:

```sh
uv run --script eval/compile-xrf55-feature-cache.py \
  --role-cache-dir data/derived/eval/xrf55-trimodal-fusion-v0
```

The cache compiler retains the existing deterministic performer/action group
ranking. Whole ranks 1 through 8 are train, 9 through 10 are calibration, 11
through 12 are validation, and 13 through 16 are locked test. Each group
contributes all 20 complete events, giving exact role counts of 160, 40, 40,
and 80. Groups cannot cross roles, and the Wi-Fi, RFID, and mmWave feature row
for one event always has the same role-local row. Each role has a separate
path-free adapter and three read-only-mmap-compatible NPY artifacts. The
default role-cache request excludes locked test; its raw member payloads and
private cache artifacts are opened only by a later explicit locked-test request
after the validation gate passes.

The evaluator fits all
six directed fixed-alpha 0.1 ridge maps on the 160 train events only. Feature
means, nonzero scales, active coordinates, and the positive paired-event mean
residual used to normalize each direction are train-only quantities. Dividing
each directed residual by its train mean gives every direction equal mean
before combination. Each unordered modality pair then receives the arithmetic
mean of its two reciprocal directed scores. The trimodal score is the
equal-weight arithmetic mean of the Wi-Fi/RFID, Wi-Fi/mmWave, and RFID/mmWave
symmetric scores; there is no learned fusion weight or pair selection.

Within each role and opaque group, the evaluator will score the complete
ordered event-pair grid. Equal event IDs are same-event references and all
other rows are different-event references. Calibration alone fixes, separately
for fusion and for each of the three pair baselines, the linear-interpolated
90th percentile of same-event scores and 10th percentile of different-event
scores. A profile is invalid unless the same threshold is strictly lower.
Scores at or below the same threshold decide same, scores at or above the
different threshold decide different, and scores between them abstain.

Validation applies the frozen profiles to its two unseen groups. It reports
coverage, abstention, selective risk, false-link and false-nonmatch counts and
rates, and same/different support for fusion and all three baselines, overall
and by opaque group. The locked test uses the same frozen models,
normalization, thresholds, and gates on four further unseen groups. Test data
cannot alter a model, normalization quantity, threshold, abstention policy, or
gate. Any missing role artifact, digest or shape mismatch, nonfinite value,
zero normalization mean, group overlap, row drift, or attempted pre-gate
locked-test open fails closed.

## Data provenance

The source is the receipt-bound XRF55 processed RF-array corpus already
profiled for experiments 0010 through 0013. This checkpoint selects 16 complete
opaque performer/action groups and all 20 synchronized trimodal events in each,
for 320 events total. Raw scene, performer, action, repetition, archive, member,
label, feature value, and local-path data exist only in ignored private inputs
or caches and are absent from this tracked record and from cache metadata.

The group axis is a split mechanism, not evidence of independent people,
devices, sessions, sites, physical sources, or principals. A same-event result
would establish only bounded cross-modal event relation in this corpus; it
would not establish identity, authentication, intent, authorization, tamper,
or maliciousness.

## Results

The hermetic evaluator suite passed 12 tests. It covers an independent naive
score oracle, exact metric and quantile oracles, role-isolation checks, gate
boundaries, content-bound validation replay, locked-test non-open and
single-use behavior, mmap access, deterministic private reports, and malformed
or tampered inputs.

The real pre-gate run completed with `calibration_failed`. For fusion and all
three pair baselines, the calibration same-event 90th-percentile residual was
higher than the different-event 10th-percentile residual, so none of the four
abstention profiles had ordered thresholds. Validation was not scored. The
locked-test adapter, matrices, and use marker were not created or opened.

## Conclusion

This fixed ridge-residual hypothesis failed at calibration and the locked test
remains closed. The result does not show that trimodal event relation is
impossible; it shows that these fixed summary features and independently
linear cross-modal maps do not produce the preregistered low-is-same ordering
on unseen performer/action groups. Any next model must be a new preregistered
experiment with new calibration and validation roles or a separately declared
follow-up question, not a threshold or weight adjustment against this failed
split.
