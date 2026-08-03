# Experiment 0016: XRF55 calibrated event relation v0

## Hypothesis

A reciprocal, fit-only linear alignment of XRF55 Wi-Fi and RFID features can
support a selective same-event decision on held-out repetitions without
turning performer, device, source, identifier, principal, variant, intent, or
tamper relations into model claims.

The validation gate requires both directional calibration thresholds to be
ordered, at least 50% decided coverage, no more than two different-to-same
errors among 48 different-event pairs, no more than two same-to-different
errors among 24 same-event pairs, and lower selective risk than the unaligned
control at no lower coverage. The locked test role is scored once only if that
gate passes.

## Method

Pre-implementation base revision: `cbe5677`.

The canonical hermetic contract check is:

```sh
just xrf55-calibrated-event-relation-check
```

The later real-data command is:

```sh
just xrf55-calibrated-event-relation
```

The evaluator reuses experiment 0013's receipt-bound, path-free feature cache
and read-only NumPy memmaps. It preregisters one unordered modality pair,
Wi-Fi and RFID, instead of selecting the strongest result among all six
directions after evaluation. Publisher repetitions have fixed roles:

- fit: 1 through 8;
- calibration: 9 through 11;
- validation: 12 through 14;
- locked test: 15 through 20.

Standardizers and fixed-alpha 0.1 ridge maps are fit separately for Wi-Fi to
RFID and RFID to Wi-Fi using only the 64 fit events. Event and group IDs,
repetitions, row order, paths, and archive grammar may form roles and reference
pairs but never enter feature standardization, model fitting, distance scoring,
or threshold selection.

Within each opaque performer/action group and role, the evaluator scores the
complete cross-modal Cartesian product. Equal repetitions are same-event
references and unequal repetitions are different-event references. Calibration
and validation therefore each contain 24 same and 48 different pairs; test
contains 48 same and 240 different pairs.

Each direction uses mean squared residual distance in the train-standardized
target feature space. Calibration alone selects the linear-interpolated 90th
percentile of same-event distances as its same threshold and the 10th
percentile of different-event distances as its different threshold. A profile
is invalid unless the same threshold is strictly lower. A direction decides
same at or below the same threshold, different at or above the different
threshold, and abstains between them. The final relation decides only when the
reciprocal directions agree; direct conflict records
`direction_disagreement`, while a threshold gap records `score_gap`.

The strict `netbraid.calibrated_event_relation_profile.v0` profile binds the
feature policy, input matrices, fitted models, fit partition, calibration
partition, reducer revision, thresholds, and quantile policy by digest.
Predictions bind that profile and retain canonical nonnegative binary64 scores
as `float.hex()` text. They are scores, not probabilities. The metrics adapter
sets only `event_relation`; every other relation axis must be `abstain`.

The all-abstain control exposes selective-risk gaming. The unaligned control
uses the same role and threshold procedure without a learned cross-modal map.
Reports retain raw confusion, support, coverage, abstention, selective-risk,
false-link, false-nonmatch, and reciprocal-disagreement counts overall and by
opaque group. Pair rows share events, groups, and thresholds, so no naive
binomial or row-bootstrap interval is reported.

## Data provenance

The inputs are the ignored outputs of experiment 0013: 160 synchronized events
across eight complete opaque performer/action groups, all 20 publisher
repetitions, and three modalities. This experiment reads only the Wi-Fi and
RFID matrices plus their adapter. No raw scene, performer, action, archive,
member, local-path, address, claimed identifier, or principal value may enter
the profile, predictions, or report.

The publisher grid supplies the event reference. It does not expose an
independent acquisition-session axis, and all eight groups recur across roles.
This is a bounded cross-modal event-relation smoke evaluation, not an
independent-session, unseen-performer, physical-device, physical-source, or
authentication benchmark.

## Results

The strict profile and prediction schema checkpoint passes ten hermetic tests.
It covers exact-shape parsing, bounded and duplicate-safe JSON, canonical
nonnegative finite score encoding, content binding, ordered thresholds, all
nine reciprocal direction-state combinations, forged decisions and abstention
reasons, and rejection of identity-bearing fields.

The five-test hermetic evaluator suite also passes. It proves the exact 72-row
calibration and validation partitions and 288-row test partition, immutable
fit/calibration results under changed test rows, a projection that changes only
`event_relation`, validation failure before any test score, read-only memmap
loading, deterministic private reports, and explicit failure of an unaligned
control whose calibration thresholds overlap. The synthetic transformed
fixture intentionally fails the validation gate rather than opening test.

The real-corpus result is pending. No model-performance claim is made at this
checkpoint.

## Conclusion

The score-to-decision contract is narrow enough to evaluate without changing
the Rust hypothesis engine. A production learned family is considered only
after the hermetic evaluator, validation gate, and one-shot real result exist.
Even a successful same-event result authenticates no performer, device,
physical source, identifier, principal, intent, or tamper state, and pairwise
same-event predictions must not be transitively merged into persistent
identities.
