# Experiment 0035: XRF55 joint representation adequacy v0

## Hypothesis

The fixed 512-value joint-grid representation will preserve enough
channel-by-sequence and channel-by-space structure for each reciprocal XRF55
modality pair to calibrate an ordered selective same-event relation and pass
the preregistered validation quality gates on unseen opaque groups.

This is a representation-adequacy experiment. It does not select or combine
modality pairs, learn fusion weights, or define a locked-test role.

## Method

Pre-implementation base revision: `a41636e`.

The hermetic representation and partition contract is checked with:

```sh
uv run --script eval/test-xrf55-joint-features.py
```

A later evaluator must run without data-dependent arguments through:

```sh
uv run --script eval/evaluate-xrf55-joint-representation-adequacy.py
```

The feature reducer validates each input through the existing XRF55 feature
contract before reduction. Wi-Fi and RFID use the Cartesian product of eight
channel bins and 16 sequence bins. mmWave removes its singleton axis and uses
the Cartesian product of eight channel bins and a row-major 4 by 4 spatial
grid. Every joint region contributes, in order, mean, population standard
deviation, mean absolute value, and root mean square. Channel bins are the
outer order, yielding exactly 512 binary64 values per modality. Labels and
metadata are not features.

The existing domain-separated opaque group ranking selects 20 complete groups.
Whole ranks 1 through 8 are train, 9 through 16 are quarantined and omitted,
17 through 18 are calibration, and 19 through 20 are validation. Every group
contains all 20 synchronized events, giving exact role counts of 160 train, 40
calibration, and 40 validation events, plus 160 unused quarantine events.
Groups cannot cross roles. Validation is the terminal evidence role for this
experiment; no test role is created later from the quarantined ranks.

The later evaluator will retain experiment 0033's fixed pair mechanics while
removing fusion. Train-only means, population standard deviations, and active
coordinates standardize each modality. Six directed ridge maps, one for every
ordered modality pair, use fixed alpha 0.1. Each direction's mean paired-event
train residual is its fixed positive normalizer. For each unordered modality
pair, the score is the arithmetic mean of its two normalized directed mean
squared residuals. No direction, pair, coordinate, alpha, normalization rule,
or weight may be selected from calibration or validation results.

Within each opaque group and role, all 20 by 20 ordered event pairs are scored.
Equal opaque event IDs are same-event references; all other pairs are
different-event references. Calibration alone fixes, separately for each of
the Wi-Fi/RFID, Wi-Fi/mmWave, and RFID/mmWave pairs, the linear-interpolated
90th percentile of same-event scores and 10th percentile of different-event
scores. The same threshold must be strictly lower. Scores at or below it decide
same, scores at or above the different threshold decide different, and scores
between them abstain.

Calibration passes only if all three pair profiles have ordered thresholds.
Validation passes only if every pair, both overall and in each validation
group, has at least 50% decided coverage, at most 5% different-to-same error,
and at most 10% same-to-different error. Reports must include support, coverage,
abstention, selective risk, false-link, and false-nonmatch counts and rates for
each pair overall and by opaque group. Pair rows share events and fitted models,
so no independent-row significance claim or macro-average is permitted.

## Data provenance

The source is the receipt-bound processed XRF55 RF-array corpus used by the
earlier XRF55 evaluations. The partition requires 20 complete opaque groups
and all 20 synchronized trimodal events in each, for 400 candidate events.
Only 240 events enter train, calibration, or validation; the other 160 remain
quarantined and unscored.

Raw scene, performer, action, repetition, archive, member, label, feature
value, and local-path data may exist only in ignored private inputs or caches.
Tracked policy, reports, and receipts retain only opaque event and group
digests, role-local rows, aggregate counts, policy fields, and content digests.
The group axis is a split mechanism, not evidence of independent people,
devices, sessions, sites, physical sources, or principals. A passing result
would support only bounded cross-modal event relation in this corpus.

## Results

Not executed. The real-data calibration gate, validation gate, cache
compilation, ridge fits, scores, and metrics have not been run. Hermetic policy
tests are implementation checks and do not count as experiment results.

## Conclusion

Pending execution by the later evaluator. Failure of any pair's calibration
order or any preregistered validation quality gate falsifies the joint
representation-adequacy hypothesis without changing bins, moments, model
mechanics, thresholds, pair selection, or role boundaries.
