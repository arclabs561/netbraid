# Experiment 0020: UJIIndoorLoc phone-holdout baseline v0

## Hypothesis

A train-only standardized nearest-centroid classifier using only RSSI can
predict the 13 UJIIndoorLoc building/floor classes across acquisition-phone
holdouts while retaining at least 80% validation coverage, at most 50%
selective validation error, and at least 0.20 validation macro recall when
abstentions count as missed classes.

## Method

Pre-implementation base revision: `d6c4777`.

The fixed four-role split is the deterministic, coverage-preserving phone
assignment established by experiment 0015. Every phone belongs to exactly one
of train, calibration, validation, or test, every source row is assigned once,
and all 13 observed building/floor classes must occur in every role.

Only the 520 RSSI columns are model inputs. The publisher value `100` is a
missing-observation sentinel and is never treated as positive signal. Features
are retained only when observed in training, missing cells are encoded as
`-105` dBm, and zero-variance features are removed using training rows only.
Feature means, scales, and all 13 class centroids are fit from training only.
Prediction uses mean squared distance to the standardized centroids. A tied
nearest centroid always abstains.

Calibration chooses only among observed nonnegative nearest-versus-second
distance margins plus zero. Candidates deciding at least 80% of calibration
rows are ordered by lowest selective error, then highest coverage, then lowest
threshold. No validation or test value participates in feature handling,
centroids, or threshold selection.

Validation is read and scored after calibration. Test rows are not read for
model evaluation unless validation has complete 13-class support and meets all
three preregistered gates: coverage at least 0.80, selective error at most
0.50, and macro recall at least 0.20. A failed gate produces no test metrics.

The hermetic contract is:

```sh
python3 eval/test-evaluate-ujiindoorloc-phone-holdout.py
python3 eval/test-evaluate-ujiindoorloc-split-capability.py
```

The future real-corpus command is:

```sh
python3 eval/evaluate-ujiindoorloc-phone-holdout.py
```

The report records raw publisher/role/model-read reconciliation counts,
coverage, selective error, macro recall and macro F1, and anonymous per-phone
plus building/floor per-class metrics. It does not emit a single aggregate
accuracy. It retains no phone or user values, source rows, member or local
paths, coordinates, timestamps, or RSSI fingerprints.

## Data provenance

UJIIndoorLoc was the IPIN 2015 Track 3 dataset and is distributed by the UCI
Machine Learning Repository under CC BY 4.0, DOI `10.24432/C5MS59`. The central
fetch receipt pins the 1,463,759-byte static archive by MD5 and SHA-256. The
evaluator reconciles both publisher CSV members and all 21,048 expected rows
before constructing the phone-disjoint roles. Corpus and report bytes remain
ignored.

## Results

Not run. This preregistration was written before any real-corpus baseline run.
Only hermetic synthetic and unit tests may be executed during implementation.

## Conclusion

Pending the preregistered real-corpus run.
