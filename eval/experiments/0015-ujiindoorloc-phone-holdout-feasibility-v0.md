# Experiment 0015: UJIIndoorLoc phone-holdout feasibility v0

## Hypothesis

The verified UJIIndoorLoc corpus admits a four-role assignment that keeps every
acquisition phone in exactly one role while preserving all observed
building/floor groups in every role. Requiring users and phones to both remain
disjoint will instead expose a structural blocker because shared user/phone
edges connect otherwise separable phone groups.

## Method

Pre-implementation base revision: `992da68`.

The evaluator consumes the exact ignored archive and central fetch receipt
produced by:

```sh
just public-corpus-fetch ipin-2015-ujiindoorloc
```

It reuses the publisher-split v0 integrity, archive-inventory, CSV-schema, row,
and value gates. In memory, it aggregates rows by phone and by connected
components of the bipartite user/phone graph. A deterministic exhaustive
cover search asks whether train, calibration, validation, and test can each
cover every observed building/floor group while every holdout unit is assigned
exactly once. Necessary blockers are reported before search when fewer than
four units exist or any target group occurs in fewer than four units.

The hermetic contract is:

```sh
just ujiindoorloc-split-capability-check
```

The real-corpus run is:

```sh
just ujiindoorloc-phone-holdout-feasibility
```

The report retains aggregate counts only. It omits rows, RSSI vectors,
coordinates, timestamps, phone and user values, group assignments, member
paths, source URLs, and local paths. A found assignment is a feasibility
witness, not a benchmark recommendation; model-aware role sizing remains a
later preregistered decision.

## Data provenance

UJIIndoorLoc was the IPIN 2015 Track 3 dataset and is distributed by the UCI
Machine Learning Repository under CC BY 4.0, DOI `10.24432/C5MS59`. The checked
fetch manifest pins the 1,463,759-byte static archive by MD5 and SHA-256. The
archive, receipt, and derived reports remain ignored.

## Results

The real-corpus recipe passed after validating 21,048 rows, 25 phone groups,
and all 13 observed building/floor groups. Every target group occurred under at
least five phones. The deterministic witness assigned every row exactly once,
kept phone groups disjoint, and retained complete target coverage in all four
roles. Its aggregate role sizes were 5,106 rows/10 phones, 5,392 rows/2 phones,
5,077 rows/11 phones, and 5,473 rows/2 phones after the coverage-preserving
single-unit balancing pass.

The stricter user-plus-phone graph had 15 connected components, but at least
one building/floor group occurred in only one component. That is below the four
components required to cover the target in all roles, so the necessary support
condition blocked a joint user-and-phone-disjoint assignment before search.

The evaluator retained zero rows, RSSI vectors, coordinates, timestamps,
identifier values, group assignments, member paths, source URLs, and local
paths. A second run produced a byte-identical report. Re-running the original
publisher-split v0 path preserved its prior SHA-256 exactly:
`0072071161a8a74b71bdc092c911832206eeffdcb74d1a1208d9184b0cea5d0d`.

## Conclusion

The phone-only hypothesis held; the joint user-and-phone hypothesis was
correctly blocked. UJIIndoorLoc can therefore motivate a phone-domain holdout
baseline with shared building/floor coverage, but the feasibility witness is
not yet the benchmark split. The highly uneven phone counts behind similar row
counts make per-phone and per-building/floor metrics mandatory, and a later
experiment must preregister role proportions, model inputs, abstention policy,
and validation-only model selection before any performance result is run.
