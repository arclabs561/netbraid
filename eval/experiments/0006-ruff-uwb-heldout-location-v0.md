# RUFF-UWB held-out-location baseline v0

## Hypothesis

A physical-device classifier evaluated at globally held-out receiver locations
can be measured without location leakage if location assignment precedes row
sampling, prototype fitting uses train rows only, and configuration selection
uses validation rows only.

## Method

The checked-in evaluator fixes a seeded global 80/10/10 location split and
treats distance collection, physical source, physical device, and location as
one atomic row group. It bounds rows and windows per group, opens only a
digest-bound standalone two-dimensional NPY through read-only NumPy mmap, fits
centroid and centroid-nearest-template candidates on train windows, chooses
between them on validation macro-F1 and balanced accuracy, and reports the
chosen candidate once on test. Reports retain aggregate metrics, opaque split
receipts, and an aliased confusion matrix, but no paths, rows, locations, or
publisher source identifiers.

The canonical commands are:

```sh
just public-corpus-fetch ruff-uwb-1m-npy
just ruff-uwb-row-adapter-check
just ruff-uwb-row-adapter
just ruff-uwb-heldout-location-check
just ruff-uwb-heldout-location
just ruff-uwb-heldout-location-real
```

## Data provenance

The aggregate boundary consumes the ignored
`netbraid.ruff_uwb_observation_oracles.v0` artifact compiled from the two pinned
publisher archives. The real boundary additionally consumes a central fetch
receipt and `netbraid.ruff_uwb_row_adapter.v0` compiled from the pinned
one-meter archive. The compiler verifies the complete archive, label-member,
and waveform-member contracts; preserves publisher row order as 645 gap-free
opaque spans; and stream-extracts 771,232 rows to a private standalone NPY.
The evaluator rehashes that 3,084,928,128-byte NPY before opening it read-only
through NumPy mmap.

## Result

The synthetic exact-oracle suite exercises deterministic partitioning,
non-overlap, held-out-test isolation, exact metrics, read-only mmap, malformed
row and waveform contracts, and path-free output. The aggregate-only command
still records `oracle_row_mapping_unavailable`; it does not silently assume row
order.

The receipt-bound real command completed with zero row, location, or atomic
group overlap. It assigned 40 locations to train, five to validation, and five
to test. Bounded sampling selected 4,120 train rows and 520 rows for each held-
out split, with four 128-sample windows per row. Validation selected the
centroid candidate at macro-F1 0.100123586080 and balanced accuracy
0.101923076923 over the template candidate. The single test evaluation reached
macro-F1 0.068668798186 and balanced accuracy 0.075000000000 across 13 devices
and 520 sampled rows.

Uniform-chance balanced accuracy for 13 devices is approximately 0.076923.
The measured baseline therefore provides no evidence of device discrimination
that generalizes to held-out locations under this representation and protocol.
It is a valid negative result, not a failed data pipeline.

## Conclusion

The scripted row adapter closes the original correspondence blocker and makes
the complete one-meter corpus evaluable without loading the waveform array into
memory. The simple centered amplitude-shape prototype does not survive location
holdout. Next experiments should change one preregistered factor at a time—
feature representation, cross-distance split, or open-set device holdout—while
retaining the same row binding, leakage audit, validation-only selection, and
single-use test boundary.
