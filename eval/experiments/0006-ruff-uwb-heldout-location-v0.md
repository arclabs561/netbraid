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
just ruff-uwb-heldout-location-check
just ruff-uwb-heldout-location
```

## Data provenance

The production boundary consumes the ignored
`netbraid.ruff_uwb_observation_oracles.v0` artifact compiled from the two pinned
publisher archives. The one-meter archive is bound by SHA-256 in the evaluator.
The current compiler opens only bounded label arrays and emits aggregate
source/location/campaign cells; it does not open waveform members.

## Result

The synthetic exact-oracle suite exercises deterministic partitioning,
non-overlap, held-out-test isolation, exact metrics, read-only mmap, malformed
row and waveform contracts, and path-free output. The real production command
records `oracle_row_mapping_unavailable` before opening a waveform: oracle v0
contains counts but no row indices, row spans, row-order contract, or digest
binding to a standalone mmap-able NPY.

No RUFF-UWB corpus metric was computed. Unknown row correspondence is not an
evaluation result and is not repaired by assuming archive member order.

## Conclusion

The baseline protocol and executable boundary are ready, but the current data
adapter is insufficient. The next admissible step is a scripted row-mapping
compiler that binds every label record to one standalone NPY row and its exact
archive/member digest. Until that contract exists, the canonical result is the
reproducible blocker rather than a classifier score.
