# Experiment 0018: RUFF-UWB cross-campaign transfer v0

## Hypothesis

A publisher-aligned common magnitude projection may preserve more physical-
device information than uniform chance when prototype rules are fit on the
one-meter campaign and evaluated once on the two-meter campaign, despite the
combined distance, day, room-position, and stored-representation shift.

Balanced accuracy at or below the 1/13 uniform-chance baseline would falsify
that prediction for this projection and protocol.

## Method

Status: preregistered; the real two-meter extraction and evaluation have not
been executed. Implementation baseline before this experiment is `cf40d57`;
the evaluator, exact-oracle suite, recipe, and this log land together in the
next checkpoint.

The source campaign retains experiment 0006's seeded 80/10/10 location
assignment. Prototype candidates are fit only on its 40-location train role and
selected only on its five-location validation role. The previously observed
five-location one-meter test role is quarantined: it has zero feature rows and
is never predicted or scored. Every two-meter location is assigned to the sole
target-test role before bounded row sampling.

The common projection converts each row to magnitude, aligns the maximum
positive magnitude gradient to sample 40, crops a common 200-sample prefix,
then mean-centers and L2-normalizes four deterministic 128-sample windows. This
explicitly reconciles the publisher archives' complex-250 and real-200 stored
representations; it does not establish that those representations are
semantically equivalent.

The canonical commands are:

```sh
just ruff-uwb-cross-campaign-check
just ruff-uwb-two-meter-row-adapter
just ruff-uwb-cross-campaign-transfer
```

## Data provenance

- Source: pinned RUFF-UWB one-meter NPY archive and central fetch receipt.
- Target: pinned RUFF-UWB two-meter NPY archive and central fetch receipt.
- Publisher design: the same 13 transmitting boards and receiver were used;
  the campaigns were recorded on different days, at different positions in the
  same room, and at relative distances of one and two meters.
- Source rows: 771,232 across 50 locations; source test locations remain
  assigned but unused.
- Target rows: 1,152,491 across 100 locations, all assigned to target test
  before bounded sampling.
- Stored arrays: source `<c16` with 250 samples per row; target `<f8` with 200
  samples per row.
- Retention: archives, standalone arrays, row adapters, and generated reports
  remain ignored. The checked-in code retains only public immutable metadata.

The evaluator requires exact equality of source-to-device opaque alias maps
across adapters. This assumes the publisher's shared numeric labels identify
the same physical boards across campaigns; no serial-number evidence is
available in the corpus.

## Results

The seven-test synthetic suite passes. It covers exact production-binding
projection from the compiler registry, deterministic transfer with overlapping
collection-local row indices, source-test non-use, target perturbation
isolation, pre-I/O identity rejection, pre-I/O feature-memory rejection,
read-only mmap, and path-free output.

Real target metrics are not recorded because the two-meter standalone NPY has
not yet been extracted. No predictive conclusion is available.

## Conclusion

The protocol is executable and its leakage boundary is tested, but the
hypothesis remains open. The eventual result is a cross-campaign transfer
measurement, not an isolated distance effect: distance, day, room position,
and stored representation all change together.

The production run also has a known cost outside the bounded feature sample:
adapter loading materializes roughly 1.9 million row records, and source
verification hashes approximately 4.93 GB before opening the two arrays by
read-only mmap. Those costs must be measured or reduced before presenting the
recipe as a fast path.
