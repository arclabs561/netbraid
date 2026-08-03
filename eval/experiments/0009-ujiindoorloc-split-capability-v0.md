# Experiment 0009: UJIIndoorLoc split capability v0

## Hypothesis

The UJIIndoorLoc publisher split holds out anonymized users but not acquisition
phones: user-group overlap between training and validation will be zero, while
phone-group overlap will be nonzero. Building and building/floor overlap will
also be nonzero because they describe target-space coverage, not identity
separation.

## Method

Pre-implementation base revision: `70349e3`.

The evaluator consumes the exact ignored archive and central fetch receipt
produced by:

```sh
just public-corpus-fetch ipin-2015-ujiindoorloc
```

It verifies the pinned archive bytes and both digests, requires the exact two
publisher CSV members and 529-column schema, and streams at most 22,000 rows.
It reports only aggregate train/validation group counts and intersection counts
for user, phone, building, floor, building/floor, and location-cell axes. It
does not retain rows, coordinates, timestamps, RSSI vectors, identifier values,
member paths, source URLs, or local paths.

The hermetic contract is:

```sh
just ujiindoorloc-split-capability-check
```

The real-corpus run is:

```sh
just ujiindoorloc-split-capability
```

The evaluator must not collapse the axis reports into a generic “leakage”
label: user and phone are identity/domain holdout axes, while building, floor,
and location cells describe target-space coverage whose desired policy depends
on the downstream task.

## Data provenance

UJIIndoorLoc was the IPIN 2015 Track 3 dataset and is distributed by the UCI
Machine Learning Repository under CC BY 4.0, DOI `10.24432/C5MS59`. The checked
fetch manifest pins the current 1,463,759-byte static archive by MD5 and
SHA-256. Corpus and receipt bytes remain ignored.

## Results

The real-corpus run passed after validating 21,048 rows and 529 columns. The
publisher files had zero user-group intersections (18 training groups, one
validation group) but two phone-group intersections (16 training groups, 11
validation groups). Joint user/phone pairs remained disjoint.

All three buildings, all five floor labels, and all 13 building/floor groups
occurred in both files. Fine location-cell comparison was unknown rather than
disjoint: training exposed 905 cells, while every validation row used the
publisher's zero sentinel for both space and relative position, so validation
had no observed location-cell group.

The evaluator retained zero rows, RSSI vectors, coordinates, timestamps,
identifier values, member paths, source URLs, and local paths.
An independent second run produced a byte-identical report.

## Conclusion

The hypothesis was confirmed. The publisher split supports a user-disjoint
benchmark but not an independently phone-disjoint device/domain-shift claim.
That claim requires a new assignment with phone groups held out. Fine-grained
location-cell generalization cannot be scored from the validation file because
those labels are unobserved; reporting a zero overlap there would have been a
false disjointness claim.
