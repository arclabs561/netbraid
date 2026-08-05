# OPERAnet exp018 semantic alignment v0

## Hypothesis

The publisher's exp018 Kinect, power, and two UWB payloads contain enough
measured timestamp and activity-label agreement to establish bounded semantic
joinability across those four modalities.

This is a development checkpoint. Exp018 was inspected while designing the
reader, so it cannot serve as a held-out evaluation partition or support an
archive-wide result.

## Method

Producer commit: pending checkpoint.

Run `just operanet-semantic-alignment-profile`. The recipe first verifies the
hermetic parser and alignment contracts. It then verifies the pinned archives
and receipts, opens only the selected exp018 members, and reads:

- required semantic columns from the Kinect and power MATLAB v5 cell arrays;
- required semantic columns from the two UWB CSV streams; and
- no Wi-Fi CSI payloads.

The profiler compares exact readable Kinect/power semantic rows and evaluates
all four activity streams on a 100 millisecond fixed grid. At each grid point,
it uses the latest sample no more than 150 milliseconds old and excludes points
within 50 milliseconds of any observed activity transition. The two generated
reports must be byte-identical.

The report retains aggregate counts, durations, gaps, cardinalities, and
agreement totals. It retains no participant or room values, raw timestamps,
raw rows, signal values, archive paths, or member paths.

## Data provenance

The inputs are the pinned `OPERAnet-kinect.zip`, `OPERAnet-pwr.zip`,
`OPERAnet-uwb1.zip`, and `OPERAnet-uwb2.zip` archives and their digest-bound
receipts from dataset DOI `10.6084/m9.figshare.16578299.v1`. The registered
publisher descriptor is `10.1038/s41597-022-01573-2`.

The profiler reads experiment 18 only. The publisher's same-local-NTP and
less-than-20-millisecond synchronization statements are recorded as provenance
but are not used as measured alignment results.

## Success condition

Joinability is established only if:

1. all four timelines have a positive overlap;
2. readable Kinect and power experiment, timestamp, and activity rows are
   exactly equal;
3. the fixed grid has at least one assessed point;
4. no assessed grid point lacks a modality or has an activity disagreement;
5. no duplicate timestamp carries conflicting activity labels; and
6. the repeated reports are byte-identical.

Any failed condition closes the joinability gate while retaining the bounded
descriptive profile.

## Results

Not recorded. The preregistered producer has not yet been run against the
pinned corpus.

## Conclusion

Pending the registered corpus run.

## Non-claims

This checkpoint does not establish multimodal feature fusion, cross-experiment
generalization, physical-device identity, participant identity, room identity,
positioning accuracy, clock accuracy, causal same-event identity, tamper,
authorization, intent, or maliciousness.
