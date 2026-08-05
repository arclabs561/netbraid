# OPERAnet exp018 semantic alignment v0

## Hypothesis

The publisher's exp018 Kinect, power, and two UWB payloads contain enough
measured timestamp and activity-label agreement to establish bounded semantic
joinability across those four modalities.

This is a development checkpoint. Exp018 was inspected while designing the
reader, so it cannot serve as a held-out evaluation partition or support an
archive-wide result.

## Method

Producer commit: `fdf354e1776e5e4670488f3057480f6cfc6171a3`.

Run `just operanet-semantic-alignment-profile`. The recipe first verifies the
hermetic parser and alignment contracts. It then verifies the pinned archives
and receipts, opens only the selected exp018 members, and reads:

- the complete pinned Kinect and power MATLAB v5 cell variables, from which it
  retains only required semantic columns;
- required semantic columns from the two UWB CSV streams; and
- no Wi-Fi CSI payloads.

The profiler stably orders each stream by its parsed time-of-day value while
retaining aggregate source-order inversion counts and maximum backward jumps.
It rejects any adjacent source-order inversion above 1 millisecond.
It compares exact readable Kinect/power semantic rows and evaluates all four
activity streams on a 100 millisecond fixed grid. At each grid point, it uses
the latest sample no more than 150 milliseconds old and excludes points within
50 milliseconds of any observed activity transition. The two generated reports
must be byte-identical.

The report retains aggregate counts, durations, gaps, cardinalities, and
agreement totals. It retains no participant or room values, raw timestamps,
raw rows, signal values, archive paths, or member paths.

## Data provenance

The inputs are the pinned `OPERAnet-kinect.zip`, `OPERAnet-pwr.zip`,
`OPERAnet-uwb1.zip`, and `OPERAnet-uwb2.zip` archives and their digest-bound
receipts from collection DOI `10.6084/m9.figshare.c.5551209.v1`. The registered
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

At the producer commit above, `just operanet-semantic-alignment-profile` read
the four pinned exp018 members twice and produced byte-identical 7,301-byte
reports, both mode 0600. The joinability gate was blocked.

The four timelines had a positive 903,463,236-microsecond intersection. Kinect
and power each contained 9,149 semantic rows; their experiment, timestamp, and
activity fields were exactly equal on every row. UWB1 contained 340,964 rows,
and UWB2 contained 195,438 rows.

The fixed grid had 9,035 candidate points. It excluded 308 transition-boundary
points and assessed the remaining 8,727 with no missing-modality points. Of
those assessed points, 5,875 had one activity label across all four modalities
and 2,852 disagreed. UWB1 also contained 57 conflicting activity labels among
229,789 duplicate-timestamp rows.

UWB2 contained 1,073 adjacent source-order inversions. Their maximum backward
jump was 96 microseconds, within the registered 1-millisecond normalization
bound. No other modality had a source-order inversion.

The reports retained no participant or room values, raw timestamps, raw rows,
signal values, archive paths, or member paths. The publisher's clock statement
remained provenance rather than a measured result.

## Conclusion

The hypothesis was rejected. Exp018 does not provide a clean four-modality
activity-join oracle under the registered fixed-grid protocol, despite exact
Kinect/power semantic equality and complete grid coverage. The activity
disagreements and UWB1 duplicate-label conflicts close the gate.

The result still identifies a narrower exact Kinect/power semantic relation and
a bounded negative cross-modality case. Any revised temporal policy must be
registered on another experiment or partition rather than tuned against these
development results.

## Non-claims

This checkpoint does not establish multimodal feature fusion, cross-experiment
generalization, physical-device identity, participant identity, room identity,
positioning accuracy, clock accuracy, causal same-event identity, tamper,
authorization, intent, or maliciousness.
