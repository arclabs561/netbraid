# SDR4IoT packet/table/signal alignment v0

## Hypothesis

Within a publisher-defined SDR4IoT observation group, the packet capture, CSV
table, and publisher-named SigMF bundle describe the same ordered detections.
This is a cross-representation alignment claim within BLE or Zigbee, not a
cross-protocol event or identity claim.

## Registration boundary

One BLE group was inspected while designing the parser. The deterministic
largest complete group by total uncompressed member bytes is therefore the
development partition and cannot contribute to the evaluation result. Every
other complete three-layer group in the pinned archive is the evaluation
partition. The partition is selected from ZIP metadata before any member
payload is opened.

## Method

The evaluator must first pass the existing archive digest and layout checks.
For each complete group it then opens exactly one classic-PCAP member, one CSV
member, and one tar-contained SigMF pair under the existing per-member and
archive bounds. It checks:

1. packet, CSV-row, SigMF-capture, and SigMF-annotation counts are equal and
   nonzero;
2. CSV frame extents equal SigMF annotation sample counts;
3. SigMF capture and annotation sample starts agree and form one contiguous
   signal-data extent;
4. CSV frequency and sample rate equal the corresponding SigMF capture fields;
5. packet and CSV elapsed times agree within 2 milliseconds after removing one
   group-level constant clock offset; and
6. the signal-data byte extent and SHA-512 match the SigMF metadata.

The report retains only aggregate counts, maximum timing residuals, source
digests, and stable failure-reason counts. It must not retain member names,
publisher token values, packet bytes, signal samples, table rows, coordinates,
addresses, or timestamps.

## Success condition

The hypothesis is supported only if every evaluation-partition group passes all
six checks. A partial result remains useful as an inventory of which alignment
relations are and are not supported, but it does not establish synchronized
fusion input for the failing groups.

## Results

At producer commit `7fed040`, `just sdr4iot-layer-alignment` evaluated the
pinned archive twice and produced byte-identical 1,507-byte reports, both mode
0600. The archive had 218 complete filename groups. One was excluded as the
development partition; 3 of the remaining 217 groups passed every registered
check and 214 failed at least one check.

The evaluation partition contained 18,500 packet records, 13,718 CSV rows,
13,516 SigMF captures, 13,516 SigMF annotations, and 145,009,280 signal-data
bytes. Failure reasons are non-exclusive across groups:

| Reason | Groups |
|---|---:|
| layer count mismatch | 134 |
| nonzero count required | 126 |
| timing residual above 2 ms | 70 |
| invalid CSV timestamp | 8 |
| unsupported CSV schema | 2 |
| signal-data extent mismatch | 1 |

The largest observed relative-timing residual was 45.574018 seconds. Signal
bytes and source identifiers were not retained in either report.

The descriptive modality breakdown does not alter the gate. Of 94 evaluation
BLE groups, 72 had equal nonzero counts and exact table-to-signal structural
alignment; only 3 also met the clock rule. None of the 123 Zigbee groups had
equal nonzero counts across all four record sets. The excluded development
group is absent from these figures.

## Conclusion

The registered archive-wide hypothesis was rejected. Three sibling filenames
are not sufficient evidence that all three layers are populated or synchronized,
and the available packet and table clocks do not support the registered
2-millisecond rule for most count-comparable groups. This archive remains
useful for packet conformance and for narrower descriptive BLE alignment work,
but it is not an archive-wide packet/table/signal fusion oracle.

## Non-claims

Filename co-grouping and row alignment do not establish event identity across
protocols, physical-device or physical-source identity, location truth,
independent clock accuracy, packet-to-waveform causality, tamper, authorization,
intent, or maliciousness. The publisher's `.sigmf` suffix is treated as a tar
bundle until its contained metadata and data extent pass validation.
