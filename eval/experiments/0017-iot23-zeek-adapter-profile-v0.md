# Experiment 0017: IoT-23 Zeek adapter profile v0

## Hypothesis

Prospective implementation hypothesis, recorded after the first scripted run
rather than as a formal preregistration: the bounded Rust Zeek adapter would
accept the complete publisher flow log, produce deterministic aggregate output,
and agree with the independent Python lineage parser on row count and duration
availability without retaining source rows or endpoint values.

## Method

Status: executed twice through the canonical campaign.

`just iot23-flow-lineage` built the feature-gated Rust adapter profiler, derived
packet sessions, evaluated lineage, and projected the same publisher log through
the adapter twice. The campaign required byte-identical repeated outputs and
rejected the run unless the Rust and Python paths agreed on publisher row count
and missing-duration count.

The adapter profile reports only protocol and missing-value counts plus a
deterministic digest of the typed projection. The digest and generated reports
remain ignored; this ledger retains no digest, endpoint, UID, label, raw row, or
local path.

## Data provenance

- Source: the same complete paired packet-capture and labeled publisher-flow
  scenario from the public IoT-23 v2 corpus used by experiment 0003.
- Evaluation unit: all publisher `conn.log` rows in the scenario.
- Split: none; this is parser conformance and deterministic replay, not a
  predictive evaluation.
- Retention: raw corpus data and all generated campaign outputs remain ignored.

## Results

Both adapter profiles were byte-identical. The Rust adapter and independent
Python evaluator each counted 10,403 publisher sessions and 6,185 sessions with
unset duration.

The aggregate adapter profile contained 8,224 TCP sessions, 2,179 UDP sessions,
and no ICMP or unknown-transport sessions. Packet and IP-byte counters were
available in both directions for every row.

The surrounding lineage result remained consistent with experiment 0003: it
contained 4,237 packet-derived flows, 2,179 unambiguous one-to-one pairs, two
unmatched publisher flows, and two unmatched packet-derived flows.

## Conclusion

The hypothesis held for this corpus scenario. The new adapter is exercised by
real public data and agrees with a separately implemented parser at the two
locked coverage boundaries.

This does not establish compatibility with every Zeek customization, semantic
equivalence between publisher sessions and packet-derived flows, or any device,
identity, maliciousness, or tamper claim. The adapter intentionally accepts only
canonical full-metadata logs with the default metadata prefix, and this scenario
does not exercise optional counter absence, ICMP, or unknown transports.
