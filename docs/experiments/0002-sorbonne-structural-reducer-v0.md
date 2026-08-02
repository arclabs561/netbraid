# Experiment 0002: Sorbonne structural reducer v0

## Hypothesis

All publisher-labeled same-event pairs and the registered different-event sample
collapse to one non-discriminating structural basis after Netbraid normalization,
so `assess_packet_same_event_v0` selects `unknown` for every weighted pair.

## Method

Status: contract campaign revised before execution, not executed.

The locked campaign is
`scripts/fixtures/sorbonne-structural-reducer-campaign-v0.json`. It was committed
before the evaluator was implemented or run. The evaluator will normalize all
ten one-metre PCAP traces through Netbraid, join packet records to publisher rows
by observer and exact frame number, construct the registered positive and
negative pair populations, and invoke the Rust JSONL reducer once per distinct
label-and-structural-basis class.

Planned command:

```text
just sorbonne-structural-reducer-eval
```

Locked implementation revision:
`459db84b1dafdb4f44e55b1e84853ba6c656bdaf`.

Revision 2 supersedes revision 1 before execution. It records byte-exact,
domain-separated negative sampling; locks intermediate population counts and
digests; separates sampling identity from reducer canonical order; expands the
expected dispositions; and binds the final semantic-validator hardening for
canonical frame IDs and structural values. The campaign remained unexecuted.

## Data provenance

- Publisher: Sorbonne Université, DOI `10.57745/HAOPHF`.
- Artifact: `220211012-SU-Outdoors-Campus.zip`, 3,144,312 bytes.
- SHA-256: `7a650d450d339683cf7591bc24a6006238456b8dfa54e352aa1aceda8682c3f8`.
- Split: complete one-metre run, all ten observers, all 18,926 labeled frames.
- Positive labels: equal complete publisher source-address and sequence-number
  keys across distinct observers.
- Negative labels: deterministic registered sample from unequal complete keys
  across distinct observers.
- Predictive signal: only the closed structural allowlist owned by the Rust v0
  reducer. Publisher keys and synchronized timestamps remain label/audit-only.

The earlier oracle audit already exposed that the publisher invariant projection
is constant. This campaign is therefore a confirmatory contract and full-path
normalization check, not an independent discovery or discrimination benchmark.

## Results

Not executed.

## Conclusion

Pending execution. Confirmation would validate the data path and establish that
this corpus cannot measure discrimination by the v0 structural baseline; it
would not show that same-event inference works.
