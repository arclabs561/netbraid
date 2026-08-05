# Experiment 0002: Sorbonne structural reducer v0

## Hypothesis

All publisher-labeled same-event pairs and the registered different-event sample
collapse to one non-discriminating structural basis after Netbraid normalization,
so `assess_packet_same_event_v0` selects `unknown` for every weighted pair.

## Method

Status: executed through the canonical target, including its required repeat,
then re-executed after the packet-envelope registry advanced to v5 and the
reducer bridge began projecting content-bound finite claims.

The locked campaign is
`eval/fixtures/sorbonne-structural-reducer-campaign-v0.json`. It was committed
before the evaluator was implemented or run. The evaluator normalized all
ten one-metre PCAP traces through Netbraid, join packet records to publisher rows
by observer and exact frame number, construct the registered positive and
negative pair populations, and invoke the Rust JSONL reducer once per distinct
label-and-structural-basis class.

Executed command:

```text
just sorbonne-structural-reducer-eval
```

Registered reducer revision:
`6c7c9b535b746c454f98ecb37cab4670906bf891`.

Pre-execution harness revision:
`b8f2aa422e1ce00076703732705c22521e079ad1`.

Revision 2 supersedes revision 1 before execution. It records byte-exact,
domain-separated negative sampling; locks intermediate population counts and
digests; separates sampling identity from reducer canonical order; expands the
expected dispositions; and binds the final semantic-validator hardening for
canonical frame IDs and structural values. The campaign remained unexecuted
until the harness revision above was committed.

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

The canonical target completed successfully. Its two independent executions
produced byte-identical reports. The replay contract now requires
`netmon.tshark.packet_envelope.v5`; it separately rejects disagreement between
observers and a single shared registry that is unsupported by the evaluator.

- Normalization emitted 18,926 packets, zero quarantines, and zero unmatched
  publisher-label joins under one TShark version, configuration digest, and v4
  field registry.
- The positive population contained 64,149 unique pairs with the registered
  digest. Negative construction produced 83,927 raw candidates, rejected 67
  equal-key pairs, retained 83,860 eligible candidates, and selected 64,149;
  both registered negative digests matched.
- Positive and negative populations were disjoint. Each oracle label collapsed
  to one serialized basis and one assessment class.
- The reducer ran twice, once per weighted label/basis class. For all 128,298
  weighted pairs, `same_event` and `different_event` were underdetermined and
  `unknown` was supported with reason
  `no_discriminating_structural_conflict`.
- Each representative reducer invocation also emitted a production finite
  claim. Its participant references matched the normalized packet schema,
  record IDs, and envelope digests. Across the complete populations, the
  evaluator found 128,298 distinct content-bound event targets, no duplicate
  target claims, and no overlap between oracle classes. All targets remained
  unresolved; this one-claim-per-target campaign does not test conflict
  resolution.
- The canonical decision projection SHA-256 was
  `20b47442e49695c6f1289a4f7cb5ff31c1042fd4a0c07122717d1417f59dac45`.
- The repeated report SHA-256 was
  `78ab5aa9a6beda782fe9544cc09d1d9a5b654f27179e1f07ae2cbc6f2e00672e`.

The reports remain local under ignored `data/derived/`; this ledger records only
bounded metadata and content digests.

## Conclusion

The result confirms the registered contract: Netbraid normalization, exact
publisher-label joins, deterministic population construction, weighted reducer
execution, content-bound target construction, and the v0 abstention boundary
agree end to end. This corpus cannot measure discrimination by the v0
structural baseline because both oracle classes project to the same basis. It
does not show that same-event inference works or that conflicts can be
resolved; the next experiment needs richer non-oracle packet evidence, another
legitimate claim family over the same participants, and a separately justified
negative set.
