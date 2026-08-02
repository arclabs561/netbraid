# Experiment 0003: IoT-23 flow lineage v0

## Hypothesis

Retrospective, not preregistered: Netbraid's IP-length-backed packet
sessionization would exactly preserve publisher packet and IP-byte counters for
unambiguous one-to-one lineages while making any session merges explicit.

## Method

Status: executed through the production flow path, then repeated byte for byte.

The packet-flow input was produced by Netbraid's `pcap --flows-tsv` mode with
TCP inactivity set to 300 seconds and UDP inactivity set to 60 seconds. The
evaluator then compared that TSV with the publisher's labeled Zeek flow log.
The path-bearing operands are deliberately omitted from this public ledger:

```text
netbraid pcap <omitted> --flows-tsv \
  --tcp-inactivity-seconds 300 \
  --udp-inactivity-seconds 60
python3 eval/evaluate-iot23-flow-lineage.py \
  --zeek-log <omitted> --packet-flows <omitted> --report <omitted>
```

Producer revision: `ffcf4835107607939654627fffa0b1968cd76212`.

Evaluator revision: `ae9f99c`.

The repeated 403,160-byte flow TSV had SHA-256
`e826aa335dc4170c91204eb4a16134fb0698a4a005df9d0e1ca8af0c38db61c0`.
The repeated 4,678-byte aggregate report had SHA-256
`0653c6a12c5b8808cacf217adac0a59a3d0277b65fc316f6e3fb7da9ffc87f2a`.
Producer provenance comes from this experiment receipt, not from the TSV or
evaluator; the evaluator cannot infer producer identity or sessionization
settings from its locked input schema.

## Data provenance

- Source: one complete paired packet-capture and publisher-flow scenario from
  the public IoT-23 corpus.
- Evaluation unit: all 10,403 publisher flows and all 4,237 packet-derived
  flows supplied to the evaluator; there was no train/test split.
- Predictive use: none. This is a deterministic lineage reconciliation against
  publisher metadata, not a classifier evaluation.
- Retention: raw packet data, flow TSV, and generated reports remain ignored.
  This ledger contains no endpoint, address, UID, local path, or corpus row.

## Results

The report was deterministic.

- 2,179 publisher flows and packet sessions formed unambiguous one-to-one
  pairs. Directional and total packet-count deltas were exactly zero, and
  directional and total IP-byte deltas were exactly zero.
- 8,222 matched malicious publisher flows mapped into 2,056 merged packet
  sessions under the recorded inactivity policy.
- Two of 10,403 publisher flows were unmatched.
- Two of 4,237 packet-derived flows were unmatched.

The counts reconcile: 2,179 one-to-one publisher flows, 8,222 publisher flows
in merged sessions, and two unmatched publisher flows account for all 10,403;
2,179 one-to-one packet sessions, 2,056 merged sessions, and two unmatched
packet sessions account for all 4,237.

## Conclusion

The retrospective hypothesis held for this scenario. Every unambiguous pair
had exact packet and IP-byte agreement, while the reported merge structure
made the publisher/session boundary visible instead of hiding it in aggregate
totals.

This result does not establish equivalent publisher and packet session
semantics, generalization beyond the scenario, or TSV producer provenance. The
producer and inactivity policy must remain part of the external experiment
record even when the TSV satisfies the evaluator's schema.
