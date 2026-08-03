# Experiment 0001: Sorbonne same-transmission oracle and candidate audit

## Hypothesis

The complete Sorbonne 1 m synchronized run can provide a deterministic,
publisher-grounded cross-sniffer same-transmission oracle without allowing its
source-address or sequence-number labels into predictive features.

## Method

Preregistered before execution at Netbraid commit `98399c8`.

```sh
just sorbonne-same-event-audit
```

The evaluator must read exactly the ten `1m/csvTracesSynchronized` TSV members,
enforce the publisher's nine-column schema, and treat
`Source_MAC_address + Sequence_number` as evaluator-only labels. It audits
event-key uniqueness per observer and invariant metadata consistency. It also
reproduces the synchronized-time 1 ms pair set as a leakage diagnostic.

No threshold is fit. The complete run is one evaluation unit. Sequence number,
source address, RSSI, and observer identity are forbidden predictive fields.
Synchronized time is forbidden for blocking and prediction: before execution,
adversarial review established that PyPal fitted it from common reference
frames matched by a composite key containing source MAC and sequence number.
The diagnostic is preregistered to contain 64,149 positives and zero negatives;
it is not a three-way evaluation set.

## Data provenance

- Publisher DOI: `10.57745/HAOPHF`.
- Local archive: `data/raw/220211012-SU-Outdoors-Campus.zip`.
- Archive receipt and digest: maintained by
  `data/fetch/fetch-public-eval-corpus.py`.
- Slice: complete 1 m run, all ten synchronized sniffer TSVs.
- Split: one locked publisher experiment; no row, event, or observer-pair
  train/test split.
- Preregistered structural expectations: 18,926 observations; 2,715 oracle
  events; 2,673 events observed by at least two sniffers; 455 observed by all
  ten sniffers; 64,149 positive cross-sniffer pairs.

## Metrics and gates

- Exact structural counts above.
- Count of duplicate sequence keys within each observer.
- Count of oracle events with contradictory invariant metadata.
- Synchronized-time diagnostic pair count, positive count, negative count, and
  positive coverage.
- Deterministic report serialization.

Any duplicate key, contradictory metadata, synchronized-time diagnostic
mismatch, or mismatch against a preregistered count fails the campaign.

## Results

The canonical recipe completed and its two producer-written reports were
byte-identical.

- Observations: 18,926 / 18,926 expected.
- Oracle events: 2,715 / 2,715 expected.
- Multi-observer events: 2,673 / 2,673 expected.
- All-observer events: 455 / 455 expected.
- Positive cross-observer pairs: 64,149 / 64,149 expected.
- Duplicate event keys within an observer: 0.
- Events with contradictory invariant metadata: 0.
- Pairs inside the inclusive absolute 1 ms synchronized-time diagnostic:
  64,149 same-event, 0 different-event.

The report was written only under ignored `data/derived/`; no corpus rows or
generated report are committed.

## Conclusion

The structural-oracle hypothesis held. The stronger implied hypothesis—that a
1 ms synchronized-time window could form a useful three-way evaluation
set—was falsified before execution and preregistration was revised: PyPal's
clock transform used same-frame composite correspondences containing source
MAC and sequence number, and the resulting window contains no negatives.

This dataset now earns an oracle-audit gate and an abstention requirement, not
a classifier score. The next implementation should expose a fixed
`same_event / different_event / unknown` contract whose structural-only
baseline returns `unknown` for this constant beacon projection; a masked packet
fingerprint and separately justified negative set are required before a
positive-decision baseline.
