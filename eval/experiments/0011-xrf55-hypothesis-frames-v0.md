# Experiment 0011: XRF55 hypothesis-frame evidence v0

## Hypothesis

The complete XRF55 processed event grid can populate a bounded shared
hypothesis-frame manifest with exact same-event and same/different-performer
relations, while leaving device identity, principal identity, tamper, intent,
and payload integrity explicitly unresolved where the corpus provides no
oracle.

## Method

Pre-implementation base revision: `e8447b3`.

Three integration shapes were considered:

1. Dataset-specific frame types would preserve every XRF55 detail, but would
   make cross-corpus evaluation depend on dataset-specific consumers.
2. A universal normalized event model would offer one ingestion schema, but
   would prematurely require semantics that many admitted corpora cannot
   support.
3. A thin evidence compiler can preserve the source-native observation key at
   the adapter boundary and emit only relations justified by the corpus into
   the shared frame schema.

The third shape was selected. The compiler is reproduced with:

```sh
just xrf55-hypothesis-frames
```

It reuses the bounded XRF55 ZIP profiler and exact local archive-size and
receipt-metadata checks. The profiler reads central-directory metadata but no
member payloads. It admits only complete observations keyed by scene-scoped
performer, action, and repetition. Source keys are retained in memory only.

For a deterministic hash-ranked sample of at most 512 events, the compiler
emits the three Wi-Fi/RFID/mmWave modality pairs as same-event and
same-performer frames with different physical devices, physical sources,
configurations, and variants. It also emits one different-event control for
each performer and pairs performers to form different-performer controls.
Frame identifiers are domain-separated opaque hashes. The complete manifest is
parsed through the shared hypothesis-frame v2 boundary, generated twice, and
required to be byte-identical.

The term `event_performer_relation` is deliberately narrower than three
existing vocabularies. W3C PROV agents bear responsibility for activities,
which is stronger than the XRF55 label. SOSA features of interest include
passive observed things, which is broader. ActivityStreams actors can be
people, applications, groups, organizations, or services. Here, performer
means only the entity performing the activity that defines the event; it does
not imply responsibility, a cryptographic principal, RF-device identity, or
malicious agency.

## Data provenance

The corpus is XRF55 under CC BY-NC 4.0. The
[publisher project page](https://aiotgroup.github.io/XRF55/) documents 42,900
synchronized samples from 39 subjects, 55 actions, 20 repetitions, and four
scenes. It also identifies distinct Wi-Fi, RFID, and mmWave hardware and the
first-14/last-6 repetition split. The
[publisher Q&A](https://github.com/airslab2020/XRF55-repo/blob/main/XRF55-QA.md)
documents the processed filename grammar. The ignored archives and receipts
are acquired by `data/fetch/fetch-xrf55.py`.

The terminology comparison uses the official
[W3C PROV-O agent definition](https://www.w3.org/TR/prov-o/#Agent),
[W3C SOSA feature-of-interest definition](https://www.w3.org/TR/vocab-ssn/#SOSAFeatureOfInterest),
and [W3C ActivityStreams actor types](https://www.w3.org/TR/activitystreams-vocabulary/#actor-types).

## Results

The real-corpus compiler completed twice with byte-identical outputs. Each run
consumed 42,900 complete observation keys and emitted 1,594 schema-v2 frames:
1,536 cross-modal same-event frames, 39 same-performer/different-event
controls, and 19 different-performer controls.

The result establishes deterministic oracle coverage, not predictive quality.
Most same-event frames are confirm-by-construction from the publisher's
synchronized naming grid, so they carry little evidence about a future model's
ability to recover the relation from signal content. No signal or packet
features were scored, no classifier ran, and no accuracy metric is reported.

The compiler intentionally records claimed identifiers and cryptographic
principals as not observed; software, continuity, freshness, and transmission
as unknown; integrity as unverifiable; and scenario cause, mechanisms,
authorization, intent, and tamper disposition as underdetermined. Local receipt
metadata was validated, but the 195,896,168,944 archive bytes were not freshly
rehashed during this run.

## Conclusion

The hypothesis held at the metadata-oracle boundary. XRF55 now supplies a
reproducible shared-frame corpus that proves event-performer, physical-source,
and modality relations can coexist without overloading identity. The next
high-information experiment must exercise actual modality features against
held-out performer or event controls; generating more frames from the same
filename grammar would add volume but almost no evidence.
