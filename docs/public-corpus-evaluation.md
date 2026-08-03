# Public network corpus evaluation

Six allowlisted public archives and one receipt-bound standalone public capture
are available to the bounded local evaluation workflow. Together they contain
2,047,242,284 source bytes, 2,241 ZIP members plus the standalone file, and
10,968,465,167 uncompressed input bytes. They remain ignored under `data/raw/`:
successful fetching is not admission into Netbraid's committed fixture ledger.

## Data lineage

| Corpus | Source unit | Available reference | Appropriate use now | Not established |
|---|---|---|---|---|
| V2I 802.11ad | one uninterrupted vehicle trace, with colocated monitor capture | raw PCAP, extracted Wi-Fi CSV, GPS, throughput, trace metadata, and the publisher's tshark field configuration | deterministic PCAP normalization, 802.11ad coverage, frame-field checks, trace-level temporal robustness | host-path identity, cross-corpus identity, or a generic mobility label |
| ZBDS2023 | one hour observed concurrently by four Raspberry Pis | 1,028 Zigbee PCAPs: 257 per observer from 2022-06-30 through 2022-07-11 | identifier-free IEEE 802.15.4 frame/address-form/command/FCS projections and bounded cross-observer consistency | device identity across observers without a protocol-derived or publisher-provided label |
| SDR4IoT BLE/Zigbee | one scenario/scene/session observed by several servers | paired capture, CSV, and SigMF artifacts for BLE and Zigbee | exact IEEE 802.15.4 projection checks for the admitted Zigbee slice and future paired-waveform alignment | comparability between servers when capture clocks and labeling have not been validated |
| Matter DATA1813 Thread N1 | one publisher PCAPNG acquired as a standalone file with an exact local fetch receipt | saved Thread/IEEE 802.15.4 packets with 6LoWPAN-decoded IPv6 evidence | bounded post-adapter-fix conformance for packet yield, quarantine absence, decoded-length preservation, and unavailable saved-capture FCS status | device identity, payload semantics, behavior, or capture-wide completeness from the 32-packet prefix |
| Wi-Fi management frames | one anonymized station capture | two PCAP/CSV pairs with publisher frame counts and anonymization procedure | parser robustness, management-frame coverage, deterministic output, and count reconciliation | exact original frame bytes: anonymization deliberately removed elements and may leave inconsistent lengths |
| Wi-Fi probe requests | one environment/scenario/device time block | processed JSON, measurement intervals, device/scenario spreadsheet, and collection description | structured-data profiling and future privacy/abstention cases | a raw-PCAP oracle or permission to treat MAC/IE similarity as durable identity |
| Sorbonne campus RSSI | one outdoor experiment, with one transmitter observed by ten sniffers at six known distances | paired PCAP and publisher TSV traces for each sniffer/distance cell | radio-metadata normalization, distance-slice sensitivity, and exact frame/channel/RSSI-summary reconciliation | general ranging accuracy, device identity, or independent train/test examples within the same experiment |

The corpora are independent. Temporal proximity, matching protocol fields, or
similar radio fingerprints across archives cannot create a positive relation
label.

## Evaluation tasks

### Netbraid normalization

For every selected PCAP or capture member:

1. Verify the parent archive receipt and selected-member digest.
2. Run the bounded normalizer twice with the same extractor configuration.
3. Require byte-identical canonical output and unchanged input bytes.
4. Record normalized, quarantined, and unsupported counts separately.
5. Preserve capture completeness and extractor provenance in every projection.

The initial campaign should include one V2I trace, both anonymized management
captures, one four-observer ZBDS hour, one complete SDR4IoT session, and the
receipt-bound 32-packet Matter Thread N1 prefix. Probe request JSON is a
structured-data case, not input to the PCAP adapter.

The bounded run covers 12 slices from all seven source units. With a
1,000-packet limit, the V2I case reports 1,000 observed WLAN frames. Both
management-frame captures run to completion and reconcile all 36,306 and
60,984 frames, respectively, with their publisher CSVs. Two Sorbonne captures
from the same sniffer at 1 m and 50 m run to completion and exactly reconcile
1,885 and 1,280 rows, respectively, including frame mix, channel mix, and RSSI
summary. The complete
50-packet SDR4IoT Zigbee case reports
`unsupported`, while each limited ZBDS observer reports `insufficient` rather
than converting partial non-WLAN coverage into a capture-wide unsupported
claim. The Matter case verifies its standalone acquisition receipt before
normalization; its limited prefix emits 32 packet envelopes, zero quarantines,
two preserved 6LoWPAN-decoded IPv6 total lengths greater than their saved frame
lengths, and 32 unavailable IEEE 802.15.4 FCS statuses. The probe-request
example passes only its checked structured-JSON shape. All eleven PCAP cases
produce byte-identical projections on two runs. The v1 report
also records the exact campaign-manifest SHA-256, clean Netbraid Git revision,
and executable SHA-256 that produced it; evaluation fails closed when tracked
repository changes make the revision ambiguous or when executable bytes change
during the run.

The identifier-free IEEE 802.15.4 projection schema does not expose decoded
IPv6 length relationships. For the Matter conformance case only, the evaluator
therefore runs the deterministic `--records-jsonl` surface twice, validates its
artifact binding, derives the single decoded-length count, and discards the
records. Packet addresses, PAN identifiers, sequence numbers, record IDs, raw
rows, and local paths are not copied into the manifest or report.

### Reference reconciliation

Publisher-derived CSV is a reference, not automatically ground truth. Reconcile
only fields whose preprocessing is disclosed:

- management-frame subtype counts and total rows for each PCAP/CSV pair (now
  enforced with zero absolute delta for both captures);
- Sorbonne frame mix, channel mix, RSSI count/sum/range, and total rows for each
  selected PCAP/TSV pair (now enforced with exact agreement at 1 m and 50 m);
- V2I trace number, timestamps, selected frame subtypes, and disclosed tshark
  fields;
- SDR4IoT capture/CSV session membership before considering packet-level
  agreement.

Report absolute count deltas and the exact denominator. Do not collapse parser
failure, unsupported link types, quarantine, and genuinely absent evidence into
one error rate.

### Sorbonne same-transmission oracle audit

The complete 1 m run supplies a narrow publisher-grounded event oracle:
different sniffers observing the same source address and sequence number saw
the same transmitted beacon within this run. The preregistered audit covers all
ten synchronized TSVs and verifies 18,926 observations, 2,715 event keys, 2,673
events seen by at least two sniffers, 455 events seen by all ten, and 64,149
cross-sniffer positive pairs. There are no duplicate event keys within a
sniffer and no contradictory channel/type/subtype/retransmission metadata
within an event.

PyPal produced the synchronized time axis from common reference frames matched
with a composite key that included source MAC and sequence number. Accordingly,
the 1 ms synchronized-time diagnostic contains exactly those 64,149 positive
pairs and zero negatives. It is evidence of oracle-related synchronization,
not perfect candidate retrieval or classification. Synchronized time is
forbidden as predictive evidence in this campaign.

Run the metadata-only audit with:

```sh
just sorbonne-same-event-audit
```

Run the separate full-normalization reducer contract with:

```sh
just sorbonne-structural-reducer-eval
```

That campaign uses a byte-exact, oracle-conditioned negative sample only to
exercise the registered abstention boundary. It reports weighted dispositions
and distinct structural classes, not accuracy, precision, recall, calibration,
or generalization.

The next hypothesis baseline must either abstain on the current structural
projection or use a packet fingerprint that masks oracle and observer-specific
fields. A separately justified negative set is required before precision,
recall, or false-link rates are meaningful.

### OPERAnet layout profile

Run the archive-metadata profile with:

```sh
just operanet-layout-profile
```

The profiler verifies the seven pinned archives and receipts, then reads ZIP
central-directory metadata without opening member payload streams. Thirty-six
of 61 observed experiment-number tokens occur in every sensing modality.
Incomplete modality coverage, ambiguous Wi-Fi CSI 2 suffixes, and absent
participant/activity/clock metadata block any stronger alignment claim.

### Linktop review

Linktop consumes only the verified Netbraid saved-evidence stream. Its campaign
measures whether review output:

- preserves complete versus partial capture coverage;
- emits positive observed evidence when present;
- qualifies or abstains from negative claims when coverage is insufficient;
- remains deterministic and input-preserving; and
- contains no source identifiers beyond its declared output contract.

Linktop does not ingest GPS, SigMF, spreadsheets, or processed probe-request
JSON merely because those files share an archive with wireless captures.

## Split discipline

Rows from one capture are dependent observations and must never be split across
train, calibration, and evaluation sets.

- V2I: group by trace; reserve an entire year or collection day for temporal
  shift evaluation.
- ZBDS2023: group all four observers for an hour together, then split by day or
  contiguous multi-hour block.
- SDR4IoT: keep every server and modality from one scenario/scene/session in the
  same split.
- Matter DATA1813: keep each complete publisher trace as one split group; the
  32-packet N1 prefix is a conformance slice, not an independent sample.
- Wi-Fi management frames: treat the two captures as two cases from one site,
  not as an independent train/test pair.
- Probe requests: group by environment, scenario interval, and physical device;
  evaluate environment or scenario transfer only with the spreadsheet's
  publisher-provided intervals.
- Sorbonne: keep all sniffers and distances in this experiment in one split
  group; the 1 m and 50 m cases are sensitivity slices, not independent folds.

Deduplicate content before splitting. Near-duplicate time windows and paired
CSV/PCAP representations stay in the same group.

## Metrics

Report data validity before model or relation quality:

- archive/member digest success and selected-byte yield;
- parse, unsupported, and quarantine counts;
- deterministic replay success;
- normalized-frame yield and publisher-reference count delta;
- capture-completeness classification;
- Linktop expectation failures and false definitive-negative count;
- abstention count by corpus, link type, and completeness slice.

Precision, recall, false-link rate, and calibration require an independently
labeled subset with both positive and negative cases. Rates must include raw
numerators, denominators, and confidence intervals. Sorbonne labels one narrow
same-transmission relation within a run; it does not label a Netbraid-to-Linktop,
durable-device, or cross-protocol identity relation.

## Adapter-motivating corpus

The fetch catalog also pins 16 artifacts (109,299,217,230 bytes) for later
adapter and model work. These downloads are provenance-bearing inputs, not part
of the 11-case normalization report:

| Corpus | Downloaded unit | What it can motivate | Boundary |
|---|---|---|---|
| IoT-23 v2 Hakai | Ethernet PCAP, labeled Zeek flow log, and label configuration for scenario 8-1 | a packet-to-flow adapter and malicious/benign label-lineage checks | not WLAN evidence and not a device-identity oracle |
| WiSig compact variants | SingleDay, ManyRx, ManyTx, and ManySig IQ/pickle archives | transmitter/receiver/day split discipline and learned radio-fingerprint experiments | requires a bounded pickle/IQ adapter; non-commercial share-alike terms apply |
| CAEZ indoor L-shape | multi-sniffer Wi-Fi CSI with position ground truth | CSI/position schema design and spatial holdout experiments | not accepted by the packet adapter; original data may not be redistributed |
| OPERAnet | PWR, two Wi-Fi CSI, two UWB, Kinect, and code archives | participant/activity/room/time alignment across modalities | requires modality-specific adapters and cannot establish cross-protocol identity by temporal overlap |
| Gotham 2025 | complete 23.8 GB IoT emulation archive with PCAP/CSV and attack events | scale, flow/security, and abstention stress cases | emulated devices do not establish physical-hardware or live-deployment parity |

Use these corpora to develop the smallest adapter seams and to motivate hardware
work with evidence. Do not promote a relation type merely because a public
dataset makes a model trainable.

Prioritize later-work experiments by expected information gain, not archive
size or adapter convenience:

1. **OPERAnet multimodal complementarity.** Keep complete
   experiment/participant/room groups together. Compare every fused condition
   with its best single modality under registered missing-modality masks. The
   hypothesis fails when grouped macro-F1 or balanced-accuracy improvement has
   no positive paired confidence bound. Time overlap is not cross-protocol
   identity evidence.
2. **CAEZ multi-AP spatial fusion.** Align CSI/frame metadata to publisher
   position rows, then hold out complete takes and contiguous spatial regions.
   Report median and 90th-percentile localization error plus selective
   risk-versus-coverage. The hypothesis fails when fusion does not improve on
   the best single AP or abstention does not monotonically reduce error.
3. **V2I mobility/throughput episodes.** Keep whole traces together and reserve
   a collection day or year for temporal shift. Compare radio-plus-GPS evidence
   with each component using throughput-drop AUPRC and detection lead time at a
   fixed false-alarm rate.
4. **WiSig nuisance robustness.** Use a bounded non-executing pickle/IQ reader;
   never deserialize the downloaded pickle. Split by transmitter, receiver,
   acquisition, and day rather than waveform windows. Report EER and TPR at a
   preregistered low FPR on held-out receiver/day conditions.
5. **Zigbee multi-observer coverage.** Keep all four ZBDS observers for an hour
   in one split. Admit same-event labels only after validating clocks and a
   protocol-derived or immutable-byte key. Fail on any unjustified merge or
   non-positive unique-event coverage gain over the best observer.
6. **Gotham and IoT-23 flow lineage.** Reconcile raw packets to processed flows
   and retain the matching rule as provenance. Report join precision/recall,
   unmatched-flow rate, labels without rule lineage, per-attack AUPRC, and
   bounded throughput. One scenario or emulated hardware cannot establish
   generalization.

Every experiment reports per-group results, firing and abstention counts, raw
metric numerators and denominators, and a confidence interval where a rate is
used. A new adapter is not evidence for a fusion claim until the corresponding
held-out comparison passes.

The separate `fusion` fetch group pins two cross-layer corpora. Data4Cyber
co-ships synchronized PCAPNG, one-second process telemetry, state logs, and
attack-phase labels in one 134 MB archive. NetsLab-5GORAN-IDD co-ships packet
captures with independent lower-layer radio telemetry; the first bounded slice
is its benign archive plus the lower- and network-layer summary databases.
The Data4Cyber archive includes a CC BY 4.0 `LICENSE.txt`; its Zenodo metadata
omits the license field. The NetsLab Zenodo record also omits that field, so
its artifacts remain local-only evaluation inputs unless a later rights review
establishes redistribution terms. They can motivate cross-layer adapter and
alignment work; they do not label Netbraid's counter-to-capture relation or
establish identity.

Run the bounded Data4Cyber alignment profile with:

```sh
just data4cyber-alignment-profile
```

The profile verifies the complete archive and exact digest, requires the
publisher's eight-scenario layout, compares only tabular headers and README
synchronization claims, and structurally scans bounded PCAPNG prefixes. It does
not read table rows or packet payloads. Matching timestamp-bearing structures
make a later alignment adapter testable; they do not establish clock offset,
event correspondence, device identity, packet semantics, or model quality.

The NetsLab profile verifies the benign capture archive and both SQLite
summaries, inventories the ZIP without extraction, and queries exact schemas
read-only with a bounded 256 MiB mmap request. It emits aggregate row, null, and
category-cardinality metadata only. The lower-layer table has a timestamp; the
network summary does not, so filename/scenario lineage must be established
before any cross-layer join. Run it with:

```sh
just netslab-alignment-profile
```

IoT-23 supplies a separate packet-to-flow lineage oracle. The evaluator accepts
strict, externally sessionized packet-flow metadata and the publisher's Zeek
log, then reports aggregate five-tuple/time-envelope match, split, merge,
unmatched, counter-delta, and label-lineage metrics. Reports omit paths,
endpoints, payloads, and hashes. Netbraid can now emit the evaluator's locked
TSV directly with `pcap --flows-tsv`; callers must explicitly supply both TCP
and UDP inactivity thresholds. The projection uses normalized IP lengths and
TCP stream indices, records split/orientation boundaries, and excludes legacy
or ambiguous packets. Corpus-level agreement with the publisher remains an
evaluation result, not a production-parity claim. Run its hermetic contract
with:

```sh
just iot23-flow-lineage-check
```

Two controlled-jamming records provide exact condition structure without
providing identity, tamper, or malicious-intent truth. The 80-file mmWave
record forms 40 receiver/regime/target-matched with/without-jammer pairs; its
compiler hashes every byte but never parses MAT payloads. The indoor record
uses one publisher workbook and HDF5 metadata from 31 MAT files to bind silent,
sine, and Gaussian segments while reading no dataset elements. Both compilers
emit opaque split groups and assign no train/test roles.

```sh
just mmwave-jamming-oracles-check
just indoor-jamming-oracles-check
```

XRF55 is a larger deferred multimodal corpus: its three official Kaggle dataset
records total 235,496,571,505 metadata bytes, while the compressed archives
total 195,896,168,944 bytes and cover synchronized Wi-Fi, RFID, and mmWave
observations. `data/fetch/fetch-xrf55.py` pins the public dataset references,
versions, metadata sizes, compressed sizes, and archive MD5 values. It
downloads resumably without extraction and writes a local SHA-256 receipt.
The corpus remains
deferred until bounded Wi-Fi/RFID adapters and a grouped cross-environment split
exist. Its video data is not required for the initial radio-fusion hypothesis.

```sh
just xrf55-fetch all
```

The first such seam is an archive-backed CAEZ CSI profile:

```sh
just caez-csi-profile
```

It verifies the complete 1.93 GB artifact and fetch receipt, scans the
uncompressed tar inventory without extraction, requires all 161,182 CSI/frame
metadata pairs, and parses only eight small AP/take samples plus four AP metadata
objects (75,174 bytes total). The report checks a 5-by-52 CSI shape and stable
metadata keys. It deliberately leaves the large ground-truth CSV and NPZ
position payload unread, so it establishes an adapter/container seam but no
position alignment, ranging accuracy, radio identity, or model quality.

## Admission gate

A local result can be useful without becoming a committed fixture. Admission
requires a separate review that records:

- exact source member, archive digest, member digest, and transformation;
- license text and redistribution permission;
- the smallest bytes needed to exercise the oracle;
- disclosure review for identifiers, location, and device metadata;
- a requirement assertion or mutant that the fixture uniquely catches; and
- a stable split group so later additions cannot leak adjacent observations.

Until that gate passes, reports and selected extractions remain local artifacts.
