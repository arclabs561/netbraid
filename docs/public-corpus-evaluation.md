# Public network corpus evaluation

Six allowlisted public archives are available to the bounded local evaluation
workflow. Together they contain 2,047,216,276 archive bytes, 2,241 ZIP members,
and 10,968,439,159 uncompressed member bytes. They remain ignored under
`eval-data/`: successful fetching is not admission into Netbraid's committed
fixture ledger.

## Data lineage

| Corpus | Source unit | Available reference | Appropriate use now | Not established |
|---|---|---|---|---|
| V2I 802.11ad | one uninterrupted vehicle trace, with colocated monitor capture | raw PCAP, extracted Wi-Fi CSV, GPS, throughput, trace metadata, and the publisher's tshark field configuration | deterministic PCAP normalization, 802.11ad coverage, frame-field checks, trace-level temporal robustness | host-path identity, cross-corpus identity, or a generic mobility label |
| ZBDS2023 | one hour observed concurrently by four Raspberry Pis | 1,028 Zigbee PCAPs: 257 per observer from 2022-06-30 through 2022-07-11 | bounded unsupported-link handling today; future multi-observer Zigbee adapter consistency | device identity across observers without a protocol-derived or publisher-provided label |
| SDR4IoT BLE/Zigbee | one scenario/scene/session observed by several servers | paired capture, CSV, and SigMF artifacts for BLE and Zigbee | format detection, explicit abstention, and future adapter checks against paired publisher extracts | comparability between servers when capture clocks and labeling have not been validated |
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
captures, one four-observer ZBDS hour, and one complete SDR4IoT session. Probe
request JSON is a structured-data case, not input to the PCAP adapter.

The bounded run covers 11 slices from all six archives. With a
1,000-packet limit, the V2I case reports 1,000 observed WLAN frames. Both
management-frame captures run to completion and reconcile all 36,306 and
60,984 frames, respectively, with their publisher CSVs. Two Sorbonne captures
from the same sniffer at 1 m and 50 m run to completion and exactly reconcile
1,885 and 1,280 rows, respectively, including frame mix, channel mix, and RSSI
summary. The complete
50-packet SDR4IoT Zigbee case reports
`unsupported`, while each limited ZBDS observer reports `insufficient` rather
than converting partial non-WLAN coverage into a capture-wide unsupported
claim. The probe-request example passes only its checked structured-JSON shape.
All ten PCAP cases produce byte-identical projections on two runs. The v1 report
also records the exact campaign-manifest SHA-256, clean Netbraid Git revision,
and executable SHA-256 that produced it; evaluation fails closed when tracked
repository changes make the revision ambiguous or when executable bytes change
during the run.

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
labeled subset. Rates must include raw numerators, denominators, and confidence
intervals. None of the six archives, by itself, labels a Netbraid-to-Linktop or
cross-protocol identity relation.

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
