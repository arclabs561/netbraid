# Experiment 0005: Hypothesis frames v0

## Hypothesis

Separating event relation, physical-source relation, variant relation,
observation cause, and evidence integrity will preserve open-set uncertainty
and expose failures that a single fingerprint-identity score would hide.

## Method

Pre-implementation base revision: `a295344`.

The first implementation adds a typed counter/capture hypothesis set under the
Rust `infer` facade while preserving the existing packet same-event contract.
It uses source-neutral bounded traffic windows, a content-bound profile,
checked fixed-point arithmetic, and explicit support, contradiction, and
unknown alternatives. No default scoring profile is admitted before a real
paired campaign establishes it.

Later RF evaluation will use separate, preregistered frames:

1. artifact relation: same source object, equal content, different, or unknown;
2. event relation: same event, different event, unknown;
3. physical-source relation: same immediate emitter, different emitter,
   unknown;
4. variant relation: same variant, left-derived, right-derived, different, or
   unknown;
5. integrity: verified unchanged, verified changed, or unverifiable.

Attack cause remains an evaluation-only `scenario_tag`: benign domain drift,
replay, impersonation, evasion, accidental corruption, compromise, ambiguous,
or insufficient evidence. A production reducer does not infer intent or cause
from anomaly, mismatch, or abstention.

Admissibility, freshness, continuity, and transmission path are gates rather
than identity classes. Their states include in-domain/out-of-domain,
fresh/replay-detected/unknown, complete/gap/reordered/duplicate/unknown, and
direct/relayed/unknown where the evidence supports them. Unknown and not
applicable remain distinct.

“Identity” is not used without a qualifier. The evaluation distinguishes:

- artifact identity: whether two references name one acquisition object, kept
  separate from whether their bytes are equal;
- event identity: whether observations refer to one physical emission or
  occurrence;
- claimed identity: an identifier asserted by a packet, device, or operator;
- cryptographic principal: the key or credential that authenticated a claim;
- physical device instance: the chassis, board, or tag under test;
- physical-source identity: the immediate radio or sensor chain that produced
  an event, which may change while the containing device instance remains;
- software state: firmware or software image and version;
- configuration state: settings that may alter behavior without changing the
  device or software instance;
- variant identity: model, hardware revision, manufacturing batch, software
  family, or configuration family shared across instances;
- lineage relation: same, left-derived, right-derived, common-ancestor,
  unrelated, or unknown for versioned artifacts and variants.

A cryptographically valid claim supports a relationship to a key under a
declared verification policy. It does not by itself establish the physical
source, freshness, untampered hardware, or benign intent. Logical and physical
device identifiers may also differ.

The frames are evaluated independently. A result may be same physical source
but a different event, or different physical sources sharing one variant. A
changed digest establishes byte inequality under the named hash procedure; it
does not by itself establish broken evidentiary integrity or malicious intent.

Security mechanism, integrity, authorization, and intent are also independent:

- mechanism records replay, relay, claimed-identifier spoofing, credential
  cloning or theft, RF mimicry, adversarial perturbation, poisoning, deletion,
  reordering, duplication, or another explicitly generated scenario;
- modification locus records source hardware, firmware, configuration, payload,
  transport, capture pipeline, stored artifact, metadata or label, or model and
  index state;
- integrity records verified unchanged, verified changed, authorized
  transformation, or unverifiable;
- authorization records authorized, unauthorized, or unknown only when policy
  evidence exists;
- intent records benign, accidental, malicious, mixed, or unknown only as
  scenario provenance, never as a deduction from anomaly or integrity state.

“Tampered” is therefore a derived security hypothesis, not a synonym for
“different bytes.” It requires evidence that a modification or interference
violated the applicable authorization or provenance policy. Without that
policy evidence the tamper result remains unknown, and even supported tampering
does not identify an actor or prove a broader malicious campaign.

This permits the combinations that matter operationally: a genuine enrolled
device can be compromised and act maliciously; a different replacement device
can be benign; a copied identifier can come from a different physical tag; a
valid credential can be replayed; and a changed artifact can be an authorized
conversion or accidental corruption.

The first adversarial evaluation matrix includes at least these independently
labeled cases:

| Case | Event | Physical source | Variant | Integrity | Cause |
| --- | --- | --- | --- | --- | --- |
| repeated observation of one retained capture | same | same or unknown | same | unchanged | benign |
| new emission from the enrolled transmitter | different | same | same | unchanged | benign |
| channel, receiver, location, or time drift | different | same | same | unchanged | benign drift |
| same-model hardware clone | different | different | same | unchanged | benign or ambiguous |
| replay by another transmitter | different | different | same or derived | unchanged or changed | replay |
| identifier or credential impersonation | different | different | same or derived | unchanged or unverifiable | impersonation |
| legitimate conversion, truncation, or repair | same or unknown | same or unknown | derived | changed | benign transformation |
| content mutation intended to evade detection | same or unknown | same or different | derived | changed | evasion |
| corrupted transport or storage | same | same or unknown | derived | changed | accidental corruption |
| valid signature after key compromise | different | different or unknown | same or derived | unchanged | compromise or ambiguous |
| compromised enrolled device emits attack traffic | different | same | same or derived | unchanged or changed | malicious scenario |
| authorized firmware upgrade on enrolled hardware | different | same or changed radio chain | right-derived | verified changed | benign transformation |
| copied UID on a second physical tag | different | different | same or different | unchanged or unverifiable | clone scenario |
| collision or high-load stress without an attacker | different | same or different | same or unknown | unchanged | benign confounder |

The table defines expected combinations, not inference shortcuts. In
particular, byte equality does not prove freshness, signature validity does not
prove benign intent, and anomaly does not prove tampering or attack.

Required split groups are capture event, physical transmitter, device model or
variant, day, receiver chain, location, channel, and configuration. Unknown
devices used for final testing may not tune thresholds. Replay, impersonation,
evasion, mutation, deletion, reordering, and key-compromise cases must come
from explicit threat fixtures or labeled sources rather than anomaly relabeling.

Planned commands are:

```sh
cargo test --locked --manifest-path rust/Cargo.toml --test counter_capture
cargo test --locked --manifest-path rust/Cargo.toml --test infer_facade
just counter-capture-eval-check
just hypothesis-frame-check
just hypothesis-metrics-check
just relation-split-audit-check
just gnss-rff-layout-profile-check
just osu-lora-profile
just osu-lora-oracles-check
just ruff-uwb-oracles-check
just wlan-rff-layout-profile
```

The Rust reducer and a dedicated Python exact-rational oracle must agree on
shared golden inputs. The existing Decimal campaign helper remains a separate
finite evaluator and is not used as the fixed-point compatibility oracle.
RF classifier commands, model identity, seeds, and thresholds remain unchosen
until the complete metadata profile establishes which setup groups and labels
are admissible without leakage.

## Data provenance

Contract checks use generated integer traffic windows and reviewed Netbraid
evidence fixtures. They contain documentation-only identifiers and no raw
capture or IQ bytes.

The planned RF evaluation uses the public Oregon State LoRa RFFI corpus fetched
by `data/fetch/fetch-osu-lora.py`. Its seven publisher-defined setup families
vary days, receiver hardware, location, distance, and radio configuration.
Downloaded metadata, IQ payloads, local receipts, and derived reports remain
ignored. The bounded metadata profiler retains only aggregate counts and
extent checks; label values, source URLs, and paths are not written to reports.
The oracle compiler hashes publisher labels into domain-separated local group
IDs and fences source/device continuity by setup family. It groups IQ and FFT
representations only when their path grammar and metadata agree, and leaves
split-role assignment to a later explicit campaign builder.

Additional public corpora may be admitted only when they provide explicit
physical-device, variant, acquisition-domain, or attack provenance. Dataset
labels remain evaluation oracles and do not become production identities.

The RUFF-UWB compiler admits publisher source and position labels from the two
pinned NPY archives without deserializing waveform arrays. Because numeric
position labels are not assumed to denote one physical coordinate system
across distance campaigns, location and source/location groups are fenced by
campaign. Publisher evidence supports cross-day source/device continuity, one
fixed receiver, and channel 5. Source ID and the single hardware variant remain
separate axes; individual capture event and session are not observed.

The pinned GNSS RFF archive is profiled from its ZIP central directory after
publisher-MD5 verification. The profiler accepts no password and opens no MAT
or H5 payload streams. Filename labels support controlled clean/spoof, day, and
acquisition-category coverage only; they do not establish event, actor,
physical-source, malicious-intent, or tamper truth.

The pinned WLAN RFF environment archives are profiled from ZIP central
directories only. Their NPZ payloads are not opened. Filename tokens are
reduced to aggregate counts, and their values, session values, paths, and
payload bytes are excluded from the report. Cross-environment token reuse is
layout evidence only until publisher documentation establishes the token's
semantic referent.

## Metrics and gates

No single aggregate fingerprint accuracy is admitted. Report separately:

- event-relation confusion counts and abstention rate;
- physical-source false-match and false-nonmatch rates, with per-domain counts;
- variant false-match rates, especially for same-model different devices;
- unknown-device false-accept and known-device true-accept rates at every
  locked threshold;
- per-day, receiver, location, channel, configuration, and distance results;
- benign-drift versus replay, impersonation, and evasion confusion counts;
- integrity detection coverage and false alarms on declared legitimate
  transformations;
- exclusion, missing-coverage, out-of-domain, and ambiguous counts.

The implemented metrics manifest enforces this separation for every qualified
relation axis. It reports exact integer numerators and denominators for
coverage, abstention, and decided-known-reference risk; unknown references do
not become errors or negatives merely because the evaluator lacks an oracle.
Optional strata are bounded opaque tokens so reports can expose domain skew
without carrying corpus labels or deployment identifiers.

Threshold selection, calibration, and test groups must be disjoint. Correlated
features are not summed as independent evidence unless the calibration model
explicitly represents their dependence. Confidence intervals are reported
only for units that satisfy their independence or grouped-resampling
assumptions. Exact pass thresholds require a separate preregistration after
class balance and achievable power are known.

The split auditor represents train, calibration, validation, and test as four
exact nonempty roles. Event and session groups must be disjoint across every
role pair. Other axes declare the exact forbidden role pairs required by the
campaign, allowing intentional reuse such as known sources shared between
training and calibration while still holding them out from final test. A
required pair containing unknown or unobserved group coverage is unknown and
fails the CLI gate; it cannot pass by absence of a known intersection.

The structural gate fails if any positive physical-source decision is possible
when integrity fails, the input is out of domain, an unknown device is forced
into a known class, or event/variant evidence is silently promoted to source
identity. It also fails if a reducer emits malicious cause from anomaly or
hash mismatch, if deleted/reordered/duplicate evidence is hidden, or if the
same physical-source relation changes when symmetric inputs are swapped.

## Research basis

- [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) separates entities,
  activities, derivation, attribution, revision, alternate representation, and
  specialization; provenance structure is not itself authenticity proof.
- [NIST IR 8387](https://doi.org/10.6028/NIST.IR.8387) recommends separate
  hashes and chain-of-custody records, and explicitly requires assessment of
  whether a mismatch arose from intentional or accidental change.
- [Bendale and Boult](https://openaccess.thecvf.com/content_cvpr_2016/html/Bendale_Towards_Open_Set_CVPR_2016_paper.html)
  show why closed-set classifiers need an explicit unknown rejection path.
- [Karunaratne, Hanna, and Cabric](https://arxiv.org/abs/2108.13099) apply that
  requirement to RF fingerprinting: unauthorized transmitters must be rejected
  rather than mapped onto enrolled devices.
- [Chen, Wong, and Hamdaoui](https://arxiv.org/abs/2403.04036) measure material
  RF device-classification degradation across time and environment domains.
- [RFC 5848](https://www.rfc-editor.org/rfc/rfc5848.html) separates message
  origin authentication, integrity, replay resistance, sequencing, and missing
  record detection—properties that must not be collapsed into transmitter
  identity.
- [NISTIR 8259A](https://doi.org/10.6028/NIST.IR.8259A) distinguishes logical
  and physical device identifiers and notes that they need not have the same
  value.
- [RFC 9334](https://www.rfc-editor.org/rfc/rfc9334.html) separates claims,
  evidence, endorsements, reference values, appraisal policy, attestation
  results, and relying-party policy. Evidence must be associated with its
  target environment and appraised rather than treated as identity truth.
- [RFC 9711](https://www.rfc-editor.org/rfc/rfc9711.html) makes the mapping from
  evidence claims to attestation-result claims explicitly verifier-policy
  dependent.
- [OASIS STIX 2.1](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)
  distinguishes raw Observed Data from the intelligence assertion represented
  by a Sighting; observation and threat attribution are not one object.
- [RFC 4949](https://www.rfc-editor.org/rfc/rfc4949.html) distinguishes
  deliberate tampering from human, hardware, and software errors that also
  alter data or behavior.
- [SPDX 2.3 relationships](https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/)
  distinguish directional ancestor and descendant relations from a variant
  whose ordering is unknown.
- [Irfan et al.](https://arxiv.org/abs/2408.09179) demonstrate RF fingerprint
  mutation after SDR power cycles and FPGA reloads, contradicting an assumption
  that a learned fingerprint is permanently stable.
- [Tyler et al.](https://arxiv.org/abs/2308.03579) demonstrate replay and
  learned mimicry attacks against specific-emitter identification, so RF
  similarity cannot be treated as unforgeable identity evidence.

## Results

The first implementation checkpoint passed:

- 13 Rust counter/capture integration tests and two inference-facade tests;
- one bounded arithmetic property test comparing the overflow-avoiding
  multiply/divide helper with safe naive products;
- eight Python evaluator tests and eight campaign-policy tests through
  `just counter-capture-eval-check`;
- shared-fixture parity at an exact final score of 45,000,000,000 PPB.

The checks cover exact-rational feature and residual serialization, support and
contradiction boundaries, explicit unknown results for missing, sparse, or
arithmetically unrepresentable evidence, content-reference mutation, strict
deserialization, and recomputation against resolved evidence and profile
content. Structural validation alone deliberately does not claim that a
well-formed digest names the supplied content.

No RF classifier, identity threshold, attack detector, or malicious-intent
inference was executed. The downloaded public corpora therefore contribute no
model-performance result at this checkpoint.

The WLAN RFF layout checkpoint verified both publisher archive digests and 411
NPZ members without opening a member payload. Each archive contains five
distinct device-shaped filename tokens, all five tokens occur in both
environments, and no session token occurs in both. This establishes a candidate
cross-environment grouping key, not physical-device or physical-source truth.

The hypothesis-metrics checkpoint passed seven hermetic tests and the existing
twelve hypothesis-frame tests. These are contract checks over synthetic opaque
identifiers; they are not classifier-performance results.

The relation-split checkpoint passed thirteen hermetic tests over all eleven
group axes and all six role pairs. Reports retain only opaque partition IDs and
aggregate group-intersection counts; they never emit group values or raw corpus
labels. This validates the manifest/audit boundary, not any corpus split.

The OSU oracle-compiler contract passed eleven hermetic tests plus the nine
metadata-profiler tests. A live full-tree manifest was not produced while
downloads were mutating the tree; the compiler failed closed on that changing
inventory as required.

The RUFF-UWB compiler passed seven hermetic tests and a receipt-enforced run on
both public archives. It reduced 1,923,723 label rows to 1,790 observed
source/location/campaign cells covering 13 source labels, one declared variant,
two collection days, one fixed receiver, channel 5, and 150 campaign-fenced
location groups. It opened zero waveform members. These are oracle inventory
counts, not model predictions or independent event samples.

The GNSS RFF layout profiler passed nine hermetic tests and verified the public
6,358,035,306-byte archive. Its central directory contains 13,354 data members:
8,000 from the first day and 5,354 from the second. Six of eight
category/scenario pairs have members on both days. All 13,363 file members are
traditionally encrypted, and the profiler opened zero member payload streams
and used no password. These are layout counts, not classifier results.

## Conclusion

The source-neutral hypothesis-set boundary and its exact-rational compatibility
oracle are implemented and fail closed for the tested evidence gaps. This does
not validate physical-source identity or attack attribution. The next
evidence-bearing step is to construct leakage-safe relation labels and splits
from the public multi-device, multi-domain, clone, replay, and benign-confounder
corpora before choosing an RF model or threshold.
