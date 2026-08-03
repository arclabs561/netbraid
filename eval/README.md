# Evaluation

This directory contains executable measurements of Netbraid behavior.

- `fixtures/` contains bounded synthetic or reviewed public-safe inputs.
- `experiments/` records aggregate methods, provenance, results, and limits.
- `evaluate-*.py` implements dataset-backed evaluators.
- `profile-*.py` inspects bounded corpus structure without promoting it to a
  production contract.
- `test-*.py` provides exact hermetic oracles for the harnesses.

`counter_capture_campaign.py` evaluates a bounded campaign containing only
identifier-free traffic windows. Collection paths, addresses, interfaces, and
deployment-selected runs remain outside this repository.

`hypothesis_frame.py` validates evaluation-only pair labels for artifact,
content, event, claimed-identifier, cryptographic-principal, physical-device,
physical-source, software, configuration, variant, and lineage relations. It
keeps integrity, admissibility, freshness, continuity, transmission, scenario
cause, authorization, intent, and tamper evidence separate. The strict schema
rejects bare identity or attack labels and contains no raw observations or
deployment identifiers.

`hypothesis_metrics.py` evaluates those qualified relation axes without
collapsing them into one identity or attack score. Its strict manifest accepts
only opaque frame and stratum identifiers, reports raw confusion/support and
abstention counts, and keeps unknown references separate from predictions that
decline to decide. Its joined evaluation schema takes a validated hypothesis
frame manifest plus relation-only prediction rows, requires an exact frame-ID
bijection, and derives references from the frames. Bounded qualified cells keep
physical-device, physical-source, variant, integrity, cause, authorization,
intent, provenance, and tamper evidence together without permitting a generic
identity, malicious, or tampered prediction.

`relation_split_audit.py` checks opaque observation-group manifests across
train, calibration, validation, and test roles. Policies declare forbidden
role-pair overlap separately for event, source, device, variant, session, and
domain-shift axes; unknown coverage makes a required comparison unknown rather
than silently passing it.

`profile-wlan-rff-layout.py` verifies the two pinned WLAN RFF archives and
profiles their strict filename grammar without opening NPZ payloads. Its
aggregate report can establish cross-environment token reuse, but deliberately
does not promote publisher-undocumented tokens to physical-device or
physical-source identity.

`profile-gnss-rff-layout.py` verifies the pinned GNSS RFF archive and profiles
its encrypted ZIP central directory without accepting a password or opening a
member payload. It reports controlled clean/spoof, day, and acquisition-category
coverage while keeping sequence tokens and member paths out of the report.
Spoof is a controlled cause label, not proof of malicious intent, tamper, actor
identity, event identity, or physical-source identity.

`compile-osu-lora-oracles.py` converts a strict OSU LoRa SigMF tree into an
ignored observation inventory with opaque group identifiers. Physical-device
and physical-source groups are fenced by publisher setup family; the compiler
does not assume cross-scenario identity continuity, assign train/test roles, or
open IQ/FFT payload streams.

`compile-ruff-uwb-oracles.py` verifies the two pinned RUFF-UWB archives and
reads only their bounded label arrays. It aggregates observed
source/location/campaign cells, preserves cross-day source and device identity,
and fences locations by distance campaign. The fixed receiver, channel 5, and
collection day are explicit controls; event and session remain unobserved. The
compiler emits opaque groups without opening waveform members or synthesizing
missing source/location combinations.

`compile-mmwave-jamming-oracles.py` hashes all 80 pinned MAT artifacts without
parsing them and compiles the exact receiver/regime/target/condition grid into
40 opaque with/without-jammer pairs. Receiver element, radar regime, radar
configuration, and target count remain explicit split groups. Jammer presence
is a controlled cause, not malicious intent, tamper, event, device, variant, or
physical-source truth.

`compile-indoor-jamming-oracles.py` binds the publisher workbook to the exact
three HDF5 datasets in each of 31 MAT files. It reads dataset metadata but no
dataset elements, producing 93 opaque condition segments with file, setup,
power, and distance split groups. Receipt-only mode reports that it did not
rehash payload bytes; `--integrity full-digest` rehashes all artifacts. The
compiler assigns no identity, intent, tamper, or train/test labels.

Manifest schema v1 is the frozen 24-run compatibility profile. Schema v2 adds
an explicit policy for opaque regime tokens, per-regime split sizes, candidate
count, truth position, and an engineering acceptance threshold. V2 also
requires campaign-local split-group IDs and rejects group overlap between
calibration and held-out runs. Because outcomes share calibration scales and
can reuse candidate windows, v2 reports raw numerators, denominators, and
abstentions without a binomial confidence interval.

Evaluators read ignored artifacts from `data/raw/` and write ignored results to
`data/derived/eval/`. A dataset result is not a unit test and is not part of the
default CI gate unless its oracle is exact and corpus-independent.

Derived campaign artifacts must have a checked-in producer and canonical
`just` recipe; an interactive shell transcript is not provenance. The IoT-23
lineage campaign is the reference pattern: `just iot23-flow-lineage` derives
flows and evaluates them twice, rejects byte drift, and writes a path-free
receipt beside the ignored outputs. Its hermetic producer/evaluator boundary is
covered by `just iot23-flow-lineage-check` without requiring corpus bytes.
