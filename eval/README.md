# Evaluation

This directory contains executable measurements of Netbraid behavior.

- `fixtures/` contains bounded synthetic or reviewed public-safe inputs.
- `experiments/` records aggregate methods, provenance, results, and limits.
- `evaluate-*.py` implements dataset-backed evaluators.
- `profile-*.py` inspects bounded corpus structure without promoting it to a
  production contract.
- `test-*.py` provides exact hermetic oracles for the harnesses.

`audit-modality-coverage.py` validates the eval-facing modality registry. The
registry keeps radio technology, carrier regime, representation, observation
level, and evaluation readiness on separate axes. A downloaded or profiled
corpus is not counted as an evaluated surface, and cross-technology
classification is not counted as synchronized fusion.

`counter_capture_campaign.py` evaluates a bounded campaign containing only
identifier-free traffic windows. Collection paths, addresses, interfaces, and
deployment-selected runs remain outside this repository.

`hypothesis_frame.py` validates evaluation-only pair labels for artifact,
content, event, event-performer, claimed-identifier, cryptographic-principal,
physical-device, physical-source, software, configuration, variant, and
lineage relations. An event performer is the entity performing the activity
that defines the event; it is not a generic actor, RF source, device, principal,
or intent label. The frame keeps integrity, admissibility, freshness,
continuity, transmission, scenario cause, authorization, intent, and tamper
evidence separate. The strict schema rejects bare identity or attack labels and
contains no raw observations or deployment identifiers.

`hypothesis_metrics.py` evaluates those qualified relation axes without
collapsing them into one identity or attack score. Its strict manifest accepts
only opaque frame and stratum identifiers, reports raw confusion/support and
abstention counts, and keeps unknown references separate from predictions that
decline to decide. Its joined evaluation schema takes a validated hypothesis
frame manifest plus relation-only prediction rows, requires an exact frame-ID
bijection, and derives references from the frames. Bounded qualified cells keep
physical-device, physical-source, variant, integrity, cause, authorization,
intent, provenance, and tamper evidence together without permitting a generic
identity, malicious, or tampered prediction. Its partial-prediction composer
combines decisions only across the named relation axes: abstention is neutral,
equal decisions are idempotent, unspecified axes abstain, and two different
decisions on one axis fail closed instead of being silently fused.

`hypothesis_belief_metrics.py` evaluates finite normalized beliefs without
changing the relation ontology. It is source-agnostic only over the existing
`hypothesis_frame` relation axes; RSSI endpoint variables and other factor-family
states require their own evaluator or an explicit future contract. Each row is
exact, solver-abstained, or infeasible. Exact rows must distribute one billion
integer parts across every non-unknown state of that axis. Validated hypothesis
frames supply references; unknown references are not latent classes and remain
unscored. Per-axis multiclass Brier totals are a quadratic diagnostic for
heuristic-relative weights. They have a proper-score interpretation only for
probability forecasts over the declared exhaustive outcomes, and the selective
score must be read with coverage and outcome counts. Fixed top-state confidence
bins are raw diagnostics; the report emits no ECE or cross-axis aggregate. The
belief-evaluation profile is canonicalized and domain-hashed from its document,
including bounded family-specific configuration slots; the report retains only
its identifier, digest, and declared semantics. The caller remains responsible
for making those slots complete. Neither semantics label is an empirical
calibration claim.

`evaluate-sorbonne-rssi-explanation.py` compares unsynchronized 1 m and 50 m
RSSI conditions through the non-packet shift-explanation API. Ten observer
filenames become closed synthetic roles and the one address becomes a constant
source role after an integrity-only uniqueness check. Only RSSI reaches Rust;
time, sequence, event, frame, channel, packet-type, address, and condition
fields do not. The bridge emits aggregate heuristic-relative beliefs without
caller identifiers. This is a dependent condition-sensitivity check, not a
distance, location, identity, cause, tamper, intent, calibration, or
generalization result.

`calibrated_event_relation.py` is the strict evaluation-only boundary between
bidirectional model distances and one event-relation decision. A content-bound
profile fixes model, feature, input, fit, calibration, threshold, and quantile
provenance. Both directions must agree outside a deliberate score gap to emit
`same` or `different`; every other result abstains. Scores are canonical
nonnegative binary64 values, not probabilities. The schema has no generic
relation map or actor, performer, identifier, principal, device, source,
ownership, intent, or tamper field, and it does not alter the Rust inference
API.

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

`profile-sdr4iot-layout.py` verifies the pinned SDR4IoT archive and profiles its
BLE and Zigbee collection structure without opening capture, CSV, or
publisher-named SigMF payloads. It counts candidate packet/table/signal
artifact groups separately for each protocol and reports receiver-token reuse
across protocols. Filename co-grouping does not establish payload alignment,
event identity, cross-protocol identity, physical device/source identity,
location truth, or SigMF conformance.

`evaluate-public-corpus-slices.py` includes one complete SDR4IoT Bluetooth LE
capture. It runs the saved-capture normalizer twice and checks typed packet,
PDU, address-field-presence, header-flag, checked-CRC, channel, and
validity-gated signal/noise aggregates. Its report omits observed addresses,
access addresses, record IDs, raw rows, paths, and capture bytes. Random-address
flags remain packet evidence; the evaluator performs no identity inference.

`profile-gnss-rff-layout.py` verifies the pinned GNSS RFF archive and profiles
its encrypted ZIP central directory without accepting a password or opening a
member payload. It reports controlled clean/spoof, day, and acquisition-category
coverage while keeping sequence tokens and member paths out of the report.
Spoof is a controlled cause label, not proof of malicious intent, tamper, actor
identity, event identity, or physical-source identity.

`profile-osu-lora-sigmf.py` inventories the bounded SigMF tree without reading
IQ payload bytes. Three publisher-malformed metadata objects have an exact
size-and-SHA erratum for prepending the missing opening object brace; drift or
any other malformed metadata still fails closed. The aggregate report retains
only the repair count and a domain-separated receipt, never the affected paths.
Pairing and payload-extent failures remain independent hard oracle gates.

`compile-osu-lora-oracles.py` converts a strict OSU LoRa SigMF tree into an
ignored observation inventory with opaque group identifiers. Physical-device
and physical-source groups are fenced by publisher setup family; the compiler
does not assume cross-scenario identity continuity, assign train/test roles, or
open IQ/FFT payload streams.

`build-osu-lora-relation-split.py` tests whether that v0 oracle can support a
leakage-safe train/calibration/validation/test assignment. It co-locates all
observations connected by known event or session groups, validates the result
with the canonical relation-split auditor, and never substitutes setup, day,
domain, receiver, location, path, or input order for missing session evidence.
The current oracle therefore returns `unbounded_session_axis` and publishes no
manifest; the hermetic check covers the successful known-session boundary.

`compile-smorffi-csv-iq-adapter.py` verifies the pinned local SMoRFFI inventory
while streaming its variable-length complex preambles into a flat complex NPY
and a half-open row-offset NPY. Both arrays support read-only memory mapping.
The adapter retains opaque contiguous source spans but no filename, address,
publisher device value, or local path. One malformed header is repaired only
for its exact receipt-bound SHA-256 and exact three-cell shape; every other
header deviation fails closed. Publisher device labels remain claims rather
than independently verified physical identity. The compiler also records the
observed ragged sequence lengths instead of treating the publisher's nominal
288-sample description as an established boundary.

`evaluate-smorffi-relation-split-capability.py` reads only that adapter's
metadata. The capability audit passes, but its nested relation split remains
blocked with `unbounded_session_axis`: file boundaries, row order, row count,
filenames, and filesystem times are not acquisition-session evidence. It
publishes no split manifest and reads no IQ or row-offset payload bytes.
`just smorffi-rust-vector-adapter` separately reopens both generated rank-one
arrays through the public bounded NPY vector projection, checks the exact
complex and unsigned dtypes and extents, and verifies that the complete offset
vector is strictly increasing from zero to the IQ sample count.

`profile-xrf55-layout.py` validates the three local XRF55 archive and receipt
metadata contracts, bounds their ZIP central directories, and reports aggregate
format, path-depth, and cross-archive path-overlap evidence. The publisher's
scene-scoped subject/action/repetition grammar must form complete synchronized
Wi-Fi/RFID/mmWave event triples. It never opens member payloads or retains
member names or identifier values. Receipt validation is reported separately
from the intentionally deferred full archive rehash; performer groups are not
promoted to RF-device or physical-source identity.

`compile-xrf55-hypothesis-frames.py` converts the complete processed event grid
into a bounded deterministic v2 frame sample. It covers synchronized
cross-modal events, same-performer different-event controls, and
different-performer controls with opaque IDs. Cross-modal frames deliberately
permit one event and performer to have different sensing devices and physical
RF sources; intent, tamper, freshness, and unobserved infrastructure relations
remain unknown rather than inferred from action labels.

`profile-xrf55-npy-shapes.py` validates the processed layout and then opens one
bounded NPY header per distinct archive/modality/member-size class. It rejects
object or structured dtypes, malformed extents, oversized members, and more
than 16 size classes per modality. Reports retain only aggregate shape, dtype,
order, and byte evidence; no array element is deserialized and no member name,
observation identifier, or path is retained. The measured complete-event byte
cost bounds the later private feature-cache campaign before payload I/O begins.

`compile-xrf55-feature-cache.py` hash-selects eight complete performer/action
groups and streams their 160 tri-modal events without extracting the archives.
The feature policy follows the publisher model geometry: Wi-Fi and RFID are
summarized across sequence and channel bins, while mmWave is summarized across
its two-dimensional grid and channel bins. Each region contributes four fixed
moments, producing one 96-value vector per event and modality. Only opaque
group/event IDs and repetition roles enter the path-free adapter; raw scene,
performer, action, archive, member, and local-path values are omitted. Matrices
and adapters are written atomically with mode 0600 and are ignored by Git.

`evaluate-xrf55-cross-modal-retrieval.py` verifies the adapter and matrix
digests before reopening all three matrices as read-only NumPy memmaps. For
each ordered modality pair it standardizes on publisher-train repetitions
1–14, fits one fixed-alpha ridge map, and retrieves each held-out repetition
15–20 only among the six events with the same opaque performer/action group.
It reports exact-event top-1 and mean reciprocal rank for every direction and
group, alongside a direct unaligned-feature control and the theoretical
six-candidate chance reference. No real-data hyperparameter tuning or
cross-direction aggregate hides a weak modality pair.

`evaluate-xrf55-calibrated-event-relation.py` fixes Wi-Fi/RFID as one
unordered modality pair, fits reciprocal ridge maps on repetitions 1 through
8, selects directional same/different thresholds from repetitions 9 through
11, and gates the one-shot repetitions 15 through 20 score on repetitions 12
through 14. Pair candidates stay inside one opaque performer/action group.
The report uses exact dependent-pair confusion, coverage, selective-risk,
false-link, false-nonmatch, and reciprocal-disagreement counts; it emits no
row-level probability or confidence interval. Its qualified projection can
change only `event_relation`; all identity-bearing axes abstain.

`evaluate-ujiindoorloc-split-capability.py` streams the pinned IPIN 2015 Track
3 CSV members after verifying the archive and central receipt. It reports
aggregate user, phone, building, floor, building/floor, and location-cell
intersections across the publisher files. Identity/domain holdout capability is
kept separate from target-space coverage; no fingerprint rows, coordinates,
timestamps, identifier values, member paths, source URLs, or local paths enter
the report. Its separate phone-holdout mode tests whether the combined corpus
admits four phone-disjoint roles with complete building/floor coverage. It also
co-locates every user/phone connected component to expose the stricter joint
holdout boundary. The aggregate witness is a feasibility result, not a chosen
benchmark split, and retains neither identifiers nor group assignments.

`evaluate-ujiindoorloc-phone-holdout.py` uses that deterministic four-role
phone split for a 13-class building/floor nearest-centroid baseline. Feature
handling and centroids use train only, the abstention margin uses calibration
only, and a fixed validation gate decides whether test RSSI rows are read. The
report keeps raw reconciliation, coverage, selective error, and macro,
per-phone, and per-class counts without retaining phone values, coordinates,
fingerprints, rows, or paths. It does not evaluate fine-grained location.

`compile-ruff-uwb-oracles.py` verifies the two pinned RUFF-UWB archives and
reads only their bounded label arrays. It aggregates observed
source/location/campaign cells, preserves cross-day source and device identity,
and fences locations by distance campaign. The fixed receiver, channel 5, and
collection day are explicit controls; event and session remain unobserved. The
compiler emits opaque groups without opening waveform members or synthesizing
missing source/location combinations.

`compile-ruff-uwb-row-adapter.py` verifies either pinned one- or two-meter
archive and its central fetch receipt, parses the label member in publisher
order, and emits gap-free opaque row spans. It stream-extracts the waveform
member to an ignored standalone NPY with full digest, CRC, extent, permission,
and source-mutation checks; it never performs bulk archive extraction.

`build-ruff-uwb-open-set-source-split.py` prepares a fixed 4/3/3/3
device-disjoint train/calibration/validation/test split across both campaigns.
It reads only opaque oracle metadata, requires a shared bijective source/device
map, and publishes a manifest only if the canonical auditor can also prove
event and session separation. The current publisher metadata does not expose
those two axes, so the real command fails before waveform I/O; the hermetic
check covers the complete future contract without weakening that gate.

`evaluate-ruff-uwb-heldout-location.py` defines a deterministic 80/10/10
held-out-location baseline with atomic source/device/location groups, bounded
row and window sampling, read-only NumPy mmap, train-only prototype fitting,
and validation-only model selection. `just ruff-uwb-heldout-location` retains
the aggregate-oracle blocker, while `just ruff-uwb-heldout-location-real`
compiles the receipt-bound row adapter and runs the real one-meter evaluation.
The synthetic exact boundaries are covered by the corresponding `-check`
recipes.

`evaluate-ruff-uwb-cross-distance.py` fits and selects only on one-meter
train/validation locations, quarantines the previously observed one-meter test
role, then evaluates once across all two-meter locations. Both adapters remain
compact until exact SHA-256 top-k row selection, and both waveform arrays are
opened by read-only mmap after full digest verification. The result measures a
combined distance, day, room-position, and stored-representation shift, not an
isolated distance effect. `verify-ruff-uwb-cross-campaign-experiment.py` binds
the tracked aggregate result summary to the ignored canonical report without
opening either waveform array.

`compile-mmwave-jamming-oracles.py` hashes all 80 pinned MAT artifacts without
parsing them and compiles the exact receiver/regime/target/condition grid into
40 opaque with/without-jammer pairs. Receiver element, radar regime, radar
configuration, and target count remain explicit split groups. Jammer presence
is a controlled cause, not malicious intent, tamper, event, device, variant, or
physical-source truth.

`profile-mmwave-jamming-mat-layout.py` fully re-admits those artifacts, then
reads MAT v5 variable metadata without materializing array values. It compares
the combined named layout, variable names alone, array shape/class alone, exact
file extent, and one-MiB extent class only within the 40 matched condition
pairs. Paths, filenames, variable names, condition labels, and per-artifact
rows are absent from the report. A mismatch blocks that metadata from later
feature extraction; it is not evidence of a detector.

`compile-mmwave-jamming-paired-grid.py` re-admits each MAT artifact on the
descriptor used for payload parsing. Within each opaque matched pair it takes
the elementwise common ADC-sample, chirp, and frame extent, then applies the
same fixed integer-stratified indices to both members. It writes an ignored
16 by 16 by 8 real/imaginary float32 NPY cache directly through a temporary
memmap and records only opaque row bindings in the adapter. Source geometry,
names, paths, storage details, byte counts, digests, pair IDs, and condition
labels are absent. The cache is an input boundary for later evals, not a
detector or a train/test assignment.

`evaluate-mmwave-jamming-receiver-crossfit.py` joins that cache to the
separate oracle and scores every matched pair once while its receiver group is
held out. A fixed five-feature nearest-centroid baseline is fitted only on the
other three receiver groups. The primary result is within-pair score ordering
with a nominal sign diagnostic; thresholded row metrics remain secondary. The
inferential gate stays blocked because reciprocal cross-fit predictions are
dependent and pair independence is not established. Because the cache
coordinates are derived jointly within each matched pair, this measures paired
corpus discrimination rather than standalone or live detection.
`verify-mmwave-jamming-experiment.py` binds the tracked aggregate result in
experiment 0028 to the ignored canonical report.

`compile-indoor-jamming-oracles.py` binds the publisher workbook to the exact
three HDF5 datasets in each of 31 MAT files. It reads dataset metadata but no
dataset elements, producing 93 opaque condition segments with file, setup,
power, and distance split groups. Receipt-only mode reports that it did not
rehash payload bytes; `--integrity full-digest` rehashes all artifacts. The
compiler assigns no identity, intent, tamper, or train/test labels.

`evaluate-indoor-jamming-controlled-cause.py` is a preregistered conditional
smoke eval over assigned power 0.5 and distance 10 m. It holds jammer setups
apart across a fixed 9/6/9 train/validation/test split, reads four common
bounded HDF5 windows per observation, and fits a train-only nearest-centroid
baseline with explicit abstention. Validation gates the one-shot test; the
result does not support population-level setup, Tx/Rx, power, distance,
identity, tamper, actor, or malicious-intent claims.

`verify-indoor-jamming-experiment.py` compares the machine-readable result
summary in experiment 0007 with the ignored canonical report. The real recipe
fails if tracked metrics, read counts, abstentions, gate status, or test-use
state drift from the producer output.

`hdf5_window.py` is the bounded payload seam for that corpus. It accepts only a
direct, singly linked, rank-two float64 dataset with two rows, gzip-only chunked
storage, an 8 GiB source ceiling, a 64 MiB chunk ceiling, and a 64 MiB absolute
hyperslab ceiling. It reads only the selected column interval and returns
path-free per-row aggregates; it does not assign condition or identity labels.

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

The derived-artifact contract is a presence allowlist: declared outputs and the
entire derived root may be absent, so the audit is suitable for a fresh clone.
When an output is present, it must be classified. A `reproducibility_output`
entry must name a checked-in Python producer and canonical `just` recipe. The
audit parses the producer AST, requires an executable `__main__` entrypoint, and
tracks output defaults and argparse options through reachable calls to an
output-writing sink. The named recipe's actual Python/`uv` invocation must use
that producer path and, when it overrides the default, a producer-declared
output option. Comments, `echo`, unused literals, and no-op entrypoints do not
count. This is a prospective static wiring guarantee, not proof that retained
bytes came from that producer or recipe.

The IoT-23 lineage campaign is the reference pattern. Running
`just iot23-flow-lineage` derives flows, evaluates them, and profiles the same
publisher log through the Rust Zeek adapter twice. It rejects byte drift and
requires the independent parser paths to agree on row and duration coverage
before writing a path-free receipt beside the ignored outputs. Its hermetic
producer/evaluator/adapter boundary is covered by
`just iot23-flow-lineage-check` without requiring corpus bytes. The Sorbonne same-event recipe likewise writes
two reports and rejects byte drift. Older local reports whose producer context
predates this rule are not active derived outputs: `just
legacy-derived-migration` preserves only their fixed allowlist under
`data/archive/legacy-derived-unknown/` with a path-free integrity receipt. The
script also relocates and verifies the former archive location without
overwriting either state. `just derived-artifact-audit` therefore requires
every file under `data/derived/` to have a checked-in producer and recipe, and
fails closed on unclassified outputs, unsafe filesystem entries, missing
recipes, and private or absolute paths. It inventories metadata only and emits
bounded aggregate counts; it never opens retained artifact contents.
