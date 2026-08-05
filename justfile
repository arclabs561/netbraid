python := env_var_or_default("PYTHON", "python3")
raw_data := "data/raw"
eval_output := "data/derived/eval"

check: rust-check scenario-check python-check

test: check

python-check:
    {{ python }} eval/run-python-tests.py

rust-check:
    cargo fmt --manifest-path rust/Cargo.toml --all -- --check
    cargo check --manifest-path rust/fuzz/Cargo.toml --bin parse_saved_capture_jsonl
    cargo test --locked --manifest-path rust/Cargo.toml --no-default-features
    cargo check --locked --manifest-path rust/Cargo.toml --lib --no-default-features --features scenario-fixtures,scenario-fixtures-capture-derived
    cargo build --locked --manifest-path rust/Cargo.toml
    cargo test --locked --manifest-path rust/Cargo.toml
    cargo test --locked --manifest-path rust/Cargo.toml --no-default-features --example rssi_shift_explanation_jsonl
    cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --no-deps

scenario-check:
    cargo test --locked --manifest-path rust/Cargo.toml --all-features
    cargo clippy --locked --manifest-path rust/Cargo.toml --all-targets --all-features -- -D warnings
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --manifest-path rust/Cargo.toml --all-features --no-deps
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/wifi-hotspot-wifi/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/vpn-overlay-transition/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/cache-source-gap/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/host-path.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/same-ssid-attachment-boundary/viewport.txt'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/scenario.json'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/prefix-6.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/prefix-7.jsonl'
    @cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Fqx 'tests/fixtures/replay/scenarios/saved-capture-prefix-boundary/LICENSE-libpcap-BSD-3-Clause.txt'
    @! cargo package --locked --allow-dirty --manifest-path rust/Cargo.toml --list -p netbraid | grep -Eq '^tests/(adapter_curated_corpus\.rs$|fixtures/adapter/(third-party-licenses|upstream)/|fixtures/[^/]+\.hex$|pcap_cli\.rs$|scenario_cli\.rs$)'

pcap-smoke:
    cargo test --locked --manifest-path rust/Cargo.toml --test adapter_tshark_smoke --test adapter_curated_corpus -- --ignored
    cargo build --locked --manifest-path rust/Cargo.toml --example zeek_conn_profile --features adapter-zeek
    NETBRAID_ZEEK_PROFILE_BIN="$PWD/rust/target/debug/examples/zeek_conn_profile" cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored

counter-capture-eval-check:
    {{ python }} eval/test-counter-capture-eval.py
    {{ python }} eval/test-counter-capture-campaign.py

hypothesis-frame-check:
    {{ python }} eval/test-hypothesis-frame.py

hypothesis-metrics-check:
    {{ python }} eval/test-hypothesis-metrics.py

hypothesis-belief-metrics-check:
    {{ python }} eval/test-hypothesis-belief-metrics.py

provenance-perturbation-check:
    {{ python }} eval/test-provenance-perturbations.py

calibrated-event-relation-check:
    {{ python }} eval/test-calibrated-event-relation.py

relation-split-audit-check:
    {{ python }} eval/test-relation-split-audit.py

wlan-rff-layout-profile-check:
    {{ python }} eval/test-profile-wlan-rff-layout.py

wlan-rff-layout-profile:
    {{ python }} eval/profile-wlan-rff-layout.py

sdr4iot-layout-profile-check:
    {{ python }} eval/test-profile-sdr4iot-layout.py

# Verify the pinned archive and profile BLE/Zigbee collection structure twice.
# Capture, tabular, and publisher-named SigMF payloads remain unopened.
sdr4iot-layout-profile:
    {{ python }} eval/profile-sdr4iot-layout.py --report {{ eval_output }}/sdr4iot-layout-profile.json
    {{ python }} eval/profile-sdr4iot-layout.py --report {{ eval_output }}/sdr4iot-layout-profile-repeat.json
    cmp {{ eval_output }}/sdr4iot-layout-profile.json {{ eval_output }}/sdr4iot-layout-profile-repeat.json

sdr4iot-layer-alignment-check:
    {{ python }} eval/test-evaluate-sdr4iot-layer-alignment.py

# Compare packet, table, and signal metadata in every complete publisher group.
# The report is aggregate and the inspected development group is excluded.
sdr4iot-layer-alignment:
    {{ python }} eval/evaluate-sdr4iot-layer-alignment.py --report {{ eval_output }}/sdr4iot-layer-alignment-v0.json
    {{ python }} eval/evaluate-sdr4iot-layer-alignment.py --report {{ eval_output }}/sdr4iot-layer-alignment-v0-repeat.json
    cmp {{ eval_output }}/sdr4iot-layer-alignment-v0.json {{ eval_output }}/sdr4iot-layer-alignment-v0-repeat.json

smorffi-fetcher-check:
    uv run --python 3.10 data/tests/test-fetch-smorffi.py

smorffi-status:
    uv run --script data/fetch/fetch-smorffi.py status

smorffi-fetch:
    uv run --script data/fetch/fetch-smorffi.py fetch

smorffi-row-adapter-check:
    uv run --script eval/test-compile-smorffi-csv-iq-adapter.py

# Verify the exact local inventory and stream every variable-length preamble
# into private flat NPY arrays. The path-free adapter is replaced last.
smorffi-row-adapter:
    uv run --script eval/compile-smorffi-csv-iq-adapter.py

smorffi-split-capability-check:
    {{ python }} eval/test-evaluate-smorffi-relation-split-capability.py

# Read adapter metadata only. The successful audit records that a leakage-safe
# relation split is blocked because the publisher exposes no session axis.
smorffi-split-capability: smorffi-row-adapter
    {{ python }} eval/evaluate-smorffi-relation-split-capability.py

# Reopen the generated rank-one complex IQ and unsigned offset arrays through
# Netbraid's public bounded vector projection. No source path enters metadata.
smorffi-rust-vector-adapter: smorffi-row-adapter
    NETBRAID_SMORFFI_IQ="$PWD/data/derived/eval/smorffi-iq.npy" NETBRAID_SMORFFI_ROW_OFFSETS="$PWD/data/derived/eval/smorffi-row-offsets.npy" cargo test --locked --manifest-path rust/Cargo.toml --features adapter-npy --test adapter_npy generated_smorffi_vectors_project_through_the_public_adapter -- --ignored

controlled-jamming-fetcher-check:
    uv run --python 3.11 data/tests/test-fetch-controlled-jamming.py

controlled-jamming-list record="all":
    uv run --script data/fetch/fetch-controlled-jamming.py list {{ record }}

controlled-jamming-status record="all":
    uv run --script data/fetch/fetch-controlled-jamming.py status {{ record }}

controlled-jamming-fetch record max_total_bytes="137438953472" max_file_bytes="8589934592" workers="2":
    uv run --script data/fetch/fetch-controlled-jamming.py fetch {{ record }} --max-total-bytes {{ max_total_bytes }} --max-file-bytes {{ max_file_bytes }} --workers {{ workers }}

curated-eval-fetcher-check:
    uv run --python 3.11 data/tests/test-fetch-curated-eval.py

curated-eval-list selection="all":
    uv run --script data/fetch/fetch-curated-eval.py list {{ selection }}

curated-eval-status selection="all":
    uv run --script data/fetch/fetch-curated-eval.py status {{ selection }}

curated-eval-fetch selection="all" max_total_bytes="8589934592" max_file_bytes="2147483648":
    uv run --script data/fetch/fetch-curated-eval.py fetch {{ selection }} --max-total-bytes {{ max_total_bytes }} --max-file-bytes {{ max_file_bytes }}

hdf5-window-check:
    uv run --script eval/test_hdf5_window.py

catalog-check:
    {{ python }} data/tests/test-catalogs.py

legacy-derived-migration-check:
    {{ python }} data/tests/test-migrate-legacy-derived.py

# Preserve only the fixed legacy-output allowlist outside the active derived
# tree, then verify its path-free legacy/unknown receipt on every later run.
legacy-derived-migration:
    {{ python }} data/migrate/migrate-legacy-derived.py

derived-artifact-audit-check:
    {{ python }} eval/test-audit-derived-artifacts.py

# Fail if an ignored derived artifact lacks an exact checked-in producer and
# canonical recipe. The audit reads filesystem metadata, not artifact bytes.
derived-artifact-audit:
    {{ python }} eval/audit-derived-artifacts.py

modality-coverage-audit-check:
    {{ python }} eval/test-modality-coverage.py

modality-coverage-audit:
    {{ python }} eval/audit-modality-coverage.py --report {{ eval_output }}/modality-coverage-report.json

# Evaluate checked, bounded slices from the ignored public archives. Fetch the
# archives first; this target never admits or writes corpus bytes into Git.
public-corpus-eval-check:
    {{ python }} eval/test-evaluate-public-corpus-slices.py

public-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    {{ python }} eval/evaluate-public-corpus-slices.py --report {{ eval_output }}/public-corpus-eval-report.json

# Verify or fetch the exact public allowlist. Existing artifacts are fully
# rehashed; absent artifacts are downloaded through the bounded fetcher.
public-corpus-fetch dataset="all" verify_workers="4":
    uv run --script data/fetch/fetch-public-eval-corpus.py {{ dataset }} --verify-workers {{ verify_workers }}

# Write a path-free central-directory inventory for the selected allowlist.
public-corpus-inventory dataset="all" verify_workers="4":
    uv run --script data/fetch/fetch-public-eval-corpus.py {{ dataset }} --verify-workers {{ verify_workers }} --inspect --inspect-output {{ eval_output }}/public-corpus-inventory.json

# Materialize the receipt-bound BLE member used for adapter inspection. The
# capture and receipt remain ignored under the derived-data tree.
sdr4iot-ble-slice:
    uv run --script data/fetch/fetch-public-eval-corpus.py sdr4iot-ble-zigbee --extract-member ble/scenario1/scene1/20200316_1636/S1_s1_2020-03-16_16-36_server9_mobile5.cap --extract-dir {{ eval_output }}/sdr4iot-ble-slice --extract-output {{ eval_output }}/sdr4iot-ble-slice/S1_s1_2020-03-16_16-36_server9_mobile5.cap --max-extract-bytes 12375

ujiindoorloc-split-capability-check:
    {{ python }} eval/test-evaluate-ujiindoorloc-split-capability.py

ujiindoorloc-phone-holdout-check:
    {{ python }} eval/test-evaluate-ujiindoorloc-phone-holdout.py
    {{ python }} eval/test-evaluate-ujiindoorloc-split-capability.py

# Verify the pinned IPIN 2015 archive and report aggregate publisher-split
# intersections without retaining fingerprints, coordinates, or identifiers.
ujiindoorloc-split-capability:
    {{ python }} eval/evaluate-ujiindoorloc-split-capability.py

# Reassign the verified corpus in memory by acquisition phone, prove a
# four-role full-building/floor-coverage witness, and report the stricter
# user-plus-phone boundary separately. No group assignments are retained.
ujiindoorloc-phone-holdout-feasibility:
    {{ python }} eval/evaluate-ujiindoorloc-split-capability.py --phone-holdout-report {{ eval_output }}/ujiindoorloc-phone-holdout-feasibility.json
    {{ python }} eval/evaluate-ujiindoorloc-split-capability.py --phone-holdout-report {{ eval_output }}/ujiindoorloc-phone-holdout-feasibility-repeat.json
    cmp {{ eval_output }}/ujiindoorloc-phone-holdout-feasibility.json {{ eval_output }}/ujiindoorloc-phone-holdout-feasibility-repeat.json

# Fit only on phone-disjoint train rows, choose the abstention threshold only
# on calibration, gate test use on validation, and verify deterministic bytes.
ujiindoorloc-phone-holdout:
    {{ python }} eval/evaluate-ujiindoorloc-phone-holdout.py --report {{ eval_output }}/ujiindoorloc-phone-holdout-baseline-v0.json
    {{ python }} eval/evaluate-ujiindoorloc-phone-holdout.py --report {{ eval_output }}/ujiindoorloc-phone-holdout-baseline-v0-repeat.json
    cmp {{ eval_output }}/ujiindoorloc-phone-holdout-baseline-v0.json {{ eval_output }}/ujiindoorloc-phone-holdout-baseline-v0-repeat.json

# Evaluate the complete admitted capture-fixture manifest through the current
# production binary and retain only the ignored metadata report.
admitted-corpus-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    uv run --script eval/evaluate-admitted-corpus.py --out {{ eval_output }}/admitted-corpus-report.json

# Audit the complete Sorbonne 1 m cross-sniffer event oracle. This reports the
# synchronized-time leakage boundary; it does not run a predictive classifier.
sorbonne-same-event-audit:
    {{ python }} eval/evaluate-sorbonne-same-event.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-same-event-campaign-v0.json --report {{ eval_output }}/sorbonne-same-event-report.json
    {{ python }} eval/evaluate-sorbonne-same-event.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-same-event-campaign-v0.json --report {{ eval_output }}/sorbonne-same-event-report-repeat.json
    cmp {{ eval_output }}/sorbonne-same-event-report.json {{ eval_output }}/sorbonne-same-event-report-repeat.json

# Normalize the complete Sorbonne 1 m run, join the publisher event labels,
# and exercise the structural reducer once per distinct weighted pair basis.
sorbonne-structural-reducer-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    cargo build --locked --manifest-path rust/Cargo.toml --example packet_same_event_jsonl
    {{ python }} eval/evaluate-sorbonne-structural-reducer.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report {{ eval_output }}/sorbonne-structural-reducer-report.json
    {{ python }} eval/evaluate-sorbonne-structural-reducer.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-structural-reducer-campaign-v0.json --netbraid-bin rust/target/debug/netbraid --reducer-bin rust/target/debug/examples/packet_same_event_jsonl --report {{ eval_output }}/sorbonne-structural-reducer-report-repeat.json
    cmp {{ eval_output }}/sorbonne-structural-reducer-report.json {{ eval_output }}/sorbonne-structural-reducer-report-repeat.json

# Verify the RSSI condition evaluator and its aggregate-only Rust bridge
# without opening the corpus.
sorbonne-rssi-explanation-check:
    cargo test --locked --manifest-path rust/Cargo.toml --no-default-features --example rssi_shift_explanation_jsonl
    {{ python }} eval/test-evaluate-sorbonne-rssi-explanation.py

# Compare the unsynchronized 1 m control and 50 m condition through the
# source-agnostic RSSI explanation API. Reports contain aggregate values only.
sorbonne-rssi-explanation-eval:
    cargo build --locked --manifest-path rust/Cargo.toml --no-default-features --example rssi_shift_explanation_jsonl
    {{ python }} eval/evaluate-sorbonne-rssi-explanation.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-rssi-explanation-campaign-v0.json --bridge-bin rust/target/debug/examples/rssi_shift_explanation_jsonl --report {{ eval_output }}/sorbonne-rssi-explanation-report.json
    {{ python }} eval/evaluate-sorbonne-rssi-explanation.py --archive {{ raw_data }}/220211012-SU-Outdoors-Campus.zip --campaign eval/fixtures/sorbonne-rssi-explanation-campaign-v0.json --bridge-bin rust/target/debug/examples/rssi_shift_explanation_jsonl --report {{ eval_output }}/sorbonne-rssi-explanation-report-repeat.json
    cmp {{ eval_output }}/sorbonne-rssi-explanation-report.json {{ eval_output }}/sorbonne-rssi-explanation-report-repeat.json

# Verify the bounded OPERAnet archive-layout profiler without corpus data.
operanet-layout-profile-check:
    {{ python }} eval/test-profile-operanet-layout.py

# Verify all pinned OPERAnet archives and profile only their ZIP metadata.
# Member payload streams are never opened, extracted, or deserialized.
operanet-layout-profile:
    {{ python }} eval/test-profile-operanet-layout.py
    {{ python }} eval/profile-operanet-layout.py --report {{ eval_output }}/operanet-layout-profile.json
    {{ python }} eval/profile-operanet-layout.py --report {{ eval_output }}/operanet-layout-profile-repeat.json
    cmp {{ eval_output }}/operanet-layout-profile.json {{ eval_output }}/operanet-layout-profile-repeat.json

# Verify the exp018 semantic-alignment profiler without corpus data.
operanet-semantic-alignment-check:
    uv run --script eval/test-profile-operanet-semantic-alignment.py

# Compare activity labels on a fixed grid across the pinned exp018 Kinect,
# power, and two UWB payloads. This is a development-only joinability profile,
# not a fusion or identity result.
operanet-semantic-alignment-profile:
    uv run --script eval/test-profile-operanet-semantic-alignment.py
    uv run --script eval/profile-operanet-semantic-alignment.py --report {{ eval_output }}/operanet-semantic-alignment-profile.json
    uv run --script eval/profile-operanet-semantic-alignment.py --report {{ eval_output }}/operanet-semantic-alignment-profile-repeat.json
    cmp {{ eval_output }}/operanet-semantic-alignment-profile.json {{ eval_output }}/operanet-semantic-alignment-profile-repeat.json

# Profile a bounded CAEZ CSI shape slice directly from the verified local tar.
# The target never extracts members or deserializes position/model payloads.
caez-csi-profile:
    {{ python }} eval/profile-caez-csi-slices.py

# Stream the publisher position CSV and a fixed frame-metadata sample directly
# from the verified CAEZ tar. Column/time semantics remain explicitly unknown.
caez-alignment-profile:
    {{ python }} eval/test-profile-caez-alignment.py
    {{ python }} eval/profile-caez-alignment.py --report {{ eval_output }}/caez-alignment-profile.json
    {{ python }} eval/profile-caez-alignment.py --report {{ eval_output }}/caez-alignment-profile-repeat.json
    cmp {{ eval_output }}/caez-alignment-profile.json {{ eval_output }}/caez-alignment-profile-repeat.json

# Verify the complete Data4Cyber archive and profile only bounded structural
# evidence needed to assess whether a future cross-layer join is possible.
data4cyber-alignment-profile:
    {{ python }} eval/test-profile-data4cyber-alignment.py
    {{ python }} eval/profile-data4cyber-alignment.py --report {{ eval_output }}/data4cyber-alignment-profile.json
    {{ python }} eval/profile-data4cyber-alignment.py --report {{ eval_output }}/data4cyber-alignment-profile-repeat.json
    cmp {{ eval_output }}/data4cyber-alignment-profile.json {{ eval_output }}/data4cyber-alignment-profile-repeat.json

# Verify the pinned NetsLab archive/databases, using bounded read-only SQLite
# mmap where available, and emit aggregate schema/alignment metadata only.
netslab-alignment-profile:
    {{ python }} eval/test-profile-netslab-alignment.py
    {{ python }} eval/profile-netslab-alignment.py --report {{ eval_output }}/netslab-alignment-profile.json
    {{ python }} eval/profile-netslab-alignment.py --report {{ eval_output }}/netslab-alignment-profile-repeat.json
    cmp {{ eval_output }}/netslab-alignment-profile.json {{ eval_output }}/netslab-alignment-profile-repeat.json

# Exercise the strict packet-to-publisher-flow oracle without requiring the
# ignored IoT-23 corpus. Production use supplies externally sessionized flows.
iot23-flow-lineage-check:
    {{ python }} eval/test-evaluate-iot23-flow-lineage.py
    {{ python }} eval/test-run-iot23-flow-lineage-campaign.py
    cargo build --locked --manifest-path rust/Cargo.toml --example zeek_conn_profile --features adapter-zeek
    NETBRAID_ZEEK_PROFILE_BIN="$PWD/rust/target/debug/examples/zeek_conn_profile" cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli pcap_flows_tsv_drives_the_hermetic_production_lineage_campaign -- --ignored

# Reproduce packet-flow derivation and oracle evaluation twice from the pinned
# ignored IoT-23 pair, then write a path-free deterministic campaign receipt.
iot23-flow-lineage:
    cargo build --locked --manifest-path rust/Cargo.toml --bin netbraid
    cargo build --locked --manifest-path rust/Cargo.toml --example zeek_conn_profile --features adapter-zeek
    {{ python }} eval/run-iot23-flow-lineage-campaign.py --capture {{ raw_data }}/iot23v2-hakai-capture-8-1.pcap --zeek-log {{ raw_data }}/iot23v2-hakai-capture-8-1-zeek.log.labeled --netbraid-bin rust/target/debug/netbraid --zeek-profile-bin rust/target/debug/examples/zeek_conn_profile --output-dir {{ eval_output }}/iot23-flow-lineage-v1

# Fetch pinned XRF55 bundles into the ignored corpus directory. Archives are
# never extracted; a local SHA-256 receipt protects reuse after acquisition.
xrf55-fetcher-check:
    {{ python }} data/tests/test-fetch-xrf55.py

xrf55-fetch dataset="list":
    {{ python }} data/fetch/fetch-xrf55.py {{ dataset }}

# Report archive/receipt readiness without hashing the 196 GB payload corpus.
# This is metadata-only and never claims that payload integrity was verified.
xrf55-status:
    {{ python }} data/fetch/fetch-xrf55.py status

# Inspect only bounded ZIP metadata. The report records receipt validation but
# explicitly does not claim a fresh archive-payload digest verification.
xrf55-layout-profile:
    {{ python }} eval/test-profile-xrf55-layout.py
    {{ python }} eval/profile-xrf55-layout.py --report {{ eval_output }}/xrf55-layout-profile.json
    {{ python }} eval/profile-xrf55-layout.py --report {{ eval_output }}/xrf55-layout-profile-repeat.json
    cmp {{ eval_output }}/xrf55-layout-profile.json {{ eval_output }}/xrf55-layout-profile-repeat.json

xrf55-npy-shape-profile-check:
    {{ python }} eval/test-profile-xrf55-npy-shapes.py

# Read one bounded NPY header per distinct processed modality/size class.
xrf55-npy-shape-profile:
    {{ python }} eval/profile-xrf55-npy-shapes.py --report {{ eval_output }}/xrf55-npy-shape-profile.json
    {{ python }} eval/profile-xrf55-npy-shapes.py --report {{ eval_output }}/xrf55-npy-shape-profile-repeat.json
    cmp {{ eval_output }}/xrf55-npy-shape-profile.json {{ eval_output }}/xrf55-npy-shape-profile-repeat.json

xrf55-feature-cache-check:
    uv run --script eval/test-compile-xrf55-feature-cache.py

# Stream only the fixed 160-event campaign into private 0600 feature matrices.
# The second run proves byte-level determinism without retaining source labels.
xrf55-feature-cache:
    uv run --script eval/compile-xrf55-feature-cache.py
    uv run --script eval/compile-xrf55-feature-cache.py --adapter {{ eval_output }}/xrf55-feature-cache-adapter-repeat.json --wifi-matrix {{ eval_output }}/xrf55-feature-cache-wifi-repeat.npy --rfid-matrix {{ eval_output }}/xrf55-feature-cache-rfid-repeat.npy --mmwave-matrix {{ eval_output }}/xrf55-feature-cache-mmwave-repeat.npy
    cmp {{ eval_output }}/xrf55-feature-cache-adapter.json {{ eval_output }}/xrf55-feature-cache-adapter-repeat.json
    cmp {{ eval_output }}/xrf55-feature-cache-wifi.npy {{ eval_output }}/xrf55-feature-cache-wifi-repeat.npy
    cmp {{ eval_output }}/xrf55-feature-cache-rfid.npy {{ eval_output }}/xrf55-feature-cache-rfid-repeat.npy
    cmp {{ eval_output }}/xrf55-feature-cache-mmwave.npy {{ eval_output }}/xrf55-feature-cache-mmwave-repeat.npy

# Compile only preregistered train, calibration, and validation groups into
# separate mmap-ready caches. Locked test requires an explicit later request.
xrf55-trimodal-role-cache:
    uv run --script eval/compile-xrf55-feature-cache.py --role-cache-dir {{ eval_output }}/xrf55-trimodal-fusion-v0
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-train-adapter.json
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-train-wifi.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-train-rfid.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-train-mmwave.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-calibration-adapter.json
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-calibration-wifi.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-calibration-rfid.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-calibration-mmwave.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-validation-adapter.json
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-validation-wifi.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-validation-rfid.npy
    test -f {{ eval_output }}/xrf55-trimodal-fusion-v0/xrf55-trimodal-fusion-validation-mmwave.npy

xrf55-trimodal-fusion-check:
    uv run --script eval/test-evaluate-xrf55-trimodal-fusion.py

# Check the fresh-group role policy and joint channel/sequence or
# channel/spatial representation before admitting a real-data evaluator.
xrf55-joint-representation-adequacy-check:
    uv run --script eval/test-xrf55-joint-features.py

# Fit only on train, fix thresholds on calibration, and evaluate validation.
# There is deliberately no locked-test recipe: that role stays unopened unless
# this command records a passing preregistered gate.
xrf55-trimodal-fusion-validate: xrf55-trimodal-role-cache
    uv run --script eval/evaluate-xrf55-trimodal-fusion.py validate --report {{ eval_output }}/xrf55-trimodal-fusion-v0/validation-receipt.json

xrf55-cross-modal-retrieval-check:
    uv run --script eval/test-evaluate-xrf55-cross-modal-retrieval.py

# Fit only on repetitions 1-14 and retrieve exact held-out events among the
# six same-performer/action candidates from repetitions 15-20.
xrf55-cross-modal-retrieval: xrf55-feature-cache
    uv run --script eval/evaluate-xrf55-cross-modal-retrieval.py
    uv run --script eval/evaluate-xrf55-cross-modal-retrieval.py --report {{ eval_output }}/xrf55-cross-modal-retrieval-report-repeat.json
    cmp {{ eval_output }}/xrf55-cross-modal-retrieval-report.json {{ eval_output }}/xrf55-cross-modal-retrieval-report-repeat.json

xrf55-calibrated-event-relation-check: calibrated-event-relation-check
    uv run --script eval/test-evaluate-xrf55-calibrated-event-relation.py

# Fit on repetitions 1-8, calibrate on 9-11, gate on 12-14, and score
# repetitions 15-20 only when the preregistered validation gate passes.
xrf55-calibrated-event-relation: xrf55-feature-cache
    uv run --script eval/evaluate-xrf55-calibrated-event-relation.py
    uv run --script eval/evaluate-xrf55-calibrated-event-relation.py --report {{ eval_output }}/xrf55-calibrated-event-relation-report-repeat.json
    cmp {{ eval_output }}/xrf55-calibrated-event-relation-report.json {{ eval_output }}/xrf55-calibrated-event-relation-report-repeat.json

xrf55-hypothesis-frames-check:
    {{ python }} eval/test-compile-xrf55-hypothesis-frames.py

# Compile a bounded opaque frame sample from the complete processed event grid.
xrf55-hypothesis-frames:
    {{ python }} eval/compile-xrf55-hypothesis-frames.py --manifest {{ eval_output }}/xrf55-hypothesis-frames.json
    {{ python }} eval/compile-xrf55-hypothesis-frames.py --manifest {{ eval_output }}/xrf55-hypothesis-frames-repeat.json
    cmp {{ eval_output }}/xrf55-hypothesis-frames.json {{ eval_output }}/xrf55-hypothesis-frames-repeat.json

# Inventory or explicitly fetch one Oregon State LoRa RFFI setup. The fetcher
# rejects redirects and traversal, and defaults to a 10 GiB aggregate cap.
osu-lora-fetcher-check:
    {{ python }} data/tests/test-fetch-osu-lora.py

osu-lora-discover setup workers="4":
    {{ python }} data/fetch/fetch-osu-lora.py discover {{ setup }} --workers {{ workers }}

# Recompute path-free per-setup and corpus byte bounds from the publisher
# inventory without retaining file paths, URLs, or transport validators.
osu-lora-discover-summary setup="all" workers="4":
    {{ python }} data/fetch/fetch-osu-lora.py summarize {{ setup }} --workers {{ workers }}

osu-lora-fetch setup max_total_bytes="10737418240" max_file_bytes="4294967296" workers="2":
    {{ python }} data/fetch/fetch-osu-lora.py fetch {{ setup }} --max-total-bytes {{ max_total_bytes }} --max-file-bytes {{ max_file_bytes }} --workers {{ workers }}

# Verify or complete all seven publisher setups under explicit corpus-wide and
# per-file ceilings. Reproduce the path-free inventory used to size the bounds
# with `just osu-lora-discover-summary all`; discovery drift fails closed.
osu-lora-fetch-all:
    {{ python }} data/fetch/fetch-osu-lora.py fetch all --max-total-bytes 1099511627776 --max-file-bytes 268435456 --workers 4

# Reproduce the full acquisition-to-oracle metadata pipeline. The profiler and
# oracle compiler never open IQ/FFT payload streams.
osu-lora-corpus: osu-lora-fetch-all
    just osu-lora-profile
    just osu-lora-oracles

# Validate the bounded metadata-only profiler without requiring corpus bytes.
osu-lora-profile-check:
    {{ python }} eval/test-profile-osu-lora-sigmf.py

# Profile the ignored local tree without opening IQ payload streams.
osu-lora-profile:
    {{ python }} eval/profile-osu-lora-sigmf.py

osu-lora-oracles-check:
    {{ python }} eval/test-compile-osu-lora-oracles.py

osu-lora-oracles:
    {{ python }} eval/compile-osu-lora-oracles.py

# Prove the four-role assignment contract hermetically. The real OSU oracle
# currently fails closed because publisher metadata does not expose sessions.
osu-lora-relation-split-check:
    {{ python }} eval/test-build-osu-lora-relation-split.py

osu-lora-relation-split:
    {{ python }} eval/build-osu-lora-relation-split.py

ruff-uwb-oracles-check:
    {{ python }} eval/test-compile-ruff-uwb-oracles.py

ruff-uwb-oracles:
    {{ python }} eval/compile-ruff-uwb-oracles.py

# Prove the fixed device-disjoint assignment hermetically. The real metadata
# must expose event and session groups before this can publish a split.
ruff-uwb-open-set-source-split-check:
    {{ python }} eval/test-build-ruff-uwb-open-set-source-split.py

ruff-uwb-open-set-source-split:
    {{ python }} eval/build-ruff-uwb-open-set-source-split.py

ruff-uwb-row-adapter-check:
    uv run --script eval/test-compile-ruff-uwb-row-adapter.py

# Verify the pinned one-meter archive and central fetch receipt, then stream its
# waveform member to a private standalone NPY suitable for read-only mmap.
ruff-uwb-row-adapter:
    {{ python }} eval/compile-ruff-uwb-row-adapter.py --waveforms-output data/derived/eval/ruff-uwb-one-meter-waveforms.npy --adapter-output data/derived/eval/ruff-uwb-one-meter-row-adapter.json

# Apply the same fail-closed adapter contract to the pinned two-meter collection.
# This is intentionally separate because extraction reads and writes several GiB.
ruff-uwb-two-meter-row-adapter:
    {{ python }} eval/compile-ruff-uwb-row-adapter.py --collection distance-2 --waveforms-output data/derived/eval/ruff-uwb-two-meter-waveforms.npy --adapter-output data/derived/eval/ruff-uwb-two-meter-row-adapter.json

# Record the current leakage-safe RUFF-UWB baseline boundary. The aggregate
# oracle cannot yet bind waveform rows, so this succeeds only for that exact
# path-free blocker and never opens the waveform payload.
ruff-uwb-heldout-location-check:
    uv run --script eval/test-evaluate-ruff-uwb-heldout-location.py

ruff-uwb-heldout-location:
    {{ python }} eval/evaluate-ruff-uwb-heldout-location.py --expect-blocked --report {{ eval_output }}/ruff-uwb-heldout-location-blocker.json

ruff-uwb-heldout-location-real: ruff-uwb-row-adapter
    uv run --script eval/evaluate-ruff-uwb-heldout-location.py --row-adapter {{ eval_output }}/ruff-uwb-one-meter-row-adapter.json --waveforms {{ eval_output }}/ruff-uwb-one-meter-waveforms.npy --report {{ eval_output }}/ruff-uwb-heldout-location-report.json

# Prove cross-campaign role isolation, collection-scoped row identity, common
# representation projection, exact metrics, and read-only mmap hermetically.
ruff-uwb-cross-campaign-check:
    uv run --script eval/test-evaluate-ruff-uwb-cross-distance.py
    {{ python }} eval/test-verify-ruff-uwb-cross-campaign-experiment.py

# Compare the tracked aggregate result summary with the ignored canonical
# report. This never reads either waveform array.
ruff-uwb-cross-campaign-result-verify:
    {{ python }} eval/verify-ruff-uwb-cross-campaign-experiment.py

# Compare exact source-row selection through the reference expanded path and
# the production compact-span path. Requires the ignored one-meter adapter.
ruff-uwb-row-sampling-benchmark:
    uv run --script eval/benchmark-ruff-uwb-row-sampling.py --mode expanded
    uv run --script eval/benchmark-ruff-uwb-row-sampling.py --mode compact

# Fit/select only on the one-meter train/validation roles, quarantine its prior
# test role, then evaluate once on the complete two-meter campaign.
ruff-uwb-cross-campaign-transfer: ruff-uwb-row-adapter ruff-uwb-two-meter-row-adapter
    uv run --script eval/evaluate-ruff-uwb-cross-distance.py --report {{ eval_output }}/ruff-uwb-cross-distance-report.json

gnss-rff-layout-profile-check:
    {{ python }} eval/test-profile-gnss-rff-layout.py

gnss-rff-layout-profile:
    {{ python }} eval/profile-gnss-rff-layout.py

mmwave-jamming-oracles-check:
    {{ python }} eval/test-compile-mmwave-jamming-oracles.py

mmwave-jamming-oracles:
    {{ python }} eval/compile-mmwave-jamming-oracles.py

mmwave-jamming-layout-profile-check:
    uv run --script eval/test-profile-mmwave-jamming-mat-layout.py

mmwave-jamming-layout-profile:
    uv run --script eval/profile-mmwave-jamming-mat-layout.py
    uv run --script eval/profile-mmwave-jamming-mat-layout.py --report {{ eval_output }}/mmwave-jamming-mat-layout-profile-repeat.json
    cmp {{ eval_output }}/mmwave-jamming-mat-layout-profile.json {{ eval_output }}/mmwave-jamming-mat-layout-profile-repeat.json

mmwave-jamming-paired-grid-check:
    uv run --script eval/test-compile-mmwave-jamming-paired-grid.py

# Re-admit each source on the descriptor SciPy reads, apply one shared index
# policy within each matched pair, and write a fixed private NPY content grid.
mmwave-jamming-paired-grid:
    uv run --script eval/compile-mmwave-jamming-paired-grid.py
    uv run --script eval/compile-mmwave-jamming-paired-grid.py --adapter {{ eval_output }}/mmwave-jamming-paired-grid-adapter-repeat.json --matrix {{ eval_output }}/mmwave-jamming-paired-grid-repeat.npy
    cmp {{ eval_output }}/mmwave-jamming-paired-grid-adapter.json {{ eval_output }}/mmwave-jamming-paired-grid-adapter-repeat.json
    cmp {{ eval_output }}/mmwave-jamming-paired-grid.npy {{ eval_output }}/mmwave-jamming-paired-grid-repeat.npy

mmwave-jamming-receiver-crossfit-check:
    uv run --script eval/test-evaluate-mmwave-jamming-receiver-crossfit.py
    {{ python }} eval/test-verify-mmwave-jamming-experiment.py

# Score every pair once under receiver-held-out cross-fitting. This consumes
# only the ignored pair-aligned cache and the separate path-free oracle.
mmwave-jamming-receiver-crossfit:
    uv run --script eval/evaluate-mmwave-jamming-receiver-crossfit.py
    uv run --script eval/evaluate-mmwave-jamming-receiver-crossfit.py --output {{ eval_output }}/mmwave-jamming-receiver-crossfit-report-repeat.json
    cmp {{ eval_output }}/mmwave-jamming-receiver-crossfit-report.json {{ eval_output }}/mmwave-jamming-receiver-crossfit-report-repeat.json
    {{ python }} eval/verify-mmwave-jamming-experiment.py

indoor-jamming-oracles-check:
    uv run --script eval/test-compile-indoor-jamming-oracles.py

indoor-jamming-oracles integrity="receipt-only":
    uv run --script eval/compile-indoor-jamming-oracles.py --integrity {{ integrity }}

indoor-jamming-controlled-cause-check:
    uv run --script eval/test-evaluate-indoor-jamming-controlled-cause.py
    {{ python }} eval/test-verify-indoor-jamming-experiment.py

# Rehash the complete source set, reconstruct private bindings in memory, and
# read only the preregistered 96 MiB of bounded HDF5 windows.
indoor-jamming-controlled-cause-eval:
    just indoor-jamming-oracles full-digest
    uv run --script eval/evaluate-indoor-jamming-controlled-cause.py
    {{ python }} eval/verify-indoor-jamming-experiment.py

fuzz-smoke:
    cd rust && RUSTUP_TOOLCHAIN=nightly cargo fuzz run parse_saved_capture_jsonl -- -runs=1000

mutation-check:
    cargo mutants --manifest-path rust/Cargo.toml --package netbraid --file src/replay/fingerprint.rs --re 'project_saved_pcap_fingerprint_v0|compare_saved_pcap_fingerprints_v0' --test-package netbraid --jobs 2 --timeout 180 --no-shuffle -v

rust-check-full: rust-check scenario-check pcap-smoke

pcap-smoke-show:
    NETBRAID_SMOKE_SHOW_OUTPUT=1 cargo test --locked --manifest-path rust/Cargo.toml --test pcap_cli -- --ignored --nocapture
