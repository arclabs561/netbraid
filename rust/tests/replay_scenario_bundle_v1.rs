use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use netbraid::evidence::{
    CaptureFileMetadataV0, CaptureManifestV0, CaptureRunReceiptV0, Ipv4FieldsV0, PacketEnvelopeV0,
    PacketQuarantineV0, ToolRunReceiptV0, CAPTURE_RUN_RECEIPT_SCHEMA_V0,
    NORMALIZED_RECORDS_DIGEST_PROFILE_V0, PACKET_QUARANTINE_SCHEMA_V0,
};
use netbraid::replay::{
    load_scenario_bundle_v0, load_scenario_bundle_v1, parse_saved_capture_jsonl,
    project_saved_pcap_triage_v1, replay_scenario_v1, SavedPcapClaimScopeV0,
    SavedPcapTriageOptionsV1, SavedPcapWlanDisconnectKindV0, SavedPcapWlanTriageV0,
    ScenarioAcquisitionV1, ScenarioCheckpointInputsV0, ScenarioConclusionDispositionV0,
    ScenarioDerivationV1, ScenarioIdentifierClassV1, ScenarioLimitsV0, ScenarioPayloadHandlingV1,
    ScenarioSavedCaptureInputV0, ScenarioSensitivityV1, ScenarioSourceOriginV1,
    SCENARIO_BUNDLE_SCHEMA_V1, SCENARIO_REPLAY_SCHEMA_V1,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

const SCENARIO: &str = "saved-capture-prefix-boundary";
const BUILTIN_V1: &str = "synthetic-wlan-prefix-boundary";
const RAW_CAPTURE_SHA256: &str =
    "sha256:d66a40532f2a67d3dac9bb8c438b6dca59f5228f531087f781ec03858b63162e";

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/replay/scenarios")
        .join(name)
}

fn copy_fixture(name: &str) -> tempfile::TempDir {
    let temporary = tempfile::tempdir().unwrap();
    for entry in fs::read_dir(fixture(name)).unwrap() {
        let entry = entry.unwrap();
        fs::copy(entry.path(), temporary.path().join(entry.file_name())).unwrap();
    }
    temporary
}

fn mutate_manifest(directory: &Path, mutate: impl FnOnce(&mut Value)) {
    let path = directory.join("scenario.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    mutate(&mut manifest);
    fs::write(path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

fn replace_artifact(directory: &Path, artifact_id: &str, bytes: &[u8]) {
    let manifest_path = directory.join("scenario.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let artifact = manifest["artifacts"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|artifact| artifact["id"] == artifact_id)
        .unwrap();
    let path = artifact["path"].as_str().unwrap();
    fs::write(directory.join(path), bytes).unwrap();
    artifact["bytes"] = serde_json::json!(bytes.len());
    artifact["sha256"] = serde_json::json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

fn saved_stream<'a>(
    inputs: &'a ScenarioCheckpointInputsV0,
    artifact: &str,
) -> &'a ScenarioSavedCaptureInputV0 {
    inputs
        .saved_capture_streams
        .iter()
        .find(|stream| stream.artifact == artifact)
        .unwrap_or_else(|| panic!("missing saved-capture artifact {artifact:?}"))
}

#[test]
fn reviewed_capture_fixture_preserves_exact_lineage_and_disclosure_review() {
    let bundle = load_scenario_bundle_v1(fixture(SCENARIO), ScenarioLimitsV0::default()).unwrap();
    let manifest = bundle.manifest();

    assert_eq!(manifest.schema, SCENARIO_BUNDLE_SCHEMA_V1);
    assert_eq!(manifest.scenario_id, SCENARIO);
    assert_eq!(manifest.license, "(MIT OR Unlicense) AND BSD-3-Clause");
    assert_eq!(manifest.sensitivity, ScenarioSensitivityV1::PublicReviewed);
    assert_eq!(
        manifest
            .disclosure_review
            .retained_evidence_identifier_classes,
        [
            ScenarioIdentifierClassV1::LinkLayerAddress,
            ScenarioIdentifierClassV1::NetworkName,
            ScenarioIdentifierClassV1::PacketTimestamp,
        ]
    );
    assert_eq!(
        manifest.disclosure_review.evidence_payload_handling,
        ScenarioPayloadHandlingV1::OmittedFromIngestibleEvidenceArtifacts
    );

    let source = manifest.provenance.sources.as_slice();
    assert_eq!(source.len(), 1);
    let source = &source[0];
    assert_eq!(source.id, "libpcap.network-join-nokia-mobile");
    assert_eq!(source.source_origin, ScenarioSourceOriginV1::Observed);
    assert_eq!(
        source.derivation,
        ScenarioDerivationV1::NormalizedSavedCapture
    );
    assert_eq!(
        source.acquisition,
        ScenarioAcquisitionV1::ThirdPartyUpstream
    );
    assert_eq!(source.corpus_schema, "netmon.capture_fixture_corpus.v0");
    assert_eq!(
        source.corpus_fixture_id,
        "libpcap.network-join-nokia-mobile"
    );
    assert_eq!(source.repository.as_deref(), Some("the-tcpdump-group/libpcap"));
    assert_eq!(source.revision.as_deref(), Some("9f37478bad2abafb626a0bf8921506569960d48d"));
    assert_eq!(
        source.source_path.as_deref(),
        Some("tests/filter/Network_Join_Nokia_Mobile.pcap")
    );
    assert_eq!(
        source.source_url.as_deref(),
        Some("https://raw.githubusercontent.com/the-tcpdump-group/libpcap/9f37478bad2abafb626a0bf8921506569960d48d/tests/filter/Network_Join_Nokia_Mobile.pcap")
    );
    assert_eq!(
        source.upstream_blob_sha1.as_deref(),
        Some("28997e70e3e584119286e54a4a7d0ebb3bd38e6b")
    );
    assert_eq!(source.content_sha256, RAW_CAPTURE_SHA256);
    assert_eq!(source.size_bytes, 734);
    assert_eq!(source.spdx_license_expression, "BSD-3-Clause");
    assert_eq!(source.license_artifact.as_deref(), Some("libpcap-license"));
}

#[test]
fn replay_exposes_atomic_prefixes_and_independently_derives_the_boundary() {
    let bundle = load_scenario_bundle_v1(fixture(SCENARIO), ScenarioLimitsV0::default()).unwrap();

    let six_receipt = replay_scenario_v1(&bundle, "prefix-six").unwrap();
    assert_eq!(six_receipt.schema, SCENARIO_REPLAY_SCHEMA_V1);
    assert_eq!(six_receipt.bundle_schema, SCENARIO_BUNDLE_SCHEMA_V1);
    assert_eq!(
        six_receipt.declared_sensitivity,
        ScenarioSensitivityV1::PublicReviewed
    );
    assert_eq!(
        six_receipt.declared_disclosure_review,
        bundle.manifest().disclosure_review
    );
    let six_inputs = bundle.checkpoint_inputs_v1(&six_receipt).unwrap();
    assert!(six_inputs.host_path_records.is_empty());
    assert_eq!(six_inputs.saved_capture_streams.len(), 1);
    let six = saved_stream(&six_inputs, "prefix-six");
    assert_eq!(six.stream.packets.len(), 6);
    assert!(six.stream.receipt.is_none());

    let seven_receipt = replay_scenario_v1(&bundle, "prefix-seven").unwrap();
    let seven_inputs = bundle.checkpoint_inputs_v1(&seven_receipt).unwrap();
    assert!(seven_inputs.host_path_records.is_empty());
    assert_eq!(seven_inputs.saved_capture_streams.len(), 2);
    let seven = saved_stream(&seven_inputs, "prefix-seven");
    assert_eq!(seven.stream.packets.len(), 7);
    assert!(seven.stream.receipt.is_none());

    assert_eq!(six.stream.manifest.capture_id, RAW_CAPTURE_SHA256);
    assert_eq!(
        six.stream.manifest.capture_id,
        seven.stream.manifest.capture_id
    );
    assert_eq!(
        six.stream.packets.as_slice(),
        &seven.stream.packets[..six.stream.packets.len()]
    );
    let frame_seven = &seven.stream.packets[6];
    assert_eq!(frame_seven.frame.number, 7);
    let wlan = frame_seven.ieee80211.as_ref().unwrap();
    assert_eq!(wlan.frame_type, 0);
    assert_eq!(wlan.frame_subtype, 12);

    let six_triage =
        project_saved_pcap_triage_v1(&six.stream, SavedPcapTriageOptionsV1::default()).unwrap();
    match six_triage.wlan {
        SavedPcapWlanTriageV0::NotObserved { scope, .. } => {
            assert_eq!(scope, SavedPcapClaimScopeV0::NormalizedPacketSubset);
        }
        other => panic!("expected a prefix-scoped not-observed WLAN result, got {other:?}"),
    }

    let seven_triage =
        project_saved_pcap_triage_v1(&seven.stream, SavedPcapTriageOptionsV1::default()).unwrap();
    match seven_triage.wlan {
        SavedPcapWlanTriageV0::Observed {
            scope, disconnects, ..
        } => {
            assert_eq!(scope, SavedPcapClaimScopeV0::NormalizedPacketSubset);
            assert_eq!(disconnects.len(), 1);
            assert_eq!(
                disconnects[0].kind,
                SavedPcapWlanDisconnectKindV0::Deauthentication
            );
        }
        other => panic!("expected one prefix-scoped WLAN observation, got {other:?}"),
    }

    let prefix_six_abstentions = six_receipt
        .expected_conclusions
        .iter()
        .filter(|conclusion| conclusion.disposition == ScenarioConclusionDispositionV0::Abstained)
        .map(|conclusion| conclusion.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        prefix_six_abstentions,
        BTreeSet::from(["source-wide-disconnect-absence"])
    );

    let prefix_seven_abstentions = seven_receipt
        .expected_conclusions
        .iter()
        .filter(|conclusion| conclusion.disposition == ScenarioConclusionDispositionV0::Abstained)
        .map(|conclusion| conclusion.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        prefix_seven_abstentions,
        BTreeSet::from([
            "access-point-identity",
            "actor-identity",
            "attack-classification",
            "disconnect-causality",
            "radio-channel",
            "source-wide-frame-count",
        ])
    );
}

#[test]
fn versioned_loaders_reject_the_other_manifest_contract() {
    assert!(
        load_scenario_bundle_v0(fixture(SCENARIO), ScenarioLimitsV0::default()).is_err(),
        "the version 0 loader must not admit reviewed capture-derived manifests"
    );
    assert!(
        load_scenario_bundle_v1(fixture("wifi-hotspot-wifi"), ScenarioLimitsV0::default()).is_err(),
        "the version 1 loader must not reinterpret a PUBLIC_SYNTHETIC manifest"
    );
}

#[test]
fn unknown_v1_disclosure_and_lineage_tokens_fail_closed() {
    for (field, value) in [
        ("sensitivity", "PUBLIC_UNREVIEWED"),
        ("source_origin", "inferred"),
        ("derivation", "raw_capture"),
        ("acquisition", "local_live"),
    ] {
        let temporary = copy_fixture(SCENARIO);
        mutate_manifest(temporary.path(), |manifest| match field {
            "sensitivity" => manifest["sensitivity"] = serde_json::json!(value),
            _ => manifest["provenance"]["sources"][0][field] = serde_json::json!(value),
        });

        let error =
            load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
        assert!(
            error.to_string().contains("unknown variant"),
            "{field} unexpectedly failed as {error}"
        );
    }
}

#[test]
fn v1_rejects_unprovenanced_host_path_artifacts() {
    let temporary = copy_fixture(SCENARIO);
    mutate_manifest(temporary.path(), |manifest| {
        manifest["artifacts"][0]["role"] = serde_json::json!("host_path_jsonl");
    });

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(
        error.to_string().contains("unknown variant"),
        "host-path evidence unexpectedly entered the capture-derived contract: {error}"
    );
}

#[test]
fn v1_rejects_viewport_bytes_outside_the_disclosure_closure() {
    let temporary = copy_fixture(SCENARIO);
    mutate_manifest(temporary.path(), |manifest| {
        manifest["artifacts"][0]["role"] = serde_json::json!("viewport_text");
    });

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(
        error.to_string().contains("unknown variant"),
        "viewport bytes unexpectedly entered the capture-derived contract: {error}"
    );
}

#[test]
fn disclosure_classes_must_match_identifier_bearing_fields() {
    let temporary = copy_fixture(SCENARIO);
    let path = temporary.path().join("prefix-6.jsonl");
    let bytes = fs::read_to_string(&path).unwrap();
    let mut lines = bytes.lines().map(str::to_owned).collect::<Vec<_>>();
    let mut packet: PacketEnvelopeV0 = serde_json::from_str(&lines[1]).unwrap();
    packet.ipv4 = Some(Ipv4FieldsV0 {
        total_length_octets: None,
        source: "192.0.2.1".into(),
        destination: "198.51.100.2".into(),
        protocol: 17,
    });
    lines[1] = serde_json::to_string(&packet).unwrap();
    let bytes = format!("{}\n", lines.join("\n")).into_bytes();
    replace_artifact(temporary.path(), "prefix-six", &bytes);

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("undeclared=[NetworkLayerAddress]"));

    mutate_manifest(temporary.path(), |manifest| {
        manifest["disclosure_review"]["retained_evidence_identifier_classes"] =
            serde_json::json!([
                "link_layer_address",
                "network_name",
                "network_layer_address",
                "packet_timestamp"
            ]);
    });
    load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap();
}

#[test]
fn opaque_quarantine_rows_are_not_distributable_v1_evidence() {
    let temporary = copy_fixture(SCENARIO);
    let path = temporary.path().join("prefix-6.jsonl");
    let bytes = fs::read_to_string(&path).unwrap();
    let mut lines = bytes.lines();
    let mut manifest: CaptureManifestV0 = serde_json::from_str(lines.next().unwrap()).unwrap();
    manifest.normalization.packet_limit = 7;
    manifest.normalization.packet_rows_quarantined = 1;
    let mut rewritten = vec![serde_json::to_string(&manifest).unwrap()];
    rewritten.extend(lines.map(str::to_owned));
    rewritten.push(
        serde_json::to_string(&PacketQuarantineV0 {
            schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
            capture_id: RAW_CAPTURE_SHA256.into(),
            source_line: 8,
            frame_number_hint: Some(7),
            reason: "test opaque row".into(),
            raw_row: "opaque\tidentifier-bearing\trow".into(),
        })
        .unwrap(),
    );
    let bytes = format!("{}\n", rewritten.join("\n")).into_bytes();
    replace_artifact(temporary.path(), "prefix-six", &bytes);
    mutate_manifest(temporary.path(), |manifest| {
        manifest["timeline"][0]["ingest"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("prefix-six#quarantine:8"));
    });

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("must omit opaque quarantine rows"),
        "unexpected rejection path: {error}"
    );
}

#[test]
fn license_artifacts_are_required_non_ingestible_and_digest_bound() {
    let missing = copy_fixture(SCENARIO);
    fs::remove_file(missing.path().join("LICENSE-libpcap-BSD-3-Clause.txt")).unwrap();
    let error = load_scenario_bundle_v1(missing.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("inventory mismatch"));
    assert!(error
        .to_string()
        .contains("LICENSE-libpcap-BSD-3-Clause.txt"));

    let unknown_reference = copy_fixture(SCENARIO);
    mutate_manifest(unknown_reference.path(), |manifest| {
        manifest["provenance"]["sources"][0]["license_artifact"] =
            serde_json::json!("missing-license");
    });
    let error =
        load_scenario_bundle_v1(unknown_reference.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("must reference a license_text artifact"));

    let ingestible = copy_fixture(SCENARIO);
    mutate_manifest(ingestible.path(), |manifest| {
        manifest["timeline"][0]["ingest"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("libpcap-license#license"));
    });
    let error =
        load_scenario_bundle_v1(ingestible.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("license_text artifact \"libpcap-license\" cannot be ingested"));

    let altered = copy_fixture(SCENARIO);
    let license_path = altered.path().join("LICENSE-libpcap-BSD-3-Clause.txt");
    let mut altered_license = fs::read(&license_path).unwrap();
    altered_license[0] = if altered_license[0] == b'X' {
        b'Y'
    } else {
        b'X'
    };
    fs::write(license_path, altered_license).unwrap();
    let error = load_scenario_bundle_v1(altered.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("digest mismatch"));
}

#[test]
fn saved_capture_identity_must_match_exactly_one_declared_source() {
    let temporary = copy_fixture(SCENARIO);
    mutate_manifest(temporary.path(), |manifest| {
        manifest["provenance"]["sources"][0]["content_sha256"] = serde_json::json!(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        );
    });

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error
        .to_string()
        .contains("raw capture identity must match exactly one provenance source; matched 0"));
}

#[test]
fn capture_derived_artifacts_reject_occurrence_receipts() {
    let temporary = copy_fixture(SCENARIO);
    let capture_path = temporary.path().join("prefix-6.jsonl");
    let original = fs::read(&capture_path).unwrap();
    let stream = parse_saved_capture_jsonl(&original).unwrap();
    let first_time = stream.packets.first().unwrap().frame.event_time_unix_ns;
    let last_time = stream.packets.last().unwrap().frame.event_time_unix_ns;
    let zero_digest = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let tool_receipt = |tool: &str| ToolRunReceiptV0 {
        tool: tool.into(),
        configured_executable: tool.into(),
        tool_version: format!("{tool} test receipt"),
        argument_template: vec!["-r".into(), "$STAGED_CAPTURE".into()],
        environment_policy: "netmon.wireshark.environment.v0".into(),
        exit_code: 0,
        stdout_sha256: zero_digest.into(),
        stderr_sha256: zero_digest.into(),
    };
    let occurrence = CaptureRunReceiptV0 {
        schema: CAPTURE_RUN_RECEIPT_SCHEMA_V0.into(),
        run_id: "run:0000000000000000000000000000000000000000000000000000000000000000".into(),
        capture_id: stream.manifest.capture_id.clone(),
        started_time_unix_ns: first_time,
        finished_time_unix_ns: last_time,
        elapsed_ns: u64::try_from(last_time - first_time).unwrap(),
        file: CaptureFileMetadataV0 {
            file_type: "pcap".into(),
            encapsulation: "ieee-802-11".into(),
            timestamp_precision: "microseconds".into(),
            packet_count: 10,
            file_size_bytes: stream.manifest.artifact.size_bytes,
            original_data_size_bytes: stream.manifest.artifact.size_bytes,
            snaplen: None,
            inferred_snaplen_min: None,
            inferred_snaplen_max: None,
            duration_ns: Some(u64::try_from(last_time - first_time).unwrap()),
            earliest_packet_time_unix_ns: Some(first_time),
            latest_packet_time_unix_ns: Some(last_time),
            capture_hardware: None,
            capture_operating_system: None,
            capture_application: None,
        },
        capinfos: tool_receipt("capinfos"),
        tshark: tool_receipt("tshark"),
        configuration_sha256: stream.manifest.extractor.configuration_sha256.clone(),
        field_registry: stream.manifest.extractor.field_registry.clone(),
        normalized_records_digest_profile: NORMALIZED_RECORDS_DIGEST_PROFILE_V0.into(),
        normalized_records_sha256: stream.normalized_records_sha256.clone(),
    };

    let first_line_end = original.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    let mut with_receipt = original[..first_line_end].to_vec();
    with_receipt.extend(serde_json::to_vec(&occurrence).unwrap());
    with_receipt.push(b'\n');
    with_receipt.extend(&original[first_line_end..]);
    replace_artifact(temporary.path(), "prefix-six", &with_receipt);
    mutate_manifest(temporary.path(), |manifest| {
        manifest["timeline"][0]["ingest"]
            .as_array_mut()
            .unwrap()
            .insert(1, serde_json::json!("prefix-six#receipt"));
    });

    let error = load_scenario_bundle_v1(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("capture-derived scenario artifacts must omit occurrence receipts"),
        "unexpected receipt rejection: {error}"
    );
}

#[test]
fn synthetic_v0_manifest_closures_remain_pinned() {
    for (name, expected) in [
        (
            "wifi-hotspot-wifi",
            "0039c3aec486771112102010b07d873b276b71547d089886b13f3235bb2d0ba2",
        ),
        (
            "same-ssid-attachment-boundary",
            "9032d500e96abebc6173d04aa9e87fd23ecc6f3dbac684fad07a53bce08d2b32",
        ),
        (
            "vpn-overlay-transition",
            "486224e2b821e8e67f0ecf4376dc2cd58aeffa229a9b21452a39612540ffee66",
        ),
        (
            "cache-source-gap",
            "effe4c1029a7e0bf6a1b6a47f5510fb2a54b8389b616ac1adec593ed833a9ebc",
        ),
    ] {
        let actual = format!(
            "{:x}",
            Sha256::digest(fs::read(fixture(name).join("scenario.json")).unwrap())
        );
        assert_eq!(actual, expected, "version 0 closure changed for {name}");
    }
}

#[cfg(feature = "scenario-fixtures")]
#[test]
fn synthetic_v0_builtin_inventory_remains_exactly_four() {
    assert_eq!(
        netbraid::replay::builtin_scenario_ids_v0(),
        [
            "wifi-hotspot-wifi",
            "same-ssid-attachment-boundary",
            "vpn-overlay-transition",
            "cache-source-gap",
        ]
    );
}

#[cfg(feature = "scenario-fixtures-capture-derived")]
#[test]
fn reviewed_capture_builtin_inventory_is_exactly_one() {
    assert_eq!(
        netbraid::replay::builtin_scenario_ids_v1(),
        ["synthetic-wlan-prefix-boundary"]
    );
    let bundle = netbraid::replay::builtin_scenario_v1(BUILTIN_V1).unwrap();
    let receipt = replay_scenario_v1(&bundle, "prefix-seven").unwrap();
    assert_eq!(receipt.projection.saved_captures.len(), 2);
    assert_eq!(
        receipt.declared_sensitivity,
        ScenarioSensitivityV1::PublicReviewed
    );
    assert!(bundle
        .manifest()
        .provenance
        .sources
        .iter()
        .all(|s| s.license_artifact.is_none()));
}
