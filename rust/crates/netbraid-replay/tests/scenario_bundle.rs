use std::fs;
use std::path::{Path, PathBuf};

use netbraid_evidence::{
    CaptureManifestV0, CaptureRunReceiptV0, PacketEnvelopeV0, PacketQuarantineV0,
};
use netbraid_replay::{
    load_scenario_bundle_v0, parse_saved_capture_jsonl, replay_scenario_v0,
    ScenarioConclusionDispositionV0, ScenarioCoverageFreshnessV0, ScenarioLimitsV0,
    ScenarioPrivacyV0, SCENARIO_REPLAY_SCHEMA_V0,
};
use sha2::{Digest, Sha256};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/scenarios")
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

fn replace_artifact(directory: &Path, artifact_id: &str, bytes: &[u8]) {
    let manifest_path = directory.join("scenario.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let artifacts = manifest["artifacts"].as_array_mut().unwrap();
    let artifact = artifacts
        .iter_mut()
        .find(|artifact| artifact["id"] == artifact_id)
        .unwrap();
    let path = artifact["path"].as_str().unwrap();
    fs::write(directory.join(path), bytes).unwrap();
    artifact["bytes"] = serde_json::json!(bytes.len());
    artifact["sha256"] = serde_json::json!(format!("sha256:{:x}", Sha256::digest(bytes)));
    fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
}

#[test]
fn all_directory_bundles_validate_and_close_over_exact_manifest_bytes() {
    for name in [
        "wifi-hotspot-wifi",
        "same-ssid-attachment-boundary",
        "vpn-overlay-transition",
        "cache-source-gap",
    ] {
        let bundle = load_scenario_bundle_v0(fixture(name), ScenarioLimitsV0::default()).unwrap();
        let manifest_bytes = fs::read(fixture(name).join("scenario.json")).unwrap();
        assert_eq!(bundle.manifest().schema, "netbraid.scenario_bundle.v0");
        assert_eq!(bundle.manifest().scenario_id, name);
        assert_eq!(
            bundle.manifest().privacy,
            ScenarioPrivacyV0::PublicSynthetic
        );
        assert_eq!(
            bundle.manifest_sha256(),
            format!("sha256:{:x}", Sha256::digest(manifest_bytes))
        );
        assert!(bundle
            .manifest()
            .expected
            .conclusions
            .iter()
            .any(|conclusion| {
                conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
            }));
    }
}

#[test]
fn wifi_hotspot_wifi_replay_reports_change_recurrence_and_abstentions() {
    let bundle =
        load_scenario_bundle_v0(fixture("wifi-hotspot-wifi"), ScenarioLimitsV0::default()).unwrap();
    let replay = replay_scenario_v0(&bundle, "wifi-returned").unwrap();
    let inputs = bundle.checkpoint_inputs_v0(&replay).unwrap();
    let host = replay.projection.host_path.unwrap();

    assert_eq!(replay.schema, SCENARIO_REPLAY_SCHEMA_V0);
    assert_eq!(host.records, 3);
    assert_eq!(host.exact_context_keys, 2);
    assert_eq!(host.confirmed_context_transitions, 2);
    assert_eq!(host.latest_record_id, "wifi-primary-2");
    assert_eq!(inputs.host_path_records.len(), 3);
    assert!(inputs.saved_capture_streams.is_empty());
    assert!(bundle
        .manifest()
        .expected
        .conclusions
        .iter()
        .any(|conclusion| conclusion.id == "physical-location"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained));
    assert!(bundle
        .manifest()
        .expected
        .conclusions
        .iter()
        .any(|conclusion| conclusion.id == "network-owner"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained));
}

#[test]
fn same_ssid_attachment_preserves_boundary_evidence_before_label_reuse_diverges() {
    let bundle = load_scenario_bundle_v0(
        fixture("same-ssid-attachment-boundary"),
        ScenarioLimitsV0::default(),
    )
    .unwrap();
    let new_attachment = replay_scenario_v0(&bundle, "mesh-new-attachment").unwrap();
    let new_attachment_inputs = bundle.checkpoint_inputs_v0(&new_attachment).unwrap();
    assert!(new_attachment_inputs.saved_capture_streams.is_empty());
    let records = &new_attachment_inputs.host_path_records;

    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|record| {
        record.policy.is_passive()
            && record.coverage.observed_sources == ["host_route", "wifi_association"]
            && record.coverage.missing_sources.is_empty()
    }));
    assert_eq!(records[0].path.network_name, records[1].path.network_name);
    assert_ne!(
        records[0].path.associated_bssid,
        records[1].path.associated_bssid
    );
    assert_eq!(
        records[0].path.next_hop_link_address,
        records[1].path.next_hop_link_address
    );
    let attachment_change = netbraid_replay::compare_contexts(Some(&records[0]), &records[1]);
    assert_eq!(
        attachment_change.relation,
        netbraid_replay::ContextRelationV0::SameContext
    );
    assert_eq!(
        attachment_change.changed_dimensions,
        ["association", "associated_bssid"]
    );
    let recurrence = netbraid_replay::summarize_context_recurrence(records, &records[1]);
    assert_eq!(
        recurrence.exact_context_match,
        netbraid_replay::ExactContextMatchV0::AnchoredExactRecurrence
    );
    assert_eq!(
        recurrence.attachment_corroboration,
        netbraid_replay::AttachmentCorroborationV0::NotSeenBefore
    );
    // These are the authored abstention oracles. Downstream consumer tests must
    // independently derive that this host-path-only evidence cannot establish
    // place, managed AP identity, or an actual 802.11 roam.
    assert!(new_attachment
        .expected_conclusions
        .iter()
        .any(|conclusion| {
            conclusion.id == "bssid-transition"
                && conclusion.disposition == ScenarioConclusionDispositionV0::Supported
        }));
    assert!(new_attachment
        .expected_conclusions
        .iter()
        .any(|conclusion| {
            conclusion.id == "physical-location"
                && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
        }));
    assert!(new_attachment
        .expected_conclusions
        .iter()
        .any(|conclusion| {
            conclusion.id == "access-point-identity"
                && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
        }));
    assert!(new_attachment
        .expected_conclusions
        .iter()
        .any(|conclusion| {
            conclusion.id == "actual-80211-roam"
                && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
        }));

    let diverged = replay_scenario_v0(&bundle, "same-label-new-boundary").unwrap();
    let diverged_inputs = bundle.checkpoint_inputs_v0(&diverged).unwrap();
    assert!(diverged_inputs.saved_capture_streams.is_empty());
    let records = &diverged_inputs.host_path_records;

    assert_eq!(records.len(), 3);
    assert_eq!(records[1].path.network_name, records[2].path.network_name);
    assert_ne!(
        records[1].path.next_hop_link_address,
        records[2].path.next_hop_link_address
    );
    assert_ne!(records[1].path.resolvers, records[2].path.resolvers);
    assert_ne!(
        records[1].path.address_prefixes,
        records[2].path.address_prefixes
    );
    let boundary_change = netbraid_replay::compare_contexts(Some(&records[1]), &records[2]);
    assert_eq!(
        boundary_change.relation,
        netbraid_replay::ContextRelationV0::ContextChanged
    );
    assert!(boundary_change
        .changed_dimensions
        .contains(&"next_hop_link_address"));
    assert!(boundary_change.changed_dimensions.contains(&"resolvers"));
    assert!(boundary_change
        .changed_dimensions
        .contains(&"address_prefixes"));
    assert!(diverged.expected_conclusions.iter().any(|conclusion| {
        conclusion.id == "same-label-new-context"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Supported
    }));
    assert!(diverged.expected_conclusions.iter().any(|conclusion| {
        conclusion.id == "network-owner"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
    }));
}

#[test]
fn overlay_replay_does_not_invent_provider_rf_or_intent() {
    let bundle = load_scenario_bundle_v0(
        fixture("vpn-overlay-transition"),
        ScenarioLimitsV0::default(),
    )
    .unwrap();
    let entered = replay_scenario_v0(&bundle, "overlay-entered").unwrap();
    let abstained = entered
        .expected_conclusions
        .iter()
        .filter(|conclusion| conclusion.disposition == ScenarioConclusionDispositionV0::Abstained)
        .map(|conclusion| conclusion.id.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        abstained,
        vec!["overlay-provider", "overlay-intent", "rf-condition"]
    );
    assert_eq!(
        entered
            .projection
            .host_path
            .as_ref()
            .unwrap()
            .confirmed_context_transitions,
        1
    );
}

#[test]
fn cache_gap_keeps_stale_distinct_from_presence_and_departure() {
    let bundle =
        load_scenario_bundle_v0(fixture("cache-source-gap"), ScenarioLimitsV0::default()).unwrap();
    let replay = replay_scenario_v0(&bundle, "cache-stale").unwrap();

    assert_eq!(replay.projection.host_path.as_ref().unwrap().records, 1);
    assert_eq!(replay.source_coverage.len(), 3);
    assert!(replay
        .source_coverage
        .iter()
        .any(|coverage| coverage.id == "cache-stale-gap"
            && coverage.freshness == ScenarioCoverageFreshnessV0::Stale));
    assert!(replay.expected_conclusions.iter().any(|conclusion| {
        conclusion.id == "departed"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Abstained
    }));
    assert!(replay
        .expected_conclusions
        .iter()
        .any(|conclusion| conclusion.id == "stale-not-current"
            && conclusion.disposition == ScenarioConclusionDispositionV0::Supported));
}

#[test]
fn tampered_artifact_digest_and_extra_inventory_fail_closed() {
    let tampered = copy_fixture("wifi-hotspot-wifi");
    let path = tampered.path().join("host-path.jsonl");
    let mut bytes = fs::read(&path).unwrap();
    bytes[0] = b' ';
    fs::write(&path, bytes).unwrap();
    let error = load_scenario_bundle_v0(tampered.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("digest mismatch"));

    let extra = copy_fixture("wifi-hotspot-wifi");
    fs::write(extra.path().join("undeclared.txt"), b"undeclared\n").unwrap();
    let error = load_scenario_bundle_v0(extra.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("inventory mismatch"));
    assert!(error.to_string().contains("undeclared.txt"));
}

#[test]
fn manifest_unknown_fields_fail_closed() {
    let temporary = copy_fixture("cache-source-gap");
    let path = temporary.path().join("scenario.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let error = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn current_observed_coverage_requires_cited_evidence() {
    let temporary = copy_fixture("cache-source-gap");
    let path = temporary.path().join("scenario.json");
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["expected"]["source_coverage"][0]["evidence"] = serde_json::json!([]);
    fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();

    let error = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("current observed coverage"));
}

#[test]
fn host_path_unknown_fields_fail_closed_through_the_typed_projection() {
    let temporary = copy_fixture("cache-source-gap");
    let path = temporary.path().join("host-path.jsonl");
    let mut record: serde_json::Value =
        serde_json::from_slice(fs::read(&path).unwrap().strip_suffix(b"\n").unwrap()).unwrap();
    record["guessed_identity"] = serde_json::json!("not-evidence");
    let mut bytes = serde_json::to_vec(&record).unwrap();
    bytes.push(b'\n');
    replace_artifact(temporary.path(), "path", &bytes);

    let error = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("unknown, noncanonical"));
}

#[test]
fn viewport_ansi_and_line_overflow_fail_closed_after_digest_validation() {
    let ansi = copy_fixture("cache-source-gap");
    replace_artifact(
        ansi.path(),
        "stale-view",
        b"\x1b[31mCACHE\x1b[0m\nFRESH\nABSTAIN\nABSTAIN\nGUARD\nSOURCE\n",
    );
    let error = load_scenario_bundle_v0(ansi.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("ANSI"));

    let overflow = copy_fixture("cache-source-gap");
    replace_artifact(
        overflow.path(),
        "stale-view",
        b"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nFRESH\nABSTAIN\nABSTAIN\nGUARD\nSOURCE\n",
    );
    let error = load_scenario_bundle_v0(overflow.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("exceeding width 47"));

    let tab = copy_fixture("cache-source-gap");
    replace_artifact(
        tab.path(),
        "stale-view",
        b"CACHE\tSTALE\nFRESH\nABSTAIN\nABSTAIN\nGUARD\nSOURCE\n",
    );
    let error = load_scenario_bundle_v0(tab.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("printable ASCII cells"));
}

#[cfg(unix)]
#[test]
fn symlinked_artifacts_fail_closed() {
    use std::os::unix::fs::symlink;

    let temporary = copy_fixture("cache-source-gap");
    let path = temporary.path().join("viewport.txt");
    fs::remove_file(&path).unwrap();
    symlink(fixture("cache-source-gap").join("viewport.txt"), &path).unwrap();

    let error = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("symlink"));
}

#[test]
fn saved_capture_records_are_ingested_atomically_and_projected() {
    let temporary = tempfile::tempdir().unwrap();
    let manifest_record: CaptureManifestV0 = serde_json::from_str(include_str!(
        "fixtures/evidence-v0/capture_manifest_v0.json"
    ))
    .unwrap();
    let receipt_record: CaptureRunReceiptV0 = serde_json::from_str(include_str!(
        "fixtures/evidence-v0/capture_run_receipt_v0.json"
    ))
    .unwrap();
    let packet_record: PacketEnvelopeV0 =
        serde_json::from_str(include_str!("fixtures/evidence-v0/packet_envelope_v0.json")).unwrap();
    let quarantine_record: PacketQuarantineV0 = serde_json::from_str(include_str!(
        "fixtures/evidence-v0/packet_quarantine_v0.json"
    ))
    .unwrap();
    let mut capture = Vec::new();
    for record in [
        serde_json::to_vec(&manifest_record).unwrap(),
        serde_json::to_vec(&receipt_record).unwrap(),
        serde_json::to_vec(&packet_record).unwrap(),
        serde_json::to_vec(&quarantine_record).unwrap(),
    ] {
        capture.extend(record);
        capture.push(b'\n');
    }
    fs::write(temporary.path().join("capture.jsonl"), &capture).unwrap();

    let artifact_sha256 = format!("sha256:{:x}", Sha256::digest(&capture));
    let mut manifest = serde_json::json!({
        "schema": "netbraid.scenario_bundle.v0",
        "scenario_id": "saved-capture-atomic",
        "license": "PUBLIC_SYNTHETIC",
        "privacy": "PUBLIC_SYNTHETIC",
        "provenance": {
            "generator": "netbraid-test",
            "generator_version": "0",
            "description": "Exercises saved-capture scenario ingestion."
        },
        "artifacts": [{
            "id": "capture",
            "path": "capture.jsonl",
            "role": "saved_capture_jsonl",
            "media_type": "application/x-ndjson",
            "bytes": capture.len(),
            "sha256": artifact_sha256
        }],
        "timeline": [{
            "name": "capture-loaded",
            "at_ms": 0,
            "ingest": [
                "capture#manifest",
                "capture#receipt",
                "capture#frame:1",
                "capture#quarantine:2"
            ]
        }],
        "expected": {
            "source_coverage": [{
                "id": "capture-coverage",
                "checkpoint": "capture-loaded",
                "source": "saved_capture",
                "state": "partial",
                "freshness": "current",
                "evidence": ["capture#manifest", "capture#frame:1"],
                "limitation": "The normalization receipt reports one quarantined row."
            }],
            "conclusions": [{
                "id": "capture-readable",
                "checkpoint": "capture-loaded",
                "question": "Was the complete normalized record stream accepted?",
                "disposition": "supported",
                "conclusion": "The declared saved-capture stream is structurally valid.",
                "evidence": ["capture#manifest", "capture#receipt"],
                "coverage": ["capture-coverage"],
                "limitations": ["This validates normalized records, not live acquisition coverage."]
            }],
            "viewports": []
        }
    });
    let manifest_path = temporary.path().join("scenario.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap(),
    )
    .unwrap();

    let bundle = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap();
    let receipt = replay_scenario_v0(&bundle, "capture-loaded").unwrap();
    let inputs = bundle.checkpoint_inputs_v0(&receipt).unwrap();
    assert_eq!(receipt.projection.saved_captures.len(), 1);
    assert_eq!(receipt.projection.saved_captures[0].packet_records, 1);
    assert_eq!(receipt.projection.saved_captures[0].quarantine_records, 1);
    assert!(inputs.host_path_records.is_empty());
    assert_eq!(inputs.saved_capture_streams.len(), 1);
    assert_eq!(inputs.saved_capture_streams[0].artifact, "capture");
    assert_eq!(
        inputs.saved_capture_streams[0].stream,
        parse_saved_capture_jsonl(&capture).unwrap()
    );
    assert_eq!(inputs.saved_capture_streams[0].stream.packets.len(), 1);
    assert_eq!(inputs.saved_capture_streams[0].stream.quarantines.len(), 1);

    let all_records = manifest["timeline"][0]["ingest"].take();
    manifest["timeline"] = serde_json::json!([
        {
            "name": "capture-partial",
            "at_ms": 0,
            "ingest": ["capture#manifest"]
        },
        {
            "name": "capture-loaded",
            "at_ms": 1,
            "ingest": all_records.as_array().unwrap()[1..]
        }
    ]);
    fs::write(manifest_path, serde_json::to_vec_pretty(&manifest).unwrap()).unwrap();
    let error = load_scenario_bundle_v0(temporary.path(), ScenarioLimitsV0::default()).unwrap_err();
    assert!(error.to_string().contains("ingested atomically"));
}

#[cfg(feature = "scenario-fixtures")]
#[test]
fn builtins_use_the_same_validation_and_replay_api() {
    assert_eq!(
        netbraid_replay::builtin_scenario_ids_v0(),
        [
            "wifi-hotspot-wifi",
            "same-ssid-attachment-boundary",
            "vpn-overlay-transition",
            "cache-source-gap"
        ]
    );
    for id in netbraid_replay::builtin_scenario_ids_v0() {
        let bundle = netbraid_replay::builtin_scenario_v0(id).unwrap();
        let checkpoint = bundle.manifest().timeline.last().unwrap().name.clone();
        let replay = replay_scenario_v0(&bundle, &checkpoint).unwrap();
        assert_eq!(replay.scenario_id, *id);
        let inputs = bundle.checkpoint_inputs_v0(&replay).unwrap();
        assert_eq!(
            inputs.host_path_records.len(),
            replay
                .projection
                .host_path
                .as_ref()
                .map_or(0, |host| usize::try_from(host.records).unwrap())
        );
    }
}

#[cfg(feature = "scenario-fixtures")]
#[test]
fn checkpoint_inputs_reject_a_receipt_from_another_bundle() {
    let first = netbraid_replay::builtin_scenario_v0("wifi-hotspot-wifi").unwrap();
    let second = netbraid_replay::builtin_scenario_v0("vpn-overlay-transition").unwrap();
    let receipt = replay_scenario_v0(&first, "wifi-returned").unwrap();

    let error = second.checkpoint_inputs_v0(&receipt).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("does not match this bundle and checkpoint")
            || error.to_string().contains("unknown scenario checkpoint")
    );
}
