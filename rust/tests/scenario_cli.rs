use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("crates/netbraid-replay/tests/fixtures/scenarios")
        .join(name)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn scenario_validate_dispatches_without_changing_the_v0_json_contract() {
    let v0 = fixture("wifi-hotspot-wifi");
    let output = run(&["scenario", "validate", v0.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "netbraid.scenario_validation.v0");
    assert_eq!(value["scenario_id"], "wifi-hotspot-wifi");
    assert!(
        value.get("bundle_schema").is_none(),
        "version 0 output remains byte-shape compatible"
    );

    let v1 = fixture("saved-capture-prefix-boundary");
    let output = run(&["scenario", "validate", v1.to_str().unwrap(), "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "netbraid.scenario_validation.v1");
    assert_eq!(value["bundle_schema"], "netbraid.scenario_bundle.v1");
    assert_eq!(value["scenario_id"], "saved-capture-prefix-boundary");
    assert_eq!(value["declared_sensitivity"], "PUBLIC_REVIEWED");
    assert_eq!(value["provenance_sources"], 1);
    assert_eq!(
        value["declared_evidence_identifier_classes"],
        serde_json::json!(["link_layer_address", "network_name", "packet_timestamp"])
    );
}

#[test]
fn scenario_replay_preserves_declared_admission_metadata() {
    let v1 = fixture("saved-capture-prefix-boundary");
    let output = run(&[
        "scenario",
        "replay",
        v1.to_str().unwrap(),
        "--checkpoint",
        "prefix-seven",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema"], "netbraid.scenario_replay.v1");
    assert_eq!(value["bundle_schema"], "netbraid.scenario_bundle.v1");
    assert_eq!(value["declared_sensitivity"], "PUBLIC_REVIEWED");
    assert_eq!(
        value["declared_disclosure_review"]["retained_evidence_identifier_classes"],
        serde_json::json!(["link_layer_address", "network_name", "packet_timestamp"])
    );
    assert_eq!(value["scenario_id"], "saved-capture-prefix-boundary");
    assert_eq!(value["checkpoint"], "prefix-seven");
    assert_eq!(
        value["projection"]["saved_captures"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        value["expected_conclusions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|conclusion| conclusion["disposition"] == "abstained")
            .count(),
        6
    );
}

#[test]
fn scenario_v1_text_does_not_authenticate_the_declared_review() {
    let v1 = fixture("saved-capture-prefix-boundary");
    let output = run(&["scenario", "validate", v1.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("structurally valid v1 scenario"));
    assert!(stdout.contains("declared PUBLIC_REVIEWED"));
    assert!(stdout.contains("review authority: not authenticated"));
    assert!(!stdout.contains("valid reviewed scenario"));
}

#[test]
fn scenario_dispatch_keeps_the_strict_manifest_size_bound() {
    let temporary = tempfile::tempdir().unwrap();
    std::fs::write(
        temporary.path().join("scenario.json"),
        vec![b' '; 256 * 1024 + 1],
    )
    .unwrap();

    let output = run(&["scenario", "validate", temporary.path().to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("maximum is 262144"));
}

#[cfg(unix)]
#[test]
fn scenario_dispatch_does_not_follow_a_manifest_symlink_to_probe_its_schema() {
    let temporary = tempfile::tempdir().unwrap();
    let scenario = temporary.path().join("scenario");
    std::fs::create_dir(&scenario).unwrap();
    let outside = temporary.path().join("outside.json");
    std::fs::write(&outside, br#"{"schema":"outside.contract.v0"}"#).unwrap();
    std::os::unix::fs::symlink(&outside, scenario.join("scenario.json")).unwrap();

    let output = run(&["scenario", "validate", scenario.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("scenario.json"));
    assert!(
        !stderr.contains("unsupported scenario schema"),
        "the CLI read through the symlink before strict loading: {stderr}"
    );
}

#[test]
fn capture_scenario_lineage_matches_the_admitted_adapter_corpus() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"));
    let corpus: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            workspace
                .join("crates/netbraid-adapter-tshark")
                .join("tests/fixtures/upstream/corpus-v0.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let scenario: serde_json::Value = serde_json::from_slice(
        &std::fs::read(fixture("saved-capture-prefix-boundary").join("scenario.json")).unwrap(),
    )
    .unwrap();

    let source = &scenario["provenance"]["sources"][0];
    let admitted = corpus["fixtures"]
        .as_array()
        .unwrap()
        .iter()
        .find(|fixture| fixture["id"] == source["corpus_fixture_id"])
        .unwrap();

    assert_eq!(source["corpus_schema"], corpus["schema"]);
    assert_eq!(source["id"], admitted["id"]);
    assert_eq!(source["repository"], admitted["origin"]["repository"]);
    assert_eq!(source["revision"], admitted["origin"]["revision"]);
    assert_eq!(source["source_path"], admitted["origin"]["source_path"]);
    assert_eq!(source["source_url"], admitted["origin"]["source_url"]);
    assert_eq!(
        source["upstream_blob_sha1"],
        admitted["origin"]["upstream_blob_sha1"]
    );
    assert_eq!(
        source["content_sha256"],
        format!("sha256:{}", admitted["content_sha256"].as_str().unwrap())
    );
    assert_eq!(source["size_bytes"], admitted["size_bytes"]);
    assert_eq!(
        source["spdx_license_expression"],
        admitted["origin"]["license"]
    );

    let adapter_license = std::fs::read(
        workspace
            .join("crates/netbraid-adapter-tshark/tests/fixtures")
            .join(admitted["origin"]["license_file"].as_str().unwrap()),
    )
    .unwrap();
    let scenario_license = std::fs::read(
        fixture("saved-capture-prefix-boundary").join("LICENSE-libpcap-BSD-3-Clause.txt"),
    )
    .unwrap();
    assert_eq!(scenario_license, adapter_license);
}
