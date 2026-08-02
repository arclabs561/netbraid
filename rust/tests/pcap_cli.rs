use std::fs;
use std::process::Command;

#[test]
#[ignore = "requires an installed tshark; run through `just pcap-smoke`"]
fn pcap_command_has_human_and_jsonl_operator_surfaces() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("synthetic.pcap");
    fs::write(
        &input,
        decode_hex(include_str!("fixtures/ethernet_mixed_conversations.hex")),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_netbraid");
    let text = Command::new(binary)
        .args(["pcap", input.to_str().unwrap(), "--packet-limit", "10"])
        .output()
        .unwrap();
    assert!(
        text.status.success(),
        "{}",
        String::from_utf8_lossy(&text.stderr)
    );
    let stdout = String::from_utf8(text.stdout).unwrap();
    if std::env::var_os("NETBRAID_SMOKE_SHOW_OUTPUT").is_some() {
        eprintln!("{stdout}");
    }
    assert!(stdout
        .starts_with("triage\n  normalization complete / 6 emitted / 0 quarantined / 6 inspected"));
    assert!(stdout.contains("completeness  complete capture normalization"));
    assert!(stdout.contains(
        "top capture   cumulative complete capture aggregate by original frame octets; \
         not recent, time-local, a flow, or a session"
    ));
    assert!(stdout.contains(
        "candidate pivot  tshark display filter: (frame.encap_type == 1) && \
         (tcp && ((ip.src == 192.0.2.1 && tcp.srcport == 40000"
    ));
    assert!(stdout
        .contains("candidate pivot may also select packets excluded by reducer eligibility rules"));
    assert!(stdout.contains("capture file\n  format        pcap / ether / microseconds"));
    assert!(stdout.contains("extent        6 packets / 324 original packet-data octets"));
    assert!(stdout.contains("normalization\n  state         complete"));
    assert!(stdout.contains("coverage      6 grouped / 6 emitted packet envelopes / 0 excluded"));
    assert!(stdout.contains("policy unknown (detached artifact)"));
    assert!(stdout.contains("successful run\n  id            run:"));
    assert!(stdout.contains(
        "capture conversations\n  scope         capture-wide; endpoint A/B is canonical, not initiator"
    ));
    assert!(stdout.contains("TCP 192.0.2.1:40000 ↔ 198.51.100.2:443"));
    assert!(stdout.contains("flags SYN=1 SYN+ACK=0 FIN=0 RST=0"));
    assert!(stdout.contains("flags SYN=0 SYN+ACK=1 FIN=1 RST=0"));
    assert!(stdout.contains("UDP 203.0.113.10:53000 ↔ 203.0.113.53:53"));
    assert!(stdout
        .contains("timing      +400.000 ms .. +500.000 ms from capture start / 100.000 ms span"));

    let partial = Command::new(binary)
        .args(["pcap", input.to_str().unwrap(), "--packet-limit", "2"])
        .output()
        .unwrap();
    assert!(
        partial.status.success(),
        "{}",
        String::from_utf8_lossy(&partial.stderr)
    );
    let partial_stdout = String::from_utf8(partial.stdout).unwrap();
    assert!(partial_stdout.contains("state         partial"));
    assert!(partial_stdout.contains(
        "scope         normalized packet subset; file-wide completeness not established; \
         endpoint A/B is canonical, not initiator"
    ));
    assert!(!partial_stdout
        .contains("scope         capture-wide; endpoint A/B is canonical, not initiator"));
    assert!(partial_stdout.contains(
        "completeness  partial normalized packet subset; file-wide conclusions unavailable"
    ));
    assert!(partial_stdout.contains(
        "top capture   cumulative normalized packet subset aggregate by original frame octets; \
         not recent, time-local, a flow, or a session"
    ));

    let jsonl = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--acquisition-mode",
            "passive-host-local",
            "--jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        jsonl.status.success(),
        "{}",
        String::from_utf8_lossy(&jsonl.stderr)
    );
    let parsed_stream = netbraid_replay::parse_saved_capture_jsonl(&jsonl.stdout).unwrap();
    assert!(parsed_stream.receipt.is_some());
    assert_eq!(parsed_stream.packets.len(), 6);
    assert!(parsed_stream.quarantines.is_empty());
    assert_eq!(
        parsed_stream.normalized_records_sha256,
        parsed_stream
            .receipt
            .as_ref()
            .unwrap()
            .normalized_records_sha256
    );
    let records: Vec<serde_json::Value> = String::from_utf8(jsonl.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(records.len(), 8);
    assert_eq!(records[0]["schema"], "netmon.capture_manifest.v0");
    assert_eq!(records[1]["schema"], "netmon.capture_run_receipt.v0");
    assert!(records[2..]
        .iter()
        .all(|record| record["schema"] == "netmon.packet_envelope.v0"));
    assert!(records[0]["extractor"]["configuration_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        records[0]["acquisition_policy"]["mode"],
        "passive_host_local"
    );
    assert!(records[0]["acquisition_policy"]
        .get("active_actions")
        .is_none());
    assert_eq!(records[1]["file"]["file_type"], "pcap");
    assert!(records[1]["normalized_records_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        records[1]["capinfos"]["argument_template"]
            .as_array()
            .unwrap()
            .last()
            .unwrap(),
        "$STAGED_CAPTURE"
    );

    let records_args = [
        "pcap",
        input.to_str().unwrap(),
        "--packet-limit",
        "10",
        "--records-jsonl",
    ];
    let first_records = Command::new(binary).args(records_args).output().unwrap();
    assert!(
        first_records.status.success(),
        "{}",
        String::from_utf8_lossy(&first_records.stderr)
    );
    let second_records = Command::new(binary).args(records_args).output().unwrap();
    assert!(
        second_records.status.success(),
        "{}",
        String::from_utf8_lossy(&second_records.stderr)
    );
    assert_eq!(
        first_records.stdout, second_records.stdout,
        "normalized-record JSONL must be byte-identical for the same artifact and configuration"
    );
    let parsed_records = netbraid_replay::parse_saved_capture_jsonl(&first_records.stdout).unwrap();
    assert!(parsed_records.receipt.is_none());
    assert_eq!(parsed_records.packets.len(), 6);
    assert!(parsed_records.quarantines.is_empty());

    let deterministic_records: Vec<serde_json::Value> = String::from_utf8(first_records.stdout)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(deterministic_records.len(), 7);
    assert_eq!(
        deterministic_records[0]["schema"],
        "netmon.capture_manifest.v0"
    );
    assert!(deterministic_records[1..]
        .iter()
        .all(|record| record["schema"] == "netmon.packet_envelope.v0"));
    assert!(deterministic_records
        .iter()
        .all(|record| record["schema"] != "netmon.capture_run_receipt.v0"));

    let triage = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        triage.status.success(),
        "{}",
        String::from_utf8_lossy(&triage.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&triage.stdout).lines().count(),
        1,
        "finite triage JSON must be one object, not a record stream"
    );
    let triage: serde_json::Value = serde_json::from_slice(&triage.stdout).unwrap();
    assert_eq!(triage["schema"], "netmon.saved_pcap_triage.v1");
    assert_eq!(
        triage["source"]["manifest"]["schema"],
        "netmon.capture_manifest.v0"
    );
    assert_eq!(
        triage["source"]["receipt"]["schema"],
        "netmon.capture_run_receipt.v0"
    );
    assert_eq!(triage["normalization"]["completeness"], "complete_capture");
    assert_eq!(triage["top_capture_conversation"]["status"], "observed");
    assert_eq!(
        triage["top_capture_conversation"]["conversation"]["transport"],
        "tcp"
    );
    assert!(
        triage.get("trailing_window").is_none(),
        "the v1 no-option projection must omit tail analysis"
    );
    let traffic_filter = triage["top_capture_conversation"]["conversation"]
        ["tshark_candidate_display_filter"]
        .as_str()
        .unwrap();
    assert!(traffic_filter.contains("tcp.srcport == 40000"));
    let pivot = Command::new("tshark")
        .args([
            "-n",
            "-r",
            input.to_str().unwrap(),
            "-Y",
            traffic_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ])
        .output()
        .unwrap();
    assert!(
        pivot.status.success(),
        "{}",
        String::from_utf8_lossy(&pivot.stderr)
    );
    assert_eq!(
        String::from_utf8(pivot.stdout).unwrap().lines().count(),
        4,
        "this fixture's candidate pivot should select its four matching frames"
    );

    let fingerprint = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--fingerprint-json",
        ])
        .output()
        .unwrap();
    assert!(
        fingerprint.status.success(),
        "{}",
        String::from_utf8_lossy(&fingerprint.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&fingerprint.stdout).lines().count(),
        1,
        "fingerprint JSON must be one object"
    );
    let fingerprint: serde_json::Value = serde_json::from_slice(&fingerprint.stdout).unwrap();
    assert_eq!(
        fingerprint["schema"],
        "netmon.saved_pcap_fingerprint_candidate.v0"
    );
    assert_eq!(fingerprint["scope"], "complete_capture");
    assert_eq!(fingerprint["status"]["status"], "observed");
    assert!(fingerprint["status"]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let fingerprint_text = fingerprint.to_string();
    assert!(!fingerprint_text.contains("192.0.2.1"));
    assert!(!fingerprint_text.contains("40000"));

    let trailing = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--tail-seconds",
            "0.15",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        trailing.status.success(),
        "{}",
        String::from_utf8_lossy(&trailing.stderr)
    );
    let trailing: serde_json::Value = serde_json::from_slice(&trailing.stdout).unwrap();
    assert_eq!(
        trailing["top_capture_conversation"]["conversation"]["transport"], "tcp",
        "opting into a trailing window must not replace the cumulative result"
    );
    assert_eq!(
        trailing["trailing_window"]["negative_claim_qualification"]["status"],
        "qualified"
    );
    assert_eq!(
        trailing["trailing_window"]["requested_interval"]["start_event_time_unix_ns"],
        1_700_000_000_473_456_000_i64
    );
    assert_eq!(
        trailing["trailing_window"]["requested_interval"]["end_event_time_unix_ns"],
        1_700_000_000_623_456_000_i64
    );
    assert_eq!(
        trailing["trailing_window"]["selected_packet_extent"]["observations"],
        2
    );
    assert_eq!(
        trailing["trailing_window"]["top_conversation"]["conversation"]["transport"],
        "udp"
    );
    let trailing_filter = trailing["trailing_window"]["top_conversation"]["conversation"]
        ["tshark_candidate_display_filter"]
        .as_str()
        .unwrap();
    assert!(trailing_filter.contains(
        "frame.time_epoch >= 1700000000.473456000 && \
         frame.time_epoch <= 1700000000.623456000"
    ));
    let trailing_pivot = Command::new("tshark")
        .args([
            "-n",
            "-r",
            input.to_str().unwrap(),
            "-Y",
            trailing_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ])
        .output()
        .unwrap();
    assert!(
        trailing_pivot.status.success(),
        "{}",
        String::from_utf8_lossy(&trailing_pivot.stderr)
    );
    assert_eq!(
        String::from_utf8(trailing_pivot.stdout)
            .unwrap()
            .lines()
            .count(),
        2,
        "the time-bounded trailing pivot should select only the late DNS exchange"
    );

    let trailing_text = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--tail-seconds",
            "0.15",
        ])
        .output()
        .unwrap();
    assert!(
        trailing_text.status.success(),
        "{}",
        String::from_utf8_lossy(&trailing_text.stderr)
    );
    let trailing_text = String::from_utf8(trailing_text.stdout).unwrap();
    assert!(trailing_text.contains("trailing interval  requested 150.000 ms"));
    assert!(trailing_text.contains(
        "negative claims  qualified by complete normalization plus occurrence file packet extent"
    ));
    assert!(
        trailing_text.contains("top trailing  cumulative within requested packet-time interval")
    );
    assert!(trailing_text.contains("UDP 203.0.113.10:53000 ↔ 203.0.113.53:53"));
}

#[test]
#[ignore = "requires installed tshark and capinfos; run through `just pcap-smoke`"]
fn pcap_flows_tsv_is_deterministic_and_feeds_the_synthetic_lineage_oracle() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("synthetic.pcap");
    fs::write(
        &input,
        decode_hex(include_str!("fixtures/ethernet_mixed_conversations.hex")),
    )
    .unwrap();

    let arguments = [
        "pcap",
        input.to_str().unwrap(),
        "--packet-limit",
        "10",
        "--flows-tsv",
        "--tcp-inactivity-seconds",
        "60.000000001",
        "--udp-inactivity-seconds",
        "30",
    ];
    let first = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let second = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args(arguments)
        .output()
        .unwrap();
    assert!(
        second.status.success(),
        "{}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(first.stdout, second.stdout);

    let expected = concat!(
        "start_time\tend_time\tsrc_ip\tsrc_port\tdst_ip\tdst_port\tprotocol\t",
        "orig_packets\torig_ip_bytes\tresp_packets\tresp_ip_bytes\n",
        "1700000000.123456000\t1700000000.423456000\t192.0.2.1\t40000\t",
        "198.51.100.2\t443\ttcp\t2\t80\t2\t80\n",
        "1700000000.523456000\t1700000000.623456000\t203.0.113.10\t53000\t",
        "203.0.113.53\t53\tudp\t1\t40\t1\t40\n",
    );
    assert_eq!(String::from_utf8(first.stdout.clone()).unwrap(), expected);
    assert!(!expected.contains(input.to_str().unwrap()));
    for forbidden in ["sha256:", "payload", "capture_id", "record_id"] {
        assert!(!expected.contains(forbidden));
    }

    let packet_flows = directory.path().join("packet-flows.tsv");
    fs::write(&packet_flows, &first.stdout).unwrap();
    let zeek_log = directory.path().join("synthetic-zeek.log");
    fs::write(&zeek_log, SYNTHETIC_ZEEK_FLOW_LOG).unwrap();
    let report = directory.path().join("lineage-report.json");
    let evaluator = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../scripts/evaluate-iot23-flow-lineage.py");
    let evaluation = Command::new("python3")
        .arg(evaluator)
        .args(["--zeek-log", zeek_log.to_str().unwrap()])
        .args(["--packet-flows", packet_flows.to_str().unwrap()])
        .args(["--report", report.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        evaluation.status.success(),
        "{}",
        String::from_utf8_lossy(&evaluation.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(report["inputs"]["publisher_flows"], 2);
    assert_eq!(report["inputs"]["packet_derived_flows"], 2);
    assert_eq!(report["raw_lineage"]["one_to_one_pairs"], 2);
    assert_eq!(
        report["raw_lineage"]["packet_derived_matched"],
        serde_json::json!({"numerator": 2, "denominator": 2})
    );
    assert_eq!(
        report["counter_deltas"]["total_ip_bytes"]["signed_packet_minus_publisher"],
        0
    );
}

#[test]
#[ignore = "requires installed tshark and capinfos; run through `just pcap-smoke`"]
fn pcap_command_surfaces_bounded_wireless_operator_evidence() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("ieee80211-radiotap.pcap");
    fs::write(
        &input,
        decode_hex(include_str!("fixtures/libpcap-ieee80211-exthdr.pcap.hex")),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args(["pcap", input.to_str().unwrap(), "--packet-limit", "100"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    if std::env::var_os("NETBRAID_SMOKE_SHOW_OUTPUT").is_some() {
        eprintln!("{stdout}");
    }

    assert!(stdout.contains("IEEE 802.11\n"));
    assert!(stdout.contains("coverage      10 WLAN frames / 7 with radio metadata"));
    assert!(
        stdout.contains("identifiers   BSSID 7 frames / 1 unique; TA 7 / 2; nonempty SSID 2 / 1")
    );
    assert!(stdout.contains("3  acknowledgment (ACK) [type 1 subtype 13]"));
    assert!(stdout.contains("7  channel 1 / 2412 MHz / signal -74..-14 dBm / median -18 dBm (n=7)"));
    assert!(stdout.contains("7  90:a4:de:c0:46:0a"));
    assert!(stdout.contains("text=\"omus\" / hex=6f6d7573"));
    assert!(stdout.contains(
        "WLAN disconnect frames  not observed in complete capture among 10 emitted WLAN frames"
    ));
    assert!(!stdout.contains(
        "scope         capture-wide; endpoint A/B is canonical, not initiator\n  coverage      0 grouped"
    ));

    let wlan_fingerprint = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "100",
            "--wlan-fingerprint-json",
        ])
        .output()
        .unwrap();
    assert!(
        wlan_fingerprint.status.success(),
        "{}",
        String::from_utf8_lossy(&wlan_fingerprint.stderr)
    );
    let wlan_fingerprint: serde_json::Value =
        serde_json::from_slice(&wlan_fingerprint.stdout).unwrap();
    assert_eq!(
        wlan_fingerprint["schema"],
        "netmon.saved_pcap_wlan_fingerprint_candidate.v0"
    );
    assert_eq!(wlan_fingerprint["status"]["status"], "observed");
    assert_eq!(wlan_fingerprint["status"]["basis"]["wlan_frames"], 10);
    assert_eq!(
        wlan_fingerprint["status"]["basis"]["radio_metadata_frames"],
        7
    );
    let wlan_fingerprint_text = wlan_fingerprint.to_string();
    assert!(!wlan_fingerprint_text.contains("90:a4:de:c0:46:0a"));
    assert!(!wlan_fingerprint_text.contains("6f6d7573"));
}

#[test]
#[ignore = "requires installed tshark and capinfos; run through `just pcap-smoke`"]
fn pcap_triage_surfaces_observed_wlan_disconnect_frames_without_attack_claims() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("network-join.pcap");
    fs::write(
        &input,
        decode_hex(include_str!(
            "fixtures/libpcap-network-join-nokia-mobile.pcap.hex"
        )),
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "100",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let triage: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(triage["wlan"]["status"], "observed");
    assert_eq!(triage["wlan"]["disconnects"][0]["kind"], "deauthentication");
    assert_eq!(
        triage["wlan"]["disconnects"][0]["event_window"]["observations"],
        1
    );
    assert_eq!(
        triage["wlan"]["disconnects"][0]["tshark_display_filter"],
        "wlan.fc.type == 0 && wlan.fc.subtype == 12"
    );
    assert_eq!(triage["top_capture_conversation"]["status"], "unsupported");
    let pivot = Command::new("tshark")
        .args([
            "-n",
            "-r",
            input.to_str().unwrap(),
            "-Y",
            triage["wlan"]["disconnects"][0]["tshark_display_filter"]
                .as_str()
                .unwrap(),
            "-T",
            "fields",
            "-e",
            "frame.number",
        ])
        .output()
        .unwrap();
    assert!(
        pivot.status.success(),
        "{}",
        String::from_utf8_lossy(&pivot.stderr)
    );
    assert_eq!(
        String::from_utf8(pivot.stdout).unwrap().lines().count(),
        1,
        "the WLAN pivot must select the observed deauthentication frame"
    );
}

#[test]
#[ignore = "requires installed tshark and capinfos; run through `just pcap-smoke`"]
fn records_jsonl_preserves_the_six_to_seven_frame_wlan_boundary() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("network-join.pcap");
    fs::write(
        &input,
        decode_hex(include_str!(
            "fixtures/libpcap-network-join-nokia-mobile.pcap.hex"
        )),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_netbraid");

    let normalize = |limit: &str| {
        let args = [
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            limit,
            "--records-jsonl",
        ];
        let first = Command::new(binary).args(args).output().unwrap();
        assert!(
            first.status.success(),
            "{}",
            String::from_utf8_lossy(&first.stderr)
        );
        let second = Command::new(binary).args(args).output().unwrap();
        assert!(
            second.status.success(),
            "{}",
            String::from_utf8_lossy(&second.stderr)
        );
        assert_eq!(
            first.stdout, second.stdout,
            "receipt-free normalization must be deterministic within one extractor configuration"
        );
        netbraid_replay::parse_saved_capture_jsonl(&first.stdout).unwrap()
    };

    let six = normalize("6");
    let seven = normalize("7");
    assert_eq!(six.manifest.capture_id, seven.manifest.capture_id);
    assert_eq!(six.packets.len(), 6);
    assert_eq!(seven.packets.len(), 7);
    assert_eq!(six.packets, seven.packets[..6]);
    assert_eq!(seven.packets[6].ieee80211.as_ref().unwrap().frame_type, 0);
    assert_eq!(
        seven.packets[6].ieee80211.as_ref().unwrap().frame_subtype,
        12
    );

    let six_triage = netbraid_replay::project_saved_pcap_triage_v1(
        &six,
        netbraid_replay::SavedPcapTriageOptionsV1::default(),
    )
    .unwrap();
    let seven_triage = netbraid_replay::project_saved_pcap_triage_v1(
        &seven,
        netbraid_replay::SavedPcapTriageOptionsV1::default(),
    )
    .unwrap();
    let six_triage = serde_json::to_value(six_triage).unwrap();
    let seven_triage = serde_json::to_value(seven_triage).unwrap();
    assert_eq!(
        six_triage["normalization"]["completeness"],
        "partial_packet_subset"
    );
    assert_eq!(six_triage["wlan"]["status"], "not_observed");
    assert_eq!(six_triage["wlan"]["scope"], "normalized_packet_subset");
    assert_eq!(seven_triage["wlan"]["status"], "observed");
    assert_eq!(seven_triage["wlan"]["scope"], "normalized_packet_subset");
    assert_eq!(
        seven_triage["wlan"]["disconnects"][0]["kind"],
        "deauthentication"
    );
    assert_eq!(
        seven_triage["wlan"]["disconnects"][0]["event_window"]["observations"],
        1
    );
}

#[test]
fn pcap_jsonl_modes_are_mutually_exclusive() {
    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            "does-not-need-to-exist.pcap",
            "--jsonl",
            "--records-jsonl",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--jsonl"));
    assert!(stderr.contains("--records-jsonl"));
    assert!(stderr.contains("cannot be used with"));
}

#[test]
fn pcap_flows_tsv_requires_explicit_thresholds_and_rejects_other_output_modes() {
    let missing_thresholds = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args(["pcap", "does-not-need-to-exist.pcap", "--flows-tsv"])
        .output()
        .unwrap();
    assert!(!missing_thresholds.status.success());
    let stderr = String::from_utf8(missing_thresholds.stderr).unwrap();
    assert!(stderr.contains("--tcp-inactivity-seconds"));
    assert!(stderr.contains("--udp-inactivity-seconds"));
    assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));

    for conflicting_mode in [
        "--json",
        "--fingerprint-json",
        "--wlan-fingerprint-json",
        "--jsonl",
        "--records-jsonl",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
            .args([
                "pcap",
                "does-not-need-to-exist.pcap",
                "--flows-tsv",
                "--tcp-inactivity-seconds",
                "60",
                "--udp-inactivity-seconds",
                "30",
                conflicting_mode,
            ])
            .output()
            .unwrap();
        assert!(!output.status.success(), "{conflicting_mode} must conflict");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--flows-tsv"));
        assert!(stderr.contains(conflicting_mode));
        assert!(stderr.contains("cannot be used with"));
        assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
    }

    let tail_conflict = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            "does-not-need-to-exist.pcap",
            "--flows-tsv",
            "--tcp-inactivity-seconds",
            "60",
            "--udp-inactivity-seconds",
            "30",
            "--tail-seconds",
            "1",
        ])
        .output()
        .unwrap();
    assert!(!tail_conflict.status.success());
    let stderr = String::from_utf8(tail_conflict.stderr).unwrap();
    assert!(stderr.contains("--flows-tsv"));
    assert!(stderr.contains("--tail-seconds"));
    assert!(stderr.contains("cannot be used with"));
    assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
}

#[test]
fn pcap_fingerprint_json_is_separate_from_other_json_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            "does-not-need-to-exist.pcap",
            "--fingerprint-json",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--fingerprint-json"));
    assert!(stderr.contains("--json"));
    assert!(stderr.contains("cannot be used with"));
    assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
}

#[test]
fn pcap_wlan_fingerprint_json_is_separate_from_other_json_modes() {
    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            "does-not-need-to-exist.pcap",
            "--wlan-fingerprint-json",
            "--fingerprint-json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--wlan-fingerprint-json"));
    assert!(stderr.contains("--fingerprint-json"));
    assert!(stderr.contains("cannot be used with"));
    assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
}

#[test]
fn pcap_tail_analysis_is_not_applied_to_raw_jsonl_modes() {
    for raw_mode in ["--jsonl", "--records-jsonl"] {
        let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
            .args([
                "pcap",
                "does-not-need-to-exist.pcap",
                raw_mode,
                "--tail-seconds",
                "1",
            ])
            .output()
            .unwrap();

        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("--tail-seconds"));
        assert!(stderr.contains(raw_mode));
        assert!(stderr.contains("cannot be used with"));
        assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
    }
}

#[test]
fn pcap_rejects_active_actions_under_a_passive_acquisition_policy() {
    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .args([
            "pcap",
            "does-not-need-to-exist.pcap",
            "--acquisition-mode",
            "passive-host-local",
            "--active-action",
            "arp_probe",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.contains("--active-action cannot be used with passive-host-local acquisition"));
    assert!(!stderr.contains("normalizing does-not-need-to-exist.pcap"));
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input: String = input
        .lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().chars())
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(input.len() % 2, 0);
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

const SYNTHETIC_ZEEK_FLOW_LOG: &str = concat!(
    "#separator \\x09\n",
    "#set_separator\t,\n",
    "#empty_field\t(empty)\n",
    "#unset_field\t-\n",
    "#path\tconn\n",
    "#open\t2020-01-01-00-00-00\n",
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\t",
    "duration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\t",
    "history\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents\tlabel\t",
    "detailed-label\n",
    "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\t",
    "string\tbool\tbool\tcount\tstring\tcount\tcount\tcount\tcount\tset[string]\tstring\t",
    "string\n",
    "1700000000.123456000\tsynthetic-tcp\t192.0.2.1\t40000\t198.51.100.2\t443\ttcp\t-\t",
    "0.300000000\t0\t0\tSF\t-\t-\t0\tShADf\t2\t80\t2\t80\t-\tBenign\tNormal\n",
    "1700000000.523456000\tsynthetic-udp\t203.0.113.10\t53000\t203.0.113.53\t53\tudp\t",
    "dns\t0.100000000\t12\t12\tSF\t-\t-\t0\tDd\t1\t40\t1\t40\t-\tBenign\tNormal\n",
    "#close\t2020-01-01-00-01-00\n",
);
