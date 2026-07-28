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
    let parsed_stream = netbraid::replay::parse_saved_capture_jsonl(&jsonl.stdout).unwrap();
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
    let parsed_records =
        netbraid::replay::parse_saved_capture_jsonl(&first_records.stdout).unwrap();
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
        netbraid::replay::parse_saved_capture_jsonl(&first.stdout).unwrap()
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

    let six_triage = netbraid::replay::project_saved_pcap_triage_v1(
        &six,
        netbraid::replay::SavedPcapTriageOptionsV1::default(),
    )
    .unwrap();
    let seven_triage = netbraid::replay::project_saved_pcap_triage_v1(
        &seven,
        netbraid::replay::SavedPcapTriageOptionsV1::default(),
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
