use std::fs;
use std::process::Command;

#[test]
#[ignore = "requires an installed tshark; run through `just pcap-smoke`"]
fn pcap_command_has_human_and_jsonl_operator_surfaces() {
    let directory = tempfile::tempdir().unwrap();
    let input = directory.path().join("synthetic.pcap");
    fs::write(
        &input,
        decode_hex(include_str!(
            "../crates/netmon-adapter-tshark/tests/fixtures/ethernet_mixed_conversations.hex"
        )),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_netmon");
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
    if std::env::var_os("NETMON_SMOKE_SHOW_OUTPUT").is_some() {
        eprintln!("{stdout}");
    }
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

    let jsonl = Command::new(binary)
        .args([
            "pcap",
            input.to_str().unwrap(),
            "--packet-limit",
            "10",
            "--jsonl",
        ])
        .output()
        .unwrap();
    assert!(
        jsonl.status.success(),
        "{}",
        String::from_utf8_lossy(&jsonl.stderr)
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
    assert!(records[0].get("acquisition_policy").is_none());
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
}

#[test]
fn pcap_jsonl_modes_are_mutually_exclusive() {
    let output = Command::new(env!("CARGO_BIN_EXE_netmon"))
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
