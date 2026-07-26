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
            "../crates/netmon-adapter-tshark/tests/fixtures/ethernet_ipv4_tcp.hex"
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
    assert!(stdout.contains("capture file\n  format        pcap / ether / microseconds"));
    assert!(stdout.contains("normalization\n  state         complete"));
    assert!(stdout.contains("policy unknown (detached artifact)"));
    assert!(stdout.contains("successful run\n  id            run:"));
    assert!(stdout.contains("L3 directions (first occurrence)"));
    assert!(stdout.contains("TCP dst/443"));

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
    assert_eq!(records.len(), 3);
    assert_eq!(records[0]["schema"], "netmon.capture_manifest.v0");
    assert_eq!(records[1]["schema"], "netmon.capture_run_receipt.v0");
    assert_eq!(records[2]["schema"], "netmon.packet_envelope.v0");
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
}

fn decode_hex(input: &str) -> Vec<u8> {
    let input: String = input
        .lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().chars())
        .filter(|character| !character.is_whitespace())
        .collect();
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
