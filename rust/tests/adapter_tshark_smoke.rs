use std::fs;
use std::path::PathBuf;

use netbraid::adapters::tshark::{normalize_saved_capture, NormalizeOptions};
use netbraid::evidence::NormalizationStateV0;

#[test]
#[ignore = "requires an installed tshark; run through `just pcap-smoke`"]
fn installed_tshark_normalizes_synthetic_capture() {
    let directory = tempfile::tempdir().unwrap();
    let tcp = normalize_fixture(
        directory.path(),
        "ethernet-ipv4-tcp",
        include_str!("fixtures/adapter/ethernet_ipv4_tcp.hex"),
    );
    let tcp_again = normalize_fixture(
        directory.path(),
        "ethernet-ipv4-tcp-again",
        include_str!("fixtures/adapter/ethernet_ipv4_tcp.hex"),
    );
    assert_eq!(tcp.manifest.capture_id, tcp_again.manifest.capture_id);
    assert_eq!(
        tcp.manifest.extractor.configuration_sha256,
        tcp_again.manifest.extractor.configuration_sha256
    );
    assert_eq!(tcp.packets, tcp_again.packets);
    assert_eq!(tcp.receipt.file, tcp_again.receipt.file);
    assert_eq!(
        tcp.receipt.normalized_records_sha256,
        tcp_again.receipt.normalized_records_sha256
    );
    assert_ne!(tcp.receipt.run_id, tcp_again.receipt.run_id);
    assert_eq!(tcp.receipt.file.file_type, "pcap");
    assert_eq!(tcp.receipt.file.packet_count, 1);
    assert_eq!(
        tcp.receipt.file.file_size_bytes,
        tcp.manifest.artifact.size_bytes
    );
    assert!(tcp
        .receipt
        .tshark
        .argument_template
        .iter()
        .any(|argument| argument == "$STAGED_CAPTURE"));
    let packet = &tcp.packets[0];
    assert_eq!(packet.frame.event_time_unix_ns, 1_700_000_000_123_456_000);
    assert_eq!(packet.ipv4.as_ref().unwrap().source, "192.0.2.1");
    assert_eq!(packet.ipv4.as_ref().unwrap().destination, "198.51.100.2");
    assert_eq!(packet.ipv4.as_ref().unwrap().total_length_octets, Some(40));
    assert_eq!(packet.tcp.as_ref().unwrap().destination_port, 443);
    assert_eq!(packet.tcp.as_ref().unwrap().stream_index, Some(0));

    let udp = normalize_fixture(
        directory.path(),
        "ethernet-ipv6-udp",
        include_str!("fixtures/adapter/ethernet_ipv6_udp.hex"),
    );
    let packet = &udp.packets[0];
    assert_eq!(packet.ipv6.as_ref().unwrap().source, "2001:db8::1");
    assert_eq!(packet.ipv6.as_ref().unwrap().destination, "2001:db8::2");
    assert_eq!(packet.ipv6.as_ref().unwrap().total_length_octets, Some(48));
    assert_eq!(packet.udp.as_ref().unwrap().destination_port, 5353);

    let arp = normalize_fixture(
        directory.path(),
        "ethernet-arp",
        include_str!("fixtures/adapter/ethernet_arp.hex"),
    );
    let packet = &arp.packets[0];
    assert!(packet.ipv4.is_none());
    assert!(packet.ipv6.is_none());
    assert!(packet.tcp.is_none());
    assert!(packet.udp.is_none());
    assert!(packet
        .frame
        .protocols
        .iter()
        .any(|protocol| protocol == "arp"));

    let ieee802154 = normalize_fixture(
        directory.path(),
        "ieee802154-command",
        include_str!("fixtures/adapter/ieee802154_command.hex"),
    );
    let packet = serde_json::to_value(&ieee802154.packets[0]).unwrap();
    let fields = &packet["ieee802154"];
    assert_eq!(fields["frame_type"], 3);
    assert_eq!(fields["frame_version"], 1);
    assert_eq!(fields["sequence_number"], 42);
    assert_eq!(fields["destination_pan_id"], 0x1234);
    assert_eq!(fields["destination"]["kind"], "short");
    assert_eq!(fields["destination"]["value"], 0x5678);
    assert_eq!(fields["source"]["kind"], "extended");
    assert_eq!(fields["source"]["value"], "02:00:00:00:00:00:00:01");
    assert_eq!(fields["command"], 4);
    assert_eq!(fields["fcs_status"], "valid");
    assert!(fields.get("payload").is_none());

    let truncated = normalize_fixture(
        directory.path(),
        "ethernet-ipv4-tcp-truncated",
        include_str!("fixtures/adapter/ethernet_ipv4_tcp_truncated.hex"),
    );
    assert_eq!(truncated.receipt.file.snaplen, Some(54));
    assert_eq!(truncated.receipt.file.packet_count, 1);
    assert_eq!(truncated.receipt.file.original_data_size_bytes, 74);
    // "Complete" describes normalization of every file record. The capture
    // boundary's loss remains explicit rather than being promoted to a complete
    // packet claim.
    assert_eq!(
        truncated.manifest.normalization.state,
        NormalizationStateV0::Complete
    );
    assert!(!truncated.manifest.normalization.packet_limit_reached);
    assert_eq!(truncated.manifest.normalization.packet_rows_emitted, 1);
    assert_eq!(truncated.manifest.normalization.packet_rows_quarantined, 0);
    let packet = &truncated.packets[0];
    assert_eq!(packet.frame.original_len, 74);
    assert_eq!(packet.frame.captured_len, 54);
    assert_eq!(packet.ipv4.as_ref().unwrap().source, "192.0.2.5");
    assert_eq!(packet.ipv4.as_ref().unwrap().destination, "198.51.100.6");
    assert_eq!(packet.ipv4.as_ref().unwrap().total_length_octets, Some(60));
    assert_ne!(
        packet.ipv4.as_ref().unwrap().total_length_octets,
        Some(packet.frame.captured_len)
    );
    assert_eq!(packet.tcp.as_ref().unwrap().source_port, 41000);
    assert_eq!(packet.tcp.as_ref().unwrap().destination_port, 443);
    assert_eq!(packet.tcp.as_ref().unwrap().stream_index, Some(0));

    let vlan = normalize_fixture(
        directory.path(),
        "ethernet-vlan-ipv4-tcp",
        include_str!("fixtures/adapter/ethernet_vlan_ipv4_tcp.hex"),
    );
    assert_eq!(vlan.receipt.file.packet_count, 1);
    assert_eq!(vlan.receipt.file.original_data_size_bytes, 58);
    assert_eq!(
        vlan.manifest.normalization.state,
        NormalizationStateV0::Complete
    );
    assert!(!vlan.manifest.normalization.packet_limit_reached);
    let packet = &vlan.packets[0];
    assert_eq!(packet.frame.original_len, 58);
    assert_eq!(packet.frame.captured_len, 58);
    assert_eq!(
        packet.frame.protocols,
        ["eth", "ethertype", "vlan", "ethertype", "ip", "tcp"]
    );
    assert_eq!(packet.ipv4.as_ref().unwrap().source, "192.0.2.7");
    assert_eq!(packet.ipv4.as_ref().unwrap().destination, "198.51.100.8");
    assert_eq!(packet.tcp.as_ref().unwrap().source_port, 42000);
    assert_eq!(packet.tcp.as_ref().unwrap().destination_port, 443);

    let pcapng = normalize_fixture_with_extension(
        directory.path(),
        "ethernet-ipv4-tcp-pcapng",
        "pcapng",
        include_str!("fixtures/adapter/ethernet_ipv4_tcp.pcapng.hex"),
        1,
    );
    assert_eq!(pcapng.receipt.file.file_type, "pcapng");
    assert_eq!(pcapng.receipt.file.encapsulation, "ether");
    assert_eq!(pcapng.receipt.file.snaplen, None);
    assert_eq!(
        pcapng.manifest.normalization.state,
        NormalizationStateV0::Complete
    );
    assert!(!pcapng.manifest.normalization.packet_limit_reached);
}

#[test]
#[ignore = "requires an installed tshark; run through `just pcap-smoke`"]
fn installed_tshark_normalizes_wpan_nofcs_6lowpan_ipv6() {
    let directory = tempfile::tempdir().unwrap();
    let report = normalize_fixture_with_extension(
        directory.path(),
        "ieee802154-nofcs-6lowpan-ipv6",
        "pcapng",
        include_str!("fixtures/adapter/ieee802154_nofcs_6lowpan_ipv6.pcapng.hex"),
        1,
    );

    assert_eq!(
        report.manifest.normalization.state,
        NormalizationStateV0::Complete
    );
    assert_eq!(report.receipt.file.file_type, "pcapng");
    assert_eq!(report.receipt.file.encapsulation, "wpan-nofcs");
    assert_eq!(report.manifest.normalization.packet_rows_emitted, 1);
    assert_eq!(report.manifest.normalization.packet_rows_quarantined, 0);
    assert!(report.quarantines.is_empty());

    let packet = &report.packets[0];
    assert_eq!(packet.frame.original_len, 20);
    assert_eq!(packet.frame.captured_len, 20);
    assert!(packet
        .frame
        .protocols
        .windows(2)
        .any(|pair| pair == ["6lowpan", "ipv6"]));

    let ipv6 = packet.ipv6.as_ref().unwrap();
    assert_eq!(ipv6.source, "fe80::ff:fe00:2202");
    assert_eq!(ipv6.destination, "fe80::ff:fe00:2201");
    assert_eq!(ipv6.next_header, 58);
    assert_eq!(ipv6.total_length_octets, Some(48));
    assert!(ipv6.total_length_octets.unwrap() > packet.frame.original_len);

    let ieee802154 = packet.ieee802154.as_ref().unwrap();
    assert_eq!(ieee802154.frame_type, 1);
    assert_eq!(ieee802154.frame_version, 1);
    assert!(
        ieee802154.fcs_status.is_none(),
        "wpan-nofcs has no captured FCS bytes from which to infer validity"
    );
}

fn normalize_fixture(
    directory: &std::path::Path,
    name: &str,
    fixture: &str,
) -> netbraid::adapters::tshark::NormalizationReport {
    normalize_fixture_with_extension(directory, name, "pcap", fixture, 10)
}

fn normalize_fixture_with_extension(
    directory: &std::path::Path,
    name: &str,
    extension: &str,
    fixture: &str,
    packet_limit: usize,
) -> netbraid::adapters::tshark::NormalizationReport {
    let input = directory.join(format!("{name}.{extension}"));
    fs::write(&input, decode_hex(fixture)).unwrap();
    let report = normalize_saved_capture(
        &input,
        &NormalizeOptions {
            tshark_path: std::env::var_os("TSHARK")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("tshark")),
            capinfos_path: std::env::var_os("CAPINFOS")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("capinfos")),
            observer_id: Some("synthetic-fixture".into()),
            packet_limit,
            ..NormalizeOptions::default()
        },
    )
    .unwrap();
    assert_eq!(report.packets.len(), 1);
    assert!(report.quarantines.is_empty());
    report
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
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
