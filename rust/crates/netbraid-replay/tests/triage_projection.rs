use netbraid_evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0, CaptureNormalizationV0,
    EthernetFieldsV0, Ieee80211FieldsV0, Ipv4FieldsV0, NormalizationStateV0, PacketEnvelopeV0,
    PacketFrameV0, PacketQuarantineV0, TcpFieldsV0, CAPTURE_MANIFEST_SCHEMA_V0,
    PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};
use netbraid_replay::{
    parse_saved_capture_jsonl, project_saved_pcap_triage, SavedPcapClaimScopeV0,
    SavedPcapConversationTriageV0, SavedPcapTriageProjectionError, SavedPcapWlanDisconnectKindV0,
    SavedPcapWlanTriageV0,
};

const CAPTURE_ID: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const RECORDS_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn positive_triage_projection_matches_contract_golden() {
    let packets = vec![
        tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        wlan_packet(3, 12),
    ];
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 3, 0),
        packets,
        vec![],
    );
    let triage = project_saved_pcap_triage(&records).unwrap();

    assert_golden(&triage, include_str!("fixtures/triage-positive-v0.json"));
}

#[test]
fn partial_triage_projection_matches_contract_golden() {
    let packets = vec![tcp_packet(
        1,
        "192.0.2.1",
        40_000,
        "198.51.100.2",
        443,
        0x0002,
    )];
    let quarantines = vec![PacketQuarantineV0 {
        schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
        capture_id: CAPTURE_ID.into(),
        source_line: 2,
        frame_number_hint: Some(2),
        reason: "field count 2 does not match registry field count 32".into(),
        raw_row: "2\tinvalid".into(),
    }];
    let records = validated_stream(
        manifest(NormalizationStateV0::Partial, 1, 1),
        packets,
        quarantines,
    );
    let triage = project_saved_pcap_triage(&records).unwrap();

    assert_golden(&triage, include_str!("fixtures/triage-partial-v0.json"));
}

#[test]
fn unsupported_triage_projection_matches_contract_golden() {
    let packets = vec![PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{CAPTURE_ID}:frame:1"),
        capture_id: CAPTURE_ID.into(),
        frame: PacketFrameV0 {
            number: 1,
            event_time_unix_ns: 1_000,
            original_len: 42,
            captured_len: 42,
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(1),
            protocols: vec!["eth".into(), "ethertype".into(), "arp".into()],
        },
        ethernet: Some(EthernetFieldsV0 {
            source: Some("02:00:00:00:00:01".into()),
            destination: Some("ff:ff:ff:ff:ff:ff".into()),
        }),
        ipv4: None,
        ipv6: None,
        tcp: None,
        udp: None,
        ieee80211: None,
        wlan_radio: None,
    }];
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 1, 0),
        packets,
        vec![],
    );
    let triage = project_saved_pcap_triage(&records).unwrap();

    assert_golden(&triage, include_str!("fixtures/triage-unsupported-v0.json"));
}

#[test]
fn partial_empty_subset_is_insufficient_not_capture_wide_absence() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Partial, 0, 0),
        vec![],
        vec![],
    );
    let triage = project_saved_pcap_triage(&records).unwrap();

    assert!(matches!(
        triage.wlan,
        SavedPcapWlanTriageV0::Insufficient {
            scope: SavedPcapClaimScopeV0::NormalizedPacketSubset,
            ..
        }
    ));
    assert!(matches!(
        triage.top_capture_conversation,
        SavedPcapConversationTriageV0::Insufficient {
            scope: SavedPcapClaimScopeV0::NormalizedPacketSubset,
            ..
        }
    ));
}

#[test]
fn partial_wlan_subset_reports_positive_immediately_and_qualifies_negative() {
    let observed_records = validated_stream(
        manifest(NormalizationStateV0::Partial, 1, 0),
        vec![wlan_packet(1, 12)],
        vec![],
    );
    let observed = project_saved_pcap_triage(&observed_records).unwrap();
    assert!(matches!(
        observed.wlan,
        SavedPcapWlanTriageV0::Observed {
            scope: SavedPcapClaimScopeV0::NormalizedPacketSubset,
            ..
        }
    ));

    let negative_records = validated_stream(
        manifest(NormalizationStateV0::Partial, 1, 0),
        vec![wlan_packet(1, 8)],
        vec![],
    );
    let negative = project_saved_pcap_triage(&negative_records).unwrap();
    assert!(matches!(
        negative.wlan,
        SavedPcapWlanTriageV0::NotObserved {
            scope: SavedPcapClaimScopeV0::NormalizedPacketSubset,
            ..
        }
    ));
}

#[test]
fn wlan_projection_preserves_each_supported_disconnect_subtype_observed() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 2, 0),
        vec![wlan_packet(1, 12), wlan_packet(2, 10)],
        vec![],
    );
    let triage = project_saved_pcap_triage(&records).unwrap();
    let SavedPcapWlanTriageV0::Observed { disconnects, .. } = triage.wlan else {
        panic!("both supported disconnect subtypes should be observed");
    };

    assert_eq!(disconnects.len(), 2);
    assert_eq!(
        disconnects[0].kind,
        SavedPcapWlanDisconnectKindV0::Deauthentication
    );
    assert_eq!(
        disconnects[1].kind,
        SavedPcapWlanDisconnectKindV0::Disassociation
    );
}

#[test]
fn conversation_filter_is_explicitly_a_candidate_that_can_include_excluded_rows() {
    let flat = tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002);
    let mut vlan = tcp_packet(2, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002);
    vlan.frame.protocols = vec![
        "eth".into(),
        "ethertype".into(),
        "vlan".into(),
        "ethertype".into(),
        "ip".into(),
        "tcp".into(),
    ];
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 2, 0),
        vec![flat, vlan],
        vec![],
    );
    let triage = project_saved_pcap_triage(&records).unwrap();
    let SavedPcapConversationTriageV0::Observed {
        packet_envelopes_grouped,
        packet_envelopes_excluded,
        conversation,
        ..
    } = triage.top_capture_conversation
    else {
        panic!("flat packet should produce a conversation");
    };

    assert_eq!(packet_envelopes_grouped, 1);
    assert_eq!(packet_envelopes_excluded, 1);
    assert!(
        !conversation
            .tshark_candidate_display_filter
            .contains("vlan"),
        "the candidate pivot intentionally does not reproduce all reducer eligibility rules"
    );
}

#[test]
fn projection_rejects_a_stream_whose_validated_record_counts_were_mutated() {
    let mut records = validated_stream(
        manifest(NormalizationStateV0::Complete, 1, 0),
        vec![tcp_packet(
            1,
            "192.0.2.1",
            40_000,
            "198.51.100.2",
            443,
            0x0002,
        )],
        vec![],
    );
    records.packets.clear();

    assert_eq!(
        project_saved_pcap_triage(&records),
        Err(
            SavedPcapTriageProjectionError::ManifestPacketCountMismatch {
                declared: 1,
                actual: 0,
            }
        )
    );
}

#[test]
fn projection_recomputes_and_rejects_a_fabricated_record_digest_without_a_receipt() {
    let mut records = validated_stream(
        manifest(NormalizationStateV0::Complete, 1, 0),
        vec![tcp_packet(
            1,
            "192.0.2.1",
            40_000,
            "198.51.100.2",
            443,
            0x0002,
        )],
        vec![],
    );
    let recomputed = records.normalized_records_sha256.clone();
    records.normalized_records_sha256 = RECORDS_DIGEST.into();

    assert_eq!(
        project_saved_pcap_triage(&records),
        Err(
            SavedPcapTriageProjectionError::NormalizedRecordsDigestMismatch {
                declared: RECORDS_DIGEST.into(),
                recomputed,
            }
        )
    );
}

fn assert_golden<T: serde::Serialize>(actual: &T, expected: &str) {
    let actual = serde_json::to_value(actual).unwrap();
    let expected: serde_json::Value = serde_json::from_str(expected).unwrap();
    assert_eq!(actual, expected);
}

fn manifest(
    state: NormalizationStateV0,
    packet_rows_emitted: u64,
    packet_rows_quarantined: u64,
) -> CaptureManifestV0 {
    CaptureManifestV0 {
        schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
        capture_id: CAPTURE_ID.into(),
        artifact: CaptureArtifactRefV0 {
            content_sha256: CAPTURE_ID.into(),
            size_bytes: 100,
        },
        observer_id: None,
        acquired_time_unix_ms: None,
        extractor: CaptureExtractorRefV0 {
            adapter: "netbraid-adapter-tshark".into(),
            adapter_version: "0.2.0".into(),
            tool: "tshark".into(),
            tool_version: "TShark 4.6.7".into(),
            configuration_sha256: RECORDS_DIGEST.into(),
            field_registry: "netmon.tshark.packet_envelope.v1".into(),
        },
        acquisition_policy: None,
        normalization: CaptureNormalizationV0 {
            state,
            packet_limit: 10,
            packet_limit_reached: state == NormalizationStateV0::Partial,
            packet_rows_emitted,
            packet_rows_quarantined,
        },
    }
}

fn validated_stream(
    manifest: CaptureManifestV0,
    packets: Vec<PacketEnvelopeV0>,
    quarantines: Vec<PacketQuarantineV0>,
) -> netbraid_replay::SavedCaptureRecordStreamV0 {
    let mut jsonl = Vec::new();
    push_record(&mut jsonl, &manifest);
    for packet in packets {
        push_record(&mut jsonl, &packet);
    }
    for quarantine in quarantines {
        push_record(&mut jsonl, &quarantine);
    }
    parse_saved_capture_jsonl(&jsonl).unwrap()
}

fn push_record(output: &mut Vec<u8>, record: &impl serde::Serialize) {
    serde_json::to_writer(&mut *output, record).unwrap();
    output.push(b'\n');
}

fn tcp_packet(
    frame_number: u64,
    source: &str,
    source_port: u16,
    destination: &str,
    destination_port: u16,
    flags: u16,
) -> PacketEnvelopeV0 {
    PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{CAPTURE_ID}:frame:{frame_number}"),
        capture_id: CAPTURE_ID.into(),
        frame: PacketFrameV0 {
            number: frame_number,
            event_time_unix_ns: i64::try_from(frame_number).unwrap() * 1_000,
            original_len: 100,
            captured_len: 100,
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(1),
            protocols: vec!["eth".into(), "ethertype".into(), "ip".into(), "tcp".into()],
        },
        ethernet: Some(EthernetFieldsV0 {
            source: Some("02:00:00:00:00:01".into()),
            destination: Some("02:00:00:00:00:02".into()),
        }),
        ipv4: Some(Ipv4FieldsV0 {
            source: source.into(),
            destination: destination.into(),
            protocol: 6,
        }),
        ipv6: None,
        tcp: Some(TcpFieldsV0 {
            source_port,
            destination_port,
            flags,
        }),
        udp: None,
        ieee80211: None,
        wlan_radio: None,
    }
}

fn wlan_packet(frame_number: u64, frame_subtype: u8) -> PacketEnvelopeV0 {
    PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{CAPTURE_ID}:frame:{frame_number}"),
        capture_id: CAPTURE_ID.into(),
        frame: PacketFrameV0 {
            number: frame_number,
            event_time_unix_ns: i64::try_from(frame_number).unwrap() * 1_000,
            original_len: 50,
            captured_len: 50,
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(105),
            protocols: vec!["wlan".into()],
        },
        ethernet: None,
        ipv4: None,
        ipv6: None,
        tcp: None,
        udp: None,
        ieee80211: Some(Ieee80211FieldsV0 {
            frame_type: 0,
            frame_subtype,
            transmitter: Some("02:00:00:00:00:01".into()),
            receiver: Some("02:00:00:00:00:02".into()),
            source: Some("02:00:00:00:00:01".into()),
            destination: Some("02:00:00:00:00:02".into()),
            bssid: Some("02:00:00:00:00:01".into()),
            ssid_hex: None,
        }),
        wlan_radio: None,
    }
}
