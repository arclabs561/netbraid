use netbraid::evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0, CaptureNormalizationV0,
    NormalizationStateV0, PacketEnvelopeV0, PacketFrameV0, PacketQuarantineV0,
    CAPTURE_MANIFEST_SCHEMA_V0, PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};
use netbraid::replay::{
    parse_saved_capture_jsonl, project_saved_pcap_ieee802154_v0, SavedPcapClaimScopeV0,
    SavedPcapTriageProjectionError, SAVED_PCAP_IEEE802154_PROJECTION_SCHEMA_V0,
};

const CAPTURE_ID: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const CONFIGURATION_DIGEST: &str =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXTENDED_ADDRESS: &str = "02:00:00:00:00:00:00:01";

#[test]
fn projection_has_exact_aggregate_contract_without_identifiers() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 10, false, 4, 0),
        vec![
            ieee802154_packet(
                1,
                (3, 1),
                Some(42),
                (Some(0x1111), Some(0x1234), None),
                (Some(0x2222), None, Some(EXTENDED_ADDRESS.into())),
                Some(4),
                Some(true),
            ),
            ieee802154_packet(
                2,
                (1, 2),
                Some(43),
                (None, None, None),
                (Some(0x2222), Some(0x5678), None),
                None,
                Some(false),
            ),
            ieee802154_packet(
                3,
                (1, 2),
                None,
                (Some(0x1111), None, Some("02:00:00:00:00:00:00:02".into())),
                (None, None, None),
                Some(4),
                None,
            ),
            packet(4),
        ],
        vec![],
    );

    let projection = project_saved_pcap_ieee802154_v0(&records).unwrap();

    assert_eq!(
        projection.schema,
        SAVED_PCAP_IEEE802154_PROJECTION_SCHEMA_V0
    );
    assert_eq!(
        projection.completeness.scope,
        SavedPcapClaimScopeV0::CompleteCapture
    );
    assert_eq!(projection.counts.packet_envelopes, 4);
    assert_eq!(projection.counts.packet_quarantines, 0);
    assert_eq!(projection.counts.packet_rows_inspected, 4);
    assert_eq!(projection.counts.ieee802154_frames, 3);
    assert_eq!(projection.counts.other_packet_envelopes, 1);
    assert_eq!(
        serde_json::to_value(&projection.frame_type_version_mix).unwrap(),
        serde_json::json!([
            {"frame_type": 1, "frame_version": 2, "frames": 2},
            {"frame_type": 3, "frame_version": 1, "frames": 1}
        ])
    );
    assert_eq!(
        serde_json::to_value(projection.address_forms).unwrap(),
        serde_json::json!({
            "destination": {"absent_frames": 1, "short_frames": 1, "extended_frames": 1},
            "source": {"absent_frames": 1, "short_frames": 1, "extended_frames": 1}
        })
    );
    assert_eq!(
        serde_json::to_value(&projection.commands).unwrap(),
        serde_json::json!({
            "present_frames": 2,
            "unavailable_frames": 1,
            "command_mix": [{"command": 4, "frames": 2}]
        })
    );
    assert_eq!(
        serde_json::to_value(projection.fcs).unwrap(),
        serde_json::json!({
            "valid_frames": 1,
            "invalid_frames": 1,
            "unavailable_frames": 1
        })
    );
    assert_eq!(projection.limitations.len(), 7);

    let first = serde_json::to_vec(&projection).unwrap();
    let second = serde_json::to_vec(&projection).unwrap();
    assert_eq!(first, second);
    let encoded = String::from_utf8(first).unwrap();
    for excluded in [
        "observer-secret",
        EXTENDED_ADDRESS,
        "02:00:00:00:00:00:00:02",
        "destination_pan_id",
        "source_pan_id",
        "sequence_number",
        "capture_id",
        "record_id",
        "raw_row",
    ] {
        assert!(!encoded.contains(excluded), "retained {excluded:?}");
    }
    assert!(!encoded.contains("\"value\":4660"));
    assert!(!encoded.contains("\"value\":22136"));
}

#[test]
fn partial_scope_and_quarantine_counts_remain_explicit() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Partial, 2, true, 1, 1),
        vec![ieee802154_packet(
            1,
            (1, 0),
            None,
            (None, Some(0x1234), None),
            (None, None, Some(EXTENDED_ADDRESS.into())),
            None,
            None,
        )],
        vec![PacketQuarantineV0 {
            schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
            capture_id: CAPTURE_ID.into(),
            source_line: 2,
            frame_number_hint: None,
            reason: "fixture quarantine".into(),
            raw_row: format!("private-row {EXTENDED_ADDRESS}"),
        }],
    );

    let projection = project_saved_pcap_ieee802154_v0(&records).unwrap();

    assert_eq!(
        projection.completeness.scope,
        SavedPcapClaimScopeV0::NormalizedPacketSubset
    );
    assert_eq!(projection.completeness.state, NormalizationStateV0::Partial);
    assert_eq!(projection.completeness.packet_limit, 2);
    assert!(projection.completeness.packet_limit_reached);
    assert_eq!(projection.counts.packet_envelopes, 1);
    assert_eq!(projection.counts.packet_quarantines, 1);
    assert_eq!(projection.counts.packet_rows_inspected, 2);
    assert!(!serde_json::to_string(&projection)
        .unwrap()
        .contains("private-row"));
}

#[test]
fn projection_rejects_a_stream_that_no_longer_matches_its_provenance() {
    let mut records = validated_stream(
        manifest(NormalizationStateV0::Complete, 10, false, 1, 0),
        vec![ieee802154_packet(
            1,
            (1, 0),
            None,
            (None, None, None),
            (None, None, None),
            None,
            None,
        )],
        vec![],
    );
    records.packets[0].capture_id = CONFIGURATION_DIGEST.into();

    assert_eq!(
        project_saved_pcap_ieee802154_v0(&records),
        Err(SavedPcapTriageProjectionError::CaptureIdMismatch { family: "packet" })
    );
}

fn manifest(
    state: NormalizationStateV0,
    packet_limit: u64,
    packet_limit_reached: bool,
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
        observer_id: Some("observer-secret".into()),
        acquired_time_unix_ms: Some(1_700_000_000_000),
        extractor: CaptureExtractorRefV0 {
            adapter: "netbraid-adapter-tshark".into(),
            adapter_version: "0.3.1".into(),
            tool: "tshark".into(),
            tool_version: "TShark 4.6.7".into(),
            configuration_sha256: CONFIGURATION_DIGEST.into(),
            field_registry: "netmon.tshark.packet_envelope.v1".into(),
        },
        acquisition_policy: None,
        normalization: CaptureNormalizationV0 {
            state,
            packet_limit,
            packet_limit_reached,
            packet_rows_emitted,
            packet_rows_quarantined,
        },
    }
}

fn validated_stream(
    manifest: CaptureManifestV0,
    packets: Vec<PacketEnvelopeV0>,
    quarantines: Vec<PacketQuarantineV0>,
) -> netbraid::replay::SavedCaptureRecordStreamV0 {
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

fn packet(frame_number: u64) -> PacketEnvelopeV0 {
    PacketEnvelopeV0 {
        schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
        record_id: format!("{CAPTURE_ID}:frame:{frame_number}"),
        capture_id: CAPTURE_ID.into(),
        frame: PacketFrameV0 {
            number: frame_number,
            event_time_unix_ns: i64::try_from(frame_number).unwrap() * 1_000,
            original_len: 32,
            captured_len: 32,
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(195),
            protocols: vec!["wpan".into()],
        },
        ethernet: None,
        ipv4: None,
        ipv6: None,
        tcp: None,
        udp: None,
        ieee802154: None,
        ieee80211: None,
        wlan_radio: None,
        bluetooth_le: None,
    }
}

#[allow(clippy::too_many_arguments)]
fn ieee802154_packet(
    frame_number: u64,
    header: (u8, u8),
    sequence_number: Option<u8>,
    destination: (Option<u16>, Option<u16>, Option<String>),
    source: (Option<u16>, Option<u16>, Option<String>),
    command: Option<u8>,
    fcs_valid: Option<bool>,
) -> PacketEnvelopeV0 {
    let mut packet = packet(frame_number);
    packet
        .set_ieee802154_fields(
            header,
            sequence_number,
            destination,
            source,
            command,
            fcs_valid,
        )
        .unwrap();
    packet
}
