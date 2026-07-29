use netbraid_evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureFileMetadataV0, CaptureManifestV0,
    CaptureNormalizationV0, CaptureRunReceiptV0, EthernetFieldsV0, Ieee80211FieldsV0, Ipv4FieldsV0,
    NormalizationStateV0, PacketEnvelopeV0, PacketFrameV0, PacketQuarantineV0, TcpFieldsV0,
    ToolRunReceiptV0, UdpFieldsV0, CAPTURE_MANIFEST_SCHEMA_V0, CAPTURE_RUN_RECEIPT_SCHEMA_V0,
    NORMALIZED_RECORDS_DIGEST_PROFILE_V0, PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};
use netbraid_replay::{
    parse_saved_capture_jsonl, project_saved_pcap_fingerprint_v0, project_saved_pcap_triage,
    project_saved_pcap_triage_v1, SavedPcapClaimScopeV0, SavedPcapConversationAggregationV0,
    SavedPcapConversationTriageV0, SavedPcapFingerprintStatusV0,
    SavedPcapNegativeClaimAbstentionReasonV1, SavedPcapNegativeClaimQualificationV1,
    SavedPcapTrailingConversationAggregationV1, SavedPcapTrailingConversationTriageV1,
    SavedPcapTrailingIntervalAnchorV1, SavedPcapTransportProtocolV0, SavedPcapTriageOptionsV1,
    SavedPcapTriageProjectionError, SavedPcapWlanDisconnectKindV0, SavedPcapWlanTriageV0,
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
fn fingerprint_candidate_is_observed_and_endpoint_free() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 3, 0),
        vec![
            tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
            tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
            wlan_packet(3, 12),
        ],
        vec![],
    );
    let triage =
        project_saved_pcap_triage_v1(&records, SavedPcapTriageOptionsV1::default()).unwrap();
    let candidate = project_saved_pcap_fingerprint_v0(&triage);

    assert_eq!(candidate.scope, SavedPcapClaimScopeV0::CompleteCapture);
    let SavedPcapFingerprintStatusV0::Observed {
        digest,
        basis,
        caveats,
    } = &candidate.status
    else {
        panic!("complete eligible packet evidence should produce an observed candidate");
    };
    assert!(digest.starts_with("sha256:"));
    assert_eq!(basis.feature_names.len(), 25);
    assert!(caveats
        .iter()
        .any(|caveat| caveat.contains("not sessionized")));

    let encoded = serde_json::to_string(&candidate).unwrap();
    assert!(!encoded.contains("192.0.2.1"));
    assert!(!encoded.contains("198.51.100.2"));
    assert!(!encoded.contains("40000"));
    assert!(!encoded.contains("443"));
    assert_eq!(encoded, serde_json::to_string(&candidate).unwrap());
}

#[test]
fn fingerprint_digest_ignores_endpoints_but_changes_for_included_features() {
    let records = validated_stream(
        manifest(NormalizationStateV0::Complete, 2, 0),
        vec![
            tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
            tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        ],
        vec![],
    );
    let triage =
        project_saved_pcap_triage_v1(&records, SavedPcapTriageOptionsV1::default()).unwrap();
    let baseline = project_saved_pcap_fingerprint_v0(&triage);

    let mut endpoint_changed = triage.clone();
    let SavedPcapConversationTriageV0::Observed { conversation, .. } =
        &mut endpoint_changed.top_capture_conversation
    else {
        panic!("the fixture should produce an observed conversation");
    };
    conversation.endpoint_a.address = "203.0.113.9".parse().unwrap();
    conversation.endpoint_b.port = 8443;
    let endpoint_candidate = project_saved_pcap_fingerprint_v0(&endpoint_changed);

    let mut feature_changed = triage;
    let SavedPcapConversationTriageV0::Observed { conversation, .. } =
        &mut feature_changed.top_capture_conversation
    else {
        panic!("the fixture should produce an observed conversation");
    };
    conversation.total_frames += 1;
    let feature_candidate = project_saved_pcap_fingerprint_v0(&feature_changed);

    let digest = |candidate: &netbraid_replay::SavedPcapFingerprintCandidateV0| {
        let SavedPcapFingerprintStatusV0::Observed { digest, .. } = &candidate.status else {
            panic!("candidate should remain observed");
        };
        digest.clone()
    };
    assert_eq!(digest(&baseline), digest(&endpoint_candidate));
    assert_ne!(digest(&baseline), digest(&feature_candidate));
}

#[test]
fn fingerprint_candidate_preserves_partial_and_unsupported_abstentions() {
    let partial = validated_stream(
        manifest(NormalizationStateV0::Partial, 0, 0),
        vec![],
        vec![],
    );
    let partial_triage =
        project_saved_pcap_triage_v1(&partial, SavedPcapTriageOptionsV1::default()).unwrap();
    let partial_candidate = project_saved_pcap_fingerprint_v0(&partial_triage);
    assert!(matches!(
        partial_candidate.status,
        SavedPcapFingerprintStatusV0::Insufficient { .. }
    ));
    assert!(!serde_json::to_string(&partial_candidate)
        .unwrap()
        .contains("digest"));

    let unsupported = validated_stream(
        manifest(NormalizationStateV0::Complete, 1, 0),
        vec![wlan_packet(1, 8)],
        vec![],
    );
    let unsupported_triage =
        project_saved_pcap_triage_v1(&unsupported, SavedPcapTriageOptionsV1::default()).unwrap();
    let unsupported_candidate = project_saved_pcap_fingerprint_v0(&unsupported_triage);
    assert!(matches!(
        unsupported_candidate.status,
        SavedPcapFingerprintStatusV0::Unsupported { .. }
    ));
    assert!(!serde_json::to_string(&unsupported_candidate)
        .unwrap()
        .contains("digest"));
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
fn v0_projection_preserves_its_exact_wire_shape_while_v1_retains_provenance() {
    let records = validated_stream(
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

    let v0 = project_saved_pcap_triage(&records).unwrap();
    let v0_json = serde_json::to_value(&v0).unwrap();
    assert!(
        v0_json.get("trailing_window").is_none(),
        "v0 must not grow v1 tail-analysis fields"
    );

    let v1 = project_saved_pcap_triage_v1(&records, SavedPcapTriageOptionsV1::default()).unwrap();
    assert_eq!(v1.schema, "netmon.saved_pcap_triage.v1");
    assert!(v1.trailing_window.is_none());
    assert_eq!(v1.source.manifest, records.manifest);
    assert_eq!(v1.source.receipt, records.receipt);
    assert_eq!(
        v1.source.normalized_records_sha256,
        records.normalized_records_sha256
    );
}

#[test]
fn trailing_window_selects_late_dns_while_cumulative_top_remains_https() {
    let packets = vec![
        tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        tcp_packet(3, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0010),
        tcp_packet(4, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0001),
        udp_packet(9, "203.0.113.10", 53_000, "203.0.113.53", 53),
        udp_packet(10, "203.0.113.53", 53, "203.0.113.10", 53_000),
    ];
    let records = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 6, 0),
        packets,
        vec![],
        1_000,
        10_000,
    );

    let triage = project_saved_pcap_triage_v1(
        &records,
        SavedPcapTriageOptionsV1 {
            tail_window_ns: Some(2_000),
        },
    )
    .unwrap();

    let SavedPcapConversationTriageV0::Observed {
        conversation: cumulative,
        ..
    } = triage.top_capture_conversation
    else {
        panic!("the four-frame HTTPS conversation should remain the cumulative top");
    };
    assert_eq!(cumulative.transport, SavedPcapTransportProtocolV0::Tcp);
    assert_eq!(
        cumulative.aggregation,
        SavedPcapConversationAggregationV0::CumulativeAcrossClaimScope
    );

    let trailing = triage.trailing_window.unwrap();
    assert_eq!(
        trailing.interval_anchor,
        Some(SavedPcapTrailingIntervalAnchorV1::SourceArtifactLatestPacketTime)
    );
    assert!(matches!(
        trailing.negative_claim_qualification,
        SavedPcapNegativeClaimQualificationV1::Qualified { .. }
    ));
    let bounds = trailing.requested_interval.unwrap();
    assert_eq!(bounds.start_event_time_unix_ns, 8_000);
    assert_eq!(bounds.end_event_time_unix_ns, 10_000);
    assert_eq!(trailing.selected_packet_extent.unwrap().observations, 2);
    let SavedPcapTrailingConversationTriageV1::Observed {
        packet_envelopes_seen,
        packet_envelopes_grouped,
        packet_envelopes_excluded,
        conversation,
        ..
    } = trailing.top_conversation
    else {
        panic!("the late DNS exchange should be the trailing-window top");
    };
    assert_eq!(packet_envelopes_seen, 2);
    assert_eq!(packet_envelopes_grouped, 2);
    assert_eq!(packet_envelopes_excluded, 0);
    assert_eq!(conversation.transport, SavedPcapTransportProtocolV0::Udp);
    assert_eq!(
        conversation.aggregation,
        SavedPcapTrailingConversationAggregationV1::CumulativeWithinRequestedInterval
    );
    assert!(conversation
        .tshark_candidate_display_filter
        .contains("frame.time_epoch >= 0.000008000 && frame.time_epoch <= 0.000010000"));
    assert!(conversation
        .tshark_candidate_display_filter
        .contains("udp.srcport == 53000"));
}

#[test]
fn trailing_window_projection_is_invariant_to_packet_input_order() {
    let packets = vec![
        tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        udp_packet(9, "203.0.113.10", 53_000, "203.0.113.53", 53),
        udp_packet(10, "203.0.113.53", 53, "203.0.113.10", 53_000),
    ];
    let forward = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 4, 0),
        packets.clone(),
        vec![],
        1_000,
        10_000,
    );
    let reverse_packets = packets
        .into_iter()
        .rev()
        .enumerate()
        .map(|(index, mut packet)| {
            let frame_number = u64::try_from(index).unwrap() + 1;
            packet.frame.number = frame_number;
            packet.record_id = format!("{CAPTURE_ID}:frame:{frame_number}");
            packet
        })
        .collect();
    let reverse = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 4, 0),
        reverse_packets,
        vec![],
        1_000,
        10_000,
    );
    let options = SavedPcapTriageOptionsV1 {
        tail_window_ns: Some(2_000),
    };

    let forward = project_saved_pcap_triage_v1(&forward, options)
        .unwrap()
        .trailing_window;
    let reverse = project_saved_pcap_triage_v1(&reverse, options)
        .unwrap()
        .trailing_window;

    assert_eq!(forward, reverse);
}

#[test]
fn trailing_window_includes_packets_on_both_requested_boundaries() {
    let packets = vec![
        tcp_packet(7, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        tcp_packet(8, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0010),
        tcp_packet(10, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
    ];
    let records = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 3, 0),
        packets,
        vec![],
        7_000,
        10_000,
    );

    let trailing = project_saved_pcap_triage_v1(
        &records,
        SavedPcapTriageOptionsV1 {
            tail_window_ns: Some(2_000),
        },
    )
    .unwrap()
    .trailing_window
    .unwrap();

    let observed = trailing.selected_packet_extent.unwrap();
    assert_eq!(observed.observations, 2);
    assert_eq!(observed.earliest_event_time_unix_ns, 8_000);
    assert_eq!(observed.latest_event_time_unix_ns, 10_000);
    let SavedPcapTrailingConversationTriageV1::Observed {
        packet_envelopes_seen,
        conversation,
        ..
    } = trailing.top_conversation
    else {
        panic!("both boundary packets should remain eligible");
    };
    assert_eq!(packet_envelopes_seen, 2);
    assert_eq!(conversation.total_frames, 2);
}

#[test]
fn receiptless_partial_tail_keeps_positive_selection_but_abstains_on_negatives() {
    let packets = vec![
        tcp_packet(9, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        tcp_packet(10, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
    ];
    let records = validated_stream(
        manifest(NormalizationStateV0::Partial, 2, 0),
        packets,
        vec![],
    );

    let trailing = project_saved_pcap_triage_v1(
        &records,
        SavedPcapTriageOptionsV1 {
            tail_window_ns: Some(20_000),
        },
    )
    .unwrap()
    .trailing_window
    .unwrap();

    assert_eq!(
        trailing.negative_claim_qualification,
        SavedPcapNegativeClaimQualificationV1::Abstained {
            reasons: vec![
                SavedPcapNegativeClaimAbstentionReasonV1::PartialNormalization,
                SavedPcapNegativeClaimAbstentionReasonV1::MissingOccurrenceReceipt,
            ],
        }
    );
    assert_eq!(
        trailing.interval_anchor,
        Some(SavedPcapTrailingIntervalAnchorV1::LatestNormalizedPacketEventTime)
    );
    let SavedPcapTrailingConversationTriageV1::Observed { .. } = trailing.top_conversation else {
        panic!("an abstained negative still preserves the positive conversation selection");
    };
}

#[test]
fn trailing_window_without_an_eligible_conversation_preserves_exclusion_counts() {
    let packets = vec![
        tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
        wlan_packet(9, 8),
        wlan_packet(10, 12),
    ];
    let records = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 3, 0),
        packets,
        vec![],
        1_000,
        10_000,
    );

    let trailing = project_saved_pcap_triage_v1(
        &records,
        SavedPcapTriageOptionsV1 {
            tail_window_ns: Some(2_000),
        },
    )
    .unwrap()
    .trailing_window
    .unwrap();

    let SavedPcapTrailingConversationTriageV1::NotObserved {
        packet_envelopes_seen,
        packet_envelopes_excluded,
        exclusions,
        ..
    } = trailing.top_conversation
    else {
        panic!("receipt-backed artifact extent supports a scoped not-observed result");
    };
    assert_eq!(packet_envelopes_seen, 2);
    assert_eq!(packet_envelopes_excluded, 2);
    assert_eq!(
        exclusions
            .iter()
            .map(|exclusion| exclusion.packet_envelopes)
            .sum::<u64>(),
        2
    );
}

#[test]
fn source_artifact_extent_that_does_not_span_the_interval_forces_negative_abstention() {
    let records = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 2, 0),
        vec![
            tcp_packet(9, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
            tcp_packet(10, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        ],
        vec![],
        9_000,
        10_000,
    );

    let trailing = project_saved_pcap_triage_v1(
        &records,
        SavedPcapTriageOptionsV1 {
            tail_window_ns: Some(20_000),
        },
    )
    .unwrap()
    .trailing_window
    .unwrap();

    assert_eq!(
        trailing.negative_claim_qualification,
        SavedPcapNegativeClaimQualificationV1::Abstained {
            reasons: vec![
                SavedPcapNegativeClaimAbstentionReasonV1::SourceArtifactExtentDoesNotSpanRequestedInterval,
            ],
        }
    );
    assert!(matches!(
        trailing.top_conversation,
        SavedPcapTrailingConversationTriageV1::Observed { .. }
    ));
}

#[test]
fn normalized_future_timestamp_outside_receipt_file_extent_is_rejected() {
    let records = validated_stream_with_receipt(
        manifest(NormalizationStateV0::Complete, 2, 0),
        vec![
            tcp_packet(9, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x0002),
            tcp_packet(10, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x0012),
        ],
        vec![],
        1_000,
        9_000,
    );

    assert_eq!(
        project_saved_pcap_triage_v1(
            &records,
            SavedPcapTriageOptionsV1 {
                tail_window_ns: Some(2_000),
            },
        ),
        Err(
            SavedPcapTriageProjectionError::NormalizedPacketExtentOutsideReceiptFileExtent {
                normalized_earliest_event_time_unix_ns: 9_000,
                normalized_latest_event_time_unix_ns: 10_000,
                receipt_earliest_packet_time_unix_ns: 1_000,
                receipt_latest_packet_time_unix_ns: 9_000,
            }
        )
    );
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

fn validated_stream_with_receipt(
    manifest: CaptureManifestV0,
    packets: Vec<PacketEnvelopeV0>,
    quarantines: Vec<PacketQuarantineV0>,
    earliest_packet_time_unix_ns: i64,
    latest_packet_time_unix_ns: i64,
) -> netbraid_replay::SavedCaptureRecordStreamV0 {
    let records = validated_stream(manifest, packets, quarantines);
    let receipt = CaptureRunReceiptV0 {
        schema: CAPTURE_RUN_RECEIPT_SCHEMA_V0.into(),
        run_id: "run:1111111111111111111111111111111111111111111111111111111111111111".into(),
        capture_id: records.manifest.capture_id.clone(),
        started_time_unix_ns: 20_000,
        finished_time_unix_ns: 30_000,
        elapsed_ns: 10_000,
        file: CaptureFileMetadataV0 {
            file_type: "pcap".into(),
            encapsulation: "ether".into(),
            timestamp_precision: "nanoseconds".into(),
            packet_count: records
                .manifest
                .normalization
                .packet_rows_emitted
                .saturating_add(records.manifest.normalization.packet_rows_quarantined),
            file_size_bytes: records.manifest.artifact.size_bytes,
            original_data_size_bytes: 100,
            snaplen: Some(65_535),
            inferred_snaplen_min: None,
            inferred_snaplen_max: None,
            duration_ns: Some(
                u64::try_from(
                    latest_packet_time_unix_ns.saturating_sub(earliest_packet_time_unix_ns),
                )
                .unwrap(),
            ),
            earliest_packet_time_unix_ns: Some(earliest_packet_time_unix_ns),
            latest_packet_time_unix_ns: Some(latest_packet_time_unix_ns),
            capture_hardware: None,
            capture_operating_system: None,
            capture_application: None,
        },
        capinfos: successful_tool_receipt("capinfos"),
        tshark: successful_tool_receipt("tshark"),
        configuration_sha256: records.manifest.extractor.configuration_sha256.clone(),
        field_registry: records.manifest.extractor.field_registry.clone(),
        normalized_records_digest_profile: NORMALIZED_RECORDS_DIGEST_PROFILE_V0.into(),
        normalized_records_sha256: records.normalized_records_sha256.clone(),
    };
    let mut jsonl = Vec::new();
    push_record(&mut jsonl, &records.manifest);
    push_record(&mut jsonl, &receipt);
    for packet in records.packets {
        push_record(&mut jsonl, &packet);
    }
    for quarantine in records.quarantines {
        push_record(&mut jsonl, &quarantine);
    }
    parse_saved_capture_jsonl(&jsonl).unwrap()
}

fn successful_tool_receipt(tool: &str) -> ToolRunReceiptV0 {
    ToolRunReceiptV0 {
        tool: tool.into(),
        configured_executable: tool.into(),
        tool_version: format!("{tool} 4.6.7"),
        argument_template: vec!["-r".into(), "$STAGED_CAPTURE".into()],
        environment_policy: "netmon.wireshark.environment.v0".into(),
        exit_code: 0,
        stdout_sha256: RECORDS_DIGEST.into(),
        stderr_sha256: RECORDS_DIGEST.into(),
    }
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

fn udp_packet(
    frame_number: u64,
    source: &str,
    source_port: u16,
    destination: &str,
    destination_port: u16,
) -> PacketEnvelopeV0 {
    let mut packet = tcp_packet(
        frame_number,
        source,
        source_port,
        destination,
        destination_port,
        0,
    );
    packet.frame.protocols = vec!["eth".into(), "ethertype".into(), "ip".into(), "udp".into()];
    packet.ipv4.as_mut().unwrap().protocol = 17;
    packet.tcp = None;
    packet.udp = Some(UdpFieldsV0 {
        source_port,
        destination_port,
    });
    packet
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
