use netbraid::evidence::PacketEnvelopeV0;
use netbraid::infer::{
    assess_content_relation_v0, assess_counter_capture_v0, assess_packet_same_event_v0,
    assess_saved_pcap_fingerprint_v0, ContentDigestEvidenceV0, ContentRelationDispositionV0,
    ContentRelationReferenceV0, ContentSha256V0, CounterCaptureDispositionV0,
    CounterCaptureProfileV0, CounterCaptureReferenceV0, CounterCaptureScaleVectorPpbV0,
    CounterCaptureUnknownReasonV0, PacketSameEventDispositionV0, PacketSameEventReferenceV0,
    PacketSameEventUnknownReasonV0, ProjectFiniteHypothesesV0, ProjectFiniteHypothesisClaimV0,
    SavedPcapFingerprintCandidateRefV0, SavedPcapFingerprintCandidateV0,
    SavedPcapFingerprintComparisonV0, SavedPcapFingerprintDispositionV0,
    SavedPcapFingerprintErrorV0, SavedPcapFingerprintHypothesisSetV0,
    SavedPcapFingerprintReferenceV0, SavedPcapFingerprintValidationErrorV0,
    TrafficWindowEvidenceV0, TrafficWindowV0, FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0,
    FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0, SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0,
    SAVED_PCAP_FINGERPRINT_REDUCER_V0,
};

fn packet() -> PacketEnvelopeV0 {
    serde_json::from_str(include_str!(
        "fixtures/replay/evidence-v0/packet_envelope_v0.json"
    ))
    .expect("fixture is a valid packet envelope")
}

fn wlan_packet() -> PacketEnvelopeV0 {
    serde_json::from_str(include_str!(
        "fixtures/evidence/v0/packet_envelope_wlan_v0.json"
    ))
    .expect("fixture is a valid WLAN packet envelope")
}

// Keep the shared law local: each production family retains its own
// dispositions, evidence roles, decision basis, and error type.
fn assert_finite_hypothesis_law<D>(
    family: &str,
    substantive: [(&str, D); 2],
    unknown: D,
    selected_substantive: Option<&str>,
    supported: D,
    contradicted: D,
    underdetermined: D,
) where
    D: Copy + std::fmt::Debug + PartialEq,
{
    match selected_substantive {
        Some(selected) => {
            let mut selected_count = 0;
            for (role, disposition) in substantive {
                let expected = if role == selected {
                    selected_count += 1;
                    supported
                } else {
                    contradicted
                };
                assert_eq!(disposition, expected, "{family} {role} disposition");
            }
            assert_eq!(selected_count, 1, "{family} selected substantive role");
            assert_eq!(unknown, contradicted, "{family} unknown disposition");
        }
        None => {
            for (role, disposition) in substantive {
                assert_eq!(disposition, underdetermined, "{family} {role} disposition");
            }
            assert_eq!(unknown, supported, "{family} unknown disposition");
        }
    }
}

#[test]
fn public_same_event_family_obeys_finite_hypothesis_law() {
    let left = packet();
    let mut right = packet();
    right.capture_id =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
    right.record_id = format!("{}:frame:1", right.capture_id);

    let result = assess_packet_same_event_v0(&left, &right).expect("valid assessment");
    let projection = result
        .project_finite_hypotheses_v0()
        .expect("valid finite projection");
    let claim = result
        .project_finite_hypothesis_claim_v0((&left, &right))
        .expect("valid finite claim");

    assert_eq!(
        result.reference,
        PacketSameEventReferenceV0::Unknown {
            reason: PacketSameEventUnknownReasonV0::MissingIeee80211Evidence,
        }
    );
    assert_eq!(projection.schema(), FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0);
    assert_eq!(claim.schema(), FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0);
    assert_eq!(claim.projection(), &projection);
    assert_eq!(claim.inputs()[0].role(), "left_packet");
    assert_eq!(claim.inputs()[1].role(), "right_packet");
    assert_eq!(projection.family_schema(), result.schema);
    assert_eq!(projection.reducer(), result.reducer);
    assert_eq!(
        projection
            .alternatives()
            .iter()
            .map(|alternative| alternative.role())
            .collect::<Vec<_>>(),
        ["same_event", "different_event", "unknown"]
    );
    assert_finite_hypothesis_law(
        "same-event unknown",
        [
            ("same_event", result.same_event),
            ("different_event", result.different_event),
        ],
        result.unknown,
        None,
        PacketSameEventDispositionV0::Supported,
        PacketSameEventDispositionV0::Contradicted,
        PacketSameEventDispositionV0::Underdetermined,
    );
    assert!(result.basis.compared_dimensions.is_empty());

    let left = wlan_packet();
    let mut right = wlan_packet();
    right.capture_id =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
    right.record_id = format!("{}:frame:2", right.capture_id);
    right
        .ieee80211
        .as_mut()
        .expect("WLAN fixture has IEEE 802.11 fields")
        .frame_subtype = 4;

    let result = assess_packet_same_event_v0(&left, &right).expect("valid assessment");

    assert_eq!(result.reference, PacketSameEventReferenceV0::DifferentEvent);
    assert_finite_hypothesis_law(
        "same-event substantive",
        [
            ("same_event", result.same_event),
            ("different_event", result.different_event),
        ],
        result.unknown,
        Some("different_event"),
        PacketSameEventDispositionV0::Supported,
        PacketSameEventDispositionV0::Contradicted,
        PacketSameEventDispositionV0::Underdetermined,
    );
    assert_eq!(result.basis.compared_dimensions.len(), 2);
    assert_eq!(result.basis.conflicting_dimensions.len(), 1);
}

#[test]
fn public_counter_capture_family_obeys_finite_hypothesis_law() {
    let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
    let counter = TrafficWindowEvidenceV0::declared_complete("counter:facade:0", window);
    let capture = TrafficWindowEvidenceV0::declared_complete("capture:facade:0", window);
    let profile = CounterCaptureProfileV0::new(
        "profile:facade:0",
        CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
        0,
        1,
    )
    .unwrap();

    let result = assess_counter_capture_v0(&counter, &capture, &profile).unwrap();
    let claim = result
        .project_finite_hypothesis_claim_v0((&counter, &capture, &profile))
        .unwrap();

    assert_eq!(
        result.reference,
        CounterCaptureReferenceV0::CaptureAccountsForWindow
    );
    assert_finite_hypothesis_law(
        "counter/capture substantive",
        [
            (
                "capture_accounts_for_window",
                result.capture_accounts_for_window,
            ),
            (
                "capture_does_not_account_for_window",
                result.capture_does_not_account_for_window,
            ),
        ],
        result.unknown,
        Some("capture_accounts_for_window"),
        CounterCaptureDispositionV0::Supported,
        CounterCaptureDispositionV0::Contradicted,
        CounterCaptureDispositionV0::Underdetermined,
    );
    assert_eq!(result.basis.scaled_residual_sum_ppb, Some(0));
    assert_eq!(
        claim
            .inputs()
            .iter()
            .map(|reference| reference.role())
            .collect::<Vec<_>>(),
        ["calibration_profile", "capture_window", "counter_window"]
    );

    let counter = TrafficWindowEvidenceV0::incomplete("counter:facade:unknown");
    let result = assess_counter_capture_v0(&counter, &capture, &profile).unwrap();

    assert_eq!(
        result.reference,
        CounterCaptureReferenceV0::Unknown {
            reason: CounterCaptureUnknownReasonV0::CounterEvidenceIncomplete,
        }
    );
    assert_finite_hypothesis_law(
        "counter/capture unknown",
        [
            (
                "capture_accounts_for_window",
                result.capture_accounts_for_window,
            ),
            (
                "capture_does_not_account_for_window",
                result.capture_does_not_account_for_window,
            ),
        ],
        result.unknown,
        None,
        CounterCaptureDispositionV0::Supported,
        CounterCaptureDispositionV0::Contradicted,
        CounterCaptureDispositionV0::Underdetermined,
    );
    assert!(result.basis.counter_features_ppb.is_none());
}

#[test]
fn public_content_relation_family_obeys_finite_hypothesis_law() {
    let left = ContentDigestEvidenceV0::observed(
        "digest:left",
        "netbraid.test_artifact.v0",
        "artifact:left",
        ContentSha256V0::try_new("a".repeat(64)).unwrap(),
    )
    .unwrap();
    let right = ContentDigestEvidenceV0::observed(
        "digest:right",
        "netbraid.test_artifact.v0",
        "artifact:right",
        ContentSha256V0::try_new("b".repeat(64)).unwrap(),
    )
    .unwrap();

    let result = assess_content_relation_v0(&left, &right).unwrap();
    let projection = result.project_finite_hypotheses_v0().unwrap();
    let claim = result
        .project_finite_hypothesis_claim_v0((&left, &right))
        .unwrap();
    let swapped_claim = result
        .project_finite_hypothesis_claim_v0((&right, &left))
        .unwrap();

    assert_eq!(
        result.reference(),
        ContentRelationReferenceV0::Sha256Mismatch
    );
    assert_finite_hypothesis_law(
        "content relation substantive",
        [
            ("sha256_match", result.sha256_match()),
            ("sha256_mismatch", result.sha256_mismatch()),
        ],
        result.unknown(),
        Some("sha256_mismatch"),
        ContentRelationDispositionV0::Supported,
        ContentRelationDispositionV0::Contradicted,
        ContentRelationDispositionV0::Underdetermined,
    );
    assert_eq!(
        projection
            .alternatives()
            .iter()
            .map(|alternative| alternative.role())
            .collect::<Vec<_>>(),
        ["sha256_match", "sha256_mismatch", "unknown"]
    );
    assert_eq!(claim.projection(), &projection);
    assert_eq!(swapped_claim, claim);
    assert_eq!(claim.inputs()[0].role(), "left_content_evidence");
    assert_eq!(claim.inputs()[0].source_id(), "digest:left");
    assert_eq!(claim.inputs()[1].role(), "right_content_evidence");
    assert_eq!(claim.inputs()[1].source_id(), "digest:right");
}

#[test]
fn public_saved_pcap_fingerprint_family_is_available_through_infer() {
    let _reducer: fn(
        &SavedPcapFingerprintCandidateV0,
        &SavedPcapFingerprintCandidateV0,
    )
        -> Result<SavedPcapFingerprintHypothesisSetV0, SavedPcapFingerprintErrorV0> =
        assess_saved_pcap_fingerprint_v0;
    let _public_types = (
        std::mem::size_of::<netbraid::infer::FiniteHypothesisClaimErrorV0>(),
        std::mem::size_of::<netbraid::infer::FiniteHypothesisClaimV0>(),
        std::mem::size_of::<netbraid::infer::FiniteHypothesisInputRefV0>(),
        std::mem::size_of::<SavedPcapFingerprintCandidateRefV0>(),
        std::mem::size_of::<SavedPcapFingerprintComparisonV0>(),
        std::mem::size_of::<SavedPcapFingerprintDispositionV0>(),
        std::mem::size_of::<SavedPcapFingerprintReferenceV0>(),
        std::mem::size_of::<SavedPcapFingerprintValidationErrorV0>(),
    );

    assert_eq!(
        SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0,
        "netmon.saved_pcap_fingerprint_hypothesis_set.v0"
    );
    assert_eq!(
        SAVED_PCAP_FINGERPRINT_REDUCER_V0,
        "netbraid.saved_pcap_fingerprint.packet_shape.v0"
    );
}
