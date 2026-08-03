use netbraid::infer::{
    assess_counter_capture_v0, derive_traffic_window_features_ppb_v0,
    score_counter_capture_windows_v0, CounterCaptureDispositionV0, CounterCaptureErrorV0,
    CounterCaptureFeatureV0, CounterCaptureFeatureVectorPpbV0, CounterCaptureProfileV0,
    CounterCaptureReferenceV0, CounterCaptureResidualVectorPpbV0, CounterCaptureScaleVectorPpbV0,
    CounterCaptureScoringErrorV0, CounterCaptureUnknownReasonV0, CounterCaptureValidationErrorV0,
    TrafficWindowCoverageV0, TrafficWindowEvidenceV0, TrafficWindowV0, PPB,
};
use proptest::prelude::*;
use serde::Deserialize;

const EXACT_RATIONAL_FIXTURE: &str =
    include_str!("fixtures/infer/v0/exact-rational-counter-capture.json");

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactRationalFixture {
    counter: TrafficWindowEvidenceV0,
    capture: TrafficWindowEvidenceV0,
    profile: CounterCaptureProfileV0,
    expected: ExactRationalExpected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExactRationalExpected {
    counter_features_ppb: CounterCaptureFeatureVectorPpbV0,
    capture_features_ppb: CounterCaptureFeatureVectorPpbV0,
    residuals_ppb: CounterCaptureResidualVectorPpbV0,
    scaled_residual_sum_ppb: u128,
    counter_content_sha256: String,
    capture_content_sha256: String,
    profile_content_sha256: String,
}

fn fixture() -> ExactRationalFixture {
    serde_json::from_str(EXACT_RATIONAL_FIXTURE).expect("valid exact-rational fixture")
}

fn window(
    duration_ms: u64,
    received_bytes: u64,
    transmitted_bytes: u64,
    received_packets: u64,
    transmitted_packets: u64,
) -> TrafficWindowV0 {
    TrafficWindowV0::new(
        duration_ms,
        received_bytes,
        transmitted_bytes,
        received_packets,
        transmitted_packets,
    )
    .unwrap()
}

fn profile(
    profile_id: &str,
    support_threshold_ppb: u128,
    contradiction_threshold_ppb: u128,
) -> CounterCaptureProfileV0 {
    CounterCaptureProfileV0::new(
        profile_id,
        CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
        support_threshold_ppb,
        contradiction_threshold_ppb,
    )
    .unwrap()
}

#[test]
fn exact_rational_fixture_pins_all_ten_features_residuals_sum_and_hashes() {
    let fixture = fixture();
    let counter_window = fixture.counter.window.as_ref().unwrap();
    let capture_window = fixture.capture.window.as_ref().unwrap();

    let score = score_counter_capture_windows_v0(
        counter_window,
        capture_window,
        &fixture.profile.scales_ppb,
    )
    .unwrap();
    let assessment =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &fixture.profile).unwrap();

    assert_eq!(
        score.counter_features_ppb,
        fixture.expected.counter_features_ppb
    );
    assert_eq!(
        score.capture_features_ppb,
        fixture.expected.capture_features_ppb
    );
    assert_eq!(score.residuals_ppb, fixture.expected.residuals_ppb);
    assert_eq!(
        score.scaled_residual_sum_ppb,
        fixture.expected.scaled_residual_sum_ppb
    );
    assert_eq!(
        assessment.reference,
        CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow
    );
    assert_eq!(
        assessment.counter.content_sha256,
        fixture.expected.counter_content_sha256
    );
    assert_eq!(
        assessment.capture.content_sha256,
        fixture.expected.capture_content_sha256
    );
    assert_eq!(
        assessment.profile.content_sha256,
        fixture.expected.profile_content_sha256
    );
}

#[test]
fn public_scorer_and_assessment_reuse_exactly_the_same_artifacts() {
    let fixture = fixture();
    let score = score_counter_capture_windows_v0(
        fixture.counter.window.as_ref().unwrap(),
        fixture.capture.window.as_ref().unwrap(),
        &fixture.profile.scales_ppb,
    )
    .unwrap();
    let assessment =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &fixture.profile).unwrap();

    assert_eq!(
        assessment.basis.counter_features_ppb.as_ref(),
        Some(&score.counter_features_ppb)
    );
    assert_eq!(
        assessment.basis.capture_features_ppb.as_ref(),
        Some(&score.capture_features_ppb)
    );
    assert_eq!(
        assessment.basis.residuals_ppb.as_ref(),
        Some(&score.residuals_ppb)
    );
    assert_eq!(
        assessment.basis.scaled_residual_sum_ppb,
        Some(score.scaled_residual_sum_ppb)
    );
}

#[test]
fn support_contradiction_and_unknown_threshold_boundaries_are_explicit() {
    let fixture = fixture();
    let score = fixture.expected.scaled_residual_sum_ppb;

    let at_support = assess_counter_capture_v0(
        &fixture.counter,
        &fixture.capture,
        &profile("profile:at-support", score, score + 1),
    )
    .unwrap();
    assert_eq!(
        at_support.reference,
        CounterCaptureReferenceV0::CaptureAccountsForWindow
    );

    let at_contradiction = assess_counter_capture_v0(
        &fixture.counter,
        &fixture.capture,
        &profile("profile:at-contradiction", score - 1, score),
    )
    .unwrap();
    assert_eq!(
        at_contradiction.reference,
        CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow
    );

    let between = assess_counter_capture_v0(
        &fixture.counter,
        &fixture.capture,
        &profile("profile:between", score - 1, score + 1),
    )
    .unwrap();
    assert_eq!(
        between.reference,
        CounterCaptureReferenceV0::Unknown {
            reason: CounterCaptureUnknownReasonV0::ScoreBetweenThresholds,
        }
    );
    assert_eq!(between.unknown, CounterCaptureDispositionV0::Supported);
}

#[test]
fn incomplete_and_unavailable_coverage_hard_gate_to_unknown() {
    let complete_counter =
        TrafficWindowEvidenceV0::declared_complete("counter:complete", window(1_000, 10, 10, 1, 1));
    let complete_capture =
        TrafficWindowEvidenceV0::declared_complete("capture:complete", window(1_000, 10, 10, 1, 1));
    let calibration = profile("profile:coverage", 0, 1);
    let cases = [
        (
            TrafficWindowEvidenceV0::incomplete("counter:incomplete"),
            complete_capture.clone(),
            CounterCaptureUnknownReasonV0::CounterEvidenceIncomplete,
        ),
        (
            TrafficWindowEvidenceV0::unavailable("counter:unavailable"),
            complete_capture.clone(),
            CounterCaptureUnknownReasonV0::CounterEvidenceUnavailable,
        ),
        (
            complete_counter.clone(),
            TrafficWindowEvidenceV0::incomplete("capture:incomplete"),
            CounterCaptureUnknownReasonV0::CaptureEvidenceIncomplete,
        ),
        (
            complete_counter,
            TrafficWindowEvidenceV0::unavailable("capture:unavailable"),
            CounterCaptureUnknownReasonV0::CaptureEvidenceUnavailable,
        ),
    ];

    for (counter, capture, reason) in cases {
        let result = assess_counter_capture_v0(&counter, &capture, &calibration).unwrap();
        assert_eq!(
            result.reference,
            CounterCaptureReferenceV0::Unknown { reason }
        );
        assert_eq!(result.unknown, CounterCaptureDispositionV0::Supported);
        assert!(result.basis.counter_features_ppb.is_none());
        assert!(result.basis.capture_features_ppb.is_none());
        assert!(result.basis.scaled_residual_sum_ppb.is_none());
    }
}

#[test]
fn incompatible_sparse_features_hard_gate_to_unknown() {
    let counter =
        TrafficWindowEvidenceV0::declared_complete("counter:sparse", window(1_000, 0, 100, 0, 1));
    let capture =
        TrafficWindowEvidenceV0::declared_complete("capture:sparse", window(1_000, 100, 100, 1, 1));

    let result =
        assess_counter_capture_v0(&counter, &capture, &profile("profile:sparse", 0, 1)).unwrap();

    assert_eq!(
        result.reference,
        CounterCaptureReferenceV0::Unknown {
            reason: CounterCaptureUnknownReasonV0::IncompatibleEvidence {
                feature: CounterCaptureFeatureV0::MeanReceivedPacketBytes,
            },
        }
    );
    assert!(result.basis.counter_features_ppb.is_some());
    assert!(result.basis.capture_features_ppb.is_some());
    assert!(result.basis.residuals_ppb.is_none());
}

#[test]
fn evidence_and_profile_mutations_change_their_content_refs() {
    let fixture = fixture();
    let baseline =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &fixture.profile).unwrap();
    let original = *fixture.counter.window.as_ref().unwrap();
    let mutations = [
        window(
            original.duration_ms + 1,
            original.received_bytes,
            original.transmitted_bytes,
            original.received_packets,
            original.transmitted_packets,
        ),
        window(
            original.duration_ms,
            original.received_bytes + 1,
            original.transmitted_bytes,
            original.received_packets,
            original.transmitted_packets,
        ),
        window(
            original.duration_ms,
            original.received_bytes,
            original.transmitted_bytes + 1,
            original.received_packets,
            original.transmitted_packets,
        ),
        window(
            original.duration_ms,
            original.received_bytes,
            original.transmitted_bytes,
            original.received_packets + 1,
            original.transmitted_packets,
        ),
        window(
            original.duration_ms,
            original.received_bytes,
            original.transmitted_bytes,
            original.received_packets,
            original.transmitted_packets + 1,
        ),
    ];
    for mutation in mutations {
        let evidence =
            TrafficWindowEvidenceV0::declared_complete(fixture.counter.record_id.clone(), mutation);
        assert_ne!(
            evidence.canonical_sha256().unwrap(),
            baseline.counter.content_sha256
        );
    }

    let mut changed_profile = fixture.profile.clone();
    changed_profile.contradiction_threshold_ppb += 1;
    let changed =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &changed_profile).unwrap();
    assert_ne!(
        baseline.profile.content_sha256,
        changed.profile.content_sha256
    );
    assert_eq!(
        baseline.counter.content_sha256,
        changed.counter.content_sha256
    );
}

#[test]
fn strict_serde_and_structural_validation_have_explicit_limits() {
    let fixture = fixture();
    let assessment =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &fixture.profile).unwrap();
    let mut encoded = serde_json::to_value(&assessment).unwrap();
    encoded
        .as_object_mut()
        .unwrap()
        .insert("unexpected".into(), serde_json::Value::Bool(true));
    assert!(
        serde_json::from_value::<netbraid::infer::CounterCaptureHypothesisSetV0>(encoded).is_err()
    );

    let mut evidence = serde_json::to_value(&fixture.counter).unwrap();
    evidence["window"]["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<TrafficWindowEvidenceV0>(evidence).is_err());

    let mut incoherent = assessment.clone();
    incoherent.basis.scaled_residual_sum_ppb = Some(
        incoherent
            .basis
            .scaled_residual_sum_ppb
            .unwrap()
            .saturating_add(1),
    );
    assert_eq!(incoherent.validate_structure(), Ok(()));
    assert!(matches!(
        incoherent.validate_against(&fixture.counter, &fixture.capture, &fixture.profile),
        Err(CounterCaptureErrorV0::InternalInvariant(
            CounterCaptureValidationErrorV0::ResolvedContentMismatch
        ))
    ));

    let mut invalid_ref = assessment;
    invalid_ref.counter.content_sha256 = "A".repeat(64);
    assert_eq!(
        invalid_ref.validate_structure(),
        Err(CounterCaptureValidationErrorV0::InvalidEvidenceReference)
    );
}

#[test]
fn resolved_validation_binds_well_formed_references_basis_and_profile() {
    let fixture = fixture();
    let assessment =
        assess_counter_capture_v0(&fixture.counter, &fixture.capture, &fixture.profile).unwrap();
    assessment
        .validate_against(&fixture.counter, &fixture.capture, &fixture.profile)
        .unwrap();

    let mut unrelated_reference = assessment.clone();
    unrelated_reference.counter.content_sha256 = "0".repeat(64);
    assert_eq!(unrelated_reference.validate_structure(), Ok(()));
    assert!(matches!(
        unrelated_reference.validate_against(&fixture.counter, &fixture.capture, &fixture.profile,),
        Err(CounterCaptureErrorV0::InternalInvariant(
            CounterCaptureValidationErrorV0::ResolvedContentMismatch
        ))
    ));

    let mut changed_profile = fixture.profile.clone();
    changed_profile.contradiction_threshold_ppb += 1;
    assert!(matches!(
        assessment.validate_against(&fixture.counter, &fixture.capture, &changed_profile),
        Err(CounterCaptureErrorV0::InternalInvariant(
            CounterCaptureValidationErrorV0::ResolvedContentMismatch
        ))
    ));
}

#[test]
fn bounded_exact_arithmetic_hard_gates_unrepresentable_input_to_unknown() {
    let counter_window = window(u64::MAX - 1, u64::MAX, 0, 1, 0);
    let capture_window = window(u64::MAX - 3, u64::MAX - 1, 0, 1, 0);
    let scales = CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]);
    assert_eq!(
        score_counter_capture_windows_v0(&counter_window, &capture_window, &scales),
        Err(CounterCaptureScoringErrorV0::ArithmeticOverflow)
    );

    let counter = TrafficWindowEvidenceV0::declared_complete("counter:bounded", counter_window);
    let capture = TrafficWindowEvidenceV0::declared_complete("capture:bounded", capture_window);
    let result = assess_counter_capture_v0(
        &counter,
        &capture,
        &CounterCaptureProfileV0::new("profile:bounded", scales, 0, 1).unwrap(),
    )
    .unwrap();
    assert_eq!(
        result.reference,
        CounterCaptureReferenceV0::Unknown {
            reason: CounterCaptureUnknownReasonV0::ArithmeticUnrepresentable,
        }
    );
    assert_eq!(
        result.basis.counter_coverage,
        TrafficWindowCoverageV0::DeclaredComplete
    );
    assert!(result
        .limitations
        .iter()
        .any(|value| value.contains("caller assertion")));
}

#[test]
fn representable_u64_max_score_does_not_false_overflow() {
    let counter = window(1, 0, 0, 0, 0);
    let capture = window(1, u64::MAX, 0, 0, 0);
    let scales = CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]);

    let score = score_counter_capture_windows_v0(&counter, &capture, &scales)
        .expect("the exact score is representable in u128");
    assert_eq!(
        score.scaled_residual_sum_ppb,
        u128::from(u64::MAX) * 160_020_000_000_000
    );

    let counter = TrafficWindowEvidenceV0::declared_complete("counter:overflow", counter);
    let capture = TrafficWindowEvidenceV0::declared_complete("capture:overflow", capture);
    let calibration = CounterCaptureProfileV0::new("profile:overflow", scales, 0, 1).unwrap();
    let assessment = assess_counter_capture_v0(&counter, &capture, &calibration)
        .expect("representable arithmetic produces an assessment");
    assert_eq!(
        assessment.reference,
        CounterCaptureReferenceV0::CaptureDoesNotAccountForWindow
    );
}

#[test]
fn profile_validation_requires_supplied_positive_scales_and_ordered_thresholds() {
    assert!(CounterCaptureProfileV0::new(
        "profile:zero-scale",
        CounterCaptureScaleVectorPpbV0::from_values([0; 10]),
        0,
        1,
    )
    .is_err());
    assert!(CounterCaptureProfileV0::new(
        "profile:threshold-order",
        CounterCaptureScaleVectorPpbV0::from_values([1; 10]),
        1,
        1,
    )
    .is_err());
}

proptest! {
    #[test]
    fn identical_windows_have_zero_residual_and_support_correspondence(
        duration_ms in 1u64..=1_000_000,
        received_bytes in 0u64..=u32::MAX.into(),
        transmitted_bytes in 0u64..=u32::MAX.into(),
        received_packets in 0u64..=u32::MAX.into(),
        transmitted_packets in 0u64..=u32::MAX.into(),
    ) {
        let candidate = window(
            duration_ms,
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
        );
        let scales = CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]);
        let score = score_counter_capture_windows_v0(&candidate, &candidate, &scales).unwrap();
        prop_assert_eq!(score.scaled_residual_sum_ppb, 0);

        let counter = TrafficWindowEvidenceV0::declared_complete("counter:property", candidate);
        let capture = TrafficWindowEvidenceV0::declared_complete("capture:property", candidate);
        let calibration = CounterCaptureProfileV0::new("profile:property", scales, 0, 1).unwrap();
        let assessment = assess_counter_capture_v0(&counter, &capture, &calibration).unwrap();
        prop_assert_eq!(
            assessment.reference,
            CounterCaptureReferenceV0::CaptureAccountsForWindow
        );
    }

    #[test]
    fn feature_derivation_matches_the_closed_form_definition(
        duration_ms in 1u64..=1_000_000,
        received_bytes in 0u64..=u32::MAX.into(),
        transmitted_bytes in 0u64..=u32::MAX.into(),
        received_packets in 0u64..=u32::MAX.into(),
        transmitted_packets in 0u64..=u32::MAX.into(),
    ) {
        let candidate = window(
            duration_ms,
            received_bytes,
            transmitted_bytes,
            received_packets,
            transmitted_packets,
        );
        let ppb = PPB;
        let scaled_ratio = |numerator: u64, denominator: u64| {
            (denominator != 0).then(|| u128::from(numerator) * ppb / u128::from(denominator))
        };
        let packet_total = received_packets + transmitted_packets;
        let actual = derive_traffic_window_features_ppb_v0(&candidate).unwrap();
        prop_assert_eq!(actual.received_bytes, Some(u128::from(received_bytes) * ppb));
        prop_assert_eq!(actual.transmitted_bytes, Some(u128::from(transmitted_bytes) * ppb));
        prop_assert_eq!(actual.received_packets, Some(u128::from(received_packets) * ppb));
        prop_assert_eq!(actual.transmitted_packets, Some(u128::from(transmitted_packets) * ppb));
        prop_assert_eq!(actual.received_share, scaled_ratio(received_packets, packet_total));
        prop_assert_eq!(actual.transmitted_share, scaled_ratio(transmitted_packets, packet_total));
        prop_assert_eq!(actual.mean_received_packet_bytes, scaled_ratio(received_bytes, received_packets));
        prop_assert_eq!(actual.mean_transmitted_packet_bytes, scaled_ratio(transmitted_bytes, transmitted_packets));
        prop_assert_eq!(
            actual.mean_received_bits_per_second,
            Some(u128::from(received_bytes) * 8_000 * ppb / u128::from(duration_ms))
        );
        prop_assert_eq!(
            actual.mean_transmitted_bits_per_second,
            Some(u128::from(transmitted_bytes) * 8_000 * ppb / u128::from(duration_ms))
        );
    }
}
