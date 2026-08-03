use netbraid::infer::{
    assess_rssi_reference_frame_v0, RssiLinkShiftKindV0, RssiMilliDbV0, RssiObserverEvidenceV0,
    RssiReferenceFrameErrorV0, RssiReferenceFrameLinkV0, RssiReferenceFrameProfileV0,
    RssiReferenceFrameProfileValidationErrorV0, RSSI_REFERENCE_FRAME_PPB_V0,
};
use proptest::prelude::*;

const OBSERVERS: [&str; 3] = ["observer-a", "observer-b", "observer-c"];
const SOURCES: [&str; 4] = ["screen", "printer", "appliance", "speaker"];
const BASELINES: [[i32; 4]; 3] = [
    [-58_000, -66_000, -72_000, -61_000],
    [-70_000, -55_000, -64_000, -75_000],
    [-77_000, -68_000, -52_000, -69_000],
];

fn profile() -> RssiReferenceFrameProfileV0 {
    RssiReferenceFrameProfileV0::new(
        "profile:rssi-reference-frame:test",
        4,
        8_000,
        4 * RSSI_REFERENCE_FRAME_PPB_V0,
        3,
        600_000_000,
    )
    .unwrap()
}

fn link(
    observer_id: &str,
    source_id: &str,
    baseline_milli_db: i32,
    baseline_readings: usize,
    recent_milli_db: Option<i32>,
) -> RssiReferenceFrameLinkV0 {
    RssiReferenceFrameLinkV0::new(
        observer_id,
        source_id,
        vec![RssiMilliDbV0::new(baseline_milli_db); baseline_readings],
        recent_milli_db.map(RssiMilliDbV0::new),
    )
    .unwrap()
}

fn frame_links(
    baseline_readings: usize,
    mut recent: impl FnMut(&str, &str, i32) -> Option<i32>,
) -> Vec<RssiReferenceFrameLinkV0> {
    let mut links = Vec::new();
    for (observer_index, observer_id) in OBSERVERS.into_iter().enumerate() {
        for (source_index, source_id) in SOURCES.into_iter().enumerate() {
            let baseline = BASELINES[observer_index][source_index];
            links.push(link(
                observer_id,
                source_id,
                baseline,
                baseline_readings,
                recent(observer_id, source_id, baseline),
            ));
        }
    }
    links
}

fn stable_links() -> Vec<RssiReferenceFrameLinkV0> {
    frame_links(4, |_, _, baseline| Some(baseline))
}

fn observer<'a>(
    assessment: &'a netbraid::infer::RssiReferenceFrameAssessmentV0,
    observer_id: &str,
) -> Option<&'a RssiObserverEvidenceV0> {
    assessment
        .observer_evidence()
        .iter()
        .find(|evidence| evidence.observer_id() == observer_id)
}

#[test]
fn stable_reference_frame_retains_evidence_without_candidates() {
    let assessment = assess_rssi_reference_frame_v0(&stable_links(), &profile()).unwrap();

    assert!(assessment.source_wide_shift_candidates().is_empty());
    assert_eq!(assessment.observer_evidence().len(), 3);
    for evidence in assessment.observer_evidence() {
        assert!(!evidence.observer_shift_candidate());
        assert_eq!(evidence.steady_link_count(), 4);
        assert_eq!(evidence.shifted_link_count(), 0);
        assert_eq!(evidence.median_shift_milli_db(), None);
        assert!(evidence.link_evidence().is_empty());
    }
}

#[test]
fn observer_wide_shift_is_an_observer_candidate() {
    let links = frame_links(4, |observer_id, _, baseline| {
        Some(if observer_id == "observer-a" {
            baseline - 15_000
        } else {
            baseline
        })
    });
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
    let evidence = observer(&assessment, "observer-a").unwrap();

    assert!(evidence.observer_shift_candidate());
    assert_eq!(evidence.steady_link_count(), 4);
    assert_eq!(evidence.shifted_link_count(), 4);
    assert_eq!(evidence.median_shift_milli_db(), Some(-15_000));
    assert!(assessment.source_wide_shift_candidates().is_empty());
    assert!(assessment
        .observer_evidence()
        .iter()
        .filter(|candidate| candidate.observer_id() != "observer-a")
        .all(|candidate| !candidate.observer_shift_candidate()));
}

#[test]
fn source_wide_shift_is_attributed_before_observer_evidence() {
    let links = frame_links(4, |_, source_id, baseline| {
        Some(if source_id == "screen" {
            baseline - 20_000
        } else {
            baseline
        })
    });
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();

    assert_eq!(assessment.source_wide_shift_candidates().len(), 1);
    assert_eq!(
        assessment.source_wide_shift_candidates()[0].source_id(),
        "screen"
    );
    assert_eq!(
        assessment.source_wide_shift_candidates()[0].observer_ids(),
        OBSERVERS
    );
    for evidence in assessment.observer_evidence() {
        assert!(!evidence.observer_shift_candidate());
        assert_eq!(evidence.steady_link_count(), 3);
        assert_eq!(evidence.shifted_link_count(), 0);
        assert!(evidence
            .link_evidence()
            .iter()
            .all(|link| link.source_id() != "screen"));
    }
}

#[test]
fn vanished_steady_links_count_only_for_an_observer_with_recent_input() {
    let mut links = frame_links(4, |observer_id, _, baseline| {
        (observer_id != "observer-a").then_some(baseline)
    });
    links.push(link("observer-a", "recent-only", -50_000, 0, Some(-50_000)));

    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
    let evidence = observer(&assessment, "observer-a").unwrap();

    assert!(evidence.observer_shift_candidate());
    assert_eq!(evidence.steady_link_count(), 4);
    assert_eq!(evidence.shifted_link_count(), 4);
    assert_eq!(evidence.median_shift_milli_db(), None);
    assert!(evidence
        .link_evidence()
        .iter()
        .all(|link| link.kind() == RssiLinkShiftKindV0::Vanished));
    assert!(assessment.source_wide_shift_candidates().is_empty());
}

#[test]
fn inactive_observer_is_absent_from_evidence_and_candidates() {
    let links = frame_links(4, |observer_id, _, baseline| {
        (observer_id != "observer-a").then_some(baseline)
    });
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();

    assert!(observer(&assessment, "observer-a").is_none());
    assert!(assessment
        .observer_evidence()
        .iter()
        .all(|evidence| !evidence.observer_shift_candidate()));
}

#[test]
fn source_gone_at_every_active_observer_is_source_wide_only() {
    let links = frame_links(4, |_, source_id, baseline| {
        (source_id != "screen").then_some(baseline)
    });
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();

    assert_eq!(assessment.source_wide_shift_candidates().len(), 1);
    assert_eq!(
        assessment.source_wide_shift_candidates()[0].source_id(),
        "screen"
    );
    assert!(assessment
        .observer_evidence()
        .iter()
        .all(|evidence| !evidence.observer_shift_candidate()));
}

#[test]
fn observer_candidate_requires_the_absolute_link_quorum() {
    let links = vec![
        link("observer-a", "screen", -58_000, 4, Some(-75_000)),
        link("observer-a", "printer", -66_000, 4, Some(-80_000)),
    ];
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
    let evidence = observer(&assessment, "observer-a").unwrap();

    assert_eq!(evidence.steady_link_count(), 2);
    assert_eq!(evidence.shifted_link_count(), 2);
    assert!(!evidence.observer_shift_candidate());
}

#[test]
fn insufficient_baseline_history_is_inert() {
    let links = frame_links(2, |_, _, baseline| Some(baseline - 20_000));
    let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();

    assert!(assessment.observer_evidence().is_empty());
    assert!(assessment.source_wide_shift_candidates().is_empty());
}

#[test]
fn conflicting_duplicate_links_and_invalid_profiles_are_rejected() {
    let links = vec![
        link("observer-a", "screen", -58_000, 4, Some(-58_000)),
        link("observer-a", "screen", -58_000, 4, Some(-70_000)),
    ];
    assert!(matches!(
        assess_rssi_reference_frame_v0(&links, &profile()),
        Err(RssiReferenceFrameErrorV0::ConflictingObserverSourceLink {
            observer_id,
            source_id,
        }) if observer_id == "observer-a" && source_id == "screen"
    ));

    assert_eq!(
        RssiReferenceFrameProfileV0::new(
            "profile:invalid",
            4,
            8_000,
            4 * RSSI_REFERENCE_FRAME_PPB_V0,
            3,
            RSSI_REFERENCE_FRAME_PPB_V0 + 1,
        ),
        Err(RssiReferenceFrameProfileValidationErrorV0::InvalidMinimumShiftedFraction)
    );

    let mut encoded_profile = serde_json::to_value(profile()).unwrap();
    encoded_profile["schema"] = serde_json::Value::String("unsupported".into());
    let invalid_profile: RssiReferenceFrameProfileV0 =
        serde_json::from_value(encoded_profile).unwrap();
    assert!(matches!(
        assess_rssi_reference_frame_v0(&stable_links(), &invalid_profile),
        Err(RssiReferenceFrameErrorV0::InvalidProfile(
            RssiReferenceFrameProfileValidationErrorV0::UnsupportedSchema
        ))
    ));
}

#[test]
fn equivalent_duplicate_links_are_canonicalized() {
    let first = RssiReferenceFrameLinkV0::new(
        "observer-a",
        "screen",
        vec![
            RssiMilliDbV0::new(-58_000),
            RssiMilliDbV0::new(-57_000),
            RssiMilliDbV0::new(-59_000),
            RssiMilliDbV0::new(-58_000),
        ],
        Some(RssiMilliDbV0::new(-58_000)),
    )
    .unwrap();
    let second = RssiReferenceFrameLinkV0::new(
        "observer-a",
        "screen",
        vec![
            RssiMilliDbV0::new(-59_000),
            RssiMilliDbV0::new(-58_000),
            RssiMilliDbV0::new(-57_000),
            RssiMilliDbV0::new(-58_000),
        ],
        Some(RssiMilliDbV0::new(-58_000)),
    )
    .unwrap();

    let duplicated = assess_rssi_reference_frame_v0(&[first.clone(), second], &profile()).unwrap();
    let singular = assess_rssi_reference_frame_v0(&[first], &profile()).unwrap();
    assert_eq!(duplicated, singular);
}

proptest! {
    #[test]
    fn input_order_does_not_change_the_assessment(order_keys in prop::collection::vec(any::<u64>(), 12)) {
        let links = frame_links(4, |observer_id, source_id, baseline| {
            Some(if observer_id == "observer-a" && source_id != "screen" {
                baseline - 15_000
            } else if source_id == "screen" {
                baseline - 20_000
            } else {
                baseline
            })
        });
        let expected = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
        let mut indexed = links.into_iter().enumerate().collect::<Vec<_>>();
        indexed.sort_by_key(|(index, _)| (order_keys[*index], *index));
        let reordered = indexed.into_iter().map(|(_, link)| link).collect::<Vec<_>>();

        prop_assert_eq!(
            assess_rssi_reference_frame_v0(&reordered, &profile()).unwrap(),
            expected
        );
    }

    #[test]
    fn serde_is_deterministic_for_fixed_point_inputs(delta_milli_db in -30_000i32..=30_000) {
        let links = frame_links(4, |observer_id, _, baseline| {
            Some(if observer_id == "observer-a" {
                baseline.saturating_add(delta_milli_db)
            } else {
                baseline
            })
        });
        let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
        let first = serde_json::to_string(&assessment).unwrap();
        let decoded: netbraid::infer::RssiReferenceFrameAssessmentV0 =
            serde_json::from_str(&first).unwrap();
        let second = serde_json::to_string(&decoded).unwrap();

        prop_assert_eq!(first, second);
    }

    #[test]
    fn source_wide_shift_never_becomes_observer_candidate(
        magnitude_milli_db in 8_000i32..=30_000,
        positive in any::<bool>(),
    ) {
        let delta = if positive { magnitude_milli_db } else { -magnitude_milli_db };
        let links = frame_links(4, |_, source_id, baseline| {
            Some(if source_id == "screen" {
                baseline + delta
            } else {
                baseline
            })
        });
        let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();

        prop_assert_eq!(assessment.source_wide_shift_candidates().len(), 1);
        prop_assert!(assessment
            .observer_evidence()
            .iter()
            .all(|evidence| !evidence.observer_shift_candidate()));
        let source_excluded = assessment.observer_evidence().iter().all(|evidence| {
            evidence
                .link_evidence()
                .iter()
                .all(|link| link.source_id() != "screen")
        });
        prop_assert!(source_excluded);
    }

    #[test]
    fn inactive_observer_never_becomes_a_candidate(inactive_shift in -30_000i32..=30_000) {
        let mut links = Vec::new();
        for (source_index, source_id) in SOURCES.into_iter().enumerate() {
            let baseline = BASELINES[0][source_index].saturating_add(inactive_shift);
            links.push(link("observer-a", source_id, baseline, 4, None));
        }
        links.extend(frame_links(4, |observer_id, _, baseline| {
            (observer_id != "observer-a").then_some(baseline)
        }).into_iter().filter(|link| link.observer_id() != "observer-a"));

        let assessment = assess_rssi_reference_frame_v0(&links, &profile()).unwrap();
        prop_assert!(observer(&assessment, "observer-a").is_none());
    }
}
