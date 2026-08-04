use netbraid::infer::{
    infer_rssi_shift_explanations_v0, RssiMilliDbV0, RssiReferenceFrameLinkV0,
    RssiReferenceFrameProfileV0, RssiShiftExplanationAbstentionReasonV0,
    RssiShiftExplanationComponentOutcomeV0, RssiShiftExplanationErrorV0,
    RssiShiftExplanationOptionsV0,
};
use proptest::prelude::*;

const OBSERVERS: [&str; 3] = ["observer-a", "observer-b", "observer-c"];
const SOURCES: [&str; 3] = ["screen", "printer", "speaker"];

fn reference_profile() -> RssiReferenceFrameProfileV0 {
    RssiReferenceFrameProfileV0::new(
        "profile:rssi-shift-explanation:test",
        4,
        8_000,
        4_000_000_000,
        3,
        600_000_000,
    )
    .unwrap()
}

fn link(
    observer_id: &str,
    source_id: &str,
    baseline_milli_db: i32,
    recent_milli_db: Option<i32>,
) -> RssiReferenceFrameLinkV0 {
    RssiReferenceFrameLinkV0::new(
        observer_id,
        source_id,
        vec![RssiMilliDbV0::new(baseline_milli_db); 4],
        recent_milli_db.map(RssiMilliDbV0::new),
    )
    .unwrap()
}

fn frame(mut recent: impl FnMut(&str, &str, i32) -> Option<i32>) -> Vec<RssiReferenceFrameLinkV0> {
    let mut links = Vec::new();
    for (observer_index, observer_id) in OBSERVERS.into_iter().enumerate() {
        for (source_index, source_id) in SOURCES.into_iter().enumerate() {
            let baseline =
                -50_000 - i32::try_from(observer_index * 8_000 + source_index * 3_000).unwrap();
            links.push(link(
                observer_id,
                source_id,
                baseline,
                recent(observer_id, source_id, baseline),
            ));
        }
    }
    links
}

#[test]
fn source_wide_pattern_aggregates_without_promoting_observers() {
    let links = frame(|_, source_id, baseline| {
        Some(if source_id == "screen" {
            baseline - 20_000
        } else {
            baseline
        })
    });
    let report = infer_rssi_shift_explanations_v0(
        &links,
        &reference_profile(),
        &RssiShiftExplanationOptionsV0::default(),
    )
    .unwrap();

    assert_eq!(report.eligible_links(), 9);
    assert_eq!(report.shifted_links(), 3);
    assert_eq!(report.components().len(), 1);
    let component = &report.components()[0];
    assert!(matches!(
        component.outcome(),
        RssiShiftExplanationComponentOutcomeV0::Exact { .. }
    ));
    let screen = component
        .source_beliefs()
        .iter()
        .find(|belief| belief.source_id == "screen")
        .unwrap();
    assert!(screen.shifted_relative_belief_ppb > 900_000_000);
    assert!(component
        .observer_beliefs()
        .iter()
        .all(|belief| belief.shifted_relative_belief_ppb < 100_000_000));
    assert!(component
        .residual_beliefs()
        .iter()
        .all(|belief| belief.residual_relative_belief_ppb > 0));
}

#[test]
fn observer_wide_pattern_aggregates_without_promoting_sources() {
    let links = frame(|observer_id, _, baseline| {
        Some(if observer_id == "observer-a" {
            baseline + 18_000
        } else {
            baseline
        })
    });
    let report = infer_rssi_shift_explanations_v0(
        &links,
        &reference_profile(),
        &RssiShiftExplanationOptionsV0::default(),
    )
    .unwrap();
    let component = &report.components()[0];
    let observer = component
        .observer_beliefs()
        .iter()
        .find(|belief| belief.observer_id == "observer-a")
        .unwrap();

    assert!(observer.shifted_relative_belief_ppb > 900_000_000);
    assert!(component
        .source_beliefs()
        .iter()
        .all(|belief| belief.shifted_relative_belief_ppb < 100_000_000));
}

#[test]
fn isolated_shift_retains_symmetric_endpoint_and_residual_explanations() {
    let links = vec![link("observer-a", "screen", -50_000, Some(-70_000))];
    let report = infer_rssi_shift_explanations_v0(
        &links,
        &reference_profile(),
        &RssiShiftExplanationOptionsV0::default(),
    )
    .unwrap();
    let component = &report.components()[0];

    assert_eq!(component.observer_beliefs().len(), 1);
    assert_eq!(component.source_beliefs().len(), 1);
    assert_eq!(
        component.observer_beliefs()[0].shifted_relative_belief_ppb,
        component.source_beliefs()[0].shifted_relative_belief_ppb
    );
    assert_eq!(component.residual_beliefs().len(), 1);
    assert_eq!(
        component.residual_beliefs()[0].residual_relative_belief_ppb,
        29_850_746
    );
}

#[test]
fn stable_frame_has_no_residual_variables_or_shift_verdict() {
    let links = frame(|_, _, baseline| Some(baseline));
    let report = infer_rssi_shift_explanations_v0(
        &links,
        &reference_profile(),
        &RssiShiftExplanationOptionsV0::default(),
    )
    .unwrap();
    let component = &report.components()[0];

    assert_eq!(report.shifted_links(), 0);
    assert!(component.residual_beliefs().is_empty());
    assert!(component
        .observer_beliefs()
        .iter()
        .all(|belief| belief.shifted_relative_belief_ppb < 10_000_000));
    assert!(component
        .source_beliefs()
        .iter()
        .all(|belief| belief.shifted_relative_belief_ppb < 10_000_000));
}

#[test]
fn oversized_component_abstains_without_partial_beliefs() {
    let links = frame(|_, source_id, baseline| {
        Some(if source_id == "screen" {
            baseline - 20_000
        } else {
            baseline
        })
    });
    let mut options = RssiShiftExplanationOptionsV0::default();
    options.limits.max_component_variables = 5;
    let report = infer_rssi_shift_explanations_v0(&links, &reference_profile(), &options).unwrap();
    let component = &report.components()[0];

    assert_eq!(
        component.outcome(),
        &RssiShiftExplanationComponentOutcomeV0::Abstained(
            RssiShiftExplanationAbstentionReasonV0::ComponentVariableLimitExceeded {
                variables: 6,
                limit: 5,
            }
        )
    );
    assert!(component.observer_beliefs().is_empty());
    assert!(component.source_beliefs().is_empty());
    assert!(component.residual_beliefs().is_empty());
}

#[test]
fn report_budget_abstains_all_components_without_identifier_priority() {
    let links = vec![
        link("observer-a", "screen", -50_000, Some(-70_000)),
        link("observer-b", "speaker", -60_000, Some(-80_000)),
    ];
    let mut options = RssiShiftExplanationOptionsV0::default();
    options.limits.max_assignments = 4;
    let report = infer_rssi_shift_explanations_v0(&links, &reference_profile(), &options).unwrap();

    assert!(report.components().iter().all(|component| {
        component.outcome()
            == &RssiShiftExplanationComponentOutcomeV0::Abstained(
                RssiShiftExplanationAbstentionReasonV0::ReportAssignmentBudgetExceeded {
                    required: 8,
                    limit: 4,
                },
            )
    }));
}

#[test]
fn assignment_work_budget_abstains_before_model_evaluation() {
    let links = vec![link("observer-a", "screen", -50_000, Some(-70_000))];
    let mut options = RssiShiftExplanationOptionsV0::default();
    options.limits.max_assignment_work_units = 47;
    let report = infer_rssi_shift_explanations_v0(&links, &reference_profile(), &options).unwrap();

    assert_eq!(
        report.components()[0].outcome(),
        &RssiShiftExplanationComponentOutcomeV0::Abstained(
            RssiShiftExplanationAbstentionReasonV0::ReportAssignmentWorkBudgetExceeded {
                required: 48,
                limit: 47,
            }
        )
    );
}

#[test]
fn aggregate_baseline_sample_limit_precedes_classification() {
    let links = vec![link("observer-a", "screen", -50_000, Some(-70_000))];
    let mut options = RssiShiftExplanationOptionsV0::default();
    options.limits.max_baseline_samples = 3;

    assert!(matches!(
        infer_rssi_shift_explanations_v0(&links, &reference_profile(), &options),
        Err(RssiShiftExplanationErrorV0::BaselineSampleLimitExceeded)
    ));
}

#[test]
fn invalid_family_options_and_reference_input_fail_before_inference() {
    let links = vec![link("observer-a", "screen", -50_000, Some(-70_000))];
    let mut options = RssiShiftExplanationOptionsV0::default();
    options.profile.active_endpoint_potential_ppb = 0;
    assert!(matches!(
        infer_rssi_shift_explanations_v0(&links, &reference_profile(), &options),
        Err(RssiShiftExplanationErrorV0::InvalidProfile)
    ));

    let conflicting = vec![
        link("observer-a", "screen", -50_000, Some(-70_000)),
        link("observer-a", "screen", -50_000, Some(-50_000)),
    ];
    assert!(matches!(
        infer_rssi_shift_explanations_v0(
            &conflicting,
            &reference_profile(),
            &RssiShiftExplanationOptionsV0::default()
        ),
        Err(RssiShiftExplanationErrorV0::InvalidReferenceFrame(_))
    ));
}

proptest! {
    #[test]
    fn input_order_and_exact_duplicates_do_not_change_beliefs(order_keys in prop::collection::vec(any::<u64>(), 10)) {
        let links = frame(|_, source_id, baseline| {
            Some(if source_id == "screen" { baseline - 20_000 } else { baseline })
        });
        let expected = infer_rssi_shift_explanations_v0(
            &links,
            &reference_profile(),
            &RssiShiftExplanationOptionsV0::default(),
        ).unwrap();
        let mut reordered = links.clone();
        reordered.extend(links.iter().take(2).cloned());
        reordered.sort_by_key(|link| {
            let index = links.iter().position(|candidate| candidate == link).unwrap();
            order_keys.get(index).copied().unwrap_or(0)
        });
        let actual = infer_rssi_shift_explanations_v0(
            &reordered,
            &reference_profile(),
            &RssiShiftExplanationOptionsV0::default(),
        ).unwrap();

        prop_assert_eq!(actual.eligible_links(), expected.eligible_links());
        prop_assert_eq!(actual.shifted_links(), expected.shifted_links());
        prop_assert_eq!(actual.components(), expected.components());
    }
}
