//! Public synthetic preflight for source-preserving relation semantics.
//!
//! The fixture is public and synthetic, but the reducer under test is the
//! production policy-neutral Netbraid relation primitive. It does not infer
//! identity, access live radios, or write durable state.

use netbraid_replay::{reduce_relation_v0, RelationRecordV0, RelationStateV0};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    schema: String,
    privacy: String,
    as_of_unix_s: i64,
    freshness_window_s: i64,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    expected_sources: Vec<String>,
    records: Vec<RelationRecordV0>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Expected {
    relation: RelationStateV0,
    #[serde(default)]
    corrected_claim: Option<String>,
    #[serde(default)]
    history_length: Option<usize>,
    #[serde(default)]
    missing_sources: Vec<String>,
    #[serde(default)]
    stale_sources: Vec<String>,
    #[serde(default)]
    future_sources: Vec<String>,
    #[serde(default)]
    uncertain_sources: Vec<String>,
}

fn fixture() -> Fixture {
    serde_json::from_str(include_str!("fixtures/relation-preflight-v0.json"))
        .expect("public relation preflight fixture is valid JSON")
}

fn scope_key(case: &Case) -> Option<String> {
    case.records
        .iter()
        .find_map(|record| record.join_key.clone())
}

fn permutations(input: &[RelationRecordV0]) -> Vec<Vec<RelationRecordV0>> {
    fn visit(
        prefix: &mut Vec<RelationRecordV0>,
        remaining: &mut Vec<RelationRecordV0>,
        output: &mut Vec<Vec<RelationRecordV0>>,
    ) {
        if remaining.is_empty() {
            output.push(prefix.clone());
            return;
        }
        for index in 0..remaining.len() {
            let value = remaining.remove(index);
            prefix.push(value.clone());
            visit(prefix, remaining, output);
            prefix.pop();
            remaining.insert(index, value);
        }
    }

    let mut output = Vec::new();
    visit(&mut Vec::new(), &mut input.to_vec(), &mut output);
    output
}

fn reduce(
    fixture: &Fixture,
    case: &Case,
    records: Vec<RelationRecordV0>,
) -> netbraid_replay::RelationProjectionV0 {
    reduce_relation_v0(
        records,
        case.expected_sources.clone(),
        scope_key(case).as_deref(),
        fixture.as_of_unix_s,
        fixture.freshness_window_s,
    )
    .expect("synthetic relation fixture is valid")
}

#[test]
fn public_fixture_is_synthetic_and_covers_the_preflight_cases() {
    let value = fixture();
    assert_eq!(value.schema, "netbraid.relation_preflight_fixture.v0");
    assert_eq!(value.privacy, "PUBLIC_SYNTHETIC");
    assert_eq!(
        value
            .cases
            .iter()
            .map(|case| case.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "fresh_disagreement",
            "late_correction",
            "rotation_without_closure",
            "spectrum_clock_uncertainty",
            "health_without_station_link",
            "stale_observer",
            "future_observation",
        ]
    );
}

#[test]
fn production_relation_projection_is_stable_under_delivery_reordering_and_duplicates() {
    let fixture = fixture();
    for case in &fixture.cases {
        let baseline = reduce(&fixture, case, case.records.clone());
        assert_eq!(baseline.relation, case.expected.relation);
        assert_eq!(baseline.missing_sources, case.expected.missing_sources);
        assert_eq!(baseline.stale_sources, case.expected.stale_sources);
        assert_eq!(baseline.future_sources, case.expected.future_sources);
        assert_eq!(baseline.uncertain_sources, case.expected.uncertain_sources);

        for permutation in permutations(&case.records) {
            assert_eq!(reduce(&fixture, case, permutation), baseline);
        }
        let mut duplicate = case.records.clone();
        duplicate.push(case.records[0].clone());
        assert_eq!(reduce(&fixture, case, duplicate), baseline);

        if let Some(corrected_claim) = &case.expected.corrected_claim {
            assert_eq!(
                baseline.active_claims.as_slice(),
                std::slice::from_ref(corrected_claim)
            );
            assert_eq!(
                baseline.history_record_ids.len(),
                case.expected.history_length.unwrap()
            );
        }
    }
}

#[test]
fn rotating_identifiers_without_a_join_key_remain_insufficient() {
    let value = fixture();
    let case = value
        .cases
        .iter()
        .find(|case| case.id == "rotation_without_closure")
        .unwrap();
    let result = reduce(&value, case, case.records.clone());
    assert_eq!(result.relation, RelationStateV0::Insufficient);
    assert_eq!(result.active_claims, ["same-scene".to_owned()]);
}

#[test]
fn health_and_spectrum_limits_remain_explicit() {
    let value = fixture();
    let spectrum = value
        .cases
        .iter()
        .find(|case| case.id == "spectrum_clock_uncertainty")
        .unwrap();
    assert_eq!(
        reduce(&value, spectrum, spectrum.records.clone()).relation,
        RelationStateV0::Uncertain
    );

    let health = value
        .cases
        .iter()
        .find(|case| case.id == "health_without_station_link")
        .unwrap();
    assert_eq!(
        reduce(&value, health, health.records.clone()).relation,
        RelationStateV0::Missing
    );
}

#[test]
fn unrelated_join_keys_do_not_merge_into_the_selected_relation() {
    let value = fixture();
    let case = Case {
        id: "scoped-records".into(),
        expected_sources: vec!["wifi_observer".into()],
        records: vec![
            RelationRecordV0 {
                record_id: "scope-a".into(),
                source: "wifi_observer".into(),
                event_ts: 990,
                received_ts: 990,
                join_key: Some("a".into()),
                claim: "claim-a".into(),
                supersedes: None,
                clock_uncertainty_s: 0,
                corrected_by: None,
            },
            RelationRecordV0 {
                record_id: "scope-b".into(),
                source: "wifi_observer".into(),
                event_ts: 991,
                received_ts: 991,
                join_key: Some("b".into()),
                claim: "claim-b".into(),
                supersedes: None,
                clock_uncertainty_s: 0,
                corrected_by: None,
            },
        ],
        expected: Expected {
            relation: RelationStateV0::Correlated,
            corrected_claim: None,
            history_length: None,
            missing_sources: Vec::new(),
            stale_sources: Vec::new(),
            future_sources: Vec::new(),
            uncertain_sources: Vec::new(),
        },
    };
    let result = reduce(&value, &case, case.records.clone());
    assert_eq!(result.relation, RelationStateV0::Correlated);
    assert_eq!(result.active_record_ids, ["scope-a"]);
}
