//! Public synthetic preflight for source-preserving relation semantics.
//!
//! This is a fixture contract, not a public heterogeneous-fusion API. It lets
//! downstream developers exercise the important abstention and replay rules
//! without deployment-specific data, live radios, or a durable writer.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

#[derive(Debug, PartialEq, Eq)]
struct Reduced {
    relation: String,
    sources: BTreeSet<String>,
    missing_sources: BTreeSet<String>,
    uncertain_sources: BTreeSet<String>,
    active_claims: BTreeSet<String>,
    history_length: usize,
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/relation-preflight-v0.json"))
        .expect("public relation preflight fixture is valid JSON")
}

fn records(case: &Value) -> Vec<Value> {
    case["records"]
        .as_array()
        .expect("relation case records")
        .clone()
}

fn record_sort_key(record: &Value) -> (i64, i64, String) {
    (
        record["event_ts"].as_i64().expect("event timestamp"),
        record["received_ts"].as_i64().expect("receipt timestamp"),
        record["record_id"].as_str().expect("record id").to_owned(),
    )
}

fn canonical_records(records: &[Value]) -> Vec<Value> {
    let mut canonical = records.to_vec();
    canonical.sort_by_key(record_sort_key);
    canonical
}

fn replay(records: &[Value]) -> (Vec<Value>, Vec<String>) {
    let mut active = BTreeMap::<String, Value>::new();
    let mut seen = BTreeMap::<String, Value>::new();
    let mut history = Vec::new();

    for record in canonical_records(records) {
        let record_id = record["record_id"].as_str().expect("record id").to_owned();
        if let Some(previous) = seen.get(&record_id) {
            assert_eq!(previous, &record, "duplicate record id changed content");
            continue;
        }
        seen.insert(record_id.clone(), record.clone());
        history.push(record_id.clone());
        let Some(superseded) = record.get("supersedes").and_then(Value::as_str) else {
            active.insert(record_id, record);
            continue;
        };

        let mut corrected = active
            .get(superseded)
            .and_then(Value::as_object)
            .expect("correction references an earlier record")
            .clone();
        corrected.extend(
            record
                .as_object()
                .expect("relation record object")
                .iter()
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        corrected.insert("record_id".into(), Value::String(superseded.into()));
        corrected.insert("corrected_by".into(), Value::String(record_id));
        active.insert(superseded.into(), Value::Object(corrected));
    }

    (active.into_values().collect(), history)
}

fn reduce(case: &Value, input: &[Value]) -> Reduced {
    let (active, history) = replay(input);
    let expected_sources = case["expected_sources"]
        .as_array()
        .expect("expected source list")
        .iter()
        .map(|source| source.as_str().expect("source id").to_owned())
        .collect::<BTreeSet<_>>();
    let sources = input
        .iter()
        .map(|record| record["source"].as_str().expect("record source").to_owned())
        .collect::<BTreeSet<_>>();
    let missing_sources = expected_sources
        .difference(&sources)
        .cloned()
        .collect::<BTreeSet<_>>();
    let uncertain_sources = active
        .iter()
        .filter(|record| record["clock_uncertainty_s"].as_i64().unwrap_or_default() > 0)
        .map(|record| record["source"].as_str().expect("record source").to_owned())
        .collect::<BTreeSet<_>>();
    let has_missing_join_key = active
        .iter()
        .any(|record| record.get("join_key").and_then(Value::as_str).is_none());
    let active_claims = active
        .iter()
        .map(|record| record["claim"].as_str().expect("claim").to_owned())
        .collect::<BTreeSet<_>>();
    let relation = if !missing_sources.is_empty() {
        "missing"
    } else if !uncertain_sources.is_empty() {
        "uncertain"
    } else if has_missing_join_key {
        "insufficient"
    } else if active_claims.len() > 1 {
        "disagree"
    } else {
        "correlated"
    };

    Reduced {
        relation: relation.into(),
        sources,
        missing_sources,
        uncertain_sources,
        active_claims,
        history_length: history.len(),
    }
}

fn permutations(input: &[Value]) -> Vec<Vec<Value>> {
    fn visit(prefix: &mut Vec<Value>, remaining: &mut Vec<Value>, output: &mut Vec<Vec<Value>>) {
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

fn object(case: &Value) -> &Map<String, Value> {
    case.as_object().expect("relation case object")
}

#[test]
fn public_fixture_is_synthetic_and_covers_the_preflight_cases() {
    let value = fixture();
    assert_eq!(value["schema"], "netbraid.relation_preflight_fixture.v0");
    assert_eq!(value["privacy"], "PUBLIC_SYNTHETIC");
    let cases = value["cases"].as_array().expect("relation cases");
    assert_eq!(cases.len(), 5);
    assert_eq!(
        cases
            .iter()
            .map(|case| case["id"].as_str().expect("case id"))
            .collect::<Vec<_>>(),
        vec![
            "fresh_disagreement",
            "late_correction",
            "rotation_without_closure",
            "spectrum_clock_uncertainty",
            "health_without_station_link",
        ]
    );
}

#[test]
fn relation_oracle_is_stable_under_delivery_reordering_and_duplicate_delivery() {
    let cases = fixture()["cases"].as_array().unwrap().clone();
    for case in cases {
        let input = records(&case);
        let baseline = reduce(&case, &input);
        let expected = &case["expected"];
        assert_eq!(baseline.relation, expected["relation"]);
        assert_eq!(
            baseline.missing_sources,
            expected["missing_sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|source| source.as_str().unwrap().to_owned())
                .collect()
        );
        assert_eq!(
            baseline.uncertain_sources,
            expected["uncertain_sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|source| source.as_str().unwrap().to_owned())
                .collect()
        );
        let expected_sources = case["expected_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|source| source.as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert!(baseline
            .sources
            .iter()
            .all(|source| expected_sources.contains(source.as_str())));

        for permutation in permutations(&input) {
            assert_eq!(reduce(&case, &permutation), baseline);
        }
        let mut duplicate = input.clone();
        duplicate.push(input[0].clone());
        assert_eq!(reduce(&case, &duplicate), baseline);

        if let Some(corrected_claim) = expected.get("corrected_claim") {
            assert_eq!(
                baseline.active_claims,
                [corrected_claim.as_str().unwrap().to_owned()].into()
            );
            assert_eq!(baseline.history_length, expected["history_length"]);
        }
    }
}

#[test]
fn rotating_identifiers_without_a_join_key_remain_insufficient() {
    let value = fixture();
    let case = value["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["id"] == "rotation_without_closure")
        .unwrap();
    let result = reduce(case, &records(case));
    assert_eq!(result.relation, "insufficient");
    assert_eq!(result.active_claims, ["same-scene".to_owned()].into());
}

#[test]
fn health_and_spectrum_limits_remain_explicit() {
    let value = fixture();
    let cases = value["cases"].as_array().unwrap();
    let spectrum = cases
        .iter()
        .find(|case| case["id"] == "spectrum_clock_uncertainty")
        .unwrap();
    assert_eq!(reduce(spectrum, &records(spectrum)).relation, "uncertain");

    let health = cases
        .iter()
        .find(|case| case["id"] == "health_without_station_link")
        .unwrap();
    let health_record = &records(health)[0];
    assert_eq!(health_record["station_count"], 0);
    assert_eq!(reduce(health, &records(health)).relation, "missing");
}

#[test]
fn case_objects_are_closed_over_expected_fields() {
    for case in fixture()["cases"].as_array().unwrap() {
        let value = object(case);
        assert!(value.contains_key("id"));
        assert!(value.contains_key("expected_sources"));
        assert!(value.contains_key("records"));
        assert!(value.contains_key("expected"));
    }
}
