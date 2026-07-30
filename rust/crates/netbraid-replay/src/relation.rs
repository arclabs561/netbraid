//! Source-preserving relation reduction over already admitted observations.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

pub const RELATION_PROJECTION_SCHEMA_V0: &str = "netbraid.relation_projection.v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationRecordV0 {
    pub record_id: String,
    pub source: String,
    pub event_ts: i64,
    pub received_ts: i64,
    pub join_key: Option<String>,
    pub claim: String,
    #[serde(default)]
    pub supersedes: Option<String>,
    #[serde(default)]
    pub clock_uncertainty_s: u64,
    #[serde(default)]
    pub corrected_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationSourceStateV0 {
    ObservedFresh,
    ObservedStale,
    ObservedFuture,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationStateV0 {
    Correlated,
    Disagree,
    Uncertain,
    Missing,
    Insufficient,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelationProjectionV0 {
    pub schema: &'static str,
    pub relation: RelationStateV0,
    pub scope_key: Option<String>,
    pub source_ids: Vec<String>,
    pub source_states: BTreeMap<String, RelationSourceStateV0>,
    pub missing_sources: Vec<String>,
    pub stale_sources: Vec<String>,
    pub future_sources: Vec<String>,
    pub uncertain_sources: Vec<String>,
    pub active_record_ids: Vec<String>,
    pub history_record_ids: Vec<String>,
    pub active_claims: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelationError {
    InvalidFreshnessWindow(i64),
    EmptyExpectedSources,
    EmptyRecordId,
    EmptySource(String),
    EmptyClaim(String),
    UnexpectedSource(String),
    ConflictingRecordId(String),
    UnknownCorrection(String),
    CorrectionSourceMismatch(String),
    CorrectionScopeMismatch(String),
}

impl std::fmt::Display for RelationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidFreshnessWindow(value) => {
                write!(
                    formatter,
                    "freshness window must be non-negative, got {value}"
                )
            }
            Self::EmptyExpectedSources => write!(formatter, "expected source set is empty"),
            Self::EmptyRecordId => write!(formatter, "relation record_id is empty"),
            Self::EmptySource(record_id) => {
                write!(
                    formatter,
                    "relation record {record_id:?} has an empty source"
                )
            }
            Self::EmptyClaim(record_id) => {
                write!(
                    formatter,
                    "relation record {record_id:?} has an empty claim"
                )
            }
            Self::UnexpectedSource(source) => {
                write!(formatter, "relation source {source:?} was not expected")
            }
            Self::ConflictingRecordId(record_id) => {
                write!(formatter, "record_id {record_id:?} has conflicting content")
            }
            Self::UnknownCorrection(record_id) => {
                write!(
                    formatter,
                    "correction references unknown record {record_id:?}"
                )
            }
            Self::CorrectionSourceMismatch(record_id) => write!(
                formatter,
                "correction {record_id:?} changes the source of the superseded record"
            ),
            Self::CorrectionScopeMismatch(record_id) => write!(
                formatter,
                "correction {record_id:?} changes the scope of the superseded record"
            ),
        }
    }
}

impl std::error::Error for RelationError {}

/// Reduce one explicitly scoped relation without inferring identity.
///
/// Records with another non-null `join_key` belong to another scope and are
/// ignored. Records without a key remain in the selected scope but force an
/// `insufficient` result, so identifier rotation cannot become continuity.
pub fn reduce_relation_v0(
    records: impl IntoIterator<Item = RelationRecordV0>,
    expected_sources: impl IntoIterator<Item = String>,
    scope_key: Option<&str>,
    as_of_unix_s: i64,
    freshness_window_s: i64,
) -> Result<RelationProjectionV0, RelationError> {
    if freshness_window_s < 0 {
        return Err(RelationError::InvalidFreshnessWindow(freshness_window_s));
    }
    let expected_sources = expected_sources.into_iter().collect::<BTreeSet<_>>();
    if expected_sources.is_empty() {
        return Err(RelationError::EmptyExpectedSources);
    }

    let mut scoped = records
        .into_iter()
        .filter(|record| record.join_key.is_none() || record.join_key.as_deref() == scope_key)
        .collect::<Vec<_>>();
    scoped.sort_by(|left, right| {
        left.event_ts
            .cmp(&right.event_ts)
            .then_with(|| left.received_ts.cmp(&right.received_ts))
            .then_with(|| left.record_id.cmp(&right.record_id))
    });

    let mut active = BTreeMap::<String, RelationRecordV0>::new();
    let mut seen = BTreeMap::<String, RelationRecordV0>::new();
    let mut history_record_ids = Vec::new();
    for record in scoped.iter().cloned() {
        validate_record(&record, &expected_sources)?;
        if let Some(previous) = seen.get(&record.record_id) {
            if previous != &record {
                return Err(RelationError::ConflictingRecordId(record.record_id));
            }
            continue;
        }
        seen.insert(record.record_id.clone(), record.clone());
        history_record_ids.push(record.record_id.clone());

        let Some(superseded) = record.supersedes.clone() else {
            active.insert(record.record_id.clone(), record);
            continue;
        };
        let previous = active
            .get(&superseded)
            .ok_or_else(|| RelationError::UnknownCorrection(superseded.clone()))?;
        if previous.source != record.source {
            return Err(RelationError::CorrectionSourceMismatch(record.record_id));
        }
        if previous.join_key != record.join_key {
            return Err(RelationError::CorrectionScopeMismatch(record.record_id));
        }
        let mut corrected = record;
        corrected.record_id = superseded.clone();
        corrected.corrected_by = Some(history_record_ids.last().cloned().unwrap());
        active.insert(superseded, corrected);
    }

    let source_ids = scoped
        .iter()
        .map(|record| record.source.clone())
        .collect::<BTreeSet<_>>();
    let latest_by_source = active.values().fold(
        BTreeMap::<String, &RelationRecordV0>::new(),
        |mut latest, record| {
            let replace = latest.get(&record.source).is_none_or(|previous| {
                (record.event_ts, record.received_ts) > (previous.event_ts, previous.received_ts)
            });
            if replace {
                latest.insert(record.source.clone(), record);
            }
            latest
        },
    );
    let mut source_states = BTreeMap::new();
    for source in &expected_sources {
        let state = match latest_by_source.get(source) {
            None => RelationSourceStateV0::Missing,
            Some(record) if record.event_ts > as_of_unix_s => RelationSourceStateV0::ObservedFuture,
            Some(record) if as_of_unix_s - record.event_ts > freshness_window_s => {
                RelationSourceStateV0::ObservedStale
            }
            Some(_) => RelationSourceStateV0::ObservedFresh,
        };
        source_states.insert(source.clone(), state);
    }

    let missing_sources = sources_with_state(&source_states, RelationSourceStateV0::Missing);
    let stale_sources = sources_with_state(&source_states, RelationSourceStateV0::ObservedStale);
    let future_sources = sources_with_state(&source_states, RelationSourceStateV0::ObservedFuture);
    let uncertain_sources = latest_by_source
        .values()
        .filter(|record| record.clock_uncertainty_s > 0)
        .map(|record| record.source.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let active_claims = active
        .values()
        .map(|record| record.claim.clone())
        .collect::<BTreeSet<_>>();
    let unscoped_record = active.values().any(|record| record.join_key.is_none());
    let relation = if !missing_sources.is_empty() {
        RelationStateV0::Missing
    } else if !uncertain_sources.is_empty() {
        RelationStateV0::Uncertain
    } else if !stale_sources.is_empty() || !future_sources.is_empty() || unscoped_record {
        RelationStateV0::Insufficient
    } else if active_claims.len() > 1 {
        RelationStateV0::Disagree
    } else {
        RelationStateV0::Correlated
    };

    Ok(RelationProjectionV0 {
        schema: RELATION_PROJECTION_SCHEMA_V0,
        relation,
        scope_key: scope_key.map(str::to_owned),
        source_ids: source_ids.into_iter().collect(),
        source_states,
        missing_sources,
        stale_sources,
        future_sources,
        uncertain_sources,
        active_record_ids: active.keys().cloned().collect(),
        history_record_ids,
        active_claims: active_claims.into_iter().collect(),
    })
}

fn validate_record(
    record: &RelationRecordV0,
    expected_sources: &BTreeSet<String>,
) -> Result<(), RelationError> {
    if record.record_id.is_empty() {
        return Err(RelationError::EmptyRecordId);
    }
    if record.source.is_empty() {
        return Err(RelationError::EmptySource(record.record_id.clone()));
    }
    if record.claim.is_empty() {
        return Err(RelationError::EmptyClaim(record.record_id.clone()));
    }
    if !expected_sources.contains(&record.source) {
        return Err(RelationError::UnexpectedSource(record.source.clone()));
    }
    Ok(())
}

fn sources_with_state(
    source_states: &BTreeMap<String, RelationSourceStateV0>,
    state: RelationSourceStateV0,
) -> Vec<String> {
    source_states
        .iter()
        .filter(|(_, actual)| **actual == state)
        .map(|(source, _)| source.clone())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, source: &str, event_ts: i64, key: Option<&str>) -> RelationRecordV0 {
        RelationRecordV0 {
            record_id: id.into(),
            source: source.into(),
            event_ts,
            received_ts: event_ts,
            join_key: key.map(str::to_owned),
            claim: "claim".into(),
            supersedes: None,
            clock_uncertainty_s: 0,
            corrected_by: None,
        }
    }

    #[test]
    fn stale_and_future_sources_abstain() {
        let stale = reduce_relation_v0(
            [record("stale", "wifi", 900, Some("scope"))],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(stale.relation, RelationStateV0::Insufficient);
        assert_eq!(stale.stale_sources, ["wifi"]);

        let future = reduce_relation_v0(
            [record("future", "wifi", 1_001, Some("scope"))],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(future.relation, RelationStateV0::Insufficient);
        assert_eq!(future.future_sources, ["wifi"]);

        let at_future_boundary = reduce_relation_v0(
            [record("boundary", "wifi", 1_000, Some("scope"))],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(
            at_future_boundary.source_states["wifi"],
            RelationSourceStateV0::ObservedFresh
        );

        let at_stale_boundary = reduce_relation_v0(
            [record("boundary", "wifi", 970, Some("scope"))],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(
            at_stale_boundary.source_states["wifi"],
            RelationSourceStateV0::ObservedFresh
        );

        let at_zero_window_boundary = reduce_relation_v0(
            [record("zero-window", "wifi", 1_000, Some("scope"))],
            ["wifi".into()],
            Some("scope"),
            1_000,
            0,
        )
        .unwrap();
        assert_eq!(
            at_zero_window_boundary.source_states["wifi"],
            RelationSourceStateV0::ObservedFresh
        );

        assert!(matches!(
            reduce_relation_v0(
                [record("negative", "wifi", 1_000, Some("scope"))],
                ["wifi".into()],
                Some("scope"),
                1_000,
                -1,
            ),
            Err(RelationError::InvalidFreshnessWindow(-1))
        ));
    }

    #[test]
    fn other_scopes_do_not_create_a_relation() {
        let result = reduce_relation_v0(
            [
                record("scope-a", "wifi", 990, Some("a")),
                record("scope-b", "wifi", 991, Some("b")),
            ],
            ["wifi".into()],
            Some("a"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(result.relation, RelationStateV0::Correlated);
        assert_eq!(result.active_record_ids, ["scope-a"]);
    }

    #[test]
    fn latest_record_controls_freshness_and_uncertainty() {
        let result = reduce_relation_v0(
            [
                record("a-old", "wifi", 900, Some("scope")),
                record("z-new", "wifi", 990, Some("scope")),
            ],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert_eq!(
            result.source_states["wifi"],
            RelationSourceStateV0::ObservedFresh
        );

        let result = reduce_relation_v0(
            [
                record("a-clear", "wifi", 990, Some("scope")),
                RelationRecordV0 {
                    record_id: "z-uncertain".into(),
                    source: "wifi".into(),
                    event_ts: 990,
                    received_ts: 990,
                    join_key: Some("scope".into()),
                    claim: "claim".into(),
                    supersedes: None,
                    clock_uncertainty_s: 5,
                    corrected_by: None,
                },
            ],
            ["wifi".into()],
            Some("scope"),
            1_000,
            30,
        )
        .unwrap();
        assert!(result.uncertain_sources.is_empty());
    }

    #[test]
    fn invalid_records_fail_before_projection() {
        let mut invalid = record("invalid", "wifi", 990, Some("scope"));
        invalid.claim.clear();
        assert!(matches!(
            reduce_relation_v0([invalid], ["wifi".into()], Some("scope"), 1_000, 30,),
            Err(RelationError::EmptyClaim(_))
        ));
    }

    #[test]
    fn relation_errors_have_stable_operator_messages() {
        let cases = [
            (RelationError::EmptyExpectedSources, "expected source set"),
            (RelationError::EmptyRecordId, "record_id"),
            (RelationError::EmptySource("id".into()), "empty source"),
            (RelationError::EmptyClaim("id".into()), "empty claim"),
            (
                RelationError::UnexpectedSource("source".into()),
                "not expected",
            ),
            (
                RelationError::ConflictingRecordId("id".into()),
                "conflicting",
            ),
            (RelationError::UnknownCorrection("id".into()), "unknown"),
            (
                RelationError::CorrectionSourceMismatch("id".into()),
                "changes the source",
            ),
            (
                RelationError::CorrectionScopeMismatch("id".into()),
                "changes the scope",
            ),
        ];
        for (error, message) in cases {
            assert!(error.to_string().contains(message), "{error:?}");
        }
    }
}
