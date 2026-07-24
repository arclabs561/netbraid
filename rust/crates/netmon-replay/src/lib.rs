//! Deterministic replay for experimental Netmon host-path evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

pub use netmon_evidence::{
    CollectionModeV0, CollectionPolicyV0, ContextKeyV0, CoverageStateV0, CoverageV0,
    HOST_PATH_SCHEMA_V0, HostPathObservationV0, HostPathV0, NetworkNameV0,
    NetworkNameVisibilityV0, ObservationOrderV0, SourceRefV0, ValidationError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextRelationV0 {
    FirstObservation,
    SameContext,
    CompatibleContext,
    ContextChanged,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextComparisonV0 {
    pub relation: ContextRelationV0,
    pub changed_dimensions: Vec<&'static str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayStateV0 {
    pub records: Vec<HostPathObservationV0>,
    pub transitions: Vec<ContextComparisonV0>,
}

#[derive(Debug)]
pub enum ReplayError {
    Io(io::Error),
    Json {
        line: usize,
        source: serde_json::Error,
    },
    Invalid {
        line: usize,
        source: ValidationError,
    },
    ConflictingRecordId(String),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
            Self::Json { line, source } => write!(formatter, "invalid JSON on line {line}: {source}"),
            Self::Invalid { line, source } => {
                write!(formatter, "invalid evidence on line {line}: {source}")
            }
            Self::ConflictingRecordId(record_id) => {
                write!(formatter, "record_id {record_id:?} has conflicting content")
            }
        }
    }
}

impl std::error::Error for ReplayError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Json { source, .. } => Some(source),
            Self::Invalid { source, .. } => Some(source),
            Self::ConflictingRecordId(_) => None,
        }
    }
}

impl From<io::Error> for ReplayError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

pub fn compare_contexts(
    previous: Option<&HostPathObservationV0>,
    current: &HostPathObservationV0,
) -> ContextComparisonV0 {
    let Some(previous) = previous else {
        return ContextComparisonV0 {
            relation: ContextRelationV0::FirstObservation,
            changed_dimensions: Vec::new(),
        };
    };

    let mut changed = Vec::new();
    if previous.path.interface != current.path.interface {
        changed.push("interface");
    }
    if previous.path.link_type != current.path.link_type {
        changed.push("link_type");
    }
    if previous.path.network_name != current.path.network_name {
        changed.push("network_name");
    }
    if previous.path.association_id != current.path.association_id {
        changed.push("association");
    }
    if previous.path.associated_bssid != current.path.associated_bssid {
        changed.push("associated_bssid");
    }
    if previous.path.next_hop != current.path.next_hop {
        changed.push("next_hop");
    }
    if previous.path.next_hop_link_address != current.path.next_hop_link_address {
        changed.push("next_hop_link_address");
    }
    if canonical_set(&previous.path.resolvers) != canonical_set(&current.path.resolvers) {
        changed.push("resolvers");
    }
    if canonical_set(&previous.path.address_prefixes)
        != canonical_set(&current.path.address_prefixes)
    {
        changed.push("address_prefixes");
    }
    let relation = if previous.context_key() == current.context_key() {
        ContextRelationV0::SameContext
    } else if contexts_are_compatible(previous, current) {
        ContextRelationV0::CompatibleContext
    } else {
        ContextRelationV0::ContextChanged
    };
    ContextComparisonV0 {
        relation,
        changed_dimensions: changed,
    }
}

pub fn contexts_are_compatible(
    previous: &HostPathObservationV0,
    current: &HostPathObservationV0,
) -> bool {
    !optional_conflicts(&previous.path.link_type, &current.path.link_type)
        && !network_names_conflict(&previous.path.network_name, &current.path.network_name)
        && !optional_conflicts(&previous.path.next_hop, &current.path.next_hop)
        && !optional_conflicts(
            &previous.path.next_hop_link_address,
            &current.path.next_hop_link_address,
        )
        && !sets_conflict(&previous.path.resolvers, &current.path.resolvers)
        && !sets_conflict(
            &previous.path.address_prefixes,
            &current.path.address_prefixes,
        )
}

fn optional_conflicts<T: PartialEq>(previous: &Option<T>, current: &Option<T>) -> bool {
    matches!((previous, current), (Some(previous), Some(current)) if previous != current)
}

fn network_names_conflict(previous: &NetworkNameV0, current: &NetworkNameV0) -> bool {
    matches!(
        (
            previous.visibility,
            previous.value.as_deref(),
            current.visibility,
            current.value.as_deref(),
        ),
        (
            NetworkNameVisibilityV0::Observed,
            Some(previous),
            NetworkNameVisibilityV0::Observed,
            Some(current),
        ) if previous != current
    )
}

fn sets_conflict(previous: &[String], current: &[String]) -> bool {
    !previous.is_empty() && !current.is_empty() && canonical_set(previous) != canonical_set(current)
}

pub fn replay(
    records: impl IntoIterator<Item = HostPathObservationV0>,
) -> Result<ReplayStateV0, ReplayError> {
    let mut by_id = BTreeMap::new();
    for mut record in records {
        record.canonicalize();
        record.validate().map_err(|source| ReplayError::Invalid {
            line: 0,
            source,
        })?;
        if let Some(previous) = by_id.get(&record.record_id) {
            if previous != &record {
                return Err(ReplayError::ConflictingRecordId(record.record_id));
            }
            continue;
        }
        by_id.insert(record.record_id.clone(), record);
    }
    let mut records: Vec<_> = by_id.into_values().collect();
    records.sort_by(|left, right| {
        left.order
            .cmp(&right.order)
            .then_with(|| left.source.observer_id.cmp(&right.source.observer_id))
            .then_with(|| left.record_id.cmp(&right.record_id))
    });
    let transitions = records
        .iter()
        .enumerate()
        .map(|(index, current)| compare_contexts(index.checked_sub(1).map(|i| &records[i]), current))
        .collect();
    Ok(ReplayStateV0 {
        records,
        transitions,
    })
}

pub fn read_jsonl(path: impl AsRef<Path>) -> Result<ReplayStateV0, ReplayError> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut records = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line_number = index + 1;
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let record: HostPathObservationV0 =
            serde_json::from_str(&line).map_err(|source| ReplayError::Json {
                line: line_number,
                source,
            })?;
        record
            .validate()
            .map_err(|source| ReplayError::Invalid {
                line: line_number,
                source,
            })?;
        records.push(record);
    }
    replay(records)
}

pub fn append_jsonl(
    path: impl AsRef<Path>,
    record: &HostPathObservationV0,
) -> Result<(), ReplayError> {
    let mut record = record.clone();
    record.canonicalize();
    record
        .validate()
        .map_err(|source| ReplayError::Invalid { line: 0, source })?;
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, &record).map_err(|source| ReplayError::Json {
        line: 0,
        source,
    })?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn canonical_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(id: &str, sequence: u64, network: &str) -> HostPathObservationV0 {
        HostPathObservationV0 {
            schema: HOST_PATH_SCHEMA_V0.into(),
            record_id: id.into(),
            order: ObservationOrderV0 {
                event_time_unix_ms: sequence as i64,
                acquired_time_unix_ms: sequence as i64,
                source_sequence: sequence,
            },
            source: SourceRefV0 {
                observer_id: "host".into(),
                adapter: "linktop".into(),
                adapter_version: "0.1.0".into(),
            },
            policy: CollectionPolicyV0::passive_host_local(),
            coverage: CoverageV0 {
                state: CoverageStateV0::Complete,
                observed_sources: vec!["route".into()],
                missing_sources: Vec::new(),
            },
            path: HostPathV0 {
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                network_name: NetworkNameV0 {
                    visibility: NetworkNameVisibilityV0::Observed,
                    value: Some(network.into()),
                },
                association_id: Some(format!("association-{sequence}")),
                associated_bssid: Some(format!("02:00:00:00:00:{sequence:02x}")),
                next_hop: Some("192.0.2.1".into()),
                next_hop_link_address: Some("02:00:00:00:01:01".into()),
                resolvers: vec!["192.0.2.53".into()],
                address_prefixes: vec!["192.0.2.7".into()],
            },
        }
    }

    #[test]
    fn replay_is_ordered_deduplicated_and_deterministic() {
        let second = observation("second", 2, "house");
        let first = observation("first", 1, "house");
        let once = replay(vec![second.clone(), first.clone(), first]).unwrap();
        let twice = replay(once.records.clone()).unwrap();

        assert_eq!(once, twice);
        assert_eq!(once.records.len(), 2);
        assert_eq!(once.records[0].record_id, "first");
    }

    #[test]
    fn association_change_is_same_context_but_still_visible() {
        let first = observation("first", 1, "house");
        let second = observation("second", 2, "house");
        let comparison = compare_contexts(Some(&first), &second);

        assert_eq!(comparison.relation, ContextRelationV0::SameContext);
        assert_eq!(
            comparison.changed_dimensions,
            vec!["association", "associated_bssid"]
        );
    }

    #[test]
    fn newly_observed_gateway_binding_is_compatible_not_a_context_change() {
        let mut first = observation("first", 1, "house");
        first.path.next_hop_link_address = None;
        let second = observation("second", 2, "house");
        let comparison = compare_contexts(Some(&first), &second);

        assert_eq!(
            comparison.relation,
            ContextRelationV0::CompatibleContext
        );
        assert!(
            comparison
                .changed_dimensions
                .contains(&"next_hop_link_address")
        );
    }

    #[test]
    fn different_observed_gateway_bindings_are_a_context_change() {
        let first = observation("first", 1, "house");
        let mut second = observation("second", 2, "house");
        second.path.next_hop_link_address = Some("02:00:00:00:02:01".into());
        let comparison = compare_contexts(Some(&first), &second);

        assert_eq!(comparison.relation, ContextRelationV0::ContextChanged);
    }

    #[test]
    fn network_name_change_is_a_context_change() {
        let first = observation("first", 1, "house");
        let second = observation("second", 2, "hotspot");
        let comparison = compare_contexts(Some(&first), &second);

        assert_eq!(comparison.relation, ContextRelationV0::ContextChanged);
        assert_eq!(
            comparison.changed_dimensions,
            vec!["network_name", "association", "associated_bssid"]
        );
    }

    #[test]
    fn conflicting_duplicate_id_fails_closed() {
        let first = observation("same", 1, "house");
        let second = observation("same", 2, "hotspot");

        assert!(matches!(
            replay(vec![first, second]),
            Err(ReplayError::ConflictingRecordId(id)) if id == "same"
        ));
    }

    #[test]
    fn appended_jsonl_replays_the_same_on_repeated_reads() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        append_jsonl(&path, &observation("first", 1, "house")).unwrap();
        append_jsonl(&path, &observation("second", 2, "hotspot")).unwrap();

        let first = read_jsonl(&path).unwrap();
        let second = read_jsonl(&path).unwrap();

        assert_eq!(first, second);
        assert_eq!(first.records.len(), 2);
        assert_eq!(
            first.transitions[1].relation,
            ContextRelationV0::ContextChanged
        );
    }
}
