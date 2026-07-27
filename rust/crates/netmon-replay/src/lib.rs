//! Deterministic replay and pure reduction for experimental Netmon evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

mod conversation;
mod saved_capture;
mod triage;

pub use conversation::{
    reduce_capture_conversations, CaptureConversationKeyV0, CaptureConversationReportV0,
    CaptureConversationV0, ConversationDirectionV0, ConversationEndpointV0,
    ConversationExclusionReasonV0, IpFamilyV0, ObservationPointV0, TcpFlagCountsV0,
    TransportProtocolV0,
};
pub use netmon_evidence::{
    CollectionModeV0, CollectionPolicyV0, ContextKeyV0, CoverageStateV0, CoverageV0,
    HostPathObservationV0, HostPathV0, NetworkNameV0, NetworkNameVisibilityV0, ObservationOrderV0,
    SourceRefV0, ValidationError, HOST_PATH_SCHEMA_V0,
};
pub use saved_capture::{
    parse_saved_capture_jsonl, read_saved_capture_jsonl, SavedCaptureReadError,
    SavedCaptureRecordFamilyV0, SavedCaptureRecordStreamV0,
};
pub use triage::{
    project_saved_pcap_triage, SavedPcapClaimScopeV0, SavedPcapCompletenessV0,
    SavedPcapConversationAggregationV0, SavedPcapConversationDirectionV0,
    SavedPcapConversationEndpointV0, SavedPcapConversationExclusionCountV0,
    SavedPcapConversationExclusionReasonV0, SavedPcapConversationInsufficientReasonV0,
    SavedPcapConversationTriageV0, SavedPcapConversationUnsupportedReasonV0,
    SavedPcapEventWindowV0, SavedPcapNormalizationTriageV0, SavedPcapObservationPointV0,
    SavedPcapQuarantineReasonV0, SavedPcapQuarantineTriageV0, SavedPcapTcpFlagCountsV0,
    SavedPcapTemporalRelevanceV0, SavedPcapTopConversationV0, SavedPcapTransportProtocolV0,
    SavedPcapTriageProjectionError, SavedPcapTriageSourceV0, SavedPcapTriageV0,
    SavedPcapWlanDisconnectKindV0, SavedPcapWlanDisconnectV0, SavedPcapWlanInsufficientReasonV0,
    SavedPcapWlanTriageV0, SavedPcapWlanUnsupportedReasonV0, SAVED_PCAP_TRIAGE_SCHEMA_V0,
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

/// Whether prior exact key matches support a recurring network-context claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExactContextMatchV0 {
    NoPriorExactKeyMatch,
    /// Exact key equality exists, but the key contains no context anchor.
    UnanchoredExactKeyMatch,
    /// Exact key equality includes a gateway next-hop link-layer address.
    AnchoredExactRecurrence,
}

/// Whether the current attachment is corroborated by an exact prior key match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttachmentCorroborationV0 {
    /// The current BSSID or all exact prior BSSIDs are unavailable.
    NotObserved,
    /// Exact prior BSSID evidence exists, but not for the current BSSID.
    NotSeenBefore,
    /// The current BSSID appears in at least one exact prior key match.
    SeenBefore,
}

/// Observer-scoped recurrence evidence for one host-path observation.
///
/// Exact key matches use [`ContextKeyV0`] equality. They support an anchored
/// recurrence only when the key includes a gateway next-hop link-layer
/// address. Compatible records are reported separately because missing
/// evidence is not an equivalence relation and must not be transitively
/// clustered into a claimed context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextRecurrenceV0 {
    pub exact_context_match: ExactContextMatchV0,
    pub exact_prior_observations: usize,
    pub compatible_prior_observations: usize,
    pub first_exact_observation_unix_ms: Option<i64>,
    pub last_exact_observation_unix_ms: Option<i64>,
    pub distinct_prior_associated_bssids: usize,
    pub attachment_corroboration: AttachmentCorroborationV0,
}

/// A replay prefix read from a JSONL log with an explicit tail warning.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonlReadV0 {
    pub replay: ReplayStateV0,
    pub warning: Option<JsonlReadWarningV0>,
}

/// A recoverable condition confined to the final unterminated JSONL fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonlReadWarningV0 {
    UnterminatedMalformedRecord {
        line: usize,
        byte_offset: usize,
        fragment_bytes: usize,
    },
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
            Self::Json { line, source } => {
                write!(formatter, "invalid JSON on line {line}: {source}")
            }
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

pub fn summarize_context_recurrence(
    records: &[HostPathObservationV0],
    current: &HostPathObservationV0,
) -> ContextRecurrenceV0 {
    let current_key = current.context_key();
    let prior = records.iter().filter(|record| {
        record.source.observer_id == current.source.observer_id
            && record.record_id != current.record_id
            && (record.order < current.order
                || (record.order == current.order && record.record_id < current.record_id))
    });
    let mut exact_prior_observations = 0;
    let mut compatible_prior_observations = 0;
    let mut first_exact_observation_unix_ms = None;
    let mut last_exact_observation_unix_ms = None;
    let mut prior_bssids = BTreeSet::new();

    for record in prior {
        if record.context_key() == current_key {
            exact_prior_observations += 1;
            first_exact_observation_unix_ms = Some(
                first_exact_observation_unix_ms
                    .map_or(record.order.event_time_unix_ms, |first: i64| {
                        first.min(record.order.event_time_unix_ms)
                    }),
            );
            last_exact_observation_unix_ms = Some(
                last_exact_observation_unix_ms
                    .map_or(record.order.event_time_unix_ms, |last: i64| {
                        last.max(record.order.event_time_unix_ms)
                    }),
            );
            if let Some(bssid) = &record.path.associated_bssid {
                prior_bssids.insert(bssid.clone());
            }
        } else if contexts_are_compatible(record, current) {
            compatible_prior_observations += 1;
        }
    }

    let exact_context_match = if exact_prior_observations == 0 {
        ExactContextMatchV0::NoPriorExactKeyMatch
    } else if current.path.next_hop_link_address.is_some() {
        ExactContextMatchV0::AnchoredExactRecurrence
    } else {
        ExactContextMatchV0::UnanchoredExactKeyMatch
    };
    let attachment_corroboration = match (
        current.path.associated_bssid.as_ref(),
        prior_bssids.is_empty(),
    ) {
        (Some(bssid), false) if prior_bssids.contains(bssid) => {
            AttachmentCorroborationV0::SeenBefore
        }
        (Some(_), false) => AttachmentCorroborationV0::NotSeenBefore,
        _ => AttachmentCorroborationV0::NotObserved,
    };

    ContextRecurrenceV0 {
        exact_context_match,
        exact_prior_observations,
        compatible_prior_observations,
        first_exact_observation_unix_ms,
        last_exact_observation_unix_ms,
        distinct_prior_associated_bssids: prior_bssids.len(),
        attachment_corroboration,
    }
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
        record
            .validate()
            .map_err(|source| ReplayError::Invalid { line: 0, source })?;
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
        .map(|(index, current)| {
            compare_contexts(index.checked_sub(1).map(|i| &records[i]), current)
        })
        .collect();
    Ok(ReplayStateV0 {
        records,
        transitions,
    })
}

pub fn read_jsonl(path: impl AsRef<Path>) -> Result<ReplayStateV0, ReplayError> {
    Ok(read_jsonl_bytes(&fs::read(path)?, false)?.replay)
}

/// Reads the valid replay prefix while explicitly warning about an interrupted
/// final record.
///
/// Only a malformed final fragment without a terminating newline is
/// recoverable. Malformed internal records, newline-terminated malformed
/// records, and invalid evidence remain errors.
pub fn read_jsonl_recovering_tail(path: impl AsRef<Path>) -> Result<JsonlReadV0, ReplayError> {
    read_jsonl_bytes(&fs::read(path)?, true)
}

fn read_jsonl_bytes(
    bytes: &[u8],
    recover_unterminated_tail: bool,
) -> Result<JsonlReadV0, ReplayError> {
    let mut records = Vec::new();
    let has_unterminated_tail = !bytes.is_empty() && !bytes.ends_with(b"\n");
    let final_fragment_index = bytes.split(|byte| *byte == b'\n').count() - 1;
    let mut byte_offset = 0;

    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        let line_number = index + 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            byte_offset += line.len() + usize::from(index != final_fragment_index);
            continue;
        }
        let value: serde_json::Value = match serde_json::from_slice(line) {
            Ok(value) => value,
            Err(_)
                if recover_unterminated_tail
                    && has_unterminated_tail
                    && index == final_fragment_index =>
            {
                return Ok(JsonlReadV0 {
                    replay: replay(records)?,
                    warning: Some(JsonlReadWarningV0::UnterminatedMalformedRecord {
                        line: line_number,
                        byte_offset,
                        fragment_bytes: line.len(),
                    }),
                });
            }
            Err(source) => {
                return Err(ReplayError::Json {
                    line: line_number,
                    source,
                });
            }
        };
        let record: HostPathObservationV0 =
            serde_json::from_value(value).map_err(|source| ReplayError::Json {
                line: line_number,
                source,
            })?;
        record.validate().map_err(|source| ReplayError::Invalid {
            line: line_number,
            source,
        })?;
        records.push(record);
        byte_offset += line.len() + usize::from(index != final_fragment_index);
    }
    Ok(JsonlReadV0 {
        replay: replay(records)?,
        warning: None,
    })
}

/// Appends one canonical record to a JSONL log.
///
/// Existing content is parsed strictly before the append, so a corrupt tail is
/// never silently extended. This is a fail-closed preflight, not cross-process
/// locking; callers must keep one writer per log.
pub fn append_jsonl(
    path: impl AsRef<Path>,
    record: &HostPathObservationV0,
) -> Result<(), ReplayError> {
    let path = path.as_ref();
    let mut record = record.clone();
    record.canonicalize();
    record
        .validate()
        .map_err(|source| ReplayError::Invalid { line: 0, source })?;

    let existing = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(source) => return Err(source.into()),
    };
    if !existing.is_empty() {
        read_jsonl_bytes(&existing, false)?;
    }

    let mut serialized = serialize_jsonl_record(&record)?;
    if !existing.is_empty() && !existing.ends_with(b"\n") {
        serialized.insert(0, b'\n');
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    file.write_all(&serialized)?;
    file.flush()?;
    Ok(())
}

fn serialize_jsonl_record(record: &HostPathObservationV0) -> Result<Vec<u8>, ReplayError> {
    let mut serialized =
        serde_json::to_vec(record).map_err(|source| ReplayError::Json { line: 0, source })?;
    serialized.push(b'\n');
    Ok(serialized)
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

        assert_eq!(comparison.relation, ContextRelationV0::CompatibleContext);
        assert!(comparison
            .changed_dimensions
            .contains(&"next_hop_link_address"));
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

    #[test]
    fn append_serializes_one_canonical_newline_terminated_record() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut record = observation("first", 1, "house");
        record.path.resolvers = vec![
            "192.0.2.54".into(),
            "192.0.2.53".into(),
            "192.0.2.53".into(),
        ];
        let mut canonical = record.clone();
        canonical.canonicalize();

        append_jsonl(&path, &record).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(bytes, serialize_jsonl_record(&canonical).unwrap());
        assert_eq!(bytes.iter().filter(|byte| **byte == b'\n').count(), 1);
        assert!(bytes.ends_with(b"\n"));
    }

    #[test]
    fn strict_and_recovering_reads_accept_valid_final_json_without_newline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut bytes = serialize_jsonl_record(&observation("first", 1, "house")).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        std::fs::write(&path, bytes).unwrap();

        let strict = read_jsonl(&path).unwrap();
        let recovering = read_jsonl_recovering_tail(&path).unwrap();

        assert_eq!(strict.records.len(), 1);
        assert_eq!(recovering.replay, strict);
        assert_eq!(recovering.warning, None);
    }

    #[test]
    fn recovering_read_warns_about_malformed_unterminated_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let first = serialize_jsonl_record(&observation("first", 1, "house")).unwrap();
        let mut bytes = first.clone();
        bytes.extend_from_slice(br#"{"schema":"netmon.host_path_observation.v0""#);
        std::fs::write(&path, &bytes).unwrap();

        assert!(matches!(
            read_jsonl(&path),
            Err(ReplayError::Json { line: 2, .. })
        ));
        let recovering = read_jsonl_recovering_tail(&path).unwrap();

        assert_eq!(recovering.replay.records.len(), 1);
        assert_eq!(
            recovering.warning,
            Some(JsonlReadWarningV0::UnterminatedMalformedRecord {
                line: 2,
                byte_offset: first.len(),
                fragment_bytes: bytes.len() - first.len(),
            })
        );
    }

    #[test]
    fn recovering_read_rejects_malformed_internal_line() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut bytes = serialize_jsonl_record(&observation("first", 1, "house")).unwrap();
        bytes.extend_from_slice(b"{malformed}\n");
        bytes.extend_from_slice(
            &serialize_jsonl_record(&observation("second", 2, "house")).unwrap(),
        );
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            read_jsonl_recovering_tail(&path),
            Err(ReplayError::Json { line: 2, .. })
        ));
    }

    #[test]
    fn recovering_read_rejects_complete_invalid_final_record_without_newline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut invalid = observation("invalid", 1, "house");
        invalid.schema = "unsupported".into();
        let mut bytes = serialize_jsonl_record(&invalid).unwrap();
        assert_eq!(bytes.pop(), Some(b'\n'));
        std::fs::write(&path, bytes).unwrap();

        assert!(matches!(
            read_jsonl_recovering_tail(&path),
            Err(ReplayError::Invalid { line: 1, .. })
        ));
    }

    #[test]
    fn append_inserts_one_separator_after_valid_final_json_without_newline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut first = serialize_jsonl_record(&observation("first", 1, "house")).unwrap();
        assert_eq!(first.pop(), Some(b'\n'));
        std::fs::write(&path, &first).unwrap();

        let second = observation("second", 2, "house");
        append_jsonl(&path, &second).unwrap();

        let mut expected = first;
        expected.push(b'\n');
        expected.extend_from_slice(&serialize_jsonl_record(&second).unwrap());
        assert_eq!(std::fs::read(&path).unwrap(), expected);
        assert_eq!(read_jsonl(&path).unwrap().records.len(), 2);
    }

    #[test]
    fn append_refuses_and_preserves_a_corrupt_tail() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("evidence.jsonl");
        let mut corrupt = serialize_jsonl_record(&observation("first", 1, "house")).unwrap();
        corrupt.extend_from_slice(b"{");
        std::fs::write(&path, &corrupt).unwrap();

        assert!(matches!(
            append_jsonl(&path, &observation("second", 2, "house")),
            Err(ReplayError::Json { line: 2, .. })
        ));
        assert_eq!(std::fs::read(&path).unwrap(), corrupt);
    }

    #[test]
    fn recurrence_keeps_exact_and_compatible_evidence_separate() {
        let exact = observation("exact", 1, "house");
        let mut incomplete = observation("incomplete", 2, "house");
        incomplete.path.next_hop_link_address = None;
        let current = observation("current", 3, "house");

        let summary = summarize_context_recurrence(&[exact, incomplete, current.clone()], &current);

        assert_eq!(
            summary.exact_context_match,
            ExactContextMatchV0::AnchoredExactRecurrence
        );
        assert_eq!(summary.exact_prior_observations, 1);
        assert_eq!(summary.compatible_prior_observations, 1);
        assert_eq!(summary.first_exact_observation_unix_ms, Some(1));
        assert_eq!(summary.last_exact_observation_unix_ms, Some(1));
    }

    #[test]
    fn recurrence_distinguishes_known_and_new_attachment_variants() {
        let first = observation("first", 1, "house");
        let second = observation("second", 2, "house");
        let mut known = observation("known", 3, "house");
        known.path.associated_bssid = first.path.associated_bssid.clone();
        let mut new = observation("new", 4, "house");
        new.path.associated_bssid = Some("02:00:00:00:00:ff".into());

        let known_summary = summarize_context_recurrence(&[first.clone(), second.clone()], &known);
        let new_summary = summarize_context_recurrence(&[first, second], &new);

        assert_eq!(known_summary.distinct_prior_associated_bssids, 2);
        assert_eq!(
            known_summary.attachment_corroboration,
            AttachmentCorroborationV0::SeenBefore
        );
        assert_eq!(new_summary.distinct_prior_associated_bssids, 2);
        assert_eq!(
            new_summary.attachment_corroboration,
            AttachmentCorroborationV0::NotSeenBefore
        );
    }

    #[test]
    fn recurrence_abstains_without_prior_attachment_evidence() {
        let mut prior = observation("prior", 1, "house");
        prior.path.associated_bssid = None;
        let current = observation("current", 2, "house");

        let summary = summarize_context_recurrence(&[prior], &current);

        assert_eq!(summary.exact_prior_observations, 1);
        assert_eq!(summary.distinct_prior_associated_bssids, 0);
        assert_eq!(
            summary.attachment_corroboration,
            AttachmentCorroborationV0::NotObserved
        );
    }

    #[test]
    fn exact_missing_values_are_an_unanchored_key_match() {
        let mut prior = observation("prior", 1, "house");
        prior.path.next_hop_link_address = None;
        prior.path.associated_bssid = None;
        let mut current = observation("current", 2, "house");
        current.path.next_hop_link_address = None;
        current.path.associated_bssid = None;

        let summary = summarize_context_recurrence(&[prior], &current);

        assert_eq!(summary.exact_prior_observations, 1);
        assert_eq!(
            summary.exact_context_match,
            ExactContextMatchV0::UnanchoredExactKeyMatch
        );
        assert_eq!(
            summary.attachment_corroboration,
            AttachmentCorroborationV0::NotObserved
        );
    }

    #[test]
    fn repeated_bssid_corroborates_but_does_not_anchor_context() {
        let mut prior = observation("prior", 1, "house");
        prior.path.next_hop_link_address = None;
        let mut current = observation("current", 2, "house");
        current.path.next_hop_link_address = None;
        current.path.associated_bssid = prior.path.associated_bssid.clone();

        let summary = summarize_context_recurrence(&[prior], &current);

        assert_eq!(
            summary.exact_context_match,
            ExactContextMatchV0::UnanchoredExactKeyMatch
        );
        assert_eq!(
            summary.attachment_corroboration,
            AttachmentCorroborationV0::SeenBefore
        );
    }

    #[test]
    fn recurrence_uses_replay_id_order_when_timestamps_tie() {
        let prior = observation("a-prior", 1, "house");
        let mut current = observation("z-current", 2, "house");
        current.order = prior.order.clone();

        let summary = summarize_context_recurrence(&[prior], &current);

        assert_eq!(summary.exact_prior_observations, 1);
    }

    #[test]
    fn recurrence_reports_when_no_prior_exact_key_match_exists() {
        let current = observation("current", 1, "house");

        let summary = summarize_context_recurrence(&[], &current);

        assert_eq!(summary.exact_prior_observations, 0);
        assert_eq!(
            summary.exact_context_match,
            ExactContextMatchV0::NoPriorExactKeyMatch
        );
    }
}
