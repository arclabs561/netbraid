//! Packet-shape fingerprint candidate v1.
//!
//! The v1 basis is the v0 basis without the operator's packet limit and
//! without absolute event times. Two complete captures of the same exchange
//! taken with different `--packet-limit` values (neither reached), or by
//! observers whose clocks differ, have the same v1 digest; v0 reports them as
//! different packet shapes. Durations (`observed_span_ns`) and
//! `packet_limit_reached` remain features.
//!
//! v0 is unchanged. Candidates of the two schemas are separate types and are
//! never comparable with each other.

use serde::{Deserialize, Serialize};

use crate::evidence::NormalizationStateV0;
use crate::replay::fingerprint::schema_digest;
use crate::replay::{
    project_saved_pcap_fingerprint_v0, SavedPcapClaimScopeV0, SavedPcapCompletenessV0,
    SavedPcapConversationAggregationV0, SavedPcapConversationDirectionV0,
    SavedPcapConversationExclusionCountV0, SavedPcapEventWindowV0,
    SavedPcapFingerprintComparisonReasonV0, SavedPcapFingerprintComparisonV0,
    SavedPcapFingerprintConversationV0, SavedPcapFingerprintInsufficientReasonV0,
    SavedPcapFingerprintSourceV0, SavedPcapFingerprintStatusV0,
    SavedPcapFingerprintUnsupportedReasonV0, SavedPcapNormalizationTriageV0,
    SavedPcapObservationPointV0, SavedPcapTemporalRelevanceV0, SavedPcapTransportProtocolV0,
    SavedPcapTriageV1, SavedPcapWlanDisconnectKindV0, SavedPcapWlanInsufficientReasonV0,
    SavedPcapWlanTriageV0, SavedPcapWlanUnsupportedReasonV0,
};

pub const SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V1: &str =
    "netmon.saved_pcap_fingerprint_candidate.v1";

const FINGERPRINT_CAVEATS_V1: &[&str] = &[
    "capture-wide aggregate over eligible normalized packet envelopes; not sessionized",
    "endpoint addresses and ports are excluded from the comparison digest",
    "absolute event times and the normalization packet limit are excluded from the comparison digest; durations and whether the limit was reached remain",
    "no cross-observer join or device, person, place, or intent identity",
    "missing radiotap, CSI, and BLE evidence remains outside this packet-shape candidate",
];

const FINGERPRINT_FEATURE_NAMES_V1: &[&str] = &[
    "normalization.state",
    "normalization.completeness",
    "normalization.packet_rows_emitted",
    "normalization.packet_rows_quarantined",
    "normalization.packet_rows_inspected",
    "normalization.packet_limit_reached",
    "normalization.emitted_packet_span",
    "wlan",
    "conversation.aggregation",
    "conversation.temporal_relevance",
    "conversation.transport",
    "conversation.observation_point",
    "conversation.packet_envelopes_seen",
    "conversation.packet_envelopes_grouped",
    "conversation.packet_envelopes_excluded",
    "conversation.exclusions",
    "conversation.total_frames",
    "conversation.total_original_frame_octets",
    "conversation.total_captured_frame_octets",
    "conversation.a_to_b",
    "conversation.b_to_a",
    "conversation.observed_span_ns",
];

/// Observation count and duration of an event window, without its absolute
/// start and end times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintEventSpanV1 {
    pub observations: u64,
    pub observed_span_ns: u64,
}

impl From<&SavedPcapEventWindowV0> for SavedPcapFingerprintEventSpanV1 {
    fn from(window: &SavedPcapEventWindowV0) -> Self {
        Self {
            observations: window.observations,
            observed_span_ns: window.observed_span_ns,
        }
    }
}

/// Normalization features of a v1 candidate: no packet limit, no absolute
/// emitted-packet window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintNormalizationV1 {
    pub state: NormalizationStateV0,
    pub completeness: SavedPcapCompletenessV0,
    pub packet_rows_emitted: u64,
    pub packet_rows_quarantined: u64,
    pub packet_rows_inspected: u64,
    pub packet_limit_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_packet_span: Option<SavedPcapFingerprintEventSpanV1>,
}

/// One WLAN disconnect kind with its span instead of its absolute window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintWlanDisconnectV1 {
    pub kind: SavedPcapWlanDisconnectKindV0,
    pub event_span: SavedPcapFingerprintEventSpanV1,
}

/// WLAN triage features of a v1 candidate, without absolute event times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapFingerprintWlanV1 {
    Insufficient {
        scope: SavedPcapClaimScopeV0,
        reason: SavedPcapWlanInsufficientReasonV0,
    },
    Unsupported {
        scope: SavedPcapClaimScopeV0,
        reason: SavedPcapWlanUnsupportedReasonV0,
    },
    NotObserved {
        scope: SavedPcapClaimScopeV0,
        wlan_span: SavedPcapFingerprintEventSpanV1,
    },
    Observed {
        scope: SavedPcapClaimScopeV0,
        wlan_span: SavedPcapFingerprintEventSpanV1,
        disconnects: Vec<SavedPcapFingerprintWlanDisconnectV1>,
    },
}

/// The endpoint- and clock-independent packet-shape portion of a top
/// conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintConversationV1 {
    pub aggregation: SavedPcapConversationAggregationV0,
    pub temporal_relevance: SavedPcapTemporalRelevanceV0,
    pub transport: SavedPcapTransportProtocolV0,
    pub observation_point: SavedPcapObservationPointV0,
    pub packet_envelopes_seen: u64,
    pub packet_envelopes_grouped: u64,
    pub packet_envelopes_excluded: u64,
    pub exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    pub total_frames: u64,
    pub total_original_frame_octets: u64,
    pub total_captured_frame_octets: u64,
    pub a_to_b: SavedPcapConversationDirectionV0,
    pub b_to_a: SavedPcapConversationDirectionV0,
    pub observed_span_ns: u64,
}

/// The feature values that participate in a v1 observed candidate's digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintBasisV1 {
    pub feature_names: Vec<String>,
    pub normalization: SavedPcapFingerprintNormalizationV1,
    pub wlan: SavedPcapFingerprintWlanV1,
    pub conversation: SavedPcapFingerprintConversationV1,
}

/// The result of reducing a validated triage projection to a v1 candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapFingerprintStatusV1 {
    Observed {
        digest: String,
        basis: Box<SavedPcapFingerprintBasisV1>,
        caveats: Vec<String>,
    },
    Insufficient {
        reason: SavedPcapFingerprintInsufficientReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
    Unsupported {
        reason: SavedPcapFingerprintUnsupportedReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
}

/// A v1 endpoint- and clock-independent candidate for multi-vantage
/// comparison.
///
/// This is derived evidence, not an identity claim. Only the `Observed`
/// variant carries a digest; partial and unsupported inputs remain typed
/// abstentions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintCandidateV1 {
    pub schema: String,
    pub source: SavedPcapFingerprintSourceV0,
    pub scope: SavedPcapClaimScopeV0,
    pub status: SavedPcapFingerprintStatusV1,
}

/// Projects one validated triage result into a v1 packet-shape candidate.
///
/// Same inputs, scope, and abstentions as
/// [`project_saved_pcap_fingerprint_v0`]; the observed basis drops the packet
/// limit and absolute event times.
pub fn project_saved_pcap_fingerprint_v1(
    triage: &SavedPcapTriageV1,
) -> SavedPcapFingerprintCandidateV1 {
    let v0 = project_saved_pcap_fingerprint_v0(triage);
    let status = match v0.status {
        SavedPcapFingerprintStatusV0::Observed { basis, .. } => {
            let basis = SavedPcapFingerprintBasisV1 {
                feature_names: FINGERPRINT_FEATURE_NAMES_V1
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                normalization: normalization_v1(&basis.normalization),
                wlan: wlan_v1(&basis.wlan),
                conversation: conversation_v1(basis.conversation),
            };
            SavedPcapFingerprintStatusV1::Observed {
                digest: schema_digest(SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V1, &basis),
                basis: Box::new(basis),
                caveats: FINGERPRINT_CAVEATS_V1
                    .iter()
                    .map(|caveat| (*caveat).to_owned())
                    .collect(),
            }
        }
        SavedPcapFingerprintStatusV0::Insufficient {
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => SavedPcapFingerprintStatusV1::Insufficient {
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        },
        SavedPcapFingerprintStatusV0::Unsupported {
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => SavedPcapFingerprintStatusV1::Unsupported {
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        },
    };
    SavedPcapFingerprintCandidateV1 {
        schema: SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V1.to_owned(),
        source: v0.source,
        scope: v0.scope,
        status,
    }
}

/// Compares two v1 candidates with the v0 comparison rules.
///
/// Candidates are comparable only when their schema, claim scope, and feature
/// set match and both carry an observed digest that matches its basis. A
/// missing or unsupported candidate is reported as `NotComparable`, not as
/// disagreement.
pub fn compare_saved_pcap_fingerprints_v1(
    left: &SavedPcapFingerprintCandidateV1,
    right: &SavedPcapFingerprintCandidateV1,
) -> SavedPcapFingerprintComparisonV0 {
    let not_comparable = |reason| SavedPcapFingerprintComparisonV0::NotComparable { reason };
    if left.schema != right.schema {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::DifferentSchema);
    }
    if left.scope != right.scope {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::DifferentClaimScope);
    }
    let SavedPcapFingerprintStatusV1::Observed {
        digest: left_digest,
        basis: left_basis,
        ..
    } = &left.status
    else {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::LeftNotObserved);
    };
    let SavedPcapFingerprintStatusV1::Observed {
        digest: right_digest,
        basis: right_basis,
        ..
    } = &right.status
    else {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::RightNotObserved);
    };
    if left_basis.feature_names != right_basis.feature_names {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::DifferentFeatureSet);
    }
    if left_digest != &schema_digest(SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V1, left_basis)
        || right_digest != &schema_digest(SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V1, right_basis)
    {
        return not_comparable(SavedPcapFingerprintComparisonReasonV0::InvalidDigest);
    }
    if left_basis == right_basis {
        SavedPcapFingerprintComparisonV0::Corroborated
    } else {
        SavedPcapFingerprintComparisonV0::Conflicting
    }
}

fn normalization_v1(
    normalization: &SavedPcapNormalizationTriageV0,
) -> SavedPcapFingerprintNormalizationV1 {
    SavedPcapFingerprintNormalizationV1 {
        state: normalization.state,
        completeness: normalization.completeness,
        packet_rows_emitted: normalization.packet_rows_emitted,
        packet_rows_quarantined: normalization.packet_rows_quarantined,
        packet_rows_inspected: normalization.packet_rows_inspected,
        packet_limit_reached: normalization.packet_limit_reached,
        emitted_packet_span: normalization.emitted_packet_window.as_ref().map(Into::into),
    }
}

fn wlan_v1(wlan: &SavedPcapWlanTriageV0) -> SavedPcapFingerprintWlanV1 {
    match wlan {
        SavedPcapWlanTriageV0::Insufficient { scope, reason } => {
            SavedPcapFingerprintWlanV1::Insufficient {
                scope: *scope,
                reason: *reason,
            }
        }
        SavedPcapWlanTriageV0::Unsupported { scope, reason } => {
            SavedPcapFingerprintWlanV1::Unsupported {
                scope: *scope,
                reason: *reason,
            }
        }
        SavedPcapWlanTriageV0::NotObserved { scope, wlan_window } => {
            SavedPcapFingerprintWlanV1::NotObserved {
                scope: *scope,
                wlan_span: wlan_window.into(),
            }
        }
        SavedPcapWlanTriageV0::Observed {
            scope,
            wlan_window,
            disconnects,
        } => SavedPcapFingerprintWlanV1::Observed {
            scope: *scope,
            wlan_span: wlan_window.into(),
            disconnects: disconnects
                .iter()
                .map(|disconnect| SavedPcapFingerprintWlanDisconnectV1 {
                    kind: disconnect.kind,
                    event_span: (&disconnect.event_window).into(),
                })
                .collect(),
        },
    }
}

fn conversation_v1(
    conversation: SavedPcapFingerprintConversationV0,
) -> SavedPcapFingerprintConversationV1 {
    SavedPcapFingerprintConversationV1 {
        aggregation: conversation.aggregation,
        temporal_relevance: conversation.temporal_relevance,
        transport: conversation.transport,
        observation_point: conversation.observation_point,
        packet_envelopes_seen: conversation.packet_envelopes_seen,
        packet_envelopes_grouped: conversation.packet_envelopes_grouped,
        packet_envelopes_excluded: conversation.packet_envelopes_excluded,
        exclusions: conversation.exclusions,
        total_frames: conversation.total_frames,
        total_original_frame_octets: conversation.total_original_frame_octets,
        total_captured_frame_octets: conversation.total_captured_frame_octets,
        a_to_b: conversation.a_to_b,
        b_to_a: conversation.b_to_a,
        observed_span_ns: conversation.observed_span_ns,
    }
}
