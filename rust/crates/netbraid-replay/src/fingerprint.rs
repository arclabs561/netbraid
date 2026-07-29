use netbraid_evidence::CaptureExtractorRefV0;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    SavedPcapClaimScopeV0, SavedPcapConversationAggregationV0, SavedPcapConversationDirectionV0,
    SavedPcapConversationExclusionCountV0, SavedPcapConversationTriageV0,
    SavedPcapNormalizationTriageV0, SavedPcapObservationPointV0, SavedPcapTemporalRelevanceV0,
    SavedPcapTopConversationV0, SavedPcapTransportProtocolV0, SavedPcapTriageV1,
    SavedPcapWlanTriageV0,
};

pub const SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0: &str =
    "netmon.saved_pcap_fingerprint_candidate.v0";

const FINGERPRINT_CAVEATS: &[&str] = &[
    "capture-wide aggregate over eligible normalized packet envelopes; not sessionized",
    "endpoint addresses and ports are excluded from the comparison digest",
    "no cross-observer join or device, person, place, or intent identity",
    "missing radiotap, CSI, and BLE evidence remains outside this packet-shape candidate",
];

const FINGERPRINT_FEATURE_NAMES: &[&str] = &[
    "normalization.state",
    "normalization.completeness",
    "normalization.packet_rows_emitted",
    "normalization.packet_rows_quarantined",
    "normalization.packet_rows_inspected",
    "normalization.packet_limit",
    "normalization.packet_limit_reached",
    "normalization.emitted_packet_window",
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
    "conversation.earliest_event_time_unix_ns",
    "conversation.latest_event_time_unix_ns",
    "conversation.observed_span_ns",
];

/// A provenance reference for one packet-shape fingerprint candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintSourceV0 {
    pub capture_id: String,
    pub normalized_records_sha256: String,
    pub extractor: CaptureExtractorRefV0,
}

/// The feature values that participate in an observed candidate's digest.
///
/// Endpoint addresses, ports, and the display-filter suggestion are omitted on
/// purpose. They are useful for operator investigation but are not stable
/// cross-observer fingerprint features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintBasisV0 {
    pub feature_names: Vec<String>,
    pub normalization: SavedPcapNormalizationTriageV0,
    pub wlan: SavedPcapWlanTriageV0,
    pub conversation: SavedPcapFingerprintConversationV0,
}

/// The endpoint-independent packet-shape portion of a top conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintConversationV0 {
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
    pub earliest_event_time_unix_ns: i64,
    pub latest_event_time_unix_ns: i64,
    pub observed_span_ns: u64,
}

/// Why a packet-shape candidate cannot be promoted to an observed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintInsufficientReasonV0 {
    PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes,
}

/// Why a packet-shape candidate is outside the supported evidence vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintUnsupportedReasonV0 {
    NoEligibleIpTcpUdpPacketEnvelopes,
}

/// The result of reducing a validated saved-capture triage projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapFingerprintStatusV0 {
    Observed {
        digest: String,
        basis: Box<SavedPcapFingerprintBasisV0>,
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

/// An endpoint-independent candidate for later multi-vantage comparison.
///
/// This is derived evidence, not an identity claim. Only the `Observed`
/// variant carries a digest; partial and unsupported inputs remain typed
/// abstentions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintCandidateV0 {
    pub schema: String,
    pub source: SavedPcapFingerprintSourceV0,
    pub scope: SavedPcapClaimScopeV0,
    pub status: SavedPcapFingerprintStatusV0,
}

/// Projects one validated triage result into a deterministic packet-shape
/// candidate without reparsing raw capture or JSONL input.
pub fn project_saved_pcap_fingerprint_v0(
    triage: &SavedPcapTriageV1,
) -> SavedPcapFingerprintCandidateV0 {
    let source = SavedPcapFingerprintSourceV0 {
        capture_id: triage.source.manifest.capture_id.clone(),
        normalized_records_sha256: triage.source.normalized_records_sha256.clone(),
        extractor: triage.source.manifest.extractor.clone(),
    };

    let (scope, status) = match &triage.top_capture_conversation {
        SavedPcapConversationTriageV0::Observed {
            scope,
            packet_envelopes_seen,
            packet_envelopes_grouped,
            packet_envelopes_excluded,
            exclusions,
            conversation,
        } => {
            let basis = SavedPcapFingerprintBasisV0 {
                feature_names: FINGERPRINT_FEATURE_NAMES
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                normalization: triage.normalization.clone(),
                wlan: triage.wlan.clone(),
                conversation: fingerprint_conversation(
                    *packet_envelopes_seen,
                    *packet_envelopes_grouped,
                    *packet_envelopes_excluded,
                    exclusions,
                    conversation,
                ),
            };
            let digest = fingerprint_digest(&basis);
            (
                *scope,
                SavedPcapFingerprintStatusV0::Observed {
                    digest,
                    basis: Box::new(basis),
                    caveats: FINGERPRINT_CAVEATS
                        .iter()
                        .map(|caveat| (*caveat).to_owned())
                        .collect(),
                },
            )
        }
        SavedPcapConversationTriageV0::Insufficient {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => (
            *scope,
            SavedPcapFingerprintStatusV0::Insufficient {
                reason: match reason {
                    crate::SavedPcapConversationInsufficientReasonV0::
                        PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes => {
                        SavedPcapFingerprintInsufficientReasonV0::
                            PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes
                    }
                },
                packet_envelopes_seen: *packet_envelopes_seen,
                packet_envelopes_excluded: *packet_envelopes_excluded,
                exclusions: exclusions.clone(),
            },
        ),
        SavedPcapConversationTriageV0::Unsupported {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => (
            *scope,
            SavedPcapFingerprintStatusV0::Unsupported {
                reason: match reason {
                    crate::SavedPcapConversationUnsupportedReasonV0::
                        NoEligibleIpTcpUdpPacketEnvelopes => {
                        SavedPcapFingerprintUnsupportedReasonV0::NoEligibleIpTcpUdpPacketEnvelopes
                    }
                },
                packet_envelopes_seen: *packet_envelopes_seen,
                packet_envelopes_excluded: *packet_envelopes_excluded,
                exclusions: exclusions.clone(),
            },
        ),
    };

    SavedPcapFingerprintCandidateV0 {
        schema: SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.to_owned(),
        source,
        scope,
        status,
    }
}

fn fingerprint_conversation(
    packet_envelopes_seen: u64,
    packet_envelopes_grouped: u64,
    packet_envelopes_excluded: u64,
    exclusions: &[SavedPcapConversationExclusionCountV0],
    conversation: &SavedPcapTopConversationV0,
) -> SavedPcapFingerprintConversationV0 {
    SavedPcapFingerprintConversationV0 {
        aggregation: conversation.aggregation,
        temporal_relevance: conversation.temporal_relevance,
        transport: conversation.transport,
        observation_point: conversation.observation_point.clone(),
        packet_envelopes_seen,
        packet_envelopes_grouped,
        packet_envelopes_excluded,
        exclusions: exclusions.to_vec(),
        total_frames: conversation.total_frames,
        total_original_frame_octets: conversation.total_original_frame_octets,
        total_captured_frame_octets: conversation.total_captured_frame_octets,
        a_to_b: conversation.a_to_b.clone(),
        b_to_a: conversation.b_to_a.clone(),
        earliest_event_time_unix_ns: conversation.earliest_event_time_unix_ns,
        latest_event_time_unix_ns: conversation.latest_event_time_unix_ns,
        observed_span_ns: conversation.observed_span_ns,
    }
}

fn fingerprint_digest(basis: &SavedPcapFingerprintBasisV0) -> String {
    let encoded = serde_json::to_vec(basis).expect("fingerprint basis is serializable");
    let mut hasher = Sha256::new();
    hasher.update(SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}
