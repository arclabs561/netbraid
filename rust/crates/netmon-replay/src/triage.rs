use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use netmon_evidence::{NormalizationStateV0, PacketEnvelopeV0, PacketQuarantineV0};
use serde::{Deserialize, Serialize};

use crate::saved_capture::recompute_normalized_records_sha256;
use crate::{
    reduce_capture_conversations, CaptureConversationV0, ConversationDirectionV0,
    ConversationExclusionReasonV0, IpFamilyV0, SavedCaptureRecordStreamV0, TransportProtocolV0,
};

pub const SAVED_PCAP_TRIAGE_SCHEMA_V0: &str = "netmon.saved_pcap_triage.v0";
const QUARANTINE_REASON_LIMIT: usize = 8;

/// A bounded derived projection over one validated saved-capture record stream.
///
/// This is an operator projection, not a normalized evidence record. It binds
/// back to the deterministic normalized-record digest and does not add records
/// to the manifest/packet/quarantine stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapTriageV0 {
    pub schema: String,
    pub normalization: SavedPcapNormalizationTriageV0,
    pub quarantine: SavedPcapQuarantineTriageV0,
    pub wlan: SavedPcapWlanTriageV0,
    pub top_capture_conversation: SavedPcapConversationTriageV0,
    pub source: SavedPcapTriageSourceV0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapTriageSourceV0 {
    pub capture_id: String,
    pub field_registry: String,
    pub normalized_records_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapCompletenessV0 {
    CompleteCapture,
    PartialPacketSubset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapClaimScopeV0 {
    CompleteCapture,
    NormalizedPacketSubset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapNormalizationTriageV0 {
    pub state: NormalizationStateV0,
    pub completeness: SavedPcapCompletenessV0,
    pub packet_rows_emitted: u64,
    pub packet_rows_quarantined: u64,
    pub packet_rows_inspected: u64,
    pub packet_limit: u64,
    pub packet_limit_reached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub emitted_packet_window: Option<SavedPcapEventWindowV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapQuarantineTriageV0 {
    pub rows: u64,
    pub distinct_reasons: u64,
    pub reasons_shown: u64,
    pub top_reasons: Vec<SavedPcapQuarantineReasonV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapQuarantineReasonV0 {
    pub reason: String,
    pub rows: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapEventWindowV0 {
    pub observations: u64,
    pub earliest_event_time_unix_ns: i64,
    pub latest_event_time_unix_ns: i64,
    pub observed_span_ns: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapWlanTriageV0 {
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
        wlan_window: SavedPcapEventWindowV0,
    },
    Observed {
        scope: SavedPcapClaimScopeV0,
        wlan_window: SavedPcapEventWindowV0,
        disconnects: Vec<SavedPcapWlanDisconnectV0>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapWlanInsufficientReasonV0 {
    PartialNormalizationWithoutIeee80211FrameEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapWlanUnsupportedReasonV0 {
    NoIeee80211FrameEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanDisconnectV0 {
    pub kind: SavedPcapWlanDisconnectKindV0,
    pub event_window: SavedPcapEventWindowV0,
    pub tshark_display_filter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapWlanDisconnectKindV0 {
    Deauthentication,
    Disassociation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapConversationTriageV0 {
    Insufficient {
        scope: SavedPcapClaimScopeV0,
        reason: SavedPcapConversationInsufficientReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
    Unsupported {
        scope: SavedPcapClaimScopeV0,
        reason: SavedPcapConversationUnsupportedReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
    Observed {
        scope: SavedPcapClaimScopeV0,
        packet_envelopes_seen: u64,
        packet_envelopes_grouped: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
        conversation: Box<SavedPcapTopConversationV0>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapConversationInsufficientReasonV0 {
    PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapConversationUnsupportedReasonV0 {
    NoEligibleIpTcpUdpPacketEnvelopes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapConversationExclusionCountV0 {
    pub reason: SavedPcapConversationExclusionReasonV0,
    pub packet_envelopes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapConversationExclusionReasonV0 {
    InvalidPacketEnvelope,
    UnmodeledEncapsulation,
    AmbiguousNetworkLayer,
    AmbiguousTransportLayer,
    IndistinguishableEndpoints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapTopConversationV0 {
    pub aggregation: SavedPcapConversationAggregationV0,
    pub temporal_relevance: SavedPcapTemporalRelevanceV0,
    pub transport: SavedPcapTransportProtocolV0,
    pub endpoint_a: SavedPcapConversationEndpointV0,
    pub endpoint_b: SavedPcapConversationEndpointV0,
    pub observation_point: SavedPcapObservationPointV0,
    pub total_frames: u64,
    pub total_original_frame_octets: u64,
    pub total_captured_frame_octets: u64,
    pub a_to_b: SavedPcapConversationDirectionV0,
    pub b_to_a: SavedPcapConversationDirectionV0,
    pub earliest_event_time_unix_ns: i64,
    pub latest_event_time_unix_ns: i64,
    pub observed_span_ns: u64,
    pub tshark_candidate_display_filter: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapConversationAggregationV0 {
    CumulativeAcrossClaimScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapTemporalRelevanceV0 {
    NotAssessed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapTransportProtocolV0 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapConversationEndpointV0 {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapObservationPointV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encapsulation_type: Option<i16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapConversationDirectionV0 {
    pub frames: u64,
    pub original_frame_octets: u64,
    pub captured_frame_octets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_flags: Option<SavedPcapTcpFlagCountsV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapTcpFlagCountsV0 {
    pub syn_without_ack_frames: u64,
    pub syn_ack_frames: u64,
    pub fin_frames: u64,
    pub rst_frames: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SavedPcapTriageProjectionError {
    ManifestPacketCountMismatch {
        declared: u64,
        actual: u64,
    },
    ManifestQuarantineCountMismatch {
        declared: u64,
        actual: u64,
    },
    CaptureIdMismatch {
        family: &'static str,
    },
    NormalizedRecordsDigestMismatch {
        declared: String,
        recomputed: String,
    },
    NormalizedRecordsDigestRecomputationFailed,
    ReceiptDigestMismatch,
}

impl fmt::Display for SavedPcapTriageProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ManifestPacketCountMismatch { declared, actual } => write!(
                formatter,
                "manifest declares {declared} emitted packets but validated stream has {actual}"
            ),
            Self::ManifestQuarantineCountMismatch { declared, actual } => write!(
                formatter,
                "manifest declares {declared} quarantines but validated stream has {actual}"
            ),
            Self::CaptureIdMismatch { family } => {
                write!(formatter, "{family} capture ID differs from the manifest")
            }
            Self::NormalizedRecordsDigestMismatch {
                declared,
                recomputed,
            } => write!(
                formatter,
                "record-stream digest {declared} differs from recomputed digest {recomputed}"
            ),
            Self::NormalizedRecordsDigestRecomputationFailed => {
                formatter.write_str("could not recompute the normalized-record digest")
            }
            Self::ReceiptDigestMismatch => formatter
                .write_str("receipt digest differs from the validated record-stream digest"),
        }
    }
}

impl std::error::Error for SavedPcapTriageProjectionError {}

pub fn project_saved_pcap_triage(
    records: &SavedCaptureRecordStreamV0,
) -> Result<SavedPcapTriageV0, SavedPcapTriageProjectionError> {
    validate_projection_input(records)?;
    let manifest = &records.manifest;
    let packets = &records.packets;
    let quarantines = &records.quarantines;
    let normalization = &manifest.normalization;
    let packet_rows_inspected = normalization
        .packet_rows_emitted
        .saturating_add(normalization.packet_rows_quarantined);
    let completeness = match normalization.state {
        NormalizationStateV0::Complete => SavedPcapCompletenessV0::CompleteCapture,
        NormalizationStateV0::Partial => SavedPcapCompletenessV0::PartialPacketSubset,
    };

    Ok(SavedPcapTriageV0 {
        schema: SAVED_PCAP_TRIAGE_SCHEMA_V0.into(),
        normalization: SavedPcapNormalizationTriageV0 {
            state: normalization.state,
            completeness,
            packet_rows_emitted: normalization.packet_rows_emitted,
            packet_rows_quarantined: normalization.packet_rows_quarantined,
            packet_rows_inspected,
            packet_limit: normalization.packet_limit,
            packet_limit_reached: normalization.packet_limit_reached,
            emitted_packet_window: event_window(packets.iter()),
        },
        quarantine: quarantine_triage(quarantines),
        wlan: wlan_triage(completeness, packets),
        top_capture_conversation: conversation_triage(completeness, packets),
        source: SavedPcapTriageSourceV0 {
            capture_id: manifest.capture_id.clone(),
            field_registry: manifest.extractor.field_registry.clone(),
            normalized_records_sha256: records.normalized_records_sha256.clone(),
        },
    })
}

fn validate_projection_input(
    records: &SavedCaptureRecordStreamV0,
) -> Result<(), SavedPcapTriageProjectionError> {
    let normalization = &records.manifest.normalization;
    let packet_count = u64::try_from(records.packets.len()).unwrap_or(u64::MAX);
    if normalization.packet_rows_emitted != packet_count {
        return Err(
            SavedPcapTriageProjectionError::ManifestPacketCountMismatch {
                declared: normalization.packet_rows_emitted,
                actual: packet_count,
            },
        );
    }
    let quarantine_count = u64::try_from(records.quarantines.len()).unwrap_or(u64::MAX);
    if normalization.packet_rows_quarantined != quarantine_count {
        return Err(
            SavedPcapTriageProjectionError::ManifestQuarantineCountMismatch {
                declared: normalization.packet_rows_quarantined,
                actual: quarantine_count,
            },
        );
    }
    if records
        .packets
        .iter()
        .any(|packet| packet.capture_id != records.manifest.capture_id)
    {
        return Err(SavedPcapTriageProjectionError::CaptureIdMismatch { family: "packet" });
    }
    if records
        .quarantines
        .iter()
        .any(|quarantine| quarantine.capture_id != records.manifest.capture_id)
    {
        return Err(SavedPcapTriageProjectionError::CaptureIdMismatch {
            family: "quarantine",
        });
    }
    let recomputed = recompute_normalized_records_sha256(
        &records.manifest,
        &records.packets,
        &records.quarantines,
    )
    .map_err(|_| SavedPcapTriageProjectionError::NormalizedRecordsDigestRecomputationFailed)?;
    if records.normalized_records_sha256 != recomputed {
        return Err(
            SavedPcapTriageProjectionError::NormalizedRecordsDigestMismatch {
                declared: records.normalized_records_sha256.clone(),
                recomputed,
            },
        );
    }
    if records.receipt.as_ref().is_some_and(|receipt| {
        receipt.normalized_records_sha256 != records.normalized_records_sha256
    }) {
        return Err(SavedPcapTriageProjectionError::ReceiptDigestMismatch);
    }
    Ok(())
}

fn quarantine_triage(quarantines: &[PacketQuarantineV0]) -> SavedPcapQuarantineTriageV0 {
    let mut counts = BTreeMap::<String, u64>::new();
    for quarantine in quarantines {
        *counts.entry(quarantine.reason.clone()).or_default() += 1;
    }
    let distinct_reasons = u64::try_from(counts.len()).unwrap_or(u64::MAX);
    let mut ranked: Vec<_> = counts.into_iter().collect();
    ranked.sort_by(|(left_reason, left_count), (right_reason, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_reason.cmp(right_reason))
    });
    let top_reasons = ranked
        .into_iter()
        .take(QUARANTINE_REASON_LIMIT)
        .map(|(reason, rows)| SavedPcapQuarantineReasonV0 { reason, rows })
        .collect::<Vec<_>>();
    SavedPcapQuarantineTriageV0 {
        rows: u64::try_from(quarantines.len()).unwrap_or(u64::MAX),
        distinct_reasons,
        reasons_shown: u64::try_from(top_reasons.len()).unwrap_or(u64::MAX),
        top_reasons,
    }
}

fn wlan_triage(
    completeness: SavedPcapCompletenessV0,
    packets: &[PacketEnvelopeV0],
) -> SavedPcapWlanTriageV0 {
    let scope = claim_scope(completeness);
    let wlan_packets = packets
        .iter()
        .filter(|packet| packet.ieee80211.is_some())
        .collect::<Vec<_>>();
    let Some(wlan_window) = event_window(wlan_packets.iter().copied()) else {
        return match completeness {
            SavedPcapCompletenessV0::CompleteCapture => SavedPcapWlanTriageV0::Unsupported {
                scope,
                reason: SavedPcapWlanUnsupportedReasonV0::NoIeee80211FrameEvidence,
            },
            SavedPcapCompletenessV0::PartialPacketSubset => SavedPcapWlanTriageV0::Insufficient {
                scope,
                reason:
                    SavedPcapWlanInsufficientReasonV0::PartialNormalizationWithoutIeee80211FrameEvidence,
            },
        };
    };

    let deauthentication_packets = wlan_subtype_packets(packets, 12);
    let disassociation_packets = wlan_subtype_packets(packets, 10);
    let mut disconnects = Vec::new();
    if let Some(event_window) = event_window(deauthentication_packets.iter().copied()) {
        disconnects.push(SavedPcapWlanDisconnectV0 {
            kind: SavedPcapWlanDisconnectKindV0::Deauthentication,
            event_window,
            tshark_display_filter: "wlan.fc.type == 0 && wlan.fc.subtype == 12".into(),
        });
    }
    if let Some(event_window) = event_window(disassociation_packets.iter().copied()) {
        disconnects.push(SavedPcapWlanDisconnectV0 {
            kind: SavedPcapWlanDisconnectKindV0::Disassociation,
            event_window,
            tshark_display_filter: "wlan.fc.type == 0 && wlan.fc.subtype == 10".into(),
        });
    }

    if disconnects.is_empty() {
        SavedPcapWlanTriageV0::NotObserved { scope, wlan_window }
    } else {
        SavedPcapWlanTriageV0::Observed {
            scope,
            wlan_window,
            disconnects,
        }
    }
}

fn wlan_subtype_packets(packets: &[PacketEnvelopeV0], frame_subtype: u8) -> Vec<&PacketEnvelopeV0> {
    packets
        .iter()
        .filter(|packet| {
            packet
                .ieee80211
                .as_ref()
                .is_some_and(|wlan| wlan.frame_type == 0 && wlan.frame_subtype == frame_subtype)
        })
        .collect()
}

fn event_window<'a>(
    packets: impl Iterator<Item = &'a PacketEnvelopeV0>,
) -> Option<SavedPcapEventWindowV0> {
    let mut observations = 0_u64;
    let mut earliest = None;
    let mut latest = None;
    for packet in packets {
        observations = observations.saturating_add(1);
        let timestamp = packet.frame.event_time_unix_ns;
        earliest = Some(earliest.map_or(timestamp, |value: i64| value.min(timestamp)));
        latest = Some(latest.map_or(timestamp, |value: i64| value.max(timestamp)));
    }
    let (Some(earliest_event_time_unix_ns), Some(latest_event_time_unix_ns)) = (earliest, latest)
    else {
        return None;
    };
    Some(SavedPcapEventWindowV0 {
        observations,
        earliest_event_time_unix_ns,
        latest_event_time_unix_ns,
        observed_span_ns: u64::try_from(
            latest_event_time_unix_ns.saturating_sub(earliest_event_time_unix_ns),
        )
        .unwrap_or(u64::MAX),
    })
}

fn conversation_triage(
    completeness: SavedPcapCompletenessV0,
    packets: &[PacketEnvelopeV0],
) -> SavedPcapConversationTriageV0 {
    let scope = claim_scope(completeness);
    let report = reduce_capture_conversations(packets);
    let exclusions = report
        .exclusions
        .iter()
        .map(
            |(reason, packet_envelopes)| SavedPcapConversationExclusionCountV0 {
                reason: (*reason).into(),
                packet_envelopes: *packet_envelopes,
            },
        )
        .collect();
    let Some(conversation) = report.conversations.first() else {
        return match completeness {
            SavedPcapCompletenessV0::CompleteCapture => {
                SavedPcapConversationTriageV0::Unsupported {
                    scope,
                    reason:
                        SavedPcapConversationUnsupportedReasonV0::NoEligibleIpTcpUdpPacketEnvelopes,
                    packet_envelopes_seen: report.packet_envelopes_seen,
                    packet_envelopes_excluded: report.packet_envelopes_excluded,
                    exclusions,
                }
            }
            SavedPcapCompletenessV0::PartialPacketSubset => {
                SavedPcapConversationTriageV0::Insufficient {
                    scope,
                    reason: SavedPcapConversationInsufficientReasonV0::PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes,
                    packet_envelopes_seen: report.packet_envelopes_seen,
                    packet_envelopes_excluded: report.packet_envelopes_excluded,
                    exclusions,
                }
            }
        };
    };

    SavedPcapConversationTriageV0::Observed {
        scope,
        packet_envelopes_seen: report.packet_envelopes_seen,
        packet_envelopes_grouped: report.packet_envelopes_grouped,
        packet_envelopes_excluded: report.packet_envelopes_excluded,
        exclusions,
        conversation: Box::new(top_conversation(conversation)),
    }
}

fn top_conversation(conversation: &CaptureConversationV0) -> SavedPcapTopConversationV0 {
    SavedPcapTopConversationV0 {
        aggregation: SavedPcapConversationAggregationV0::CumulativeAcrossClaimScope,
        temporal_relevance: SavedPcapTemporalRelevanceV0::NotAssessed,
        transport: conversation.key.transport.into(),
        endpoint_a: SavedPcapConversationEndpointV0 {
            address: conversation.key.endpoint_a.address,
            port: conversation.key.endpoint_a.port,
        },
        endpoint_b: SavedPcapConversationEndpointV0 {
            address: conversation.key.endpoint_b.address,
            port: conversation.key.endpoint_b.port,
        },
        observation_point: SavedPcapObservationPointV0 {
            section_number: conversation.key.observation_point.section_number,
            interface_id: conversation.key.observation_point.interface_id,
            encapsulation_type: conversation.key.observation_point.encapsulation_type,
        },
        total_frames: conversation.total_frames(),
        total_original_frame_octets: conversation.total_original_frame_octets(),
        total_captured_frame_octets: conversation.total_captured_frame_octets(),
        a_to_b: direction(&conversation.a_to_b),
        b_to_a: direction(&conversation.b_to_a),
        earliest_event_time_unix_ns: conversation.earliest_event_time_unix_ns,
        latest_event_time_unix_ns: conversation.latest_event_time_unix_ns,
        observed_span_ns: u64::try_from(
            conversation
                .latest_event_time_unix_ns
                .saturating_sub(conversation.earliest_event_time_unix_ns),
        )
        .unwrap_or(u64::MAX),
        tshark_candidate_display_filter: conversation_candidate_display_filter(conversation),
    }
}

fn claim_scope(completeness: SavedPcapCompletenessV0) -> SavedPcapClaimScopeV0 {
    match completeness {
        SavedPcapCompletenessV0::CompleteCapture => SavedPcapClaimScopeV0::CompleteCapture,
        SavedPcapCompletenessV0::PartialPacketSubset => {
            SavedPcapClaimScopeV0::NormalizedPacketSubset
        }
    }
}

fn direction(direction: &ConversationDirectionV0) -> SavedPcapConversationDirectionV0 {
    SavedPcapConversationDirectionV0 {
        frames: direction.frames,
        original_frame_octets: direction.original_frame_octets,
        captured_frame_octets: direction.captured_frame_octets,
        tcp_flags: direction
            .tcp_flags
            .as_ref()
            .map(|flags| SavedPcapTcpFlagCountsV0 {
                syn_without_ack_frames: flags.syn_without_ack_frames,
                syn_ack_frames: flags.syn_ack_frames,
                fin_frames: flags.fin_frames,
                rst_frames: flags.rst_frames,
            }),
    }
}

fn conversation_candidate_display_filter(conversation: &CaptureConversationV0) -> String {
    let transport = match conversation.key.transport {
        TransportProtocolV0::Tcp => "tcp",
        TransportProtocolV0::Udp => "udp",
    };
    let network = match conversation.key.ip_family {
        IpFamilyV0::Ipv4 => "ip",
        IpFamilyV0::Ipv6 => "ipv6",
    };
    let endpoint_a = &conversation.key.endpoint_a;
    let endpoint_b = &conversation.key.endpoint_b;
    let mut clauses = Vec::new();
    if let Some(section) = conversation.key.observation_point.section_number {
        clauses.push(format!("frame.section_number == {section}"));
    }
    if let Some(interface) = conversation.key.observation_point.interface_id {
        clauses.push(format!("frame.interface_id == {interface}"));
    }
    if let Some(encapsulation) = conversation.key.observation_point.encapsulation_type {
        clauses.push(format!("frame.encap_type == {encapsulation}"));
    }
    clauses.push(format!(
        "{transport} && (({network}.src == {} && {transport}.srcport == {} && \
         {network}.dst == {} && {transport}.dstport == {}) || \
         ({network}.src == {} && {transport}.srcport == {} && \
         {network}.dst == {} && {transport}.dstport == {}))",
        endpoint_a.address,
        endpoint_a.port,
        endpoint_b.address,
        endpoint_b.port,
        endpoint_b.address,
        endpoint_b.port,
        endpoint_a.address,
        endpoint_a.port,
    ));
    clauses
        .into_iter()
        .map(|clause| format!("({clause})"))
        .collect::<Vec<_>>()
        .join(" && ")
}

impl From<TransportProtocolV0> for SavedPcapTransportProtocolV0 {
    fn from(value: TransportProtocolV0) -> Self {
        match value {
            TransportProtocolV0::Tcp => Self::Tcp,
            TransportProtocolV0::Udp => Self::Udp,
        }
    }
}

impl From<ConversationExclusionReasonV0> for SavedPcapConversationExclusionReasonV0 {
    fn from(value: ConversationExclusionReasonV0) -> Self {
        match value {
            ConversationExclusionReasonV0::InvalidPacketEnvelope => Self::InvalidPacketEnvelope,
            ConversationExclusionReasonV0::UnmodeledEncapsulation => Self::UnmodeledEncapsulation,
            ConversationExclusionReasonV0::AmbiguousNetworkLayer => Self::AmbiguousNetworkLayer,
            ConversationExclusionReasonV0::AmbiguousTransportLayer => Self::AmbiguousTransportLayer,
            ConversationExclusionReasonV0::IndistinguishableEndpoints => {
                Self::IndistinguishableEndpoints
            }
        }
    }
}
