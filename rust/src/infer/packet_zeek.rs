//! Compatibility adapter from Zeek `conn.log` projections to flow records.

use std::fmt;

use crate::adapters::zeek::{ZeekConnProtocolV0, ZeekConnStreamV0, ZeekConnV0};
use crate::replay::{ConversationEndpointV0, PacketFlowV0};

use super::packet_flow_correspondence::{
    infer_packet_flow_correspondence_v0, FlowRecordProtocolV0, FlowRecordV0,
    PacketFlowCorrespondenceComponentOutcomeV0, PacketFlowCorrespondenceDispositionV0,
    PacketFlowCorrespondenceErrorV0, PacketFlowCorrespondenceHeuristicProfileV0,
    PacketFlowCorrespondenceLimitsV0, PacketFlowCorrespondenceOptionsV0,
    PacketFlowCorrespondenceReportV0,
};

/// Identifier retained for the packet/Zeek compatibility entry point.
pub const PACKET_ZEEK_HEURISTIC_PROFILE_V0: &str =
    "netbraid.packet_zeek_correspondence.heuristic.v0";

/// Fixed-point potentials used by the packet/Zeek compatibility entry point.
pub type PacketZeekHeuristicProfileV0 = PacketFlowCorrespondenceHeuristicProfileV0;

/// Maximum state of one binary edge marginal.
pub type PacketZeekMarginalDispositionV0 = PacketFlowCorrespondenceDispositionV0;

/// Why one candidate component was not enumerated.
pub type PacketZeekAbstentionReasonV0 =
    super::packet_flow_correspondence::PacketFlowCorrespondenceAbstentionReasonV0;

/// Exact, infeasible, or resource-bounded result for one candidate component.
pub type PacketZeekComponentOutcomeV0 = PacketFlowCorrespondenceComponentOutcomeV0;

/// Resource limits for packet/Zeek candidate construction and exact inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketZeekInferenceLimitsV0 {
    pub max_packet_flows: usize,
    pub max_zeek_connections: usize,
    pub max_candidate_edges: usize,
    pub max_component_edges: usize,
    pub max_assignments: u64,
}

impl Default for PacketZeekInferenceLimitsV0 {
    fn default() -> Self {
        let limits = PacketFlowCorrespondenceLimitsV0::default();
        Self {
            max_packet_flows: limits.max_packet_flows,
            max_zeek_connections: limits.max_flow_records,
            max_candidate_edges: limits.max_candidate_edges,
            max_component_edges: limits.max_component_edges,
            max_assignments: limits.max_assignments,
        }
    }
}

/// Candidate, scoring, and resource policy for one packet/Zeek inference run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketZeekCorrespondenceOptionsV0 {
    pub candidate_tolerance_ns: u64,
    pub profile: PacketZeekHeuristicProfileV0,
    pub limits: PacketZeekInferenceLimitsV0,
}

impl Default for PacketZeekCorrespondenceOptionsV0 {
    fn default() -> Self {
        Self {
            candidate_tolerance_ns: 1_000,
            profile: PacketZeekHeuristicProfileV0::default(),
            limits: PacketZeekInferenceLimitsV0::default(),
        }
    }
}

/// Model-relative belief for one admitted packet/Zeek candidate edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekEdgeBeliefV0 {
    packet_flow_index: usize,
    zeek_connection_index: usize,
    corresponds_relative_belief_ppb: u64,
    marginal_disposition: PacketZeekMarginalDispositionV0,
}

impl PacketZeekEdgeBeliefV0 {
    pub const fn packet_flow_index(&self) -> usize {
        self.packet_flow_index
    }

    pub const fn zeek_connection_index(&self) -> usize {
        self.zeek_connection_index
    }

    pub const fn corresponds_relative_belief_ppb(&self) -> u64 {
        self.corresponds_relative_belief_ppb
    }

    pub const fn marginal_disposition(&self) -> PacketZeekMarginalDispositionV0 {
        self.marginal_disposition
    }
}

/// One connected packet/Zeek candidate component and its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekComponentResultV0 {
    pub packet_flow_indices: Box<[usize]>,
    pub zeek_connection_indices: Box<[usize]>,
    pub edges: Box<[PacketZeekEdgeBeliefV0]>,
    pub outcome: PacketZeekComponentOutcomeV0,
}

/// Aggregate in-memory packet/Zeek correspondence report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekCorrespondenceReportV0 {
    pub heuristic_profile: &'static str,
    pub profile: PacketZeekHeuristicProfileV0,
    pub candidate_tolerance_ns: u64,
    pub packet_flows_seen: usize,
    pub zeek_connections_seen: usize,
    pub candidate_edges: usize,
    pub packet_flows_without_candidates: usize,
    pub zeek_connections_without_candidates: usize,
    pub components: Box<[PacketZeekComponentResultV0]>,
}

/// Failure before a complete packet/Zeek candidate report can be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketZeekCorrespondenceErrorV0 {
    InvalidProfile,
    InvalidLimits,
    PacketFlowLimitExceeded,
    ZeekConnectionLimitExceeded,
    CandidateEdgeLimitExceeded,
    InvalidPacketFlow,
    InternalModel,
}

impl fmt::Display for PacketZeekCorrespondenceErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidProfile => "invalid packet/Zeek heuristic profile",
            Self::InvalidLimits => "invalid packet/Zeek inference limits",
            Self::PacketFlowLimitExceeded => "packet-flow input limit exceeded",
            Self::ZeekConnectionLimitExceeded => "Zeek-connection input limit exceeded",
            Self::CandidateEdgeLimitExceeded => "packet/Zeek candidate-edge limit exceeded",
            Self::InvalidPacketFlow => "packet-flow input violates projection invariants",
            Self::InternalModel => "packet/Zeek factor model could not be constructed",
        })
    }
}

impl std::error::Error for PacketZeekCorrespondenceErrorV0 {}

/// Infer correspondence through the source-neutral flow-record model.
pub fn infer_packet_zeek_correspondence_v0(
    packet_flows: &[PacketFlowV0],
    zeek_connections: &ZeekConnStreamV0,
    options: &PacketZeekCorrespondenceOptionsV0,
) -> Result<PacketZeekCorrespondenceReportV0, PacketZeekCorrespondenceErrorV0> {
    if zeek_connections.connections().len() > options.limits.max_zeek_connections {
        return Err(PacketZeekCorrespondenceErrorV0::ZeekConnectionLimitExceeded);
    }
    let flow_records: Vec<_> = zeek_connections
        .connections()
        .iter()
        .map(project_zeek_connection)
        .collect();
    let generic_options = PacketFlowCorrespondenceOptionsV0 {
        candidate_tolerance_ns: options.candidate_tolerance_ns,
        profile: options.profile,
        limits: PacketFlowCorrespondenceLimitsV0 {
            max_packet_flows: options.limits.max_packet_flows,
            max_flow_records: options.limits.max_zeek_connections,
            max_candidate_edges: options.limits.max_candidate_edges,
            max_component_edges: options.limits.max_component_edges,
            max_assignments: options.limits.max_assignments,
        },
    };
    infer_packet_flow_correspondence_v0(packet_flows, &flow_records, &generic_options)
        .map(project_report)
        .map_err(project_error)
}

fn project_zeek_connection(connection: &ZeekConnV0) -> FlowRecordV0 {
    FlowRecordV0::new(
        connection.start_time_unix_ns(),
        ConversationEndpointV0 {
            address: connection.originator().address(),
            port: connection.originator().port(),
        },
        ConversationEndpointV0 {
            address: connection.responder().address(),
            port: connection.responder().port(),
        },
        match connection.protocol() {
            ZeekConnProtocolV0::Tcp => FlowRecordProtocolV0::Tcp,
            ZeekConnProtocolV0::Udp => FlowRecordProtocolV0::Udp,
            ZeekConnProtocolV0::Icmp | ZeekConnProtocolV0::UnknownTransport => {
                FlowRecordProtocolV0::Unsupported
            }
        },
        connection.duration_ns(),
        connection.orig_packets(),
        connection.orig_ip_bytes(),
        connection.resp_packets(),
        connection.resp_ip_bytes(),
    )
}

fn project_report(report: PacketFlowCorrespondenceReportV0) -> PacketZeekCorrespondenceReportV0 {
    PacketZeekCorrespondenceReportV0 {
        heuristic_profile: PACKET_ZEEK_HEURISTIC_PROFILE_V0,
        profile: report.profile,
        candidate_tolerance_ns: report.candidate_tolerance_ns,
        packet_flows_seen: report.packet_flows_seen,
        zeek_connections_seen: report.flow_records_seen,
        candidate_edges: report.candidate_edges,
        packet_flows_without_candidates: report.packet_flows_without_candidates,
        zeek_connections_without_candidates: report.flow_records_without_candidates,
        components: report
            .components
            .into_vec()
            .into_iter()
            .map(|component| PacketZeekComponentResultV0 {
                packet_flow_indices: component.packet_flow_indices,
                zeek_connection_indices: component.flow_record_indices,
                edges: component
                    .edges
                    .into_vec()
                    .into_iter()
                    .map(|edge| PacketZeekEdgeBeliefV0 {
                        packet_flow_index: edge.packet_flow_index(),
                        zeek_connection_index: edge.flow_record_index(),
                        corresponds_relative_belief_ppb: edge.corresponds_relative_belief_ppb(),
                        marginal_disposition: edge.marginal_disposition(),
                    })
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
                outcome: component.outcome,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    }
}

fn project_error(error: PacketFlowCorrespondenceErrorV0) -> PacketZeekCorrespondenceErrorV0 {
    match error {
        PacketFlowCorrespondenceErrorV0::InvalidProfile => {
            PacketZeekCorrespondenceErrorV0::InvalidProfile
        }
        PacketFlowCorrespondenceErrorV0::InvalidLimits => {
            PacketZeekCorrespondenceErrorV0::InvalidLimits
        }
        PacketFlowCorrespondenceErrorV0::PacketFlowLimitExceeded => {
            PacketZeekCorrespondenceErrorV0::PacketFlowLimitExceeded
        }
        PacketFlowCorrespondenceErrorV0::FlowRecordLimitExceeded => {
            PacketZeekCorrespondenceErrorV0::ZeekConnectionLimitExceeded
        }
        PacketFlowCorrespondenceErrorV0::CandidateEdgeLimitExceeded => {
            PacketZeekCorrespondenceErrorV0::CandidateEdgeLimitExceeded
        }
        PacketFlowCorrespondenceErrorV0::InvalidPacketFlow => {
            PacketZeekCorrespondenceErrorV0::InvalidPacketFlow
        }
        PacketFlowCorrespondenceErrorV0::InternalModel => {
            PacketZeekCorrespondenceErrorV0::InternalModel
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::adapters::zeek::{project_zeek_conn_log, ZeekConnOptions};
    use crate::replay::{
        ConversationEndpointV0, IpFamilyV0, ObservationPointV0, PacketFlowEndBasisV0,
        PacketFlowOriginBasisV0, TransportProtocolV0,
    };

    use super::*;

    #[test]
    fn compatibility_entry_point_preserves_zeek_indices_and_profile() {
        let source = "#separator \\x09\n\
            #set_separator\t,\n\
            #empty_field\t(empty)\n\
            #unset_field\t-\n\
            #path\tconn\n\
            #fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n\
            #types\ttime\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tcount\tcount\n\
            1.000000000\t192.0.2.1\t1234\t198.51.100.2\t443\ttcp\t0.100000000\t3\t300\t2\t200\n";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conn.log");
        fs::write(&path, source).unwrap();
        let stream = project_zeek_conn_log(&path, &ZeekConnOptions::default()).unwrap();
        let packet = PacketFlowV0 {
            ip_family: IpFamilyV0::Ipv4,
            transport: TransportProtocolV0::Tcp,
            observation_point: ObservationPointV0 {
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
            },
            originator: ConversationEndpointV0 {
                address: "192.0.2.1".parse().unwrap(),
                port: 1234,
            },
            responder: ConversationEndpointV0 {
                address: "198.51.100.2".parse().unwrap(),
                port: 443,
            },
            start_time_unix_ns: 1_000_000_000,
            end_time_unix_ns: 1_100_000_000,
            orig_packets: 3,
            orig_ip_bytes: 300,
            resp_packets: 2,
            resp_ip_bytes: 200,
            origin_basis: PacketFlowOriginBasisV0::UniqueSynWithoutAck,
            end_basis: PacketFlowEndBasisV0::CompleteCaptureBoundary,
        };

        let report = infer_packet_zeek_correspondence_v0(
            &[packet],
            &stream,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();

        assert_eq!(report.heuristic_profile, PACKET_ZEEK_HEURISTIC_PROFILE_V0);
        assert_eq!(report.zeek_connections_seen, 1);
        assert_eq!(report.components[0].zeek_connection_indices.as_ref(), &[0]);
        assert_eq!(report.components[0].edges[0].zeek_connection_index(), 0);
        assert_eq!(
            report.components[0].edges[0].corresponds_relative_belief_ppb(),
            998_050_682
        );
    }
}
