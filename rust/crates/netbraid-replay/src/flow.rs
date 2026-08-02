use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use netbraid_evidence::{NormalizationStateV0, PacketEnvelopeV0};

use crate::conversation::{candidate, ConversationExclusionReasonV0};
use crate::{
    ConversationEndpointV0, IpFamilyV0, ObservationPointV0, SavedCaptureRecordStreamV0,
    TransportProtocolV0,
};

const FIN: u16 = 0x0001;
const SYN: u16 = 0x0002;
const RST: u16 = 0x0004;
const ACK: u16 = 0x0010;

/// Explicit inactivity policy for deterministic packet-flow sessionization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketFlowSessionizationV0 {
    /// TCP sessions split only when the observed gap is strictly greater than this value.
    pub tcp_inactivity_ns: Option<u64>,
    /// UDP sessions split only when the observed gap is strictly greater than this value.
    pub udp_inactivity_ns: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketFlowOriginBasisV0 {
    UniqueSynWithoutAck,
    InitialSynAckOpposite,
    LowestFrameSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketFlowEndBasisV0 {
    TcpResetObserved,
    TcpFinObserved,
    InactivityGap,
    CompleteCaptureBoundary,
    PartialCaptureBoundary,
    QuarantinedCaptureBoundary,
    PartialAndQuarantinedCaptureBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFlowV0 {
    pub ip_family: IpFamilyV0,
    pub transport: TransportProtocolV0,
    pub observation_point: ObservationPointV0,
    pub originator: ConversationEndpointV0,
    pub responder: ConversationEndpointV0,
    pub start_time_unix_ns: i64,
    pub end_time_unix_ns: i64,
    pub orig_packets: u64,
    pub orig_ip_bytes: u64,
    pub resp_packets: u64,
    pub resp_ip_bytes: u64,
    pub origin_basis: PacketFlowOriginBasisV0,
    pub end_basis: PacketFlowEndBasisV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PacketFlowExclusionReasonV0 {
    InvalidPacketEnvelope,
    UnmodeledEncapsulation,
    AmbiguousNetworkLayer,
    AmbiguousTransportLayer,
    FragmentedOrIncompleteTransport,
    IndistinguishableEndpoints,
    MissingIpTotalLength,
    MissingTcpStreamIndex,
    PartialNormalization,
    QuarantinedPacketRow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketFlowReportV0 {
    pub sessionization: PacketFlowSessionizationV0,
    pub packet_envelopes_seen: u64,
    pub packet_envelopes_grouped: u64,
    pub packet_envelopes_excluded: u64,
    /// Packet-level exclusions plus capture-level partial/quarantine counts.
    pub exclusions: BTreeMap<PacketFlowExclusionReasonV0, u64>,
    pub flows: Vec<PacketFlowV0>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketFlowProjectionError {
    CounterOverflow,
}

impl fmt::Display for PacketFlowProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CounterOverflow => formatter.write_str("packet-flow counter overflow"),
        }
    }
}

impl std::error::Error for PacketFlowProjectionError {}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PartitionKey {
    capture_id: String,
    observation_point: ObservationPointV0,
    ip_family: IpFamilyV0,
    transport: TransportProtocolV0,
    endpoint_a: ConversationEndpointV0,
    endpoint_b: ConversationEndpointV0,
    tcp_stream_index: Option<u32>,
}

#[derive(Debug, Clone)]
struct EligiblePacket {
    source: ConversationEndpointV0,
    event_time_unix_ns: i64,
    frame_number: u64,
    ip_total_length: u32,
    tcp_flags: Option<u16>,
}

struct ProjectedFlow {
    flow: PacketFlowV0,
    key: PartitionKey,
    segment_ordinal: u64,
}

pub fn project_saved_capture_flows_v0(
    records: &SavedCaptureRecordStreamV0,
    policy: PacketFlowSessionizationV0,
) -> Result<PacketFlowReportV0, PacketFlowProjectionError> {
    let mut partitions = BTreeMap::<PartitionKey, Vec<EligiblePacket>>::new();
    let mut exclusions = BTreeMap::new();
    let mut grouped = 0_u64;

    for packet in &records.packets {
        match eligible_packet(packet) {
            Ok((key, packet)) => {
                grouped = checked_add(grouped, 1)?;
                partitions.entry(key).or_default().push(packet);
            }
            Err(reason) => increment(&mut exclusions, reason, 1)?,
        }
    }

    let partial = records.manifest.normalization.state == NormalizationStateV0::Partial;
    let quarantined_rows = u64::try_from(records.quarantines.len())
        .map_err(|_| PacketFlowProjectionError::CounterOverflow)?;
    if partial {
        increment(
            &mut exclusions,
            PacketFlowExclusionReasonV0::PartialNormalization,
            1,
        )?;
    }
    if quarantined_rows != 0 {
        increment(
            &mut exclusions,
            PacketFlowExclusionReasonV0::QuarantinedPacketRow,
            quarantined_rows,
        )?;
    }

    let mut projected = Vec::new();
    for (key, mut packets) in partitions {
        packets.sort_by(|left, right| {
            left.event_time_unix_ns
                .cmp(&right.event_time_unix_ns)
                .then_with(|| left.frame_number.cmp(&right.frame_number))
                .then_with(|| left.source.cmp(&right.source))
                .then_with(|| left.ip_total_length.cmp(&right.ip_total_length))
                .then_with(|| left.tcp_flags.cmp(&right.tcp_flags))
        });
        let threshold = match key.transport {
            TransportProtocolV0::Tcp => policy.tcp_inactivity_ns,
            TransportProtocolV0::Udp => policy.udp_inactivity_ns,
        };
        let mut segment_start = 0;
        let mut segment_ordinal = 0_u64;
        for index in 1..=packets.len() {
            let split = index == packets.len()
                || threshold.is_some_and(|threshold| {
                    gap_exceeds(
                        packets[index - 1].event_time_unix_ns,
                        packets[index].event_time_unix_ns,
                        threshold,
                    )
                });
            if !split {
                continue;
            }
            let has_idle_successor = index < packets.len();
            projected.push(ProjectedFlow {
                flow: project_segment(
                    &key,
                    &packets[segment_start..index],
                    has_idle_successor,
                    partial,
                    quarantined_rows != 0,
                )?,
                key: key.clone(),
                segment_ordinal,
            });
            segment_start = index;
            segment_ordinal = checked_add(segment_ordinal, 1)?;
        }
    }

    projected.sort_by(|left, right| {
        left.flow
            .start_time_unix_ns
            .cmp(&right.flow.start_time_unix_ns)
            .then_with(|| left.flow.transport.cmp(&right.flow.transport))
            .then_with(|| left.flow.originator.cmp(&right.flow.originator))
            .then_with(|| left.flow.responder.cmp(&right.flow.responder))
            .then_with(|| {
                left.flow
                    .observation_point
                    .cmp(&right.flow.observation_point)
            })
            .then_with(|| left.key.capture_id.cmp(&right.key.capture_id))
            .then_with(|| left.key.tcp_stream_index.cmp(&right.key.tcp_stream_index))
            .then_with(|| left.segment_ordinal.cmp(&right.segment_ordinal))
    });

    let seen = u64::try_from(records.packets.len())
        .map_err(|_| PacketFlowProjectionError::CounterOverflow)?;
    Ok(PacketFlowReportV0 {
        sessionization: policy,
        packet_envelopes_seen: seen,
        packet_envelopes_grouped: grouped,
        packet_envelopes_excluded: seen
            .checked_sub(grouped)
            .ok_or(PacketFlowProjectionError::CounterOverflow)?,
        exclusions,
        flows: projected
            .into_iter()
            .map(|projected| projected.flow)
            .collect(),
    })
}

fn eligible_packet(
    packet: &PacketEnvelopeV0,
) -> Result<(PartitionKey, EligiblePacket), PacketFlowExclusionReasonV0> {
    let conversation = match candidate(packet) {
        Ok(candidate) => candidate,
        Err(ConversationExclusionReasonV0::AmbiguousTransportLayer)
            if has_fragment_ambiguity(packet) =>
        {
            return Err(PacketFlowExclusionReasonV0::FragmentedOrIncompleteTransport);
        }
        Err(reason) => return Err(reason.into()),
    };
    if has_fragment_ambiguity(packet) {
        return Err(PacketFlowExclusionReasonV0::FragmentedOrIncompleteTransport);
    }
    let ip_total_length = match conversation.key.ip_family {
        IpFamilyV0::Ipv4 => packet
            .ipv4
            .as_ref()
            .and_then(|ipv4| ipv4.total_length_octets),
        IpFamilyV0::Ipv6 => packet
            .ipv6
            .as_ref()
            .and_then(|ipv6| ipv6.total_length_octets),
    }
    .ok_or(PacketFlowExclusionReasonV0::MissingIpTotalLength)?;
    let tcp_stream_index = match conversation.transport {
        TransportProtocolV0::Tcp => Some(
            packet
                .tcp
                .as_ref()
                .and_then(|tcp| tcp.stream_index)
                .ok_or(PacketFlowExclusionReasonV0::MissingTcpStreamIndex)?,
        ),
        TransportProtocolV0::Udp => None,
    };
    let source = if conversation.source_is_a {
        conversation.key.endpoint_a.clone()
    } else {
        conversation.key.endpoint_b.clone()
    };
    let key = PartitionKey {
        capture_id: conversation.key.capture_id,
        observation_point: conversation.key.observation_point,
        ip_family: conversation.key.ip_family,
        transport: conversation.transport,
        endpoint_a: conversation.key.endpoint_a,
        endpoint_b: conversation.key.endpoint_b,
        tcp_stream_index,
    };
    Ok((
        key,
        EligiblePacket {
            source,
            event_time_unix_ns: packet.frame.event_time_unix_ns,
            frame_number: packet.frame.number,
            ip_total_length,
            tcp_flags: packet.tcp.as_ref().map(|tcp| tcp.flags),
        },
    ))
}

fn has_fragment_ambiguity(packet: &PacketEnvelopeV0) -> bool {
    if packet.frame.protocols.iter().any(|protocol| {
        matches!(
            protocol.as_str(),
            "ip.fragment" | "ipv6.fragment" | "ipv6.fraghdr"
        )
    }) {
        return true;
    }
    if packet
        .ipv6
        .as_ref()
        .is_some_and(|ipv6| ipv6.next_header == 44)
    {
        return true;
    }
    packet
        .ipv4
        .as_ref()
        .is_some_and(|ipv4| match ipv4.protocol {
            6 => packet.tcp.is_none(),
            17 => packet.udp.is_none(),
            _ => false,
        })
}

impl From<ConversationExclusionReasonV0> for PacketFlowExclusionReasonV0 {
    fn from(reason: ConversationExclusionReasonV0) -> Self {
        match reason {
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

fn project_segment(
    key: &PartitionKey,
    packets: &[EligiblePacket],
    has_idle_successor: bool,
    partial: bool,
    quarantined: bool,
) -> Result<PacketFlowV0, PacketFlowProjectionError> {
    let (originator, origin_basis) = orient(key, packets);
    let responder = if originator == key.endpoint_a {
        key.endpoint_b.clone()
    } else {
        key.endpoint_a.clone()
    };
    let mut orig_packets = 0_u64;
    let mut orig_ip_bytes = 0_u64;
    let mut resp_packets = 0_u64;
    let mut resp_ip_bytes = 0_u64;
    for packet in packets {
        if packet.source == originator {
            orig_packets = checked_add(orig_packets, 1)?;
            orig_ip_bytes = checked_add(orig_ip_bytes, u64::from(packet.ip_total_length))?;
        } else {
            resp_packets = checked_add(resp_packets, 1)?;
            resp_ip_bytes = checked_add(resp_ip_bytes, u64::from(packet.ip_total_length))?;
        }
    }
    Ok(PacketFlowV0 {
        ip_family: key.ip_family,
        transport: key.transport,
        observation_point: key.observation_point,
        originator,
        responder,
        start_time_unix_ns: packets[0].event_time_unix_ns,
        end_time_unix_ns: packets[packets.len() - 1].event_time_unix_ns,
        orig_packets,
        orig_ip_bytes,
        resp_packets,
        resp_ip_bytes,
        origin_basis,
        end_basis: end_basis(
            key.transport,
            packets,
            has_idle_successor,
            partial,
            quarantined,
        ),
    })
}

fn orient(
    key: &PartitionKey,
    packets: &[EligiblePacket],
) -> (ConversationEndpointV0, PacketFlowOriginBasisV0) {
    if key.transport == TransportProtocolV0::Tcp {
        let syn_senders: BTreeSet<_> = packets
            .iter()
            .filter(|packet| packet.tcp_flags.is_some_and(is_syn_without_ack))
            .map(|packet| packet.source.clone())
            .collect();
        if syn_senders.len() == 1 {
            return (
                syn_senders.into_iter().next().expect("one SYN sender"),
                PacketFlowOriginBasisV0::UniqueSynWithoutAck,
            );
        }
        if packets[0].tcp_flags.is_some_and(is_syn_ack) {
            let originator = if packets[0].source == key.endpoint_a {
                key.endpoint_b.clone()
            } else {
                key.endpoint_a.clone()
            };
            return (originator, PacketFlowOriginBasisV0::InitialSynAckOpposite);
        }
    }
    let source = packets
        .iter()
        .min_by(|left, right| {
            left.frame_number
                .cmp(&right.frame_number)
                .then_with(|| left.source.cmp(&right.source))
        })
        .expect("flow segment is non-empty")
        .source
        .clone();
    (source, PacketFlowOriginBasisV0::LowestFrameSource)
}

fn end_basis(
    transport: TransportProtocolV0,
    packets: &[EligiblePacket],
    has_idle_successor: bool,
    partial: bool,
    quarantined: bool,
) -> PacketFlowEndBasisV0 {
    if has_idle_successor {
        return PacketFlowEndBasisV0::InactivityGap;
    }
    match (partial, quarantined) {
        (true, true) => return PacketFlowEndBasisV0::PartialAndQuarantinedCaptureBoundary,
        (true, false) => return PacketFlowEndBasisV0::PartialCaptureBoundary,
        (false, true) => return PacketFlowEndBasisV0::QuarantinedCaptureBoundary,
        (false, false) => {}
    }
    if transport == TransportProtocolV0::Tcp {
        if packets
            .iter()
            .any(|packet| packet.tcp_flags.is_some_and(|flags| flags & RST != 0))
        {
            return PacketFlowEndBasisV0::TcpResetObserved;
        }
        if packets
            .iter()
            .any(|packet| packet.tcp_flags.is_some_and(|flags| flags & FIN != 0))
        {
            return PacketFlowEndBasisV0::TcpFinObserved;
        }
    }
    PacketFlowEndBasisV0::CompleteCaptureBoundary
}

fn is_syn_without_ack(flags: u16) -> bool {
    flags & SYN != 0 && flags & ACK == 0
}

fn is_syn_ack(flags: u16) -> bool {
    flags & SYN != 0 && flags & ACK != 0
}

fn gap_exceeds(previous: i64, current: i64, threshold: u64) -> bool {
    current
        .checked_sub(previous)
        .and_then(|gap| u64::try_from(gap).ok())
        .is_some_and(|gap| gap > threshold)
}

fn increment(
    counts: &mut BTreeMap<PacketFlowExclusionReasonV0, u64>,
    reason: PacketFlowExclusionReasonV0,
    amount: u64,
) -> Result<(), PacketFlowProjectionError> {
    let count = counts.entry(reason).or_default();
    *count = checked_add(*count, amount)?;
    Ok(())
}

fn checked_add(left: u64, right: u64) -> Result<u64, PacketFlowProjectionError> {
    left.checked_add(right)
        .ok_or(PacketFlowProjectionError::CounterOverflow)
}

#[cfg(test)]
mod tests {
    use netbraid_evidence::{
        CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0, CaptureNormalizationV0,
        Ipv4FieldsV0, PacketFrameV0, PacketQuarantineV0, TcpFieldsV0, UdpFieldsV0,
        CAPTURE_MANIFEST_SCHEMA_V0, PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
    };

    use super::*;

    const CAPTURE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn policy(gap: u64) -> PacketFlowSessionizationV0 {
        PacketFlowSessionizationV0 {
            tcp_inactivity_ns: Some(gap),
            udp_inactivity_ns: Some(gap),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn tcp_packet(
        frame: u64,
        time: i64,
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        flags: u16,
        stream_index: Option<u32>,
        total_length_octets: Option<u32>,
    ) -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{CAPTURE_ID}:frame:{frame}"),
            capture_id: CAPTURE_ID.into(),
            frame: PacketFrameV0 {
                number: frame,
                event_time_unix_ns: time,
                original_len: 100,
                captured_len: 100,
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
                protocols: vec!["eth".into(), "ethertype".into(), "ip".into(), "tcp".into()],
            },
            ethernet: None,
            ipv4: Some(Ipv4FieldsV0 {
                source: source.into(),
                destination: destination.into(),
                protocol: 6,
                total_length_octets,
            }),
            ipv6: None,
            tcp: Some(TcpFieldsV0 {
                source_port,
                destination_port,
                flags,
                stream_index,
            }),
            udp: None,
            ieee802154: None,
            ieee80211: None,
            wlan_radio: None,
        }
    }

    fn udp_packet(
        frame: u64,
        time: i64,
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
    ) -> PacketEnvelopeV0 {
        let mut packet = tcp_packet(
            frame,
            time,
            source,
            source_port,
            destination,
            destination_port,
            0,
            None,
            Some(60),
        );
        packet.frame.protocols.pop();
        packet.frame.protocols.push("udp".into());
        packet.ipv4.as_mut().unwrap().protocol = 17;
        packet.tcp = None;
        packet.udp = Some(UdpFieldsV0 {
            source_port,
            destination_port,
        });
        packet
    }

    fn records(
        packets: Vec<PacketEnvelopeV0>,
        state: NormalizationStateV0,
        quarantines: Vec<PacketQuarantineV0>,
    ) -> SavedCaptureRecordStreamV0 {
        SavedCaptureRecordStreamV0 {
            manifest: CaptureManifestV0 {
                schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
                capture_id: CAPTURE_ID.into(),
                artifact: CaptureArtifactRefV0 {
                    content_sha256: CAPTURE_ID.into(),
                    size_bytes: 1,
                },
                observer_id: None,
                acquired_time_unix_ms: None,
                extractor: CaptureExtractorRefV0 {
                    adapter: "netbraid-adapter-tshark".into(),
                    adapter_version: "0.3.0".into(),
                    tool: "tshark".into(),
                    tool_version: "test".into(),
                    configuration_sha256: CAPTURE_ID.into(),
                    field_registry: "netmon.tshark.packet_envelope.v3".into(),
                },
                acquisition_policy: None,
                normalization: CaptureNormalizationV0 {
                    state,
                    packet_limit: 100,
                    packet_limit_reached: state == NormalizationStateV0::Partial,
                    packet_rows_emitted: u64::try_from(packets.len()).unwrap(),
                    packet_rows_quarantined: u64::try_from(quarantines.len()).unwrap(),
                },
            },
            receipt: None,
            packets,
            quarantines,
            normalized_records_sha256: CAPTURE_ID.into(),
        }
    }

    fn complete(packets: Vec<PacketEnvelopeV0>) -> SavedCaptureRecordStreamV0 {
        records(packets, NormalizationStateV0::Complete, Vec::new())
    }

    #[test]
    fn tcp_partitions_by_stream_and_observation_point_and_sums_ip_lengths() {
        let first = tcp_packet(
            1,
            1,
            "192.0.2.1",
            40_000,
            "198.51.100.2",
            443,
            SYN,
            Some(1),
            Some(60),
        );
        let reply = tcp_packet(
            2,
            2,
            "198.51.100.2",
            443,
            "192.0.2.1",
            40_000,
            SYN | ACK,
            Some(1),
            Some(52),
        );
        let reused = tcp_packet(
            3,
            3,
            "192.0.2.1",
            40_000,
            "198.51.100.2",
            443,
            SYN,
            Some(2),
            Some(44),
        );
        let mut other_interface = tcp_packet(
            4,
            4,
            "192.0.2.1",
            40_000,
            "198.51.100.2",
            443,
            ACK,
            Some(1),
            Some(40),
        );
        other_interface.frame.interface_id = Some(1);

        let report = project_saved_capture_flows_v0(
            &complete(vec![first, reply, reused, other_interface]),
            policy(100),
        )
        .unwrap();

        assert_eq!(report.packet_envelopes_grouped, 4);
        assert_eq!(report.flows.len(), 3);
        assert_eq!(report.flows[0].orig_packets, 1);
        assert_eq!(report.flows[0].orig_ip_bytes, 60);
        assert_eq!(report.flows[0].resp_packets, 1);
        assert_eq!(report.flows[0].resp_ip_bytes, 52);
        assert_eq!(
            report.flows[0].origin_basis,
            PacketFlowOriginBasisV0::UniqueSynWithoutAck
        );
    }

    #[test]
    fn inactivity_threshold_is_strict_for_udp_and_tcp() {
        let udp = vec![
            udp_packet(1, 0, "192.0.2.1", 50_000, "192.0.2.2", 53),
            udp_packet(2, 10, "192.0.2.2", 53, "192.0.2.1", 50_000),
            udp_packet(3, 21, "192.0.2.1", 50_000, "192.0.2.2", 53),
        ];
        let tcp = vec![
            tcp_packet(
                4,
                100,
                "192.0.2.3",
                40_000,
                "192.0.2.4",
                443,
                ACK,
                Some(7),
                Some(40),
            ),
            tcp_packet(
                5,
                110,
                "192.0.2.4",
                443,
                "192.0.2.3",
                40_000,
                ACK,
                Some(7),
                Some(40),
            ),
            tcp_packet(
                6,
                121,
                "192.0.2.3",
                40_000,
                "192.0.2.4",
                443,
                ACK,
                Some(7),
                Some(40),
            ),
        ];
        let report = project_saved_capture_flows_v0(
            &complete(udp.into_iter().chain(tcp).collect()),
            policy(10),
        )
        .unwrap();

        assert_eq!(report.flows.len(), 4);
        assert_eq!(
            report.flows[0].orig_packets + report.flows[0].resp_packets,
            2
        );
        assert_eq!(
            report.flows[0].end_basis,
            PacketFlowEndBasisV0::InactivityGap
        );
        assert_eq!(
            report.flows[2].orig_packets + report.flows[2].resp_packets,
            2
        );
        assert_eq!(
            report.flows[2].end_basis,
            PacketFlowEndBasisV0::InactivityGap
        );
    }

    #[test]
    fn fin_keeps_final_ack_and_rst_classifies_end() {
        let fin_flow = vec![
            tcp_packet(
                1,
                1,
                "192.0.2.1",
                40_000,
                "192.0.2.2",
                443,
                SYN,
                Some(1),
                Some(40),
            ),
            tcp_packet(
                2,
                2,
                "192.0.2.2",
                443,
                "192.0.2.1",
                40_000,
                SYN | ACK,
                Some(1),
                Some(40),
            ),
            tcp_packet(
                3,
                3,
                "192.0.2.1",
                40_000,
                "192.0.2.2",
                443,
                FIN | ACK,
                Some(1),
                Some(40),
            ),
            tcp_packet(
                4,
                4,
                "192.0.2.2",
                443,
                "192.0.2.1",
                40_000,
                ACK,
                Some(1),
                Some(40),
            ),
        ];
        let rst = tcp_packet(
            5,
            10,
            "192.0.2.3",
            50_000,
            "192.0.2.4",
            80,
            RST,
            Some(2),
            Some(40),
        );
        let report = project_saved_capture_flows_v0(
            &complete(fin_flow.into_iter().chain([rst]).collect()),
            policy(100),
        )
        .unwrap();

        assert_eq!(report.flows[0].end_time_unix_ns, 4);
        assert_eq!(report.flows[0].resp_packets, 2);
        assert_eq!(
            report.flows[0].end_basis,
            PacketFlowEndBasisV0::TcpFinObserved
        );
        assert_eq!(
            report.flows[1].end_basis,
            PacketFlowEndBasisV0::TcpResetObserved
        );
    }

    #[test]
    fn orientation_uses_syn_ack_then_lowest_frame_fallback() {
        let syn_ack = tcp_packet(
            10,
            1,
            "198.51.100.2",
            443,
            "192.0.2.1",
            40_000,
            SYN | ACK,
            Some(1),
            Some(40),
        );
        let later_low_frame = tcp_packet(
            2,
            3,
            "192.0.2.3",
            30_000,
            "192.0.2.4",
            53,
            ACK,
            Some(2),
            Some(40),
        );
        let earlier_high_frame = tcp_packet(
            20,
            2,
            "192.0.2.4",
            53,
            "192.0.2.3",
            30_000,
            ACK,
            Some(2),
            Some(40),
        );
        let report = project_saved_capture_flows_v0(
            &complete(vec![earlier_high_frame, syn_ack, later_low_frame]),
            policy(100),
        )
        .unwrap();

        assert_eq!(report.flows[0].originator.address.to_string(), "192.0.2.1");
        assert_eq!(
            report.flows[0].origin_basis,
            PacketFlowOriginBasisV0::InitialSynAckOpposite
        );
        assert_eq!(report.flows[1].originator.address.to_string(), "192.0.2.3");
        assert_eq!(
            report.flows[1].origin_basis,
            PacketFlowOriginBasisV0::LowestFrameSource
        );
    }

    #[test]
    fn permutation_produces_identical_report() {
        let packets = vec![
            tcp_packet(
                3,
                3,
                "192.0.2.1",
                40_000,
                "192.0.2.2",
                443,
                ACK,
                Some(1),
                Some(50),
            ),
            tcp_packet(
                1,
                1,
                "192.0.2.1",
                40_000,
                "192.0.2.2",
                443,
                SYN,
                Some(1),
                Some(60),
            ),
            tcp_packet(
                2,
                2,
                "192.0.2.2",
                443,
                "192.0.2.1",
                40_000,
                SYN | ACK,
                Some(1),
                Some(40),
            ),
        ];
        let mut reversed = packets.clone();
        reversed.reverse();

        assert_eq!(
            project_saved_capture_flows_v0(&complete(packets), policy(100)).unwrap(),
            project_saved_capture_flows_v0(&complete(reversed), policy(100)).unwrap()
        );
    }

    #[test]
    fn partial_and_quarantined_capture_never_claims_protocol_closure() {
        let packet = tcp_packet(
            1,
            1,
            "192.0.2.1",
            40_000,
            "192.0.2.2",
            443,
            RST,
            Some(1),
            Some(40),
        );
        let quarantine = PacketQuarantineV0 {
            schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
            capture_id: CAPTURE_ID.into(),
            source_line: 2,
            frame_number_hint: Some(2),
            reason: "synthetic malformed row".into(),
            raw_row: "private row omitted from projection".into(),
        };
        let report = project_saved_capture_flows_v0(
            &records(
                vec![packet],
                NormalizationStateV0::Partial,
                vec![quarantine],
            ),
            policy(100),
        )
        .unwrap();

        assert_eq!(
            report.flows[0].end_basis,
            PacketFlowEndBasisV0::PartialAndQuarantinedCaptureBoundary
        );
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::PartialNormalization],
            1
        );
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::QuarantinedPacketRow],
            1
        );
    }

    #[test]
    fn legacy_missing_fields_are_excluded_without_projection_error() {
        let missing_length = tcp_packet(
            1,
            1,
            "192.0.2.1",
            40_000,
            "192.0.2.2",
            443,
            SYN,
            Some(1),
            None,
        );
        let missing_stream = tcp_packet(
            2,
            2,
            "192.0.2.3",
            40_000,
            "192.0.2.4",
            443,
            SYN,
            None,
            Some(40),
        );
        let report = project_saved_capture_flows_v0(
            &complete(vec![missing_length, missing_stream]),
            policy(100),
        )
        .unwrap();

        assert!(report.flows.is_empty());
        assert_eq!(report.packet_envelopes_excluded, 2);
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::MissingIpTotalLength],
            1
        );
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::MissingTcpStreamIndex],
            1
        );
    }

    #[test]
    fn nested_tunnel_and_fragment_ambiguity_are_counted() {
        let mut nested = tcp_packet(
            1,
            1,
            "192.0.2.1",
            40_000,
            "192.0.2.2",
            443,
            SYN,
            Some(1),
            Some(40),
        );
        nested.frame.protocols.insert(3, "ip".into());
        let mut tunnel = tcp_packet(
            2,
            2,
            "192.0.2.1",
            40_000,
            "192.0.2.2",
            443,
            SYN,
            Some(1),
            Some(40),
        );
        tunnel.frame.protocols.insert(3, "vxlan".into());
        let mut fragment = tcp_packet(
            3,
            3,
            "192.0.2.1",
            40_000,
            "192.0.2.2",
            443,
            SYN,
            Some(1),
            Some(40),
        );
        fragment.frame.protocols.insert(3, "ip.fragment".into());
        let report =
            project_saved_capture_flows_v0(&complete(vec![nested, tunnel, fragment]), policy(100))
                .unwrap();

        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::AmbiguousNetworkLayer],
            1
        );
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::UnmodeledEncapsulation],
            1
        );
        assert_eq!(
            report.exclusions[&PacketFlowExclusionReasonV0::FragmentedOrIncompleteTransport],
            1
        );
    }
}
