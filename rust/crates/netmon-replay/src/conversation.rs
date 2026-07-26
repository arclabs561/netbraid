use std::collections::BTreeMap;
use std::net::IpAddr;

use netmon_evidence::PacketEnvelopeV0;

const UNMODELED_ENCAPSULATION_PROTOCOLS: &[&str] = &[
    "geneve",
    "gre",
    "gtp",
    "gtpv2",
    "ieee8021ad",
    "l2tp",
    "mpls",
    "mpls_pw",
    "pppoes",
    "teredo",
    "vlan",
    "vxlan",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpFamilyV0 {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportProtocolV0 {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ConversationEndpointV0 {
    pub address: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ObservationPointV0 {
    pub section_number: Option<u32>,
    pub interface_id: Option<u32>,
    pub encapsulation_type: Option<i16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CaptureConversationKeyV0 {
    pub capture_id: String,
    pub observation_point: ObservationPointV0,
    pub ip_family: IpFamilyV0,
    pub transport: TransportProtocolV0,
    pub endpoint_a: ConversationEndpointV0,
    pub endpoint_b: ConversationEndpointV0,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TcpFlagCountsV0 {
    pub syn_without_ack_frames: u64,
    pub syn_ack_frames: u64,
    pub fin_frames: u64,
    pub rst_frames: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConversationDirectionV0 {
    pub frames: u64,
    pub original_frame_octets: u64,
    pub captured_frame_octets: u64,
    pub tcp_flags: Option<TcpFlagCountsV0>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConversationV0 {
    pub key: CaptureConversationKeyV0,
    pub earliest_event_time_unix_ns: i64,
    pub latest_event_time_unix_ns: i64,
    pub a_to_b: ConversationDirectionV0,
    pub b_to_a: ConversationDirectionV0,
}

impl CaptureConversationV0 {
    pub fn total_frames(&self) -> u64 {
        self.a_to_b.frames + self.b_to_a.frames
    }

    pub fn total_original_frame_octets(&self) -> u64 {
        self.a_to_b.original_frame_octets + self.b_to_a.original_frame_octets
    }

    pub fn total_captured_frame_octets(&self) -> u64 {
        self.a_to_b.captured_frame_octets + self.b_to_a.captured_frame_octets
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConversationExclusionReasonV0 {
    InvalidPacketEnvelope,
    UnmodeledEncapsulation,
    AmbiguousNetworkLayer,
    AmbiguousTransportLayer,
    IndistinguishableEndpoints,
}

impl ConversationExclusionReasonV0 {
    pub fn label(self) -> &'static str {
        match self {
            Self::InvalidPacketEnvelope => "invalid packet envelope",
            Self::UnmodeledEncapsulation => "unmodeled partition or encapsulation",
            Self::AmbiguousNetworkLayer => "missing or ambiguous IP layer",
            Self::AmbiguousTransportLayer => "missing or ambiguous TCP/UDP layer",
            Self::IndistinguishableEndpoints => "identical source/destination endpoint",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureConversationReportV0 {
    pub packet_envelopes_seen: u64,
    pub packet_envelopes_grouped: u64,
    pub packet_envelopes_excluded: u64,
    pub exclusions: BTreeMap<ConversationExclusionReasonV0, u64>,
    pub conversations: Vec<CaptureConversationV0>,
}

pub fn reduce_capture_conversations(packets: &[PacketEnvelopeV0]) -> CaptureConversationReportV0 {
    let mut conversations = BTreeMap::<CaptureConversationKeyV0, CaptureConversationV0>::new();
    let mut exclusions = BTreeMap::new();
    let mut grouped = 0_u64;

    for packet in packets {
        let candidate = match candidate(packet) {
            Ok(candidate) => candidate,
            Err(reason) => {
                *exclusions.entry(reason).or_default() += 1;
                continue;
            }
        };
        grouped += 1;
        let conversation = conversations
            .entry(candidate.key.clone())
            .or_insert_with(|| CaptureConversationV0 {
                key: candidate.key,
                earliest_event_time_unix_ns: packet.frame.event_time_unix_ns,
                latest_event_time_unix_ns: packet.frame.event_time_unix_ns,
                a_to_b: direction(candidate.transport),
                b_to_a: direction(candidate.transport),
            });
        conversation.earliest_event_time_unix_ns = conversation
            .earliest_event_time_unix_ns
            .min(packet.frame.event_time_unix_ns);
        conversation.latest_event_time_unix_ns = conversation
            .latest_event_time_unix_ns
            .max(packet.frame.event_time_unix_ns);
        let direction = if candidate.source_is_a {
            &mut conversation.a_to_b
        } else {
            &mut conversation.b_to_a
        };
        direction.frames += 1;
        direction.original_frame_octets += u64::from(packet.frame.original_len);
        direction.captured_frame_octets += u64::from(packet.frame.captured_len);
        if let (Some(counts), Some(tcp)) = (&mut direction.tcp_flags, &packet.tcp) {
            count_tcp_flags(counts, tcp.flags);
        }
    }

    let mut conversations: Vec<_> = conversations.into_values().collect();
    conversations.sort_by(|left, right| {
        right
            .total_original_frame_octets()
            .cmp(&left.total_original_frame_octets())
            .then_with(|| right.total_frames().cmp(&left.total_frames()))
            .then_with(|| left.key.cmp(&right.key))
    });
    let seen = u64::try_from(packets.len()).unwrap_or(u64::MAX);
    CaptureConversationReportV0 {
        packet_envelopes_seen: seen,
        packet_envelopes_grouped: grouped,
        packet_envelopes_excluded: seen.saturating_sub(grouped),
        exclusions,
        conversations,
    }
}

struct Candidate {
    key: CaptureConversationKeyV0,
    transport: TransportProtocolV0,
    source_is_a: bool,
}

fn candidate(packet: &PacketEnvelopeV0) -> Result<Candidate, ConversationExclusionReasonV0> {
    if packet.validate().is_err() {
        return Err(ConversationExclusionReasonV0::InvalidPacketEnvelope);
    }
    if packet
        .frame
        .protocols
        .iter()
        .any(|protocol| UNMODELED_ENCAPSULATION_PROTOCOLS.contains(&protocol.as_str()))
    {
        return Err(ConversationExclusionReasonV0::UnmodeledEncapsulation);
    }

    let (ip_family, source_address, destination_address) = match (&packet.ipv4, &packet.ipv6) {
        (Some(ipv4), None)
            if protocol_count(packet, "ip") == 1 && protocol_count(packet, "ipv6") == 0 =>
        {
            (
                IpFamilyV0::Ipv4,
                IpAddr::V4(ipv4.source.parse().expect("validated IPv4 source")),
                IpAddr::V4(
                    ipv4.destination
                        .parse()
                        .expect("validated IPv4 destination"),
                ),
            )
        }
        (None, Some(ipv6))
            if protocol_count(packet, "ipv6") == 1 && protocol_count(packet, "ip") == 0 =>
        {
            (
                IpFamilyV0::Ipv6,
                IpAddr::V6(ipv6.source.parse().expect("validated IPv6 source")),
                IpAddr::V6(
                    ipv6.destination
                        .parse()
                        .expect("validated IPv6 destination"),
                ),
            )
        }
        _ => return Err(ConversationExclusionReasonV0::AmbiguousNetworkLayer),
    };
    let (transport, source_port, destination_port) = match (&packet.tcp, &packet.udp) {
        (Some(tcp), None)
            if protocol_count(packet, "tcp") == 1 && protocol_count(packet, "udp") == 0 =>
        {
            (
                TransportProtocolV0::Tcp,
                tcp.source_port,
                tcp.destination_port,
            )
        }
        (None, Some(udp))
            if protocol_count(packet, "udp") == 1 && protocol_count(packet, "tcp") == 0 =>
        {
            (
                TransportProtocolV0::Udp,
                udp.source_port,
                udp.destination_port,
            )
        }
        _ => return Err(ConversationExclusionReasonV0::AmbiguousTransportLayer),
    };

    let source = ConversationEndpointV0 {
        address: source_address,
        port: source_port,
    };
    let destination = ConversationEndpointV0 {
        address: destination_address,
        port: destination_port,
    };
    if source == destination {
        return Err(ConversationExclusionReasonV0::IndistinguishableEndpoints);
    }
    let (endpoint_a, endpoint_b, source_is_a) = if source <= destination {
        (source, destination, true)
    } else {
        (destination, source, false)
    };
    Ok(Candidate {
        key: CaptureConversationKeyV0 {
            capture_id: packet.capture_id.clone(),
            observation_point: ObservationPointV0 {
                section_number: packet.frame.section_number,
                interface_id: packet.frame.interface_id,
                encapsulation_type: packet.frame.encapsulation_type,
            },
            ip_family,
            transport,
            endpoint_a,
            endpoint_b,
        },
        transport,
        source_is_a,
    })
}

fn protocol_count(packet: &PacketEnvelopeV0, name: &str) -> usize {
    packet
        .frame
        .protocols
        .iter()
        .filter(|protocol| protocol.as_str() == name)
        .count()
}

fn direction(transport: TransportProtocolV0) -> ConversationDirectionV0 {
    ConversationDirectionV0 {
        tcp_flags: (transport == TransportProtocolV0::Tcp).then(TcpFlagCountsV0::default),
        ..ConversationDirectionV0::default()
    }
}

fn count_tcp_flags(counts: &mut TcpFlagCountsV0, flags: u16) {
    const FIN: u16 = 0x0001;
    const SYN: u16 = 0x0002;
    const RST: u16 = 0x0004;
    const ACK: u16 = 0x0010;

    if flags & SYN != 0 {
        if flags & ACK != 0 {
            counts.syn_ack_frames += 1;
        } else {
            counts.syn_without_ack_frames += 1;
        }
    }
    if flags & FIN != 0 {
        counts.fin_frames += 1;
    }
    if flags & RST != 0 {
        counts.rst_frames += 1;
    }
}

#[cfg(test)]
mod tests {
    use netmon_evidence::{
        EthernetFieldsV0, Ipv4FieldsV0, Ipv6FieldsV0, PacketFrameV0, TcpFieldsV0, UdpFieldsV0,
        PACKET_ENVELOPE_SCHEMA_V0,
    };

    use super::*;

    const CAPTURE_ID: &str =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn tcp_packet(
        frame: u64,
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        flags: u16,
    ) -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{CAPTURE_ID}:frame:{frame}"),
            capture_id: CAPTURE_ID.into(),
            frame: PacketFrameV0 {
                number: frame,
                event_time_unix_ns: 1_000 + i64::try_from(frame).unwrap(),
                original_len: 74,
                captured_len: 70,
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
                protocols: vec!["eth".into(), "ethertype".into(), "ip".into(), "tcp".into()],
            },
            ethernet: Some(EthernetFieldsV0 {
                source: Some("02:00:00:00:00:01".into()),
                destination: Some("02:00:00:00:00:02".into()),
            }),
            ipv4: Some(Ipv4FieldsV0 {
                source: source.into(),
                destination: destination.into(),
                protocol: 6,
            }),
            ipv6: None,
            tcp: Some(TcpFieldsV0 {
                source_port,
                destination_port,
                flags,
            }),
            udp: None,
            ieee80211: None,
            wlan_radio: None,
        }
    }

    fn udp_packet(
        frame: u64,
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
    ) -> PacketEnvelopeV0 {
        let mut packet = tcp_packet(frame, source, source_port, destination, destination_port, 0);
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

    fn ipv6_tcp_packet(
        frame: u64,
        source: &str,
        source_port: u16,
        destination: &str,
        destination_port: u16,
        flags: u16,
    ) -> PacketEnvelopeV0 {
        let mut packet = tcp_packet(
            frame,
            "192.0.2.1",
            source_port,
            "198.51.100.2",
            destination_port,
            flags,
        );
        packet.frame.protocols[2] = "ipv6".into();
        packet.ipv4 = None;
        packet.ipv6 = Some(Ipv6FieldsV0 {
            source: source.into(),
            destination: destination.into(),
            next_header: 6,
        });
        packet
    }

    #[test]
    fn opposite_directions_share_one_canonical_conversation() {
        let forward = tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x002);
        let reverse = tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x012);
        let report = reduce_capture_conversations(&[reverse.clone(), forward.clone()]);

        assert_eq!(report.packet_envelopes_grouped, 2);
        assert_eq!(report.packet_envelopes_excluded, 0);
        assert_eq!(report.conversations.len(), 1);
        let conversation = &report.conversations[0];
        assert_eq!(conversation.a_to_b.frames, 1);
        assert_eq!(conversation.b_to_a.frames, 1);
        assert_eq!(conversation.a_to_b.original_frame_octets, 74);
        assert_eq!(conversation.b_to_a.captured_frame_octets, 70);
        assert_eq!(
            conversation
                .a_to_b
                .tcp_flags
                .as_ref()
                .unwrap()
                .syn_without_ack_frames,
            1
        );
        assert_eq!(
            conversation
                .b_to_a
                .tcp_flags
                .as_ref()
                .unwrap()
                .syn_ack_frames,
            1
        );

        let ordered = reduce_capture_conversations(&[forward, reverse]);
        assert_eq!(report, ordered);
    }

    #[test]
    fn observation_points_do_not_merge() {
        let first = tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x002);
        let mut interface = tcp_packet(2, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x010);
        interface.frame.interface_id = Some(1);
        let mut section = tcp_packet(3, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x010);
        section.frame.section_number = Some(1);
        let mut encapsulation = tcp_packet(4, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x010);
        encapsulation.frame.encapsulation_type = Some(113);

        let report = reduce_capture_conversations(&[first, interface, section, encapsulation]);
        assert_eq!(report.conversations.len(), 4);
    }

    #[test]
    fn udp_uses_directional_counters_without_tcp_state() {
        let forward = udp_packet(1, "192.0.2.10", 53_000, "192.0.2.53", 53);
        let reverse = udp_packet(2, "192.0.2.53", 53, "192.0.2.10", 53_000);

        let report = reduce_capture_conversations(&[forward, reverse]);
        let conversation = &report.conversations[0];
        assert_eq!(conversation.a_to_b.frames, 1);
        assert_eq!(conversation.b_to_a.frames, 1);
        assert_eq!(conversation.a_to_b.tcp_flags, None);
        assert_eq!(conversation.b_to_a.tcp_flags, None);
    }

    #[test]
    fn ipv6_endpoints_share_the_same_canonical_conversation() {
        let forward = ipv6_tcp_packet(1, "2001:db8::1", 40_000, "2001:db8::2", 443, 0x002);
        let reverse = ipv6_tcp_packet(2, "2001:db8::2", 443, "2001:db8::1", 40_000, 0x012);

        let report = reduce_capture_conversations(&[forward, reverse]);
        assert_eq!(report.packet_envelopes_seen, 2);
        assert_eq!(report.packet_envelopes_grouped, 2);
        assert_eq!(report.packet_envelopes_excluded, 0);
        assert!(report.exclusions.is_empty());
        assert_eq!(report.conversations.len(), 1);
        let conversation = &report.conversations[0];
        assert_eq!(conversation.key.ip_family, IpFamilyV0::Ipv6);
        assert_eq!(
            conversation.key.endpoint_a.address,
            "2001:db8::1".parse::<IpAddr>().unwrap()
        );
        assert_eq!(
            conversation.key.endpoint_b.address,
            "2001:db8::2".parse::<IpAddr>().unwrap()
        );
        assert_eq!(conversation.a_to_b.frames, 1);
        assert_eq!(conversation.b_to_a.frames, 1);
    }

    #[test]
    fn ranking_and_reduction_are_input_order_independent() {
        let mut packets = vec![
            tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x002),
            tcp_packet(2, "198.51.100.2", 443, "192.0.2.1", 40_000, 0x012),
            tcp_packet(3, "192.0.2.10", 50_000, "198.51.100.20", 80, 0x002),
        ];
        let forward = reduce_capture_conversations(&packets);
        packets.reverse();
        let reverse = reduce_capture_conversations(&packets);

        assert_eq!(forward, reverse);
        assert_eq!(forward.conversations[0].total_original_frame_octets(), 148);
        assert_eq!(forward.conversations[1].total_original_frame_octets(), 74);
    }

    #[test]
    fn encapsulations_and_repeated_network_layers_are_explicit_exclusions() {
        let mut vlan = tcp_packet(1, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x002);
        vlan.frame.protocols.insert(2, "vlan".into());
        let mut tunnel = tcp_packet(2, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x010);
        tunnel.frame.protocols.insert(3, "ip".into());
        let mut mpls = tcp_packet(3, "192.0.2.1", 40_000, "198.51.100.2", 443, 0x010);
        mpls.frame.protocols.insert(2, "mpls".into());

        let report = reduce_capture_conversations(&[vlan, tunnel, mpls]);
        assert_eq!(report.packet_envelopes_grouped, 0);
        assert_eq!(
            report.exclusions[&ConversationExclusionReasonV0::UnmodeledEncapsulation],
            2
        );
        assert_eq!(
            report.exclusions[&ConversationExclusionReasonV0::AmbiguousNetworkLayer],
            1
        );
    }

    #[test]
    fn identical_endpoints_do_not_invent_direction() {
        let packet = tcp_packet(1, "192.0.2.1", 443, "192.0.2.1", 443, 0x010);
        let report = reduce_capture_conversations(&[packet]);

        assert_eq!(report.conversations.len(), 0);
        assert_eq!(
            report.exclusions[&ConversationExclusionReasonV0::IndistinguishableEndpoints],
            1
        );
    }
}
