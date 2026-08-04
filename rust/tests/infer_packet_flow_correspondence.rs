use netbraid::infer::{
    infer_packet_flow_correspondence_v0, FlowRecordProtocolV0, FlowRecordV0,
    PacketFlowCorrespondenceDispositionV0, PacketFlowCorrespondenceOptionsV0,
    PACKET_FLOW_CORRESPONDENCE_HEURISTIC_PROFILE_V0,
};
use netbraid::replay::{
    ConversationEndpointV0, IpFamilyV0, ObservationPointV0, PacketFlowEndBasisV0,
    PacketFlowOriginBasisV0, PacketFlowV0, TransportProtocolV0,
};

fn endpoint(address: &str, port: u16) -> ConversationEndpointV0 {
    ConversationEndpointV0 {
        address: address.parse().unwrap(),
        port,
    }
}

#[test]
fn public_flow_record_api_infers_without_an_adapter() {
    let originator = endpoint("192.0.2.1", 1234);
    let responder = endpoint("198.51.100.2", 443);
    let packet = PacketFlowV0 {
        ip_family: IpFamilyV0::Ipv4,
        transport: TransportProtocolV0::Tcp,
        observation_point: ObservationPointV0 {
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(1),
        },
        originator: originator.clone(),
        responder: responder.clone(),
        start_time_unix_ns: 1_000_000_000,
        end_time_unix_ns: 1_100_000_000,
        orig_packets: 3,
        orig_ip_bytes: 300,
        resp_packets: 2,
        resp_ip_bytes: 200,
        origin_basis: PacketFlowOriginBasisV0::UniqueSynWithoutAck,
        end_basis: PacketFlowEndBasisV0::CompleteCaptureBoundary,
    };
    let record = FlowRecordV0::new(
        1_000_000_000,
        originator,
        responder,
        FlowRecordProtocolV0::Tcp,
        Some(100_000_000),
        Some(3),
        Some(300),
        Some(2),
        Some(200),
    );

    let report = infer_packet_flow_correspondence_v0(
        &[packet],
        &[record],
        &PacketFlowCorrespondenceOptionsV0::default(),
    )
    .unwrap();

    assert_eq!(
        report.heuristic_profile,
        PACKET_FLOW_CORRESPONDENCE_HEURISTIC_PROFILE_V0
    );
    assert_eq!(report.candidate_edges, 1);
    let edge = &report.components[0].edges[0];
    assert_eq!(edge.packet_flow_index(), 0);
    assert_eq!(edge.flow_record_index(), 0);
    assert_eq!(
        edge.marginal_disposition(),
        PacketFlowCorrespondenceDispositionV0::Corresponds
    );
}
