#![cfg(feature = "adapter-zeek")]

use netbraid::adapters::zeek::{project_zeek_conn_log, ZeekConnOptions};
use netbraid::infer::{
    infer_packet_zeek_correspondence_v0, PacketZeekCorrespondenceOptionsV0,
    PacketZeekCorrespondenceReportV0,
};
use netbraid::replay::{
    ConversationEndpointV0, IpFamilyV0, ObservationPointV0, PacketFlowEndBasisV0,
    PacketFlowOriginBasisV0, PacketFlowV0, TransportProtocolV0,
};

/// One conn.log row for a lone TCP SYN from 192.0.2.10:40000 to
/// 198.51.100.53:443 at t = 1 s, with the given `duration` field, correlated
/// against a packet flow with exactly matching counters.
fn correspond_lone_syn(duration: &str) -> PacketZeekCorrespondenceReportV0 {
    let source = format!(
        "#separator \\x09\n\
        #set_separator\t,\n\
        #empty_field\t(empty)\n\
        #unset_field\t-\n\
        #path\tconn\n\
        #fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n\
        #types\ttime\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tcount\tcount\n\
        1.000000000\t192.0.2.10\t40000\t198.51.100.53\t443\ttcp\t{duration}\t1\t60\t0\t0\n"
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("conn.log");
    std::fs::write(&path, source).unwrap();
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
            address: "192.0.2.10".parse().unwrap(),
            port: 40000,
        },
        responder: ConversationEndpointV0 {
            address: "198.51.100.53".parse().unwrap(),
            port: 443,
        },
        start_time_unix_ns: 1_000_000_000,
        end_time_unix_ns: 1_000_000_000,
        orig_packets: 1,
        orig_ip_bytes: 60,
        resp_packets: 0,
        resp_ip_bytes: 0,
        // A lone SYN: the packet reducer orients it by UniqueSynWithoutAck.
        origin_basis: PacketFlowOriginBasisV0::UniqueSynWithoutAck,
        end_basis: PacketFlowEndBasisV0::CompleteCaptureBoundary,
    };

    infer_packet_zeek_correspondence_v0(
        &[packet],
        &stream,
        &PacketZeekCorrespondenceOptionsV0::default(),
    )
    .unwrap()
}

/// Zeek `base/protocols/conn/main.zeek` (`set_conn`) assigns
/// `c$conn$duration` only when `c$duration > 0secs`, so an unset `duration`
/// in conn.log means a zero-length connection (for example a single TCP SYN
/// that was never answered, Zeek state S0), not an unknown interval. Such a
/// row must be admitted as a point at its start time.
#[test]
fn zeek_zero_duration_connection_is_admitted() {
    let report = correspond_lone_syn("-");
    assert_eq!(
        report.candidate_edges, 1,
        "zero-duration Zeek row (unset duration) got no candidate edge"
    );
}

/// Control: the same row with an explicit zero duration is admitted, so
/// only the unset sentinel differs.
#[test]
fn zeek_explicit_zero_duration_is_admitted() {
    let report = correspond_lone_syn("0.000000000");
    assert_eq!(report.candidate_edges, 1);
}
