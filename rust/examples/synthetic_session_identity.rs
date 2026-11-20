//! Run from rust/ with cargo run --locked --example synthetic_session_identity.
use netbraid::infer::{
    infer_packet_flow_correspondence_v0, FlowRecordProtocolV0, FlowRecordV0,
    PacketFlowCorrespondenceComponentOutcomeV0, PacketFlowCorrespondenceDispositionV0,
    PacketFlowCorrespondenceOptionsV0,
};
use netbraid::replay::{
    ConversationEndpointV0, IpFamilyV0, ObservationPointV0, PacketFlowEndBasisV0,
    PacketFlowOriginBasisV0, PacketFlowV0, TransportProtocolV0,
};
use std::cmp::Ordering;

const SECOND: i64 = 1_000_000_000;

#[derive(Clone, Copy, Debug)]
enum Counters {
    CompleteDistinct,
    IncompleteDistinct,
    IncompleteCollision,
    CompleteEqual,
}

#[derive(Clone, Copy, Debug)]
enum Clock {
    CommonBucket,
    Padded,
}

struct Session {
    id: u32,
    start: i64,
    // A transaction has this many request/reply pairs, 84/104 IP octets each.
    pairs: u64,
}

fn record(session: &Session, clock: Clock, epoch: i64, packet: &PacketFlowV0) -> FlowRecordV0 {
    let (start, end) = match clock {
        Clock::CommonBucket => (epoch, epoch + 240 * SECOND),
        Clock::Padded => (session.start - 70 * SECOND, session.start + 71 * SECOND),
    };
    FlowRecordV0::new(
        start,
        packet.originator.clone(),
        packet.responder.clone(),
        FlowRecordProtocolV0::Tcp,
        Some((end - start).try_into().unwrap()),
        Some(session.pairs),
        Some(84 * session.pairs),
        Some(session.pairs),
        Some(104 * session.pairs),
    )
}

// Return the distance between doubled midpoints only for a matching tuple and window.
fn tuple_time(packet: &PacketFlowV0, record: &FlowRecordV0, tolerance: u64) -> Option<u128> {
    let start = i128::from(record.start_time_unix_ns());
    let end = start + i128::from(record.duration_ns()?);
    let first = i128::from(packet.start_time_unix_ns);
    let last = i128::from(packet.end_time_unix_ns);
    let matches = packet.transport == TransportProtocolV0::Tcp
        && record.protocol() == FlowRecordProtocolV0::Tcp
        && packet.originator == *record.originator()
        && packet.responder == *record.responder()
        && first <= end + i128::from(tolerance)
        && last >= start - i128::from(tolerance);
    matches.then(|| (first + last).abs_diff(start + end))
}

fn run(group: u32, clock: Clock, regime: Counters, query_slot: usize) {
    let base = 10 + u64::from(group);
    let other = if query_slot == 0 { base - 4 } else { base + 5 };
    let (query_pairs, lost_interior_pairs, other_pairs) = match regime {
        Counters::CompleteDistinct => (base, 0, other),
        Counters::IncompleteDistinct => (base, 2, other),
        Counters::IncompleteCollision => (base + 3, 3, base),
        Counters::CompleteEqual => (base, 0, base),
    };
    let epoch = SECOND * (1_000 + 300 * i64::from(group));
    let sessions = [0, 1].map(|slot| Session {
        id: 2 * group + slot as u32,
        start: epoch + (80 + 60 * slot as i64) * SECOND,
        pairs: if slot == query_slot {
            query_pairs
        } else {
            other_pairs
        },
    });
    let query = &sessions[query_slot];
    let seen = query.pairs - lost_interior_pairs;
    let packet = PacketFlowV0 {
        ip_family: IpFamilyV0::Ipv4,
        transport: TransportProtocolV0::Tcp,
        observation_point: ObservationPointV0 {
            section_number: Some(0),
            interface_id: Some(0),
            encapsulation_type: Some(1),
        },
        originator: ConversationEndpointV0 {
            address: [192, 0, 2, 1].into(),
            port: 12_000 + group as u16,
        },
        responder: ConversationEndpointV0 {
            address: [198, 51, 100, 2].into(),
            port: 443,
        },
        start_time_unix_ns: query.start,
        end_time_unix_ns: query.start + SECOND,
        orig_packets: seen,
        orig_ip_bytes: 84 * seen,
        resp_packets: seen,
        resp_ip_bytes: 104 * seen,
        origin_basis: PacketFlowOriginBasisV0::UniqueSynWithoutAck,
        end_basis: PacketFlowEndBasisV0::TcpFinObserved,
    };

    let records = sessions
        .each_ref()
        .map(|s| record(s, clock, epoch, &packet));
    let options = PacketFlowCorrespondenceOptionsV0::default();
    let distances = records
        .each_ref()
        .map(|r| tuple_time(&packet, r, options.candidate_tolerance_ns));
    assert!(distances.iter().all(Option::is_some));
    let report = infer_packet_flow_correspondence_v0(&[packet], &records, &options).unwrap();
    assert_eq!(report.candidate_edges, 2);
    assert_eq!(report.components.len(), 1);
    let component = &report.components[0];
    assert!(matches!(
        component.outcome,
        PacketFlowCorrespondenceComponentOutcomeV0::Exact { .. }
    ));
    let mut scored = [None; 2];
    for edge in &component.edges {
        assert_eq!(edge.packet_flow_index(), 0);
        assert!(scored[edge.flow_record_index()].replace(edge).is_none());
    }

    let same = sessions.iter().position(|s| s.id == query.id).unwrap();
    let different = 1 - same;
    let [positive, negative] = [same, different].map(|i| scored[i].unwrap());
    let score_rank = positive
        .corresponds_relative_belief_ppb()
        .cmp(&negative.corresponds_relative_belief_ppb());
    let time_rank = distances[different].unwrap().cmp(&distances[same].unwrap());
    let rank = |ordering| match ordering {
        Ordering::Greater => "win",
        Ordering::Equal => "tie",
        Ordering::Less => "loss",
    };
    let call = |d| match d {
        PacketFlowCorrespondenceDispositionV0::Corresponds => "yes",
        PacketFlowCorrespondenceDispositionV0::DoesNotCorrespond => "no",
        PacketFlowCorrespondenceDispositionV0::Tied => "tie",
        _ => panic!("unexpected marginal disposition"),
    };
    if matches!(
        (clock, regime),
        (Clock::CommonBucket, Counters::CompleteEqual)
    ) {
        assert_eq!(records[0], records[1]);
        assert_eq!(score_rank, Ordering::Equal);
        assert_eq!(time_rank, Ordering::Equal);
    }
    println!(
        "{group}\t{clock:?}\t{regime:?}\t{query_slot}\t{}\t{}\t{}\t{}\t{}\t{}",
        positive.corresponds_relative_belief_ppb(),
        negative.corresponds_relative_belief_ppb(),
        call(positive.marginal_disposition()),
        call(negative.marginal_disposition()),
        rank(score_rank),
        rank(time_rank)
    );
}

fn main() {
    println!("group\tclock\tcounters\tquery_slot\tsame_ppb\tother_ppb\tsame_call\tother_call\tscore_rank\ttime_rank");
    let mut group = 0;
    for clock in [Clock::CommonBucket, Clock::Padded] {
        for regime in [
            Counters::CompleteDistinct,
            Counters::IncompleteDistinct,
            Counters::IncompleteCollision,
            Counters::CompleteEqual,
        ] {
            for slot in 0..2 {
                run(group, clock, regime, slot);
                group += 1;
            }
        }
    }
}
