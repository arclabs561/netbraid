//! Read the pairs emitted by eval/project-zeek-echo.py and report aggregate ranks.
use netbraid::infer::{
    infer_packet_flow_correspondence_v0, FlowRecordProtocolV0, FlowRecordV0,
    PacketFlowCorrespondenceComponentOutcomeV0, PacketFlowCorrespondenceOptionsV0,
};
use netbraid::replay::{
    ConversationEndpointV0, IpFamilyV0, ObservationPointV0, PacketFlowEndBasisV0,
    PacketFlowOriginBasisV0, PacketFlowV0, TransportProtocolV0,
};
use serde::Deserialize;
use std::cmp::{Ordering, Reverse};
use std::io::{self, BufRead};

#[derive(Deserialize)]
struct View {
    label: Option<u32>,
    basis: String,
    end: String,
    first: i64,
    last: i64,
    counters: [u64; 4],
}

#[derive(Deserialize)]
struct Pair {
    complete: [View; 2],
    thinned: [View; 2],
}

fn client(slot: usize) -> ConversationEndpointV0 {
    ConversationEndpointV0 {
        address: [192, 0, 2, 1].into(),
        port: 40000 + slot as u16,
    }
}

fn server() -> ConversationEndpointV0 {
    ConversationEndpointV0 {
        address: [198, 51, 100, 2].into(),
        port: 7000,
    }
}

impl View {
    fn flow(&self, port_slot: usize) -> PacketFlowV0 {
        let [orig_packets, orig_ip_bytes, resp_packets, resp_ip_bytes] = self.counters;
        PacketFlowV0 {
            ip_family: IpFamilyV0::Ipv4,
            transport: TransportProtocolV0::Tcp,
            observation_point: ObservationPointV0 {
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
            },
            originator: client(port_slot),
            responder: server(),
            start_time_unix_ns: self.first,
            end_time_unix_ns: self.last,
            orig_packets,
            orig_ip_bytes,
            resp_packets,
            resp_ip_bytes,
            origin_basis: match self.basis.as_str() {
                "syn" => PacketFlowOriginBasisV0::UniqueSynWithoutAck,
                "synack" => PacketFlowOriginBasisV0::InitialSynAckOpposite,
                "unknown" => PacketFlowOriginBasisV0::LowestFrameSource,
                _ => panic!("unexpected direction basis"),
            },
            end_basis: match self.end.as_str() {
                "rst" => PacketFlowEndBasisV0::TcpResetObserved,
                "fin" => PacketFlowEndBasisV0::TcpFinObserved,
                "boundary" => PacketFlowEndBasisV0::PartialCaptureBoundary,
                _ => panic!("unexpected end basis"),
            },
        }
    }

    fn record(&self, port_slot: usize) -> FlowRecordV0 {
        let [op, ob, rp, rb] = self.counters.map(Some);
        FlowRecordV0::new(
            self.first,
            client(port_slot),
            server(),
            FlowRecordProtocolV0::Tcp,
            Some((self.last - self.first).try_into().unwrap()),
            op,
            ob,
            rp,
            rb,
        )
    }

    fn doubled_midpoint(&self) -> i128 {
        i128::from(self.first) + i128::from(self.last)
    }
}

#[derive(Default)]
struct Counts {
    correct: usize,
    wrong: usize,
    tied: usize,
}

impl Counts {
    fn add<T: Ord>(&mut self, ranks: [Option<T>; 2], truth: usize) {
        match ranks[truth].cmp(&ranks[1 - truth]) {
            Ordering::Greater => self.correct += 1,
            Ordering::Less => self.wrong += 1,
            Ordering::Equal => self.tied += 1,
        }
    }
}

fn main() {
    let pairs: Vec<Pair> = io::stdin()
        .lock()
        .lines()
        .map(|row| serde_json::from_str(&row.unwrap()).unwrap())
        .collect();
    assert_eq!(pairs.len(), 250);
    let options = PacketFlowCorrespondenceOptionsV0::default();
    println!("ports\tview\tqueries\tzero\tone\ttwo\tscore_correct\tscore_wrong\tscore_tied\ttime_correct\ttime_wrong\ttime_tied");
    for masked in [false, true] {
        for thin in [false, true] {
            let mut admitted = [0usize; 3];
            let mut scored = Counts::default();
            let mut timed = Counts::default();
            for pair in &pairs {
                let port = |slot| if masked { 0 } else { slot };
                let records = [0, 1].map(|s| pair.complete[s].record(port(s)));
                let queries = if thin { &pair.thinned } else { &pair.complete };
                for (slot, query) in queries.iter().enumerate() {
                    let report = infer_packet_flow_correspondence_v0(
                        &[query.flow(port(slot))],
                        &records,
                        &options,
                    )
                    .unwrap();
                    admitted[report.candidate_edges] += 1;
                    if report.candidate_edges == 0 {
                        continue;
                    }
                    let label = query.label.expect("handshake evidence for admitted query");
                    let truth = pair
                        .complete
                        .iter()
                        .position(|r| r.label == Some(label))
                        .unwrap();
                    let mut scores = [None; 2];
                    let mut times = [None; 2];
                    for component in report.components {
                        assert!(matches!(
                            component.outcome,
                            PacketFlowCorrespondenceComponentOutcomeV0::Exact { .. }
                        ));
                        for edge in component.edges {
                            let index = edge.flow_record_index();
                            scores[index] = Some(edge.corresponds_relative_belief_ppb());
                            times[index] = Some(Reverse(
                                query
                                    .doubled_midpoint()
                                    .abs_diff(pair.complete[index].doubled_midpoint()),
                            ));
                        }
                    }
                    scored.add(scores, truth);
                    timed.add(times, truth);
                }
            }
            let [zero, one, two] = admitted;
            let ports = if masked { "paired" } else { "distinct" };
            let view = if thin { "thinned" } else { "complete" };
            println!(
                "{ports}\t{view}\t{}\t{zero}\t{one}\t{two}\t{}\t{}\t{}\t{}\t{}\t{}",
                zero + one + two,
                scored.correct,
                scored.wrong,
                scored.tied,
                timed.correct,
                timed.wrong,
                timed.tied
            );
        }
    }
}
