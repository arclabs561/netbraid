//! Bounded in-memory correspondence inference between packet-derived flows and Zeek connections.
//!
//! Candidate admission is deterministic. The factor model only ranks admitted
//! split/merge candidates. Its normalized output is model-relative, not a
//! calibrated probability or a durable finite claim.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use std::net::IpAddr;

use crate::adapters::zeek::{ZeekConnProtocolV0, ZeekConnStreamV0, ZeekConnV0};
use crate::infer::factor_graph::{
    infer_exact, ComponentInferenceOutcome, DerivationId, DiscreteFactor, DiscreteFactorGraph,
    DiscreteVariable, EvidenceAtomId, ExactInferenceLimits, FactorDependence, FactorGraphLimits,
    FactorId, FactorProvenance, FactorSemantics, InferenceAbstentionReason, VariableId,
};
use crate::replay::{IpFamilyV0, PacketFlowOriginBasisV0, PacketFlowV0, TransportProtocolV0};

const PPB: u64 = 1_000_000_000;
const MAX_POTENTIAL_PPB: u64 = 1_000 * PPB;

/// Identifier for the built-in packet/Zeek heuristic family.
pub const PACKET_ZEEK_HEURISTIC_PROFILE_V0: &str =
    "netbraid.packet_zeek_correspondence.heuristic.v0";

/// Fixed-point potentials used by the packet/Zeek heuristic.
///
/// One billion represents a neutral potential of one. Values may be above one
/// billion because these are relative weights, not probabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketZeekHeuristicProfileV0 {
    /// Potential applied to each selected candidate edge.
    pub selected_edge_potential_ppb: u64,
    /// Additional potential when the unexpanded intervals overlap.
    pub direct_overlap_potential_ppb: u64,
    /// Potential applied to each exact aggregate counter comparison.
    pub exact_counter_potential_ppb: u64,
    /// Potential applied to each aggregate counter comparison within tolerance.
    pub near_counter_potential_ppb: u64,
    /// Potential applied to each aggregate counter comparison outside tolerance.
    pub conflicting_counter_potential_ppb: u64,
    /// Symmetric relative tolerance used for a near counter comparison.
    pub near_counter_tolerance_ppb: u64,
}

impl Default for PacketZeekHeuristicProfileV0 {
    fn default() -> Self {
        Self {
            selected_edge_potential_ppb: PPB,
            direct_overlap_potential_ppb: 2 * PPB,
            exact_counter_potential_ppb: 4 * PPB,
            near_counter_potential_ppb: 1_500_000_000,
            conflicting_counter_potential_ppb: 250_000_000,
            near_counter_tolerance_ppb: 50_000_000,
        }
    }
}

/// Resource limits for packet/Zeek candidate construction and exact inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketZeekInferenceLimitsV0 {
    /// Maximum submitted packet-derived flows.
    pub max_packet_flows: usize,
    /// Maximum submitted Zeek connections.
    pub max_zeek_connections: usize,
    /// Maximum admitted candidate edges across the report.
    pub max_candidate_edges: usize,
    /// Maximum binary edge variables in one connected component.
    pub max_component_edges: usize,
    /// Maximum complete assignments evaluated across all components.
    pub max_assignments: u64,
}

impl Default for PacketZeekInferenceLimitsV0 {
    fn default() -> Self {
        Self {
            max_packet_flows: 100_000,
            max_zeek_connections: 100_000,
            max_candidate_edges: 1_000_000,
            max_component_edges: 16,
            max_assignments: 1_048_576,
        }
    }
}

/// Candidate, scoring, and resource policy for one in-memory inference run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketZeekCorrespondenceOptionsV0 {
    /// Nanoseconds added to both ends of each Zeek interval for candidate admission.
    pub candidate_tolerance_ns: u64,
    /// Relative heuristic potentials. These do not assert calibration.
    pub profile: PacketZeekHeuristicProfileV0,
    /// Construction and exact-enumeration limits.
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
///
/// Indices refer only to the submitted packet slice and the Zeek stream's
/// retained-semantic ordering. They are not durable evidence identifiers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekEdgeBeliefV0 {
    /// Index into the submitted packet-flow slice.
    packet_flow_index: usize,
    /// Index into [`ZeekConnStreamV0::connections`].
    zeek_connection_index: usize,
    /// Normalized relative belief in parts per billion.
    corresponds_relative_belief_ppb: u64,
    /// Maximum marginal state for this edge, with ties retained.
    marginal_disposition: PacketZeekMarginalDispositionV0,
}

impl PacketZeekEdgeBeliefV0 {
    /// Index into the submitted packet-flow slice.
    pub const fn packet_flow_index(&self) -> usize {
        self.packet_flow_index
    }

    /// Index into the parsed Zeek connection stream.
    pub const fn zeek_connection_index(&self) -> usize {
        self.zeek_connection_index
    }

    /// Normalized relative belief in parts per billion.
    pub const fn corresponds_relative_belief_ppb(&self) -> u64 {
        self.corresponds_relative_belief_ppb
    }

    /// Maximum marginal state for this edge, with ties retained.
    pub const fn marginal_disposition(&self) -> PacketZeekMarginalDispositionV0 {
        self.marginal_disposition
    }
}

/// Maximum state of one binary edge marginal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketZeekMarginalDispositionV0 {
    Corresponds,
    DoesNotCorrespond,
    Tied,
}

/// Why one candidate component was not enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketZeekAbstentionReasonV0 {
    /// The component contains more admitted edges than allowed.
    ComponentEdgeLimitExceeded { edges: usize, limit: usize },
    /// Enumerating every otherwise-admissible component would exceed the report budget.
    ReportAssignmentBudgetExceeded { required: u64, limit: u64 },
}

/// Exact, infeasible, or resource-bounded result for one candidate component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketZeekComponentOutcomeV0 {
    /// Every assignment in this component was evaluated.
    Exact { assignments_evaluated: u64 },
    /// Every assignment was evaluated and all had zero admissible mass.
    NoFeasibleAssignment { assignments_evaluated: u64 },
    /// No edge beliefs are emitted because the component was not enumerated.
    Abstained(PacketZeekAbstentionReasonV0),
}

/// One connected split/merge candidate component and its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekComponentResultV0 {
    /// Packet-flow indices present in the component.
    pub packet_flow_indices: Box<[usize]>,
    /// Zeek-connection indices present in the component.
    pub zeek_connection_indices: Box<[usize]>,
    /// Edge beliefs, present only for an exact outcome.
    pub edges: Box<[PacketZeekEdgeBeliefV0]>,
    /// Exact, infeasible, or bounded result.
    pub outcome: PacketZeekComponentOutcomeV0,
}

/// Aggregate in-memory packet/Zeek correspondence report.
///
/// The complete scoring profile is copied into the report, but source indices
/// are ephemeral. This report is intentionally not a serialized finite claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketZeekCorrespondenceReportV0 {
    /// Identifier for the heuristic interpretation.
    pub heuristic_profile: &'static str,
    /// Exact scoring parameters used.
    pub profile: PacketZeekHeuristicProfileV0,
    /// Exact candidate interval tolerance used.
    pub candidate_tolerance_ns: u64,
    /// Number of submitted packet flows.
    pub packet_flows_seen: usize,
    /// Number of retained Zeek connections.
    pub zeek_connections_seen: usize,
    /// Number of admitted directional, interval-overlapping edges.
    pub candidate_edges: usize,
    /// Packet flows with no admitted edge.
    pub packet_flows_without_candidates: usize,
    /// Zeek connections with no admitted edge, including unsupported protocols.
    pub zeek_connections_without_candidates: usize,
    /// Connected candidate components in canonical edge order.
    pub components: Box<[PacketZeekComponentResultV0]>,
}

/// Failure before a complete candidate report can be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketZeekCorrespondenceErrorV0 {
    /// A potential or counter tolerance is outside the admitted range.
    InvalidProfile,
    /// A resource limit is zero or exceeds the implementation ceiling.
    InvalidLimits,
    /// The packet input exceeds its configured bound.
    PacketFlowLimitExceeded,
    /// The Zeek input exceeds its configured bound.
    ZeekConnectionLimitExceeded,
    /// Candidate admission exceeded its configured edge bound.
    CandidateEdgeLimitExceeded,
    /// A caller-constructed packet flow violates projection invariants.
    InvalidPacketFlow,
    /// Validated family inputs could not be represented by the private kernel.
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

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct DirectionalFlowKey {
    protocol: TransportProtocolV0,
    originator_address: IpAddr,
    originator_port: u16,
    responder_address: IpAddr,
    responder_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CandidateEdge {
    packet: usize,
    zeek: usize,
    direct_overlap: bool,
}

#[derive(Debug)]
struct CandidateComponent {
    packets: Box<[usize]>,
    zeeks: Box<[usize]>,
    edges: Box<[CandidateEdge]>,
}

/// Infer model-relative correspondence belief over deterministic packet/Zeek candidates.
///
/// Admission requires the same directional TCP/UDP five-tuple and closed
/// interval overlap after expanding the Zeek interval by the configured
/// tolerance. Packet flows oriented only by their lowest observed frame and
/// Zeek connections without a duration are not admitted. Callers remain
/// responsible for supplying timestamps in one comparable clock frame. All
/// admitted edges remain available; there is no one-to-one assignment policy.
/// Exact enumeration aggregates counters across split and merge candidates
/// within each bounded connected component.
pub fn infer_packet_zeek_correspondence_v0(
    packet_flows: &[PacketFlowV0],
    zeek_connections: &ZeekConnStreamV0,
    options: &PacketZeekCorrespondenceOptionsV0,
) -> Result<PacketZeekCorrespondenceReportV0, PacketZeekCorrespondenceErrorV0> {
    validate_options(options)?;
    if packet_flows.len() > options.limits.max_packet_flows {
        return Err(PacketZeekCorrespondenceErrorV0::PacketFlowLimitExceeded);
    }
    let zeek_connections = zeek_connections.connections();
    if zeek_connections.len() > options.limits.max_zeek_connections {
        return Err(PacketZeekCorrespondenceErrorV0::ZeekConnectionLimitExceeded);
    }
    for flow in packet_flows {
        validate_packet_flow(flow)?;
    }

    let candidates = candidate_edges(packet_flows, zeek_connections, options)?;
    let packet_candidates: BTreeSet<_> = candidates.iter().map(|edge| edge.packet).collect();
    let zeek_candidates: BTreeSet<_> = candidates.iter().map(|edge| edge.zeek).collect();
    let components = candidate_components(packet_flows.len(), zeek_connections.len(), &candidates);
    let component_results = infer_components(packet_flows, zeek_connections, &components, options)?;

    Ok(PacketZeekCorrespondenceReportV0 {
        heuristic_profile: PACKET_ZEEK_HEURISTIC_PROFILE_V0,
        profile: options.profile,
        candidate_tolerance_ns: options.candidate_tolerance_ns,
        packet_flows_seen: packet_flows.len(),
        zeek_connections_seen: zeek_connections.len(),
        candidate_edges: candidates.len(),
        packet_flows_without_candidates: packet_flows.len() - packet_candidates.len(),
        zeek_connections_without_candidates: zeek_connections.len() - zeek_candidates.len(),
        components: component_results.into_boxed_slice(),
    })
}

fn validate_options(
    options: &PacketZeekCorrespondenceOptionsV0,
) -> Result<(), PacketZeekCorrespondenceErrorV0> {
    let profile = options.profile;
    if [
        profile.selected_edge_potential_ppb,
        profile.direct_overlap_potential_ppb,
        profile.exact_counter_potential_ppb,
        profile.near_counter_potential_ppb,
        profile.conflicting_counter_potential_ppb,
    ]
    .into_iter()
    .any(|value| value == 0 || value > MAX_POTENTIAL_PPB)
        || profile.near_counter_tolerance_ppb > PPB
    {
        return Err(PacketZeekCorrespondenceErrorV0::InvalidProfile);
    }
    let limits = options.limits;
    if limits.max_packet_flows == 0
        || limits.max_zeek_connections == 0
        || limits.max_candidate_edges == 0
        || !(1..=20).contains(&limits.max_component_edges)
        || limits.max_assignments == 0
        || limits.max_assignments > 16_777_216
    {
        return Err(PacketZeekCorrespondenceErrorV0::InvalidLimits);
    }
    Ok(())
}

fn validate_packet_flow(flow: &PacketFlowV0) -> Result<(), PacketZeekCorrespondenceErrorV0> {
    let family_matches = match flow.ip_family {
        IpFamilyV0::Ipv4 => flow.originator.address.is_ipv4() && flow.responder.address.is_ipv4(),
        IpFamilyV0::Ipv6 => flow.originator.address.is_ipv6() && flow.responder.address.is_ipv6(),
    };
    if !family_matches
        || flow.start_time_unix_ns > flow.end_time_unix_ns
        || (flow.orig_packets == 0) != (flow.orig_ip_bytes == 0)
        || (flow.resp_packets == 0) != (flow.resp_ip_bytes == 0)
        || (flow.orig_packets == 0 && flow.resp_packets == 0)
    {
        return Err(PacketZeekCorrespondenceErrorV0::InvalidPacketFlow);
    }
    Ok(())
}

fn candidate_edges(
    packet_flows: &[PacketFlowV0],
    zeek_connections: &[ZeekConnV0],
    options: &PacketZeekCorrespondenceOptionsV0,
) -> Result<Vec<CandidateEdge>, PacketZeekCorrespondenceErrorV0> {
    let mut zeek_by_key = BTreeMap::<DirectionalFlowKey, Vec<usize>>::new();
    for (index, connection) in zeek_connections.iter().enumerate() {
        if connection.duration_ns().is_none() {
            continue;
        }
        if let Some(key) = zeek_key(connection) {
            zeek_by_key.entry(key).or_default().push(index);
        }
    }
    let tolerance = i128::from(options.candidate_tolerance_ns);
    let mut candidates = Vec::new();
    for (packet_index, flow) in packet_flows.iter().enumerate() {
        if flow.origin_basis == PacketFlowOriginBasisV0::LowestFrameSource {
            continue;
        }
        let key = packet_key(flow);
        for zeek_index in zeek_by_key.get(&key).into_iter().flatten() {
            let connection = &zeek_connections[*zeek_index];
            let zeek_start = i128::from(connection.start_time_unix_ns());
            let zeek_end = zeek_start
                + i128::from(
                    connection
                        .duration_ns()
                        .expect("candidate index retains known durations"),
                );
            let packet_start = i128::from(flow.start_time_unix_ns);
            let packet_end = i128::from(flow.end_time_unix_ns);
            let direct_overlap =
                closed_intervals_overlap(packet_start, packet_end, zeek_start, zeek_end);
            if !closed_intervals_overlap(
                packet_start,
                packet_end,
                zeek_start - tolerance,
                zeek_end + tolerance,
            ) {
                continue;
            }
            if candidates.len() == options.limits.max_candidate_edges {
                return Err(PacketZeekCorrespondenceErrorV0::CandidateEdgeLimitExceeded);
            }
            candidates.push(CandidateEdge {
                packet: packet_index,
                zeek: *zeek_index,
                direct_overlap,
            });
        }
    }
    candidates.sort_unstable();
    Ok(candidates)
}

fn packet_key(flow: &PacketFlowV0) -> DirectionalFlowKey {
    DirectionalFlowKey {
        protocol: flow.transport,
        originator_address: flow.originator.address,
        originator_port: flow.originator.port,
        responder_address: flow.responder.address,
        responder_port: flow.responder.port,
    }
}

fn zeek_key(connection: &ZeekConnV0) -> Option<DirectionalFlowKey> {
    let protocol = match connection.protocol() {
        ZeekConnProtocolV0::Tcp => TransportProtocolV0::Tcp,
        ZeekConnProtocolV0::Udp => TransportProtocolV0::Udp,
        ZeekConnProtocolV0::Icmp | ZeekConnProtocolV0::UnknownTransport => return None,
    };
    Some(DirectionalFlowKey {
        protocol,
        originator_address: connection.originator().address(),
        originator_port: connection.originator().port(),
        responder_address: connection.responder().address(),
        responder_port: connection.responder().port(),
    })
}

fn closed_intervals_overlap(
    left_start: i128,
    left_end: i128,
    right_start: i128,
    right_end: i128,
) -> bool {
    left_start <= right_end && right_start <= left_end
}

fn candidate_components(
    packet_count: usize,
    zeek_count: usize,
    candidates: &[CandidateEdge],
) -> Vec<CandidateComponent> {
    let mut by_packet = vec![Vec::new(); packet_count];
    let mut by_zeek = vec![Vec::new(); zeek_count];
    for (edge_index, edge) in candidates.iter().enumerate() {
        by_packet[edge.packet].push(edge_index);
        by_zeek[edge.zeek].push(edge_index);
    }
    let mut seen = vec![false; candidates.len()];
    let mut components = Vec::new();
    for start in 0..candidates.len() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        let mut queue = VecDeque::from([start]);
        let mut edge_indices = Vec::new();
        let mut packets = BTreeSet::new();
        let mut zeeks = BTreeSet::new();
        while let Some(edge_index) = queue.pop_front() {
            edge_indices.push(edge_index);
            let edge = candidates[edge_index];
            packets.insert(edge.packet);
            zeeks.insert(edge.zeek);
            for neighbor in by_packet[edge.packet].iter().chain(&by_zeek[edge.zeek]) {
                if !seen[*neighbor] {
                    seen[*neighbor] = true;
                    queue.push_back(*neighbor);
                }
            }
        }
        edge_indices.sort_unstable();
        components.push(CandidateComponent {
            packets: packets.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            zeeks: zeeks.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            edges: edge_indices
                .into_iter()
                .map(|index| candidates[index])
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        });
    }
    components
}

fn infer_components(
    packet_flows: &[PacketFlowV0],
    zeek_connections: &[ZeekConnV0],
    components: &[CandidateComponent],
    options: &PacketZeekCorrespondenceOptionsV0,
) -> Result<Vec<PacketZeekComponentResultV0>, PacketZeekCorrespondenceErrorV0> {
    let report_assignments_required = components
        .iter()
        .filter(|component| component.edges.len() <= options.limits.max_component_edges)
        .try_fold(0_u64, |total, component| {
            total
                .checked_add(1_u64 << component.edges.len())
                .ok_or(PacketZeekCorrespondenceErrorV0::InvalidLimits)
        })?;
    let report_budget_exceeded = report_assignments_required > options.limits.max_assignments;
    let mut results = Vec::with_capacity(components.len());
    for (component_index, component) in components.iter().enumerate() {
        if component.edges.len() > options.limits.max_component_edges {
            results.push(abstained_component(
                component,
                PacketZeekAbstentionReasonV0::ComponentEdgeLimitExceeded {
                    edges: component.edges.len(),
                    limit: options.limits.max_component_edges,
                },
            ));
            continue;
        }
        let assignments = 1_u64 << component.edges.len();
        if report_budget_exceeded {
            results.push(abstained_component(
                component,
                PacketZeekAbstentionReasonV0::ReportAssignmentBudgetExceeded {
                    required: report_assignments_required,
                    limit: options.limits.max_assignments,
                },
            ));
            continue;
        }
        let mut scope = Vec::with_capacity(component.edges.len());
        let mut variables = Vec::with_capacity(component.edges.len());
        for edge in &component.edges {
            let id = edge_variable_id(*edge)?;
            variables.push(
                DiscreteVariable::try_new(id.clone(), ["false", "true"])
                    .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?,
            );
            scope.push(id);
        }
        let potentials =
            component_potentials(component, packet_flows, zeek_connections, options.profile)?;
        let evidence_atoms = component
            .packets
            .iter()
            .map(|index| format!("packet:{index}"))
            .chain(component.zeeks.iter().map(|index| format!("zeek:{index}")))
            .map(EvidenceAtomId::try_new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?;
        let provenance = FactorProvenance::try_new(
            evidence_atoms,
            [DerivationId::try_new(PACKET_ZEEK_HEURISTIC_PROFILE_V0)
                .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?],
            FactorDependence::Independent,
        )
        .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?;
        let factor = DiscreteFactor::try_positive(
            FactorId::try_new(format!("component:{component_index}"))
                .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?,
            scope,
            potentials,
            FactorSemantics::Heuristic,
            provenance,
        )
        .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?;
        let graph = DiscreteFactorGraph::try_new(
            variables,
            vec![factor],
            FactorGraphLimits {
                max_variables: options.limits.max_component_edges,
                max_factors: 1,
                max_factor_arity: options.limits.max_component_edges,
                max_factor_entries: usize::try_from(assignments)
                    .map_err(|_| PacketZeekCorrespondenceErrorV0::InvalidLimits)?,
            },
        )
        .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?;
        let inference = infer_exact(
            &graph,
            ExactInferenceLimits {
                max_component_variables: options.limits.max_component_edges,
                max_assignments: assignments,
            },
        )
        .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)?;
        let component_result = inference
            .components
            .into_vec()
            .into_iter()
            .next()
            .ok_or(PacketZeekCorrespondenceErrorV0::InternalModel)?;
        results.push(project_component_result(
            component,
            component_result.outcome,
        )?);
    }
    Ok(results)
}

fn edge_variable_id(edge: CandidateEdge) -> Result<VariableId, PacketZeekCorrespondenceErrorV0> {
    VariableId::try_new(format!("edge:p{}:z{}", edge.packet, edge.zeek))
        .map_err(|_| PacketZeekCorrespondenceErrorV0::InternalModel)
}

fn abstained_component(
    component: &CandidateComponent,
    reason: PacketZeekAbstentionReasonV0,
) -> PacketZeekComponentResultV0 {
    PacketZeekComponentResultV0 {
        packet_flow_indices: component.packets.clone(),
        zeek_connection_indices: component.zeeks.clone(),
        edges: Vec::new().into_boxed_slice(),
        outcome: PacketZeekComponentOutcomeV0::Abstained(reason),
    }
}

fn project_component_result(
    component: &CandidateComponent,
    outcome: ComponentInferenceOutcome,
) -> Result<PacketZeekComponentResultV0, PacketZeekCorrespondenceErrorV0> {
    let (edges, outcome) = match outcome {
        ComponentInferenceOutcome::Exact {
            assignments_evaluated,
            beliefs,
        } => {
            let edges = component
                .edges
                .iter()
                .map(|edge| {
                    let id = edge_variable_id(*edge)?;
                    let belief = beliefs
                        .get(&id)
                        .ok_or(PacketZeekCorrespondenceErrorV0::InternalModel)?;
                    let true_belief = belief
                        .states
                        .iter()
                        .find(|state| state.state == "true")
                        .ok_or(PacketZeekCorrespondenceErrorV0::InternalModel)?;
                    Ok(PacketZeekEdgeBeliefV0 {
                        packet_flow_index: edge.packet,
                        zeek_connection_index: edge.zeek,
                        corresponds_relative_belief_ppb: true_belief.probability_ppb,
                        marginal_disposition: match true_belief.probability_ppb.cmp(&(PPB / 2)) {
                            std::cmp::Ordering::Greater => {
                                PacketZeekMarginalDispositionV0::Corresponds
                            }
                            std::cmp::Ordering::Less => {
                                PacketZeekMarginalDispositionV0::DoesNotCorrespond
                            }
                            std::cmp::Ordering::Equal => PacketZeekMarginalDispositionV0::Tied,
                        },
                    })
                })
                .collect::<Result<Vec<_>, PacketZeekCorrespondenceErrorV0>>()?
                .into_boxed_slice();
            (
                edges,
                PacketZeekComponentOutcomeV0::Exact {
                    assignments_evaluated,
                },
            )
        }
        ComponentInferenceOutcome::NoFeasibleAssignment {
            assignments_evaluated,
        } => (
            Vec::new().into_boxed_slice(),
            PacketZeekComponentOutcomeV0::NoFeasibleAssignment {
                assignments_evaluated,
            },
        ),
        ComponentInferenceOutcome::Abstained(reason) => {
            let reason = match reason {
                InferenceAbstentionReason::ComponentVariableLimitExceeded { variables, limit } => {
                    PacketZeekAbstentionReasonV0::ComponentEdgeLimitExceeded {
                        edges: variables,
                        limit,
                    }
                }
                InferenceAbstentionReason::ReportAssignmentBudgetExceeded { required, limit } => {
                    PacketZeekAbstentionReasonV0::ReportAssignmentBudgetExceeded { required, limit }
                }
            };
            (
                Vec::new().into_boxed_slice(),
                PacketZeekComponentOutcomeV0::Abstained(reason),
            )
        }
    };
    Ok(PacketZeekComponentResultV0 {
        packet_flow_indices: component.packets.clone(),
        zeek_connection_indices: component.zeeks.clone(),
        edges,
        outcome,
    })
}

fn component_potentials(
    component: &CandidateComponent,
    packet_flows: &[PacketFlowV0],
    zeek_connections: &[ZeekConnV0],
    profile: PacketZeekHeuristicProfileV0,
) -> Result<Vec<f64>, PacketZeekCorrespondenceErrorV0> {
    let assignments = 1_usize << component.edges.len();
    let mut potentials = Vec::with_capacity(assignments);
    for encoded in 0..assignments {
        let selected: Vec<_> = (0..component.edges.len())
            .map(|index| encoded & (1 << (component.edges.len() - index - 1)) != 0)
            .collect();
        let mut potential = 1.0;
        for (edge, selected) in component.edges.iter().zip(&selected) {
            if !selected {
                continue;
            }
            potential *= scaled_potential(profile.selected_edge_potential_ppb);
            if edge.direct_overlap {
                potential *= scaled_potential(profile.direct_overlap_potential_ppb);
            }
        }
        potential *= counter_potential(
            component,
            &selected,
            packet_flows,
            zeek_connections,
            profile,
        );
        if !potential.is_finite() || potential <= 0.0 {
            return Err(PacketZeekCorrespondenceErrorV0::InternalModel);
        }
        potentials.push(potential);
    }
    Ok(potentials)
}

fn scaled_potential(value_ppb: u64) -> f64 {
    value_ppb as f64 / PPB as f64
}

fn counter_potential(
    component: &CandidateComponent,
    selected: &[bool],
    packet_flows: &[PacketFlowV0],
    zeek_connections: &[ZeekConnV0],
    profile: PacketZeekHeuristicProfileV0,
) -> f64 {
    let mut packet_degree = BTreeMap::<usize, usize>::new();
    let mut zeek_degree = BTreeMap::<usize, usize>::new();
    for (edge, selected) in component.edges.iter().zip(selected) {
        if *selected {
            *packet_degree.entry(edge.packet).or_default() += 1;
            *zeek_degree.entry(edge.zeek).or_default() += 1;
        }
    }
    let mut potential = 1.0;
    for zeek_index in &component.zeeks {
        let selected_packets: Vec<_> = component
            .edges
            .iter()
            .zip(selected)
            .filter(|(edge, selected)| {
                **selected
                    && edge.zeek == *zeek_index
                    && packet_degree.get(&edge.packet) == Some(&1)
            })
            .map(|(edge, _)| edge.packet)
            .collect();
        if selected_packets.is_empty()
            || selected_packets.len() != *zeek_degree.get(zeek_index).unwrap_or(&0)
        {
            continue;
        }
        let zeek = &zeek_connections[*zeek_index];
        for (observed, expected) in [
            (
                sum_packet_counter(&selected_packets, packet_flows, |flow| flow.orig_packets),
                zeek.orig_packets().map(u128::from),
            ),
            (
                sum_packet_counter(&selected_packets, packet_flows, |flow| flow.orig_ip_bytes),
                zeek.orig_ip_bytes().map(u128::from),
            ),
            (
                sum_packet_counter(&selected_packets, packet_flows, |flow| flow.resp_packets),
                zeek.resp_packets().map(u128::from),
            ),
            (
                sum_packet_counter(&selected_packets, packet_flows, |flow| flow.resp_ip_bytes),
                zeek.resp_ip_bytes().map(u128::from),
            ),
        ] {
            if let Some(expected) = expected {
                potential *= compare_counter(observed, expected, profile);
            }
        }
    }
    for packet_index in &component.packets {
        if packet_degree.get(packet_index).copied().unwrap_or(0) <= 1 {
            continue;
        }
        let selected_zeeks: Vec<_> = component
            .edges
            .iter()
            .zip(selected)
            .filter(|(edge, selected)| **selected && edge.packet == *packet_index)
            .map(|(edge, _)| edge.zeek)
            .collect();
        let packet = &packet_flows[*packet_index];
        for (observed, expected) in [
            (
                sum_zeek_counter(&selected_zeeks, zeek_connections, ZeekConnV0::orig_packets),
                u128::from(packet.orig_packets),
            ),
            (
                sum_zeek_counter(&selected_zeeks, zeek_connections, ZeekConnV0::orig_ip_bytes),
                u128::from(packet.orig_ip_bytes),
            ),
            (
                sum_zeek_counter(&selected_zeeks, zeek_connections, ZeekConnV0::resp_packets),
                u128::from(packet.resp_packets),
            ),
            (
                sum_zeek_counter(&selected_zeeks, zeek_connections, ZeekConnV0::resp_ip_bytes),
                u128::from(packet.resp_ip_bytes),
            ),
        ] {
            if let Some(observed) = observed {
                potential *= compare_counter(observed, expected, profile);
            }
        }
    }
    potential
}

fn sum_packet_counter(
    indices: &[usize],
    packet_flows: &[PacketFlowV0],
    select: impl Fn(&PacketFlowV0) -> u64,
) -> u128 {
    indices
        .iter()
        .map(|index| u128::from(select(&packet_flows[*index])))
        .sum()
}

fn sum_zeek_counter(
    indices: &[usize],
    zeek_connections: &[ZeekConnV0],
    select: impl Fn(&ZeekConnV0) -> Option<u64>,
) -> Option<u128> {
    indices.iter().try_fold(0_u128, |sum, index| {
        select(&zeek_connections[*index]).map(|value| sum + u128::from(value))
    })
}

fn compare_counter(observed: u128, expected: u128, profile: PacketZeekHeuristicProfileV0) -> f64 {
    if observed == expected {
        return scaled_potential(profile.exact_counter_potential_ppb);
    }
    let delta = observed.abs_diff(expected);
    let scale = observed.max(expected);
    if delta.saturating_mul(u128::from(PPB))
        <= scale.saturating_mul(u128::from(profile.near_counter_tolerance_ppb))
    {
        scaled_potential(profile.near_counter_potential_ppb)
    } else {
        scaled_potential(profile.conflicting_counter_potential_ppb)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::adapters::zeek::{project_zeek_conn_log, ZeekConnOptions};
    use crate::replay::{
        ConversationEndpointV0, ObservationPointV0, PacketFlowEndBasisV0, PacketFlowOriginBasisV0,
    };

    use super::*;

    fn zeek_stream(rows: &[&str]) -> ZeekConnStreamV0 {
        let source = format!(
            "#separator \\x09\n\
             #set_separator\t,\n\
             #empty_field\t(empty)\n\
             #unset_field\t-\n\
             #path\tconn\n\
             #fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n\
             #types\ttime\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tcount\tcount\n\
             {}",
            if rows.is_empty() {
                String::new()
            } else {
                format!("{}\n", rows.join("\n"))
            }
        );
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conn.log");
        fs::write(&path, source).unwrap();
        project_zeek_conn_log(&path, &ZeekConnOptions::default()).unwrap()
    }

    fn row(timestamp: &str, originator_port: u16, duration: &str, counters: [u64; 4]) -> String {
        format!(
            "{timestamp}\t192.0.2.1\t{originator_port}\t198.51.100.2\t443\ttcp\t{duration}\t{}\t{}\t{}\t{}",
            counters[0], counters[1], counters[2], counters[3]
        )
    }

    fn packet_flow(
        originator_port: u16,
        start_time_unix_ns: i64,
        end_time_unix_ns: i64,
        counters: [u64; 4],
    ) -> PacketFlowV0 {
        PacketFlowV0 {
            ip_family: IpFamilyV0::Ipv4,
            transport: TransportProtocolV0::Tcp,
            observation_point: ObservationPointV0 {
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
            },
            originator: ConversationEndpointV0 {
                address: "192.0.2.1".parse().unwrap(),
                port: originator_port,
            },
            responder: ConversationEndpointV0 {
                address: "198.51.100.2".parse().unwrap(),
                port: 443,
            },
            start_time_unix_ns,
            end_time_unix_ns,
            orig_packets: counters[0],
            orig_ip_bytes: counters[1],
            resp_packets: counters[2],
            resp_ip_bytes: counters[3],
            origin_basis: PacketFlowOriginBasisV0::UniqueSynWithoutAck,
            end_basis: PacketFlowEndBasisV0::CompleteCaptureBoundary,
        }
    }

    fn exact_edges(report: &PacketZeekCorrespondenceReportV0) -> &[PacketZeekEdgeBeliefV0] {
        assert!(matches!(
            report.components[0].outcome,
            PacketZeekComponentOutcomeV0::Exact { .. }
        ));
        &report.components[0].edges
    }

    #[test]
    fn one_to_one_exact_counters_match_hand_derived_relative_belief() {
        let known_duration_row = row("1.000000000", 1234, "0.100000000", [3, 300, 2, 200]);
        let zeek = zeek_stream(&[&known_duration_row]);
        let packet = packet_flow(1234, 1_000_000_000, 1_100_000_000, [3, 300, 2, 200]);

        let report = infer_packet_zeek_correspondence_v0(
            &[packet],
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();

        assert_eq!(report.candidate_edges, 1);
        let edges = exact_edges(&report);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].corresponds_relative_belief_ppb, 998_050_682);
        assert_eq!(
            edges[0].marginal_disposition,
            PacketZeekMarginalDispositionV0::Corresponds
        );
    }

    #[test]
    fn candidate_admission_is_directional_closed_and_tolerance_bounded() {
        let known_duration_row = row("1.000000000", 1234, "0.100000000", [3, 300, 2, 200]);
        let zeek = zeek_stream(&[&known_duration_row]);
        let at_boundary = packet_flow(1234, 1_100_001_000, 1_100_001_000, [3, 300, 2, 200]);
        let outside = packet_flow(1234, 1_100_001_001, 1_100_001_001, [3, 300, 2, 200]);

        let report = infer_packet_zeek_correspondence_v0(
            &[at_boundary, outside],
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();

        assert_eq!(report.candidate_edges, 1);
        assert_eq!(report.packet_flows_without_candidates, 1);
        assert_eq!(exact_edges(&report)[0].packet_flow_index, 0);

        let reversed = PacketFlowV0 {
            originator: ConversationEndpointV0 {
                address: "198.51.100.2".parse().unwrap(),
                port: 443,
            },
            responder: ConversationEndpointV0 {
                address: "192.0.2.1".parse().unwrap(),
                port: 1234,
            },
            ..packet_flow(1234, 1_000_000_000, 1_100_000_000, [2, 200, 3, 300])
        };
        let report = infer_packet_zeek_correspondence_v0(
            &[reversed],
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();
        assert_eq!(report.candidate_edges, 0);
        assert!(report.components.is_empty());

        let unknown_duration_row = row("1.000000000", 1234, "-", [3, 300, 2, 200]);
        let unknown_duration = zeek_stream(&[&unknown_duration_row]);
        let reliable_origin = packet_flow(1234, 1_000_000_000, 1_100_000_000, [3, 300, 2, 200]);
        let report = infer_packet_zeek_correspondence_v0(
            &[reliable_origin],
            &unknown_duration,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();
        assert_eq!(report.candidate_edges, 0);

        let mut uncertain_origin =
            packet_flow(1234, 1_000_000_000, 1_100_000_000, [3, 300, 2, 200]);
        uncertain_origin.origin_basis = PacketFlowOriginBasisV0::LowestFrameSource;
        let report = infer_packet_zeek_correspondence_v0(
            &[uncertain_origin],
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();
        assert_eq!(report.candidate_edges, 0);
    }

    #[test]
    fn joint_component_scores_packet_splits_without_one_to_one_policy() {
        let row = row("1.000000000", 1234, "0.100000000", [5, 500, 2, 200]);
        let zeek = zeek_stream(&[&row]);
        let packets = [
            packet_flow(1234, 1_000_000_000, 1_050_000_000, [2, 200, 1, 100]),
            packet_flow(1234, 1_050_000_000, 1_100_000_000, [3, 300, 1, 100]),
        ];

        let report = infer_packet_zeek_correspondence_v0(
            &packets,
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();

        let edges = exact_edges(&report);
        assert_eq!(edges.len(), 2);
        assert!(edges.iter().all(|edge| {
            edge.marginal_disposition == PacketZeekMarginalDispositionV0::Corresponds
        }));
        assert!(edges
            .iter()
            .all(|edge| edge.corresponds_relative_belief_ppb > 999_000_000));
    }

    #[test]
    fn joint_component_scores_zeek_merges_without_one_to_one_policy() {
        let left = row("1.000000000", 1234, "0.050000000", [2, 200, 1, 100]);
        let right = row("1.050000000", 1234, "0.050000000", [3, 300, 1, 100]);
        let zeek = zeek_stream(&[&left, &right]);
        let packet = packet_flow(1234, 1_000_000_000, 1_100_000_000, [5, 500, 2, 200]);

        let report = infer_packet_zeek_correspondence_v0(
            &[packet],
            &zeek,
            &PacketZeekCorrespondenceOptionsV0::default(),
        )
        .unwrap();

        let edges = exact_edges(&report);
        assert_eq!(edges.len(), 2);
        assert!(edges.iter().all(|edge| {
            edge.marginal_disposition == PacketZeekMarginalDispositionV0::Corresponds
        }));
        assert!(edges
            .iter()
            .all(|edge| edge.corresponds_relative_belief_ppb > 999_000_000));
    }

    #[test]
    fn component_and_assignment_bounds_abstain_without_partial_edge_beliefs() {
        let first = row("1.000000000", 1234, "0.100000000", [3, 300, 2, 200]);
        let second = row("2.000000000", 5678, "0.100000000", [4, 400, 1, 100]);
        let zeek = zeek_stream(&[&first, &second]);
        let packets = [
            packet_flow(1234, 1_000_000_000, 1_100_000_000, [3, 300, 2, 200]),
            packet_flow(5678, 2_000_000_000, 2_100_000_000, [4, 400, 1, 100]),
        ];
        let mut options = PacketZeekCorrespondenceOptionsV0::default();
        options.limits.max_assignments = 2;

        let report = infer_packet_zeek_correspondence_v0(&packets, &zeek, &options).unwrap();

        assert!(report.components.iter().all(|component| {
            component.outcome
                == PacketZeekComponentOutcomeV0::Abstained(
                    PacketZeekAbstentionReasonV0::ReportAssignmentBudgetExceeded {
                        required: 4,
                        limit: 2,
                    },
                )
                && component.edges.is_empty()
        }));

        let mut component_limited = PacketZeekCorrespondenceOptionsV0::default();
        component_limited.limits.max_component_edges = 1;
        let split_row = row("1.000000000", 1234, "0.100000000", [5, 500, 2, 200]);
        let split_zeek = zeek_stream(&[&split_row]);
        let split_packets = [
            packet_flow(1234, 1_000_000_000, 1_050_000_000, [2, 200, 1, 100]),
            packet_flow(1234, 1_050_000_000, 1_100_000_000, [3, 300, 1, 100]),
        ];
        let report =
            infer_packet_zeek_correspondence_v0(&split_packets, &split_zeek, &component_limited)
                .unwrap();
        assert!(matches!(
            report.components[0].outcome,
            PacketZeekComponentOutcomeV0::Abstained(
                PacketZeekAbstentionReasonV0::ComponentEdgeLimitExceeded { edges: 2, limit: 1 }
            )
        ));
        assert!(report.components[0].edges.is_empty());
    }
}
