//! Bounded heuristic inference over RSSI observer, source, and residual shifts.
//!
//! The model starts from the deterministic link classification owned by the
//! RSSI reference-frame family. It does not identify a physical cause. It
//! retains relative belief in observer-wide, source-wide, and link-residual
//! explanations without forcing one explanation to win.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::infer::factor_graph::{
    infer_exact, ComponentInferenceOutcome, DerivationId, DiscreteFactor, DiscreteFactorGraph,
    DiscreteVariable, EvidenceAtomId, ExactInferenceLimits, FactorDependence, FactorGraphLimits,
    FactorId, FactorProvenance, FactorSemantics, InferenceAbstentionReason, VariableBelief,
    VariableId,
};
use crate::infer::rssi_reference_frame::{
    classify_rssi_reference_frame_links_v0, RssiReferenceFrameErrorV0, RssiReferenceFrameLinkV0,
    RssiReferenceFrameProfileV0,
};

const PPB: u64 = 1_000_000_000;
const MAX_POTENTIAL_PPB: u64 = 64 * PPB;
const MAX_LINKS: usize = 1_000_000;
const MAX_BASELINE_SAMPLES: usize = 10_000_000;
const MAX_COMPONENT_VARIABLES: usize = 20;
const MAX_ASSIGNMENTS: u64 = 16_777_216;
const MAX_ASSIGNMENT_WORK_UNITS: u64 = 4_294_967_296;

/// Identifier for the built-in RSSI shift-explanation heuristic.
pub const RSSI_SHIFT_EXPLANATION_HEURISTIC_PROFILE_V0: &str =
    "netbraid.rssi_shift_explanation.heuristic.v0";

/// Relative fixed-point potentials used by the RSSI explanation family.
///
/// These values are weights, not probabilities. Multiplying every field by the
/// same positive constant preserves the normalized result because every
/// assignment contains one term per endpoint and eligible link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RssiShiftExplanationHeuristicProfileV0 {
    /// Weight for an inactive observer- or source-shift candidate.
    pub inactive_endpoint_potential_ppb: u64,
    /// Weight for an active observer- or source-shift candidate.
    pub active_endpoint_potential_ppb: u64,
    /// Weight when a shifted link has no active endpoint explanation.
    pub shifted_without_endpoint_potential_ppb: u64,
    /// Weight when exactly one endpoint explains a shifted link.
    pub shifted_with_one_endpoint_potential_ppb: u64,
    /// Weight when both endpoints explain a shifted link.
    pub shifted_with_both_endpoints_potential_ppb: u64,
    /// Weight when a stable link has no active endpoint explanation.
    pub stable_without_endpoint_potential_ppb: u64,
    /// Weight when one endpoint conflicts with a stable link.
    pub stable_with_one_endpoint_potential_ppb: u64,
    /// Weight when both endpoints conflict with a stable link.
    pub stable_with_both_endpoints_potential_ppb: u64,
}

impl Default for RssiShiftExplanationHeuristicProfileV0 {
    fn default() -> Self {
        Self {
            inactive_endpoint_potential_ppb: 4 * PPB,
            active_endpoint_potential_ppb: PPB,
            shifted_without_endpoint_potential_ppb: PPB,
            shifted_with_one_endpoint_potential_ppb: 64 * PPB,
            shifted_with_both_endpoints_potential_ppb: 8 * PPB,
            stable_without_endpoint_potential_ppb: 64 * PPB,
            stable_with_one_endpoint_potential_ppb: 4 * PPB,
            stable_with_both_endpoints_potential_ppb: PPB,
        }
    }
}

/// Resource policy for one bounded RSSI explanation run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RssiShiftExplanationLimitsV0 {
    /// Maximum submitted links, before exact duplicate collapse.
    pub max_links: usize,
    /// Maximum aggregate baseline samples inspected before duplicate collapse.
    pub max_baseline_samples: usize,
    /// Maximum observer and source variables in one connected component.
    pub max_component_variables: usize,
    /// Maximum aggregate exact state-space cardinality across the report.
    pub max_assignments: u64,
    /// Maximum aggregate assignment work under the documented family cost model.
    ///
    /// A component with `V` endpoint variables, `L` eligible links, and `S`
    /// shifted links costs `2^V * (4V + L + 2S + 1)` work units. The formula
    /// bounds table construction, kernel enumeration, and residual projection;
    /// it is a resource policy, not a performance measurement.
    pub max_assignment_work_units: u64,
}

impl Default for RssiShiftExplanationLimitsV0 {
    fn default() -> Self {
        Self {
            max_links: 100_000,
            max_baseline_samples: 1_000_000,
            max_component_variables: 20,
            max_assignments: 1_048_576,
            max_assignment_work_units: 134_217_728,
        }
    }
}

/// Heuristic and resource policy for RSSI shift explanations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RssiShiftExplanationOptionsV0 {
    /// Relative family weights. They do not assert calibration or causality.
    pub profile: RssiShiftExplanationHeuristicProfileV0,
    /// Input and exact-enumeration limits.
    pub limits: RssiShiftExplanationLimitsV0,
}

/// Relative belief in an observer-wide shift explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssiObserverShiftBeliefV0 {
    /// Observer identifier from the submitted reference-frame links.
    pub observer_id: String,
    /// Normalized model-relative belief in parts per billion.
    pub shifted_relative_belief_ppb: u64,
}

/// Relative belief in a source-wide shift explanation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssiSourceShiftBeliefV0 {
    /// Source identifier from the submitted reference-frame links.
    pub source_id: String,
    /// Normalized model-relative belief in parts per billion.
    pub shifted_relative_belief_ppb: u64,
}

/// Relative belief that one shifted link remains unexplained by either endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssiResidualShiftBeliefV0 {
    /// Observer side of the shifted link.
    pub observer_id: String,
    /// Source side of the shifted link.
    pub source_id: String,
    /// Normalized model-relative belief in a residual explanation.
    pub residual_relative_belief_ppb: u64,
}

/// Why one RSSI explanation component was not enumerated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssiShiftExplanationAbstentionReasonV0 {
    /// The component has more observer and source variables than allowed.
    ComponentVariableLimitExceeded { variables: usize, limit: usize },
    /// Enumerating every otherwise-admissible component would exceed the report budget.
    ReportAssignmentBudgetExceeded { required: u64, limit: u64 },
    /// Evaluating every otherwise-admissible component would exceed the family work budget.
    ReportAssignmentWorkBudgetExceeded { required: u64, limit: u64 },
}

/// Exact, infeasible, or resource-bounded result for one component.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RssiShiftExplanationComponentOutcomeV0 {
    /// Every assignment in this component was evaluated.
    Exact { assignments_evaluated: u64 },
    /// Every assignment was evaluated and all had zero admissible mass.
    NoFeasibleAssignment { assignments_evaluated: u64 },
    /// No beliefs are emitted because the component was not enumerated.
    Abstained(RssiShiftExplanationAbstentionReasonV0),
}

/// One connected observer/source link component and its explanation beliefs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssiShiftExplanationComponentResultV0 {
    /// Observer identifiers in canonical order.
    observer_ids: Box<[String]>,
    /// Source identifiers in canonical order.
    source_ids: Box<[String]>,
    /// Eligible reference-frame links in this component.
    eligible_links: usize,
    /// Links classified as shifted in this component.
    shifted_links: usize,
    /// Observer beliefs, present only for an exact outcome.
    observer_beliefs: Box<[RssiObserverShiftBeliefV0]>,
    /// Source beliefs, present only for an exact outcome.
    source_beliefs: Box<[RssiSourceShiftBeliefV0]>,
    /// Residual beliefs for shifted links, present only for an exact outcome.
    residual_beliefs: Box<[RssiResidualShiftBeliefV0]>,
    /// Exact, infeasible, or bounded result.
    outcome: RssiShiftExplanationComponentOutcomeV0,
}

impl RssiShiftExplanationComponentResultV0 {
    /// Observer identifiers in canonical order.
    pub fn observer_ids(&self) -> &[String] {
        &self.observer_ids
    }

    /// Source identifiers in canonical order.
    pub fn source_ids(&self) -> &[String] {
        &self.source_ids
    }

    /// Number of eligible reference-frame links in this component.
    pub const fn eligible_links(&self) -> usize {
        self.eligible_links
    }

    /// Number of links classified as shifted in this component.
    pub const fn shifted_links(&self) -> usize {
        self.shifted_links
    }

    /// Observer beliefs, present only for an exact outcome.
    pub fn observer_beliefs(&self) -> &[RssiObserverShiftBeliefV0] {
        &self.observer_beliefs
    }

    /// Source beliefs, present only for an exact outcome.
    pub fn source_beliefs(&self) -> &[RssiSourceShiftBeliefV0] {
        &self.source_beliefs
    }

    /// Residual beliefs for shifted links, present only for an exact outcome.
    pub fn residual_beliefs(&self) -> &[RssiResidualShiftBeliefV0] {
        &self.residual_beliefs
    }

    /// Exact, infeasible, or bounded result.
    pub const fn outcome(&self) -> &RssiShiftExplanationComponentOutcomeV0 {
        &self.outcome
    }
}

/// Aggregate in-memory RSSI shift-explanation report.
///
/// Identifiers are copied from caller input, so this report is intentionally
/// not serialized as a durable claim. The relative beliefs are heuristic model
/// values, not calibrated probabilities and not physical-cause verdicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RssiShiftExplanationReportV0 {
    /// Identifier for the heuristic interpretation.
    heuristic_profile: &'static str,
    /// Exact family weights used.
    profile: RssiShiftExplanationHeuristicProfileV0,
    /// Exact reference-frame threshold profile used to classify links.
    reference_frame_profile: RssiReferenceFrameProfileV0,
    /// Submitted links before exact duplicate collapse.
    links_seen: usize,
    /// Aggregate baseline samples inspected before exact duplicate collapse.
    baseline_samples_seen: usize,
    /// Distinct links with enough baseline and recent-frame context.
    eligible_links: usize,
    /// Eligible links classified as shifted.
    shifted_links: usize,
    /// Connected components in canonical link order.
    components: Box<[RssiShiftExplanationComponentResultV0]>,
}

impl RssiShiftExplanationReportV0 {
    /// Identifier for the heuristic interpretation.
    pub const fn heuristic_profile(&self) -> &str {
        self.heuristic_profile
    }

    /// Exact family weights used.
    pub const fn profile(&self) -> RssiShiftExplanationHeuristicProfileV0 {
        self.profile
    }

    /// Exact reference-frame threshold profile used to classify links.
    pub const fn reference_frame_profile(&self) -> &RssiReferenceFrameProfileV0 {
        &self.reference_frame_profile
    }

    /// Submitted links before exact duplicate collapse.
    pub const fn links_seen(&self) -> usize {
        self.links_seen
    }

    /// Aggregate baseline samples inspected before exact duplicate collapse.
    pub const fn baseline_samples_seen(&self) -> usize {
        self.baseline_samples_seen
    }

    /// Distinct links with enough baseline and recent-frame context.
    pub const fn eligible_links(&self) -> usize {
        self.eligible_links
    }

    /// Eligible links classified as shifted.
    pub const fn shifted_links(&self) -> usize {
        self.shifted_links
    }

    /// Connected components in canonical link order.
    pub fn components(&self) -> &[RssiShiftExplanationComponentResultV0] {
        &self.components
    }
}

/// Failure before a complete RSSI explanation report can be constructed.
#[derive(Debug)]
#[non_exhaustive]
pub enum RssiShiftExplanationErrorV0 {
    /// The reference-frame profile or one submitted link is invalid.
    InvalidReferenceFrame(RssiReferenceFrameErrorV0),
    /// A relative potential is outside the admitted range.
    InvalidProfile,
    /// A resource limit is zero or exceeds the implementation ceiling.
    InvalidLimits,
    /// The submitted input exceeds its configured link bound.
    LinkLimitExceeded,
    /// Aggregate submitted baseline samples exceed the configured bound.
    BaselineSampleLimitExceeded,
    /// Validated family inputs could not be represented by the private kernel.
    InternalModel,
}

impl fmt::Display for RssiShiftExplanationErrorV0 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidReferenceFrame(source) => {
                write!(formatter, "invalid RSSI reference frame: {source}")
            }
            Self::InvalidProfile => formatter.write_str("invalid RSSI shift-explanation profile"),
            Self::InvalidLimits => formatter.write_str("invalid RSSI shift-explanation limits"),
            Self::LinkLimitExceeded => {
                formatter.write_str("RSSI shift-explanation link limit exceeded")
            }
            Self::BaselineSampleLimitExceeded => {
                formatter.write_str("RSSI shift-explanation baseline sample limit exceeded")
            }
            Self::InternalModel => {
                formatter.write_str("RSSI shift-explanation factor model could not be constructed")
            }
        }
    }
}

impl std::error::Error for RssiShiftExplanationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidReferenceFrame(source) => Some(source),
            Self::InvalidProfile
            | Self::InvalidLimits
            | Self::LinkLimitExceeded
            | Self::BaselineSampleLimitExceeded
            | Self::InternalModel => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct ClassifiedLink {
    observer: usize,
    source: usize,
    shifted: bool,
}

#[derive(Debug)]
struct LinkComponent {
    observers: Box<[usize]>,
    sources: Box<[usize]>,
    links: Box<[usize]>,
}

/// Infer relative observer, source, and residual explanations for RSSI shifts.
///
/// Link eligibility and shifted/stable classification use the supplied
/// reference-frame profile. The family then builds a separate finite model for
/// each connected observer/source component. Stable links remain evidence:
/// they counter endpoint-wide explanations that would otherwise absorb every
/// changed link. A shifted link always retains a derived residual explanation,
/// so the model never requires an observer or source explanation.
pub fn infer_rssi_shift_explanations_v0(
    links: &[RssiReferenceFrameLinkV0],
    reference_frame_profile: &RssiReferenceFrameProfileV0,
    options: &RssiShiftExplanationOptionsV0,
) -> Result<RssiShiftExplanationReportV0, RssiShiftExplanationErrorV0> {
    validate_options(options)?;
    if links.len() > options.limits.max_links {
        return Err(RssiShiftExplanationErrorV0::LinkLimitExceeded);
    }
    let baseline_samples_seen = links.iter().try_fold(0_usize, |total, link| {
        total
            .checked_add(link.baseline_rssi_milli_db().len())
            .ok_or(RssiShiftExplanationErrorV0::BaselineSampleLimitExceeded)
    })?;
    if baseline_samples_seen > options.limits.max_baseline_samples {
        return Err(RssiShiftExplanationErrorV0::BaselineSampleLimitExceeded);
    }
    let assessments = classify_rssi_reference_frame_links_v0(links, reference_frame_profile)
        .map_err(RssiShiftExplanationErrorV0::InvalidReferenceFrame)?;
    let observer_ids = assessments
        .keys()
        .map(|(observer_id, _)| observer_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let source_ids = assessments
        .keys()
        .map(|(_, source_id)| source_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let observer_positions = observer_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let source_positions = source_ids
        .iter()
        .enumerate()
        .map(|(index, id)| (id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let classified_links = assessments
        .iter()
        .map(|((observer_id, source_id), assessment)| ClassifiedLink {
            observer: observer_positions[observer_id.as_str()],
            source: source_positions[source_id.as_str()],
            shifted: assessment.shifted,
        })
        .collect::<Vec<_>>();
    let components = link_components(observer_ids.len(), source_ids.len(), &classified_links);
    let report_assignments_required = components
        .iter()
        .filter(|component| {
            component_variable_count(component) <= options.limits.max_component_variables
        })
        .try_fold(0_u64, |total, component| {
            total
                .checked_add(component_assignment_count(component))
                .ok_or(RssiShiftExplanationErrorV0::InternalModel)
        })?;
    let report_work_units_required = components
        .iter()
        .filter(|component| {
            component_variable_count(component) <= options.limits.max_component_variables
        })
        .try_fold(0_u64, |total, component| {
            total
                .checked_add(component_assignment_work_units(
                    component,
                    &classified_links,
                )?)
                .ok_or(RssiShiftExplanationErrorV0::InternalModel)
        })?;
    let report_abstention = if report_assignments_required > options.limits.max_assignments {
        Some(
            RssiShiftExplanationAbstentionReasonV0::ReportAssignmentBudgetExceeded {
                required: report_assignments_required,
                limit: options.limits.max_assignments,
            },
        )
    } else if report_work_units_required > options.limits.max_assignment_work_units {
        Some(
            RssiShiftExplanationAbstentionReasonV0::ReportAssignmentWorkBudgetExceeded {
                required: report_work_units_required,
                limit: options.limits.max_assignment_work_units,
            },
        )
    } else {
        None
    };
    let mut results = Vec::with_capacity(components.len());
    for (component_index, component) in components.iter().enumerate() {
        let result = infer_component(
            component_index,
            component,
            &classified_links,
            &observer_ids,
            &source_ids,
            options,
            report_abstention,
        )?;
        results.push(result);
    }

    Ok(RssiShiftExplanationReportV0 {
        heuristic_profile: RSSI_SHIFT_EXPLANATION_HEURISTIC_PROFILE_V0,
        profile: options.profile,
        reference_frame_profile: reference_frame_profile.clone(),
        links_seen: links.len(),
        baseline_samples_seen,
        eligible_links: classified_links.len(),
        shifted_links: classified_links.iter().filter(|link| link.shifted).count(),
        components: results.into_boxed_slice(),
    })
}

fn component_variable_count(component: &LinkComponent) -> usize {
    component.observers.len() + component.sources.len()
}

fn component_assignment_count(component: &LinkComponent) -> u64 {
    1_u64 << component_variable_count(component)
}

fn component_assignment_work_units(
    component: &LinkComponent,
    links: &[ClassifiedLink],
) -> Result<u64, RssiShiftExplanationErrorV0> {
    let variable_count = u64::try_from(component_variable_count(component))
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let link_count = u64::try_from(component.links.len())
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let shifted_count = u64::try_from(
        component
            .links
            .iter()
            .filter(|index| links[**index].shifted)
            .count(),
    )
    .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let per_assignment = variable_count
        .checked_mul(4)
        .and_then(|value| value.checked_add(link_count))
        .and_then(|value| value.checked_add(shifted_count.checked_mul(2)?))
        .and_then(|value| value.checked_add(1))
        .ok_or(RssiShiftExplanationErrorV0::InternalModel)?;
    component_assignment_count(component)
        .checked_mul(per_assignment)
        .ok_or(RssiShiftExplanationErrorV0::InternalModel)
}

fn validate_options(
    options: &RssiShiftExplanationOptionsV0,
) -> Result<(), RssiShiftExplanationErrorV0> {
    let profile = options.profile;
    if [
        profile.inactive_endpoint_potential_ppb,
        profile.active_endpoint_potential_ppb,
        profile.shifted_without_endpoint_potential_ppb,
        profile.shifted_with_one_endpoint_potential_ppb,
        profile.shifted_with_both_endpoints_potential_ppb,
        profile.stable_without_endpoint_potential_ppb,
        profile.stable_with_one_endpoint_potential_ppb,
        profile.stable_with_both_endpoints_potential_ppb,
    ]
    .into_iter()
    .any(|value| !(PPB..=MAX_POTENTIAL_PPB).contains(&value))
    {
        return Err(RssiShiftExplanationErrorV0::InvalidProfile);
    }
    let limits = options.limits;
    if limits.max_links == 0
        || limits.max_links > MAX_LINKS
        || limits.max_baseline_samples == 0
        || limits.max_baseline_samples > MAX_BASELINE_SAMPLES
        || limits.max_component_variables == 0
        || limits.max_component_variables > MAX_COMPONENT_VARIABLES
        || limits.max_assignments == 0
        || limits.max_assignments > MAX_ASSIGNMENTS
        || limits.max_assignment_work_units == 0
        || limits.max_assignment_work_units > MAX_ASSIGNMENT_WORK_UNITS
    {
        return Err(RssiShiftExplanationErrorV0::InvalidLimits);
    }
    Ok(())
}

fn link_components(
    observer_count: usize,
    source_count: usize,
    links: &[ClassifiedLink],
) -> Vec<LinkComponent> {
    let mut by_observer = vec![Vec::new(); observer_count];
    let mut by_source = vec![Vec::new(); source_count];
    for (link_index, link) in links.iter().enumerate() {
        by_observer[link.observer].push(link_index);
        by_source[link.source].push(link_index);
    }
    let mut seen = vec![false; links.len()];
    let mut components = Vec::new();
    for start in 0..links.len() {
        if seen[start] {
            continue;
        }
        seen[start] = true;
        let mut queue = VecDeque::from([start]);
        let mut component_links = Vec::new();
        let mut observers = BTreeSet::new();
        let mut sources = BTreeSet::new();
        while let Some(link_index) = queue.pop_front() {
            component_links.push(link_index);
            let link = links[link_index];
            observers.insert(link.observer);
            sources.insert(link.source);
            for neighbor in by_observer[link.observer]
                .iter()
                .chain(&by_source[link.source])
            {
                if !seen[*neighbor] {
                    seen[*neighbor] = true;
                    queue.push_back(*neighbor);
                }
            }
        }
        component_links.sort_unstable();
        components.push(LinkComponent {
            observers: observers.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            sources: sources.into_iter().collect::<Vec<_>>().into_boxed_slice(),
            links: component_links.into_boxed_slice(),
        });
    }
    components
}

fn infer_component(
    component_index: usize,
    component: &LinkComponent,
    links: &[ClassifiedLink],
    observer_ids: &[String],
    source_ids: &[String],
    options: &RssiShiftExplanationOptionsV0,
    report_abstention: Option<RssiShiftExplanationAbstentionReasonV0>,
) -> Result<RssiShiftExplanationComponentResultV0, RssiShiftExplanationErrorV0> {
    let shifted_link_indices = component
        .links
        .iter()
        .copied()
        .filter(|index| links[*index].shifted)
        .collect::<Vec<_>>();
    let variable_count = component_variable_count(component);
    if variable_count > options.limits.max_component_variables {
        return Ok(abstained_component(
            component,
            links,
            observer_ids,
            source_ids,
            RssiShiftExplanationAbstentionReasonV0::ComponentVariableLimitExceeded {
                variables: variable_count,
                limit: options.limits.max_component_variables,
            },
        ));
    }
    let required = component_assignment_count(component);
    if let Some(reason) = report_abstention {
        return Ok(abstained_component(
            component,
            links,
            observer_ids,
            source_ids,
            reason,
        ));
    }

    let mut variables = Vec::with_capacity(variable_count);
    let mut endpoint_scope =
        Vec::with_capacity(component.observers.len() + component.sources.len());
    let mut observer_variables = BTreeMap::new();
    let mut source_variables = BTreeMap::new();
    for observer in &component.observers {
        let id = variable_id("observer", *observer)?;
        endpoint_scope.push(id.clone());
        variables.push(binary_variable(id.clone())?);
        observer_variables.insert(*observer, id);
    }
    for source in &component.sources {
        let id = variable_id("source", *source)?;
        endpoint_scope.push(id.clone());
        variables.push(binary_variable(id.clone())?);
        source_variables.insert(*source, id);
    }

    let joint_model = FactorDependence::joint_model(format!("joint:rssi-shift:{component_index}"))
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let evidence_atoms = component
        .links
        .iter()
        .map(|index| evidence_atom(*index))
        .collect::<Result<Vec<_>, _>>()?;
    let potentials = explanation_potentials(
        component,
        links,
        &observer_variables,
        &source_variables,
        &endpoint_scope,
        options.profile,
    )?;
    let endpoint_positions = endpoint_scope
        .iter()
        .cloned()
        .enumerate()
        .map(|(position, variable)| (variable, position))
        .collect::<BTreeMap<_, _>>();
    let factor = DiscreteFactor::try_positive(
        FactorId::try_new(format!("rssi-shift:{component_index}"))
            .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?,
        endpoint_scope.clone(),
        potentials.clone(),
        FactorSemantics::Heuristic,
        FactorProvenance::try_new(
            evidence_atoms,
            [DerivationId::try_new("derive:rssi-shift-explanation-v0")
                .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?],
            joint_model,
        )
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?,
    )
    .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;

    let endpoint_assignments = 1_usize << endpoint_scope.len();
    let graph = DiscreteFactorGraph::try_new(
        variables,
        vec![factor],
        FactorGraphLimits {
            max_variables: variable_count,
            max_factors: 1,
            max_factor_arity: endpoint_scope.len(),
            max_factor_entries: endpoint_assignments,
        },
    )
    .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let inference = infer_exact(
        &graph,
        ExactInferenceLimits {
            max_component_variables: variable_count,
            max_assignments: required,
        },
    )
    .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)?;
    let result = inference
        .components
        .first()
        .ok_or(RssiShiftExplanationErrorV0::InternalModel)?;
    let observer_names = component
        .observers
        .iter()
        .map(|index| observer_ids[*index].clone())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let source_names = component
        .sources
        .iter()
        .map(|index| source_ids[*index].clone())
        .collect::<Vec<_>>()
        .into_boxed_slice();
    let shifted_links = shifted_link_indices.len();

    match &result.outcome {
        ComponentInferenceOutcome::Exact {
            assignments_evaluated,
            beliefs,
            ..
        } => {
            let observer_beliefs = component
                .observers
                .iter()
                .map(|index| {
                    Ok(RssiObserverShiftBeliefV0 {
                        observer_id: observer_ids[*index].clone(),
                        shifted_relative_belief_ppb: shifted_belief(
                            beliefs,
                            &observer_variables[index],
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, RssiShiftExplanationErrorV0>>()?;
            let source_beliefs = component
                .sources
                .iter()
                .map(|index| {
                    Ok(RssiSourceShiftBeliefV0 {
                        source_id: source_ids[*index].clone(),
                        shifted_relative_belief_ppb: shifted_belief(
                            beliefs,
                            &source_variables[index],
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, RssiShiftExplanationErrorV0>>()?;
            let residual_beliefs = shifted_link_indices
                .iter()
                .map(|link_index| {
                    let link = links[*link_index];
                    Ok(RssiResidualShiftBeliefV0 {
                        observer_id: observer_ids[link.observer].clone(),
                        source_id: source_ids[link.source].clone(),
                        residual_relative_belief_ppb: residual_belief(
                            &potentials,
                            endpoint_scope.len(),
                            endpoint_positions[&observer_variables[&link.observer]],
                            endpoint_positions[&source_variables[&link.source]],
                        )?,
                    })
                })
                .collect::<Result<Vec<_>, RssiShiftExplanationErrorV0>>()?;
            Ok(RssiShiftExplanationComponentResultV0 {
                observer_ids: observer_names,
                source_ids: source_names,
                eligible_links: component.links.len(),
                shifted_links,
                observer_beliefs: observer_beliefs.into_boxed_slice(),
                source_beliefs: source_beliefs.into_boxed_slice(),
                residual_beliefs: residual_beliefs.into_boxed_slice(),
                outcome: RssiShiftExplanationComponentOutcomeV0::Exact {
                    assignments_evaluated: *assignments_evaluated,
                },
            })
        }
        ComponentInferenceOutcome::NoFeasibleAssignment {
            assignments_evaluated,
        } => Ok(RssiShiftExplanationComponentResultV0 {
            observer_ids: observer_names,
            source_ids: source_names,
            eligible_links: component.links.len(),
            shifted_links,
            observer_beliefs: Box::new([]),
            source_beliefs: Box::new([]),
            residual_beliefs: Box::new([]),
            outcome: RssiShiftExplanationComponentOutcomeV0::NoFeasibleAssignment {
                assignments_evaluated: *assignments_evaluated,
            },
        }),
        ComponentInferenceOutcome::Abstained(reason) => Ok(RssiShiftExplanationComponentResultV0 {
            observer_ids: observer_names,
            source_ids: source_names,
            eligible_links: component.links.len(),
            shifted_links,
            observer_beliefs: Box::new([]),
            source_beliefs: Box::new([]),
            residual_beliefs: Box::new([]),
            outcome: RssiShiftExplanationComponentOutcomeV0::Abstained(map_abstention(reason)),
        }),
    }
}

fn variable_id(kind: &str, index: usize) -> Result<VariableId, RssiShiftExplanationErrorV0> {
    VariableId::try_new(format!("{kind}:{index}"))
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)
}

fn binary_variable(id: VariableId) -> Result<DiscreteVariable, RssiShiftExplanationErrorV0> {
    DiscreteVariable::try_new(id, ["stable", "shifted"])
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)
}

fn evidence_atom(index: usize) -> Result<EvidenceAtomId, RssiShiftExplanationErrorV0> {
    EvidenceAtomId::try_new(format!("rssi-link:{index}"))
        .map_err(|_| RssiShiftExplanationErrorV0::InternalModel)
}

fn explanation_potentials(
    component: &LinkComponent,
    links: &[ClassifiedLink],
    observer_variables: &BTreeMap<usize, VariableId>,
    source_variables: &BTreeMap<usize, VariableId>,
    scope: &[VariableId],
    profile: RssiShiftExplanationHeuristicProfileV0,
) -> Result<Vec<f64>, RssiShiftExplanationErrorV0> {
    let positions = scope
        .iter()
        .enumerate()
        .map(|(index, id)| (id, index))
        .collect::<BTreeMap<_, _>>();
    let assignment_count = 1_usize << scope.len();
    let mut log_weights = Vec::with_capacity(assignment_count);
    for encoded in 0..assignment_count {
        let active = |position: usize| encoded & (1 << (scope.len() - position - 1)) != 0;
        let mut log_weight = 0.0;
        for position in 0..scope.len() {
            let potential = if active(position) {
                profile.active_endpoint_potential_ppb
            } else {
                profile.inactive_endpoint_potential_ppb
            };
            log_weight += (potential as f64).ln();
        }
        for link_index in &component.links {
            let link = links[*link_index];
            let active_endpoints =
                usize::from(active(positions[&observer_variables[&link.observer]]))
                    + usize::from(active(positions[&source_variables[&link.source]]));
            let potential = link_potential(profile, link.shifted, active_endpoints);
            log_weight += (potential as f64).ln();
        }
        log_weights.push(log_weight);
    }
    let maximum = log_weights
        .iter()
        .copied()
        .max_by(f64::total_cmp)
        .ok_or(RssiShiftExplanationErrorV0::InternalModel)?;
    let potentials = log_weights
        .into_iter()
        .map(|weight| (weight - maximum).exp())
        .collect::<Vec<_>>();
    if potentials
        .iter()
        .any(|value| !value.is_finite() || *value <= 0.0)
    {
        return Err(RssiShiftExplanationErrorV0::InternalModel);
    }
    Ok(potentials)
}

fn link_potential(
    profile: RssiShiftExplanationHeuristicProfileV0,
    shifted: bool,
    active_endpoints: usize,
) -> u64 {
    match (shifted, active_endpoints) {
        (true, 0) => profile.shifted_without_endpoint_potential_ppb,
        (true, 1) => profile.shifted_with_one_endpoint_potential_ppb,
        (true, 2) => profile.shifted_with_both_endpoints_potential_ppb,
        (false, 0) => profile.stable_without_endpoint_potential_ppb,
        (false, 1) => profile.stable_with_one_endpoint_potential_ppb,
        (false, 2) => profile.stable_with_both_endpoints_potential_ppb,
        (_, _) => unreachable!("a link has exactly two endpoints"),
    }
}

fn shifted_belief(
    beliefs: &BTreeMap<VariableId, VariableBelief>,
    variable: &VariableId,
) -> Result<u64, RssiShiftExplanationErrorV0> {
    beliefs
        .get(variable)
        .and_then(|belief| belief.states.iter().find(|state| state.state == "shifted"))
        .map(|state| state.probability_ppb)
        .ok_or(RssiShiftExplanationErrorV0::InternalModel)
}

fn residual_belief(
    potentials: &[f64],
    variable_count: usize,
    observer_position: usize,
    source_position: usize,
) -> Result<u64, RssiShiftExplanationErrorV0> {
    let total = potentials.iter().sum::<f64>();
    if !total.is_finite() || total <= 0.0 {
        return Err(RssiShiftExplanationErrorV0::InternalModel);
    }
    let residual = potentials
        .iter()
        .enumerate()
        .filter(|(encoded, _)| {
            !binary_assignment_state(*encoded, variable_count, observer_position)
                && !binary_assignment_state(*encoded, variable_count, source_position)
        })
        .map(|(_, potential)| potential)
        .sum::<f64>();
    let scaled = residual / total * PPB as f64;
    if !scaled.is_finite() || !(0.0..=PPB as f64).contains(&scaled) {
        return Err(RssiShiftExplanationErrorV0::InternalModel);
    }
    Ok(scaled.round() as u64)
}

fn binary_assignment_state(encoded: usize, variable_count: usize, position: usize) -> bool {
    encoded & (1 << (variable_count - position - 1)) != 0
}

fn abstained_component(
    component: &LinkComponent,
    links: &[ClassifiedLink],
    observer_ids: &[String],
    source_ids: &[String],
    reason: RssiShiftExplanationAbstentionReasonV0,
) -> RssiShiftExplanationComponentResultV0 {
    RssiShiftExplanationComponentResultV0 {
        observer_ids: component
            .observers
            .iter()
            .map(|index| observer_ids[*index].clone())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        source_ids: component
            .sources
            .iter()
            .map(|index| source_ids[*index].clone())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
        eligible_links: component.links.len(),
        shifted_links: component
            .links
            .iter()
            .filter(|index| links[**index].shifted)
            .count(),
        observer_beliefs: Box::new([]),
        source_beliefs: Box::new([]),
        residual_beliefs: Box::new([]),
        outcome: RssiShiftExplanationComponentOutcomeV0::Abstained(reason),
    }
}

fn map_abstention(reason: &InferenceAbstentionReason) -> RssiShiftExplanationAbstentionReasonV0 {
    match reason {
        InferenceAbstentionReason::ComponentVariableLimitExceeded { variables, limit } => {
            RssiShiftExplanationAbstentionReasonV0::ComponentVariableLimitExceeded {
                variables: *variables,
                limit: *limit,
            }
        }
        InferenceAbstentionReason::ReportAssignmentBudgetExceeded { required, limit } => {
            RssiShiftExplanationAbstentionReasonV0::ReportAssignmentBudgetExceeded {
                required: *required,
                limit: *limit,
            }
        }
    }
}
