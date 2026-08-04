use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::infer::content_relation::ContentSha256V0;

const PROBABILITY_SCALE: u64 = 1_000_000_000;
const HARD_MAX_VARIABLES: usize = 4_096;
const HARD_MAX_FACTORS: usize = 8_192;
const HARD_MAX_STATES_PER_VARIABLE: usize = 64;
const HARD_MAX_FACTOR_ARITY: usize = 20;
const HARD_MAX_FACTOR_ENTRIES: usize = 1_048_576;
const HARD_MAX_COMPONENT_VARIABLES: usize = 24;
const HARD_MAX_ASSIGNMENTS: u64 = 16_777_216;
const MAX_IDENTIFIER_LEN: usize = 192;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VariableId(String);

impl VariableId {
    pub(crate) fn try_new(value: impl Into<String>) -> Result<Self, FactorGraphError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FactorId(String);

impl FactorId {
    pub(crate) fn try_new(value: impl Into<String>) -> Result<Self, FactorGraphError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct EvidenceAtomId(String);

impl EvidenceAtomId {
    pub(crate) fn try_new(value: impl Into<String>) -> Result<Self, FactorGraphError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct DerivationId(String);

impl DerivationId {
    pub(crate) fn try_new(value: impl Into<String>) -> Result<Self, FactorGraphError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiscreteVariable {
    id: VariableId,
    states: Box<[String]>,
}

impl DiscreteVariable {
    pub(crate) fn try_new(
        id: VariableId,
        states: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, FactorGraphError> {
        let states: Vec<String> = states.into_iter().map(Into::into).collect();
        if !(2..=HARD_MAX_STATES_PER_VARIABLE).contains(&states.len()) {
            return Err(FactorGraphError::InvalidStateCount);
        }
        let mut seen = BTreeSet::new();
        for state in &states {
            if !valid_identifier(state) {
                return Err(FactorGraphError::InvalidIdentifier);
            }
            if !seen.insert(state) {
                return Err(FactorGraphError::DuplicateState);
            }
        }
        Ok(Self {
            id,
            states: states.into_boxed_slice(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FactorDependence {
    Independent,
    JointModel(String),
}

impl FactorDependence {
    pub(crate) fn joint_model(value: impl Into<String>) -> Result<Self, FactorGraphError> {
        let value = value.into();
        if !valid_identifier(&value) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self::JointModel(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FactorProvenance {
    evidence_atoms: BTreeSet<EvidenceAtomId>,
    derivations: BTreeSet<DerivationId>,
    dependence: FactorDependence,
}

impl FactorProvenance {
    pub(crate) fn try_new(
        evidence_atoms: impl IntoIterator<Item = EvidenceAtomId>,
        derivations: impl IntoIterator<Item = DerivationId>,
        dependence: FactorDependence,
    ) -> Result<Self, FactorGraphError> {
        let evidence_atoms: BTreeSet<_> = evidence_atoms.into_iter().collect();
        let derivations: BTreeSet<_> = derivations.into_iter().collect();
        if evidence_atoms.is_empty() {
            return Err(FactorGraphError::MissingEvidenceProvenance);
        }
        Ok(Self {
            evidence_atoms,
            derivations,
            dependence,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ModelSnapshotRef {
    model_id: String,
    profile_sha256: ContentSha256V0,
}

impl ModelSnapshotRef {
    pub(crate) fn try_new(
        model_id: impl Into<String>,
        profile_sha256: ContentSha256V0,
    ) -> Result<Self, FactorGraphError> {
        let model_id = model_id.into();
        if !valid_identifier(&model_id) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self {
            model_id,
            profile_sha256,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FactorSemantics {
    Heuristic,
    Prior { model: ModelSnapshotRef },
    Likelihood { model: ModelSnapshotRef },
    DeterministicConstraint { proof_id: String },
}

impl FactorSemantics {
    pub(crate) fn prior(model: ModelSnapshotRef) -> Self {
        Self::Prior { model }
    }

    pub(crate) fn likelihood(model: ModelSnapshotRef) -> Self {
        Self::Likelihood { model }
    }

    pub(crate) fn deterministic_constraint(
        proof_id: impl Into<String>,
    ) -> Result<Self, FactorGraphError> {
        let proof_id = proof_id.into();
        if !valid_identifier(&proof_id) {
            return Err(FactorGraphError::InvalidIdentifier);
        }
        Ok(Self::DeterministicConstraint { proof_id })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DiscreteFactor {
    id: FactorId,
    scope: Box<[VariableId]>,
    log_potentials: Box<[f64]>,
    semantics: FactorSemantics,
    provenance: FactorProvenance,
}

impl DiscreteFactor {
    pub(crate) fn try_positive(
        id: FactorId,
        scope: Vec<VariableId>,
        potentials: Vec<f64>,
        semantics: FactorSemantics,
        provenance: FactorProvenance,
    ) -> Result<Self, FactorGraphError> {
        if matches!(semantics, FactorSemantics::DeterministicConstraint { .. }) {
            return Err(FactorGraphError::InvalidFactorSemantics);
        }
        validate_scope(&scope)?;
        if potentials.is_empty() || potentials.len() > HARD_MAX_FACTOR_ENTRIES {
            return Err(FactorGraphError::InvalidFactorTableSize);
        }
        if potentials
            .iter()
            .any(|value| !value.is_finite() || *value <= 0.0)
        {
            return Err(FactorGraphError::InvalidPositivePotential);
        }
        Ok(Self {
            id,
            scope: scope.into_boxed_slice(),
            log_potentials: potentials
                .into_iter()
                .map(f64::ln)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            semantics,
            provenance,
        })
    }

    pub(crate) fn try_constraint(
        id: FactorId,
        scope: Vec<VariableId>,
        admissible: Vec<bool>,
        semantics: FactorSemantics,
        provenance: FactorProvenance,
    ) -> Result<Self, FactorGraphError> {
        if !matches!(semantics, FactorSemantics::DeterministicConstraint { .. }) {
            return Err(FactorGraphError::InvalidFactorSemantics);
        }
        validate_scope(&scope)?;
        if admissible.is_empty()
            || admissible.len() > HARD_MAX_FACTOR_ENTRIES
            || !admissible.iter().any(|value| *value)
        {
            return Err(FactorGraphError::InvalidFactorTableSize);
        }
        if provenance.derivations.is_empty() {
            return Err(FactorGraphError::ConstraintMissingProofDerivation);
        }
        Ok(Self {
            id,
            scope: scope.into_boxed_slice(),
            log_potentials: admissible
                .into_iter()
                .map(|value| if value { 0.0 } else { f64::NEG_INFINITY })
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            semantics,
            provenance,
        })
    }
}

fn validate_scope(scope: &[VariableId]) -> Result<(), FactorGraphError> {
    if scope.is_empty() || scope.len() > HARD_MAX_FACTOR_ARITY {
        return Err(FactorGraphError::InvalidFactorArity);
    }
    let mut seen = BTreeSet::new();
    if scope.iter().any(|variable| !seen.insert(variable)) {
        return Err(FactorGraphError::DuplicateVariableInScope);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FactorGraphLimits {
    pub(crate) max_variables: usize,
    pub(crate) max_factors: usize,
    pub(crate) max_factor_arity: usize,
    pub(crate) max_factor_entries: usize,
}

impl FactorGraphLimits {
    pub(crate) const fn conservative() -> Self {
        Self {
            max_variables: 4_096,
            max_factors: 8_192,
            max_factor_arity: 16,
            max_factor_entries: 65_536,
        }
    }

    fn validate(self) -> Result<Self, FactorGraphError> {
        if self.max_variables == 0
            || self.max_variables > HARD_MAX_VARIABLES
            || self.max_factors == 0
            || self.max_factors > HARD_MAX_FACTORS
            || self.max_factor_arity == 0
            || self.max_factor_arity > HARD_MAX_FACTOR_ARITY
            || self.max_factor_entries == 0
            || self.max_factor_entries > HARD_MAX_FACTOR_ENTRIES
        {
            return Err(FactorGraphError::InvalidGraphLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GraphSemantics {
    ConstraintOnly,
    ModelRelative,
    ModelPosterior { model: ModelSnapshotRef },
}

#[derive(Debug, Clone)]
pub(crate) struct DiscreteFactorGraph {
    variables: Box<[DiscreteVariable]>,
    factors: Box<[DiscreteFactor]>,
    semantics: GraphSemantics,
}

impl DiscreteFactorGraph {
    pub(crate) fn try_new(
        mut variables: Vec<DiscreteVariable>,
        mut factors: Vec<DiscreteFactor>,
        limits: FactorGraphLimits,
    ) -> Result<Self, FactorGraphError> {
        let limits = limits.validate()?;
        if variables.is_empty() {
            return Err(FactorGraphError::MissingVariables);
        }
        if factors.is_empty() {
            return Err(FactorGraphError::MissingFactors);
        }
        if variables.len() > limits.max_variables {
            return Err(FactorGraphError::VariableLimitExceeded);
        }
        if factors.len() > limits.max_factors {
            return Err(FactorGraphError::FactorLimitExceeded);
        }

        variables.sort_by(|left, right| left.id.cmp(&right.id));
        variables = deduplicate_variables(variables)?;
        let cardinalities: BTreeMap<_, _> = variables
            .iter()
            .map(|variable| (variable.id.clone(), variable.states.len()))
            .collect();

        factors.sort_by(|left, right| left.id.cmp(&right.id));
        factors = deduplicate_factors(factors)?;
        for factor in &factors {
            if factor.scope.len() > limits.max_factor_arity
                || factor.log_potentials.len() > limits.max_factor_entries
            {
                return Err(FactorGraphError::FactorLimitExceeded);
            }
            let expected_entries = factor.scope.iter().try_fold(1_usize, |product, id| {
                cardinalities
                    .get(id)
                    .ok_or(FactorGraphError::UnknownVariableInScope)
                    .and_then(|cardinality| {
                        product
                            .checked_mul(*cardinality)
                            .ok_or(FactorGraphError::InvalidFactorTableSize)
                    })
            })?;
            if expected_entries != factor.log_potentials.len() {
                return Err(FactorGraphError::InvalidFactorTableSize);
            }
        }
        reject_unmodeled_overlap(&factors)?;
        let semantics = graph_semantics(&factors)?;

        Ok(Self {
            variables: variables.into_boxed_slice(),
            factors: factors.into_boxed_slice(),
            semantics,
        })
    }
}

fn deduplicate_variables(
    variables: Vec<DiscreteVariable>,
) -> Result<Vec<DiscreteVariable>, FactorGraphError> {
    let mut canonical: Vec<DiscreteVariable> = Vec::with_capacity(variables.len());
    for variable in variables {
        if let Some(previous) = canonical.last() {
            if previous.id == variable.id {
                if previous == &variable {
                    continue;
                }
                return Err(FactorGraphError::DivergentVariable);
            }
        }
        canonical.push(variable);
    }
    Ok(canonical)
}

fn deduplicate_factors(
    factors: Vec<DiscreteFactor>,
) -> Result<Vec<DiscreteFactor>, FactorGraphError> {
    let mut canonical: Vec<DiscreteFactor> = Vec::with_capacity(factors.len());
    for factor in factors {
        if let Some(previous) = canonical.last() {
            if previous.id == factor.id {
                if previous == &factor {
                    continue;
                }
                return Err(FactorGraphError::DivergentFactor);
            }
        }
        canonical.push(factor);
    }
    Ok(canonical)
}

fn reject_unmodeled_overlap(factors: &[DiscreteFactor]) -> Result<(), FactorGraphError> {
    for (index, left) in factors.iter().enumerate() {
        for right in &factors[index + 1..] {
            if left
                .provenance
                .evidence_atoms
                .is_disjoint(&right.provenance.evidence_atoms)
            {
                continue;
            }
            match (&left.provenance.dependence, &right.provenance.dependence) {
                (FactorDependence::JointModel(left), FactorDependence::JointModel(right))
                    if left == right => {}
                _ => return Err(FactorGraphError::UnmodeledEvidenceDependence),
            }
        }
    }
    Ok(())
}

fn graph_semantics(factors: &[DiscreteFactor]) -> Result<GraphSemantics, FactorGraphError> {
    let mut heuristic = false;
    let mut probabilistic = false;
    let mut prior = false;
    let mut model: Option<&ModelSnapshotRef> = None;
    for factor in factors {
        match &factor.semantics {
            FactorSemantics::Heuristic => heuristic = true,
            FactorSemantics::Prior { model: current } => {
                probabilistic = true;
                prior = true;
                merge_model(&mut model, current)?;
            }
            FactorSemantics::Likelihood { model: current } => {
                probabilistic = true;
                merge_model(&mut model, current)?;
            }
            FactorSemantics::DeterministicConstraint { .. } => {}
        }
    }
    if heuristic && probabilistic {
        return Err(FactorGraphError::MixedFactorSemantics);
    }
    if heuristic || (probabilistic && !prior) {
        return Ok(GraphSemantics::ModelRelative);
    }
    match model {
        Some(model) => Ok(GraphSemantics::ModelPosterior {
            model: model.clone(),
        }),
        None => Ok(GraphSemantics::ConstraintOnly),
    }
}

fn merge_model<'a>(
    retained: &mut Option<&'a ModelSnapshotRef>,
    current: &'a ModelSnapshotRef,
) -> Result<(), FactorGraphError> {
    if retained.is_some_and(|retained| retained != current) {
        return Err(FactorGraphError::MixedProbabilisticModels);
    }
    *retained = Some(current);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExactInferenceLimits {
    pub(crate) max_component_variables: usize,
    pub(crate) max_assignments: u64,
}

impl ExactInferenceLimits {
    pub(crate) const fn conservative() -> Self {
        Self {
            max_component_variables: 20,
            max_assignments: 1_048_576,
        }
    }

    fn validate(self) -> Result<Self, FactorGraphError> {
        if self.max_component_variables == 0
            || self.max_component_variables > HARD_MAX_COMPONENT_VARIABLES
            || self.max_assignments == 0
            || self.max_assignments > HARD_MAX_ASSIGNMENTS
        {
            return Err(FactorGraphError::InvalidInferenceLimits);
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StateBelief {
    pub(crate) state: String,
    pub(crate) probability_ppb: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VariableBelief {
    pub(crate) variable: VariableId,
    pub(crate) states: Box<[StateBelief]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InferenceAbstentionReason {
    ComponentVariableLimitExceeded { variables: usize, limit: usize },
    AssignmentBudgetExceeded { required: u64, remaining: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComponentInferenceOutcome {
    Exact {
        assignments_evaluated: u64,
        beliefs: BTreeMap<VariableId, VariableBelief>,
        map_states: BTreeMap<VariableId, String>,
    },
    NoFeasibleAssignment {
        assignments_evaluated: u64,
    },
    Abstained(InferenceAbstentionReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ComponentInferenceResult {
    pub(crate) variables: Box<[VariableId]>,
    pub(crate) factors: Box<[FactorId]>,
    pub(crate) outcome: ComponentInferenceOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactInferenceReport {
    pub(crate) semantics: GraphSemantics,
    pub(crate) components: Box<[ComponentInferenceResult]>,
}

pub(crate) fn infer_exact(
    graph: &DiscreteFactorGraph,
    limits: ExactInferenceLimits,
) -> Result<ExactInferenceReport, FactorGraphError> {
    let limits = limits.validate()?;
    let components = graph_components(graph);
    let mut results = Vec::with_capacity(components.len());
    let mut assignments_used = 0_u64;

    for component in components {
        let variable_ids: Vec<_> = component
            .variable_indices
            .iter()
            .map(|index| graph.variables[*index].id.clone())
            .collect();
        let factor_ids: Vec<_> = component
            .factor_indices
            .iter()
            .map(|index| graph.factors[*index].id.clone())
            .collect();
        if component.variable_indices.len() > limits.max_component_variables {
            results.push(ComponentInferenceResult {
                variables: variable_ids.into_boxed_slice(),
                factors: factor_ids.into_boxed_slice(),
                outcome: ComponentInferenceOutcome::Abstained(
                    InferenceAbstentionReason::ComponentVariableLimitExceeded {
                        variables: component.variable_indices.len(),
                        limit: limits.max_component_variables,
                    },
                ),
            });
            continue;
        }
        let assignments = component
            .variable_indices
            .iter()
            .try_fold(1_u64, |product, index| {
                product.checked_mul(
                    u64::try_from(graph.variables[*index].states.len())
                        .expect("bounded state count fits u64"),
                )
            })
            .ok_or(FactorGraphError::AssignmentCountOverflow)?;
        let remaining = limits.max_assignments.saturating_sub(assignments_used);
        if assignments > remaining {
            results.push(ComponentInferenceResult {
                variables: variable_ids.into_boxed_slice(),
                factors: factor_ids.into_boxed_slice(),
                outcome: ComponentInferenceOutcome::Abstained(
                    InferenceAbstentionReason::AssignmentBudgetExceeded {
                        required: assignments,
                        remaining,
                    },
                ),
            });
            continue;
        }
        assignments_used += assignments;
        let outcome = match infer_component(graph, &component, assignments)? {
            Some(component_result) => ComponentInferenceOutcome::Exact {
                assignments_evaluated: assignments,
                beliefs: component_result.beliefs,
                map_states: component_result.map_states,
            },
            None => ComponentInferenceOutcome::NoFeasibleAssignment {
                assignments_evaluated: assignments,
            },
        };
        results.push(ComponentInferenceResult {
            variables: variable_ids.into_boxed_slice(),
            factors: factor_ids.into_boxed_slice(),
            outcome,
        });
    }

    Ok(ExactInferenceReport {
        semantics: graph.semantics.clone(),
        components: results.into_boxed_slice(),
    })
}

struct Component {
    variable_indices: Vec<usize>,
    factor_indices: Vec<usize>,
}

fn graph_components(graph: &DiscreteFactorGraph) -> Vec<Component> {
    let positions: BTreeMap<_, _> = graph
        .variables
        .iter()
        .enumerate()
        .map(|(index, variable)| (variable.id.clone(), index))
        .collect();
    let factor_variables: Vec<Vec<usize>> = graph
        .factors
        .iter()
        .map(|factor| {
            factor
                .scope
                .iter()
                .map(|id| positions[id])
                .collect::<Vec<_>>()
        })
        .collect();
    let mut variable_factors = vec![Vec::new(); graph.variables.len()];
    for (factor_index, variables) in factor_variables.iter().enumerate() {
        for variable in variables {
            variable_factors[*variable].push(factor_index);
        }
    }

    let mut seen_variables = vec![false; graph.variables.len()];
    let mut seen_factors = vec![false; graph.factors.len()];
    let mut components = Vec::new();
    for start in 0..graph.variables.len() {
        if seen_variables[start] {
            continue;
        }
        let mut queue = VecDeque::from([start]);
        seen_variables[start] = true;
        let mut variables = Vec::new();
        let mut factors = Vec::new();
        while let Some(variable) = queue.pop_front() {
            variables.push(variable);
            for factor in &variable_factors[variable] {
                if !seen_factors[*factor] {
                    seen_factors[*factor] = true;
                    factors.push(*factor);
                }
                for neighbor in &factor_variables[*factor] {
                    if !seen_variables[*neighbor] {
                        seen_variables[*neighbor] = true;
                        queue.push_back(*neighbor);
                    }
                }
            }
        }
        variables.sort_unstable();
        factors.sort_unstable();
        components.push(Component {
            variable_indices: variables,
            factor_indices: factors,
        });
    }
    components
}

struct ComponentResult {
    beliefs: BTreeMap<VariableId, VariableBelief>,
    map_states: BTreeMap<VariableId, String>,
}

fn infer_component(
    graph: &DiscreteFactorGraph,
    component: &Component,
    assignments: u64,
) -> Result<Option<ComponentResult>, FactorGraphError> {
    let component_positions: BTreeMap<_, _> = component
        .variable_indices
        .iter()
        .enumerate()
        .map(|(position, index)| (graph.variables[*index].id.clone(), position))
        .collect();
    let cardinalities: Vec<_> = component
        .variable_indices
        .iter()
        .map(|index| graph.variables[*index].states.len())
        .collect();
    let mut state_log_sums: Vec<Vec<f64>> = cardinalities
        .iter()
        .map(|cardinality| vec![f64::NEG_INFINITY; *cardinality])
        .collect();
    let mut log_partition = f64::NEG_INFINITY;
    let mut best_log_weight = f64::NEG_INFINITY;
    let mut best_assignment = None;
    let mut states = vec![0_usize; cardinalities.len()];

    for assignment_index in 0..assignments {
        decode_assignment(assignment_index, &cardinalities, &mut states);
        let mut log_weight = 0.0;
        for factor_index in &component.factor_indices {
            let factor = &graph.factors[*factor_index];
            let mut table_index = 0_usize;
            for variable in &factor.scope {
                let position = component_positions[variable];
                table_index = table_index
                    .checked_mul(cardinalities[position])
                    .and_then(|index| index.checked_add(states[position]))
                    .ok_or(FactorGraphError::InvalidFactorTableSize)?;
            }
            log_weight += factor.log_potentials[table_index];
        }
        if log_weight == f64::NEG_INFINITY {
            continue;
        }
        if !log_weight.is_finite() {
            return Err(FactorGraphError::NumericalFailure);
        }
        log_partition = log_add_exp(log_partition, log_weight);
        for (position, state) in states.iter().enumerate() {
            state_log_sums[position][*state] =
                log_add_exp(state_log_sums[position][*state], log_weight);
        }
        if log_weight > best_log_weight {
            best_log_weight = log_weight;
            best_assignment = Some(states.clone());
        }
    }
    if log_partition == f64::NEG_INFINITY {
        return Ok(None);
    }

    let mut beliefs = BTreeMap::new();
    for (position, variable_index) in component.variable_indices.iter().enumerate() {
        let variable = &graph.variables[*variable_index];
        let probabilities: Vec<_> = state_log_sums[position]
            .iter()
            .map(|value| (*value - log_partition).exp())
            .collect();
        let probability_ppb = quantize_simplex(&probabilities)?;
        let states = variable
            .states
            .iter()
            .cloned()
            .zip(probability_ppb)
            .map(|(state, probability_ppb)| StateBelief {
                state,
                probability_ppb,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice();
        beliefs.insert(
            variable.id.clone(),
            VariableBelief {
                variable: variable.id.clone(),
                states,
            },
        );
    }
    let best_assignment = best_assignment.expect("finite partition has a best assignment");
    let map_states = component
        .variable_indices
        .iter()
        .enumerate()
        .map(|(position, variable_index)| {
            let variable = &graph.variables[*variable_index];
            (
                variable.id.clone(),
                variable.states[best_assignment[position]].clone(),
            )
        })
        .collect();
    Ok(Some(ComponentResult {
        beliefs,
        map_states,
    }))
}

fn decode_assignment(mut encoded: u64, cardinalities: &[usize], states: &mut [usize]) {
    for (state, cardinality) in states.iter_mut().zip(cardinalities).rev() {
        let cardinality = u64::try_from(*cardinality).expect("bounded cardinality fits u64");
        *state = usize::try_from(encoded % cardinality).expect("state index fits usize");
        encoded /= cardinality;
    }
}

fn log_add_exp(left: f64, right: f64) -> f64 {
    if left == f64::NEG_INFINITY {
        return right;
    }
    if right == f64::NEG_INFINITY {
        return left;
    }
    let maximum = left.max(right);
    maximum + ((left - maximum).exp() + (right - maximum).exp()).ln()
}

fn quantize_simplex(probabilities: &[f64]) -> Result<Vec<u64>, FactorGraphError> {
    if probabilities.is_empty()
        || probabilities
            .iter()
            .any(|value| !value.is_finite() || *value < 0.0)
    {
        return Err(FactorGraphError::NumericalFailure);
    }
    let sum: f64 = probabilities.iter().sum();
    if !sum.is_finite() || sum <= 0.0 {
        return Err(FactorGraphError::NumericalFailure);
    }
    let mut quantized = Vec::with_capacity(probabilities.len());
    let mut remainders = Vec::with_capacity(probabilities.len());
    let mut assigned = 0_u64;
    for (index, probability) in probabilities.iter().enumerate() {
        let scaled = (*probability / sum) * PROBABILITY_SCALE as f64;
        let floor = scaled.floor() as u64;
        assigned = assigned
            .checked_add(floor)
            .ok_or(FactorGraphError::NumericalFailure)?;
        quantized.push(floor);
        remainders.push((scaled - floor as f64, index));
    }
    if assigned > PROBABILITY_SCALE {
        return Err(FactorGraphError::NumericalFailure);
    }
    remainders.sort_by(|left, right| {
        right
            .0
            .total_cmp(&left.0)
            .then_with(|| left.1.cmp(&right.1))
    });
    for (_, index) in remainders
        .into_iter()
        .take(usize::try_from(PROBABILITY_SCALE - assigned).expect("PPB remainder fits usize"))
    {
        quantized[index] += 1;
    }
    Ok(quantized)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'_' | b'-' | b'/')
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FactorGraphError {
    InvalidIdentifier,
    InvalidStateCount,
    DuplicateState,
    InvalidFactorSemantics,
    InvalidPositivePotential,
    InvalidFactorArity,
    DuplicateVariableInScope,
    InvalidFactorTableSize,
    MissingEvidenceProvenance,
    ConstraintMissingProofDerivation,
    InvalidGraphLimits,
    MissingVariables,
    MissingFactors,
    VariableLimitExceeded,
    FactorLimitExceeded,
    DivergentVariable,
    DivergentFactor,
    UnknownVariableInScope,
    UnmodeledEvidenceDependence,
    MixedProbabilisticModels,
    MixedFactorSemantics,
    InvalidInferenceLimits,
    AssignmentCountOverflow,
    NumericalFailure,
}

impl fmt::Display for FactorGraphError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentifier => "invalid factor-graph identifier",
            Self::InvalidStateCount => "invalid factor-graph state count",
            Self::DuplicateState => "duplicate state in one factor-graph variable",
            Self::InvalidFactorSemantics => "factor constructor does not match its semantics",
            Self::InvalidPositivePotential => "factor potential is not finite and positive",
            Self::InvalidFactorArity => "invalid factor arity",
            Self::DuplicateVariableInScope => "factor scope contains a duplicate variable",
            Self::InvalidFactorTableSize => "factor table size does not match its scope",
            Self::MissingEvidenceProvenance => "factor has no evidence provenance",
            Self::ConstraintMissingProofDerivation => {
                "deterministic constraint has no proof derivation"
            }
            Self::InvalidGraphLimits => "invalid factor-graph construction limits",
            Self::MissingVariables => "factor graph has no variables",
            Self::MissingFactors => "factor graph has no factors",
            Self::VariableLimitExceeded => "factor-graph variable limit exceeded",
            Self::FactorLimitExceeded => "factor-graph factor limit exceeded",
            Self::DivergentVariable => "divergent variables share one identifier",
            Self::DivergentFactor => "divergent factors share one identifier",
            Self::UnknownVariableInScope => "factor scope cites an unknown variable",
            Self::UnmodeledEvidenceDependence => {
                "factors reuse evidence without one explicit joint model"
            }
            Self::MixedProbabilisticModels => "probabilistic factors cite different models",
            Self::MixedFactorSemantics => {
                "heuristic and probabilistic factors cannot share one graph"
            }
            Self::InvalidInferenceLimits => "invalid exact-inference limits",
            Self::AssignmentCountOverflow => "factor-graph assignment count overflowed",
            Self::NumericalFailure => "factor-graph inference encountered a numerical failure",
        })
    }
}

impl std::error::Error for FactorGraphError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn variable(id: &str) -> DiscreteVariable {
        DiscreteVariable::try_new(VariableId::try_new(id).unwrap(), ["false", "true"]).unwrap()
    }

    fn atom(id: &str) -> EvidenceAtomId {
        EvidenceAtomId::try_new(id).unwrap()
    }

    fn derivation(id: &str) -> DerivationId {
        DerivationId::try_new(id).unwrap()
    }

    fn provenance(atom_id: &str) -> FactorProvenance {
        FactorProvenance::try_new(
            [atom(atom_id)],
            [derivation(&format!("derive:{atom_id}"))],
            FactorDependence::Independent,
        )
        .unwrap()
    }

    fn positive_factor(
        id: &str,
        scope: &[&str],
        potentials: &[f64],
        atom_id: &str,
    ) -> DiscreteFactor {
        DiscreteFactor::try_positive(
            FactorId::try_new(id).unwrap(),
            scope
                .iter()
                .map(|id| VariableId::try_new(*id).unwrap())
                .collect(),
            potentials.to_vec(),
            FactorSemantics::Heuristic,
            provenance(atom_id),
        )
        .unwrap()
    }

    fn model_snapshot() -> ModelSnapshotRef {
        ModelSnapshotRef::try_new(
            "model:binary-v0",
            ContentSha256V0::try_new("a".repeat(64)).unwrap(),
        )
        .unwrap()
    }

    fn exact_component(
        report: &ExactInferenceReport,
        index: usize,
    ) -> (
        u64,
        &BTreeMap<VariableId, VariableBelief>,
        &BTreeMap<VariableId, String>,
    ) {
        match &report.components[index].outcome {
            ComponentInferenceOutcome::Exact {
                assignments_evaluated,
                beliefs,
                map_states,
            } => (*assignments_evaluated, beliefs, map_states),
            outcome => panic!("expected exact component, got {outcome:?}"),
        }
    }

    #[test]
    fn exact_binary_marginal_matches_hand_derived_six_sevenths() {
        let variables = vec![variable("a"), variable("b")];
        let factors = vec![
            DiscreteFactor::try_positive(
                FactorId::try_new("prior:a").unwrap(),
                vec![VariableId::try_new("a").unwrap()],
                vec![1.0, 3.0],
                FactorSemantics::prior(model_snapshot()),
                provenance("evidence:prior-a"),
            )
            .unwrap(),
            DiscreteFactor::try_positive(
                FactorId::try_new("likelihood:b").unwrap(),
                vec![VariableId::try_new("b").unwrap()],
                vec![1.0, 2.0],
                FactorSemantics::likelihood(model_snapshot()),
                provenance("evidence:b"),
            )
            .unwrap(),
            DiscreteFactor::try_constraint(
                FactorId::try_new("constraint:equal").unwrap(),
                vec![
                    VariableId::try_new("a").unwrap(),
                    VariableId::try_new("b").unwrap(),
                ],
                vec![true, false, false, true],
                FactorSemantics::deterministic_constraint("proof:equality").unwrap(),
                provenance("evidence:equality"),
            )
            .unwrap(),
        ];
        let graph =
            DiscreteFactorGraph::try_new(variables, factors, FactorGraphLimits::conservative())
                .unwrap();
        let result = infer_exact(&graph, ExactInferenceLimits::conservative()).unwrap();

        assert_eq!(
            result.semantics,
            GraphSemantics::ModelPosterior {
                model: model_snapshot()
            }
        );
        let (assignments, beliefs, _) = exact_component(&result, 0);
        for id in ["a", "b"] {
            let belief = &beliefs[&VariableId::try_new(id).unwrap()];
            assert_eq!(belief.states[0].probability_ppb, 142_857_143);
            assert_eq!(belief.states[1].probability_ppb, 857_142_857);
        }
        assert_eq!(assignments, 4);
    }

    #[test]
    fn heuristic_normalization_is_typed_as_model_relative() {
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("edge")],
            vec![positive_factor(
                "heuristic:edge",
                &["edge"],
                &[1.0, 4.0],
                "evidence:edge",
            )],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let result = infer_exact(&graph, ExactInferenceLimits::conservative()).unwrap();

        assert_eq!(result.semantics, GraphSemantics::ModelRelative);
        let (_, beliefs, _) = exact_component(&result, 0);
        assert_eq!(
            beliefs[&VariableId::try_new("edge").unwrap()].states[1].probability_ppb,
            800_000_000
        );
    }

    #[test]
    fn heuristic_and_snapshot_bound_model_factors_cannot_be_mixed() {
        let heuristic = positive_factor("heuristic", &["edge"], &[1.0, 2.0], "evidence:h");
        let prior = DiscreteFactor::try_positive(
            FactorId::try_new("prior").unwrap(),
            vec![VariableId::try_new("edge").unwrap()],
            vec![1.0, 2.0],
            FactorSemantics::prior(model_snapshot()),
            provenance("evidence:p"),
        )
        .unwrap();

        assert!(matches!(
            DiscreteFactorGraph::try_new(
                vec![variable("edge")],
                vec![heuristic, prior],
                FactorGraphLimits::conservative()
            ),
            Err(FactorGraphError::MixedFactorSemantics)
        ));
    }

    #[test]
    fn heuristic_zero_is_rejected_but_proven_constraint_zero_is_admitted() {
        let heuristic = DiscreteFactor::try_positive(
            FactorId::try_new("heuristic").unwrap(),
            vec![VariableId::try_new("edge").unwrap()],
            vec![0.0, 1.0],
            FactorSemantics::Heuristic,
            provenance("evidence:edge"),
        );
        assert!(matches!(
            heuristic,
            Err(FactorGraphError::InvalidPositivePotential)
        ));

        let constraint = DiscreteFactor::try_constraint(
            FactorId::try_new("constraint").unwrap(),
            vec![VariableId::try_new("edge").unwrap()],
            vec![false, true],
            FactorSemantics::deterministic_constraint("proof:admission").unwrap(),
            provenance("evidence:admission"),
        )
        .unwrap();
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("edge")],
            vec![constraint],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let result = infer_exact(&graph, ExactInferenceLimits::conservative()).unwrap();
        let (_, beliefs, _) = exact_component(&result, 0);
        assert_eq!(
            beliefs[&VariableId::try_new("edge").unwrap()].states[1].probability_ppb,
            PROBABILITY_SCALE
        );
    }

    #[test]
    fn shared_evidence_requires_one_explicit_joint_model() {
        let left = positive_factor("left", &["edge"], &[1.0, 2.0], "shared");
        let right = positive_factor("right", &["edge"], &[1.0, 3.0], "shared");
        assert!(matches!(
            DiscreteFactorGraph::try_new(
                vec![variable("edge")],
                vec![left, right],
                FactorGraphLimits::conservative()
            ),
            Err(FactorGraphError::UnmodeledEvidenceDependence)
        ));

        let joint = FactorDependence::joint_model("joint:edge-v0").unwrap();
        let make = |id: &str, weight: f64| {
            DiscreteFactor::try_positive(
                FactorId::try_new(id).unwrap(),
                vec![VariableId::try_new("edge").unwrap()],
                vec![1.0, weight],
                FactorSemantics::Heuristic,
                FactorProvenance::try_new(
                    [atom("shared")],
                    [derivation(&format!("derive:{id}"))],
                    joint.clone(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("edge")],
            vec![make("left", 2.0), make("right", 3.0)],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let result = infer_exact(&graph, ExactInferenceLimits::conservative()).unwrap();
        let (_, beliefs, _) = exact_component(&result, 0);
        assert_eq!(
            beliefs[&VariableId::try_new("edge").unwrap()].states[1].probability_ppb,
            857_142_857
        );
    }

    #[test]
    fn exact_duplicate_factors_are_idempotent_and_divergent_ids_fail() {
        let factor = positive_factor("same", &["edge"], &[1.0, 4.0], "evidence:edge");
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("edge")],
            vec![factor.clone(), factor],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        assert_eq!(graph.factors.len(), 1);

        let divergent = positive_factor("same", &["edge"], &[1.0, 5.0], "evidence:other");
        assert!(matches!(
            DiscreteFactorGraph::try_new(
                vec![variable("edge")],
                vec![graph.factors[0].clone(), divergent],
                FactorGraphLimits::conservative()
            ),
            Err(FactorGraphError::DivergentFactor)
        ));
    }

    #[test]
    fn component_and_total_assignment_limits_return_typed_receipts() {
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("a"), variable("b")],
            vec![
                positive_factor("a", &["a"], &[1.0, 1.0], "evidence:a"),
                positive_factor("b", &["b"], &[1.0, 1.0], "evidence:b"),
            ],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let result = infer_exact(
            &graph,
            ExactInferenceLimits {
                max_component_variables: 1,
                max_assignments: 2,
            },
        )
        .unwrap();

        assert_eq!(exact_component(&result, 0).0, 2);
        assert_eq!(
            result.components[1].outcome,
            ComponentInferenceOutcome::Abstained(
                InferenceAbstentionReason::AssignmentBudgetExceeded {
                    required: 2,
                    remaining: 0,
                }
            )
        );
    }

    #[test]
    fn contradictory_constraints_return_unsatisfiable_without_fake_beliefs() {
        let joint = FactorDependence::joint_model("joint:constraints").unwrap();
        let constraint = |id: &str, admissible: Vec<bool>| {
            DiscreteFactor::try_constraint(
                FactorId::try_new(id).unwrap(),
                vec![VariableId::try_new("edge").unwrap()],
                admissible,
                FactorSemantics::deterministic_constraint(format!("proof:{id}")).unwrap(),
                FactorProvenance::try_new(
                    [atom("evidence:edge")],
                    [derivation(&format!("derive:{id}"))],
                    joint.clone(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let graph = DiscreteFactorGraph::try_new(
            vec![variable("edge")],
            vec![
                constraint("false-only", vec![true, false]),
                constraint("true-only", vec![false, true]),
            ],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let result = infer_exact(&graph, ExactInferenceLimits::conservative()).unwrap();

        assert_eq!(
            result.components[0].outcome,
            ComponentInferenceOutcome::NoFeasibleAssignment {
                assignments_evaluated: 2,
            }
        );
    }

    #[test]
    fn variable_and_factor_order_do_not_change_exact_result() {
        let a = variable("a");
        let b = variable("b");
        let fa = positive_factor("fa", &["a"], &[1.0, 2.0], "evidence:a");
        let fb = positive_factor("fb", &["b"], &[1.0, 3.0], "evidence:b");
        let forward = DiscreteFactorGraph::try_new(
            vec![a.clone(), b.clone()],
            vec![fa.clone(), fb.clone()],
            FactorGraphLimits::conservative(),
        )
        .unwrap();
        let reverse = DiscreteFactorGraph::try_new(
            vec![b, a],
            vec![fb, fa],
            FactorGraphLimits::conservative(),
        )
        .unwrap();

        assert_eq!(
            infer_exact(&forward, ExactInferenceLimits::conservative()).unwrap(),
            infer_exact(&reverse, ExactInferenceLimits::conservative()).unwrap()
        );
    }
}
