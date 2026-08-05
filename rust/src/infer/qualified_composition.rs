use serde::Serialize;

use super::{
    FiniteHypothesisCompositionV0, ProvenanceArtifactRefErrorV0, ProvenanceArtifactRefV0,
    ProvenanceComparisonV0, ProvenanceContentRelationV0, ProvenanceGraphV0,
    ProvenanceLineageRelationV0,
};

pub const PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0: &str =
    "netbraid.provenance_qualified_finite_hypothesis_composition.v0";
pub const PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0: usize = 16;
pub const PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_TOTAL_CLAIM_INPUTS_V0: usize = 64;

/// Whether a canonical claim pair has lineage connected by the declared graph.
///
/// `NoSharedAncestryFound` reports only the absence of a connecting declaration
/// in the supplied graph. It does not establish that the claims are independent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceQualifiedClaimLineageStatusV0 {
    DeclaredSharedLineage,
    NoSharedAncestryFound,
}

/// One retained comparison between inputs of two canonical claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceQualifiedClaimInputRelationV0 {
    left_input_index: usize,
    right_input_index: usize,
    comparison: ProvenanceComparisonV0,
}

impl ProvenanceQualifiedClaimInputRelationV0 {
    pub fn left_input_index(&self) -> usize {
        self.left_input_index
    }

    pub fn right_input_index(&self) -> usize {
        self.right_input_index
    }

    pub fn comparison(&self) -> &ProvenanceComparisonV0 {
        &self.comparison
    }
}

/// Canonical declared-lineage summary for one pair of finite claims.
///
/// Claim and input indices refer directly to the arrays retained by the
/// qualified composition. `input_relations` contains every input pair whose
/// comparison has declared lineage or matching content. Matching content alone
/// does not change the pair's declared-lineage status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceQualifiedClaimPairSummaryV0 {
    left_claim_index: usize,
    right_claim_index: usize,
    status: ProvenanceQualifiedClaimLineageStatusV0,
    input_relations: Box<[ProvenanceQualifiedClaimInputRelationV0]>,
}

impl ProvenanceQualifiedClaimPairSummaryV0 {
    pub fn left_claim_index(&self) -> usize {
        self.left_claim_index
    }

    pub fn right_claim_index(&self) -> usize {
        self.right_claim_index
    }

    pub fn status(&self) -> ProvenanceQualifiedClaimLineageStatusV0 {
        self.status
    }

    pub fn input_relations(&self) -> &[ProvenanceQualifiedClaimInputRelationV0] {
        &self.input_relations
    }
}

/// A canonical finite hypothesis composition qualified by declared provenance.
///
/// The canonical claim array remains the sole claim identity surface. Pair
/// summaries refer to it by stable array indices and retain full content and
/// lineage comparisons for every declared connection or matching-content pair.
/// Pair status depends only on declared lineage. The composition adds no claim
/// key, subject, entity, confidence, weight, or fusion semantics.
///
/// V0 admits at most 16 canonical claims and at most 64 inputs across them.
/// Construction therefore considers at most 120 claim pairs and 1,920
/// cross-claim input pairs. The supplied provenance graph is already bounded
/// separately.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProvenanceQualifiedFiniteHypothesisCompositionV0 {
    schema: String,
    composition: FiniteHypothesisCompositionV0,
    provenance_graph: ProvenanceGraphV0,
    claim_lineage_pairs: Box<[ProvenanceQualifiedClaimPairSummaryV0]>,
}

impl ProvenanceQualifiedFiniteHypothesisCompositionV0 {
    /// Qualify canonical claims using only lineage declared by `provenance_graph`.
    ///
    /// The claim limit and then total canonical-input limit are checked before
    /// input conversion or graph comparison. Every canonical claim input must
    /// satisfy the provenance artifact-reference contract; any
    /// narrower-contract mismatch fails construction.
    pub fn try_new(
        composition: FiniteHypothesisCompositionV0,
        provenance_graph: ProvenanceGraphV0,
    ) -> Result<Self, ProvenanceQualifiedFiniteHypothesisCompositionErrorV0> {
        if composition.claims().len()
            > PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0
        {
            return Err(ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::ClaimLimitExceeded);
        }
        let total_claim_inputs = composition
            .claims()
            .iter()
            .map(|claim| claim.inputs().len())
            .sum::<usize>();
        if total_claim_inputs
            > PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_TOTAL_CLAIM_INPUTS_V0
        {
            return Err(
                ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::TotalClaimInputLimitExceeded,
            );
        }

        let mut claim_inputs = Vec::with_capacity(composition.claims().len());
        for (claim_index, claim) in composition.claims().iter().enumerate() {
            let mut inputs = Vec::with_capacity(claim.inputs().len());
            for (input_index, input) in claim.inputs().iter().enumerate() {
                let reference = ProvenanceArtifactRefV0::try_from(input).map_err(|source| {
                    ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::InvalidClaimInputReference {
                        claim_index,
                        input_index,
                        source,
                    }
                })?;
                inputs.push(reference);
            }
            claim_inputs.push(inputs.into_boxed_slice());
        }

        let mut claim_lineage_pairs = Vec::new();
        for left_claim_index in 0..claim_inputs.len() {
            for right_claim_index in (left_claim_index + 1)..claim_inputs.len() {
                let mut input_relations = Vec::new();
                let mut declared_shared_lineage = false;
                for (left_input_index, left) in claim_inputs[left_claim_index].iter().enumerate() {
                    for (right_input_index, right) in
                        claim_inputs[right_claim_index].iter().enumerate()
                    {
                        let comparison = provenance_graph.compare(left, right);
                        let lineage_connected = has_declared_shared_lineage(comparison.lineage());
                        declared_shared_lineage |= lineage_connected;
                        if lineage_connected || has_content_overlap(comparison.content()) {
                            input_relations.push(ProvenanceQualifiedClaimInputRelationV0 {
                                left_input_index,
                                right_input_index,
                                comparison,
                            });
                        }
                    }
                }
                let status = if declared_shared_lineage {
                    ProvenanceQualifiedClaimLineageStatusV0::DeclaredSharedLineage
                } else {
                    ProvenanceQualifiedClaimLineageStatusV0::NoSharedAncestryFound
                };
                claim_lineage_pairs.push(ProvenanceQualifiedClaimPairSummaryV0 {
                    left_claim_index,
                    right_claim_index,
                    status,
                    input_relations: input_relations.into_boxed_slice(),
                });
            }
        }

        Ok(Self {
            schema: PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0.to_owned(),
            composition,
            provenance_graph,
            claim_lineage_pairs: claim_lineage_pairs.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn composition(&self) -> &FiniteHypothesisCompositionV0 {
        &self.composition
    }

    pub fn provenance_graph(&self) -> &ProvenanceGraphV0 {
        &self.provenance_graph
    }

    pub fn claim_lineage_pairs(&self) -> &[ProvenanceQualifiedClaimPairSummaryV0] {
        &self.claim_lineage_pairs
    }
}

/// Failure to qualify a canonical finite hypothesis composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProvenanceQualifiedFiniteHypothesisCompositionErrorV0 {
    ClaimLimitExceeded,
    TotalClaimInputLimitExceeded,
    InvalidClaimInputReference {
        claim_index: usize,
        input_index: usize,
        source: ProvenanceArtifactRefErrorV0,
    },
}

impl std::fmt::Display for ProvenanceQualifiedFiniteHypothesisCompositionErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClaimLimitExceeded => {
                formatter.write_str("provenance-qualified composition claim limit exceeded")
            }
            Self::TotalClaimInputLimitExceeded => formatter
                .write_str("provenance-qualified composition total claim-input limit exceeded"),
            Self::InvalidClaimInputReference {
                claim_index,
                input_index,
                source,
            } => write!(
                formatter,
                "canonical claim {claim_index} input {input_index} violates the provenance reference contract: {source}"
            ),
        }
    }
}

impl std::error::Error for ProvenanceQualifiedFiniteHypothesisCompositionErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidClaimInputReference { source, .. } => Some(source),
            Self::ClaimLimitExceeded | Self::TotalClaimInputLimitExceeded => None,
        }
    }
}

fn has_declared_shared_lineage(lineage: ProvenanceLineageRelationV0) -> bool {
    matches!(
        lineage,
        ProvenanceLineageRelationV0::SameReference
            | ProvenanceLineageRelationV0::LeftDescendsFromRight
            | ProvenanceLineageRelationV0::RightDescendsFromLeft
            | ProvenanceLineageRelationV0::SharedAncestor
    )
}

fn has_content_overlap(content: ProvenanceContentRelationV0) -> bool {
    matches!(
        content,
        ProvenanceContentRelationV0::SameReference
            | ProvenanceContentRelationV0::MatchingContentDigest
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infer::{
        FiniteHypothesisAlternativeV0, FiniteHypothesisClaimV0, FiniteHypothesisDispositionV0,
        FiniteHypothesisInputRefV0, FiniteHypothesisProjectionV0,
    };

    fn claim(
        index: usize,
        input_count: usize,
        invalid_provenance_input: bool,
    ) -> FiniteHypothesisClaimV0 {
        let alternatives = ["same", "different", "unknown"]
            .into_iter()
            .map(|role| {
                FiniteHypothesisAlternativeV0::try_new(
                    role,
                    if role == "same" {
                        FiniteHypothesisDispositionV0::Supported
                    } else {
                        FiniteHypothesisDispositionV0::Contradicted
                    },
                )
                .unwrap()
            })
            .collect();
        let projection = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            alternatives,
        )
        .unwrap();
        let inputs = (0..input_count)
            .map(|input_index| {
                let source_id = if invalid_provenance_input && input_index == 0 {
                    format!("{}:{index}", "x".repeat(512))
                } else {
                    format!("input:{index}:{input_index}")
                };
                FiniteHypothesisInputRefV0::try_new(
                    format!("input_{input_index:02}"),
                    "netbraid.test_input.v0",
                    source_id,
                    if input_index % 2 == 0 {
                        "a".repeat(64)
                    } else {
                        "b".repeat(64)
                    },
                )
                .unwrap()
            })
            .collect();
        FiniteHypothesisClaimV0::try_new(projection, inputs).unwrap()
    }

    #[test]
    fn narrower_provenance_reference_contract_fails_closed() {
        let composition = FiniteHypothesisCompositionV0::try_new(vec![claim(0, 2, true)]).unwrap();

        assert_eq!(
            ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
                composition,
                ProvenanceGraphV0::try_new(vec![]).unwrap(),
            ),
            Err(
                ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::InvalidClaimInputReference {
                    claim_index: 0,
                    input_index: 0,
                    source: ProvenanceArtifactRefErrorV0::InvalidSourceId,
                }
            )
        );
    }

    #[test]
    fn claim_limit_is_enforced_before_input_conversion() {
        let claims = (0..=PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0)
            .map(|index| claim(index, 2, true))
            .collect();
        let composition = FiniteHypothesisCompositionV0::try_new(claims).unwrap();

        assert_eq!(
            ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
                composition,
                ProvenanceGraphV0::try_new(vec![]).unwrap(),
            ),
            Err(ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::ClaimLimitExceeded)
        );
    }

    #[test]
    fn total_claim_input_limit_is_enforced_before_input_conversion() {
        let claims = (0..13).map(|index| claim(index, 5, true)).collect();
        let composition = FiniteHypothesisCompositionV0::try_new(claims).unwrap();

        assert_eq!(
            ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
                composition,
                ProvenanceGraphV0::try_new(vec![]).unwrap(),
            ),
            Err(
                ProvenanceQualifiedFiniteHypothesisCompositionErrorV0::TotalClaimInputLimitExceeded
            )
        );
    }

    #[test]
    fn matching_content_is_retained_without_changing_lineage_status() {
        let composition =
            FiniteHypothesisCompositionV0::try_new(vec![claim(0, 2, false), claim(1, 2, false)])
                .unwrap();
        let qualified = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
            composition,
            ProvenanceGraphV0::try_new(vec![]).unwrap(),
        )
        .unwrap();
        let pair = &qualified.claim_lineage_pairs()[0];

        assert_eq!(
            pair.status(),
            ProvenanceQualifiedClaimLineageStatusV0::NoSharedAncestryFound
        );
        assert_eq!(pair.input_relations().len(), 2);
        for relation in pair.input_relations() {
            assert_eq!(
                relation.comparison().content(),
                ProvenanceContentRelationV0::MatchingContentDigest
            );
            assert_eq!(
                relation.comparison().lineage(),
                ProvenanceLineageRelationV0::NoSharedAncestryFound
            );
        }
        let serialized = serde_json::to_value(pair).unwrap();
        assert_eq!(serialized["status"], "no_shared_ancestry_found");
        assert_eq!(serialized["input_relations"].as_array().unwrap().len(), 2);
        assert_eq!(
            serialized["input_relations"][0]["comparison"]["content"],
            "matching_content_digest"
        );
        assert!(!serde_json::to_string(&serialized)
            .unwrap()
            .contains("independent"));
    }
}
