use std::cmp::Ordering;

use serde::Serialize;

use super::FiniteHypothesisClaimV0;

pub const FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0: &str =
    "netbraid.finite_hypothesis_composition.v0";
pub const FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0: usize = 64;

/// A bounded set of evidence-linked finite hypothesis claims.
///
/// Each claim occupies the exact slot identified by its family schema,
/// reducer, and canonical content-bound inputs. Different slots remain
/// separate: co-presence does not assert that their inputs concern the
/// same identity or entity, and an omitted family remains absent rather than
/// being synthesized as an unknown claim. The composition retains each claim
/// unchanged, including its existing source identifiers; it adds no new
/// identifier or raw evidence field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FiniteHypothesisCompositionV0 {
    schema: String,
    claims: Box<[FiniteHypothesisClaimV0]>,
}

impl FiniteHypothesisCompositionV0 {
    /// Canonicalize a bounded collection of typed finite hypothesis claims.
    ///
    /// At most [`FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0`]
    /// claims are admitted so canonicalization work remains bounded. Within
    /// that admitted batch, exact duplicates are idempotent. Claims with the
    /// same family, reducer, and inputs must be exactly equal or construction
    /// fails closed.
    pub fn try_new(
        mut claims: Vec<FiniteHypothesisClaimV0>,
    ) -> Result<Self, FiniteHypothesisCompositionErrorV0> {
        if claims.len() > FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0 {
            return Err(FiniteHypothesisCompositionErrorV0::SubmittedClaimLimitExceeded);
        }

        claims.sort_by(compare_claim_slots);
        let mut canonical = Vec::with_capacity(claims.len());
        for claim in claims {
            if let Some(previous) = canonical.last() {
                if compare_claim_slots(previous, &claim) == Ordering::Equal {
                    if previous == &claim {
                        continue;
                    }
                    return Err(FiniteHypothesisCompositionErrorV0::DivergentSlot);
                }
            }
            canonical.push(claim);
        }

        Ok(Self {
            schema: FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0.to_owned(),
            claims: canonical.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn claims(&self) -> &[FiniteHypothesisClaimV0] {
        &self.claims
    }
}

/// Failure to construct a bounded finite hypothesis composition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FiniteHypothesisCompositionErrorV0 {
    SubmittedClaimLimitExceeded,
    DivergentSlot,
}

impl std::fmt::Display for FiniteHypothesisCompositionErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::SubmittedClaimLimitExceeded => {
                "finite-hypothesis composition submitted-claim limit exceeded"
            }
            Self::DivergentSlot => "divergent finite-hypothesis claims occupy one exact slot",
        })
    }
}

impl std::error::Error for FiniteHypothesisCompositionErrorV0 {}

fn compare_claim_slots(
    left: &FiniteHypothesisClaimV0,
    right: &FiniteHypothesisClaimV0,
) -> Ordering {
    left.projection()
        .family_schema()
        .cmp(right.projection().family_schema())
        .then_with(|| {
            left.projection()
                .reducer()
                .cmp(right.projection().reducer())
        })
        .then_with(|| compare_inputs(left, right))
}

fn compare_inputs(left: &FiniteHypothesisClaimV0, right: &FiniteHypothesisClaimV0) -> Ordering {
    for (left, right) in left.inputs().iter().zip(right.inputs()) {
        let ordering = (
            left.role(),
            left.source_schema(),
            left.source_id(),
            left.content_sha256(),
        )
            .cmp(&(
                right.role(),
                right.source_schema(),
                right.source_id(),
                right.content_sha256(),
            ));
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left.inputs().len().cmp(&right.inputs().len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infer::hypothesis::{
        FiniteHypothesisAlternativeV0, FiniteHypothesisDispositionV0, FiniteHypothesisInputRefV0,
        FiniteHypothesisProjectionV0,
    };

    fn claim(supported_role: &str) -> FiniteHypothesisClaimV0 {
        let alternatives = ["same", "different", "unknown"]
            .into_iter()
            .map(|role| {
                let disposition = if role == supported_role {
                    FiniteHypothesisDispositionV0::Supported
                } else {
                    FiniteHypothesisDispositionV0::Contradicted
                };
                FiniteHypothesisAlternativeV0::try_new(role, disposition).unwrap()
            })
            .collect();
        let projection = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            alternatives,
        )
        .unwrap();
        let inputs = ["left", "right"]
            .into_iter()
            .map(|role| {
                FiniteHypothesisInputRefV0::try_new(
                    role,
                    "netbraid.test_input.v0",
                    format!("input:{role}"),
                    if role == "left" {
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
    fn divergent_claims_in_one_exact_slot_fail_closed() {
        let error = FiniteHypothesisCompositionV0::try_new(vec![claim("same"), claim("different")])
            .unwrap_err();

        assert_eq!(error, FiniteHypothesisCompositionErrorV0::DivergentSlot);
    }
}
