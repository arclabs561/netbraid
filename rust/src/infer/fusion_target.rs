use std::collections::{BTreeMap, BTreeSet};

use crate::evidence::PACKET_ENVELOPE_SCHEMA_V0;
use crate::replay::{PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0, PACKET_SAME_EVENT_REDUCER_V0};

use super::calibrated_event_relation::{
    CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0, CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0,
    CALIBRATED_EVENT_RELATION_REDUCER_V0, EVENT_RELATION_PREDICTION_SCHEMA_V0,
    HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0,
};
use super::content_relation::{
    CONTENT_DIGEST_EVIDENCE_SCHEMA_V0, CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
    CONTENT_RELATION_REDUCER_V0,
};
use super::{
    FiniteHypothesisClaimV0, FiniteHypothesisDispositionV0, FiniteHypothesisInputRefV0,
    ProvenanceQualifiedClaimLineageStatusV0, ProvenanceQualifiedFiniteHypothesisCompositionV0,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum RelationAxis {
    Event,
    Content,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationParticipant {
    source_schema: String,
    source_id: String,
    content_sha256: String,
}

impl From<&FiniteHypothesisInputRefV0> for RelationParticipant {
    fn from(value: &FiniteHypothesisInputRefV0) -> Self {
        Self {
            source_schema: value.source_schema().to_owned(),
            source_id: value.source_id().to_owned(),
            content_sha256: value.content_sha256().to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RelationTarget {
    axis: RelationAxis,
    participants: [RelationParticipant; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationTargetGroup {
    target: RelationTarget,
    claim_indices: Box<[usize]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RelationTargetResolution {
    Unresolved,
    SingleAlternative { role: String },
    Conflict { roles: Box<[String]> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RelationTargetSummary {
    target: RelationTarget,
    claim_indices: Box<[usize]>,
    substantive_claim_indices: Box<[usize]>,
    abstaining_claim_indices: Box<[usize]>,
    declared_shared_lineage_pairs: Box<[(usize, usize)]>,
    resolution: RelationTargetResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RelationTargetError {
    InvalidKnownFamilyContract,
    InvalidClaimDisposition,
}

#[derive(Debug, Clone, Copy)]
struct RelationContract {
    axis: RelationAxis,
    reducer: &'static str,
    alternative_roles: &'static [&'static str],
    input_roles: &'static [&'static str],
    input_schemas: &'static [Option<&'static str>],
    participant_roles: [&'static str; 2],
}

const EVENT_ALTERNATIVE_ROLES: &[&str] = &["same_event", "different_event", "unknown"];
const CONTENT_ALTERNATIVE_ROLES: &[&str] = &["sha256_match", "sha256_mismatch", "unknown"];
const PACKET_SAME_EVENT_INPUT_ROLES: &[&str] = &["left_packet", "right_packet"];
const PACKET_SAME_EVENT_INPUT_SCHEMAS: &[Option<&str>] = &[
    Some(PACKET_ENVELOPE_SCHEMA_V0),
    Some(PACKET_ENVELOPE_SCHEMA_V0),
];
const CALIBRATED_EVENT_INPUT_ROLES: &[&str] = &[
    "calibration_profile",
    "heldout_evaluation_receipt",
    "left_observation",
    "prediction",
    "right_observation",
];
const CALIBRATED_EVENT_INPUT_SCHEMAS: &[Option<&str>] = &[
    Some(CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0),
    Some(HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0),
    None,
    Some(EVENT_RELATION_PREDICTION_SCHEMA_V0),
    None,
];
const CONTENT_RELATION_INPUT_ROLES: &[&str] = &["left_content_evidence", "right_content_evidence"];
const CONTENT_RELATION_INPUT_SCHEMAS: &[Option<&str>] = &[
    Some(CONTENT_DIGEST_EVIDENCE_SCHEMA_V0),
    Some(CONTENT_DIGEST_EVIDENCE_SCHEMA_V0),
];

pub(crate) fn group_relation_targets(
    claims: &[FiniteHypothesisClaimV0],
) -> Result<Box<[RelationTargetGroup]>, RelationTargetError> {
    let mut groups = BTreeMap::<RelationTarget, Vec<usize>>::new();
    for (claim_index, claim) in claims.iter().enumerate() {
        if let Some(target) = relation_target(claim)? {
            groups.entry(target).or_default().push(claim_index);
        }
    }
    Ok(groups
        .into_iter()
        .map(|(target, claim_indices)| RelationTargetGroup {
            target,
            claim_indices: claim_indices.into_boxed_slice(),
        })
        .collect::<Vec<_>>()
        .into_boxed_slice())
}

pub(crate) fn summarize_relation_targets(
    qualified: &ProvenanceQualifiedFiniteHypothesisCompositionV0,
) -> Result<Box<[RelationTargetSummary]>, RelationTargetError> {
    let claims = qualified.composition().claims();
    let groups = group_relation_targets(claims)?;
    groups
        .into_vec()
        .into_iter()
        .map(|group| summarize_group(group, claims, qualified.claim_lineage_pairs()))
        .collect::<Result<Vec<_>, _>>()
        .map(Vec::into_boxed_slice)
}

fn summarize_group(
    group: RelationTargetGroup,
    claims: &[FiniteHypothesisClaimV0],
    lineage_pairs: &[super::ProvenanceQualifiedClaimPairSummaryV0],
) -> Result<RelationTargetSummary, RelationTargetError> {
    let mut substantive_claim_indices = Vec::new();
    let mut abstaining_claim_indices = Vec::new();
    let mut substantive_roles = BTreeSet::new();
    for claim_index in &group.claim_indices {
        let mut supported = claims[*claim_index]
            .projection()
            .alternatives()
            .iter()
            .filter(|alternative| {
                alternative.disposition() == FiniteHypothesisDispositionV0::Supported
            });
        let alternative = supported
            .next()
            .ok_or(RelationTargetError::InvalidClaimDisposition)?;
        if supported.next().is_some() {
            return Err(RelationTargetError::InvalidClaimDisposition);
        }
        if alternative.role() == "unknown" {
            abstaining_claim_indices.push(*claim_index);
        } else {
            substantive_claim_indices.push(*claim_index);
            substantive_roles.insert(alternative.role().to_owned());
        }
    }

    let resolution = match substantive_roles.len() {
        0 => RelationTargetResolution::Unresolved,
        1 => RelationTargetResolution::SingleAlternative {
            role: substantive_roles
                .into_iter()
                .next()
                .expect("the exact role count was checked"),
        },
        _ => RelationTargetResolution::Conflict {
            roles: substantive_roles
                .into_iter()
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        },
    };
    let group_indices = group.claim_indices.iter().copied().collect::<BTreeSet<_>>();
    let declared_shared_lineage_pairs = lineage_pairs
        .iter()
        .filter(|pair| {
            pair.status() == ProvenanceQualifiedClaimLineageStatusV0::DeclaredSharedLineage
                && group_indices.contains(&pair.left_claim_index())
                && group_indices.contains(&pair.right_claim_index())
        })
        .map(|pair| (pair.left_claim_index(), pair.right_claim_index()))
        .collect::<Vec<_>>()
        .into_boxed_slice();

    Ok(RelationTargetSummary {
        target: group.target,
        claim_indices: group.claim_indices,
        substantive_claim_indices: substantive_claim_indices.into_boxed_slice(),
        abstaining_claim_indices: abstaining_claim_indices.into_boxed_slice(),
        declared_shared_lineage_pairs,
        resolution,
    })
}

fn relation_target(
    claim: &FiniteHypothesisClaimV0,
) -> Result<Option<RelationTarget>, RelationTargetError> {
    let Some(contract) = relation_contract(claim.projection().family_schema()) else {
        return Ok(None);
    };
    if claim.projection().reducer() != contract.reducer
        || claim
            .projection()
            .alternatives()
            .iter()
            .map(|alternative| alternative.role())
            .ne(contract.alternative_roles.iter().copied())
        || claim
            .inputs()
            .iter()
            .map(FiniteHypothesisInputRefV0::role)
            .ne(contract.input_roles.iter().copied())
        || claim
            .inputs()
            .iter()
            .zip(contract.input_schemas)
            .any(|(input, expected)| expected.is_some_and(|schema| input.source_schema() != schema))
    {
        return Err(RelationTargetError::InvalidKnownFamilyContract);
    }

    let mut participants = contract.participant_roles.map(|role| {
        claim
            .inputs()
            .iter()
            .find(|input| input.role() == role)
            .map(RelationParticipant::from)
            .expect("the exact role contract was checked")
    });
    participants.sort();
    Ok(Some(RelationTarget {
        axis: contract.axis,
        participants,
    }))
}

fn relation_contract(family_schema: &str) -> Option<RelationContract> {
    match family_schema {
        PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0 => Some(RelationContract {
            axis: RelationAxis::Event,
            reducer: PACKET_SAME_EVENT_REDUCER_V0,
            alternative_roles: EVENT_ALTERNATIVE_ROLES,
            input_roles: PACKET_SAME_EVENT_INPUT_ROLES,
            input_schemas: PACKET_SAME_EVENT_INPUT_SCHEMAS,
            participant_roles: ["left_packet", "right_packet"],
        }),
        CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0 => Some(RelationContract {
            axis: RelationAxis::Event,
            reducer: CALIBRATED_EVENT_RELATION_REDUCER_V0,
            alternative_roles: EVENT_ALTERNATIVE_ROLES,
            input_roles: CALIBRATED_EVENT_INPUT_ROLES,
            input_schemas: CALIBRATED_EVENT_INPUT_SCHEMAS,
            participant_roles: ["left_observation", "right_observation"],
        }),
        CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0 => Some(RelationContract {
            axis: RelationAxis::Content,
            reducer: CONTENT_RELATION_REDUCER_V0,
            alternative_roles: CONTENT_ALTERNATIVE_ROLES,
            input_roles: CONTENT_RELATION_INPUT_ROLES,
            input_schemas: CONTENT_RELATION_INPUT_SCHEMAS,
            participant_roles: ["left_content_evidence", "right_content_evidence"],
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::PacketEnvelopeV0;
    use crate::infer::{
        assess_calibrated_event_relation_v0, calibrated_event_relation_pair_id_v0,
        CalibratedEventRelationObservationRefV0, CalibratedEventRelationProfileV0,
        EventRelationPredictionV0, FiniteHypothesisAlternativeV0, FiniteHypothesisCompositionV0,
        FiniteHypothesisDispositionV0, FiniteHypothesisProjectionV0,
        HeldoutEventRelationEvaluationReceiptV0, ProjectFiniteHypothesisClaimV0, ProvenanceGraphV0,
    };
    use crate::replay::assess_packet_same_event_v0;
    use serde_json::json;

    fn input(
        role: &str,
        source_schema: &str,
        source_id: &str,
        digest: char,
    ) -> FiniteHypothesisInputRefV0 {
        FiniteHypothesisInputRefV0::try_new(
            role,
            source_schema,
            source_id,
            digest.to_string().repeat(64),
        )
        .unwrap()
    }

    fn claim(
        family_schema: &str,
        reducer: &str,
        alternatives: [&str; 3],
        inputs: Vec<FiniteHypothesisInputRefV0>,
    ) -> FiniteHypothesisClaimV0 {
        claim_supporting(
            family_schema,
            reducer,
            alternatives,
            alternatives[0],
            inputs,
        )
    }

    fn claim_supporting(
        family_schema: &str,
        reducer: &str,
        alternatives: [&str; 3],
        supported_role: &str,
        inputs: Vec<FiniteHypothesisInputRefV0>,
    ) -> FiniteHypothesisClaimV0 {
        let alternatives = alternatives
            .into_iter()
            .map(|role| {
                FiniteHypothesisAlternativeV0::try_new(
                    role,
                    if role == supported_role {
                        FiniteHypothesisDispositionV0::Supported
                    } else if supported_role == "unknown" {
                        FiniteHypothesisDispositionV0::Underdetermined
                    } else {
                        FiniteHypothesisDispositionV0::Contradicted
                    },
                )
                .unwrap()
            })
            .collect();
        let projection =
            FiniteHypothesisProjectionV0::try_new(family_schema, reducer, alternatives).unwrap();
        FiniteHypothesisClaimV0::try_new(projection, inputs).unwrap()
    }

    fn packet_event_claim(left: (&str, char), right: (&str, char)) -> FiniteHypothesisClaimV0 {
        packet_event_claim_supporting(left, right, "same_event")
    }

    fn packet_event_claim_supporting(
        left: (&str, char),
        right: (&str, char),
        supported_role: &str,
    ) -> FiniteHypothesisClaimV0 {
        claim_supporting(
            PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0,
            PACKET_SAME_EVENT_REDUCER_V0,
            ["same_event", "different_event", "unknown"],
            supported_role,
            vec![
                input("left_packet", PACKET_ENVELOPE_SCHEMA_V0, left.0, left.1),
                input("right_packet", PACKET_ENVELOPE_SCHEMA_V0, right.0, right.1),
            ],
        )
    }

    fn calibrated_event_claim(
        left: (&str, char),
        right: (&str, char),
        support_digest: char,
    ) -> FiniteHypothesisClaimV0 {
        calibrated_event_claim_supporting(left, right, support_digest, "same_event")
    }

    fn calibrated_event_claim_supporting(
        left: (&str, char),
        right: (&str, char),
        support_digest: char,
        supported_role: &str,
    ) -> FiniteHypothesisClaimV0 {
        claim_supporting(
            CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0,
            CALIBRATED_EVENT_RELATION_REDUCER_V0,
            ["same_event", "different_event", "unknown"],
            supported_role,
            vec![
                input(
                    "calibration_profile",
                    CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0,
                    "profile:0",
                    support_digest,
                ),
                input(
                    "heldout_evaluation_receipt",
                    HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0,
                    "receipt:0",
                    support_digest,
                ),
                input(
                    "left_observation",
                    PACKET_ENVELOPE_SCHEMA_V0,
                    left.0,
                    left.1,
                ),
                input(
                    "prediction",
                    EVENT_RELATION_PREDICTION_SCHEMA_V0,
                    "prediction:0",
                    support_digest,
                ),
                input(
                    "right_observation",
                    PACKET_ENVELOPE_SCHEMA_V0,
                    right.0,
                    right.1,
                ),
            ],
        )
    }

    fn content_claim(left: (&str, char), right: (&str, char)) -> FiniteHypothesisClaimV0 {
        claim(
            CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
            CONTENT_RELATION_REDUCER_V0,
            ["sha256_match", "sha256_mismatch", "unknown"],
            vec![
                input(
                    "left_content_evidence",
                    CONTENT_DIGEST_EVIDENCE_SCHEMA_V0,
                    left.0,
                    left.1,
                ),
                input(
                    "right_content_evidence",
                    CONTENT_DIGEST_EVIDENCE_SCHEMA_V0,
                    right.0,
                    right.1,
                ),
            ],
        )
    }

    fn summarize(claims: Vec<FiniteHypothesisClaimV0>) -> Box<[RelationTargetSummary]> {
        let composition = FiniteHypothesisCompositionV0::try_new(claims).unwrap();
        let qualified = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
            composition,
            ProvenanceGraphV0::try_new(Vec::new()).unwrap(),
        )
        .unwrap();
        summarize_relation_targets(&qualified).unwrap()
    }

    #[test]
    fn heterogeneous_event_claims_share_one_content_bound_target() {
        let claims = [
            packet_event_claim(("packet:a", 'a'), ("packet:b", 'b')),
            calibrated_event_claim(("packet:a", 'a'), ("packet:b", 'b'), 'c'),
            calibrated_event_claim(("packet:a", 'a'), ("packet:b", 'b'), 'd'),
        ];

        let groups = group_relation_targets(&claims).unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].target.axis, RelationAxis::Event);
        assert_eq!(&*groups[0].claim_indices, &[0, 1, 2]);
        assert_eq!(groups[0].target.participants[0].source_id, "packet:a");
        assert_eq!(groups[0].target.participants[1].source_id, "packet:b");
        assert!(groups[0]
            .target
            .participants
            .iter()
            .all(|participant| !participant.source_id.contains("profile")
                && !participant.source_id.contains("prediction")
                && !participant.source_id.contains("receipt")));
    }

    #[test]
    fn symmetric_participant_order_does_not_split_a_target() {
        let claims = [
            packet_event_claim(("packet:a", 'a'), ("packet:b", 'b')),
            packet_event_claim(("packet:b", 'b'), ("packet:a", 'a')),
        ];

        let groups = group_relation_targets(&claims).unwrap();

        assert_eq!(groups.len(), 1);
        assert_eq!(&*groups[0].claim_indices, &[0, 1]);
    }

    #[test]
    fn participant_content_and_relation_axis_remain_target_dimensions() {
        let claims = [
            packet_event_claim(("packet:a", 'a'), ("packet:b", 'b')),
            packet_event_claim(("packet:a", 'a'), ("packet:b", 'c')),
            content_claim(("packet:a", 'a'), ("packet:b", 'b')),
        ];

        let groups = group_relation_targets(&claims).unwrap();

        assert_eq!(groups.len(), 3);
        assert_eq!(
            groups
                .iter()
                .filter(|group| group.target.axis == RelationAxis::Event)
                .count(),
            2
        );
        assert_eq!(
            groups
                .iter()
                .filter(|group| group.target.axis == RelationAxis::Content)
                .count(),
            1
        );

        let participants = groups[0].target.participants.clone();
        assert_ne!(
            RelationTarget {
                axis: RelationAxis::Event,
                participants: participants.clone(),
            },
            RelationTarget {
                axis: RelationAxis::Content,
                participants,
            }
        );
    }

    #[test]
    fn unknown_abstains_without_masking_one_substantive_alternative() {
        let summaries = summarize(vec![
            packet_event_claim_supporting(("packet:a", 'a'), ("packet:b", 'b'), "unknown"),
            calibrated_event_claim_supporting(
                ("packet:a", 'a'),
                ("packet:b", 'b'),
                'c',
                "same_event",
            ),
        ]);

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].claim_indices.len(), 2);
        assert_eq!(summaries[0].substantive_claim_indices.len(), 1);
        assert_eq!(summaries[0].abstaining_claim_indices.len(), 1);
        assert_eq!(
            summaries[0].resolution,
            RelationTargetResolution::SingleAlternative {
                role: "same_event".to_owned()
            }
        );
        assert_eq!(&*summaries[0].declared_shared_lineage_pairs, &[(0, 1)]);
    }

    #[test]
    fn substantive_disagreement_is_retained_as_conflict() {
        let summaries = summarize(vec![
            packet_event_claim_supporting(("packet:a", 'a'), ("packet:b", 'b'), "different_event"),
            calibrated_event_claim_supporting(
                ("packet:a", 'a'),
                ("packet:b", 'b'),
                'c',
                "same_event",
            ),
        ]);

        assert_eq!(
            summaries[0].resolution,
            RelationTargetResolution::Conflict {
                roles: vec!["different_event".to_owned(), "same_event".to_owned()]
                    .into_boxed_slice()
            }
        );
        assert_eq!(summaries[0].substantive_claim_indices.len(), 2);
        assert!(summaries[0].abstaining_claim_indices.is_empty());
    }

    #[test]
    fn all_abstentions_leave_the_target_unresolved() {
        let summaries = summarize(vec![
            packet_event_claim_supporting(("packet:a", 'a'), ("packet:b", 'b'), "unknown"),
            calibrated_event_claim_supporting(("packet:a", 'a'), ("packet:b", 'b'), 'c', "unknown"),
        ]);

        assert_eq!(
            summaries[0].resolution,
            RelationTargetResolution::Unresolved
        );
        assert!(summaries[0].substantive_claim_indices.is_empty());
        assert_eq!(summaries[0].abstaining_claim_indices.len(), 2);
    }

    #[test]
    fn known_family_contract_drift_fails_closed() {
        let malformed = claim(
            PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0,
            PACKET_SAME_EVENT_REDUCER_V0,
            ["same_event", "different_event", "unknown"],
            vec![
                input("left_packet", PACKET_ENVELOPE_SCHEMA_V0, "packet:a", 'a'),
                input("model", "netbraid.model.v0", "model:0", 'c'),
                input("right_packet", PACKET_ENVELOPE_SCHEMA_V0, "packet:b", 'b'),
            ],
        );

        assert_eq!(
            group_relation_targets(&[malformed]),
            Err(RelationTargetError::InvalidKnownFamilyContract)
        );
    }

    #[test]
    fn unrecognized_families_remain_outside_the_target_registry() {
        let unrecognized = claim(
            "netbraid.device_relation.v0",
            "netbraid.device_relation.fixture.v0",
            ["same_device", "different_device", "unknown"],
            vec![
                input("left", "netbraid.observation.v0", "observation:a", 'a'),
                input("right", "netbraid.observation.v0", "observation:b", 'b'),
            ],
        );

        assert!(group_relation_targets(&[unrecognized]).unwrap().is_empty());
    }

    #[test]
    fn production_projectors_retain_abstention_conflict_and_shared_lineage() {
        let left_packet: PacketEnvelopeV0 = serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/packet_envelope_v0.json"
        ))
        .unwrap();
        let mut right_packet = left_packet.clone();
        right_packet.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right_packet.record_id = format!("{}:frame:1", right_packet.capture_id);
        let packet_claim = assess_packet_same_event_v0(&left_packet, &right_packet)
            .unwrap()
            .project_finite_hypothesis_claim_v0((&left_packet, &right_packet))
            .unwrap();
        assert_eq!(
            packet_claim
                .projection()
                .alternatives()
                .iter()
                .find(|alternative| {
                    alternative.disposition() == FiniteHypothesisDispositionV0::Supported
                })
                .unwrap()
                .role(),
            "unknown"
        );

        let left = CalibratedEventRelationObservationRefV0::try_new(
            packet_claim.inputs()[0].source_schema(),
            packet_claim.inputs()[0].source_id(),
            packet_claim.inputs()[0].content_sha256(),
        )
        .unwrap();
        let right = CalibratedEventRelationObservationRefV0::try_new(
            packet_claim.inputs()[1].source_schema(),
            packet_claim.inputs()[1].source_id(),
            packet_claim.inputs()[1].content_sha256(),
        )
        .unwrap();
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/infer/v0/calibrated-event-relation-admission.json"
        ))
        .unwrap();
        let profile = CalibratedEventRelationProfileV0::from_json_bytes(
            &serde_json::to_vec(&fixture["profile"]).unwrap(),
        )
        .unwrap();
        let receipt = HeldoutEventRelationEvaluationReceiptV0::from_json_bytes(
            &serde_json::to_vec(&fixture["heldout_evaluation_receipt"]).unwrap(),
            &profile,
        )
        .unwrap();

        let mut same_document = fixture["prediction"].clone();
        same_document["frame_id"] =
            json!(calibrated_event_relation_pair_id_v0(&left, &right).unwrap());
        let same_prediction = EventRelationPredictionV0::from_json_bytes(
            &serde_json::to_vec(&same_document).unwrap(),
            &profile,
        )
        .unwrap();
        let same_claim = assess_calibrated_event_relation_v0(
            &left,
            &right,
            &profile,
            &same_prediction,
            &receipt,
        )
        .unwrap()
        .project_finite_hypothesis_claim_v0((&left, &right, &profile, &same_prediction, &receipt))
        .unwrap();

        let mut different_document = same_document;
        different_document["forward_score"] = json!("0x1.8000000000000p-1");
        different_document["reverse_score"] = json!("0x1.999999999999ap-1");
        different_document["decision"] = json!("different");
        let different_prediction = EventRelationPredictionV0::from_json_bytes(
            &serde_json::to_vec(&different_document).unwrap(),
            &profile,
        )
        .unwrap();
        let different_claim = assess_calibrated_event_relation_v0(
            &left,
            &right,
            &profile,
            &different_prediction,
            &receipt,
        )
        .unwrap()
        .project_finite_hypothesis_claim_v0((
            &left,
            &right,
            &profile,
            &different_prediction,
            &receipt,
        ))
        .unwrap();

        let composition =
            FiniteHypothesisCompositionV0::try_new(vec![packet_claim, same_claim, different_claim])
                .unwrap();
        let qualified = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
            composition,
            ProvenanceGraphV0::try_new(Vec::new()).unwrap(),
        )
        .unwrap();
        let summaries = summarize_relation_targets(&qualified).unwrap();

        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].target.axis, RelationAxis::Event);
        assert_eq!(summaries[0].claim_indices.len(), 3);
        assert_eq!(summaries[0].substantive_claim_indices.len(), 2);
        assert_eq!(summaries[0].abstaining_claim_indices.len(), 1);
        assert_eq!(
            summaries[0].resolution,
            RelationTargetResolution::Conflict {
                roles: vec!["different_event".to_owned(), "same_event".to_owned()]
                    .into_boxed_slice()
            }
        );
        assert_eq!(summaries[0].declared_shared_lineage_pairs.len(), 3);
    }
}
