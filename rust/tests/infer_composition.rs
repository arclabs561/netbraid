use netbraid::evidence::PacketEnvelopeV0;
use netbraid::infer::{
    assess_content_relation_v0, assess_packet_same_event_v0, ContentDigestEvidenceV0,
    ContentDigestUnavailableReasonV0, ContentSha256V0, FiniteHypothesisClaimV0,
    FiniteHypothesisCompositionErrorV0, FiniteHypothesisCompositionV0,
    ProjectFiniteHypothesisClaimV0, CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
    FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0, FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0,
    PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0,
};
use proptest::prelude::*;

fn content_claim(index: usize) -> FiniteHypothesisClaimV0 {
    let left = ContentDigestEvidenceV0::observed(
        format!("digest:left:{index}"),
        "netbraid.test_subject.v0",
        format!("subject:left:{index}"),
        ContentSha256V0::try_new("a".repeat(64)).unwrap(),
    )
    .unwrap();
    let right = ContentDigestEvidenceV0::observed(
        format!("digest:right:{index}"),
        "netbraid.test_subject.v0",
        format!("subject:right:{index}"),
        ContentSha256V0::try_new("b".repeat(64)).unwrap(),
    )
    .unwrap();
    assess_content_relation_v0(&left, &right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((&left, &right))
        .unwrap()
}

fn unknown_content_claim() -> FiniteHypothesisClaimV0 {
    let left = ContentDigestEvidenceV0::unavailable(
        "digest:unknown:left",
        "netbraid.test_subject.v0",
        "subject:unknown:left",
        ContentDigestUnavailableReasonV0::NotProvided,
    )
    .unwrap();
    let right = ContentDigestEvidenceV0::observed(
        "digest:unknown:right",
        "netbraid.test_subject.v0",
        "subject:unknown:right",
        ContentSha256V0::try_new("b".repeat(64)).unwrap(),
    )
    .unwrap();
    assess_content_relation_v0(&left, &right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((&left, &right))
        .unwrap()
}

fn packet_pair() -> (PacketEnvelopeV0, PacketEnvelopeV0) {
    let left: PacketEnvelopeV0 = serde_json::from_str(include_str!(
        "fixtures/replay/evidence-v0/packet_envelope_v0.json"
    ))
    .unwrap();
    let mut right = left.clone();
    right.capture_id =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
    right.record_id = format!("{}:frame:1", right.capture_id);
    (left, right)
}

fn packet_claim(left: &PacketEnvelopeV0, right: &PacketEnvelopeV0) -> FiniteHypothesisClaimV0 {
    assess_packet_same_event_v0(left, right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((left, right))
        .unwrap()
}

#[test]
fn canonical_order_and_exact_duplicates_are_byte_invariant() {
    let claims = [content_claim(0), content_claim(1), content_claim(2)];
    let canonical = FiniteHypothesisCompositionV0::try_new(claims.to_vec()).unwrap();
    let permuted = FiniteHypothesisCompositionV0::try_new(vec![
        claims[2].clone(),
        claims[0].clone(),
        claims[1].clone(),
        claims[0].clone(),
    ])
    .unwrap();

    assert_eq!(
        serde_json::to_vec(&permuted).unwrap(),
        serde_json::to_vec(&canonical).unwrap()
    );
    assert_eq!(permuted.claims().len(), 3);
    assert_eq!(
        permuted.claims()[0].inputs()[0].source_id(),
        "digest:left:0"
    );
}

#[test]
fn unknown_families_remain_independent_and_omitted_families_remain_absent() {
    let content = unknown_content_claim();
    let (left, right) = packet_pair();
    let packet = packet_claim(&left, &right);
    assert_eq!(content.projection().alternatives()[2].role(), "unknown");
    assert_eq!(packet.projection().alternatives()[2].role(), "unknown");

    let composition =
        FiniteHypothesisCompositionV0::try_new(vec![packet.clone(), content.clone()]).unwrap();
    assert_eq!(
        composition.schema(),
        FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0
    );
    assert_eq!(composition.claims().len(), 2);
    assert!(composition.claims().contains(&content));
    assert!(composition.claims().contains(&packet));
    assert_eq!(
        composition
            .claims()
            .iter()
            .map(|claim| claim.projection().family_schema())
            .collect::<Vec<_>>(),
        [
            CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
            PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0,
        ]
    );

    let content_only = FiniteHypothesisCompositionV0::try_new(vec![content]).unwrap();
    let families = content_only
        .claims()
        .iter()
        .map(|claim| claim.projection().family_schema())
        .collect::<Vec<_>>();
    assert_eq!(families, [CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0]);
    assert!(!families.contains(&PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0));

    let document = serde_json::to_value(composition).unwrap();
    let object = document.as_object().unwrap();
    assert_eq!(object.len(), 2);
    assert!(object.contains_key("schema"));
    assert!(object.contains_key("claims"));
    assert!(!object.contains_key("subject"));
    assert!(!object.contains_key("identity"));
}

#[test]
fn claim_input_is_bounded_before_duplicate_elision() {
    let claims = vec![content_claim(0); FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0 + 1];
    assert_eq!(
        FiniteHypothesisCompositionV0::try_new(claims),
        Err(FiniteHypothesisCompositionErrorV0::SubmittedClaimLimitExceeded)
    );
}

#[test]
fn serialized_and_direct_resolved_values_compose_identically() {
    let (live_left, live_right) = packet_pair();
    let replay_left: PacketEnvelopeV0 =
        serde_json::from_slice(&serde_json::to_vec(&live_left).unwrap()).unwrap();
    let replay_right: PacketEnvelopeV0 =
        serde_json::from_slice(&serde_json::to_vec(&live_right).unwrap()).unwrap();

    let live = FiniteHypothesisCompositionV0::try_new(vec![packet_claim(&live_left, &live_right)])
        .unwrap();
    let replay =
        FiniteHypothesisCompositionV0::try_new(vec![packet_claim(&replay_left, &replay_right)])
            .unwrap();

    assert_eq!(live, replay);
    assert_eq!(
        serde_json::to_vec(&live).unwrap(),
        serde_json::to_vec(&replay).unwrap()
    );
}

proptest! {
    #[test]
    fn arbitrary_insertion_order_and_repetition_canonicalize(indices in prop::collection::vec(0usize..3, 0..=FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0)) {
        let available = [content_claim(0), content_claim(1), content_claim(2)];
        let forward = indices.iter().map(|index| available[*index].clone()).collect();
        let reverse = indices.iter().rev().map(|index| available[*index].clone()).collect();
        let forward = FiniteHypothesisCompositionV0::try_new(forward).unwrap();
        let reverse = FiniteHypothesisCompositionV0::try_new(reverse).unwrap();
        let expected_unique = (0..3).filter(|index| indices.contains(index)).count();

        prop_assert_eq!(forward.claims().len(), expected_unique);
        prop_assert_eq!(serde_json::to_vec(&forward).unwrap(), serde_json::to_vec(&reverse).unwrap());
    }
}
