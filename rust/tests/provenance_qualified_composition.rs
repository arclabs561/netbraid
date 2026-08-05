use netbraid::infer::{
    assess_content_relation_v0, ContentDigestEvidenceV0, ContentSha256V0, FiniteHypothesisClaimV0,
    FiniteHypothesisCompositionV0, ProjectFiniteHypothesisClaimV0, ProvenanceActivityKindV0,
    ProvenanceActivityV0, ProvenanceArtifactRefV0, ProvenanceContentRelationV0, ProvenanceGraphV0,
    ProvenanceLineageRelationV0, ProvenanceProducerKindV0, ProvenanceProducerV0,
    ProvenanceQualifiedClaimLineageStatusV0, ProvenanceQualifiedFiniteHypothesisCompositionV0,
    ProvenanceRecordV0, PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0,
    PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_TOTAL_CLAIM_INPUTS_V0,
    PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0,
};
use serde_json::Value;

fn evidence(record_id: &str, digest_byte: char) -> ContentDigestEvidenceV0 {
    ContentDigestEvidenceV0::observed(
        record_id,
        "netbraid.test_subject.v0",
        format!("subject:{record_id}"),
        ContentSha256V0::try_new(digest_byte.to_string().repeat(64)).unwrap(),
    )
    .unwrap()
}

fn claim(
    left: &ContentDigestEvidenceV0,
    right: &ContentDigestEvidenceV0,
) -> FiniteHypothesisClaimV0 {
    assess_content_relation_v0(left, right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((left, right))
        .unwrap()
}

fn claim_input_for(
    claim: &FiniteHypothesisClaimV0,
    evidence: &ContentDigestEvidenceV0,
) -> ProvenanceArtifactRefV0 {
    let input = claim
        .inputs()
        .iter()
        .find(|input| input.source_id() == evidence.record_id())
        .unwrap();
    ProvenanceArtifactRefV0::try_from(input).unwrap()
}

fn producer(id: &str, kind: ProvenanceProducerKindV0) -> ProvenanceProducerV0 {
    ProvenanceProducerV0::try_new(id, kind).unwrap()
}

fn activity(id: &str, kind: ProvenanceActivityKindV0) -> ProvenanceActivityV0 {
    ProvenanceActivityV0::try_new(id, kind).unwrap()
}

fn root_record(output: ProvenanceArtifactRefV0, id: &str) -> ProvenanceRecordV0 {
    ProvenanceRecordV0::try_new(
        output,
        producer(&format!("sensor:{id}"), ProvenanceProducerKindV0::Sensor),
        activity(
            &format!("observe:{id}"),
            ProvenanceActivityKindV0::DirectObservation,
        ),
        vec![],
    )
    .unwrap()
}

fn derived_record(
    output: ProvenanceArtifactRefV0,
    inputs: Vec<ProvenanceArtifactRefV0>,
    id: &str,
) -> ProvenanceRecordV0 {
    ProvenanceRecordV0::try_new(
        output,
        producer(&format!("reducer:{id}"), ProvenanceProducerKindV0::Software),
        activity(
            &format!("derive:{id}"),
            ProvenanceActivityKindV0::DeterministicDerivation,
        ),
        inputs,
    )
    .unwrap()
}

fn external_artifact(id: &str, digest_byte: char) -> ProvenanceArtifactRefV0 {
    ProvenanceArtifactRefV0::try_new(
        "netbraid.test_external.v0",
        id,
        ContentSha256V0::try_new(digest_byte.to_string().repeat(64)).unwrap(),
    )
    .unwrap()
}

#[test]
fn canonical_claim_and_graph_permutations_are_byte_invariant() {
    let shared = evidence("evidence:shared", 'a');
    let parent = evidence("evidence:a-parent", 'b');
    let child = evidence("evidence:b-child", 'c');
    let separate_left = evidence("evidence:c-left", 'd');
    let separate_right = evidence("evidence:c-right", 'e');
    let first = claim(&shared, &parent);
    let second = claim(&shared, &child);
    let third = claim(&separate_left, &separate_right);
    let records = vec![
        root_record(claim_input_for(&first, &shared), "shared"),
        root_record(claim_input_for(&first, &parent), "parent"),
        derived_record(
            claim_input_for(&second, &child),
            vec![claim_input_for(&first, &parent)],
            "child",
        ),
    ];

    let forward = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![first.clone(), second.clone(), third.clone()])
            .unwrap(),
        ProvenanceGraphV0::try_new(records.clone()).unwrap(),
    )
    .unwrap();
    let reverse = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![third, second, first]).unwrap(),
        ProvenanceGraphV0::try_new(records.into_iter().rev().collect()).unwrap(),
    )
    .unwrap();

    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reverse).unwrap()
    );
    assert_eq!(forward.composition().claims().len(), 3);
    assert!(forward.composition().claims().windows(2).all(|pair| {
        pair[0].projection().family_schema() == pair[1].projection().family_schema()
            && pair[0].projection().reducer() == pair[1].projection().reducer()
            && pair[0].inputs() != pair[1].inputs()
    }));
    assert_eq!(
        forward
            .claim_lineage_pairs()
            .iter()
            .map(|pair| (pair.left_claim_index(), pair.right_claim_index()))
            .collect::<Vec<_>>(),
        [(0, 1), (0, 2), (1, 2)]
    );
}

#[test]
fn exact_direct_transitive_and_disjoint_outcomes_are_distinguished() {
    let shared = evidence("evidence:shared", 'a');
    let exact_left_aux = evidence("evidence:a-exact-aux", 'b');
    let exact_right_aux = evidence("evidence:b-exact-aux", 'c');
    let exact_left = claim(&shared, &exact_left_aux);
    let exact_right = claim(&shared, &exact_right_aux);
    let exact = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![exact_right, exact_left.clone()]).unwrap(),
        ProvenanceGraphV0::try_new(vec![root_record(
            claim_input_for(&exact_left, &shared),
            "exact-root",
        )])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        exact.claim_lineage_pairs()[0].input_relations()[0]
            .comparison()
            .lineage(),
        ProvenanceLineageRelationV0::SameReference
    );

    let direct_parent = evidence("evidence:a-direct-parent", 'd');
    let direct_child = evidence("evidence:b-direct-child", 'e');
    let direct_left_aux = evidence("evidence:a-direct-aux", 'f');
    let direct_right_aux = evidence("evidence:b-direct-aux", '0');
    let direct_left = claim(&direct_parent, &direct_left_aux);
    let direct_right = claim(&direct_child, &direct_right_aux);
    let direct = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![direct_right.clone(), direct_left.clone()])
            .unwrap(),
        ProvenanceGraphV0::try_new(vec![
            root_record(
                claim_input_for(&direct_left, &direct_parent),
                "direct-parent",
            ),
            derived_record(
                claim_input_for(&direct_right, &direct_child),
                vec![claim_input_for(&direct_left, &direct_parent)],
                "direct-child",
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        direct.claim_lineage_pairs()[0].input_relations()[0]
            .comparison()
            .lineage(),
        ProvenanceLineageRelationV0::RightDescendsFromLeft
    );

    let transitive_left_evidence = evidence("evidence:a-transitive", '1');
    let transitive_right_evidence = evidence("evidence:b-transitive", '2');
    let transitive_left_aux = evidence("evidence:a-transitive-aux", '3');
    let transitive_right_aux = evidence("evidence:b-transitive-aux", '4');
    let transitive_left = claim(&transitive_left_evidence, &transitive_left_aux);
    let transitive_right = claim(&transitive_right_evidence, &transitive_right_aux);
    let ancestor = external_artifact("ancestor:root", '5');
    let left_middle = external_artifact("ancestor:left-middle", '6');
    let right_middle = external_artifact("ancestor:right-middle", '7');
    let transitive = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![
            transitive_right.clone(),
            transitive_left.clone(),
        ])
        .unwrap(),
        ProvenanceGraphV0::try_new(vec![
            root_record(ancestor.clone(), "ancestor"),
            derived_record(left_middle.clone(), vec![ancestor.clone()], "left-middle"),
            derived_record(right_middle.clone(), vec![ancestor], "right-middle"),
            derived_record(
                claim_input_for(&transitive_left, &transitive_left_evidence),
                vec![left_middle],
                "transitive-left",
            ),
            derived_record(
                claim_input_for(&transitive_right, &transitive_right_evidence),
                vec![right_middle],
                "transitive-right",
            ),
        ])
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        transitive.claim_lineage_pairs()[0].input_relations()[0]
            .comparison()
            .lineage(),
        ProvenanceLineageRelationV0::SharedAncestor
    );

    let disjoint = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![direct_right, direct_left]).unwrap(),
        ProvenanceGraphV0::try_new(vec![]).unwrap(),
    )
    .unwrap();
    let disjoint_pair = &disjoint.claim_lineage_pairs()[0];
    assert_eq!(
        disjoint_pair.status(),
        ProvenanceQualifiedClaimLineageStatusV0::NoSharedAncestryFound
    );
    assert!(disjoint_pair.input_relations().is_empty());
    let serialized = serde_json::to_string(disjoint_pair).unwrap();
    assert!(serialized.contains("no_shared_ancestry_found"));
    assert!(!serialized.contains("independent"));
}

#[test]
fn retained_relations_are_deterministic_auditable_and_schema_minimal() {
    let shared = evidence("evidence:shared-audit", '8');
    let parent = evidence("evidence:a-parent-audit", '9');
    let child = evidence("evidence:b-child-audit", 'a');
    let left = claim(&shared, &parent);
    let right = claim(&shared, &child);
    let graph = ProvenanceGraphV0::try_new(vec![
        root_record(claim_input_for(&left, &shared), "shared-audit"),
        root_record(claim_input_for(&left, &parent), "parent-audit"),
        derived_record(
            claim_input_for(&right, &child),
            vec![claim_input_for(&left, &parent)],
            "child-audit",
        ),
    ])
    .unwrap();
    let qualified = ProvenanceQualifiedFiniteHypothesisCompositionV0::try_new(
        FiniteHypothesisCompositionV0::try_new(vec![right, left]).unwrap(),
        graph,
    )
    .unwrap();
    let pair = &qualified.claim_lineage_pairs()[0];

    assert_eq!(
        pair.status(),
        ProvenanceQualifiedClaimLineageStatusV0::DeclaredSharedLineage
    );
    assert_eq!(
        pair.input_relations()
            .iter()
            .map(|relation| (relation.left_input_index(), relation.right_input_index()))
            .collect::<Vec<_>>(),
        [(0, 0), (1, 1)]
    );
    assert_eq!(
        pair.input_relations()[0].comparison().content(),
        ProvenanceContentRelationV0::DifferentContentDigest
    );
    assert_eq!(
        pair.input_relations()[0].comparison().lineage(),
        ProvenanceLineageRelationV0::RightDescendsFromLeft
    );
    assert_eq!(
        pair.input_relations()[1].comparison().content(),
        ProvenanceContentRelationV0::SameReference
    );
    assert_eq!(
        pair.input_relations()[1].comparison().lineage(),
        ProvenanceLineageRelationV0::SameReference
    );

    for relation in pair.input_relations() {
        let left = ProvenanceArtifactRefV0::try_from(
            &qualified.composition().claims()[pair.left_claim_index()].inputs()
                [relation.left_input_index()],
        )
        .unwrap();
        let right = ProvenanceArtifactRefV0::try_from(
            &qualified.composition().claims()[pair.right_claim_index()].inputs()
                [relation.right_input_index()],
        )
        .unwrap();
        assert_eq!(
            qualified.provenance_graph().compare(&left, &right),
            *relation.comparison()
        );
    }

    let document = serde_json::to_value(&qualified).unwrap();
    assert_eq!(
        qualified.schema(),
        PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0
    );
    assert_eq!(
        PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0,
        16
    );
    assert_eq!(
        PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_TOTAL_CLAIM_INPUTS_V0,
        64
    );
    assert_eq!(document.as_object().unwrap().len(), 4);
    assert_eq!(document["claim_lineage_pairs"][0]["left_claim_index"], 0);
    assert_eq!(document["claim_lineage_pairs"][0]["right_claim_index"], 1);
    assert_forbidden_fields_absent(&document);
}

fn assert_forbidden_fields_absent(value: &Value) {
    match value {
        Value::Object(object) => {
            for forbidden in [
                "subject",
                "identity",
                "entity",
                "fusion",
                "weight",
                "confidence",
                "claim_key",
                "evidence_root",
            ] {
                assert!(!object.contains_key(forbidden));
            }
            for nested in object.values() {
                assert_forbidden_fields_absent(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_forbidden_fields_absent(nested);
            }
        }
        _ => {}
    }
}
