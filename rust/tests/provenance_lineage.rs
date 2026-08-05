use netbraid::infer::{
    CalibratedEventRelationObservationRefV0, ContentBoundEvidenceRefV0, ContentSha256V0,
    ProvenanceActivityKindV0, ProvenanceActivityV0, ProvenanceArtifactRefErrorV0,
    ProvenanceArtifactRefV0, ProvenanceContentRelationV0, ProvenanceGraphErrorV0,
    ProvenanceGraphV0, ProvenanceLineageRelationV0, ProvenanceProducerKindV0, ProvenanceProducerV0,
    ProvenanceRecordErrorV0, ProvenanceRecordV0, PROVENANCE_GRAPH_SCHEMA_V0,
};

fn artifact(schema: &str, id: &str, digest_byte: char) -> ProvenanceArtifactRefV0 {
    ProvenanceArtifactRefV0::try_new(
        schema,
        id,
        ContentSha256V0::try_new(digest_byte.to_string().repeat(64)).unwrap(),
    )
    .unwrap()
}

fn producer(id: &str, kind: ProvenanceProducerKindV0) -> ProvenanceProducerV0 {
    ProvenanceProducerV0::try_new(id, kind).unwrap()
}

fn activity(id: &str, kind: ProvenanceActivityKindV0) -> ProvenanceActivityV0 {
    ProvenanceActivityV0::try_new(id, kind).unwrap()
}

fn record(
    output: ProvenanceArtifactRefV0,
    producer: ProvenanceProducerV0,
    activity: ProvenanceActivityV0,
    inputs: Vec<ProvenanceArtifactRefV0>,
) -> ProvenanceRecordV0 {
    ProvenanceRecordV0::try_new(output, producer, activity, inputs).unwrap()
}

#[test]
fn calibrated_and_family_specific_evidence_share_one_content_bound_reference_contract() {
    let calibrated = CalibratedEventRelationObservationRefV0::try_new(
        "netbraid.test.signal_window.v0",
        "signal-window:7",
        "a".repeat(64),
    )
    .unwrap();
    let converted = ContentBoundEvidenceRefV0::try_from(&calibrated).unwrap();

    assert_eq!(converted.source_schema(), calibrated.source_schema());
    assert_eq!(converted.source_id(), calibrated.source_id());
    assert_eq!(
        converted.content_sha256().as_str(),
        calibrated.content_sha256()
    );

    for (schema, source_id, digest) in [
        ("netbraid.test.signal_window.v0", "signal:1", 'b'),
        ("netmon.packet_envelope.v0", "packet:1", 'c'),
        ("netbraid.packet_flow.v0", "flow:1", 'd'),
    ] {
        let reference = ContentBoundEvidenceRefV0::try_new(
            schema,
            source_id,
            ContentSha256V0::try_new(digest.to_string().repeat(64)).unwrap(),
        )
        .unwrap();
        assert_eq!(reference.source_schema(), schema);
        assert_eq!(reference.source_id(), source_id);
    }

    assert_eq!(
        serde_json::to_vec(&converted).unwrap(),
        serde_json::to_vec(&ProvenanceArtifactRefV0::try_from(&calibrated).unwrap()).unwrap()
    );

    let digest = ContentSha256V0::try_new("e".repeat(64)).unwrap();
    assert_eq!(
        ContentBoundEvidenceRefV0::try_new("", "source:1", digest.clone()),
        Err(ProvenanceArtifactRefErrorV0::InvalidSourceSchema)
    );
    assert_eq!(
        ContentBoundEvidenceRefV0::try_new("netbraid.test.observation.v0", "x".repeat(513), digest,),
        Err(ProvenanceArtifactRefErrorV0::InvalidSourceId)
    );
}

#[test]
fn delayed_annotations_retain_their_source_chain() {
    let raw = artifact("netbraid.test.sensor.v0", "sensor:7", 'a');
    let normalized = artifact("netbraid.test.normalized.v0", "row:11", 'b');
    let model_note = artifact("netbraid.test.annotation.v0", "model:18", 'c');
    let human_note = artifact("netbraid.test.annotation.v0", "human:23", 'd');

    let graph = ProvenanceGraphV0::try_new(vec![
        record(
            raw.clone(),
            producer("sensor:alpha", ProvenanceProducerKindV0::Sensor),
            activity("observe:7", ProvenanceActivityKindV0::DirectObservation),
            vec![],
        ),
        record(
            normalized.clone(),
            producer("adapter:1", ProvenanceProducerKindV0::Software),
            activity(
                "normalize:11",
                ProvenanceActivityKindV0::DeterministicDerivation,
            ),
            vec![raw.clone()],
        ),
        record(
            model_note.clone(),
            producer("model:classifier", ProvenanceProducerKindV0::Model),
            activity("annotate:18", ProvenanceActivityKindV0::ModelAnnotation),
            vec![normalized],
        ),
        record(
            human_note.clone(),
            producer("human:reviewer", ProvenanceProducerKindV0::Human),
            activity("annotate:23", ProvenanceActivityKindV0::HumanAnnotation),
            vec![model_note.clone()],
        ),
    ])
    .unwrap();

    assert_eq!(graph.schema(), PROVENANCE_GRAPH_SCHEMA_V0);
    assert_eq!(
        graph.compare(&human_note, &raw).lineage(),
        ProvenanceLineageRelationV0::LeftDescendsFromRight
    );
    assert_eq!(
        graph.compare(&model_note, &human_note).lineage(),
        ProvenanceLineageRelationV0::RightDescendsFromLeft
    );
}

#[test]
fn sibling_inferences_share_ancestry_without_becoming_duplicate_content() {
    let source = artifact("netbraid.test.observation.v0", "source:1", 'a');
    let left = artifact("netbraid.test.claim.v0", "claim:left", 'b');
    let right = artifact("netbraid.test.claim.v0", "claim:right", 'c');
    let graph = ProvenanceGraphV0::try_new(vec![
        record(
            source.clone(),
            producer("sensor:1", ProvenanceProducerKindV0::Sensor),
            activity("observe:1", ProvenanceActivityKindV0::DirectObservation),
            vec![],
        ),
        record(
            left.clone(),
            producer("reducer:left", ProvenanceProducerKindV0::Software),
            activity("infer:left", ProvenanceActivityKindV0::StatisticalInference),
            vec![source.clone()],
        ),
        record(
            right.clone(),
            producer("reducer:right", ProvenanceProducerKindV0::Software),
            activity(
                "infer:right",
                ProvenanceActivityKindV0::StatisticalInference,
            ),
            vec![source],
        ),
    ])
    .unwrap();

    let comparison = graph.compare(&left, &right);
    assert_eq!(
        comparison.content(),
        ProvenanceContentRelationV0::DifferentContentDigest
    );
    assert_eq!(
        comparison.lineage(),
        ProvenanceLineageRelationV0::SharedAncestor
    );
}

#[test]
fn matching_bytes_and_declared_lineage_remain_orthogonal() {
    let original = artifact("netbraid.test.report.v0", "report:original", 'a');
    let repeated = artifact("netbraid.test.report.v0", "report:repeat", 'a');
    let unrelated_copy = artifact("netbraid.test.report.v0", "report:unknown", 'a');
    let graph = ProvenanceGraphV0::try_new(vec![
        record(
            original.clone(),
            producer("human:author", ProvenanceProducerKindV0::Human),
            activity(
                "assert:original",
                ProvenanceActivityKindV0::AuthoredAssertion,
            ),
            vec![],
        ),
        record(
            repeated.clone(),
            producer("software:feed", ProvenanceProducerKindV0::Software),
            activity("repeat:1", ProvenanceActivityKindV0::Repetition),
            vec![original.clone()],
        ),
    ])
    .unwrap();

    let declared = graph.compare(&repeated, &original);
    assert_eq!(
        declared.content(),
        ProvenanceContentRelationV0::MatchingContentDigest
    );
    assert_eq!(
        declared.lineage(),
        ProvenanceLineageRelationV0::LeftDescendsFromRight
    );

    let undeclared = graph.compare(&unrelated_copy, &original);
    assert_eq!(
        undeclared.content(),
        ProvenanceContentRelationV0::MatchingContentDigest
    );
    assert_eq!(
        undeclared.lineage(),
        ProvenanceLineageRelationV0::NoSharedAncestryFound
    );
}

#[test]
fn disjoint_graph_references_do_not_claim_independence() {
    let left = artifact("netbraid.test.observation.v0", "left", 'a');
    let right = artifact("netbraid.test.observation.v0", "right", 'b');
    let graph = ProvenanceGraphV0::try_new(vec![]).unwrap();

    assert_eq!(
        graph.compare(&left, &right).lineage(),
        ProvenanceLineageRelationV0::NoSharedAncestryFound
    );
}

#[test]
fn record_kinds_enforce_their_input_semantics() {
    let output = artifact("netbraid.test.claim.v0", "output", 'a');
    let input = artifact("netbraid.test.observation.v0", "input", 'b');
    let sensor = producer("sensor:1", ProvenanceProducerKindV0::Sensor);

    assert_eq!(
        ProvenanceRecordV0::try_new(
            output.clone(),
            sensor.clone(),
            activity("observe:bad", ProvenanceActivityKindV0::DirectObservation,),
            vec![input.clone()],
        )
        .unwrap_err(),
        ProvenanceRecordErrorV0::RootActivityHasInputs
    );
    assert_eq!(
        ProvenanceRecordV0::try_new(
            output.clone(),
            sensor.clone(),
            activity("infer:bad", ProvenanceActivityKindV0::StatisticalInference),
            vec![],
        )
        .unwrap_err(),
        ProvenanceRecordErrorV0::DerivedActivityLacksInput
    );
    assert_eq!(
        ProvenanceRecordV0::try_new(
            output,
            sensor,
            activity("repeat:bad", ProvenanceActivityKindV0::Repetition),
            vec![input.clone(), input],
        )
        .unwrap_err(),
        ProvenanceRecordErrorV0::DuplicateInput
    );
}

#[test]
fn derivation_cycles_fail_closed() {
    let left = artifact("netbraid.test.claim.v0", "left", 'a');
    let right = artifact("netbraid.test.claim.v0", "right", 'b');
    let reducer = producer("reducer:1", ProvenanceProducerKindV0::Software);
    let records = vec![
        record(
            left.clone(),
            reducer.clone(),
            activity(
                "derive:left",
                ProvenanceActivityKindV0::DeterministicDerivation,
            ),
            vec![right.clone()],
        ),
        record(
            right,
            reducer,
            activity(
                "derive:right",
                ProvenanceActivityKindV0::DeterministicDerivation,
            ),
            vec![left],
        ),
    ];

    assert_eq!(
        ProvenanceGraphV0::try_new(records).unwrap_err(),
        ProvenanceGraphErrorV0::Cycle
    );
}

#[test]
fn graph_and_record_order_are_canonical() {
    let source_a = artifact("netbraid.test.observation.v0", "source:a", 'a');
    let source_b = artifact("netbraid.test.observation.v0", "source:b", 'b');
    let output = artifact("netbraid.test.claim.v0", "claim:1", 'c');
    let reducer = producer(
        "https://example.invalid/reducer/1",
        ProvenanceProducerKindV0::Software,
    );
    let make_records = |inputs| {
        vec![
            record(
                output.clone(),
                reducer.clone(),
                activity(
                    "urn:activity:combine:1",
                    ProvenanceActivityKindV0::StatisticalInference,
                ),
                inputs,
            ),
            record(
                source_b.clone(),
                producer("sensor:b", ProvenanceProducerKindV0::Sensor),
                activity("observe:b", ProvenanceActivityKindV0::DirectObservation),
                vec![],
            ),
            record(
                source_a.clone(),
                producer("sensor:a", ProvenanceProducerKindV0::Sensor),
                activity("observe:a", ProvenanceActivityKindV0::DirectObservation),
                vec![],
            ),
        ]
    };

    let forward =
        ProvenanceGraphV0::try_new(make_records(vec![source_a.clone(), source_b.clone()])).unwrap();
    let mut reversed_records = make_records(vec![source_b.clone(), source_a.clone()]);
    reversed_records.reverse();
    let reversed = ProvenanceGraphV0::try_new(reversed_records).unwrap();

    assert_eq!(forward, reversed);
    assert_eq!(
        serde_json::to_vec(&forward).unwrap(),
        serde_json::to_vec(&reversed).unwrap()
    );
}

#[test]
fn duplicate_output_records_fail_even_when_their_metadata_matches() {
    let output = artifact("netbraid.test.observation.v0", "source:1", 'a');
    let source = producer("sensor:1", ProvenanceProducerKindV0::Sensor);
    let observation = activity("observe:1", ProvenanceActivityKindV0::DirectObservation);
    let duplicate = record(output, source, observation, vec![]);

    assert_eq!(
        ProvenanceGraphV0::try_new(vec![duplicate.clone(), duplicate]).unwrap_err(),
        ProvenanceGraphErrorV0::DuplicateOutput
    );
}

#[test]
fn serialized_graph_keeps_attribution_descriptive() {
    let output = artifact("netbraid.test.observation.v0", "source:1", 'a');
    let graph = ProvenanceGraphV0::try_new(vec![record(
        output,
        producer("sensor:1", ProvenanceProducerKindV0::Sensor),
        activity("observe:1", ProvenanceActivityKindV0::DirectObservation),
        vec![],
    )])
    .unwrap();
    let value = serde_json::to_value(graph).unwrap();

    assert_eq!(value["schema"], "netbraid.provenance_graph.v0");
    assert_eq!(
        value["records"][0]["schema"],
        "netbraid.provenance_record.v0"
    );
    assert_eq!(value["records"][0]["producer"]["kind"], "sensor");
    assert_eq!(
        value["records"][0]["activity"]["kind"],
        "direct_observation"
    );
    assert!(value["records"][0]["producer"].get("trust").is_none());
    assert!(value["records"][0]["producer"].get("reputation").is_none());
}
