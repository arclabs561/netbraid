use netbraid::infer::{
    assess_calibrated_event_relation_v0, assess_content_relation_v0,
    calibrated_event_relation_pair_id_v0, CalibratedEventRelationErrorV0,
    CalibratedEventRelationObservationRefV0, CalibratedEventRelationProfileV0,
    CalibratedEventRelationReferenceV0, ContentDigestEvidenceV0, ContentSha256V0,
    EventRelationPredictionV0, EventRelationPredictionValidationErrorV0,
    FiniteHypothesisClaimErrorV0, FiniteHypothesisCompositionV0,
    HeldoutEventRelationEvaluationReceiptV0, ProjectFiniteHypothesesV0,
    ProjectFiniteHypothesisClaimV0, CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0,
    CALIBRATED_EVENT_RELATION_REDUCER_V0,
};
use serde_json::{json, Value};

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "fixtures/infer/v0/calibrated-event-relation-admission.json"
    ))
    .unwrap()
}

fn parse_profile(document: &Value) -> CalibratedEventRelationProfileV0 {
    CalibratedEventRelationProfileV0::from_json_bytes(&serde_json::to_vec(document).unwrap())
        .unwrap()
}

fn parse_prediction(
    document: &Value,
    profile: &CalibratedEventRelationProfileV0,
) -> EventRelationPredictionV0 {
    EventRelationPredictionV0::from_json_bytes(&serde_json::to_vec(document).unwrap(), profile)
        .unwrap()
}

fn parse_receipt(
    document: &Value,
    profile: &CalibratedEventRelationProfileV0,
) -> HeldoutEventRelationEvaluationReceiptV0 {
    HeldoutEventRelationEvaluationReceiptV0::from_json_bytes(
        &serde_json::to_vec(document).unwrap(),
        profile,
    )
    .unwrap()
}

fn parse_observation(document: &Value) -> CalibratedEventRelationObservationRefV0 {
    serde_json::from_value(document.clone()).unwrap()
}

fn assert_resolution_rejected<T>(result: Result<T, FiniteHypothesisClaimErrorV0>) {
    assert!(matches!(
        result,
        Err(FiniteHypothesisClaimErrorV0::InvalidCalibratedEventRelationResolution(_))
    ));
}

#[test]
fn shared_fixture_admits_a_content_bound_finite_claim() {
    let fixture = fixture();
    let profile = parse_profile(&fixture["profile"]);
    let prediction = parse_prediction(&fixture["prediction"], &profile);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let left = parse_observation(&fixture["observations"]["left"]);
    let right = parse_observation(&fixture["observations"]["right"]);

    assert_eq!(
        profile.content_sha256().unwrap(),
        fixture["expected"]["profile_digest"]
    );
    assert_eq!(
        prediction.content_sha256().unwrap(),
        fixture["expected"]["prediction_digest"]
    );
    assert_eq!(
        receipt.content_sha256().unwrap(),
        fixture["expected"]["heldout_evaluation_receipt_digest"]
    );
    assert_eq!(
        calibrated_event_relation_pair_id_v0(&left, &right).unwrap(),
        fixture["prediction"]["frame_id"]
    );

    let assessment =
        assess_calibrated_event_relation_v0(&left, &right, &profile, &prediction, &receipt)
            .unwrap();
    let projection = assessment.project_finite_hypotheses_v0().unwrap();
    let claim = assessment
        .project_finite_hypothesis_claim_v0((&left, &right, &profile, &prediction, &receipt))
        .unwrap();

    assert_eq!(
        assessment.reference(),
        CalibratedEventRelationReferenceV0::SameEvent
    );
    assert_eq!(
        assessment.schema(),
        CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0
    );
    assert_eq!(assessment.reducer(), CALIBRATED_EVENT_RELATION_REDUCER_V0);
    assert_eq!(claim.projection(), &projection);
    assert_eq!(
        projection
            .alternatives()
            .iter()
            .map(|alternative| alternative.role())
            .collect::<Vec<_>>(),
        ["same_event", "different_event", "unknown"]
    );
    assert_eq!(
        claim
            .inputs()
            .iter()
            .map(|input| input.role())
            .collect::<Vec<_>>(),
        [
            "calibration_profile",
            "heldout_evaluation_receipt",
            "left_observation",
            "prediction",
            "right_observation",
        ]
    );
    assert_eq!(
        claim.inputs()[2].source_schema(),
        assessment.left_observation().source_schema()
    );
    assert_eq!(
        claim.inputs()[4].source_schema(),
        assessment.right_observation().source_schema()
    );

    let serialized = serde_json::to_string(&claim).unwrap();
    for forbidden in [
        "score",
        "threshold",
        "model_revision",
        "metric",
        "identity",
        "intent",
        "tamper",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "unexpected field {forbidden}"
        );
    }
}

#[test]
fn failed_heldout_gate_cannot_construct_an_assessment() {
    let mut fixture = fixture();
    fixture["heldout_evaluation_receipt"]["gate"]["status"] = json!("failed");
    let profile = parse_profile(&fixture["profile"]);
    let prediction = parse_prediction(&fixture["prediction"], &profile);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let left = parse_observation(&fixture["observations"]["left"]);
    let right = parse_observation(&fixture["observations"]["right"]);

    assert!(matches!(
        assess_calibrated_event_relation_v0(&left, &right, &profile, &prediction, &receipt),
        Err(CalibratedEventRelationErrorV0::HeldoutGateNotPassed)
    ));
}

#[test]
fn prediction_for_another_observation_pair_is_rejected() {
    let fixture = fixture();
    let profile = parse_profile(&fixture["profile"]);
    let prediction = parse_prediction(&fixture["prediction"], &profile);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let left = parse_observation(&fixture["observations"]["left"]);
    let right = CalibratedEventRelationObservationRefV0::try_new(
        fixture["observations"]["right"]["source_schema"]
            .as_str()
            .unwrap(),
        "different-observation",
        fixture["observations"]["right"]["content_sha256"]
            .as_str()
            .unwrap(),
    )
    .unwrap();

    assert!(matches!(
        assess_calibrated_event_relation_v0(&left, &right, &profile, &prediction, &receipt),
        Err(CalibratedEventRelationErrorV0::PredictionObservationMismatch)
    ));
}

#[test]
fn an_observation_cannot_be_claimed_different_from_itself() {
    let fixture = fixture();
    let profile = parse_profile(&fixture["profile"]);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let observation = parse_observation(&fixture["observations"]["left"]);
    let mut prediction_document = fixture["prediction"].clone();
    prediction_document["frame_id"] =
        json!(calibrated_event_relation_pair_id_v0(&observation, &observation).unwrap());
    prediction_document["forward_score"] = json!("0x1.8000000000000p-1");
    prediction_document["reverse_score"] = json!("0x1.999999999999ap-1");
    prediction_document["decision"] = json!("different");
    let prediction = parse_prediction(&prediction_document, &profile);

    assert!(matches!(
        assess_calibrated_event_relation_v0(
            &observation,
            &observation,
            &profile,
            &prediction,
            &receipt,
        ),
        Err(CalibratedEventRelationErrorV0::IdenticalObservations)
    ));
}

#[test]
fn prediction_boundaries_gaps_and_disagreement_are_exact() {
    let base = fixture();
    let profile = parse_profile(&base["profile"]);

    let cases = [
        (
            "0x1.0000000000000p-2",
            "0x1.999999999999ap-3",
            "same",
            Value::Null,
        ),
        (
            "0x1.8000000000000p-1",
            "0x1.999999999999ap-1",
            "different",
            Value::Null,
        ),
        (
            "0x1.0000000000000p-1",
            "0x1.999999999999ap-3",
            "abstain",
            json!("score_gap"),
        ),
        (
            "0x1.0000000000000p-2",
            "0x1.999999999999ap-1",
            "abstain",
            json!("direction_disagreement"),
        ),
    ];

    for (forward, reverse, decision, reason) in cases {
        let mut document = base["prediction"].clone();
        document["forward_score"] = json!(forward);
        document["reverse_score"] = json!(reverse);
        document["decision"] = json!(decision);
        document["abstain_reason"] = reason;
        parse_prediction(&document, &profile);
    }

    for invalid in ["-0x0.0p+0", "0x1.0p-2", "nan", "inf"] {
        let mut document = base["prediction"].clone();
        document["forward_score"] = json!(invalid);
        assert!(matches!(
            EventRelationPredictionV0::from_json_bytes(
                &serde_json::to_vec(&document).unwrap(),
                &profile,
            ),
            Err(
                netbraid::infer::CalibratedEventRelationDocumentErrorV0::InvalidPrediction(
                    EventRelationPredictionValidationErrorV0::InvalidScore
                )
            )
        ));
    }
}

#[test]
fn every_content_reference_is_rechecked_before_claim_projection() {
    let fixture = fixture();
    let profile = parse_profile(&fixture["profile"]);
    let prediction = parse_prediction(&fixture["prediction"], &profile);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let left = parse_observation(&fixture["observations"]["left"]);
    let right = parse_observation(&fixture["observations"]["right"]);
    let assessment =
        assess_calibrated_event_relation_v0(&left, &right, &profile, &prediction, &receipt)
            .unwrap();

    let changed_left = CalibratedEventRelationObservationRefV0::try_new(
        left.source_schema(),
        left.source_id(),
        "c".repeat(64),
    )
    .unwrap();
    assert_resolution_rejected(assessment.project_finite_hypothesis_claim_v0((
        &changed_left,
        &right,
        &profile,
        &prediction,
        &receipt,
    )));

    let changed_right = CalibratedEventRelationObservationRefV0::try_new(
        right.source_schema(),
        right.source_id(),
        "e".repeat(64),
    )
    .unwrap();
    assert_resolution_rejected(assessment.project_finite_hypothesis_claim_v0((
        &left,
        &changed_right,
        &profile,
        &prediction,
        &receipt,
    )));

    let mut changed_profile_document = fixture["profile"].clone();
    changed_profile_document["model_digest"] = json!("f".repeat(64));
    let changed_profile = parse_profile(&changed_profile_document);
    assert_resolution_rejected(assessment.project_finite_hypothesis_claim_v0((
        &left,
        &right,
        &changed_profile,
        &prediction,
        &receipt,
    )));

    let mut changed_prediction_document = fixture["prediction"].clone();
    changed_prediction_document["forward_score"] = json!("0x1.8000000000000p-1");
    changed_prediction_document["reverse_score"] = json!("0x1.999999999999ap-1");
    changed_prediction_document["decision"] = json!("different");
    let changed_prediction = parse_prediction(&changed_prediction_document, &profile);
    assert_resolution_rejected(assessment.project_finite_hypothesis_claim_v0((
        &left,
        &right,
        &profile,
        &changed_prediction,
        &receipt,
    )));

    let mut changed_receipt_document = fixture["heldout_evaluation_receipt"].clone();
    changed_receipt_document["evaluation_report_digest"] = json!("d".repeat(64));
    let changed_receipt = parse_receipt(&changed_receipt_document, &profile);
    assert_resolution_rejected(assessment.project_finite_hypothesis_claim_v0((
        &left,
        &right,
        &profile,
        &prediction,
        &changed_receipt,
    )));
}

#[test]
fn rust_json_boundary_rejects_duplicate_keys_unknown_fields_and_uppercase_ids() {
    let fixture = fixture();
    let mut profile_document = fixture["profile"].clone();
    profile_document["profile_id"] = json!("Uppercase-profile");
    assert!(CalibratedEventRelationProfileV0::from_json_bytes(
        &serde_json::to_vec(&profile_document).unwrap()
    )
    .is_err());

    let mut prediction_document = fixture["prediction"].clone();
    prediction_document["identity"] = json!("forbidden");
    let profile = parse_profile(&fixture["profile"]);
    assert!(EventRelationPredictionV0::from_json_bytes(
        &serde_json::to_vec(&prediction_document).unwrap(),
        &profile,
    )
    .is_err());

    let profile_json = serde_json::to_string(&fixture["profile"]).unwrap();
    let duplicate = profile_json.replacen(
        "{",
        "{\"schema\":\"netbraid.calibrated_event_relation_profile.v0\",",
        1,
    );
    assert!(CalibratedEventRelationProfileV0::from_json_bytes(duplicate.as_bytes()).is_err());
}

#[test]
fn swapping_observations_is_canonical_and_composes_with_other_families() {
    let fixture = fixture();
    let profile = parse_profile(&fixture["profile"]);
    let prediction = parse_prediction(&fixture["prediction"], &profile);
    let receipt = parse_receipt(&fixture["heldout_evaluation_receipt"], &profile);
    let left = parse_observation(&fixture["observations"]["left"]);
    let right = parse_observation(&fixture["observations"]["right"]);

    let forward =
        assess_calibrated_event_relation_v0(&left, &right, &profile, &prediction, &receipt)
            .unwrap();
    let reverse =
        assess_calibrated_event_relation_v0(&right, &left, &profile, &prediction, &receipt)
            .unwrap();
    assert_eq!(forward, reverse);
    let calibrated_claim = forward
        .project_finite_hypothesis_claim_v0((&right, &left, &profile, &prediction, &receipt))
        .unwrap();

    let content_left = ContentDigestEvidenceV0::observed(
        "digest:left",
        left.source_schema(),
        left.source_id(),
        ContentSha256V0::try_new(left.content_sha256()).unwrap(),
    )
    .unwrap();
    let content_right = ContentDigestEvidenceV0::observed(
        "digest:right",
        right.source_schema(),
        right.source_id(),
        ContentSha256V0::try_new(right.content_sha256()).unwrap(),
    )
    .unwrap();
    let content_claim = assess_content_relation_v0(&content_left, &content_right)
        .unwrap()
        .project_finite_hypothesis_claim_v0((&content_left, &content_right))
        .unwrap();

    let composition =
        FiniteHypothesisCompositionV0::try_new(vec![content_claim, calibrated_claim]).unwrap();
    assert_eq!(composition.claims().len(), 2);
    assert_ne!(
        composition.claims()[0].projection().family_schema(),
        composition.claims()[1].projection().family_schema()
    );
}
