use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0: &str =
    "netbraid.calibrated_event_relation_profile.v0";
pub const EVENT_RELATION_PREDICTION_SCHEMA_V0: &str = "netbraid.event_relation_prediction.v0";
pub const HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0: &str =
    "netbraid.heldout_event_relation_evaluation_receipt.v0";
pub const CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0: &str =
    "netbraid.calibrated_event_relation_assessment.v0";
pub const CALIBRATED_EVENT_RELATION_REDUCER_V0: &str =
    "netbraid.calibrated_event_relation.admitted_prediction.v0";

const PROFILE_DIGEST_DOMAIN: &[u8] = b"netbraid.calibrated-event-relation-profile.v0\0";
const PREDICTION_DIGEST_DOMAIN: &[u8] = b"netbraid.event-relation-prediction.v0\0";
const RECEIPT_DIGEST_DOMAIN: &[u8] = b"netbraid.heldout-event-relation-evaluation-receipt.v0\0";
const OBSERVATION_PAIR_DIGEST_DOMAIN: &[u8] =
    b"netbraid.calibrated-event-relation-observation-pair.v0\0";
const MAX_DOCUMENT_BYTES: usize = 16 * 1024;
const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_ARTIFACT_ID_LEN: usize = 96;
const MAX_SOURCE_ID_LEN: usize = 512;
const SAME_QUANTILE_HEX: &str = "0x1.ccccccccccccdp-1";
const DIFFERENT_QUANTILE_HEX: &str = "0x1.999999999999ap-4";
const LIMITATIONS: &[&str] = &[
    "the decision applies only to the cited observations under the cited calibrated profile",
    "the held-out receipt records a claimed passed frozen gate but does not resolve its cited artifacts or authenticate its producer",
    "this v0 accepts only bidirectional lower-distance reducers with its fixed quantile policy",
    "same-event and different-event decisions do not establish identity source device intent authorization or tamper",
    "scores thresholds model details and evaluation metrics remain outside the finite projection",
    "abstention preserves unknown rather than forcing an event relation",
];

/// An opaque, content-bound observation admitted to calibrated comparison.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CalibratedEventRelationObservationRefV0 {
    source_schema: String,
    source_id: String,
    content_sha256: String,
}

impl CalibratedEventRelationObservationRefV0 {
    pub fn try_new(
        source_schema: impl Into<String>,
        source_id: impl Into<String>,
        content_sha256: impl Into<String>,
    ) -> Result<Self, CalibratedEventRelationObservationRefValidationErrorV0> {
        let reference = Self {
            source_schema: source_schema.into(),
            source_id: source_id.into(),
            content_sha256: content_sha256.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn source_schema(&self) -> &str {
        &self.source_schema
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn content_sha256(&self) -> &str {
        &self.content_sha256
    }

    pub fn validate(&self) -> Result<(), CalibratedEventRelationObservationRefValidationErrorV0> {
        if !valid_identifier(&self.source_schema) {
            return Err(
                CalibratedEventRelationObservationRefValidationErrorV0::InvalidSourceSchema,
            );
        }
        if !valid_source_id(&self.source_id) {
            return Err(CalibratedEventRelationObservationRefValidationErrorV0::InvalidSourceId);
        }
        if !valid_sha256(&self.content_sha256) {
            return Err(
                CalibratedEventRelationObservationRefValidationErrorV0::InvalidContentSha256,
            );
        }
        Ok(())
    }
}

/// Derive the prediction frame identifier for a canonical observation pair.
pub fn calibrated_event_relation_pair_id_v0(
    left: &CalibratedEventRelationObservationRefV0,
    right: &CalibratedEventRelationObservationRefV0,
) -> Result<String, CalibratedEventRelationObservationRefValidationErrorV0> {
    left.validate()?;
    right.validate()?;
    let (left, right) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };

    let mut digest = Sha256::new();
    digest.update(OBSERVATION_PAIR_DIGEST_DOMAIN);
    for reference in [left, right] {
        for value in [
            reference.source_schema(),
            reference.source_id(),
            reference.content_sha256(),
        ] {
            digest.update(value.as_bytes());
            digest.update([0]);
        }
    }
    Ok(format!("event-pair-{:x}", digest.finalize()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalibratedEventRelationObservationRefValidationErrorV0 {
    InvalidSourceSchema,
    InvalidSourceId,
    InvalidContentSha256,
}

impl std::fmt::Display for CalibratedEventRelationObservationRefValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidSourceSchema => "invalid calibrated-event observation source schema",
            Self::InvalidSourceId => "invalid calibrated-event observation source identifier",
            Self::InvalidContentSha256 => "invalid calibrated-event observation content digest",
        })
    }
}

impl std::error::Error for CalibratedEventRelationObservationRefValidationErrorV0 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CalibratedQuantilePolicyV0 {
    same_quantile: String,
    different_quantile: String,
    interpolation: String,
}

/// Reproducibility-bound lower-distance calibration profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CalibratedEventRelationProfileV0 {
    schema: String,
    profile_id: String,
    reducer_revision: String,
    model_revision: String,
    feature_policy_digest: String,
    input_matrix_digest: String,
    model_digest: String,
    fit_partition_digest: String,
    calibration_partition_digest: String,
    quantile_policy: CalibratedQuantilePolicyV0,
    forward_same_threshold: String,
    forward_different_threshold: String,
    reverse_same_threshold: String,
    reverse_different_threshold: String,
}

impl CalibratedEventRelationProfileV0 {
    pub fn from_json_bytes(data: &[u8]) -> Result<Self, CalibratedEventRelationDocumentErrorV0> {
        let profile: Self = load_document(data)?;
        profile
            .validate()
            .map_err(CalibratedEventRelationDocumentErrorV0::InvalidProfile)?;
        Ok(profile)
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn validate(&self) -> Result<(), CalibratedEventRelationProfileValidationErrorV0> {
        if self.schema != CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0 {
            return Err(CalibratedEventRelationProfileValidationErrorV0::UnsupportedSchema);
        }
        if !valid_artifact_id(&self.profile_id) {
            return Err(CalibratedEventRelationProfileValidationErrorV0::InvalidProfileId);
        }
        if !valid_revision(&self.reducer_revision) || !valid_revision(&self.model_revision) {
            return Err(CalibratedEventRelationProfileValidationErrorV0::InvalidRevision);
        }
        if [
            &self.feature_policy_digest,
            &self.input_matrix_digest,
            &self.model_digest,
            &self.fit_partition_digest,
            &self.calibration_partition_digest,
        ]
        .into_iter()
        .any(|digest| !valid_sha256(digest))
        {
            return Err(CalibratedEventRelationProfileValidationErrorV0::InvalidDigest);
        }
        if self.quantile_policy.same_quantile != SAME_QUANTILE_HEX
            || self.quantile_policy.different_quantile != DIFFERENT_QUANTILE_HEX
            || self.quantile_policy.interpolation != "linear"
        {
            return Err(CalibratedEventRelationProfileValidationErrorV0::UnsupportedQuantilePolicy);
        }
        let forward_same = parse_canonical_distance(&self.forward_same_threshold)
            .ok_or(CalibratedEventRelationProfileValidationErrorV0::InvalidThreshold)?;
        let forward_different = parse_canonical_distance(&self.forward_different_threshold)
            .ok_or(CalibratedEventRelationProfileValidationErrorV0::InvalidThreshold)?;
        let reverse_same = parse_canonical_distance(&self.reverse_same_threshold)
            .ok_or(CalibratedEventRelationProfileValidationErrorV0::InvalidThreshold)?;
        let reverse_different = parse_canonical_distance(&self.reverse_different_threshold)
            .ok_or(CalibratedEventRelationProfileValidationErrorV0::InvalidThreshold)?;
        if forward_same >= forward_different || reverse_same >= reverse_different {
            return Err(CalibratedEventRelationProfileValidationErrorV0::InvalidThresholdOrder);
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut quantile_policy = BTreeMap::new();
        quantile_policy.insert(
            "different_quantile",
            value(&self.quantile_policy.different_quantile),
        );
        quantile_policy.insert("interpolation", value(&self.quantile_policy.interpolation));
        quantile_policy.insert("same_quantile", value(&self.quantile_policy.same_quantile));

        let mut document = BTreeMap::new();
        document.insert(
            "calibration_partition_digest",
            value(&self.calibration_partition_digest),
        );
        document.insert("feature_policy_digest", value(&self.feature_policy_digest));
        document.insert("fit_partition_digest", value(&self.fit_partition_digest));
        document.insert(
            "forward_different_threshold",
            value(&self.forward_different_threshold),
        );
        document.insert(
            "forward_same_threshold",
            value(&self.forward_same_threshold),
        );
        document.insert("input_matrix_digest", value(&self.input_matrix_digest));
        document.insert("model_digest", value(&self.model_digest));
        document.insert("model_revision", value(&self.model_revision));
        document.insert("profile_id", value(&self.profile_id));
        document.insert("quantile_policy", serde_json::to_value(quantile_policy)?);
        document.insert("reducer_revision", value(&self.reducer_revision));
        document.insert(
            "reverse_different_threshold",
            value(&self.reverse_different_threshold),
        );
        document.insert(
            "reverse_same_threshold",
            value(&self.reverse_same_threshold),
        );
        document.insert("schema", value(&self.schema));
        serde_json::to_vec(&document)
    }

    pub fn content_sha256(&self) -> Result<String, serde_json::Error> {
        Ok(domain_digest(
            PROFILE_DIGEST_DOMAIN,
            self.canonical_json_bytes()?,
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalibratedEventRelationProfileValidationErrorV0 {
    UnsupportedSchema,
    InvalidProfileId,
    InvalidRevision,
    InvalidDigest,
    UnsupportedQuantilePolicy,
    InvalidThreshold,
    InvalidThresholdOrder,
}

impl std::fmt::Display for CalibratedEventRelationProfileValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported calibrated-event profile schema",
            Self::InvalidProfileId => "invalid calibrated-event profile identifier",
            Self::InvalidRevision => "invalid calibrated-event profile revision",
            Self::InvalidDigest => "invalid calibrated-event profile digest",
            Self::UnsupportedQuantilePolicy => "unsupported calibrated-event quantile policy",
            Self::InvalidThreshold => "invalid calibrated-event profile threshold",
            Self::InvalidThresholdOrder => "invalid calibrated-event profile threshold order",
        })
    }
}

impl std::error::Error for CalibratedEventRelationProfileValidationErrorV0 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum EventRelationDecisionV0 {
    Same,
    Different,
    Abstain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum EventRelationAbstainReasonV0 {
    ScoreGap,
    DirectionDisagreement,
}

/// A profile-bound bidirectional event-relation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct EventRelationPredictionV0 {
    schema: String,
    frame_id: String,
    profile_digest: String,
    forward_score: String,
    reverse_score: String,
    decision: EventRelationDecisionV0,
    abstain_reason: Option<EventRelationAbstainReasonV0>,
}

impl EventRelationPredictionV0 {
    pub fn from_json_bytes(
        data: &[u8],
        profile: &CalibratedEventRelationProfileV0,
    ) -> Result<Self, CalibratedEventRelationDocumentErrorV0> {
        let prediction: Self = load_document(data)?;
        prediction
            .validate_against(profile)
            .map_err(CalibratedEventRelationDocumentErrorV0::InvalidPrediction)?;
        Ok(prediction)
    }

    pub fn frame_id(&self) -> &str {
        &self.frame_id
    }

    pub fn decision(&self) -> EventRelationDecisionV0 {
        self.decision
    }

    pub fn abstain_reason(&self) -> Option<EventRelationAbstainReasonV0> {
        self.abstain_reason
    }

    pub fn validate_against(
        &self,
        profile: &CalibratedEventRelationProfileV0,
    ) -> Result<(), EventRelationPredictionValidationErrorV0> {
        profile
            .validate()
            .map_err(EventRelationPredictionValidationErrorV0::InvalidProfile)?;
        if self.schema != EVENT_RELATION_PREDICTION_SCHEMA_V0 {
            return Err(EventRelationPredictionValidationErrorV0::UnsupportedSchema);
        }
        if !valid_artifact_id(&self.frame_id) {
            return Err(EventRelationPredictionValidationErrorV0::InvalidFrameId);
        }
        if !valid_sha256(&self.profile_digest) {
            return Err(EventRelationPredictionValidationErrorV0::InvalidProfileDigest);
        }
        let profile_digest = profile
            .content_sha256()
            .map_err(EventRelationPredictionValidationErrorV0::Serialization)?;
        if self.profile_digest != profile_digest {
            return Err(EventRelationPredictionValidationErrorV0::ProfileDigestMismatch);
        }
        let forward = parse_canonical_distance(&self.forward_score)
            .ok_or(EventRelationPredictionValidationErrorV0::InvalidScore)?;
        let reverse = parse_canonical_distance(&self.reverse_score)
            .ok_or(EventRelationPredictionValidationErrorV0::InvalidScore)?;
        let expected = expected_decision(profile, forward, reverse).ok_or(
            EventRelationPredictionValidationErrorV0::InvalidProfile(
                CalibratedEventRelationProfileValidationErrorV0::InvalidThreshold,
            ),
        )?;
        if (self.decision, self.abstain_reason) != expected {
            return Err(EventRelationPredictionValidationErrorV0::IncoherentDecision);
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut document = BTreeMap::new();
        document.insert("abstain_reason", serde_json::to_value(self.abstain_reason)?);
        document.insert("decision", serde_json::to_value(self.decision)?);
        document.insert("forward_score", value(&self.forward_score));
        document.insert("frame_id", value(&self.frame_id));
        document.insert("profile_digest", value(&self.profile_digest));
        document.insert("reverse_score", value(&self.reverse_score));
        document.insert("schema", value(&self.schema));
        serde_json::to_vec(&document)
    }

    pub fn content_sha256(&self) -> Result<String, serde_json::Error> {
        Ok(domain_digest(
            PREDICTION_DIGEST_DOMAIN,
            self.canonical_json_bytes()?,
        ))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum EventRelationPredictionValidationErrorV0 {
    InvalidProfile(CalibratedEventRelationProfileValidationErrorV0),
    UnsupportedSchema,
    InvalidFrameId,
    InvalidProfileDigest,
    ProfileDigestMismatch,
    InvalidScore,
    IncoherentDecision,
    Serialization(serde_json::Error),
}

impl std::fmt::Display for EventRelationPredictionValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProfile(source) => {
                write!(formatter, "invalid prediction profile: {source}")
            }
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported event-relation prediction schema")
            }
            Self::InvalidFrameId => {
                formatter.write_str("invalid event-relation prediction frame identifier")
            }
            Self::InvalidProfileDigest => {
                formatter.write_str("invalid event-relation prediction profile digest")
            }
            Self::ProfileDigestMismatch => {
                formatter.write_str("event-relation prediction profile digest mismatch")
            }
            Self::InvalidScore => formatter.write_str("invalid event-relation prediction score"),
            Self::IncoherentDecision => {
                formatter.write_str("incoherent event-relation prediction decision")
            }
            Self::Serialization(source) => write!(
                formatter,
                "serialize event-relation prediction profile: {source}"
            ),
        }
    }
}

impl std::error::Error for EventRelationPredictionValidationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProfile(source) => Some(source),
            Self::Serialization(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum HeldoutEvaluationGateStatusV0 {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
struct HeldoutEvaluationGateV0 {
    policy_digest: String,
    status: HeldoutEvaluationGateStatusV0,
}

/// A model-profile-bound receipt for one frozen held-out admission gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct HeldoutEventRelationEvaluationReceiptV0 {
    schema: String,
    receipt_id: String,
    profile_digest: String,
    evaluation_protocol_digest: String,
    heldout_partition_digest: String,
    evaluation_report_digest: String,
    gate: HeldoutEvaluationGateV0,
}

impl HeldoutEventRelationEvaluationReceiptV0 {
    pub fn from_json_bytes(
        data: &[u8],
        profile: &CalibratedEventRelationProfileV0,
    ) -> Result<Self, CalibratedEventRelationDocumentErrorV0> {
        let receipt: Self = load_document(data)?;
        receipt
            .validate_against(profile)
            .map_err(CalibratedEventRelationDocumentErrorV0::InvalidReceipt)?;
        Ok(receipt)
    }

    pub fn receipt_id(&self) -> &str {
        &self.receipt_id
    }

    pub fn gate_status(&self) -> HeldoutEvaluationGateStatusV0 {
        self.gate.status
    }

    pub fn validate_against(
        &self,
        profile: &CalibratedEventRelationProfileV0,
    ) -> Result<(), HeldoutEventRelationEvaluationReceiptValidationErrorV0> {
        profile
            .validate()
            .map_err(HeldoutEventRelationEvaluationReceiptValidationErrorV0::InvalidProfile)?;
        if self.schema != HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0 {
            return Err(HeldoutEventRelationEvaluationReceiptValidationErrorV0::UnsupportedSchema);
        }
        if !valid_artifact_id(&self.receipt_id) {
            return Err(HeldoutEventRelationEvaluationReceiptValidationErrorV0::InvalidReceiptId);
        }
        if [
            &self.profile_digest,
            &self.evaluation_protocol_digest,
            &self.heldout_partition_digest,
            &self.evaluation_report_digest,
            &self.gate.policy_digest,
        ]
        .into_iter()
        .any(|digest| !valid_sha256(digest))
        {
            return Err(HeldoutEventRelationEvaluationReceiptValidationErrorV0::InvalidDigest);
        }
        let profile_digest = profile
            .content_sha256()
            .map_err(HeldoutEventRelationEvaluationReceiptValidationErrorV0::Serialization)?;
        if self.profile_digest != profile_digest {
            return Err(
                HeldoutEventRelationEvaluationReceiptValidationErrorV0::ProfileDigestMismatch,
            );
        }
        Ok(())
    }

    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        let mut gate = BTreeMap::new();
        gate.insert("policy_digest", value(&self.gate.policy_digest));
        gate.insert("status", serde_json::to_value(self.gate.status)?);

        let mut document = BTreeMap::new();
        document.insert(
            "evaluation_protocol_digest",
            value(&self.evaluation_protocol_digest),
        );
        document.insert(
            "evaluation_report_digest",
            value(&self.evaluation_report_digest),
        );
        document.insert("gate", serde_json::to_value(gate)?);
        document.insert(
            "heldout_partition_digest",
            value(&self.heldout_partition_digest),
        );
        document.insert("profile_digest", value(&self.profile_digest));
        document.insert("receipt_id", value(&self.receipt_id));
        document.insert("schema", value(&self.schema));
        serde_json::to_vec(&document)
    }

    pub fn content_sha256(&self) -> Result<String, serde_json::Error> {
        Ok(domain_digest(
            RECEIPT_DIGEST_DOMAIN,
            self.canonical_json_bytes()?,
        ))
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum HeldoutEventRelationEvaluationReceiptValidationErrorV0 {
    InvalidProfile(CalibratedEventRelationProfileValidationErrorV0),
    UnsupportedSchema,
    InvalidReceiptId,
    InvalidDigest,
    ProfileDigestMismatch,
    Serialization(serde_json::Error),
}

impl std::fmt::Display for HeldoutEventRelationEvaluationReceiptValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProfile(source) => {
                write!(formatter, "invalid held-out receipt profile: {source}")
            }
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported held-out event-relation receipt schema")
            }
            Self::InvalidReceiptId => {
                formatter.write_str("invalid held-out event-relation receipt identifier")
            }
            Self::InvalidDigest => {
                formatter.write_str("invalid held-out event-relation receipt digest")
            }
            Self::ProfileDigestMismatch => {
                formatter.write_str("held-out event-relation receipt profile digest mismatch")
            }
            Self::Serialization(source) => {
                write!(formatter, "serialize held-out receipt profile: {source}")
            }
        }
    }
}

impl std::error::Error for HeldoutEventRelationEvaluationReceiptValidationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidProfile(source) => Some(source),
            Self::Serialization(source) => Some(source),
            _ => None,
        }
    }
}

/// Disposition of one calibrated event-relation alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CalibratedEventRelationDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "hypothesis", rename_all = "snake_case")]
pub enum CalibratedEventRelationReferenceV0 {
    SameEvent,
    DifferentEvent,
    Unknown {
        reason: EventRelationAbstainReasonV0,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct CalibratedEventRelationAssessmentV0 {
    schema: String,
    reducer: String,
    left_observation: CalibratedEventRelationObservationRefV0,
    right_observation: CalibratedEventRelationObservationRefV0,
    calibration_profile: CalibratedEventRelationObservationRefV0,
    prediction: CalibratedEventRelationObservationRefV0,
    heldout_evaluation_receipt: CalibratedEventRelationObservationRefV0,
    same_event: CalibratedEventRelationDispositionV0,
    different_event: CalibratedEventRelationDispositionV0,
    unknown: CalibratedEventRelationDispositionV0,
    reference: CalibratedEventRelationReferenceV0,
    limitations: Vec<String>,
}

impl CalibratedEventRelationAssessmentV0 {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn reducer(&self) -> &str {
        &self.reducer
    }

    pub fn left_observation(&self) -> &CalibratedEventRelationObservationRefV0 {
        &self.left_observation
    }

    pub fn right_observation(&self) -> &CalibratedEventRelationObservationRefV0 {
        &self.right_observation
    }

    pub fn calibration_profile(&self) -> &CalibratedEventRelationObservationRefV0 {
        &self.calibration_profile
    }

    pub fn prediction(&self) -> &CalibratedEventRelationObservationRefV0 {
        &self.prediction
    }

    pub fn heldout_evaluation_receipt(&self) -> &CalibratedEventRelationObservationRefV0 {
        &self.heldout_evaluation_receipt
    }

    pub fn same_event(&self) -> CalibratedEventRelationDispositionV0 {
        self.same_event
    }

    pub fn different_event(&self) -> CalibratedEventRelationDispositionV0 {
        self.different_event
    }

    pub fn unknown(&self) -> CalibratedEventRelationDispositionV0 {
        self.unknown
    }

    pub fn reference(&self) -> CalibratedEventRelationReferenceV0 {
        self.reference
    }

    pub fn validate(&self) -> Result<(), CalibratedEventRelationAssessmentValidationErrorV0> {
        if self.schema != CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0 {
            return Err(CalibratedEventRelationAssessmentValidationErrorV0::UnsupportedSchema);
        }
        if self.reducer != CALIBRATED_EVENT_RELATION_REDUCER_V0 {
            return Err(CalibratedEventRelationAssessmentValidationErrorV0::UnsupportedReducer);
        }
        for reference in [
            &self.left_observation,
            &self.right_observation,
            &self.calibration_profile,
            &self.prediction,
            &self.heldout_evaluation_receipt,
        ] {
            reference.validate().map_err(
                CalibratedEventRelationAssessmentValidationErrorV0::InvalidContentReference,
            )?;
        }
        if self.calibration_profile.source_schema != CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0
            || self.prediction.source_schema != EVENT_RELATION_PREDICTION_SCHEMA_V0
            || self.heldout_evaluation_receipt.source_schema
                != HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0
        {
            return Err(CalibratedEventRelationAssessmentValidationErrorV0::InvalidArtifactSchema);
        }
        if self.left_observation > self.right_observation {
            return Err(
                CalibratedEventRelationAssessmentValidationErrorV0::NonCanonicalObservationOrder,
            );
        }
        if self
            .limitations
            .iter()
            .map(String::as_str)
            .ne(LIMITATIONS.iter().copied())
        {
            return Err(CalibratedEventRelationAssessmentValidationErrorV0::UnexpectedLimitations);
        }
        let coherent = match self.reference {
            CalibratedEventRelationReferenceV0::SameEvent => {
                self.same_event == CalibratedEventRelationDispositionV0::Supported
                    && self.different_event == CalibratedEventRelationDispositionV0::Contradicted
                    && self.unknown == CalibratedEventRelationDispositionV0::Contradicted
            }
            CalibratedEventRelationReferenceV0::DifferentEvent => {
                self.same_event == CalibratedEventRelationDispositionV0::Contradicted
                    && self.different_event == CalibratedEventRelationDispositionV0::Supported
                    && self.unknown == CalibratedEventRelationDispositionV0::Contradicted
            }
            CalibratedEventRelationReferenceV0::Unknown { .. } => {
                self.same_event == CalibratedEventRelationDispositionV0::Underdetermined
                    && self.different_event == CalibratedEventRelationDispositionV0::Underdetermined
                    && self.unknown == CalibratedEventRelationDispositionV0::Supported
            }
        };
        if !coherent {
            return Err(CalibratedEventRelationAssessmentValidationErrorV0::IncoherentAssessment);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        left: &CalibratedEventRelationObservationRefV0,
        right: &CalibratedEventRelationObservationRefV0,
        profile: &CalibratedEventRelationProfileV0,
        prediction: &EventRelationPredictionV0,
        receipt: &HeldoutEventRelationEvaluationReceiptV0,
    ) -> Result<(), CalibratedEventRelationErrorV0> {
        self.validate()
            .map_err(CalibratedEventRelationErrorV0::InternalInvariant)?;
        let recomputed =
            assess_calibrated_event_relation_v0(left, right, profile, prediction, receipt)?;
        if &recomputed != self {
            return Err(CalibratedEventRelationErrorV0::InternalInvariant(
                CalibratedEventRelationAssessmentValidationErrorV0::ResolvedContentMismatch,
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CalibratedEventRelationAssessmentValidationErrorV0 {
    UnsupportedSchema,
    UnsupportedReducer,
    InvalidContentReference(CalibratedEventRelationObservationRefValidationErrorV0),
    InvalidArtifactSchema,
    NonCanonicalObservationOrder,
    IncoherentAssessment,
    UnexpectedLimitations,
    ResolvedContentMismatch,
}

impl std::fmt::Display for CalibratedEventRelationAssessmentValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema => {
                formatter.write_str("unsupported calibrated-event assessment schema")
            }
            Self::UnsupportedReducer => {
                formatter.write_str("unsupported calibrated-event assessment reducer")
            }
            Self::InvalidContentReference(source) => write!(
                formatter,
                "invalid calibrated-event content reference: {source}"
            ),
            Self::InvalidArtifactSchema => {
                formatter.write_str("invalid calibrated-event artifact schema")
            }
            Self::NonCanonicalObservationOrder => {
                formatter.write_str("calibrated-event observations are not canonically ordered")
            }
            Self::IncoherentAssessment => {
                formatter.write_str("calibrated-event assessment is incoherent")
            }
            Self::UnexpectedLimitations => {
                formatter.write_str("calibrated-event limitations differ from the v0 contract")
            }
            Self::ResolvedContentMismatch => {
                formatter.write_str("calibrated-event assessment differs from resolved inputs")
            }
        }
    }
}

impl std::error::Error for CalibratedEventRelationAssessmentValidationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidContentReference(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CalibratedEventRelationErrorV0 {
    InvalidObservation(CalibratedEventRelationObservationRefValidationErrorV0),
    IdenticalObservations,
    InvalidProfile(CalibratedEventRelationProfileValidationErrorV0),
    InvalidPrediction(EventRelationPredictionValidationErrorV0),
    InvalidReceipt(HeldoutEventRelationEvaluationReceiptValidationErrorV0),
    PredictionObservationMismatch,
    HeldoutGateNotPassed,
    Serialization(serde_json::Error),
    InternalInvariant(CalibratedEventRelationAssessmentValidationErrorV0),
}

impl std::fmt::Display for CalibratedEventRelationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidObservation(source) => {
                write!(formatter, "invalid calibrated-event observation: {source}")
            }
            Self::IdenticalObservations => {
                formatter.write_str("calibrated-event observations must be distinct")
            }
            Self::InvalidProfile(source) => {
                write!(formatter, "invalid calibrated-event profile: {source}")
            }
            Self::InvalidPrediction(source) => {
                write!(formatter, "invalid calibrated-event prediction: {source}")
            }
            Self::InvalidReceipt(source) => write!(
                formatter,
                "invalid held-out event-relation receipt: {source}"
            ),
            Self::PredictionObservationMismatch => {
                formatter.write_str("event-relation prediction does not bind the observations")
            }
            Self::HeldoutGateNotPassed => {
                formatter.write_str("held-out event-relation admission gate did not pass")
            }
            Self::Serialization(source) => {
                write!(formatter, "serialize calibrated-event input: {source}")
            }
            Self::InternalInvariant(source) => {
                write!(formatter, "validate calibrated-event assessment: {source}")
            }
        }
    }
}

impl std::error::Error for CalibratedEventRelationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidObservation(source) => Some(source),
            Self::InvalidProfile(source) => Some(source),
            Self::InvalidPrediction(source) => Some(source),
            Self::InvalidReceipt(source) => Some(source),
            Self::Serialization(source) => Some(source),
            Self::InternalInvariant(source) => Some(source),
            Self::IdenticalObservations
            | Self::PredictionObservationMismatch
            | Self::HeldoutGateNotPassed => None,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum CalibratedEventRelationDocumentErrorV0 {
    DocumentTooLarge,
    Json(serde_json::Error),
    InvalidProfile(CalibratedEventRelationProfileValidationErrorV0),
    InvalidPrediction(EventRelationPredictionValidationErrorV0),
    InvalidReceipt(HeldoutEventRelationEvaluationReceiptValidationErrorV0),
}

impl std::fmt::Display for CalibratedEventRelationDocumentErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DocumentTooLarge => {
                formatter.write_str("calibrated-event document exceeds byte limit")
            }
            Self::Json(source) => write!(formatter, "parse calibrated-event document: {source}"),
            Self::InvalidProfile(source) => {
                write!(formatter, "invalid calibrated-event profile: {source}")
            }
            Self::InvalidPrediction(source) => {
                write!(formatter, "invalid event-relation prediction: {source}")
            }
            Self::InvalidReceipt(source) => write!(
                formatter,
                "invalid held-out event-relation receipt: {source}"
            ),
        }
    }
}

impl std::error::Error for CalibratedEventRelationDocumentErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::DocumentTooLarge => None,
            Self::Json(source) => Some(source),
            Self::InvalidProfile(source) => Some(source),
            Self::InvalidPrediction(source) => Some(source),
            Self::InvalidReceipt(source) => Some(source),
        }
    }
}

pub fn assess_calibrated_event_relation_v0(
    left: &CalibratedEventRelationObservationRefV0,
    right: &CalibratedEventRelationObservationRefV0,
    profile: &CalibratedEventRelationProfileV0,
    prediction: &EventRelationPredictionV0,
    receipt: &HeldoutEventRelationEvaluationReceiptV0,
) -> Result<CalibratedEventRelationAssessmentV0, CalibratedEventRelationErrorV0> {
    left.validate()
        .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;
    right
        .validate()
        .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;
    if left == right {
        return Err(CalibratedEventRelationErrorV0::IdenticalObservations);
    }
    profile
        .validate()
        .map_err(CalibratedEventRelationErrorV0::InvalidProfile)?;
    prediction
        .validate_against(profile)
        .map_err(CalibratedEventRelationErrorV0::InvalidPrediction)?;
    receipt
        .validate_against(profile)
        .map_err(CalibratedEventRelationErrorV0::InvalidReceipt)?;
    let pair_id = calibrated_event_relation_pair_id_v0(left, right)
        .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;
    if prediction.frame_id() != pair_id {
        return Err(CalibratedEventRelationErrorV0::PredictionObservationMismatch);
    }
    if receipt.gate_status() != HeldoutEvaluationGateStatusV0::Passed {
        return Err(CalibratedEventRelationErrorV0::HeldoutGateNotPassed);
    }

    let (left, right) = if left <= right {
        (left.clone(), right.clone())
    } else {
        (right.clone(), left.clone())
    };
    let profile_ref = CalibratedEventRelationObservationRefV0::try_new(
        CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0,
        profile.profile_id(),
        profile
            .content_sha256()
            .map_err(CalibratedEventRelationErrorV0::Serialization)?,
    )
    .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;
    let prediction_ref = CalibratedEventRelationObservationRefV0::try_new(
        EVENT_RELATION_PREDICTION_SCHEMA_V0,
        prediction.frame_id(),
        prediction
            .content_sha256()
            .map_err(CalibratedEventRelationErrorV0::Serialization)?,
    )
    .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;
    let receipt_ref = CalibratedEventRelationObservationRefV0::try_new(
        HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0,
        receipt.receipt_id(),
        receipt
            .content_sha256()
            .map_err(CalibratedEventRelationErrorV0::Serialization)?,
    )
    .map_err(CalibratedEventRelationErrorV0::InvalidObservation)?;

    let (reference, same_event, different_event, unknown) = match prediction.decision() {
        EventRelationDecisionV0::Same => (
            CalibratedEventRelationReferenceV0::SameEvent,
            CalibratedEventRelationDispositionV0::Supported,
            CalibratedEventRelationDispositionV0::Contradicted,
            CalibratedEventRelationDispositionV0::Contradicted,
        ),
        EventRelationDecisionV0::Different => (
            CalibratedEventRelationReferenceV0::DifferentEvent,
            CalibratedEventRelationDispositionV0::Contradicted,
            CalibratedEventRelationDispositionV0::Supported,
            CalibratedEventRelationDispositionV0::Contradicted,
        ),
        EventRelationDecisionV0::Abstain => (
            CalibratedEventRelationReferenceV0::Unknown {
                reason: prediction.abstain_reason().ok_or(
                    CalibratedEventRelationErrorV0::InvalidPrediction(
                        EventRelationPredictionValidationErrorV0::IncoherentDecision,
                    ),
                )?,
            },
            CalibratedEventRelationDispositionV0::Underdetermined,
            CalibratedEventRelationDispositionV0::Underdetermined,
            CalibratedEventRelationDispositionV0::Supported,
        ),
    };

    let assessment = CalibratedEventRelationAssessmentV0 {
        schema: CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0.to_owned(),
        reducer: CALIBRATED_EVENT_RELATION_REDUCER_V0.to_owned(),
        left_observation: left,
        right_observation: right,
        calibration_profile: profile_ref,
        prediction: prediction_ref,
        heldout_evaluation_receipt: receipt_ref,
        same_event,
        different_event,
        unknown,
        reference,
        limitations: LIMITATIONS
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
    };
    debug_assert!(assessment.validate().is_ok());
    Ok(assessment)
}

fn expected_decision(
    profile: &CalibratedEventRelationProfileV0,
    forward: f64,
    reverse: f64,
) -> Option<(
    EventRelationDecisionV0,
    Option<EventRelationAbstainReasonV0>,
)> {
    let forward_state = direction_state(
        forward,
        parse_canonical_distance(&profile.forward_same_threshold)?,
        parse_canonical_distance(&profile.forward_different_threshold)?,
    );
    let reverse_state = direction_state(
        reverse,
        parse_canonical_distance(&profile.reverse_same_threshold)?,
        parse_canonical_distance(&profile.reverse_different_threshold)?,
    );
    Some(match (forward_state, reverse_state) {
        (DirectionState::Same, DirectionState::Same) => (EventRelationDecisionV0::Same, None),
        (DirectionState::Different, DirectionState::Different) => {
            (EventRelationDecisionV0::Different, None)
        }
        (DirectionState::Same, DirectionState::Different)
        | (DirectionState::Different, DirectionState::Same) => (
            EventRelationDecisionV0::Abstain,
            Some(EventRelationAbstainReasonV0::DirectionDisagreement),
        ),
        _ => (
            EventRelationDecisionV0::Abstain,
            Some(EventRelationAbstainReasonV0::ScoreGap),
        ),
    })
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DirectionState {
    Same,
    Different,
    Gap,
}

fn direction_state(score: f64, same: f64, different: f64) -> DirectionState {
    if score <= same {
        DirectionState::Same
    } else if score >= different {
        DirectionState::Different
    } else {
        DirectionState::Gap
    }
}

fn load_document<T>(data: &[u8]) -> Result<T, CalibratedEventRelationDocumentErrorV0>
where
    T: for<'de> Deserialize<'de>,
{
    if data.len() > MAX_DOCUMENT_BYTES {
        return Err(CalibratedEventRelationDocumentErrorV0::DocumentTooLarge);
    }
    serde_json::from_slice(data).map_err(CalibratedEventRelationDocumentErrorV0::Json)
}

fn domain_digest(domain: &[u8], bytes: Vec<u8>) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn value(value: &str) -> Value {
    Value::String(value.to_owned())
}

fn parse_canonical_distance(value: &str) -> Option<f64> {
    if value == "0x0.0p+0" {
        return Some(0.0);
    }
    let (significand, exponent) = value.split_once('p')?;
    let exponent_value = exponent.parse::<i32>().ok()?;
    if exponent != format!("{exponent_value:+}") {
        return None;
    }
    let fraction = if let Some(fraction) = significand.strip_prefix("0x1.") {
        if !(-1022..=1023).contains(&exponent_value) {
            return None;
        }
        fraction
    } else {
        let fraction = significand.strip_prefix("0x0.")?;
        if exponent_value != -1022 {
            return None;
        }
        fraction
    };
    if fraction.len() != 13
        || !fraction
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let fraction_bits = u64::from_str_radix(fraction, 16).ok()?;
    let bits = if significand.starts_with("0x1.") {
        (((exponent_value + 1023) as u64) << 52) | fraction_bits
    } else {
        if fraction_bits == 0 {
            return None;
        }
        fraction_bits
    };
    let parsed = f64::from_bits(bits);
    (canonical_distance_hex(parsed) == value).then_some(parsed)
}

fn canonical_distance_hex(value: f64) -> String {
    let bits = value.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let fraction = bits & ((1_u64 << 52) - 1);
    if exponent == 0 {
        if fraction == 0 {
            "0x0.0p+0".to_owned()
        } else {
            format!("0x0.{fraction:013x}p-1022")
        }
    } else {
        format!("0x1.{fraction:013x}p{:+}", exponent - 1023)
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && (value.as_bytes()[0].is_ascii_lowercase() || value.as_bytes()[0].is_ascii_digit())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn valid_artifact_id(value: &str) -> bool {
    value.len() <= MAX_ARTIFACT_ID_LEN && valid_identifier(value)
}

fn valid_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:+-".contains(&byte))
}

fn valid_source_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_SOURCE_ID_LEN && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
