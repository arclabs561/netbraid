use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

pub const CONTENT_DIGEST_EVIDENCE_SCHEMA_V0: &str = "netbraid.content_digest_evidence.v0";
pub const CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0: &str =
    "netbraid.content_relation_hypothesis_set.v0";
pub const CONTENT_RELATION_REDUCER_V0: &str = "netbraid.content_relation.sha256.v0";

const EVIDENCE_DIGEST_DOMAIN: &[u8] = b"netbraid.content-digest-evidence.v0\0";
const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_RECORD_ID_LEN: usize = 512;
const LIMITATIONS: &[&str] = &[
    "the decision compares declared SHA-256 content digests only",
    "evidence records bind declarations but do not authenticate their subject or provenance",
    "matching digests do not establish byte equality or the same object event source device variant or identity",
    "different digests do not establish corruption transformation tampering authorization or intent",
    "unavailable digest evidence remains unknown and is not treated as a digest mismatch",
];

/// Canonical lowercase SHA-256 content digest without an algorithm prefix.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct ContentSha256V0(String);

impl ContentSha256V0 {
    pub fn try_new(value: impl Into<String>) -> Result<Self, ContentSha256ParseErrorV0> {
        let value = value.into();
        if !valid_sha256(&value) {
            return Err(ContentSha256ParseErrorV0);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ContentSha256V0 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::try_new(value).map_err(serde::de::Error::custom)
    }
}

/// Failure to parse a canonical SHA-256 content digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContentSha256ParseErrorV0;

impl std::fmt::Display for ContentSha256ParseErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid canonical SHA-256 content digest")
    }
}

impl std::error::Error for ContentSha256ParseErrorV0 {}

/// Why a source cannot supply a content digest for the compared subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ContentDigestUnavailableReasonV0 {
    NotProvided,
    UnsupportedAlgorithm,
    IncompleteEvidence,
}

/// Digest-bearing or explicitly unavailable content evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContentDigestStateV0 {
    Observed {
        sha256: ContentSha256V0,
    },
    Unavailable {
        reason: ContentDigestUnavailableReasonV0,
    },
}

impl ContentDigestStateV0 {
    pub fn observed_sha256(&self) -> Option<&ContentSha256V0> {
        match self {
            Self::Observed { sha256 } => Some(sha256),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn unavailable_reason(&self) -> Option<ContentDigestUnavailableReasonV0> {
        match self {
            Self::Observed { .. } => None,
            Self::Unavailable { reason } => Some(*reason),
        }
    }
}

/// One source-preserving declaration about a subject's content digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct ContentDigestEvidenceV0 {
    schema: String,
    record_id: String,
    subject_schema: String,
    subject_id: String,
    digest: ContentDigestStateV0,
}

impl ContentDigestEvidenceV0 {
    pub fn observed(
        record_id: impl Into<String>,
        subject_schema: impl Into<String>,
        subject_id: impl Into<String>,
        sha256: ContentSha256V0,
    ) -> Result<Self, ContentDigestEvidenceValidationErrorV0> {
        Self::try_new(
            record_id,
            subject_schema,
            subject_id,
            ContentDigestStateV0::Observed { sha256 },
        )
    }

    pub fn unavailable(
        record_id: impl Into<String>,
        subject_schema: impl Into<String>,
        subject_id: impl Into<String>,
        reason: ContentDigestUnavailableReasonV0,
    ) -> Result<Self, ContentDigestEvidenceValidationErrorV0> {
        Self::try_new(
            record_id,
            subject_schema,
            subject_id,
            ContentDigestStateV0::Unavailable { reason },
        )
    }

    fn try_new(
        record_id: impl Into<String>,
        subject_schema: impl Into<String>,
        subject_id: impl Into<String>,
        digest: ContentDigestStateV0,
    ) -> Result<Self, ContentDigestEvidenceValidationErrorV0> {
        let evidence = Self {
            schema: CONTENT_DIGEST_EVIDENCE_SCHEMA_V0.to_owned(),
            record_id: record_id.into(),
            subject_schema: subject_schema.into(),
            subject_id: subject_id.into(),
            digest,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    pub fn subject_schema(&self) -> &str {
        &self.subject_schema
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    pub fn digest(&self) -> &ContentDigestStateV0 {
        &self.digest
    }

    pub fn validate(&self) -> Result<(), ContentDigestEvidenceValidationErrorV0> {
        if self.schema != CONTENT_DIGEST_EVIDENCE_SCHEMA_V0 {
            return Err(ContentDigestEvidenceValidationErrorV0::UnsupportedSchema);
        }
        if !valid_identifier(&self.subject_schema) {
            return Err(ContentDigestEvidenceValidationErrorV0::InvalidSubjectSchema);
        }
        if !valid_record_id(&self.record_id) {
            return Err(ContentDigestEvidenceValidationErrorV0::InvalidRecordId);
        }
        if !valid_record_id(&self.subject_id) {
            return Err(ContentDigestEvidenceValidationErrorV0::InvalidSubjectId);
        }
        Ok(())
    }

    pub fn canonical_sha256(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(self)?;
        let mut digest = Sha256::new();
        digest.update(EVIDENCE_DIGEST_DOMAIN);
        digest.update(encoded);
        Ok(format!("{:x}", digest.finalize()))
    }
}

/// Semantic failure in content-digest evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentDigestEvidenceValidationErrorV0 {
    UnsupportedSchema,
    InvalidRecordId,
    InvalidSubjectSchema,
    InvalidSubjectId,
}

impl std::fmt::Display for ContentDigestEvidenceValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported content-digest evidence schema",
            Self::InvalidRecordId => "invalid content-digest evidence record identifier",
            Self::InvalidSubjectSchema => "invalid content subject schema",
            Self::InvalidSubjectId => "invalid content subject identifier",
        })
    }
}

impl std::error::Error for ContentDigestEvidenceValidationErrorV0 {}

/// Disposition of one retained content-relation alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ContentRelationDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

/// Why digest evidence cannot decide the content relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ContentRelationUnknownReasonV0 {
    LeftDigestUnavailable,
    RightDigestUnavailable,
    BothDigestsUnavailable,
}

/// Exact decision basis retained by the content relation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum ContentRelationBasisV0 {
    Sha256Equal,
    Sha256Different,
    DigestUnavailable {
        reason: ContentRelationUnknownReasonV0,
    },
}

/// Deterministic reference answer while all alternatives remain present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "hypothesis", rename_all = "snake_case")]
pub enum ContentRelationReferenceV0 {
    Sha256Match,
    Sha256Mismatch,
    Unknown {
        reason: ContentRelationUnknownReasonV0,
    },
}

/// Content-bound reference to one digest-evidence record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct ContentRelationEvidenceRefV0 {
    record_id: String,
    subject_schema: String,
    subject_id: String,
    evidence_sha256: String,
}

impl ContentRelationEvidenceRefV0 {
    pub fn record_id(&self) -> &str {
        &self.record_id
    }

    pub fn subject_schema(&self) -> &str {
        &self.subject_schema
    }

    pub fn subject_id(&self) -> &str {
        &self.subject_id
    }

    pub fn evidence_sha256(&self) -> &str {
        &self.evidence_sha256
    }
}

/// A finite content relation over two source-preserving digest declarations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct ContentRelationHypothesisSetV0 {
    schema: String,
    reducer: String,
    left: ContentRelationEvidenceRefV0,
    right: ContentRelationEvidenceRefV0,
    basis: ContentRelationBasisV0,
    sha256_match: ContentRelationDispositionV0,
    sha256_mismatch: ContentRelationDispositionV0,
    unknown: ContentRelationDispositionV0,
    reference: ContentRelationReferenceV0,
    limitations: Vec<String>,
}

impl ContentRelationHypothesisSetV0 {
    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn reducer(&self) -> &str {
        &self.reducer
    }

    pub fn left(&self) -> &ContentRelationEvidenceRefV0 {
        &self.left
    }

    pub fn right(&self) -> &ContentRelationEvidenceRefV0 {
        &self.right
    }

    pub fn basis(&self) -> ContentRelationBasisV0 {
        self.basis
    }

    pub fn sha256_match(&self) -> ContentRelationDispositionV0 {
        self.sha256_match
    }

    pub fn sha256_mismatch(&self) -> ContentRelationDispositionV0 {
        self.sha256_mismatch
    }

    pub fn unknown(&self) -> ContentRelationDispositionV0 {
        self.unknown
    }

    pub fn reference(&self) -> ContentRelationReferenceV0 {
        self.reference
    }

    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    pub fn validate(&self) -> Result<(), ContentRelationValidationErrorV0> {
        if self.schema != CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0 {
            return Err(ContentRelationValidationErrorV0::UnsupportedSchema);
        }
        if self.reducer != CONTENT_RELATION_REDUCER_V0 {
            return Err(ContentRelationValidationErrorV0::UnsupportedReducer);
        }
        if !valid_evidence_reference(&self.left) || !valid_evidence_reference(&self.right) {
            return Err(ContentRelationValidationErrorV0::InvalidEvidenceReference);
        }
        if evidence_order(&self.left) > evidence_order(&self.right) {
            return Err(ContentRelationValidationErrorV0::NonCanonicalEvidenceOrder);
        }
        if self
            .limitations
            .iter()
            .map(String::as_str)
            .ne(LIMITATIONS.iter().copied())
        {
            return Err(ContentRelationValidationErrorV0::UnexpectedLimitations);
        }

        let coherent = match (self.reference, self.basis) {
            (ContentRelationReferenceV0::Sha256Match, ContentRelationBasisV0::Sha256Equal) => {
                self.sha256_match == ContentRelationDispositionV0::Supported
                    && self.sha256_mismatch == ContentRelationDispositionV0::Contradicted
                    && self.unknown == ContentRelationDispositionV0::Contradicted
            }
            (
                ContentRelationReferenceV0::Sha256Mismatch,
                ContentRelationBasisV0::Sha256Different,
            ) => {
                self.sha256_match == ContentRelationDispositionV0::Contradicted
                    && self.sha256_mismatch == ContentRelationDispositionV0::Supported
                    && self.unknown == ContentRelationDispositionV0::Contradicted
            }
            (
                ContentRelationReferenceV0::Unknown { reason: left },
                ContentRelationBasisV0::DigestUnavailable { reason: right },
            ) if left == right => {
                self.sha256_match == ContentRelationDispositionV0::Underdetermined
                    && self.sha256_mismatch == ContentRelationDispositionV0::Underdetermined
                    && self.unknown == ContentRelationDispositionV0::Supported
            }
            _ => false,
        };
        if !coherent {
            return Err(ContentRelationValidationErrorV0::IncoherentAssessment);
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        left: &ContentDigestEvidenceV0,
        right: &ContentDigestEvidenceV0,
    ) -> Result<(), ContentRelationErrorV0> {
        self.validate()
            .map_err(ContentRelationErrorV0::InternalInvariant)?;
        let recomputed = assess_content_relation_v0(left, right)?;
        if &recomputed != self {
            return Err(ContentRelationErrorV0::InternalInvariant(
                ContentRelationValidationErrorV0::ResolvedContentMismatch,
            ));
        }
        Ok(())
    }
}

/// Semantic failure in a serialized or resolved content relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentRelationValidationErrorV0 {
    UnsupportedSchema,
    UnsupportedReducer,
    InvalidEvidenceReference,
    NonCanonicalEvidenceOrder,
    IncoherentAssessment,
    UnexpectedLimitations,
    ResolvedContentMismatch,
}

impl std::fmt::Display for ContentRelationValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported content-relation schema",
            Self::UnsupportedReducer => "unsupported content-relation reducer",
            Self::InvalidEvidenceReference => "invalid content-relation evidence reference",
            Self::NonCanonicalEvidenceOrder => {
                "content-relation evidence references are not canonically ordered"
            }
            Self::IncoherentAssessment => "content-relation assessment is incoherent",
            Self::UnexpectedLimitations => {
                "content-relation limitations differ from the v0 contract"
            }
            Self::ResolvedContentMismatch => {
                "content-relation assessment differs from resolved digest evidence"
            }
        })
    }
}

impl std::error::Error for ContentRelationValidationErrorV0 {}

/// Failure to assess two content-digest evidence records.
#[derive(Debug)]
#[non_exhaustive]
pub enum ContentRelationErrorV0 {
    InvalidEvidence(ContentDigestEvidenceValidationErrorV0),
    Serialization(serde_json::Error),
    InternalInvariant(ContentRelationValidationErrorV0),
}

impl std::fmt::Display for ContentRelationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvidence(source) => {
                write!(formatter, "invalid content evidence: {source}")
            }
            Self::Serialization(source) => {
                write!(formatter, "content evidence serialization failed: {source}")
            }
            Self::InternalInvariant(source) => {
                write!(formatter, "validate content-relation assessment: {source}")
            }
        }
    }
}

impl std::error::Error for ContentRelationErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidEvidence(source) => Some(source),
            Self::Serialization(source) => Some(source),
            Self::InternalInvariant(source) => Some(source),
        }
    }
}

pub fn assess_content_relation_v0(
    left: &ContentDigestEvidenceV0,
    right: &ContentDigestEvidenceV0,
) -> Result<ContentRelationHypothesisSetV0, ContentRelationErrorV0> {
    left.validate()
        .map_err(ContentRelationErrorV0::InvalidEvidence)?;
    right
        .validate()
        .map_err(ContentRelationErrorV0::InvalidEvidence)?;

    let left_ref = evidence_ref(left)?;
    let right_ref = evidence_ref(right)?;
    let (left, right, left_ref, right_ref) =
        if evidence_order(&left_ref) <= evidence_order(&right_ref) {
            (left, right, left_ref, right_ref)
        } else {
            (right, left, right_ref, left_ref)
        };

    let (basis, reference, sha256_match, sha256_mismatch, unknown) =
        match (left.digest(), right.digest()) {
            (
                ContentDigestStateV0::Observed { sha256: left },
                ContentDigestStateV0::Observed { sha256: right },
            ) if left == right => (
                ContentRelationBasisV0::Sha256Equal,
                ContentRelationReferenceV0::Sha256Match,
                ContentRelationDispositionV0::Supported,
                ContentRelationDispositionV0::Contradicted,
                ContentRelationDispositionV0::Contradicted,
            ),
            (ContentDigestStateV0::Observed { .. }, ContentDigestStateV0::Observed { .. }) => (
                ContentRelationBasisV0::Sha256Different,
                ContentRelationReferenceV0::Sha256Mismatch,
                ContentRelationDispositionV0::Contradicted,
                ContentRelationDispositionV0::Supported,
                ContentRelationDispositionV0::Contradicted,
            ),
            (
                ContentDigestStateV0::Unavailable { .. },
                ContentDigestStateV0::Unavailable { .. },
            ) => unknown_assessment(ContentRelationUnknownReasonV0::BothDigestsUnavailable),
            (ContentDigestStateV0::Unavailable { .. }, _) => {
                unknown_assessment(ContentRelationUnknownReasonV0::LeftDigestUnavailable)
            }
            (_, ContentDigestStateV0::Unavailable { .. }) => {
                unknown_assessment(ContentRelationUnknownReasonV0::RightDigestUnavailable)
            }
        };

    let assessment = ContentRelationHypothesisSetV0 {
        schema: CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0.to_owned(),
        reducer: CONTENT_RELATION_REDUCER_V0.to_owned(),
        left: left_ref,
        right: right_ref,
        basis,
        sha256_match,
        sha256_mismatch,
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

fn unknown_assessment(
    reason: ContentRelationUnknownReasonV0,
) -> (
    ContentRelationBasisV0,
    ContentRelationReferenceV0,
    ContentRelationDispositionV0,
    ContentRelationDispositionV0,
    ContentRelationDispositionV0,
) {
    (
        ContentRelationBasisV0::DigestUnavailable { reason },
        ContentRelationReferenceV0::Unknown { reason },
        ContentRelationDispositionV0::Underdetermined,
        ContentRelationDispositionV0::Underdetermined,
        ContentRelationDispositionV0::Supported,
    )
}

fn evidence_ref(
    evidence: &ContentDigestEvidenceV0,
) -> Result<ContentRelationEvidenceRefV0, ContentRelationErrorV0> {
    Ok(ContentRelationEvidenceRefV0 {
        record_id: evidence.record_id().to_owned(),
        subject_schema: evidence.subject_schema().to_owned(),
        subject_id: evidence.subject_id().to_owned(),
        evidence_sha256: evidence
            .canonical_sha256()
            .map_err(ContentRelationErrorV0::Serialization)?,
    })
}

fn valid_evidence_reference(reference: &ContentRelationEvidenceRefV0) -> bool {
    valid_record_id(&reference.record_id)
        && valid_identifier(&reference.subject_schema)
        && valid_record_id(&reference.subject_id)
        && valid_sha256(&reference.evidence_sha256)
}

fn evidence_order(reference: &ContentRelationEvidenceRefV0) -> (&str, &str, &str, &str) {
    (
        &reference.subject_schema,
        &reference.subject_id,
        &reference.record_id,
        &reference.evidence_sha256,
    )
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn valid_record_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_RECORD_ID_LEN && !value.chars().any(char::is_control)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observed(record: &str, subject: &str, hex: char) -> ContentDigestEvidenceV0 {
        ContentDigestEvidenceV0::observed(
            record,
            "netbraid.test_subject.v0",
            subject,
            ContentSha256V0::try_new(hex.to_string().repeat(64)).unwrap(),
        )
        .unwrap()
    }

    fn unavailable(record: &str, subject: &str) -> ContentDigestEvidenceV0 {
        ContentDigestEvidenceV0::unavailable(
            record,
            "netbraid.test_subject.v0",
            subject,
            ContentDigestUnavailableReasonV0::NotProvided,
        )
        .unwrap()
    }

    #[test]
    fn matching_and_different_digests_are_exact_and_symmetric() {
        let left = observed("digest:left", "subject:left", 'a');
        let equal = observed("digest:right", "subject:right", 'a');
        let different = observed("digest:other", "subject:other", 'b');

        let same = assess_content_relation_v0(&left, &equal).unwrap();
        assert_eq!(same.reference(), ContentRelationReferenceV0::Sha256Match);
        assert_eq!(same.basis(), ContentRelationBasisV0::Sha256Equal);
        assert_eq!(same.sha256_match(), ContentRelationDispositionV0::Supported);

        let changed = assess_content_relation_v0(&left, &different).unwrap();
        assert_eq!(
            changed.reference(),
            ContentRelationReferenceV0::Sha256Mismatch
        );
        assert_eq!(changed.basis(), ContentRelationBasisV0::Sha256Different);
        assert_eq!(
            changed.sha256_mismatch(),
            ContentRelationDispositionV0::Supported
        );
        assert_eq!(
            assess_content_relation_v0(&different, &left).unwrap(),
            changed
        );
    }

    #[test]
    fn unavailable_digest_selects_unknown_after_canonical_ordering() {
        let available = observed("digest:z", "subject:z", 'a');
        let missing = unavailable("digest:a", "subject:a");
        let both_missing = unavailable("digest:b", "subject:b");

        let result = assess_content_relation_v0(&available, &missing).unwrap();
        assert_eq!(
            result.reference(),
            ContentRelationReferenceV0::Unknown {
                reason: ContentRelationUnknownReasonV0::LeftDigestUnavailable,
            }
        );
        assert_eq!(result.unknown(), ContentRelationDispositionV0::Supported);
        assert_eq!(
            result.sha256_match(),
            ContentRelationDispositionV0::Underdetermined
        );
        assert_eq!(
            assess_content_relation_v0(&missing, &available).unwrap(),
            result
        );

        let result = assess_content_relation_v0(&missing, &both_missing).unwrap();
        assert_eq!(
            result.reference(),
            ContentRelationReferenceV0::Unknown {
                reason: ContentRelationUnknownReasonV0::BothDigestsUnavailable,
            }
        );
    }

    #[test]
    fn digest_newtype_rejects_noncanonical_values_at_json_boundary() {
        for value in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            assert!(ContentSha256V0::try_new(value).is_err());
        }

        let evidence = observed("digest:one", "subject:one", 'a');
        let mut document = serde_json::to_value(&evidence).unwrap();
        document["digest"]["sha256"] = serde_json::Value::String("A".repeat(64));
        assert!(serde_json::from_value::<ContentDigestEvidenceV0>(document).is_err());
    }

    #[test]
    fn resolved_content_and_serialized_semantics_are_rechecked() {
        let left = observed("digest:left", "subject:left", 'a');
        let right = observed("digest:right", "subject:right", 'b');
        let assessment = assess_content_relation_v0(&left, &right).unwrap();
        assessment.validate_against(&left, &right).unwrap();

        let changed = observed("digest:right", "subject:right", 'a');
        assert!(matches!(
            assessment.validate_against(&left, &changed),
            Err(ContentRelationErrorV0::InternalInvariant(
                ContentRelationValidationErrorV0::ResolvedContentMismatch
            ))
        ));

        let mut malformed = serde_json::to_value(&left).unwrap();
        malformed["schema"] = serde_json::Value::String("netbraid.wrong.v0".to_owned());
        let malformed: ContentDigestEvidenceV0 = serde_json::from_value(malformed).unwrap();
        assert!(matches!(
            assessment.validate_against(&malformed, &right),
            Err(ContentRelationErrorV0::InvalidEvidence(
                ContentDigestEvidenceValidationErrorV0::UnsupportedSchema
            ))
        ));

        let mut document = serde_json::to_value(&assessment).unwrap();
        document["reference"] = serde_json::json!({"hypothesis": "sha256_match"});
        let forged: ContentRelationHypothesisSetV0 = serde_json::from_value(document).unwrap();
        assert_eq!(
            forged.validate(),
            Err(ContentRelationValidationErrorV0::IncoherentAssessment)
        );
    }

    #[test]
    fn canonical_evidence_digest_is_domain_separated_and_stable() {
        let evidence = observed("digest:one", "subject:one", 'a');
        let digest = evidence.canonical_sha256().unwrap();
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, evidence.canonical_sha256().unwrap());
        assert_ne!(
            digest,
            evidence.digest().observed_sha256().unwrap().as_str()
        );
    }

    #[test]
    fn serialized_shape_is_stable_and_explicit_about_non_identity() {
        let left = observed("digest:left", "subject:left", 'a');
        let right = observed("digest:right", "subject:right", 'a');
        let assessment = assess_content_relation_v0(&left, &right).unwrap();
        let document = serde_json::to_value(&assessment).unwrap();

        assert_eq!(
            document,
            serde_json::json!({
                "schema": CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
                "reducer": CONTENT_RELATION_REDUCER_V0,
                "left": {
                    "record_id": "digest:left",
                    "subject_schema": "netbraid.test_subject.v0",
                    "subject_id": "subject:left",
                    "evidence_sha256": left.canonical_sha256().unwrap(),
                },
                "right": {
                    "record_id": "digest:right",
                    "subject_schema": "netbraid.test_subject.v0",
                    "subject_id": "subject:right",
                    "evidence_sha256": right.canonical_sha256().unwrap(),
                },
                "basis": {"basis": "sha256_equal"},
                "sha256_match": "supported",
                "sha256_mismatch": "contradicted",
                "unknown": "contradicted",
                "reference": {"hypothesis": "sha256_match"},
                "limitations": LIMITATIONS,
            })
        );
    }
}
