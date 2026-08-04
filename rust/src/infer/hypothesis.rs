use serde::Serialize;

use crate::evidence::{PacketEnvelopeV0, PACKET_ENVELOPE_SCHEMA_V0};
use crate::infer::{
    ContentDigestEvidenceV0, ContentRelationDispositionV0, ContentRelationErrorV0,
    ContentRelationHypothesisSetV0, ContentRelationValidationErrorV0, CounterCaptureDispositionV0,
    CounterCaptureErrorV0, CounterCaptureHypothesisSetV0, CounterCaptureProfileV0,
    CounterCaptureValidationErrorV0, PacketSameEventDispositionV0, PacketSameEventErrorV0,
    PacketSameEventHypothesisSetV0, PacketSameEventValidationErrorV0,
    SavedPcapFingerprintCandidateV0, SavedPcapFingerprintDispositionV0,
    SavedPcapFingerprintErrorV0, SavedPcapFingerprintHypothesisSetV0,
    SavedPcapFingerprintValidationErrorV0, TrafficWindowEvidenceV0,
    CONTENT_DIGEST_EVIDENCE_SCHEMA_V0,
};

pub const FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0: &str = "netbraid.finite_hypothesis_projection.v0";
pub const FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0: &str = "netbraid.finite_hypothesis_claim.v0";

const UNKNOWN_ROLE: &str = "unknown";
const MAX_ALTERNATIVES: usize = 64;
const MAX_IDENTIFIER_LEN: usize = 128;
const MAX_INPUTS: usize = 64;
const MAX_ROLE_LEN: usize = 64;

/// Source-neutral disposition of one retained finite alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FiniteHypothesisDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

/// One named alternative in a finite, mutually exclusive hypothesis set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FiniteHypothesisAlternativeV0 {
    role: String,
    disposition: FiniteHypothesisDispositionV0,
}

impl FiniteHypothesisAlternativeV0 {
    /// Parse one stable snake-case role label.
    pub(crate) fn try_new(
        role: impl Into<String>,
        disposition: FiniteHypothesisDispositionV0,
    ) -> Result<Self, FiniteHypothesisProjectionErrorV0> {
        let role = role.into();
        if !valid_role(&role) {
            return Err(FiniteHypothesisProjectionErrorV0::InvalidAlternativeRole);
        }
        Ok(Self { role, disposition })
    }

    pub fn role(&self) -> &str {
        &self.role
    }

    pub fn disposition(&self) -> FiniteHypothesisDispositionV0 {
        self.disposition
    }
}

/// A policy-free projection of mutually exclusive alternatives and unknown.
///
/// This is an operator and evaluation seam, not a replacement for the source
/// family's assessment. It deliberately omits evidence, decision bases,
/// limitations, scores, probabilities, rankings, and identity claims. Known
/// family adapters validate serialized structure before projecting; content
/// resolution still requires the source family's `validate_against` method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FiniteHypothesisProjectionV0 {
    schema: String,
    family_schema: String,
    reducer: String,
    alternatives: Box<[FiniteHypothesisAlternativeV0]>,
}

impl FiniteHypothesisProjectionV0 {
    /// Construct a coherent finite projection.
    ///
    /// Exactly one alternative must be named `unknown`. Exactly one
    /// alternative is supported. Supporting `unknown` requires every
    /// substantive alternative to remain underdetermined; supporting a
    /// substantive alternative contradicts every other retained alternative.
    pub(crate) fn try_new(
        family_schema: impl Into<String>,
        reducer: impl Into<String>,
        alternatives: Vec<FiniteHypothesisAlternativeV0>,
    ) -> Result<Self, FiniteHypothesisProjectionErrorV0> {
        let family_schema = family_schema.into();
        if !valid_identifier(&family_schema) {
            return Err(FiniteHypothesisProjectionErrorV0::InvalidFamilySchema);
        }
        let reducer = reducer.into();
        if !valid_identifier(&reducer) {
            return Err(FiniteHypothesisProjectionErrorV0::InvalidReducer);
        }
        if !(2..=MAX_ALTERNATIVES).contains(&alternatives.len()) {
            return Err(FiniteHypothesisProjectionErrorV0::InvalidAlternativeCount);
        }
        for (index, alternative) in alternatives.iter().enumerate() {
            if alternatives[..index]
                .iter()
                .any(|prior| prior.role == alternative.role)
            {
                return Err(FiniteHypothesisProjectionErrorV0::DuplicateAlternativeRole);
            }
        }

        let unknown = alternatives
            .iter()
            .find(|alternative| alternative.role == UNKNOWN_ROLE)
            .ok_or(FiniteHypothesisProjectionErrorV0::MissingUnknownAlternative)?;
        let supported = alternatives
            .iter()
            .filter(|alternative| {
                alternative.disposition == FiniteHypothesisDispositionV0::Supported
            })
            .count();
        let dispositions_coherent = if unknown.disposition
            == FiniteHypothesisDispositionV0::Supported
        {
            supported == 1
                && alternatives.iter().all(|alternative| {
                    alternative.role == UNKNOWN_ROLE
                        || alternative.disposition == FiniteHypothesisDispositionV0::Underdetermined
                })
        } else {
            supported == 1
                && alternatives.iter().all(|alternative| {
                    alternative.disposition == FiniteHypothesisDispositionV0::Supported
                        || alternative.disposition == FiniteHypothesisDispositionV0::Contradicted
                })
        };
        if !dispositions_coherent {
            return Err(FiniteHypothesisProjectionErrorV0::IncoherentDisposition);
        }

        Ok(Self {
            schema: FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0.to_owned(),
            family_schema,
            reducer,
            alternatives: alternatives.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn family_schema(&self) -> &str {
        &self.family_schema
    }

    pub fn reducer(&self) -> &str {
        &self.reducer
    }

    pub fn alternatives(&self) -> &[FiniteHypothesisAlternativeV0] {
        &self.alternatives
    }
}

/// One content-bound input cited by a finite hypothesis claim.
///
/// The source family determines the meaning of `role`, `source_schema`, and
/// `source_id`. The digest binds the cited serialized input without retaining
/// raw evidence in the claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FiniteHypothesisInputRefV0 {
    role: String,
    source_schema: String,
    source_id: String,
    content_sha256: String,
}

impl FiniteHypothesisInputRefV0 {
    pub(crate) fn try_new(
        role: impl Into<String>,
        source_schema: impl Into<String>,
        source_id: impl Into<String>,
        content_sha256: impl Into<String>,
    ) -> Result<Self, FiniteHypothesisClaimErrorV0> {
        let role = role.into();
        if !valid_role(&role) {
            return Err(FiniteHypothesisClaimErrorV0::InvalidInputRole);
        }
        let source_schema = source_schema.into();
        if !valid_identifier(&source_schema) {
            return Err(FiniteHypothesisClaimErrorV0::InvalidInputSourceSchema);
        }
        let source_id = source_id.into();
        if source_id.is_empty() {
            return Err(FiniteHypothesisClaimErrorV0::InvalidInputSourceId);
        }
        let content_sha256 = content_sha256.into();
        if !valid_sha256(&content_sha256) {
            return Err(FiniteHypothesisClaimErrorV0::InvalidInputContentSha256);
        }
        Ok(Self {
            role,
            source_schema,
            source_id,
            content_sha256,
        })
    }

    pub fn role(&self) -> &str {
        &self.role
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
}

/// Evidence-linked form of an identifier-free finite hypothesis projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FiniteHypothesisClaimV0 {
    schema: String,
    projection: FiniteHypothesisProjectionV0,
    inputs: Box<[FiniteHypothesisInputRefV0]>,
}

impl FiniteHypothesisClaimV0 {
    pub(crate) fn try_new(
        projection: FiniteHypothesisProjectionV0,
        inputs: Vec<FiniteHypothesisInputRefV0>,
    ) -> Result<Self, FiniteHypothesisClaimErrorV0> {
        if !(2..=MAX_INPUTS).contains(&inputs.len()) {
            return Err(FiniteHypothesisClaimErrorV0::InvalidInputCount);
        }
        for pair in inputs.windows(2) {
            match pair[0].role.cmp(&pair[1].role) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => {
                    return Err(FiniteHypothesisClaimErrorV0::DuplicateInputRole)
                }
                std::cmp::Ordering::Greater => {
                    return Err(FiniteHypothesisClaimErrorV0::NonCanonicalInputOrder)
                }
            }
        }
        Ok(Self {
            schema: FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0.to_owned(),
            projection,
            inputs: inputs.into_boxed_slice(),
        })
    }

    pub fn schema(&self) -> &str {
        &self.schema
    }

    pub fn projection(&self) -> &FiniteHypothesisProjectionV0 {
        &self.projection
    }

    pub fn inputs(&self) -> &[FiniteHypothesisInputRefV0] {
        &self.inputs
    }
}

/// Failure to bind a finite projection to canonical content references.
#[derive(Debug)]
#[non_exhaustive]
pub enum FiniteHypothesisClaimErrorV0 {
    InvalidContentRelationResolution(ContentRelationErrorV0),
    InvalidProjection(FiniteHypothesisProjectionErrorV0),
    InvalidCounterCaptureResolution(CounterCaptureErrorV0),
    InvalidPacketSameEventResolution(PacketSameEventErrorV0),
    InvalidSavedPcapFingerprintResolution(SavedPcapFingerprintErrorV0),
    InvalidInputRole,
    InvalidInputSourceSchema,
    InvalidInputSourceId,
    InvalidInputContentSha256,
    InvalidInputCount,
    DuplicateInputRole,
    NonCanonicalInputOrder,
}

impl std::fmt::Display for FiniteHypothesisClaimErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContentRelationResolution(source) => {
                write!(
                    formatter,
                    "invalid resolved content-relation claim: {source}"
                )
            }
            Self::InvalidProjection(source) => {
                write!(formatter, "invalid finite projection: {source}")
            }
            Self::InvalidCounterCaptureResolution(source) => {
                write!(
                    formatter,
                    "invalid resolved counter/capture claim: {source}"
                )
            }
            Self::InvalidPacketSameEventResolution(source) => {
                write!(
                    formatter,
                    "invalid resolved packet same-event claim: {source}"
                )
            }
            Self::InvalidSavedPcapFingerprintResolution(source) => {
                write!(formatter, "invalid resolved saved-PCAP claim: {source}")
            }
            Self::InvalidInputRole => formatter.write_str("invalid finite-hypothesis input role"),
            Self::InvalidInputSourceSchema => {
                formatter.write_str("invalid finite-hypothesis input source schema")
            }
            Self::InvalidInputSourceId => {
                formatter.write_str("invalid finite-hypothesis input source identifier")
            }
            Self::InvalidInputContentSha256 => {
                formatter.write_str("invalid finite-hypothesis input content digest")
            }
            Self::InvalidInputCount => formatter.write_str("invalid finite-hypothesis input count"),
            Self::DuplicateInputRole => {
                formatter.write_str("duplicate finite-hypothesis input role")
            }
            Self::NonCanonicalInputOrder => {
                formatter.write_str("finite-hypothesis inputs are not canonically ordered")
            }
        }
    }
}

impl std::error::Error for FiniteHypothesisClaimErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidContentRelationResolution(source) => Some(source),
            Self::InvalidProjection(source) => Some(source),
            Self::InvalidCounterCaptureResolution(source) => Some(source),
            Self::InvalidPacketSameEventResolution(source) => Some(source),
            Self::InvalidSavedPcapFingerprintResolution(source) => Some(source),
            _ => None,
        }
    }
}

/// Failure to construct a bounded, coherent finite projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FiniteHypothesisProjectionErrorV0 {
    InvalidContentRelationAssessment(ContentRelationValidationErrorV0),
    InvalidCounterCaptureAssessment(CounterCaptureValidationErrorV0),
    InvalidPacketSameEventAssessment(PacketSameEventValidationErrorV0),
    InvalidSavedPcapFingerprintAssessment(SavedPcapFingerprintValidationErrorV0),
    InvalidFamilySchema,
    InvalidReducer,
    InvalidAlternativeRole,
    InvalidAlternativeCount,
    DuplicateAlternativeRole,
    MissingUnknownAlternative,
    IncoherentDisposition,
}

impl std::fmt::Display for FiniteHypothesisProjectionErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidContentRelationAssessment(source) => {
                write!(formatter, "invalid content-relation assessment: {source}")
            }
            Self::InvalidCounterCaptureAssessment(source) => {
                write!(formatter, "invalid counter/capture assessment: {source}")
            }
            Self::InvalidPacketSameEventAssessment(source) => {
                write!(formatter, "invalid packet same-event assessment: {source}")
            }
            Self::InvalidSavedPcapFingerprintAssessment(source) => {
                write!(
                    formatter,
                    "invalid saved-PCAP fingerprint assessment: {source}"
                )
            }
            Self::InvalidFamilySchema => {
                formatter.write_str("invalid finite-hypothesis family schema")
            }
            Self::InvalidReducer => formatter.write_str("invalid finite-hypothesis reducer"),
            Self::InvalidAlternativeRole => {
                formatter.write_str("invalid finite-hypothesis alternative role")
            }
            Self::InvalidAlternativeCount => {
                formatter.write_str("invalid finite-hypothesis alternative count")
            }
            Self::DuplicateAlternativeRole => {
                formatter.write_str("duplicate finite-hypothesis alternative role")
            }
            Self::MissingUnknownAlternative => {
                formatter.write_str("finite-hypothesis projection has no unknown alternative")
            }
            Self::IncoherentDisposition => {
                formatter.write_str("finite-hypothesis dispositions are incoherent")
            }
        }
    }
}

impl std::error::Error for FiniteHypothesisProjectionErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidContentRelationAssessment(source) => Some(source),
            Self::InvalidCounterCaptureAssessment(source) => Some(source),
            Self::InvalidPacketSameEventAssessment(source) => Some(source),
            Self::InvalidSavedPcapFingerprintAssessment(source) => Some(source),
            _ => None,
        }
    }
}

mod private {
    pub trait Sealed {}
}

impl private::Sealed for CounterCaptureHypothesisSetV0 {}
impl private::Sealed for ContentRelationHypothesisSetV0 {}
impl private::Sealed for PacketSameEventHypothesisSetV0 {}
impl private::Sealed for SavedPcapFingerprintHypothesisSetV0 {}

/// Project a structurally valid family assessment without merging its evidence semantics.
///
/// Implementations validate the complete serialized family assessment before
/// dropping its evidence, basis, and limitations. They cannot resolve cited
/// evidence that is not supplied to this projection boundary.
///
/// Downstream crates cannot add unvalidated family adapters:
///
/// ```compile_fail
/// use netbraid::infer::{
///     FiniteHypothesisProjectionErrorV0, FiniteHypothesisProjectionV0,
///     ProjectFiniteHypothesesV0,
/// };
///
/// struct ExternalFamily;
///
/// impl ProjectFiniteHypothesesV0 for ExternalFamily {
///     fn project_finite_hypotheses_v0(
///         &self,
///     ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
///         unreachable!()
///     }
/// }
/// ```
pub trait ProjectFiniteHypothesesV0: private::Sealed {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0>;
}

/// Bind a validated finite family assessment to its canonical input references.
///
/// The returned claim retains no raw evidence or family-specific decision
/// basis. Its nested projection is exactly the result of
/// [`ProjectFiniteHypothesesV0::project_finite_hypotheses_v0`].
pub trait ProjectFiniteHypothesisClaimV0: private::Sealed {
    type Inputs<'a>;

    fn project_finite_hypothesis_claim_v0(
        &self,
        inputs: Self::Inputs<'_>,
    ) -> Result<FiniteHypothesisClaimV0, FiniteHypothesisClaimErrorV0>;
}

impl From<CounterCaptureDispositionV0> for FiniteHypothesisDispositionV0 {
    fn from(value: CounterCaptureDispositionV0) -> Self {
        match value {
            CounterCaptureDispositionV0::Supported => Self::Supported,
            CounterCaptureDispositionV0::Contradicted => Self::Contradicted,
            CounterCaptureDispositionV0::Underdetermined => Self::Underdetermined,
        }
    }
}

impl From<ContentRelationDispositionV0> for FiniteHypothesisDispositionV0 {
    fn from(value: ContentRelationDispositionV0) -> Self {
        match value {
            ContentRelationDispositionV0::Supported => Self::Supported,
            ContentRelationDispositionV0::Contradicted => Self::Contradicted,
            ContentRelationDispositionV0::Underdetermined => Self::Underdetermined,
        }
    }
}

impl From<PacketSameEventDispositionV0> for FiniteHypothesisDispositionV0 {
    fn from(value: PacketSameEventDispositionV0) -> Self {
        match value {
            PacketSameEventDispositionV0::Supported => Self::Supported,
            PacketSameEventDispositionV0::Contradicted => Self::Contradicted,
            PacketSameEventDispositionV0::Underdetermined => Self::Underdetermined,
        }
    }
}

impl From<SavedPcapFingerprintDispositionV0> for FiniteHypothesisDispositionV0 {
    fn from(value: SavedPcapFingerprintDispositionV0) -> Self {
        match value {
            SavedPcapFingerprintDispositionV0::Supported => Self::Supported,
            SavedPcapFingerprintDispositionV0::Contradicted => Self::Contradicted,
            SavedPcapFingerprintDispositionV0::Underdetermined => Self::Underdetermined,
        }
    }
}

impl ProjectFiniteHypothesesV0 for CounterCaptureHypothesisSetV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
        self.validate_structure()
            .map_err(FiniteHypothesisProjectionErrorV0::InvalidCounterCaptureAssessment)?;
        project_three(
            &self.schema,
            &self.reducer,
            [
                (
                    "capture_accounts_for_window",
                    self.capture_accounts_for_window.into(),
                ),
                (
                    "capture_does_not_account_for_window",
                    self.capture_does_not_account_for_window.into(),
                ),
                (UNKNOWN_ROLE, self.unknown.into()),
            ],
        )
    }
}

impl ProjectFiniteHypothesesV0 for ContentRelationHypothesisSetV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
        self.validate()
            .map_err(FiniteHypothesisProjectionErrorV0::InvalidContentRelationAssessment)?;
        project_three(
            self.schema(),
            self.reducer(),
            [
                ("sha256_match", self.sha256_match().into()),
                ("sha256_mismatch", self.sha256_mismatch().into()),
                (UNKNOWN_ROLE, self.unknown().into()),
            ],
        )
    }
}

impl ProjectFiniteHypothesesV0 for PacketSameEventHypothesisSetV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
        self.validate()
            .map_err(FiniteHypothesisProjectionErrorV0::InvalidPacketSameEventAssessment)?;
        project_three(
            &self.schema,
            &self.reducer,
            [
                ("same_event", self.same_event.into()),
                ("different_event", self.different_event.into()),
                (UNKNOWN_ROLE, self.unknown.into()),
            ],
        )
    }
}

impl ProjectFiniteHypothesesV0 for SavedPcapFingerprintHypothesisSetV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
        self.validate()
            .map_err(FiniteHypothesisProjectionErrorV0::InvalidSavedPcapFingerprintAssessment)?;
        project_three(
            &self.schema,
            &self.reducer,
            [
                ("same_packet_shape", self.same_packet_shape.into()),
                ("different_packet_shape", self.different_packet_shape.into()),
                (UNKNOWN_ROLE, self.unknown.into()),
            ],
        )
    }
}

impl ProjectFiniteHypothesisClaimV0 for CounterCaptureHypothesisSetV0 {
    type Inputs<'a> = (
        &'a TrafficWindowEvidenceV0,
        &'a TrafficWindowEvidenceV0,
        &'a CounterCaptureProfileV0,
    );

    fn project_finite_hypothesis_claim_v0(
        &self,
        (counter, capture, profile): Self::Inputs<'_>,
    ) -> Result<FiniteHypothesisClaimV0, FiniteHypothesisClaimErrorV0> {
        self.validate_against(counter, capture, profile)
            .map_err(FiniteHypothesisClaimErrorV0::InvalidCounterCaptureResolution)?;
        let projection = self
            .project_finite_hypotheses_v0()
            .map_err(FiniteHypothesisClaimErrorV0::InvalidProjection)?;
        let inputs = vec![
            FiniteHypothesisInputRefV0::try_new(
                "calibration_profile",
                &self.profile.source_schema,
                &self.profile.profile_id,
                &self.profile.content_sha256,
            )?,
            FiniteHypothesisInputRefV0::try_new(
                "capture_window",
                &self.capture.source_schema,
                &self.capture.record_id,
                &self.capture.content_sha256,
            )?,
            FiniteHypothesisInputRefV0::try_new(
                "counter_window",
                &self.counter.source_schema,
                &self.counter.record_id,
                &self.counter.content_sha256,
            )?,
        ];
        FiniteHypothesisClaimV0::try_new(projection, inputs)
    }
}

impl ProjectFiniteHypothesisClaimV0 for ContentRelationHypothesisSetV0 {
    type Inputs<'a> = (&'a ContentDigestEvidenceV0, &'a ContentDigestEvidenceV0);

    fn project_finite_hypothesis_claim_v0(
        &self,
        (left, right): Self::Inputs<'_>,
    ) -> Result<FiniteHypothesisClaimV0, FiniteHypothesisClaimErrorV0> {
        self.validate_against(left, right)
            .map_err(FiniteHypothesisClaimErrorV0::InvalidContentRelationResolution)?;
        let projection = self
            .project_finite_hypotheses_v0()
            .map_err(FiniteHypothesisClaimErrorV0::InvalidProjection)?;
        let inputs = vec![
            FiniteHypothesisInputRefV0::try_new(
                "left_content_evidence",
                CONTENT_DIGEST_EVIDENCE_SCHEMA_V0,
                self.left().record_id(),
                self.left().evidence_sha256(),
            )?,
            FiniteHypothesisInputRefV0::try_new(
                "right_content_evidence",
                CONTENT_DIGEST_EVIDENCE_SCHEMA_V0,
                self.right().record_id(),
                self.right().evidence_sha256(),
            )?,
        ];
        FiniteHypothesisClaimV0::try_new(projection, inputs)
    }
}

impl ProjectFiniteHypothesisClaimV0 for PacketSameEventHypothesisSetV0 {
    type Inputs<'a> = (&'a PacketEnvelopeV0, &'a PacketEnvelopeV0);

    fn project_finite_hypothesis_claim_v0(
        &self,
        (left, right): Self::Inputs<'_>,
    ) -> Result<FiniteHypothesisClaimV0, FiniteHypothesisClaimErrorV0> {
        self.validate_against(left, right)
            .map_err(FiniteHypothesisClaimErrorV0::InvalidPacketSameEventResolution)?;
        let projection = self
            .project_finite_hypotheses_v0()
            .map_err(FiniteHypothesisClaimErrorV0::InvalidProjection)?;
        let inputs = vec![
            FiniteHypothesisInputRefV0::try_new(
                "left_packet",
                PACKET_ENVELOPE_SCHEMA_V0,
                &self.left.record_id,
                &self.left.envelope_sha256,
            )?,
            FiniteHypothesisInputRefV0::try_new(
                "right_packet",
                PACKET_ENVELOPE_SCHEMA_V0,
                &self.right.record_id,
                &self.right.envelope_sha256,
            )?,
        ];
        FiniteHypothesisClaimV0::try_new(projection, inputs)
    }
}

impl ProjectFiniteHypothesisClaimV0 for SavedPcapFingerprintHypothesisSetV0 {
    type Inputs<'a> = (
        &'a SavedPcapFingerprintCandidateV0,
        &'a SavedPcapFingerprintCandidateV0,
    );

    fn project_finite_hypothesis_claim_v0(
        &self,
        (left, right): Self::Inputs<'_>,
    ) -> Result<FiniteHypothesisClaimV0, FiniteHypothesisClaimErrorV0> {
        self.validate_against(left, right)
            .map_err(FiniteHypothesisClaimErrorV0::InvalidSavedPcapFingerprintResolution)?;
        let projection = self
            .project_finite_hypotheses_v0()
            .map_err(FiniteHypothesisClaimErrorV0::InvalidProjection)?;
        let inputs = vec![
            FiniteHypothesisInputRefV0::try_new(
                "left_candidate",
                &self.left.candidate_schema,
                &self.left.capture_id,
                &self.left.candidate_sha256,
            )?,
            FiniteHypothesisInputRefV0::try_new(
                "right_candidate",
                &self.right.candidate_schema,
                &self.right.capture_id,
                &self.right.candidate_sha256,
            )?,
        ];
        FiniteHypothesisClaimV0::try_new(projection, inputs)
    }
}

fn project_three(
    family_schema: &str,
    reducer: &str,
    alternatives: [(&str, FiniteHypothesisDispositionV0); 3],
) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
    let alternatives = alternatives
        .into_iter()
        .map(|(role, disposition)| FiniteHypothesisAlternativeV0::try_new(role, disposition))
        .collect::<Result<Vec<_>, _>>()?;
    FiniteHypothesisProjectionV0::try_new(family_schema, reducer, alternatives)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTIFIER_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
}

fn valid_role(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ROLE_LEN
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
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
    use crate::evidence::{CaptureExtractorRefV0, PacketEnvelopeV0};
    use crate::infer::{
        assess_counter_capture_v0, assess_packet_same_event_v0, assess_saved_pcap_fingerprint_v0,
        CounterCaptureProfileV0, CounterCaptureScaleVectorPpbV0, TrafficWindowEvidenceV0,
        TrafficWindowV0,
    };
    use crate::replay::{
        SavedPcapClaimScopeV0, SavedPcapFingerprintCandidateV0, SavedPcapFingerprintSourceV0,
        SavedPcapFingerprintStatusV0, SavedPcapFingerprintUnsupportedReasonV0,
        SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0,
    };

    fn alternative(
        role: &str,
        disposition: FiniteHypothesisDispositionV0,
    ) -> FiniteHypothesisAlternativeV0 {
        FiniteHypothesisAlternativeV0::try_new(role, disposition).unwrap()
    }

    fn input(role: &str) -> FiniteHypothesisInputRefV0 {
        FiniteHypothesisInputRefV0::try_new(
            role,
            "netbraid.test_input.v0",
            format!("input:{role}"),
            "a".repeat(64),
        )
        .unwrap()
    }

    fn fixture_projection() -> FiniteHypothesisProjectionV0 {
        FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Supported),
                alternative("different", FiniteHypothesisDispositionV0::Contradicted),
                alternative(UNKNOWN_ROLE, FiniteHypothesisDispositionV0::Contradicted),
            ],
        )
        .unwrap()
    }

    fn packet() -> PacketEnvelopeV0 {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/packet_envelope_v0.json"
        ))
        .unwrap()
    }

    fn unsupported_candidate(hex: char) -> SavedPcapFingerprintCandidateV0 {
        SavedPcapFingerprintCandidateV0 {
            schema: SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.to_owned(),
            source: SavedPcapFingerprintSourceV0 {
                capture_id: format!("sha256:{}", hex.to_string().repeat(64)),
                normalized_records_sha256: format!("sha256:{}", "f".repeat(64)),
                extractor: CaptureExtractorRefV0 {
                    adapter: "netbraid-adapter-tshark".into(),
                    adapter_version: "0.3.2".into(),
                    tool: "tshark".into(),
                    tool_version: "TShark 4.6.7".into(),
                    configuration_sha256: format!("sha256:{}", "e".repeat(64)),
                    field_registry: "netmon.tshark.packet_envelope.v1".into(),
                },
            },
            scope: SavedPcapClaimScopeV0::CompleteCapture,
            status: SavedPcapFingerprintStatusV0::Unsupported {
                reason: SavedPcapFingerprintUnsupportedReasonV0::NoEligibleIpTcpUdpPacketEnvelopes,
                packet_envelopes_seen: 1,
                packet_envelopes_excluded: 1,
                exclusions: Vec::new(),
            },
        }
    }

    #[test]
    fn supports_more_than_two_substantive_alternatives() {
        let projection = FiniteHypothesisProjectionV0::try_new(
            "netbraid.variant_relation.v0",
            "netbraid.variant_relation.fixture.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Contradicted),
                alternative("left_derived", FiniteHypothesisDispositionV0::Supported),
                alternative("right_derived", FiniteHypothesisDispositionV0::Contradicted),
                alternative("different", FiniteHypothesisDispositionV0::Contradicted),
                alternative(UNKNOWN_ROLE, FiniteHypothesisDispositionV0::Contradicted),
            ],
        )
        .unwrap();

        assert_eq!(projection.alternatives().len(), 5);
        assert_eq!(projection.alternatives()[1].role(), "left_derived");
        assert_eq!(
            projection.alternatives()[1].disposition(),
            FiniteHypothesisDispositionV0::Supported
        );
    }

    #[test]
    fn unknown_requires_every_substantive_alternative_to_be_underdetermined() {
        let coherent = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Underdetermined),
                alternative("different", FiniteHypothesisDispositionV0::Underdetermined),
                alternative(UNKNOWN_ROLE, FiniteHypothesisDispositionV0::Supported),
            ],
        );
        assert!(coherent.is_ok());

        let incoherent = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Contradicted),
                alternative("different", FiniteHypothesisDispositionV0::Underdetermined),
                alternative(UNKNOWN_ROLE, FiniteHypothesisDispositionV0::Supported),
            ],
        );
        assert_eq!(
            incoherent,
            Err(FiniteHypothesisProjectionErrorV0::IncoherentDisposition)
        );
    }

    #[test]
    fn rejects_invalid_roles_duplicate_roles_and_missing_unknown() {
        assert_eq!(
            FiniteHypothesisAlternativeV0::try_new(
                "Same Event",
                FiniteHypothesisDispositionV0::Supported
            ),
            Err(FiniteHypothesisProjectionErrorV0::InvalidAlternativeRole)
        );
        let duplicate = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Supported),
                alternative("same", FiniteHypothesisDispositionV0::Contradicted),
                alternative(UNKNOWN_ROLE, FiniteHypothesisDispositionV0::Contradicted),
            ],
        );
        assert_eq!(
            duplicate,
            Err(FiniteHypothesisProjectionErrorV0::DuplicateAlternativeRole)
        );
        let missing_unknown = FiniteHypothesisProjectionV0::try_new(
            "netbraid.test_family.v0",
            "netbraid.test_reducer.v0",
            vec![
                alternative("same", FiniteHypothesisDispositionV0::Supported),
                alternative("different", FiniteHypothesisDispositionV0::Contradicted),
            ],
        );
        assert_eq!(
            missing_unknown,
            Err(FiniteHypothesisProjectionErrorV0::MissingUnknownAlternative)
        );
    }

    #[test]
    fn claim_inputs_fail_closed_when_malformed_or_noncanonical() {
        assert!(matches!(
            FiniteHypothesisInputRefV0::try_new(
                "left",
                "netbraid.test_input.v0",
                "input:left",
                "A".repeat(64),
            ),
            Err(FiniteHypothesisClaimErrorV0::InvalidInputContentSha256)
        ));
        assert!(matches!(
            FiniteHypothesisInputRefV0::try_new(
                "left",
                "Invalid Schema",
                "input:left",
                "a".repeat(64),
            ),
            Err(FiniteHypothesisClaimErrorV0::InvalidInputSourceSchema)
        ));
        assert!(matches!(
            FiniteHypothesisClaimV0::try_new(
                fixture_projection(),
                vec![input("left"), input("left")],
            ),
            Err(FiniteHypothesisClaimErrorV0::DuplicateInputRole)
        ));
        assert!(matches!(
            FiniteHypothesisClaimV0::try_new(
                fixture_projection(),
                vec![input("right"), input("left")],
            ),
            Err(FiniteHypothesisClaimErrorV0::NonCanonicalInputOrder)
        ));
        assert!(matches!(
            FiniteHypothesisClaimV0::try_new(fixture_projection(), vec![input("left")]),
            Err(FiniteHypothesisClaimErrorV0::InvalidInputCount)
        ));
    }

    #[test]
    fn proven_families_project_content_bound_claims() {
        let left_packet = packet();
        let mut right_packet = packet();
        right_packet.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right_packet.record_id = format!("{}:frame:1", right_packet.capture_id);
        let packet_assessment = assess_packet_same_event_v0(&left_packet, &right_packet).unwrap();
        let packet_claim = packet_assessment
            .project_finite_hypothesis_claim_v0((&left_packet, &right_packet))
            .unwrap();
        assert_eq!(
            packet_claim.projection(),
            &packet_assessment.project_finite_hypotheses_v0().unwrap()
        );
        assert_eq!(
            packet_claim
                .inputs()
                .iter()
                .map(FiniteHypothesisInputRefV0::role)
                .collect::<Vec<_>>(),
            ["left_packet", "right_packet"]
        );
        assert!(packet_claim
            .inputs()
            .iter()
            .all(|reference| reference.source_schema() == PACKET_ENVELOPE_SCHEMA_V0));

        let original_right_digest = packet_claim.inputs()[1].content_sha256().to_owned();
        right_packet.frame.original_len += 1;
        let changed_claim = assess_packet_same_event_v0(&left_packet, &right_packet)
            .unwrap()
            .project_finite_hypothesis_claim_v0((&left_packet, &right_packet))
            .unwrap();
        assert_ne!(
            changed_claim.inputs()[1].content_sha256(),
            original_right_digest
        );

        let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
        let counter = TrafficWindowEvidenceV0::declared_complete("counter:claim:0", window);
        let capture = TrafficWindowEvidenceV0::declared_complete("capture:claim:0", window);
        let profile = CounterCaptureProfileV0::new(
            "profile:claim:0",
            CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
            0,
            1,
        )
        .unwrap();
        let counter_assessment = assess_counter_capture_v0(&counter, &capture, &profile).unwrap();
        let counter_claim = counter_assessment
            .project_finite_hypothesis_claim_v0((&counter, &capture, &profile))
            .unwrap();
        assert_eq!(
            counter_claim
                .inputs()
                .iter()
                .map(FiniteHypothesisInputRefV0::role)
                .collect::<Vec<_>>(),
            ["calibration_profile", "capture_window", "counter_window"]
        );
        assert_eq!(counter_claim.inputs()[1].source_id(), "capture:claim:0");
        assert_eq!(counter_claim.inputs()[2].source_id(), "counter:claim:0");

        let left_candidate = unsupported_candidate('a');
        let right_candidate = unsupported_candidate('b');
        let fingerprint_assessment =
            assess_saved_pcap_fingerprint_v0(&left_candidate, &right_candidate).unwrap();
        let fingerprint_claim = fingerprint_assessment
            .project_finite_hypothesis_claim_v0((&left_candidate, &right_candidate))
            .unwrap();
        assert_eq!(
            fingerprint_claim
                .inputs()
                .iter()
                .map(FiniteHypothesisInputRefV0::role)
                .collect::<Vec<_>>(),
            ["left_candidate", "right_candidate"]
        );

        for claim in [packet_claim, counter_claim, fingerprint_claim] {
            assert_eq!(claim.schema(), FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0);
            let document = serde_json::to_value(claim).unwrap();
            let object = document.as_object().unwrap();
            assert_eq!(object.len(), 3);
            assert!(object.contains_key("schema"));
            assert!(object.contains_key("projection"));
            assert!(object.contains_key("inputs"));
            for input in object["inputs"].as_array().unwrap() {
                let input = input.as_object().unwrap();
                assert_eq!(input.len(), 4);
                assert!(input.contains_key("role"));
                assert!(input.contains_key("source_schema"));
                assert!(input.contains_key("source_id"));
                assert!(input.contains_key("content_sha256"));
            }
            let encoded = serde_json::to_string(object).unwrap();
            for forbidden in [
                "basis",
                "score",
                "probability",
                "intent",
                "tamper",
                "identity",
            ] {
                assert!(!encoded.contains(forbidden), "unexpected field {forbidden}");
            }
        }
    }

    #[test]
    fn claim_projection_resolves_content_and_preserves_family_id_contracts() {
        let left = packet();
        let mut right = packet();
        right.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right.record_id = format!("{}:frame:1", right.capture_id);
        let mut forged = assess_packet_same_event_v0(&left, &right).unwrap();
        forged.left.envelope_sha256 = "b".repeat(64);
        assert!(forged.project_finite_hypotheses_v0().is_ok());
        assert!(matches!(
            forged.project_finite_hypothesis_claim_v0((&left, &right)),
            Err(
                FiniteHypothesisClaimErrorV0::InvalidPacketSameEventResolution(
                    PacketSameEventErrorV0::InternalInvariant(
                        PacketSameEventValidationErrorV0::ResolvedContentMismatch
                    )
                )
            )
        ));

        let long_id = "counter:".to_owned() + &"x".repeat(600);
        let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
        let counter = TrafficWindowEvidenceV0::declared_complete(&long_id, window);
        let capture = TrafficWindowEvidenceV0::declared_complete("capture:long-id", window);
        let profile = CounterCaptureProfileV0::new(
            "profile:long-id",
            CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
            0,
            1,
        )
        .unwrap();
        let claim = assess_counter_capture_v0(&counter, &capture, &profile)
            .unwrap()
            .project_finite_hypothesis_claim_v0((&counter, &capture, &profile))
            .unwrap();
        assert_eq!(claim.inputs()[2].source_id(), long_id);
    }

    #[test]
    fn existing_hypothesis_families_project_without_evidence_fields() {
        let mut right = packet();
        right.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right.record_id = format!("{}:frame:1", right.capture_id);
        let packet_projection = assess_packet_same_event_v0(&packet(), &right)
            .unwrap()
            .project_finite_hypotheses_v0()
            .unwrap();

        let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
        let counter = TrafficWindowEvidenceV0::declared_complete("counter:projection:0", window);
        let capture = TrafficWindowEvidenceV0::declared_complete("capture:projection:0", window);
        let profile = CounterCaptureProfileV0::new(
            "profile:projection:0",
            CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
            0,
            1,
        )
        .unwrap();
        let counter_projection = assess_counter_capture_v0(&counter, &capture, &profile)
            .unwrap()
            .project_finite_hypotheses_v0()
            .unwrap();

        let left = unsupported_candidate('a');
        let right = unsupported_candidate('b');
        let fingerprint_projection = assess_saved_pcap_fingerprint_v0(&left, &right)
            .unwrap()
            .project_finite_hypotheses_v0()
            .unwrap();

        assert_eq!(
            packet_projection.family_schema(),
            "netmon.packet_same_event_hypothesis_set.v0"
        );
        assert_eq!(
            counter_projection.alternatives()[0].role(),
            "capture_accounts_for_window"
        );
        assert_eq!(
            fingerprint_projection.alternatives()[0].role(),
            "same_packet_shape"
        );
        for projection in [
            packet_projection,
            counter_projection,
            fingerprint_projection,
        ] {
            assert_eq!(projection.schema(), FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0);
            assert_eq!(projection.alternatives().len(), 3);
            let document = serde_json::to_value(projection).unwrap();
            let object = document.as_object().unwrap();
            assert_eq!(object.len(), 4);
            assert!(object.contains_key("schema"));
            assert!(object.contains_key("family_schema"));
            assert!(object.contains_key("reducer"));
            assert!(object.contains_key("alternatives"));
        }
    }

    #[test]
    fn malformed_public_family_assessments_fail_closed() {
        let mut right = packet();
        right.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right.record_id = format!("{}:frame:1", right.capture_id);
        let mut assessment = assess_packet_same_event_v0(&packet(), &right).unwrap();
        assessment.limitations.clear();

        let error = assessment.project_finite_hypotheses_v0().unwrap_err();
        assert_eq!(
            error,
            FiniteHypothesisProjectionErrorV0::InvalidPacketSameEventAssessment(
                PacketSameEventValidationErrorV0::UnexpectedLimitations
            )
        );
        assert_eq!(
            std::error::Error::source(&error)
                .and_then(|source| source.downcast_ref::<PacketSameEventValidationErrorV0>()),
            Some(&PacketSameEventValidationErrorV0::UnexpectedLimitations)
        );
        assert!(matches!(
            assessment.project_finite_hypothesis_claim_v0((&packet(), &right)),
            Err(
                FiniteHypothesisClaimErrorV0::InvalidPacketSameEventResolution(
                    PacketSameEventErrorV0::InternalInvariant(
                        PacketSameEventValidationErrorV0::UnexpectedLimitations
                    )
                )
            )
        ));

        let window = TrafficWindowV0::new(1_000, 1_200, 400, 12, 4).unwrap();
        let counter = TrafficWindowEvidenceV0::declared_complete("counter:projection:0", window);
        let capture = TrafficWindowEvidenceV0::declared_complete("capture:projection:0", window);
        let profile = CounterCaptureProfileV0::new(
            "profile:projection:0",
            CounterCaptureScaleVectorPpbV0::from_values([50_000_000; 10]),
            0,
            1,
        )
        .unwrap();
        let mut assessment = assess_counter_capture_v0(&counter, &capture, &profile).unwrap();
        assessment.schema = "netbraid.invalid.v0".into();
        assert_eq!(
            assessment.project_finite_hypotheses_v0(),
            Err(
                FiniteHypothesisProjectionErrorV0::InvalidCounterCaptureAssessment(
                    CounterCaptureValidationErrorV0::UnsupportedSchema
                )
            )
        );

        let left = unsupported_candidate('a');
        let right = unsupported_candidate('b');
        let mut assessment = assess_saved_pcap_fingerprint_v0(&left, &right).unwrap();
        assessment.reducer = "netbraid.invalid.v0".into();
        assert_eq!(
            assessment.project_finite_hypotheses_v0(),
            Err(
                FiniteHypothesisProjectionErrorV0::InvalidSavedPcapFingerprintAssessment(
                    SavedPcapFingerprintValidationErrorV0::UnsupportedReducer
                )
            )
        );

        assert!(
            std::error::Error::source(&FiniteHypothesisProjectionErrorV0::InvalidFamilySchema)
                .is_none()
        );
    }
}
