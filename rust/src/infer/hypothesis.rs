use serde::Serialize;

use crate::infer::{
    CounterCaptureDispositionV0, CounterCaptureHypothesisSetV0, PacketSameEventDispositionV0,
    PacketSameEventHypothesisSetV0, SavedPcapFingerprintDispositionV0,
    SavedPcapFingerprintHypothesisSetV0,
};

pub const FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0: &str = "netbraid.finite_hypothesis_projection.v0";

const UNKNOWN_ROLE: &str = "unknown";
const MAX_ALTERNATIVES: usize = 64;
const MAX_IDENTIFIER_LEN: usize = 128;
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
#[serde(deny_unknown_fields)]
pub struct FiniteHypothesisAlternativeV0 {
    role: String,
    disposition: FiniteHypothesisDispositionV0,
}

impl FiniteHypothesisAlternativeV0 {
    /// Parse one stable snake-case role label.
    pub fn try_new(
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
/// limitations, scores, probabilities, rankings, and identity claims. Call the
/// source family's validator when those semantics must also be checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
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
    pub fn try_new(
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

/// Failure to construct a bounded, coherent finite projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FiniteHypothesisProjectionErrorV0 {
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
        formatter.write_str(match self {
            Self::InvalidFamilySchema => "invalid finite-hypothesis family schema",
            Self::InvalidReducer => "invalid finite-hypothesis reducer",
            Self::InvalidAlternativeRole => "invalid finite-hypothesis alternative role",
            Self::InvalidAlternativeCount => "invalid finite-hypothesis alternative count",
            Self::DuplicateAlternativeRole => "duplicate finite-hypothesis alternative role",
            Self::MissingUnknownAlternative => {
                "finite-hypothesis projection has no unknown alternative"
            }
            Self::IncoherentDisposition => "finite-hypothesis dispositions are incoherent",
        })
    }
}

impl std::error::Error for FiniteHypothesisProjectionErrorV0 {}

/// Project a family assessment without merging its evidence semantics.
pub trait ProjectFiniteHypothesesV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0>;
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

impl ProjectFiniteHypothesesV0 for PacketSameEventHypothesisSetV0 {
    fn project_finite_hypotheses_v0(
        &self,
    ) -> Result<FiniteHypothesisProjectionV0, FiniteHypothesisProjectionErrorV0> {
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
    fn malformed_public_family_dispositions_fail_closed() {
        let mut right = packet();
        right.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right.record_id = format!("{}:frame:1", right.capture_id);
        let mut assessment = assess_packet_same_event_v0(&packet(), &right).unwrap();
        assessment.same_event = PacketSameEventDispositionV0::Supported;

        assert_eq!(
            assessment.project_finite_hypotheses_v0(),
            Err(FiniteHypothesisProjectionErrorV0::IncoherentDisposition)
        );
    }
}
