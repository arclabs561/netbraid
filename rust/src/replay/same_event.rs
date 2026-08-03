use crate::evidence::{CaptureValidationError, PacketEnvelopeV0};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0: &str =
    "netmon.packet_same_event_hypothesis_set.v0";
pub const PACKET_SAME_EVENT_REDUCER_V0: &str = "netbraid.packet_same_event.structural.v0";

const LIMITATIONS: &[&str] = &[
    "matching packet structure is non-discriminating and never supports same_event",
    "source and sequence addresses, timestamps, frame numbers, capture lengths, protocols, radio metadata, SSID, RSSI, and paths are excluded from the comparative decision basis",
    "evidence references and envelope digests are audit-only, bind cited content, and do not authenticate its source",
    "capture identity does not establish observer identity",
    "no transitive join, durable device identity, track, person, place, presence, or confidence score",
];

/// Disposition of one retained alternative in the structural v0 reducer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PacketSameEventDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

/// Structural dimensions admitted by the v0 decision basis.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PacketSameEventDimensionV0 {
    Ieee80211FrameType,
    Ieee80211FrameSubtype,
}

/// One observed conflict between the canonically ordered packet envelopes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct PacketSameEventDifferenceV0 {
    pub dimension: PacketSameEventDimensionV0,
    pub left_value: u64,
    pub right_value: u64,
}

/// Content-bound reference to one packet envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct PacketSameEventEvidenceRefV0 {
    pub capture_id: String,
    pub record_id: String,
    pub envelope_sha256: String,
}

/// Auditable feature comparison used by the structural reducer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct PacketSameEventBasisV0 {
    pub compared_dimensions: Vec<PacketSameEventDimensionV0>,
    pub compatible_dimensions: Vec<PacketSameEventDimensionV0>,
    pub conflicting_dimensions: Vec<PacketSameEventDifferenceV0>,
    pub missing_dimensions: Vec<PacketSameEventDimensionV0>,
}

/// Why the structural reducer must select the explicit unknown alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum PacketSameEventUnknownReasonV0 {
    SameCapture,
    TruncatedPacketEvidence,
    MissingIeee80211Evidence,
    NoDiscriminatingStructuralConflict,
}

/// Deterministic reference answer while all three alternatives remain present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "hypothesis", rename_all = "snake_case")]
pub enum PacketSameEventReferenceV0 {
    DifferentEvent,
    Unknown {
        reason: PacketSameEventUnknownReasonV0,
    },
}

/// A fixed, source-preserving same-event hypothesis set for two packet records.
///
/// Version 0 can support `different_event` from observed structural conflicts,
/// but matching structure remains underdetermined. It has no rule that can
/// select or support `same_event`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct PacketSameEventHypothesisSetV0 {
    pub schema: String,
    pub reducer: String,
    pub left: PacketSameEventEvidenceRefV0,
    pub right: PacketSameEventEvidenceRefV0,
    pub basis: PacketSameEventBasisV0,
    pub same_event: PacketSameEventDispositionV0,
    pub different_event: PacketSameEventDispositionV0,
    pub unknown: PacketSameEventDispositionV0,
    pub reference: PacketSameEventReferenceV0,
    pub limitations: Vec<String>,
}

/// Semantic failure in a deserialized or internally constructed hypothesis set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketSameEventValidationErrorV0 {
    UnsupportedSchema,
    UnsupportedReducer,
    InvalidEvidenceReference,
    NonCanonicalEvidenceOrder,
    InvalidBasis,
    IncoherentDisposition,
    UnexpectedLimitations,
    ResolvedContentMismatch,
}

impl std::fmt::Display for PacketSameEventValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported packet same-event schema",
            Self::UnsupportedReducer => "unsupported packet same-event reducer",
            Self::InvalidEvidenceReference => "invalid packet same-event evidence reference",
            Self::NonCanonicalEvidenceOrder => {
                "packet evidence references are not canonically ordered"
            }
            Self::InvalidBasis => "packet same-event decision basis is incoherent",
            Self::IncoherentDisposition => {
                "packet same-event dispositions contradict the reference"
            }
            Self::UnexpectedLimitations => {
                "packet same-event limitations differ from the v0 contract"
            }
            Self::ResolvedContentMismatch => {
                "packet same-event assessment differs from the resolved packet evidence"
            }
        })
    }
}

impl std::error::Error for PacketSameEventValidationErrorV0 {}

impl PacketSameEventHypothesisSetV0 {
    /// Validate the serialized assessment's semantic invariants.
    ///
    /// This cannot bind content references to evidence that is not supplied.
    /// Use [`Self::validate_against`] when the cited packets are available.
    pub fn validate(&self) -> Result<(), PacketSameEventValidationErrorV0> {
        if self.schema != PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0 {
            return Err(PacketSameEventValidationErrorV0::UnsupportedSchema);
        }
        if self.reducer != PACKET_SAME_EVENT_REDUCER_V0 {
            return Err(PacketSameEventValidationErrorV0::UnsupportedReducer);
        }
        if !valid_evidence_reference(&self.left) || !valid_evidence_reference(&self.right) {
            return Err(PacketSameEventValidationErrorV0::InvalidEvidenceReference);
        }
        if evidence_order(&self.left) > evidence_order(&self.right) {
            return Err(PacketSameEventValidationErrorV0::NonCanonicalEvidenceOrder);
        }
        if self
            .limitations
            .iter()
            .map(String::as_str)
            .ne(LIMITATIONS.iter().copied())
        {
            return Err(PacketSameEventValidationErrorV0::UnexpectedLimitations);
        }

        let empty_basis = self.basis.compared_dimensions.is_empty()
            && self.basis.compatible_dimensions.is_empty()
            && self.basis.conflicting_dimensions.is_empty()
            && self.basis.missing_dimensions.is_empty();
        let compared_basis = self.basis.compared_dimensions
            == [
                PacketSameEventDimensionV0::Ieee80211FrameType,
                PacketSameEventDimensionV0::Ieee80211FrameSubtype,
            ]
            && self.basis.missing_dimensions.is_empty()
            && basis_partition_is_valid(&self.basis);
        if !empty_basis && !compared_basis {
            return Err(PacketSameEventValidationErrorV0::InvalidBasis);
        }

        let dispositions_valid = match self.reference {
            PacketSameEventReferenceV0::DifferentEvent => {
                compared_basis
                    && !self.basis.conflicting_dimensions.is_empty()
                    && self.same_event == PacketSameEventDispositionV0::Contradicted
                    && self.different_event == PacketSameEventDispositionV0::Supported
                    && self.unknown == PacketSameEventDispositionV0::Contradicted
            }
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::NoDiscriminatingStructuralConflict,
            } => {
                compared_basis
                    && self.basis.conflicting_dimensions.is_empty()
                    && self.same_event == PacketSameEventDispositionV0::Underdetermined
                    && self.different_event == PacketSameEventDispositionV0::Underdetermined
                    && self.unknown == PacketSameEventDispositionV0::Supported
            }
            PacketSameEventReferenceV0::Unknown { .. } => {
                empty_basis
                    && self.same_event == PacketSameEventDispositionV0::Underdetermined
                    && self.different_event == PacketSameEventDispositionV0::Underdetermined
                    && self.unknown == PacketSameEventDispositionV0::Supported
            }
        };
        if !dispositions_valid {
            return Err(PacketSameEventValidationErrorV0::IncoherentDisposition);
        }
        Ok(())
    }

    /// Resolve content references and recompute the complete assessment.
    pub fn validate_against(
        &self,
        left: &PacketEnvelopeV0,
        right: &PacketEnvelopeV0,
    ) -> Result<(), PacketSameEventErrorV0> {
        self.validate()
            .map_err(PacketSameEventErrorV0::InternalInvariant)?;
        let expected = assess_packet_same_event_v0(left, right)?;
        if self != &expected {
            return Err(PacketSameEventErrorV0::InternalInvariant(
                PacketSameEventValidationErrorV0::ResolvedContentMismatch,
            ));
        }
        Ok(())
    }
}

/// Failure to validate or content-bind one input envelope.
#[derive(Debug)]
#[non_exhaustive]
pub enum PacketSameEventErrorV0 {
    LeftInvalid(CaptureValidationError),
    RightInvalid(CaptureValidationError),
    EnvelopeSerialization(serde_json::Error),
    InternalInvariant(PacketSameEventValidationErrorV0),
}

impl std::fmt::Display for PacketSameEventErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LeftInvalid(source) => write!(formatter, "invalid left packet: {source}"),
            Self::RightInvalid(source) => write!(formatter, "invalid right packet: {source}"),
            Self::EnvelopeSerialization(source) => {
                write!(formatter, "serialize packet evidence: {source}")
            }
            Self::InternalInvariant(source) => write!(formatter, "validate assessment: {source}"),
        }
    }
}

impl std::error::Error for PacketSameEventErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::LeftInvalid(source) | Self::RightInvalid(source) => Some(source),
            Self::EnvelopeSerialization(source) => Some(source),
            Self::InternalInvariant(source) => Some(source),
        }
    }
}

/// Assess whether two packet envelopes can represent the same transmission.
///
/// Inputs are validated and then canonically ordered. Only IEEE 802.11 frame
/// type/subtype participate in the decision. Capture lengths are used only to
/// reject truncated evidence,
/// because capture encapsulation can differ by observer. The reducer is
/// intentionally asymmetric: a conflict can support `different_event`, while
/// a match can only support `unknown`. Successful assessments are canonical
/// under input swapping; validation errors remain positional so callers can
/// identify which argument failed.
pub fn assess_packet_same_event_v0(
    left: &PacketEnvelopeV0,
    right: &PacketEnvelopeV0,
) -> Result<PacketSameEventHypothesisSetV0, PacketSameEventErrorV0> {
    left.validate()
        .map_err(PacketSameEventErrorV0::LeftInvalid)?;
    right
        .validate()
        .map_err(PacketSameEventErrorV0::RightInvalid)?;

    let mut inputs = [bound_packet(left)?, bound_packet(right)?];
    inputs.sort_by(|(left_ref, _), (right_ref, _)| {
        (
            &left_ref.capture_id,
            &left_ref.record_id,
            &left_ref.envelope_sha256,
        )
            .cmp(&(
                &right_ref.capture_id,
                &right_ref.record_id,
                &right_ref.envelope_sha256,
            ))
    });
    let [(left_ref, left), (right_ref, right)] = inputs;

    let mut basis = PacketSameEventBasisV0 {
        compared_dimensions: Vec::new(),
        compatible_dimensions: Vec::new(),
        conflicting_dimensions: Vec::new(),
        missing_dimensions: Vec::new(),
    };

    let ineligible = if left.capture_id == right.capture_id {
        Some(PacketSameEventUnknownReasonV0::SameCapture)
    } else if left.frame.captured_len != left.frame.original_len
        || right.frame.captured_len != right.frame.original_len
    {
        Some(PacketSameEventUnknownReasonV0::TruncatedPacketEvidence)
    } else if let (Some(left_wlan), Some(right_wlan)) =
        (left.ieee80211.as_ref(), right.ieee80211.as_ref())
    {
        compare_required(
            &mut basis,
            PacketSameEventDimensionV0::Ieee80211FrameType,
            u64::from(left_wlan.frame_type),
            u64::from(right_wlan.frame_type),
        );
        compare_required(
            &mut basis,
            PacketSameEventDimensionV0::Ieee80211FrameSubtype,
            u64::from(left_wlan.frame_subtype),
            u64::from(right_wlan.frame_subtype),
        );
        None
    } else {
        Some(PacketSameEventUnknownReasonV0::MissingIeee80211Evidence)
    };

    let has_conflict = !basis.conflicting_dimensions.is_empty();
    let (same_event, different_event, unknown, reference) = match (ineligible, has_conflict) {
        (Some(reason), _) => (
            PacketSameEventDispositionV0::Underdetermined,
            PacketSameEventDispositionV0::Underdetermined,
            PacketSameEventDispositionV0::Supported,
            PacketSameEventReferenceV0::Unknown { reason },
        ),
        (None, true) => (
            PacketSameEventDispositionV0::Contradicted,
            PacketSameEventDispositionV0::Supported,
            PacketSameEventDispositionV0::Contradicted,
            PacketSameEventReferenceV0::DifferentEvent,
        ),
        (None, false) => (
            PacketSameEventDispositionV0::Underdetermined,
            PacketSameEventDispositionV0::Underdetermined,
            PacketSameEventDispositionV0::Supported,
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::NoDiscriminatingStructuralConflict,
            },
        ),
    };

    let assessment = PacketSameEventHypothesisSetV0 {
        schema: PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0.to_owned(),
        reducer: PACKET_SAME_EVENT_REDUCER_V0.to_owned(),
        left: left_ref,
        right: right_ref,
        basis,
        same_event,
        different_event,
        unknown,
        reference,
        limitations: LIMITATIONS
            .iter()
            .map(|limitation| (*limitation).to_owned())
            .collect(),
    };
    assessment
        .validate()
        .map_err(PacketSameEventErrorV0::InternalInvariant)?;
    Ok(assessment)
}

fn bound_packet(
    packet: &PacketEnvelopeV0,
) -> Result<(PacketSameEventEvidenceRefV0, &PacketEnvelopeV0), PacketSameEventErrorV0> {
    let encoded =
        serde_json::to_vec(packet).map_err(PacketSameEventErrorV0::EnvelopeSerialization)?;
    let reference = PacketSameEventEvidenceRefV0 {
        capture_id: packet.capture_id.clone(),
        record_id: packet.record_id.clone(),
        envelope_sha256: format!("{:x}", Sha256::digest(encoded)),
    };
    Ok((reference, packet))
}

fn compare_required(
    basis: &mut PacketSameEventBasisV0,
    dimension: PacketSameEventDimensionV0,
    left: u64,
    right: u64,
) {
    basis.compared_dimensions.push(dimension);
    if left == right {
        basis.compatible_dimensions.push(dimension);
    } else {
        basis
            .conflicting_dimensions
            .push(PacketSameEventDifferenceV0 {
                dimension,
                left_value: left,
                right_value: right,
            });
    }
}

fn evidence_order(reference: &PacketSameEventEvidenceRefV0) -> (&str, &str, &str) {
    (
        &reference.capture_id,
        &reference.record_id,
        &reference.envelope_sha256,
    )
}

fn valid_evidence_reference(reference: &PacketSameEventEvidenceRefV0) -> bool {
    let frame_number = reference
        .record_id
        .strip_prefix(&reference.capture_id)
        .and_then(|suffix| suffix.strip_prefix(":frame:"))
        .and_then(|number| number.parse::<u64>().ok());
    reference.capture_id.starts_with("sha256:")
        && reference.capture_id.len() == 71
        && reference
            .capture_id
            .as_bytes()
            .get(7..)
            .is_some_and(|value| value.iter().all(is_lower_hex_digit))
        && frame_number.is_some_and(|number| {
            number > 0 && reference.record_id == format!("{}:frame:{number}", reference.capture_id)
        })
        && reference.envelope_sha256.len() == 64
        && reference
            .envelope_sha256
            .as_bytes()
            .iter()
            .all(is_lower_hex_digit)
}

fn is_lower_hex_digit(byte: &u8) -> bool {
    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
}

fn basis_partition_is_valid(basis: &PacketSameEventBasisV0) -> bool {
    basis.compared_dimensions.iter().all(|dimension| {
        let compatible_count = basis
            .compatible_dimensions
            .iter()
            .filter(|candidate| *candidate == dimension)
            .count();
        let conflict_count = basis
            .conflicting_dimensions
            .iter()
            .filter(|difference| difference.dimension == *dimension)
            .count();
        compatible_count + conflict_count == 1
    }) && basis
        .compatible_dimensions
        .iter()
        .all(|dimension| basis.compared_dimensions.contains(dimension))
        && basis.conflicting_dimensions.iter().all(|difference| {
            basis.compared_dimensions.contains(&difference.dimension)
                && difference.left_value != difference.right_value
                && valid_dimension_value(difference.dimension, difference.left_value)
                && valid_dimension_value(difference.dimension, difference.right_value)
        })
}

fn valid_dimension_value(dimension: PacketSameEventDimensionV0, value: u64) -> bool {
    match dimension {
        PacketSameEventDimensionV0::Ieee80211FrameType => value <= 3,
        PacketSameEventDimensionV0::Ieee80211FrameSubtype => value <= 15,
    }
}

#[cfg(test)]
mod tests {
    use crate::evidence::{
        Ieee80211FieldsV0, PacketFrameV0, WlanRadioFieldsV0, PACKET_ENVELOPE_SCHEMA_V0,
    };
    use proptest::prelude::*;

    use super::*;

    const CAPTURE_A: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const CAPTURE_B: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn packet(capture_id: &str, frame_number: u64) -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.to_owned(),
            record_id: format!("{capture_id}:frame:{frame_number}"),
            capture_id: capture_id.to_owned(),
            frame: PacketFrameV0 {
                number: frame_number,
                event_time_unix_ns: 1_000,
                original_len: 65,
                captured_len: 65,
                section_number: None,
                interface_id: None,
                encapsulation_type: None,
                protocols: vec!["radiotap".into(), "wlan".into()],
            },
            ethernet: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            ieee802154: None,
            ieee80211: Some(Ieee80211FieldsV0 {
                frame_type: 0,
                frame_subtype: 8,
                transmitter: None,
                receiver: None,
                source: None,
                destination: None,
                bssid: None,
                ssid_hex: None,
            }),
            wlan_radio: Some(WlanRadioFieldsV0 {
                channel: Some(1),
                center_frequency_mhz: Some(2_412),
                signal_dbm: Some(-40),
            }),
        }
    }

    #[test]
    fn matching_structure_abstains() {
        let result = assess_packet_same_event_v0(&packet(CAPTURE_A, 1), &packet(CAPTURE_B, 1))
            .expect("valid assessment");

        assert_eq!(
            result.reference,
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::NoDiscriminatingStructuralConflict,
            }
        );
        assert_eq!(
            result.same_event,
            PacketSameEventDispositionV0::Underdetermined
        );
        assert_eq!(
            result.different_event,
            PacketSameEventDispositionV0::Underdetermined
        );
        assert_eq!(result.unknown, PacketSameEventDispositionV0::Supported);
        assert_eq!(result.basis.compared_dimensions.len(), 2);
        assert!(result.basis.conflicting_dimensions.is_empty());
    }

    #[test]
    fn observed_structural_conflict_supports_different_event() {
        let left = packet(CAPTURE_A, 1);
        let mut right = packet(CAPTURE_B, 1);
        right.frame.original_len = 66;
        right.frame.captured_len = 66;
        right.ieee80211.as_mut().unwrap().frame_subtype = 4;

        let result = assess_packet_same_event_v0(&left, &right).expect("valid assessment");

        assert_eq!(result.reference, PacketSameEventReferenceV0::DifferentEvent);
        assert_eq!(
            result.same_event,
            PacketSameEventDispositionV0::Contradicted
        );
        assert_eq!(
            result.different_event,
            PacketSameEventDispositionV0::Supported
        );
        assert_eq!(result.basis.conflicting_dimensions.len(), 1);
    }

    #[test]
    fn radio_metadata_is_audit_only() {
        let left = packet(CAPTURE_A, 1);
        let mut right = packet(CAPTURE_B, 1);
        let baseline = assess_packet_same_event_v0(&left, &right).unwrap();
        right.wlan_radio.as_mut().unwrap().channel = Some(6);
        right.wlan_radio.as_mut().unwrap().center_frequency_mhz = Some(2_437);

        let result = assess_packet_same_event_v0(&left, &right).expect("valid assessment");

        assert_eq!(result.basis, baseline.basis);
        assert_eq!(result.reference, baseline.reference);
        assert_ne!(result.right.envelope_sha256, baseline.right.envelope_sha256);
    }

    #[test]
    fn ineligible_inputs_abstain() {
        let left = packet(CAPTURE_A, 1);
        let mut truncated = packet(CAPTURE_B, 1);
        truncated.frame.captured_len = 64;
        assert_eq!(
            assess_packet_same_event_v0(&left, &truncated)
                .unwrap()
                .reference,
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::TruncatedPacketEvidence,
            }
        );

        let mut same_capture = packet(CAPTURE_A, 2);
        same_capture.frame.event_time_unix_ns = 2_000;
        assert_eq!(
            assess_packet_same_event_v0(&left, &same_capture)
                .unwrap()
                .reference,
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::SameCapture,
            }
        );

        let mut non_wlan = packet(CAPTURE_B, 1);
        non_wlan.ieee80211 = None;
        non_wlan.wlan_radio = None;
        assert_eq!(
            assess_packet_same_event_v0(&left, &non_wlan)
                .unwrap()
                .reference,
            PacketSameEventReferenceV0::Unknown {
                reason: PacketSameEventUnknownReasonV0::MissingIeee80211Evidence,
            }
        );
    }

    #[test]
    fn invalid_input_is_rejected() {
        let mut left = packet(CAPTURE_A, 1);
        left.frame.number = 0;
        assert!(matches!(
            assess_packet_same_event_v0(&left, &packet(CAPTURE_B, 1)),
            Err(PacketSameEventErrorV0::LeftInvalid(_))
        ));
    }

    #[test]
    fn swapping_inputs_is_byte_invariant() {
        let left = packet(CAPTURE_A, 1);
        let mut right = packet(CAPTURE_B, 1);
        right.wlan_radio.as_mut().unwrap().channel = Some(6);

        let forward = assess_packet_same_event_v0(&left, &right).unwrap();
        let reverse = assess_packet_same_event_v0(&right, &left).unwrap();

        assert_eq!(forward, reverse);
        assert_eq!(
            serde_json::to_vec(&forward).unwrap(),
            serde_json::to_vec(&reverse).unwrap()
        );
    }

    #[test]
    fn resolved_validation_accepts_original_and_swapped_inputs() {
        let left = packet(CAPTURE_A, 1);
        let right = packet(CAPTURE_B, 1);
        let assessment = assess_packet_same_event_v0(&left, &right).unwrap();

        assessment.validate_against(&left, &right).unwrap();
        assessment.validate_against(&right, &left).unwrap();
    }

    #[test]
    fn resolved_validation_rejects_substituted_reference_and_packet_content() {
        let left = packet(CAPTURE_A, 1);
        let right = packet(CAPTURE_B, 1);
        let assessment = assess_packet_same_event_v0(&left, &right).unwrap();

        let replacement = assess_packet_same_event_v0(&packet(CAPTURE_A, 2), &right).unwrap();
        let mut substituted_reference = assessment.clone();
        substituted_reference.left = replacement.left;
        substituted_reference.validate().unwrap();
        assert!(matches!(
            substituted_reference.validate_against(&left, &right),
            Err(PacketSameEventErrorV0::InternalInvariant(
                PacketSameEventValidationErrorV0::ResolvedContentMismatch
            ))
        ));

        let mut mutated_right = right.clone();
        mutated_right.wlan_radio.as_mut().unwrap().channel = Some(6);
        assert!(matches!(
            assessment.validate_against(&left, &mutated_right),
            Err(PacketSameEventErrorV0::InternalInvariant(
                PacketSameEventValidationErrorV0::ResolvedContentMismatch
            ))
        ));
    }

    #[test]
    fn resolved_validation_preserves_positional_input_errors() {
        let left = packet(CAPTURE_A, 1);
        let right = packet(CAPTURE_B, 1);
        let assessment = assess_packet_same_event_v0(&left, &right).unwrap();

        let mut malformed_left = left.clone();
        malformed_left.frame.number = 0;
        assert!(matches!(
            assessment.validate_against(&malformed_left, &right),
            Err(PacketSameEventErrorV0::LeftInvalid(_))
        ));

        let mut malformed_right = right.clone();
        malformed_right.frame.number = 0;
        assert!(matches!(
            assessment.validate_against(&left, &malformed_right),
            Err(PacketSameEventErrorV0::RightInvalid(_))
        ));
    }

    #[test]
    fn prohibited_fields_do_not_change_the_decision_basis() {
        let left = packet(CAPTURE_A, 1);
        let right = packet(CAPTURE_B, 1);
        let baseline = assess_packet_same_event_v0(&left, &right).unwrap();

        let mut changed = right.clone();
        changed.frame.number = 7;
        changed.record_id = format!("{}:frame:7", changed.capture_id);
        changed.frame.event_time_unix_ns = 999_000;
        changed.frame.protocols = vec!["different".into()];
        changed.wlan_radio.as_mut().unwrap().signal_dbm = Some(-90);
        changed.ieee80211.as_mut().unwrap().transmitter = Some("02:00:00:00:00:01".into());
        changed.ieee80211.as_mut().unwrap().ssid_hex = Some("6c6162".into());
        let mutated = assess_packet_same_event_v0(&left, &changed).unwrap();

        assert_eq!(baseline.basis, mutated.basis);
        assert_eq!(baseline.same_event, mutated.same_event);
        assert_eq!(baseline.different_event, mutated.different_event);
        assert_eq!(baseline.unknown, mutated.unknown);
        assert_eq!(baseline.reference, mutated.reference);
        assert_ne!(
            baseline.right.envelope_sha256,
            mutated.right.envelope_sha256
        );
    }

    #[test]
    fn serialized_shape_round_trips_and_rejects_unknown_fields() {
        let assessment =
            assess_packet_same_event_v0(&packet(CAPTURE_A, 1), &packet(CAPTURE_B, 1)).unwrap();
        let encoded = serde_json::to_value(&assessment).unwrap();
        assert_eq!(
            serde_json::from_value::<PacketSameEventHypothesisSetV0>(encoded.clone()).unwrap(),
            assessment
        );
        serde_json::from_value::<PacketSameEventHypothesisSetV0>(encoded.clone())
            .unwrap()
            .validate()
            .unwrap();

        let mut with_unknown = encoded.clone();
        with_unknown
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<PacketSameEventHypothesisSetV0>(with_unknown).is_err());

        let mut incoherent = encoded;
        incoherent["same_event"] = serde_json::Value::String("supported".into());
        assert_eq!(
            serde_json::from_value::<PacketSameEventHypothesisSetV0>(incoherent)
                .unwrap()
                .validate(),
            Err(PacketSameEventValidationErrorV0::IncoherentDisposition)
        );

        let mut invalid_reference = serde_json::to_value(&assessment).unwrap();
        invalid_reference["left"]["envelope_sha256"] = serde_json::Value::String("A".repeat(64));
        assert_eq!(
            serde_json::from_value::<PacketSameEventHypothesisSetV0>(invalid_reference)
                .unwrap()
                .validate(),
            Err(PacketSameEventValidationErrorV0::InvalidEvidenceReference)
        );

        let mut noncanonical_record = assessment.clone();
        noncanonical_record.left.record_id =
            format!("{}:frame:01", noncanonical_record.left.capture_id);
        assert_eq!(
            noncanonical_record.validate(),
            Err(PacketSameEventValidationErrorV0::InvalidEvidenceReference)
        );

        let mut conflicting_packet = packet(CAPTURE_B, 1);
        conflicting_packet.ieee80211.as_mut().unwrap().frame_subtype = 4;
        let mut invalid_basis =
            assess_packet_same_event_v0(&packet(CAPTURE_A, 1), &conflicting_packet).unwrap();
        invalid_basis.basis.conflicting_dimensions[0].right_value = 999;
        assert_eq!(
            invalid_basis.validate(),
            Err(PacketSameEventValidationErrorV0::InvalidBasis)
        );
    }

    proptest! {
        #[test]
        fn v0_never_supports_same_event(
            left_len in 1u32..=65_535,
            right_len in 1u32..=65_535,
            left_type in 0u8..=3,
            right_type in 0u8..=3,
            left_subtype in 0u8..=15,
            right_subtype in 0u8..=15,
            left_channel in 1u32..=255,
            right_channel in 1u32..=255,
        ) {
            let mut left = packet(CAPTURE_A, 1);
            left.frame.original_len = left_len;
            left.frame.captured_len = left_len;
            left.ieee80211.as_mut().unwrap().frame_type = left_type;
            left.ieee80211.as_mut().unwrap().frame_subtype = left_subtype;
            left.wlan_radio.as_mut().unwrap().channel = Some(left_channel);

            let mut right = packet(CAPTURE_B, 1);
            right.frame.original_len = right_len;
            right.frame.captured_len = right_len;
            right.ieee80211.as_mut().unwrap().frame_type = right_type;
            right.ieee80211.as_mut().unwrap().frame_subtype = right_subtype;
            right.wlan_radio.as_mut().unwrap().channel = Some(right_channel);

            let result = assess_packet_same_event_v0(&left, &right).unwrap();
            prop_assert_ne!(result.same_event, PacketSameEventDispositionV0::Supported);
            let unknown_selected = matches!(
                result.reference,
                PacketSameEventReferenceV0::Unknown { .. }
            );
            prop_assert!(
                !unknown_selected || result.unknown == PacketSameEventDispositionV0::Supported
            );
        }
    }
}
