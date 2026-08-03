use crate::evidence::CaptureExtractorRefV0;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::replay::{
    SavedPcapClaimScopeV0, SavedPcapConversationAggregationV0, SavedPcapConversationDirectionV0,
    SavedPcapConversationExclusionCountV0, SavedPcapConversationTriageV0,
    SavedPcapNormalizationTriageV0, SavedPcapObservationPointV0, SavedPcapTemporalRelevanceV0,
    SavedPcapTopConversationV0, SavedPcapTransportProtocolV0, SavedPcapTriageV1,
    SavedPcapWlanTriageV0,
};

pub const SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0: &str =
    "netmon.saved_pcap_fingerprint_candidate.v0";
pub const SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0: &str =
    "netmon.saved_pcap_fingerprint_hypothesis_set.v0";
pub const SAVED_PCAP_FINGERPRINT_REDUCER_V0: &str =
    "netbraid.saved_pcap_fingerprint.packet_shape.v0";

const FINGERPRINT_CANDIDATE_REF_DOMAIN_V0: &str =
    "netbraid.saved_pcap_fingerprint.candidate_ref.v0";

const FINGERPRINT_HYPOTHESIS_LIMITATIONS: &[&str] = &[
    "same_packet_shape and different_packet_shape describe only the v0 fingerprint comparison",
    "packet-shape agreement or disagreement does not establish the same or a different event, capture, device, source, variant, identity, or intent",
    "candidate references bind complete serialized candidates for audit but do not authenticate provenance or establish source or artifact integrity",
    "the lower comparison covers capture-wide eligible normalized packet-envelope aggregates and is not sessionized",
    "not-comparable candidates select unknown and are neither packet-shape agreement nor disagreement",
];

const FINGERPRINT_CAVEATS: &[&str] = &[
    "capture-wide aggregate over eligible normalized packet envelopes; not sessionized",
    "endpoint addresses and ports are excluded from the comparison digest",
    "no cross-observer join or device, person, place, or intent identity",
    "missing radiotap, CSI, and BLE evidence remains outside this packet-shape candidate",
];

const FINGERPRINT_FEATURE_NAMES: &[&str] = &[
    "normalization.state",
    "normalization.completeness",
    "normalization.packet_rows_emitted",
    "normalization.packet_rows_quarantined",
    "normalization.packet_rows_inspected",
    "normalization.packet_limit",
    "normalization.packet_limit_reached",
    "normalization.emitted_packet_window",
    "wlan",
    "conversation.aggregation",
    "conversation.temporal_relevance",
    "conversation.transport",
    "conversation.observation_point",
    "conversation.packet_envelopes_seen",
    "conversation.packet_envelopes_grouped",
    "conversation.packet_envelopes_excluded",
    "conversation.exclusions",
    "conversation.total_frames",
    "conversation.total_original_frame_octets",
    "conversation.total_captured_frame_octets",
    "conversation.a_to_b",
    "conversation.b_to_a",
    "conversation.earliest_event_time_unix_ns",
    "conversation.latest_event_time_unix_ns",
    "conversation.observed_span_ns",
];

/// A provenance reference for one packet-shape fingerprint candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintSourceV0 {
    pub capture_id: String,
    pub normalized_records_sha256: String,
    pub extractor: CaptureExtractorRefV0,
}

/// The feature values that participate in an observed candidate's digest.
///
/// Endpoint addresses, ports, and the display-filter suggestion are omitted on
/// purpose. They are useful for operator investigation but are not stable
/// cross-observer fingerprint features.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintBasisV0 {
    pub feature_names: Vec<String>,
    pub normalization: SavedPcapNormalizationTriageV0,
    pub wlan: SavedPcapWlanTriageV0,
    pub conversation: SavedPcapFingerprintConversationV0,
}

/// The endpoint-independent packet-shape portion of a top conversation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintConversationV0 {
    pub aggregation: SavedPcapConversationAggregationV0,
    pub temporal_relevance: SavedPcapTemporalRelevanceV0,
    pub transport: SavedPcapTransportProtocolV0,
    pub observation_point: SavedPcapObservationPointV0,
    pub packet_envelopes_seen: u64,
    pub packet_envelopes_grouped: u64,
    pub packet_envelopes_excluded: u64,
    pub exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    pub total_frames: u64,
    pub total_original_frame_octets: u64,
    pub total_captured_frame_octets: u64,
    pub a_to_b: SavedPcapConversationDirectionV0,
    pub b_to_a: SavedPcapConversationDirectionV0,
    pub earliest_event_time_unix_ns: i64,
    pub latest_event_time_unix_ns: i64,
    pub observed_span_ns: u64,
}

/// Why a packet-shape candidate cannot be promoted to an observed digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintInsufficientReasonV0 {
    PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes,
}

/// Why a packet-shape candidate is outside the supported evidence vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintUnsupportedReasonV0 {
    NoEligibleIpTcpUdpPacketEnvelopes,
}

/// Why two fingerprint candidates cannot be compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintComparisonReasonV0 {
    LeftNotObserved,
    RightNotObserved,
    DifferentSchema,
    DifferentClaimScope,
    DifferentFeatureSet,
    InvalidDigest,
}

/// A conservative comparison of two packet-shape candidates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapFingerprintComparisonV0 {
    Corroborated,
    Conflicting,
    NotComparable {
        reason: SavedPcapFingerprintComparisonReasonV0,
    },
}

/// Disposition of one retained packet-shape alternative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapFingerprintDispositionV0 {
    Supported,
    Contradicted,
    Underdetermined,
}

/// Content-bound reference to one complete fingerprint candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct SavedPcapFingerprintCandidateRefV0 {
    pub candidate_schema: String,
    pub capture_id: String,
    pub normalized_records_sha256: String,
    pub candidate_sha256: String,
}

/// Deterministic selected answer while all three alternatives remain present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(tag = "hypothesis", rename_all = "snake_case", deny_unknown_fields)]
pub enum SavedPcapFingerprintReferenceV0 {
    SamePacketShape,
    DifferentPacketShape,
    Unknown {
        reason: SavedPcapFingerprintComparisonReasonV0,
    },
}

/// A finite packet-shape hypothesis set over two saved-PCAP candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub struct SavedPcapFingerprintHypothesisSetV0 {
    pub schema: String,
    pub reducer: String,
    pub left: SavedPcapFingerprintCandidateRefV0,
    pub right: SavedPcapFingerprintCandidateRefV0,
    pub basis: SavedPcapFingerprintComparisonV0,
    pub same_packet_shape: SavedPcapFingerprintDispositionV0,
    pub different_packet_shape: SavedPcapFingerprintDispositionV0,
    pub unknown: SavedPcapFingerprintDispositionV0,
    pub reference: SavedPcapFingerprintReferenceV0,
    pub limitations: Vec<String>,
}

/// Semantic failure in a deserialized or internally constructed hypothesis set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SavedPcapFingerprintValidationErrorV0 {
    UnsupportedSchema,
    UnsupportedReducer,
    InvalidCandidateReference,
    NonCanonicalCandidateOrder,
    IncoherentBasis,
    IncoherentDisposition,
    UnexpectedLimitations,
    ResolvedContentMismatch,
}

impl std::fmt::Display for SavedPcapFingerprintValidationErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchema => "unsupported saved-PCAP fingerprint hypothesis-set schema",
            Self::UnsupportedReducer => "unsupported saved-PCAP fingerprint reducer",
            Self::InvalidCandidateReference => "invalid saved-PCAP fingerprint candidate reference",
            Self::NonCanonicalCandidateOrder => {
                "saved-PCAP fingerprint candidate references are not canonically ordered"
            }
            Self::IncoherentBasis => {
                "saved-PCAP fingerprint decision basis contradicts the selected reference"
            }
            Self::IncoherentDisposition => {
                "saved-PCAP fingerprint dispositions contradict the selected reference"
            }
            Self::UnexpectedLimitations => {
                "saved-PCAP fingerprint limitations differ from the v0 contract"
            }
            Self::ResolvedContentMismatch => {
                "saved-PCAP fingerprint assessment differs from the resolved candidates"
            }
        })
    }
}

impl std::error::Error for SavedPcapFingerprintValidationErrorV0 {}

/// Failure to content-bind candidates or validate the resulting assessment.
#[derive(Debug)]
#[non_exhaustive]
pub enum SavedPcapFingerprintErrorV0 {
    CandidateSerialization(serde_json::Error),
    InternalInvariant(SavedPcapFingerprintValidationErrorV0),
}

impl std::fmt::Display for SavedPcapFingerprintErrorV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CandidateSerialization(source) => {
                write!(
                    formatter,
                    "serialize saved-PCAP fingerprint candidate: {source}"
                )
            }
            Self::InternalInvariant(source) => {
                write!(
                    formatter,
                    "validate saved-PCAP fingerprint assessment: {source}"
                )
            }
        }
    }
}

impl std::error::Error for SavedPcapFingerprintErrorV0 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CandidateSerialization(source) => Some(source),
            Self::InternalInvariant(source) => Some(source),
        }
    }
}

/// The result of reducing a validated saved-capture triage projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapFingerprintStatusV0 {
    Observed {
        digest: String,
        basis: Box<SavedPcapFingerprintBasisV0>,
        caveats: Vec<String>,
    },
    Insufficient {
        reason: SavedPcapFingerprintInsufficientReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
    Unsupported {
        reason: SavedPcapFingerprintUnsupportedReasonV0,
        packet_envelopes_seen: u64,
        packet_envelopes_excluded: u64,
        exclusions: Vec<SavedPcapConversationExclusionCountV0>,
    },
}

/// An endpoint-independent candidate for later multi-vantage comparison.
///
/// This is derived evidence, not an identity claim. Only the `Observed`
/// variant carries a digest; partial and unsupported inputs remain typed
/// abstentions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapFingerprintCandidateV0 {
    pub schema: String,
    pub source: SavedPcapFingerprintSourceV0,
    pub scope: SavedPcapClaimScopeV0,
    pub status: SavedPcapFingerprintStatusV0,
}

/// Projects one validated triage result into a deterministic packet-shape
/// candidate without reparsing raw capture or JSONL input.
pub fn project_saved_pcap_fingerprint_v0(
    triage: &SavedPcapTriageV1,
) -> SavedPcapFingerprintCandidateV0 {
    let source = SavedPcapFingerprintSourceV0 {
        capture_id: triage.source.manifest.capture_id.clone(),
        normalized_records_sha256: triage.source.normalized_records_sha256.clone(),
        extractor: triage.source.manifest.extractor.clone(),
    };

    let (scope, status) = match &triage.top_capture_conversation {
        SavedPcapConversationTriageV0::Observed {
            scope,
            packet_envelopes_seen,
            packet_envelopes_grouped,
            packet_envelopes_excluded,
            exclusions,
            conversation,
        } => {
            let basis = SavedPcapFingerprintBasisV0 {
                feature_names: FINGERPRINT_FEATURE_NAMES
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
                normalization: triage.normalization.clone(),
                wlan: triage.wlan.clone(),
                conversation: fingerprint_conversation(
                    *packet_envelopes_seen,
                    *packet_envelopes_grouped,
                    *packet_envelopes_excluded,
                    exclusions,
                    conversation,
                ),
            };
            let digest = fingerprint_digest(&basis);
            (
                *scope,
                SavedPcapFingerprintStatusV0::Observed {
                    digest,
                    basis: Box::new(basis),
                    caveats: FINGERPRINT_CAVEATS
                        .iter()
                        .map(|caveat| (*caveat).to_owned())
                        .collect(),
                },
            )
        }
        SavedPcapConversationTriageV0::Insufficient {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => (
            *scope,
            SavedPcapFingerprintStatusV0::Insufficient {
                reason: match reason {
                    crate::replay::SavedPcapConversationInsufficientReasonV0::
                        PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes => {
                        SavedPcapFingerprintInsufficientReasonV0::
                            PartialNormalizationWithoutEligibleIpTcpUdpPacketEnvelopes
                    }
                },
                packet_envelopes_seen: *packet_envelopes_seen,
                packet_envelopes_excluded: *packet_envelopes_excluded,
                exclusions: exclusions.clone(),
            },
        ),
        SavedPcapConversationTriageV0::Unsupported {
            scope,
            reason,
            packet_envelopes_seen,
            packet_envelopes_excluded,
            exclusions,
        } => (
            *scope,
            SavedPcapFingerprintStatusV0::Unsupported {
                reason: match reason {
                    crate::replay::SavedPcapConversationUnsupportedReasonV0::
                        NoEligibleIpTcpUdpPacketEnvelopes => {
                        SavedPcapFingerprintUnsupportedReasonV0::NoEligibleIpTcpUdpPacketEnvelopes
                    }
                },
                packet_envelopes_seen: *packet_envelopes_seen,
                packet_envelopes_excluded: *packet_envelopes_excluded,
                exclusions: exclusions.clone(),
            },
        ),
    };

    SavedPcapFingerprintCandidateV0 {
        schema: SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.to_owned(),
        source,
        scope,
        status,
    }
}

/// Compares two candidates without joining their sources or inferring identity.
///
/// Candidates are comparable only when their schema, claim scope, and feature
/// set match and both carry an observed digest. A missing or unsupported
/// candidate is reported as `NotComparable`, not as disagreement.
pub fn compare_saved_pcap_fingerprints_v0(
    left: &SavedPcapFingerprintCandidateV0,
    right: &SavedPcapFingerprintCandidateV0,
) -> SavedPcapFingerprintComparisonV0 {
    if left.schema != right.schema {
        return SavedPcapFingerprintComparisonV0::NotComparable {
            reason: SavedPcapFingerprintComparisonReasonV0::DifferentSchema,
        };
    }
    if left.scope != right.scope {
        return SavedPcapFingerprintComparisonV0::NotComparable {
            reason: SavedPcapFingerprintComparisonReasonV0::DifferentClaimScope,
        };
    }

    let (
        SavedPcapFingerprintStatusV0::Observed {
            digest: left_digest,
            basis: left_basis,
            ..
        },
        SavedPcapFingerprintStatusV0::Observed {
            digest: right_digest,
            basis: right_basis,
            ..
        },
    ) = (&left.status, &right.status)
    else {
        return match (
            matches!(&left.status, SavedPcapFingerprintStatusV0::Observed { .. }),
            matches!(&right.status, SavedPcapFingerprintStatusV0::Observed { .. }),
        ) {
            (false, _) => SavedPcapFingerprintComparisonV0::NotComparable {
                reason: SavedPcapFingerprintComparisonReasonV0::LeftNotObserved,
            },
            (true, false) => SavedPcapFingerprintComparisonV0::NotComparable {
                reason: SavedPcapFingerprintComparisonReasonV0::RightNotObserved,
            },
            (true, true) => unreachable!("observed candidates matched above"),
        };
    };

    if left_basis.feature_names != right_basis.feature_names {
        return SavedPcapFingerprintComparisonV0::NotComparable {
            reason: SavedPcapFingerprintComparisonReasonV0::DifferentFeatureSet,
        };
    }
    if left_digest != &fingerprint_digest(left_basis)
        || right_digest != &fingerprint_digest(right_basis)
    {
        return SavedPcapFingerprintComparisonV0::NotComparable {
            reason: SavedPcapFingerprintComparisonReasonV0::InvalidDigest,
        };
    }
    if left_basis == right_basis {
        SavedPcapFingerprintComparisonV0::Corroborated
    } else {
        SavedPcapFingerprintComparisonV0::Conflicting
    }
}

impl SavedPcapFingerprintHypothesisSetV0 {
    /// Validate the serialized assessment's semantic invariants.
    ///
    /// This validates the content-reference shapes but cannot resolve them.
    /// Use [`Self::validate_against`] when the cited candidates are available.
    pub fn validate(&self) -> Result<(), SavedPcapFingerprintValidationErrorV0> {
        if self.schema != SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0 {
            return Err(SavedPcapFingerprintValidationErrorV0::UnsupportedSchema);
        }
        if self.reducer != SAVED_PCAP_FINGERPRINT_REDUCER_V0 {
            return Err(SavedPcapFingerprintValidationErrorV0::UnsupportedReducer);
        }
        if !valid_candidate_ref(&self.left) || !valid_candidate_ref(&self.right) {
            return Err(SavedPcapFingerprintValidationErrorV0::InvalidCandidateReference);
        }
        if candidate_ref_order(&self.left) > candidate_ref_order(&self.right) {
            return Err(SavedPcapFingerprintValidationErrorV0::NonCanonicalCandidateOrder);
        }
        if self
            .limitations
            .iter()
            .map(String::as_str)
            .ne(FINGERPRINT_HYPOTHESIS_LIMITATIONS.iter().copied())
        {
            return Err(SavedPcapFingerprintValidationErrorV0::UnexpectedLimitations);
        }

        let expected_reference = match self.basis {
            SavedPcapFingerprintComparisonV0::Corroborated => {
                SavedPcapFingerprintReferenceV0::SamePacketShape
            }
            SavedPcapFingerprintComparisonV0::Conflicting => {
                SavedPcapFingerprintReferenceV0::DifferentPacketShape
            }
            SavedPcapFingerprintComparisonV0::NotComparable { reason } => {
                SavedPcapFingerprintReferenceV0::Unknown { reason }
            }
        };
        if self.reference != expected_reference {
            return Err(SavedPcapFingerprintValidationErrorV0::IncoherentBasis);
        }

        let dispositions_valid = match self.reference {
            SavedPcapFingerprintReferenceV0::SamePacketShape => {
                self.same_packet_shape == SavedPcapFingerprintDispositionV0::Supported
                    && self.different_packet_shape
                        == SavedPcapFingerprintDispositionV0::Contradicted
                    && self.unknown == SavedPcapFingerprintDispositionV0::Contradicted
            }
            SavedPcapFingerprintReferenceV0::DifferentPacketShape => {
                self.same_packet_shape == SavedPcapFingerprintDispositionV0::Contradicted
                    && self.different_packet_shape == SavedPcapFingerprintDispositionV0::Supported
                    && self.unknown == SavedPcapFingerprintDispositionV0::Contradicted
            }
            SavedPcapFingerprintReferenceV0::Unknown { .. } => {
                self.same_packet_shape == SavedPcapFingerprintDispositionV0::Underdetermined
                    && self.different_packet_shape
                        == SavedPcapFingerprintDispositionV0::Underdetermined
                    && self.unknown == SavedPcapFingerprintDispositionV0::Supported
            }
        };
        if !dispositions_valid {
            return Err(SavedPcapFingerprintValidationErrorV0::IncoherentDisposition);
        }
        Ok(())
    }

    /// Resolve content references and recompute the complete assessment.
    pub fn validate_against(
        &self,
        left: &SavedPcapFingerprintCandidateV0,
        right: &SavedPcapFingerprintCandidateV0,
    ) -> Result<(), SavedPcapFingerprintErrorV0> {
        self.validate()
            .map_err(SavedPcapFingerprintErrorV0::InternalInvariant)?;
        let expected = assess_saved_pcap_fingerprint_v0(left, right)?;
        if self != &expected {
            return Err(SavedPcapFingerprintErrorV0::InternalInvariant(
                SavedPcapFingerprintValidationErrorV0::ResolvedContentMismatch,
            ));
        }
        Ok(())
    }
}

/// Assess the packet-shape relation between two saved-PCAP candidates.
///
/// Complete candidates and their content-bound references are canonically
/// ordered before invoking the lower comparison reducer. The result is thus
/// byte-invariant under input swapping, including positional not-comparable
/// reasons. The hypotheses concern packet shape only and make no event,
/// capture, device, source, variant, identity, intent, or integrity claim.
pub fn assess_saved_pcap_fingerprint_v0(
    left: &SavedPcapFingerprintCandidateV0,
    right: &SavedPcapFingerprintCandidateV0,
) -> Result<SavedPcapFingerprintHypothesisSetV0, SavedPcapFingerprintErrorV0> {
    let mut inputs = [bound_candidate(left)?, bound_candidate(right)?];
    inputs.sort_by(|(left_ref, _), (right_ref, _)| {
        candidate_ref_order(left_ref).cmp(&candidate_ref_order(right_ref))
    });
    let [(left_ref, left), (right_ref, right)] = inputs;
    let basis = compare_saved_pcap_fingerprints_v0(left, right);
    let (same_packet_shape, different_packet_shape, unknown, reference) = match basis {
        SavedPcapFingerprintComparisonV0::Corroborated => (
            SavedPcapFingerprintDispositionV0::Supported,
            SavedPcapFingerprintDispositionV0::Contradicted,
            SavedPcapFingerprintDispositionV0::Contradicted,
            SavedPcapFingerprintReferenceV0::SamePacketShape,
        ),
        SavedPcapFingerprintComparisonV0::Conflicting => (
            SavedPcapFingerprintDispositionV0::Contradicted,
            SavedPcapFingerprintDispositionV0::Supported,
            SavedPcapFingerprintDispositionV0::Contradicted,
            SavedPcapFingerprintReferenceV0::DifferentPacketShape,
        ),
        SavedPcapFingerprintComparisonV0::NotComparable { reason } => (
            SavedPcapFingerprintDispositionV0::Underdetermined,
            SavedPcapFingerprintDispositionV0::Underdetermined,
            SavedPcapFingerprintDispositionV0::Supported,
            SavedPcapFingerprintReferenceV0::Unknown { reason },
        ),
    };

    let assessment = SavedPcapFingerprintHypothesisSetV0 {
        schema: SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0.to_owned(),
        reducer: SAVED_PCAP_FINGERPRINT_REDUCER_V0.to_owned(),
        left: left_ref,
        right: right_ref,
        basis,
        same_packet_shape,
        different_packet_shape,
        unknown,
        reference,
        limitations: FINGERPRINT_HYPOTHESIS_LIMITATIONS
            .iter()
            .map(|limitation| (*limitation).to_owned())
            .collect(),
    };
    assessment
        .validate()
        .map_err(SavedPcapFingerprintErrorV0::InternalInvariant)?;
    Ok(assessment)
}

fn bound_candidate(
    candidate: &SavedPcapFingerprintCandidateV0,
) -> Result<
    (
        SavedPcapFingerprintCandidateRefV0,
        &SavedPcapFingerprintCandidateV0,
    ),
    SavedPcapFingerprintErrorV0,
> {
    let encoded = serde_json::to_vec(candidate)
        .map_err(SavedPcapFingerprintErrorV0::CandidateSerialization)?;
    let mut hasher = Sha256::new();
    hasher.update(FINGERPRINT_CANDIDATE_REF_DOMAIN_V0.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    let reference = SavedPcapFingerprintCandidateRefV0 {
        candidate_schema: candidate.schema.clone(),
        capture_id: candidate.source.capture_id.clone(),
        normalized_records_sha256: candidate.source.normalized_records_sha256.clone(),
        candidate_sha256: format!("{:x}", hasher.finalize()),
    };
    Ok((reference, candidate))
}

fn candidate_ref_order(reference: &SavedPcapFingerprintCandidateRefV0) -> (&str, &str, &str, &str) {
    (
        &reference.candidate_schema,
        &reference.capture_id,
        &reference.normalized_records_sha256,
        &reference.candidate_sha256,
    )
}

fn valid_candidate_ref(reference: &SavedPcapFingerprintCandidateRefV0) -> bool {
    reference.candidate_schema == SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0
        && valid_prefixed_sha256(&reference.capture_id)
        && valid_prefixed_sha256(&reference.normalized_records_sha256)
        && valid_sha256(&reference.candidate_sha256)
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_sha256)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn fingerprint_conversation(
    packet_envelopes_seen: u64,
    packet_envelopes_grouped: u64,
    packet_envelopes_excluded: u64,
    exclusions: &[SavedPcapConversationExclusionCountV0],
    conversation: &SavedPcapTopConversationV0,
) -> SavedPcapFingerprintConversationV0 {
    SavedPcapFingerprintConversationV0 {
        aggregation: conversation.aggregation,
        temporal_relevance: conversation.temporal_relevance,
        transport: conversation.transport,
        observation_point: conversation.observation_point.clone(),
        packet_envelopes_seen,
        packet_envelopes_grouped,
        packet_envelopes_excluded,
        exclusions: exclusions.to_vec(),
        total_frames: conversation.total_frames,
        total_original_frame_octets: conversation.total_original_frame_octets,
        total_captured_frame_octets: conversation.total_captured_frame_octets,
        a_to_b: conversation.a_to_b.clone(),
        b_to_a: conversation.b_to_a.clone(),
        earliest_event_time_unix_ns: conversation.earliest_event_time_unix_ns,
        latest_event_time_unix_ns: conversation.latest_event_time_unix_ns,
        observed_span_ns: conversation.observed_span_ns,
    }
}

fn fingerprint_digest(basis: &SavedPcapFingerprintBasisV0) -> String {
    let encoded = serde_json::to_vec(basis).expect("fingerprint basis is serializable");
    let mut hasher = Sha256::new();
    hasher.update(SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    let digest = hasher.finalize();
    let hex = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unsupported_candidate(hex: char) -> SavedPcapFingerprintCandidateV0 {
        SavedPcapFingerprintCandidateV0 {
            schema: SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0.to_owned(),
            source: SavedPcapFingerprintSourceV0 {
                capture_id: format!("sha256:{}", hex.to_string().repeat(64)),
                normalized_records_sha256: format!("sha256:{}", "f".repeat(64)),
                extractor: CaptureExtractorRefV0 {
                    adapter: "netbraid-adapter-tshark".into(),
                    adapter_version: "0.3.1".into(),
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
    fn resolved_validation_binds_candidate_content_and_provenance() {
        let left = unsupported_candidate('a');
        let right = unsupported_candidate('b');
        let assessment = assess_saved_pcap_fingerprint_v0(&left, &right).unwrap();

        assessment.validate().unwrap();
        assessment.validate_against(&left, &right).unwrap();
        assessment.validate_against(&right, &left).unwrap();
        let plain_digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&left).unwrap()));
        assert_ne!(assessment.left.candidate_sha256, plain_digest);

        let mut changed_provenance = right.clone();
        changed_provenance.source.extractor.adapter_version = "0.3.2".into();
        assert!(matches!(
            assessment.validate_against(&left, &changed_provenance),
            Err(SavedPcapFingerprintErrorV0::InternalInvariant(
                SavedPcapFingerprintValidationErrorV0::ResolvedContentMismatch
            ))
        ));

        let mut changed_reference = assessment.clone();
        changed_reference.left.candidate_sha256 = "0".repeat(64);
        changed_reference.validate().unwrap();
        assert!(matches!(
            changed_reference.validate_against(&left, &right),
            Err(SavedPcapFingerprintErrorV0::InternalInvariant(
                SavedPcapFingerprintValidationErrorV0::ResolvedContentMismatch
            ))
        ));
    }

    #[test]
    fn strict_serde_and_structural_validation_reject_forged_assessments() {
        let assessment = assess_saved_pcap_fingerprint_v0(
            &unsupported_candidate('a'),
            &unsupported_candidate('b'),
        )
        .unwrap();
        for path in ["top", "candidate_ref"] {
            let mut encoded = serde_json::to_value(&assessment).unwrap();
            let target = if path == "top" {
                encoded.as_object_mut().unwrap()
            } else {
                encoded["left"].as_object_mut().unwrap()
            };
            target.insert("unexpected".into(), serde_json::Value::Bool(true));
            assert!(
                serde_json::from_value::<SavedPcapFingerprintHypothesisSetV0>(encoded).is_err()
            );
        }

        let mut forged_basis = assessment.clone();
        forged_basis.reference = SavedPcapFingerprintReferenceV0::SamePacketShape;
        assert_eq!(
            forged_basis.validate(),
            Err(SavedPcapFingerprintValidationErrorV0::IncoherentBasis)
        );
        let mut forged_disposition = assessment.clone();
        forged_disposition.same_packet_shape = SavedPcapFingerprintDispositionV0::Supported;
        assert_eq!(
            forged_disposition.validate(),
            Err(SavedPcapFingerprintValidationErrorV0::IncoherentDisposition)
        );
        let mut forged_reference = assessment;
        forged_reference.left.candidate_sha256 = "A".repeat(64);
        assert_eq!(
            forged_reference.validate(),
            Err(SavedPcapFingerprintValidationErrorV0::InvalidCandidateReference)
        );
        forged_reference.left.candidate_sha256 = "0".repeat(64);
        forged_reference.left.candidate_schema = "unsupported.schema.v0".into();
        assert_eq!(
            forged_reference.validate(),
            Err(SavedPcapFingerprintValidationErrorV0::InvalidCandidateReference)
        );
    }
}
