mod calibrated_event_relation;
mod composition;
mod content_relation;
mod counter_capture;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "the private kernel supports factor kinds beyond its first consumer"
    )
)]
mod factor_graph;
#[cfg_attr(
    not(test),
    allow(
        dead_code,
        reason = "private relation-target binding is being validated before public exposure"
    )
)]
mod fusion_target;
mod hypothesis;
mod lineage;
mod packet_flow_correspondence;
#[cfg(feature = "adapter-zeek")]
mod packet_zeek;
mod qualified_composition;
mod rssi_reference_frame;
mod rssi_shift_explanation;

pub use crate::replay::{
    assess_packet_same_event_v0, assess_saved_pcap_fingerprint_v0, PacketSameEventBasisV0,
    PacketSameEventDifferenceV0, PacketSameEventDimensionV0, PacketSameEventDispositionV0,
    PacketSameEventErrorV0, PacketSameEventEvidenceRefV0, PacketSameEventHypothesisSetV0,
    PacketSameEventReferenceV0, PacketSameEventUnknownReasonV0, PacketSameEventValidationErrorV0,
    SavedPcapFingerprintCandidateRefV0, SavedPcapFingerprintCandidateV0,
    SavedPcapFingerprintComparisonReasonV0, SavedPcapFingerprintComparisonV0,
    SavedPcapFingerprintDispositionV0, SavedPcapFingerprintErrorV0,
    SavedPcapFingerprintHypothesisSetV0, SavedPcapFingerprintReferenceV0,
    SavedPcapFingerprintValidationErrorV0, PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0,
    PACKET_SAME_EVENT_REDUCER_V0, SAVED_PCAP_FINGERPRINT_CANDIDATE_SCHEMA_V0,
    SAVED_PCAP_FINGERPRINT_HYPOTHESIS_SET_SCHEMA_V0, SAVED_PCAP_FINGERPRINT_REDUCER_V0,
};

pub use composition::{
    FiniteHypothesisCompositionErrorV0, FiniteHypothesisCompositionV0,
    FINITE_HYPOTHESIS_COMPOSITION_MAX_SUBMITTED_CLAIMS_V0, FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0,
};

pub use calibrated_event_relation::{
    assess_calibrated_event_relation_v0, calibrated_event_relation_pair_id_v0,
    CalibratedEventRelationAssessmentV0, CalibratedEventRelationAssessmentValidationErrorV0,
    CalibratedEventRelationDispositionV0, CalibratedEventRelationDocumentErrorV0,
    CalibratedEventRelationErrorV0, CalibratedEventRelationObservationRefV0,
    CalibratedEventRelationObservationRefValidationErrorV0, CalibratedEventRelationProfileV0,
    CalibratedEventRelationProfileValidationErrorV0, CalibratedEventRelationReferenceV0,
    EventRelationAbstainReasonV0, EventRelationDecisionV0, EventRelationPredictionV0,
    EventRelationPredictionValidationErrorV0, HeldoutEvaluationGateStatusV0,
    HeldoutEventRelationEvaluationReceiptV0,
    HeldoutEventRelationEvaluationReceiptValidationErrorV0,
    CALIBRATED_EVENT_RELATION_ASSESSMENT_SCHEMA_V0, CALIBRATED_EVENT_RELATION_PROFILE_SCHEMA_V0,
    CALIBRATED_EVENT_RELATION_REDUCER_V0, EVENT_RELATION_PREDICTION_SCHEMA_V0,
    HELDOUT_EVENT_RELATION_EVALUATION_RECEIPT_SCHEMA_V0,
};

pub use counter_capture::{
    assess_counter_capture_v0, derive_traffic_window_features_ppb_v0,
    score_counter_capture_windows_v0, CounterCaptureBasisV0, CounterCaptureDispositionV0,
    CounterCaptureErrorV0, CounterCaptureEvidenceRefV0, CounterCaptureFeatureV0,
    CounterCaptureFeatureVectorPpbV0, CounterCaptureHypothesisSetV0, CounterCaptureProfileRefV0,
    CounterCaptureProfileV0, CounterCaptureProfileValidationErrorV0, CounterCaptureReferenceV0,
    CounterCaptureResidualVectorPpbV0, CounterCaptureScaleVectorPpbV0, CounterCaptureScoreV0,
    CounterCaptureScoringErrorV0, CounterCaptureUnknownReasonV0, CounterCaptureValidationErrorV0,
    TrafficWindowCoverageV0, TrafficWindowEvidenceV0, TrafficWindowEvidenceValidationErrorV0,
    TrafficWindowV0, TrafficWindowValidationErrorV0, COUNTER_CAPTURE_HYPOTHESIS_SET_SCHEMA_V0,
    COUNTER_CAPTURE_PROFILE_SCHEMA_V0, COUNTER_CAPTURE_REDUCER_V0,
    COUNTER_CAPTURE_SCALE_FLOOR_PPB_V0, PPB, TRAFFIC_WINDOW_SCHEMA_V0,
};

pub use content_relation::{
    assess_content_relation_v0, ContentDigestEvidenceV0, ContentDigestEvidenceValidationErrorV0,
    ContentDigestStateV0, ContentDigestUnavailableReasonV0, ContentRelationBasisV0,
    ContentRelationDispositionV0, ContentRelationErrorV0, ContentRelationEvidenceRefV0,
    ContentRelationHypothesisSetV0, ContentRelationReferenceV0, ContentRelationUnknownReasonV0,
    ContentRelationValidationErrorV0, ContentSha256ParseErrorV0, ContentSha256V0,
    CONTENT_DIGEST_EVIDENCE_SCHEMA_V0, CONTENT_RELATION_HYPOTHESIS_SET_SCHEMA_V0,
    CONTENT_RELATION_REDUCER_V0,
};

pub use hypothesis::{
    FiniteHypothesisAlternativeV0, FiniteHypothesisClaimErrorV0, FiniteHypothesisClaimV0,
    FiniteHypothesisDispositionV0, FiniteHypothesisInputRefV0, FiniteHypothesisProjectionErrorV0,
    FiniteHypothesisProjectionV0, ProjectFiniteHypothesesV0, ProjectFiniteHypothesisClaimV0,
    FINITE_HYPOTHESIS_CLAIM_SCHEMA_V0, FINITE_HYPOTHESIS_PROJECTION_SCHEMA_V0,
};

pub use lineage::{
    ContentBoundEvidenceRefV0, ProvenanceActivityKindV0, ProvenanceActivityV0,
    ProvenanceArtifactRefErrorV0, ProvenanceArtifactRefV0, ProvenanceComparisonV0,
    ProvenanceContentRelationV0, ProvenanceGraphErrorV0, ProvenanceGraphV0,
    ProvenanceLineageRelationV0, ProvenanceProducerKindV0, ProvenanceProducerV0,
    ProvenanceRecordErrorV0, ProvenanceRecordV0, PROVENANCE_GRAPH_MAX_RECORDS_V0,
    PROVENANCE_GRAPH_SCHEMA_V0, PROVENANCE_RECORD_MAX_INPUTS_V0, PROVENANCE_RECORD_SCHEMA_V0,
};

pub use packet_flow_correspondence::{
    infer_packet_flow_correspondence_v0, FlowRecordProtocolV0, FlowRecordV0,
    PacketFlowCorrespondenceAbstentionReasonV0, PacketFlowCorrespondenceComponentOutcomeV0,
    PacketFlowCorrespondenceComponentResultV0, PacketFlowCorrespondenceDispositionV0,
    PacketFlowCorrespondenceEdgeBeliefV0, PacketFlowCorrespondenceErrorV0,
    PacketFlowCorrespondenceHeuristicProfileV0, PacketFlowCorrespondenceLimitsV0,
    PacketFlowCorrespondenceOptionsV0, PacketFlowCorrespondenceReportV0,
    PACKET_FLOW_CORRESPONDENCE_HEURISTIC_PROFILE_V0,
};

pub use qualified_composition::{
    ProvenanceQualifiedClaimInputRelationV0, ProvenanceQualifiedClaimLineageStatusV0,
    ProvenanceQualifiedClaimPairSummaryV0, ProvenanceQualifiedFiniteHypothesisCompositionErrorV0,
    ProvenanceQualifiedFiniteHypothesisCompositionV0,
    PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_CLAIMS_V0,
    PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_MAX_TOTAL_CLAIM_INPUTS_V0,
    PROVENANCE_QUALIFIED_FINITE_HYPOTHESIS_COMPOSITION_SCHEMA_V0,
};

#[cfg(feature = "adapter-zeek")]
pub use packet_zeek::{
    infer_packet_zeek_correspondence_v0, PacketZeekAbstentionReasonV0,
    PacketZeekComponentOutcomeV0, PacketZeekComponentResultV0, PacketZeekCorrespondenceErrorV0,
    PacketZeekCorrespondenceOptionsV0, PacketZeekCorrespondenceReportV0, PacketZeekEdgeBeliefV0,
    PacketZeekHeuristicProfileV0, PacketZeekInferenceLimitsV0, PacketZeekMarginalDispositionV0,
    PACKET_ZEEK_HEURISTIC_PROFILE_V0,
};

pub use rssi_reference_frame::{
    assess_rssi_reference_frame_v0, RssiLinkShiftEvidenceV0, RssiLinkShiftKindV0, RssiMilliDbV0,
    RssiObserverEvidenceV0, RssiReferenceFrameAssessmentV0,
    RssiReferenceFrameAssessmentValidationErrorV0, RssiReferenceFrameErrorV0,
    RssiReferenceFrameLinkV0, RssiReferenceFrameLinkValidationErrorV0, RssiReferenceFrameProfileV0,
    RssiReferenceFrameProfileValidationErrorV0, RssiSourceWideShiftCandidateV0,
    RSSI_REFERENCE_FRAME_ASSESSMENT_SCHEMA_V0, RSSI_REFERENCE_FRAME_MAX_LINK_EVIDENCE_V0,
    RSSI_REFERENCE_FRAME_PPB_V0, RSSI_REFERENCE_FRAME_PROFILE_SCHEMA_V0,
    RSSI_REFERENCE_FRAME_REDUCER_V0,
};

pub use rssi_shift_explanation::{
    infer_rssi_shift_explanations_v0, RssiObserverShiftBeliefV0, RssiResidualShiftBeliefV0,
    RssiShiftExplanationAbstentionReasonV0, RssiShiftExplanationComponentOutcomeV0,
    RssiShiftExplanationComponentResultV0, RssiShiftExplanationErrorV0,
    RssiShiftExplanationHeuristicProfileV0, RssiShiftExplanationLimitsV0,
    RssiShiftExplanationOptionsV0, RssiShiftExplanationReportV0, RssiSourceShiftBeliefV0,
    RSSI_SHIFT_EXPLANATION_HEURISTIC_PROFILE_V0,
};
