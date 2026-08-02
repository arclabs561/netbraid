//! Netbraid's reusable network-evidence, replay, and saved-capture boundaries.
//!
//! The modules remain semantically separate, but ship as one package with the
//! `netbraid` operator binary. None of the library modules performs live
//! collection or active network discovery.

pub mod adapters;
pub mod evidence;

/// Auditable, revisable interpretations derived from immutable evidence.
///
/// Inference remains a separate semantic plane even though its deterministic
/// reference reducers currently live in [`replay`]. Evidence records do
/// not acquire inferred identity semantics through this facade.
pub mod infer {
    pub use crate::replay::{
        assess_packet_same_event_v0, PacketSameEventBasisV0, PacketSameEventDifferenceV0,
        PacketSameEventDimensionV0, PacketSameEventDispositionV0, PacketSameEventErrorV0,
        PacketSameEventEvidenceRefV0, PacketSameEventHypothesisSetV0, PacketSameEventReferenceV0,
        PacketSameEventUnknownReasonV0, PacketSameEventValidationErrorV0,
        PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0, PACKET_SAME_EVENT_REDUCER_V0,
    };
}

pub mod replay;
