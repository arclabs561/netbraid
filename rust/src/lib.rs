//! Netbraid's reusable evidence, replay, and saved-capture boundaries.
//!
//! The operator binary and the library share one package. The library modules
//! remain offline and do not collect traffic, discover devices, or persist
//! deployment state.

pub mod adapters {
    pub use netbraid_adapter_tshark::*;
}

pub mod evidence {
    pub use netbraid_evidence::*;
}

/// Auditable, revisable interpretations derived from immutable evidence.
///
/// Inference remains a separate semantic plane even though its deterministic
/// reference reducers currently live in `netbraid-replay`. Evidence records do
/// not acquire inferred identity semantics through this facade.
pub mod infer {
    pub use netbraid_replay::{
        assess_packet_same_event_v0, PacketSameEventBasisV0, PacketSameEventDifferenceV0,
        PacketSameEventDimensionV0, PacketSameEventDispositionV0, PacketSameEventErrorV0,
        PacketSameEventEvidenceRefV0, PacketSameEventHypothesisSetV0, PacketSameEventReferenceV0,
        PacketSameEventUnknownReasonV0, PacketSameEventValidationErrorV0,
        PACKET_SAME_EVENT_HYPOTHESIS_SET_SCHEMA_V0, PACKET_SAME_EVENT_REDUCER_V0,
    };
}

pub mod replay {
    pub use netbraid_replay::*;
}
