//! Netbraid's reusable network-evidence, replay, and saved-capture boundaries.
//!
//! The modules remain semantically separate, but ship as one package with the
//! `netbraid` operator binary. None of the library modules performs live
//! collection or active network discovery.

pub mod adapters;
pub mod evidence;

/// Auditable, revisable interpretations derived from immutable evidence.
///
/// Inference remains a separate semantic plane. Counter-capture and RSSI
/// reference-frame reducers are owned here; packet-shape and same-event
/// reducers are re-exported from [`replay`]. Evidence records do not acquire
/// inferred identity semantics through this facade.
pub mod infer;

pub mod replay;
