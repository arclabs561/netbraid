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
pub mod infer;

pub mod replay;
