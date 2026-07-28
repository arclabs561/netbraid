//! Netbraid's reusable network-evidence, replay, and saved-capture boundaries.
//!
//! The modules remain semantically separate, but ship as one package with the
//! `netbraid` operator binary. None of the library modules performs live
//! collection or active network discovery.

pub mod adapters;
pub mod evidence;
pub mod replay;
