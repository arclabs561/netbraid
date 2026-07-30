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

pub mod replay {
    pub use netbraid_replay::*;
}
