//! Experimental policy-neutral evidence records.
//!
//! `HostPathObservationV0` is intentionally narrower than Netbraid's gated
//! multi-modal observation contract. The crate owns data invariants only: it
//! performs no collection, networking, filesystem access, or wall-clock reads.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

mod capture;

pub use capture::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureFileMetadataV0, CaptureManifestV0,
    CaptureNormalizationV0, CaptureRunReceiptV0, CaptureValidationError, EthernetFieldsV0,
    Ieee80211FieldsV0, Ieee802154AddressV0, Ieee802154FcsStatusV0, Ieee802154FieldsV0,
    Ipv4FieldsV0, Ipv6FieldsV0, NormalizationStateV0, PacketEnvelopeV0, PacketFrameV0,
    PacketQuarantineV0, TcpFieldsV0, ToolRunReceiptV0, UdpFieldsV0, WlanRadioFieldsV0,
    CAPTURE_MANIFEST_SCHEMA_V0, CAPTURE_RUN_RECEIPT_SCHEMA_V0,
    NORMALIZED_RECORDS_DIGEST_PROFILE_V0, PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};

pub const HOST_PATH_SCHEMA_V0: &str = "netmon.host_path_observation.v0";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ObservationOrderV0 {
    pub event_time_unix_ms: i64,
    pub acquired_time_unix_ms: i64,
    pub source_sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceRefV0 {
    pub observer_id: String,
    pub adapter: String,
    pub adapter_version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectionModeV0 {
    PassiveHostLocal,
    ActiveBounded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionPolicyV0 {
    pub mode: CollectionModeV0,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub active_actions: Vec<String>,
}

impl CollectionPolicyV0 {
    pub fn passive_host_local() -> Self {
        Self {
            mode: CollectionModeV0::PassiveHostLocal,
            active_actions: Vec::new(),
        }
    }

    pub fn is_passive(&self) -> bool {
        self.mode == CollectionModeV0::PassiveHostLocal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStateV0 {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageV0 {
    pub state: CoverageStateV0,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub observed_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_sources: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkNameVisibilityV0 {
    Observed,
    Restricted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkNameV0 {
    pub visibility: NetworkNameVisibilityV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPathV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_type: Option<String>,
    pub network_name: NetworkNameV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub association_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub associated_bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_hop: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_hop_link_address: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolvers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub address_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostPathObservationV0 {
    pub schema: String,
    pub record_id: String,
    pub order: ObservationOrderV0,
    pub source: SourceRefV0,
    pub policy: CollectionPolicyV0,
    pub coverage: CoverageV0,
    pub path: HostPathV0,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ContextKeyV0 {
    pub link_type: Option<String>,
    pub network_name: NetworkNameV0Key,
    pub next_hop: Option<String>,
    pub next_hop_link_address: Option<String>,
    pub resolvers: Vec<String>,
    pub address_prefixes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum NetworkNameV0Key {
    Observed(String),
    Restricted,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedSchema(String),
    EmptyRecordId,
    EmptyObserverId,
    EmptyAdapter,
    EmptyAdapterVersion,
    PassivePolicyHasActiveActions,
    ObservedNetworkNameMissing,
    HiddenNetworkNameHasValue,
    CoverageContradiction(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => write!(formatter, "unsupported schema {schema:?}"),
            Self::EmptyRecordId => formatter.write_str("record_id must not be empty"),
            Self::EmptyObserverId => formatter.write_str("observer_id must not be empty"),
            Self::EmptyAdapter => formatter.write_str("adapter must not be empty"),
            Self::EmptyAdapterVersion => formatter.write_str("adapter_version must not be empty"),
            Self::PassivePolicyHasActiveActions => {
                formatter.write_str("passive policy cannot name active actions")
            }
            Self::ObservedNetworkNameMissing => {
                formatter.write_str("observed network name must have a value")
            }
            Self::HiddenNetworkNameHasValue => {
                formatter.write_str("restricted or unavailable network name cannot have a value")
            }
            Self::CoverageContradiction(source) => {
                write!(formatter, "source {source:?} is both observed and missing")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

impl HostPathObservationV0 {
    pub fn canonicalize(&mut self) {
        canonicalize_strings(&mut self.policy.active_actions);
        canonicalize_strings(&mut self.coverage.observed_sources);
        canonicalize_strings(&mut self.coverage.missing_sources);
        canonicalize_strings(&mut self.path.resolvers);
        canonicalize_strings(&mut self.path.address_prefixes);
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema != HOST_PATH_SCHEMA_V0 {
            return Err(ValidationError::UnsupportedSchema(self.schema.clone()));
        }
        if self.record_id.trim().is_empty() {
            return Err(ValidationError::EmptyRecordId);
        }
        if self.source.observer_id.trim().is_empty() {
            return Err(ValidationError::EmptyObserverId);
        }
        if self.source.adapter.trim().is_empty() {
            return Err(ValidationError::EmptyAdapter);
        }
        if self.source.adapter_version.trim().is_empty() {
            return Err(ValidationError::EmptyAdapterVersion);
        }
        if self.policy.is_passive() && !self.policy.active_actions.is_empty() {
            return Err(ValidationError::PassivePolicyHasActiveActions);
        }
        match (
            self.path.network_name.visibility,
            self.path.network_name.value.as_deref(),
        ) {
            (NetworkNameVisibilityV0::Observed, None | Some("")) => {
                return Err(ValidationError::ObservedNetworkNameMissing);
            }
            (
                NetworkNameVisibilityV0::Restricted | NetworkNameVisibilityV0::Unavailable,
                Some(_),
            ) => return Err(ValidationError::HiddenNetworkNameHasValue),
            _ => {}
        }
        let observed: BTreeSet<_> = self.coverage.observed_sources.iter().collect();
        if let Some(source) = self
            .coverage
            .missing_sources
            .iter()
            .find(|source| observed.contains(source))
        {
            return Err(ValidationError::CoverageContradiction(source.clone()));
        }
        Ok(())
    }

    pub fn context_key(&self) -> ContextKeyV0 {
        let network_name = match (
            self.path.network_name.visibility,
            self.path.network_name.value.as_deref(),
        ) {
            (NetworkNameVisibilityV0::Observed, Some(value)) => {
                NetworkNameV0Key::Observed(value.to_owned())
            }
            (NetworkNameVisibilityV0::Restricted, _) => NetworkNameV0Key::Restricted,
            _ => NetworkNameV0Key::Unavailable,
        };
        ContextKeyV0 {
            link_type: self.path.link_type.clone(),
            network_name,
            next_hop: self.path.next_hop.clone(),
            next_hop_link_address: self.path.next_hop_link_address.clone(),
            resolvers: canonical_strings(&self.path.resolvers),
            address_prefixes: canonical_strings(&self.path.address_prefixes),
        }
    }
}

fn canonicalize_strings(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

fn canonical_strings(values: &[String]) -> Vec<String> {
    let mut canonical = values.to_vec();
    canonicalize_strings(&mut canonical);
    canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation() -> HostPathObservationV0 {
        HostPathObservationV0 {
            schema: HOST_PATH_SCHEMA_V0.into(),
            record_id: "observer:7".into(),
            order: ObservationOrderV0 {
                event_time_unix_ms: 1_000,
                acquired_time_unix_ms: 1_005,
                source_sequence: 7,
            },
            source: SourceRefV0 {
                observer_id: "observer".into(),
                adapter: "linktop".into(),
                adapter_version: "0.1.0".into(),
            },
            policy: CollectionPolicyV0::passive_host_local(),
            coverage: CoverageV0 {
                state: CoverageStateV0::Complete,
                observed_sources: vec!["route".into(), "address".into()],
                missing_sources: Vec::new(),
            },
            path: HostPathV0 {
                interface: Some("en0".into()),
                link_type: Some("wifi".into()),
                network_name: NetworkNameV0 {
                    visibility: NetworkNameVisibilityV0::Observed,
                    value: Some("lab".into()),
                },
                association_id: Some("association-7".into()),
                associated_bssid: Some("02:00:00:00:00:07".into()),
                next_hop: Some("192.0.2.1".into()),
                next_hop_link_address: Some("02:00:00:00:01:01".into()),
                resolvers: vec!["2001:db8::53".into(), "192.0.2.53".into()],
                address_prefixes: vec!["2001:db8:7::/64".into(), "192.0.2.7".into()],
            },
        }
    }

    #[test]
    fn canonicalization_makes_set_like_fields_stable() {
        let mut record = observation();
        record.path.resolvers = vec!["b".into(), "a".into(), "b".into()];
        record.coverage.observed_sources = vec!["route".into(), "address".into(), "route".into()];
        record.canonicalize();

        assert_eq!(record.path.resolvers, vec!["a", "b"]);
        assert_eq!(record.coverage.observed_sources, vec!["address", "route"]);
    }

    #[test]
    fn canonicalization_is_idempotent() {
        let mut record = observation();
        record.path.resolvers = vec!["b".into(), "a".into(), "b".into()];
        record.coverage.observed_sources = vec!["route".into(), "address".into(), "route".into()];

        record.canonicalize();
        let once = record.clone();
        record.canonicalize();

        assert_eq!(record, once);
    }

    #[test]
    fn context_key_ignores_order_and_duplicates_in_set_like_fields() {
        let mut equivalent = observation();
        equivalent.path.resolvers = vec!["192.0.2.53".into(), "2001:db8::53".into()];
        equivalent.path.address_prefixes = vec!["192.0.2.7".into(), "2001:db8:7::/64".into()];

        assert_eq!(observation().context_key(), equivalent.context_key());
    }

    #[test]
    fn association_does_not_define_durable_context() {
        let before = observation();
        let mut after = before.clone();
        after.path.association_id = Some("association-8".into());
        after.path.associated_bssid = Some("02:00:00:00:00:08".into());

        assert_eq!(before.context_key(), after.context_key());
    }

    #[test]
    fn same_ssid_at_a_different_network_boundary_is_not_the_same_context() {
        let before = observation();
        let mut after = before.clone();
        after.path.next_hop = Some("198.51.100.1".into());
        after.path.address_prefixes = vec!["198.51.100.9".into()];

        assert_ne!(before.context_key(), after.context_key());
    }

    #[test]
    fn gateway_link_binding_disambiguates_reused_private_network_details() {
        let before = observation();
        let mut after = before.clone();
        after.path.next_hop_link_address = Some("02:00:00:00:02:01".into());

        assert_ne!(before.context_key(), after.context_key());
    }

    #[test]
    fn golden_json_names_the_experimental_schema_and_policy() {
        let mut record = observation();
        record.canonicalize();
        let json = serde_json::to_value(&record).unwrap();

        assert_eq!(json["schema"], HOST_PATH_SCHEMA_V0);
        assert_eq!(json["policy"]["mode"], "passive_host_local");
        assert_eq!(json["path"]["network_name"]["visibility"], "observed");
        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&record).unwrap()),
            include_str!("../tests/fixtures/v0/host_path_observation_v0.json")
        );
    }

    #[test]
    fn passive_record_rejects_active_actions() {
        let mut record = observation();
        record.policy.active_actions.push("icmp_echo".into());

        assert_eq!(
            record.validate(),
            Err(ValidationError::PassivePolicyHasActiveActions)
        );
    }
}
