use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::CollectionPolicyV0;

pub const CAPTURE_MANIFEST_SCHEMA_V0: &str = "netmon.capture_manifest.v0";
pub const CAPTURE_RUN_RECEIPT_SCHEMA_V0: &str = "netmon.capture_run_receipt.v0";
pub const NORMALIZED_RECORDS_DIGEST_PROFILE_V0: &str = "netmon.normalized_records_digest.v0";
pub const PACKET_ENVELOPE_SCHEMA_V0: &str = "netmon.packet_envelope.v0";
pub const PACKET_QUARANTINE_SCHEMA_V0: &str = "netmon.packet_quarantine.v0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureArtifactRefV0 {
    pub content_sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureExtractorRefV0 {
    pub adapter: String,
    pub adapter_version: String,
    pub tool: String,
    pub tool_version: String,
    pub configuration_sha256: String,
    pub field_registry: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationStateV0 {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureNormalizationV0 {
    pub state: NormalizationStateV0,
    pub packet_limit: u64,
    pub packet_limit_reached: bool,
    pub packet_rows_emitted: u64,
    pub packet_rows_quarantined: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureManifestV0 {
    pub schema: String,
    pub capture_id: String,
    pub artifact: CaptureArtifactRefV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observer_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired_time_unix_ms: Option<i64>,
    pub extractor: CaptureExtractorRefV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquisition_policy: Option<CollectionPolicyV0>,
    pub normalization: CaptureNormalizationV0,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureFileMetadataV0 {
    pub file_type: String,
    pub encapsulation: String,
    pub timestamp_precision: String,
    pub packet_count: u64,
    pub file_size_bytes: u64,
    pub original_data_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snaplen: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_snaplen_min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inferred_snaplen_max: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ns: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub earliest_packet_time_unix_ns: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_packet_time_unix_ns: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_hardware: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_operating_system: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture_application: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolRunReceiptV0 {
    pub tool: String,
    pub configured_executable: String,
    pub tool_version: String,
    pub argument_template: Vec<String>,
    pub environment_policy: String,
    pub exit_code: i32,
    pub stdout_sha256: String,
    pub stderr_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureRunReceiptV0 {
    pub schema: String,
    pub run_id: String,
    pub capture_id: String,
    pub started_time_unix_ns: i64,
    pub finished_time_unix_ns: i64,
    pub elapsed_ns: u64,
    pub file: CaptureFileMetadataV0,
    pub capinfos: ToolRunReceiptV0,
    pub tshark: ToolRunReceiptV0,
    pub configuration_sha256: String,
    pub field_registry: String,
    pub normalized_records_digest_profile: String,
    pub normalized_records_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketFrameV0 {
    pub number: u64,
    pub event_time_unix_ns: i64,
    pub original_len: u32,
    pub captured_len: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encapsulation_type: Option<i16>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthernetFieldsV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv4FieldsV0 {
    pub source: String,
    pub destination: String,
    pub protocol: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6FieldsV0 {
    pub source: String,
    pub destination: String,
    pub next_header: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpFieldsV0 {
    pub source_port: u16,
    pub destination_port: u16,
    pub flags: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UdpFieldsV0 {
    pub source_port: u16,
    pub destination_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ieee80211FieldsV0 {
    pub frame_type: u8,
    pub frame_subtype: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmitter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bssid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssid_hex: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WlanRadioFieldsV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub center_frequency_mhz: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketEnvelopeV0 {
    pub schema: String,
    pub record_id: String,
    pub capture_id: String,
    pub frame: PacketFrameV0,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ethernet: Option<EthernetFieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<Ipv4FieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<Ipv6FieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp: Option<TcpFieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub udp: Option<UdpFieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ieee80211: Option<Ieee80211FieldsV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wlan_radio: Option<WlanRadioFieldsV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketQuarantineV0 {
    pub schema: String,
    pub capture_id: String,
    pub source_line: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_number_hint: Option<u64>,
    pub reason: String,
    pub raw_row: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureValidationError {
    UnsupportedSchema(String),
    InvalidCaptureId,
    CaptureIdDoesNotMatchArtifact,
    EmptyObserverId,
    EmptyExtractorField(&'static str),
    InvalidConfigurationDigest,
    InvalidRunId,
    EmptyReceiptField(&'static str),
    InvalidReceiptDigest(&'static str),
    UnsupportedDigestProfile(String),
    UnsuccessfulToolReceipt(&'static str),
    UnexpectedToolReceipt {
        expected: &'static str,
        actual: String,
    },
    MissingStagedCapturePlaceholder(&'static str),
    InconsistentCaptureFileTimes,
    PassivePolicyHasActiveActions,
    InconsistentNormalization,
    ZeroFrameNumber,
    UnexpectedRecordId,
    CapturedLengthExceedsOriginal,
    InvalidEthernetAddress(String),
    InvalidIpv4Address(String),
    InvalidIpv6Address(String),
    InvalidIeee80211FrameType(u8),
    InvalidIeee80211FrameSubtype(u8),
    InvalidSsidHex,
    EmptyWlanRadioFields,
    ZeroWlanChannel,
    ZeroWlanCenterFrequency,
    ZeroSourceLine,
    EmptyQuarantineReason,
}

impl std::fmt::Display for CaptureValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema(schema) => write!(formatter, "unsupported schema {schema:?}"),
            Self::InvalidCaptureId => {
                formatter.write_str("capture_id must use sha256:<64 lowercase hex>")
            }
            Self::CaptureIdDoesNotMatchArtifact => {
                formatter.write_str("capture_id must equal artifact.content_sha256")
            }
            Self::EmptyObserverId => formatter.write_str("observer_id must not be empty"),
            Self::EmptyExtractorField(field) => {
                write!(formatter, "extractor.{field} must not be empty")
            }
            Self::InvalidConfigurationDigest => {
                formatter.write_str("extractor.configuration_sha256 is not a SHA-256 digest")
            }
            Self::InvalidRunId => formatter.write_str("run_id must use run:<64 lowercase hex>"),
            Self::EmptyReceiptField(field) => {
                write!(formatter, "receipt field {field} must not be empty")
            }
            Self::InvalidReceiptDigest(field) => {
                write!(formatter, "receipt field {field} is not a SHA-256 digest")
            }
            Self::UnsupportedDigestProfile(profile) => {
                write!(
                    formatter,
                    "unsupported normalized-record digest profile {profile:?}"
                )
            }
            Self::UnsuccessfulToolReceipt(tool) => {
                write!(
                    formatter,
                    "successful run receipt has nonzero {tool} exit code"
                )
            }
            Self::UnexpectedToolReceipt { expected, actual } => {
                write!(
                    formatter,
                    "expected {expected} tool receipt, got {actual:?}"
                )
            }
            Self::MissingStagedCapturePlaceholder(tool) => write!(
                formatter,
                "{tool} argument template must contain $STAGED_CAPTURE exactly once"
            ),
            Self::InconsistentCaptureFileTimes => formatter.write_str(
                "capture-file packet count, duration, and earliest/latest times are inconsistent",
            ),
            Self::PassivePolicyHasActiveActions => {
                formatter.write_str("passive artifact policy cannot name active actions")
            }
            Self::InconsistentNormalization => formatter.write_str(
                "complete normalization cannot have quarantines or a reached packet limit",
            ),
            Self::ZeroFrameNumber => formatter.write_str("frame number must be greater than zero"),
            Self::UnexpectedRecordId => {
                formatter.write_str("record_id must be <capture_id>:frame:<frame number>")
            }
            Self::CapturedLengthExceedsOriginal => {
                formatter.write_str("captured frame length exceeds original frame length")
            }
            Self::InvalidEthernetAddress(value) => {
                write!(formatter, "invalid Ethernet address {value:?}")
            }
            Self::InvalidIpv4Address(value) => write!(formatter, "invalid IPv4 address {value:?}"),
            Self::InvalidIpv6Address(value) => write!(formatter, "invalid IPv6 address {value:?}"),
            Self::InvalidIeee80211FrameType(value) => {
                write!(formatter, "invalid IEEE 802.11 frame type {value}")
            }
            Self::InvalidIeee80211FrameSubtype(value) => {
                write!(formatter, "invalid IEEE 802.11 frame subtype {value}")
            }
            Self::InvalidSsidHex => formatter.write_str(
                "IEEE 802.11 SSID must be 1..=32 octets encoded as lowercase hexadecimal",
            ),
            Self::EmptyWlanRadioFields => {
                formatter.write_str("WLAN radio field group must not be empty")
            }
            Self::ZeroWlanChannel => formatter.write_str("WLAN channel must be greater than zero"),
            Self::ZeroWlanCenterFrequency => {
                formatter.write_str("WLAN center frequency must be greater than zero")
            }
            Self::ZeroSourceLine => {
                formatter.write_str("quarantine source_line must be greater than zero")
            }
            Self::EmptyQuarantineReason => {
                formatter.write_str("quarantine reason must not be empty")
            }
        }
    }
}

impl std::error::Error for CaptureValidationError {}

impl CaptureManifestV0 {
    pub fn validate(&self) -> Result<(), CaptureValidationError> {
        validate_schema(&self.schema, CAPTURE_MANIFEST_SCHEMA_V0)?;
        validate_capture_id(&self.capture_id)?;
        if self.capture_id != self.artifact.content_sha256 {
            return Err(CaptureValidationError::CaptureIdDoesNotMatchArtifact);
        }
        if self
            .observer_id
            .as_deref()
            .is_some_and(|observer| observer.trim().is_empty())
        {
            return Err(CaptureValidationError::EmptyObserverId);
        }
        for (field, value) in [
            ("adapter", self.extractor.adapter.as_str()),
            ("adapter_version", self.extractor.adapter_version.as_str()),
            ("tool", self.extractor.tool.as_str()),
            ("tool_version", self.extractor.tool_version.as_str()),
            (
                "configuration_sha256",
                self.extractor.configuration_sha256.as_str(),
            ),
            ("field_registry", self.extractor.field_registry.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(CaptureValidationError::EmptyExtractorField(field));
            }
        }
        if validate_capture_id(&self.extractor.configuration_sha256).is_err() {
            return Err(CaptureValidationError::InvalidConfigurationDigest);
        }
        if self
            .acquisition_policy
            .as_ref()
            .is_some_and(|policy| policy.is_passive() && !policy.active_actions.is_empty())
        {
            return Err(CaptureValidationError::PassivePolicyHasActiveActions);
        }
        if self.normalization.state == NormalizationStateV0::Complete
            && (self.normalization.packet_limit_reached
                || self.normalization.packet_rows_quarantined != 0)
        {
            return Err(CaptureValidationError::InconsistentNormalization);
        }
        Ok(())
    }
}

impl PacketEnvelopeV0 {
    pub fn validate(&self) -> Result<(), CaptureValidationError> {
        validate_schema(&self.schema, PACKET_ENVELOPE_SCHEMA_V0)?;
        validate_capture_id(&self.capture_id)?;
        if self.frame.number == 0 {
            return Err(CaptureValidationError::ZeroFrameNumber);
        }
        if self.record_id != format!("{}:frame:{}", self.capture_id, self.frame.number) {
            return Err(CaptureValidationError::UnexpectedRecordId);
        }
        if self.frame.captured_len > self.frame.original_len {
            return Err(CaptureValidationError::CapturedLengthExceedsOriginal);
        }
        if let Some(ethernet) = &self.ethernet {
            for address in [ethernet.source.as_deref(), ethernet.destination.as_deref()]
                .into_iter()
                .flatten()
            {
                if !is_ethernet_address(address) {
                    return Err(CaptureValidationError::InvalidEthernetAddress(
                        address.to_owned(),
                    ));
                }
            }
        }
        if let Some(ipv4) = &self.ipv4 {
            for address in [&ipv4.source, &ipv4.destination] {
                if address.parse::<Ipv4Addr>().is_err() {
                    return Err(CaptureValidationError::InvalidIpv4Address(
                        address.to_string(),
                    ));
                }
            }
        }
        if let Some(ipv6) = &self.ipv6 {
            for address in [&ipv6.source, &ipv6.destination] {
                if address.parse::<Ipv6Addr>().is_err() {
                    return Err(CaptureValidationError::InvalidIpv6Address(
                        address.to_string(),
                    ));
                }
            }
        }
        if let Some(ieee80211) = &self.ieee80211 {
            if ieee80211.frame_type > 3 {
                return Err(CaptureValidationError::InvalidIeee80211FrameType(
                    ieee80211.frame_type,
                ));
            }
            if ieee80211.frame_subtype > 15 {
                return Err(CaptureValidationError::InvalidIeee80211FrameSubtype(
                    ieee80211.frame_subtype,
                ));
            }
            for address in [
                ieee80211.transmitter.as_deref(),
                ieee80211.receiver.as_deref(),
                ieee80211.source.as_deref(),
                ieee80211.destination.as_deref(),
                ieee80211.bssid.as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                if !is_ethernet_address(address) {
                    return Err(CaptureValidationError::InvalidEthernetAddress(
                        address.to_owned(),
                    ));
                }
            }
            if ieee80211
                .ssid_hex
                .as_deref()
                .is_some_and(|ssid| !is_lower_hex_bytes(ssid, 32))
            {
                return Err(CaptureValidationError::InvalidSsidHex);
            }
        }
        if let Some(radio) = &self.wlan_radio {
            if radio.channel.is_none()
                && radio.center_frequency_mhz.is_none()
                && radio.signal_dbm.is_none()
            {
                return Err(CaptureValidationError::EmptyWlanRadioFields);
            }
            if radio.channel == Some(0) {
                return Err(CaptureValidationError::ZeroWlanChannel);
            }
            if radio.center_frequency_mhz == Some(0) {
                return Err(CaptureValidationError::ZeroWlanCenterFrequency);
            }
        }
        Ok(())
    }
}

impl CaptureRunReceiptV0 {
    pub fn validate(&self) -> Result<(), CaptureValidationError> {
        validate_schema(&self.schema, CAPTURE_RUN_RECEIPT_SCHEMA_V0)?;
        validate_capture_id(&self.capture_id)?;
        validate_run_id(&self.run_id)?;
        for (field, value) in [
            ("file.file_type", self.file.file_type.as_str()),
            ("file.encapsulation", self.file.encapsulation.as_str()),
            (
                "file.timestamp_precision",
                self.file.timestamp_precision.as_str(),
            ),
            ("configuration_sha256", self.configuration_sha256.as_str()),
            ("field_registry", self.field_registry.as_str()),
            (
                "normalized_records_digest_profile",
                self.normalized_records_digest_profile.as_str(),
            ),
            (
                "normalized_records_sha256",
                self.normalized_records_sha256.as_str(),
            ),
        ] {
            if value.trim().is_empty() {
                return Err(CaptureValidationError::EmptyReceiptField(field));
            }
        }
        for (field, value) in [
            ("configuration_sha256", self.configuration_sha256.as_str()),
            (
                "normalized_records_sha256",
                self.normalized_records_sha256.as_str(),
            ),
        ] {
            if validate_capture_id(value).is_err() {
                return Err(CaptureValidationError::InvalidReceiptDigest(field));
            }
        }
        if self.normalized_records_digest_profile != NORMALIZED_RECORDS_DIGEST_PROFILE_V0 {
            return Err(CaptureValidationError::UnsupportedDigestProfile(
                self.normalized_records_digest_profile.clone(),
            ));
        }
        validate_tool_receipt("capinfos", &self.capinfos)?;
        validate_tool_receipt("tshark", &self.tshark)?;

        match (
            self.file.packet_count,
            self.file.duration_ns,
            self.file.earliest_packet_time_unix_ns,
            self.file.latest_packet_time_unix_ns,
        ) {
            (0, None, None, None) => {}
            (count, Some(_), Some(earliest), Some(latest)) if count > 0 && earliest <= latest => {}
            _ => return Err(CaptureValidationError::InconsistentCaptureFileTimes),
        }
        Ok(())
    }
}

impl PacketQuarantineV0 {
    pub fn validate(&self) -> Result<(), CaptureValidationError> {
        validate_schema(&self.schema, PACKET_QUARANTINE_SCHEMA_V0)?;
        validate_capture_id(&self.capture_id)?;
        if self.source_line == 0 {
            return Err(CaptureValidationError::ZeroSourceLine);
        }
        if self.reason.trim().is_empty() {
            return Err(CaptureValidationError::EmptyQuarantineReason);
        }
        Ok(())
    }
}

fn validate_schema(actual: &str, expected: &str) -> Result<(), CaptureValidationError> {
    if actual == expected {
        Ok(())
    } else {
        Err(CaptureValidationError::UnsupportedSchema(actual.to_owned()))
    }
}

fn validate_capture_id(value: &str) -> Result<(), CaptureValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(CaptureValidationError::InvalidCaptureId);
    };
    if hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(CaptureValidationError::InvalidCaptureId)
    }
}

fn validate_run_id(value: &str) -> Result<(), CaptureValidationError> {
    let Some(hex) = value.strip_prefix("run:") else {
        return Err(CaptureValidationError::InvalidRunId);
    };
    if is_lower_hex_sha256(hex) {
        Ok(())
    } else {
        Err(CaptureValidationError::InvalidRunId)
    }
}

fn validate_tool_receipt(
    expected_tool: &'static str,
    receipt: &ToolRunReceiptV0,
) -> Result<(), CaptureValidationError> {
    for (field, value) in [
        ("tool", receipt.tool.as_str()),
        (
            "configured_executable",
            receipt.configured_executable.as_str(),
        ),
        ("tool_version", receipt.tool_version.as_str()),
        ("environment_policy", receipt.environment_policy.as_str()),
    ] {
        if value.trim().is_empty() {
            return Err(CaptureValidationError::EmptyReceiptField(field));
        }
    }
    if receipt.tool != expected_tool {
        return Err(CaptureValidationError::UnexpectedToolReceipt {
            expected: expected_tool,
            actual: receipt.tool.clone(),
        });
    }
    if receipt.exit_code != 0 {
        return Err(CaptureValidationError::UnsuccessfulToolReceipt(
            expected_tool,
        ));
    }
    for (field, value) in [
        ("stdout_sha256", receipt.stdout_sha256.as_str()),
        ("stderr_sha256", receipt.stderr_sha256.as_str()),
    ] {
        if validate_capture_id(value).is_err() {
            return Err(CaptureValidationError::InvalidReceiptDigest(field));
        }
    }
    if receipt
        .argument_template
        .iter()
        .filter(|argument| argument.as_str() == "$STAGED_CAPTURE")
        .count()
        != 1
    {
        return Err(CaptureValidationError::MissingStagedCapturePlaceholder(
            expected_tool,
        ));
    }
    Ok(())
}

fn is_lower_hex_sha256(hex: &str) -> bool {
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lower_hex_bytes(hex: &str, maximum_bytes: usize) -> bool {
    !hex.is_empty()
        && hex.len().is_multiple_of(2)
        && hex.len() <= maximum_bytes * 2
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_ethernet_address(value: &str) -> bool {
    let mut parts = value.split(':');
    (0..6).all(|_| {
        parts.next().is_some_and(|part| {
            part.len() == 2 && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none()
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn manifest() -> CaptureManifestV0 {
        CaptureManifestV0 {
            schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
            capture_id: DIGEST.into(),
            artifact: CaptureArtifactRefV0 {
                content_sha256: DIGEST.into(),
                size_bytes: 136,
            },
            observer_id: Some("sensor-a".into()),
            acquired_time_unix_ms: None,
            extractor: CaptureExtractorRefV0 {
                adapter: "netbraid-adapter-tshark".into(),
                adapter_version: "0.2.0".into(),
                tool: "tshark".into(),
                tool_version: "TShark (Wireshark) 4.6.7".into(),
                configuration_sha256: DIGEST.into(),
                field_registry: "netmon.tshark.packet_envelope.v0".into(),
            },
            acquisition_policy: None,
            normalization: CaptureNormalizationV0 {
                state: NormalizationStateV0::Partial,
                packet_limit: 1_000,
                packet_limit_reached: false,
                packet_rows_emitted: 1,
                packet_rows_quarantined: 1,
            },
        }
    }

    fn packet() -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{DIGEST}:frame:1"),
            capture_id: DIGEST.into(),
            frame: PacketFrameV0 {
                number: 1,
                event_time_unix_ns: 1_700_000_000_123_456_789,
                original_len: 74,
                captured_len: 74,
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(1),
                protocols: vec!["eth".into(), "ethertype".into(), "ip".into(), "tcp".into()],
            },
            ethernet: Some(EthernetFieldsV0 {
                source: Some("02:00:00:00:00:01".into()),
                destination: Some("02:00:00:00:00:02".into()),
            }),
            ipv4: Some(Ipv4FieldsV0 {
                source: "192.0.2.1".into(),
                destination: "198.51.100.2".into(),
                protocol: 6,
            }),
            ipv6: None,
            tcp: Some(TcpFieldsV0 {
                source_port: 40_000,
                destination_port: 443,
                flags: 2,
            }),
            udp: None,
            ieee80211: None,
            wlan_radio: None,
        }
    }

    fn wireless_packet() -> PacketEnvelopeV0 {
        PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{DIGEST}:frame:2"),
            capture_id: DIGEST.into(),
            frame: PacketFrameV0 {
                number: 2,
                event_time_unix_ns: 1_700_000_000_223_456_789,
                original_len: 144,
                captured_len: 144,
                section_number: Some(0),
                interface_id: Some(0),
                encapsulation_type: Some(23),
                protocols: vec!["radiotap".into(), "wlan_radio".into(), "wlan".into()],
            },
            ethernet: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            ieee80211: Some(Ieee80211FieldsV0 {
                frame_type: 0,
                frame_subtype: 5,
                transmitter: Some("02:00:00:00:00:01".into()),
                receiver: Some("ff:ff:ff:ff:ff:ff".into()),
                source: Some("02:00:00:00:00:01".into()),
                destination: Some("ff:ff:ff:ff:ff:ff".into()),
                bssid: Some("02:00:00:00:00:01".into()),
                ssid_hex: Some("6f6d7573".into()),
            }),
            wlan_radio: Some(WlanRadioFieldsV0 {
                channel: Some(1),
                center_frequency_mhz: Some(2412),
                signal_dbm: Some(-74),
            }),
        }
    }

    fn quarantine() -> PacketQuarantineV0 {
        PacketQuarantineV0 {
            schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
            capture_id: DIGEST.into(),
            source_line: 2,
            frame_number_hint: Some(2),
            reason: "invalid frame.time_epoch: expected seconds.nanoseconds".into(),
            raw_row: "2\tinvalid".into(),
        }
    }

    fn receipt() -> CaptureRunReceiptV0 {
        let tool = |name: &str| ToolRunReceiptV0 {
            tool: name.into(),
            configured_executable: name.into(),
            tool_version: format!("{name} (Wireshark) 4.6.7"),
            argument_template: vec!["-r".into(), "$STAGED_CAPTURE".into()],
            environment_policy: "netmon.wireshark.environment.v0".into(),
            exit_code: 0,
            stdout_sha256: DIGEST.into(),
            stderr_sha256: DIGEST.into(),
        };
        CaptureRunReceiptV0 {
            schema: CAPTURE_RUN_RECEIPT_SCHEMA_V0.into(),
            run_id: "run:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into(),
            capture_id: DIGEST.into(),
            started_time_unix_ns: 1_700_000_001_000_000_000,
            finished_time_unix_ns: 1_700_000_001_250_000_000,
            elapsed_ns: 250_000_000,
            file: CaptureFileMetadataV0 {
                file_type: "pcapng".into(),
                encapsulation: "ether".into(),
                timestamp_precision: "nanoseconds".into(),
                packet_count: 2,
                file_size_bytes: 136,
                original_data_size_bytes: 128,
                snaplen: None,
                inferred_snaplen_min: None,
                inferred_snaplen_max: None,
                duration_ns: Some(100_000_000),
                earliest_packet_time_unix_ns: Some(1_700_000_000_123_456_789),
                latest_packet_time_unix_ns: Some(1_700_000_000_223_456_789),
                capture_hardware: Some("sensor-a".into()),
                capture_operating_system: Some("NetBSD".into()),
                capture_application: Some("dumpcap".into()),
            },
            capinfos: tool("capinfos"),
            tshark: tool("tshark"),
            configuration_sha256: DIGEST.into(),
            field_registry: "netmon.tshark.packet_envelope.v0".into(),
            normalized_records_digest_profile: NORMALIZED_RECORDS_DIGEST_PROFILE_V0.into(),
            normalized_records_sha256:
                "sha256:654cf1daa95a56dd42ae9aa133528bd7a7e840edbde60daecd77ed553b52b635".into(),
        }
    }

    #[test]
    fn manifest_requires_honest_complete_normalization() {
        let mut value = manifest();
        value.normalization.state = NormalizationStateV0::Complete;

        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::InconsistentNormalization)
        );
    }

    #[test]
    fn golden_manifest_json_preserves_extractor_and_normalization_provenance() {
        let value = manifest();
        value.validate().unwrap();

        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            include_str!("../tests/fixtures/v0/capture_manifest_v0.json")
        );
    }

    #[test]
    fn packet_rejects_cross_layer_length_and_address_errors() {
        let mut value = packet();
        value.frame.captured_len = 75;
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::CapturedLengthExceedsOriginal)
        );

        let mut value = packet();
        value.ipv4.as_mut().unwrap().source = "2001:db8::1".into();
        assert!(matches!(
            value.validate(),
            Err(CaptureValidationError::InvalidIpv4Address(_))
        ));
    }

    #[test]
    fn packet_validates_wireless_groups_without_inventing_missing_evidence() {
        let mut value = packet();
        value.ieee80211 = Some(Ieee80211FieldsV0 {
            frame_type: 0,
            frame_subtype: 5,
            transmitter: Some("02:00:00:00:00:01".into()),
            receiver: None,
            source: None,
            destination: None,
            bssid: Some("02:00:00:00:00:01".into()),
            ssid_hex: Some("6f6d7573".into()),
        });
        value.wlan_radio = Some(WlanRadioFieldsV0 {
            channel: Some(1),
            center_frequency_mhz: Some(2412),
            signal_dbm: Some(-74),
        });
        value.validate().unwrap();

        value.ieee80211.as_mut().unwrap().ssid_hex = Some(String::new());
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::InvalidSsidHex)
        );

        value.ieee80211.as_mut().unwrap().ssid_hex = None;
        value.wlan_radio = Some(WlanRadioFieldsV0 {
            channel: None,
            center_frequency_mhz: None,
            signal_dbm: None,
        });
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::EmptyWlanRadioFields)
        );

        let mut value = wireless_packet();
        value.ieee80211.as_mut().unwrap().frame_type = 4;
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::InvalidIeee80211FrameType(4))
        );

        let mut value = wireless_packet();
        value.ieee80211.as_mut().unwrap().frame_subtype = 16;
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::InvalidIeee80211FrameSubtype(16))
        );

        let mut value = wireless_packet();
        value.wlan_radio.as_mut().unwrap().channel = Some(0);
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::ZeroWlanChannel)
        );

        let mut value = wireless_packet();
        value.wlan_radio.as_mut().unwrap().center_frequency_mhz = Some(0);
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::ZeroWlanCenterFrequency)
        );
    }

    #[test]
    fn golden_packet_json_preserves_protocol_order_and_exact_time() {
        let value = packet();
        value.validate().unwrap();

        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            include_str!("../tests/fixtures/v0/packet_envelope_v0.json")
        );
    }

    #[test]
    fn golden_wireless_packet_json_preserves_header_bytes_and_radio_metadata() {
        let value = wireless_packet();
        value.validate().unwrap();

        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            include_str!("../tests/fixtures/v0/packet_envelope_wlan_v0.json")
        );
    }

    #[test]
    fn receipt_requires_success_and_consistent_file_extent() {
        let mut value = receipt();
        value.capinfos.exit_code = 2;
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::UnsuccessfulToolReceipt("capinfos"))
        );

        let mut value = receipt();
        value.file.latest_packet_time_unix_ns = None;
        assert_eq!(
            value.validate(),
            Err(CaptureValidationError::InconsistentCaptureFileTimes)
        );
    }

    #[test]
    fn golden_receipt_json_preserves_tool_and_file_provenance() {
        let value = receipt();
        value.validate().unwrap();

        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            include_str!("../tests/fixtures/v0/capture_run_receipt_v0.json")
        );
    }

    #[test]
    fn golden_quarantine_json_preserves_raw_invalid_row() {
        let value = quarantine();
        value.validate().unwrap();

        assert_eq!(
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
            include_str!("../tests/fixtures/v0/packet_quarantine_v0.json")
        );
    }
}
