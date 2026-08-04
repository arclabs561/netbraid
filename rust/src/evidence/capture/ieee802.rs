use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum Ieee802154AddressV0 {
    Short(u16),
    Extended(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ieee802154FcsStatusV0 {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ieee802154FieldsV0 {
    pub frame_type: u8,
    pub frame_version: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence_number: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_pan_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<Ieee802154AddressV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_pan_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Ieee802154AddressV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fcs_status: Option<Ieee802154FcsStatusV0>,
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
