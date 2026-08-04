use serde::{Deserialize, Serialize};

use super::{is_ethernet_address, CaptureValidationError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BluetoothLeRadioFieldsV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal_dbm: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise_dbm: Option<i8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BluetoothLeCrcStatusV0 {
    Valid,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BluetoothLeFieldsV0 {
    pub access_address: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertising_pdu_type: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_length_octets: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertising_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scanning_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_link_identifier: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_opcode: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transmitter_address_random: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver_address_random: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crc_status: Option<BluetoothLeCrcStatusV0>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub radio: Option<BluetoothLeRadioFieldsV0>,
}

pub(super) fn validate(fields: &BluetoothLeFieldsV0) -> Result<(), CaptureValidationError> {
    if let Some(value @ 16..) = fields.advertising_pdu_type {
        return Err(CaptureValidationError::InvalidBluetoothLeAdvertisingPduType(value));
    }
    if let Some(value @ 4..) = fields.logical_link_identifier {
        return Err(CaptureValidationError::InvalidBluetoothLeLogicalLinkIdentifier(value));
    }
    for address in [
        fields.advertising_address.as_deref(),
        fields.scanning_address.as_deref(),
        fields.initiator_address.as_deref(),
        fields.target_address.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        if !is_ethernet_address(address) {
            return Err(CaptureValidationError::InvalidBluetoothLeAddress(
                address.to_owned(),
            ));
        }
    }
    if let Some(radio) = &fields.radio {
        if radio.channel.is_none() && radio.signal_dbm.is_none() && radio.noise_dbm.is_none() {
            return Err(CaptureValidationError::EmptyBluetoothLeRadioFields);
        }
        if let Some(channel @ 40..) = radio.channel {
            return Err(CaptureValidationError::InvalidBluetoothLeChannel(channel));
        }
    }
    Ok(())
}
