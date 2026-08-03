use std::collections::BTreeMap;

use crate::evidence::{
    CaptureExtractorRefV0, CollectionPolicyV0, NormalizationStateV0, PacketEnvelopeV0,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::replay::{SavedCaptureRecordStreamV0, SavedPcapClaimScopeV0};

pub const SAVED_PCAP_WLAN_FINGERPRINT_CANDIDATE_SCHEMA_V0: &str =
    "netmon.saved_pcap_wlan_fingerprint_candidate.v0";

const WLAN_FINGERPRINT_FEATURE_NAMES: &[&str] = &[
    "wlan_frames",
    "radiotap_frames",
    "radio_metadata_frames",
    "ssid_element_frames",
    "frame_mix",
    "channels",
    "center_frequencies_mhz",
    "signal_dbm",
    "observed_span_ns",
];

const WLAN_FINGERPRINT_CAVEATS: &[&str] = &[
    "aggregate over validated 802.11 frames; not a continuous channel observation",
    "MAC addresses, BSSIDs, and SSID bytes are excluded from the comparison digest",
    "radiotap signal values are adapter metadata, not calibrated distance or location",
    "frame shape and radio fields are correlated views of one capture, not independent corroboration",
    "receiver calibration and placement metadata are not asserted by this candidate",
    "no BLE, CSI, spectrum, device, person, place, or intent identity",
];

/// Provenance for one validated 802.11/radiotap candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanFingerprintSourceV0 {
    pub capture_id: String,
    pub normalized_records_sha256: String,
    pub extractor: CaptureExtractorRefV0,
    pub observer_id: Option<String>,
    pub acquisition_policy: Option<CollectionPolicyV0>,
}

/// A count for one observed 802.11 frame type/subtype pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanFrameMixV0 {
    pub frame_type: u8,
    pub frame_subtype: u8,
    pub frames: u64,
}

/// A count for one observed channel or center frequency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanRadioValueV0 {
    pub value: u32,
    pub frames: u64,
}

/// Exact integer signal summary for the observed radiotap metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanSignalSummaryV0 {
    pub samples: u64,
    pub sum_dbm: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minimum_dbm: Option<i8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_dbm: Option<i8>,
}

/// Feature values for one 802.11/radiotap candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanFingerprintBasisV0 {
    pub feature_names: Vec<String>,
    pub wlan_frames: u64,
    pub radiotap_frames: u64,
    pub radio_metadata_frames: u64,
    pub ssid_element_frames: u64,
    pub frame_mix: Vec<SavedPcapWlanFrameMixV0>,
    pub channels: Vec<SavedPcapWlanRadioValueV0>,
    pub center_frequencies_mhz: Vec<SavedPcapWlanRadioValueV0>,
    pub channel_frames: u64,
    pub center_frequency_frames: u64,
    pub signal_frames: u64,
    pub signal_dbm: SavedPcapWlanSignalSummaryV0,
    pub observed_span_ns: u64,
}

/// Why a partial record stream cannot produce an RF candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapWlanFingerprintInsufficientReasonV0 {
    PartialNormalizationWithoutIeee80211FrameEvidence,
}

/// Why a complete record stream is outside this candidate family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedPcapWlanFingerprintUnsupportedReasonV0 {
    NoIeee80211FrameEvidence,
}

/// Status of the separate 802.11/radiotap candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SavedPcapWlanFingerprintStatusV0 {
    Observed {
        digest: String,
        basis: Box<SavedPcapWlanFingerprintBasisV0>,
        caveats: Vec<String>,
    },
    Insufficient {
        reason: SavedPcapWlanFingerprintInsufficientReasonV0,
        normalized_packets: u64,
    },
    Unsupported {
        reason: SavedPcapWlanFingerprintUnsupportedReasonV0,
        normalized_packets: u64,
    },
}

/// A source-preserving RF candidate for later, separately gated comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapWlanFingerprintCandidateV0 {
    pub schema: String,
    pub source: SavedPcapWlanFingerprintSourceV0,
    pub scope: SavedPcapClaimScopeV0,
    pub status: SavedPcapWlanFingerprintStatusV0,
}

/// Projects validated 802.11/radiotap packet evidence without reparsing raw input.
pub fn project_saved_pcap_wlan_fingerprint_v0(
    records: &SavedCaptureRecordStreamV0,
) -> SavedPcapWlanFingerprintCandidateV0 {
    let source = SavedPcapWlanFingerprintSourceV0 {
        capture_id: records.manifest.capture_id.clone(),
        normalized_records_sha256: records.normalized_records_sha256.clone(),
        extractor: records.manifest.extractor.clone(),
        observer_id: records.manifest.observer_id.clone(),
        acquisition_policy: records.manifest.acquisition_policy.clone(),
    };
    let scope = match records.manifest.normalization.state {
        NormalizationStateV0::Complete => SavedPcapClaimScopeV0::CompleteCapture,
        NormalizationStateV0::Partial => SavedPcapClaimScopeV0::NormalizedPacketSubset,
    };
    let wlan_packets: Vec<_> = records
        .packets
        .iter()
        .filter(|packet| packet.ieee80211.is_some())
        .collect();

    let status = if wlan_packets.is_empty() {
        match records.manifest.normalization.state {
            NormalizationStateV0::Complete => SavedPcapWlanFingerprintStatusV0::Unsupported {
                reason: SavedPcapWlanFingerprintUnsupportedReasonV0::NoIeee80211FrameEvidence,
                normalized_packets: records.packets.len() as u64,
            },
            NormalizationStateV0::Partial => SavedPcapWlanFingerprintStatusV0::Insufficient {
                reason:
                    SavedPcapWlanFingerprintInsufficientReasonV0::
                        PartialNormalizationWithoutIeee80211FrameEvidence,
                normalized_packets: records.packets.len() as u64,
            },
        }
    } else {
        let basis = wlan_basis(&wlan_packets);
        SavedPcapWlanFingerprintStatusV0::Observed {
            digest: wlan_digest(&basis),
            basis: Box::new(basis),
            caveats: WLAN_FINGERPRINT_CAVEATS
                .iter()
                .map(|caveat| (*caveat).to_owned())
                .collect(),
        }
    };

    SavedPcapWlanFingerprintCandidateV0 {
        schema: SAVED_PCAP_WLAN_FINGERPRINT_CANDIDATE_SCHEMA_V0.to_owned(),
        source,
        scope,
        status,
    }
}

fn wlan_basis(packets: &[&PacketEnvelopeV0]) -> SavedPcapWlanFingerprintBasisV0 {
    let mut frame_mix = BTreeMap::<(u8, u8), u64>::new();
    let mut channels = BTreeMap::<u32, u64>::new();
    let mut frequencies = BTreeMap::<u32, u64>::new();
    let mut signal_samples = Vec::new();
    let mut channel_frames = 0;
    let mut center_frequency_frames = 0;
    let mut signal_frames = 0;
    let mut radiotap_frames = 0;
    let mut ssid_element_frames = 0;
    let mut earliest = i64::MAX;
    let mut latest = i64::MIN;

    for packet in packets {
        let wlan = packet
            .ieee80211
            .as_ref()
            .expect("wlan packets are filtered");
        *frame_mix
            .entry((wlan.frame_type, wlan.frame_subtype))
            .or_default() += 1;
        if packet
            .frame
            .protocols
            .iter()
            .any(|protocol| protocol == "radiotap")
        {
            radiotap_frames += 1;
        }
        if wlan.ssid_hex.is_some() {
            ssid_element_frames += 1;
        }
        earliest = earliest.min(packet.frame.event_time_unix_ns);
        latest = latest.max(packet.frame.event_time_unix_ns);
        if let Some(radio) = &packet.wlan_radio {
            if let Some(channel) = radio.channel {
                channel_frames += 1;
                *channels.entry(channel).or_default() += 1;
            }
            if let Some(frequency) = radio.center_frequency_mhz {
                center_frequency_frames += 1;
                *frequencies.entry(u32::from(frequency)).or_default() += 1;
            }
            if let Some(signal) = radio.signal_dbm {
                signal_frames += 1;
                signal_samples.push(signal);
            }
        }
    }

    SavedPcapWlanFingerprintBasisV0 {
        feature_names: WLAN_FINGERPRINT_FEATURE_NAMES
            .iter()
            .map(|name| (*name).to_owned())
            .collect(),
        wlan_frames: packets.len() as u64,
        radiotap_frames,
        radio_metadata_frames: radio_metadata_frame_count(packets),
        ssid_element_frames,
        frame_mix: frame_mix
            .into_iter()
            .map(
                |((frame_type, frame_subtype), frames)| SavedPcapWlanFrameMixV0 {
                    frame_type,
                    frame_subtype,
                    frames,
                },
            )
            .collect(),
        channels: histogram(channels),
        center_frequencies_mhz: histogram(frequencies),
        channel_frames,
        center_frequency_frames,
        signal_frames,
        signal_dbm: signal_summary(&signal_samples),
        observed_span_ns: latest.saturating_sub(earliest) as u64,
    }
}

fn radio_metadata_frame_count(packets: &[&PacketEnvelopeV0]) -> u64 {
    packets
        .iter()
        .filter(|packet| packet.wlan_radio.is_some())
        .count() as u64
}

fn histogram(values: BTreeMap<u32, u64>) -> Vec<SavedPcapWlanRadioValueV0> {
    values
        .into_iter()
        .map(|(value, frames)| SavedPcapWlanRadioValueV0 { value, frames })
        .collect()
}

fn signal_summary(values: &[i8]) -> SavedPcapWlanSignalSummaryV0 {
    SavedPcapWlanSignalSummaryV0 {
        samples: values.len() as u64,
        sum_dbm: values.iter().map(|value| i64::from(*value)).sum(),
        minimum_dbm: values.iter().copied().min(),
        maximum_dbm: values.iter().copied().max(),
    }
}

fn wlan_digest(basis: &SavedPcapWlanFingerprintBasisV0) -> String {
    let encoded = serde_json::to_vec(basis).expect("WLAN fingerprint basis is serializable");
    let mut hasher = Sha256::new();
    hasher.update(SAVED_PCAP_WLAN_FINGERPRINT_CANDIDATE_SCHEMA_V0.as_bytes());
    hasher.update([0]);
    hasher.update(encoded);
    let hex = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("sha256:{hex}")
}
