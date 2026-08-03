use std::collections::BTreeMap;

use crate::evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, Ieee802154AddressV0, Ieee802154FcsStatusV0,
    NormalizationStateV0,
};
use serde::{Deserialize, Serialize};

use crate::replay::triage::{
    project_saved_pcap_triage, SavedPcapClaimScopeV0, SavedPcapCompletenessV0,
    SavedPcapTriageProjectionError,
};
use crate::replay::SavedCaptureRecordStreamV0;

pub const SAVED_PCAP_IEEE802154_PROJECTION_SCHEMA_V0: &str =
    "netmon.saved_pcap_ieee802154_projection.v0";

const LIMITATIONS: &[&str] = &[
    "aggregate over validated PacketEnvelopeV0.ieee802154 evidence; no raw DLT decoding",
    "complete_capture applies to normalization completeness, not continuous RF observation",
    "normalized_packet_subset cannot support capture-wide negative claims",
    "address values, PAN identifiers, sequence numbers, and observer identifiers are excluded",
    "command values are frame fields, not device, role, or behavior identity",
    "FCS availability depends on the saved capture and upstream dissector evidence",
    "no payload retention, cross-observer join, or device, person, place, or intent inference",
];

/// Identifier-free provenance for one saved-capture projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154SourceV0 {
    pub artifact: CaptureArtifactRefV0,
    pub extractor: CaptureExtractorRefV0,
    pub normalized_records_sha256: String,
}

/// Completeness boundary inherited from the validated normalization manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154CompletenessV0 {
    pub state: NormalizationStateV0,
    pub scope: SavedPcapClaimScopeV0,
    pub packet_limit: u64,
    pub packet_limit_reached: bool,
}

/// Record counts for the validated stream and its IEEE 802.15.4 subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154CountsV0 {
    pub packet_envelopes: u64,
    pub packet_quarantines: u64,
    pub packet_rows_inspected: u64,
    pub ieee802154_frames: u64,
    pub other_packet_envelopes: u64,
}

/// Count for one observed frame-type and frame-version pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154FrameMixV0 {
    pub frame_type: u8,
    pub frame_version: u8,
    pub frames: u64,
}

/// Aggregate coverage of one source or destination address field.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154AddressFormsV0 {
    pub absent_frames: u64,
    pub short_frames: u64,
    pub extended_frames: u64,
}

/// Source and destination address-form coverage without address values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154AddressCoverageV0 {
    pub destination: SavedPcapIeee802154AddressFormsV0,
    pub source: SavedPcapIeee802154AddressFormsV0,
}

/// Count for one observed MAC command value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154CommandMixV0 {
    pub command: u8,
    pub frames: u64,
}

/// Coverage and value mix for normalized MAC command evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154CommandCoverageV0 {
    pub present_frames: u64,
    pub unavailable_frames: u64,
    pub command_mix: Vec<SavedPcapIeee802154CommandMixV0>,
}

/// Coverage of normalized FCS status evidence.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154FcsCoverageV0 {
    pub valid_frames: u64,
    pub invalid_frames: u64,
    pub unavailable_frames: u64,
}

/// A deterministic, identifier-free projection over normalized IEEE 802.15.4 evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedPcapIeee802154ProjectionV0 {
    pub schema: String,
    pub source: SavedPcapIeee802154SourceV0,
    pub completeness: SavedPcapIeee802154CompletenessV0,
    pub counts: SavedPcapIeee802154CountsV0,
    pub frame_type_version_mix: Vec<SavedPcapIeee802154FrameMixV0>,
    pub address_forms: SavedPcapIeee802154AddressCoverageV0,
    pub commands: SavedPcapIeee802154CommandCoverageV0,
    pub fcs: SavedPcapIeee802154FcsCoverageV0,
    pub limitations: Vec<String>,
}

/// Projects an already-validated saved-capture stream without retaining link-layer identifiers.
pub fn project_saved_pcap_ieee802154_v0(
    records: &SavedCaptureRecordStreamV0,
) -> Result<SavedPcapIeee802154ProjectionV0, SavedPcapTriageProjectionError> {
    let triage = project_saved_pcap_triage(records)?;
    let mut frame_mix = BTreeMap::<(u8, u8), u64>::new();
    let mut destination = SavedPcapIeee802154AddressFormsV0::default();
    let mut source = SavedPcapIeee802154AddressFormsV0::default();
    let mut command_mix = BTreeMap::<u8, u64>::new();
    let mut commands_present = 0;
    let mut fcs = SavedPcapIeee802154FcsCoverageV0::default();
    let mut ieee802154_frames = 0;

    for fields in records
        .packets
        .iter()
        .filter_map(|packet| packet.ieee802154.as_deref())
    {
        ieee802154_frames += 1;
        *frame_mix
            .entry((fields.frame_type, fields.frame_version))
            .or_default() += 1;
        observe_address_form(&mut destination, fields.destination.as_ref());
        observe_address_form(&mut source, fields.source.as_ref());
        if let Some(command) = fields.command {
            commands_present += 1;
            *command_mix.entry(command).or_default() += 1;
        }
        match fields.fcs_status {
            Some(Ieee802154FcsStatusV0::Valid) => fcs.valid_frames += 1,
            Some(Ieee802154FcsStatusV0::Invalid) => fcs.invalid_frames += 1,
            None => fcs.unavailable_frames += 1,
        }
    }

    let scope = match triage.normalization.completeness {
        SavedPcapCompletenessV0::CompleteCapture => SavedPcapClaimScopeV0::CompleteCapture,
        SavedPcapCompletenessV0::PartialPacketSubset => {
            SavedPcapClaimScopeV0::NormalizedPacketSubset
        }
    };
    let packet_envelopes = triage.normalization.packet_rows_emitted;

    Ok(SavedPcapIeee802154ProjectionV0 {
        schema: SAVED_PCAP_IEEE802154_PROJECTION_SCHEMA_V0.to_owned(),
        source: SavedPcapIeee802154SourceV0 {
            artifact: records.manifest.artifact.clone(),
            extractor: records.manifest.extractor.clone(),
            normalized_records_sha256: records.normalized_records_sha256.clone(),
        },
        completeness: SavedPcapIeee802154CompletenessV0 {
            state: triage.normalization.state,
            scope,
            packet_limit: triage.normalization.packet_limit,
            packet_limit_reached: triage.normalization.packet_limit_reached,
        },
        counts: SavedPcapIeee802154CountsV0 {
            packet_envelopes,
            packet_quarantines: triage.normalization.packet_rows_quarantined,
            packet_rows_inspected: triage.normalization.packet_rows_inspected,
            ieee802154_frames,
            other_packet_envelopes: packet_envelopes.saturating_sub(ieee802154_frames),
        },
        frame_type_version_mix: frame_mix
            .into_iter()
            .map(
                |((frame_type, frame_version), frames)| SavedPcapIeee802154FrameMixV0 {
                    frame_type,
                    frame_version,
                    frames,
                },
            )
            .collect(),
        address_forms: SavedPcapIeee802154AddressCoverageV0 {
            destination,
            source,
        },
        commands: SavedPcapIeee802154CommandCoverageV0 {
            present_frames: commands_present,
            unavailable_frames: ieee802154_frames.saturating_sub(commands_present),
            command_mix: command_mix
                .into_iter()
                .map(|(command, frames)| SavedPcapIeee802154CommandMixV0 { command, frames })
                .collect(),
        },
        fcs,
        limitations: LIMITATIONS
            .iter()
            .map(|limitation| (*limitation).to_owned())
            .collect(),
    })
}

fn observe_address_form(
    coverage: &mut SavedPcapIeee802154AddressFormsV0,
    address: Option<&Ieee802154AddressV0>,
) {
    match address {
        Some(Ieee802154AddressV0::Short(_)) => coverage.short_frames += 1,
        Some(Ieee802154AddressV0::Extended(_)) => coverage.extended_frames += 1,
        None => coverage.absent_frames += 1,
    }
}
