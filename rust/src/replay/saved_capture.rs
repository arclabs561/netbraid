use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::evidence::digest::NormalizedRecordsDigest;
use crate::evidence::{
    CaptureManifestV0, CaptureRunReceiptV0, CaptureValidationError, PacketEnvelopeV0,
    PacketQuarantineV0, CAPTURE_MANIFEST_SCHEMA_V0, CAPTURE_RUN_RECEIPT_SCHEMA_V0,
    PACKET_ENVELOPE_SCHEMA_V0, PACKET_QUARANTINE_SCHEMA_V0,
};
use serde_json::Value;

/// A validated saved-capture record stream.
///
/// The optional receipt distinguishes the occurrence-specific `--jsonl`
/// projection from the deterministic `--records-jsonl` projection. The digest
/// is always recomputed from the manifest, packets, and quarantines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedCaptureRecordStreamV0 {
    pub manifest: CaptureManifestV0,
    pub receipt: Option<CaptureRunReceiptV0>,
    pub packets: Vec<PacketEnvelopeV0>,
    pub quarantines: Vec<PacketQuarantineV0>,
    pub normalized_records_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SavedCaptureRecordFamilyV0 {
    Manifest,
    Receipt,
    Packet,
    Quarantine,
}

impl std::fmt::Display for SavedCaptureRecordFamilyV0 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Manifest => "manifest",
            Self::Receipt => "receipt",
            Self::Packet => "packet",
            Self::Quarantine => "quarantine",
        })
    }
}

#[derive(Debug)]
pub enum SavedCaptureReadError {
    Io(io::Error),
    Json {
        line: usize,
        source: serde_json::Error,
    },
    MissingSchema {
        line: usize,
    },
    NonStringSchema {
        line: usize,
    },
    UnsupportedSchema {
        line: usize,
        schema: String,
    },
    NonCanonicalRecord {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
    },
    InvalidRecord {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
        source: CaptureValidationError,
    },
    MissingManifest {
        line: usize,
    },
    DuplicateManifest {
        line: usize,
        first_line: usize,
    },
    DuplicateReceipt {
        line: usize,
        first_line: usize,
    },
    RecordOrder {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
        expected: &'static str,
    },
    CaptureIdMismatch {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
        expected: String,
        actual: String,
    },
    ManifestCountMismatch {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
        declared: u64,
        actual: u64,
    },
    PacketFrameOrder {
        line: usize,
        previous_line: usize,
        previous_frame_number: u64,
        frame_number: u64,
    },
    QuarantineSourceLineOrder {
        line: usize,
        previous_line: usize,
        previous_source_line: u64,
        source_line: u64,
    },
    ReceiptConfigurationMismatch {
        line: usize,
    },
    ReceiptFieldRegistryMismatch {
        line: usize,
    },
    ReceiptFileSizeMismatch {
        line: usize,
        manifest_size_bytes: u64,
        receipt_size_bytes: u64,
    },
    ReceiptNormalizedCountMismatch {
        line: usize,
        normalized_rows: u128,
        expected_rows: u64,
        packet_count: u64,
        packet_limit: u64,
    },
    ReceiptPacketLimitReachedMismatch {
        line: usize,
        packet_count: u64,
        packet_limit: u64,
        declared: bool,
        expected: bool,
    },
    ReceiptDigestMismatch {
        line: usize,
        declared: String,
        recomputed: String,
    },
    RecordSerialization {
        line: usize,
        family: SavedCaptureRecordFamilyV0,
        source: serde_json::Error,
    },
    InputTooLarge {
        max_bytes: u64,
    },
}

impl SavedCaptureReadError {
    pub fn line(&self) -> Option<usize> {
        match self {
            Self::Io(_) => None,
            Self::Json { line, .. }
            | Self::MissingSchema { line }
            | Self::NonStringSchema { line }
            | Self::UnsupportedSchema { line, .. }
            | Self::NonCanonicalRecord { line, .. }
            | Self::InvalidRecord { line, .. }
            | Self::MissingManifest { line }
            | Self::DuplicateManifest { line, .. }
            | Self::DuplicateReceipt { line, .. }
            | Self::RecordOrder { line, .. }
            | Self::CaptureIdMismatch { line, .. }
            | Self::ManifestCountMismatch { line, .. }
            | Self::PacketFrameOrder { line, .. }
            | Self::QuarantineSourceLineOrder { line, .. }
            | Self::ReceiptConfigurationMismatch { line }
            | Self::ReceiptFieldRegistryMismatch { line }
            | Self::ReceiptFileSizeMismatch { line, .. }
            | Self::ReceiptNormalizedCountMismatch { line, .. }
            | Self::ReceiptPacketLimitReachedMismatch { line, .. }
            | Self::ReceiptDigestMismatch { line, .. }
            | Self::RecordSerialization { line, .. } => Some(*line),
            Self::InputTooLarge { .. } => None,
        }
    }
}

impl std::fmt::Display for SavedCaptureReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "{source}"),
            Self::Json { line, source } => {
                write!(formatter, "invalid JSON on line {line}: {source}")
            }
            Self::MissingSchema { line } => {
                write!(formatter, "record on line {line} has no schema")
            }
            Self::NonStringSchema { line } => {
                write!(formatter, "record schema on line {line} is not a string")
            }
            Self::UnsupportedSchema { line, schema } => {
                write!(formatter, "unsupported schema {schema:?} on line {line}")
            }
            Self::NonCanonicalRecord { line, family } => write!(
                formatter,
                "{family} record on line {line} is not its exact compact typed serialization"
            ),
            Self::InvalidRecord {
                line,
                family,
                source,
            } => write!(formatter, "invalid {family} record on line {line}: {source}"),
            Self::MissingManifest { line } => {
                write!(formatter, "missing capture manifest before line {line}")
            }
            Self::DuplicateManifest { line, first_line } => write!(
                formatter,
                "duplicate capture manifest on line {line}; first manifest was on line {first_line}"
            ),
            Self::DuplicateReceipt { line, first_line } => write!(
                formatter,
                "duplicate capture receipt on line {line}; first receipt was on line {first_line}"
            ),
            Self::RecordOrder {
                line,
                family,
                expected,
            } => write!(
                formatter,
                "{family} record on line {line} is out of order; expected {expected}"
            ),
            Self::CaptureIdMismatch {
                line,
                family,
                expected,
                actual,
            } => write!(
                formatter,
                "{family} record on line {line} has capture_id {actual:?}; expected {expected:?}"
            ),
            Self::ManifestCountMismatch {
                line,
                family,
                declared,
                actual,
            } => write!(
                formatter,
                "manifest on line {line} declares {declared} {family} records, but stream contains {actual}"
            ),
            Self::PacketFrameOrder {
                line,
                previous_line,
                previous_frame_number,
                frame_number,
            } => write!(
                formatter,
                "packet frame {frame_number} on line {line} does not follow frame {previous_frame_number} on line {previous_line}"
            ),
            Self::QuarantineSourceLineOrder {
                line,
                previous_line,
                previous_source_line,
                source_line,
            } => write!(
                formatter,
                "quarantine source line {source_line} on line {line} does not follow source line {previous_source_line} on line {previous_line}"
            ),
            Self::ReceiptConfigurationMismatch { line } => write!(
                formatter,
                "receipt configuration digest on line {line} does not match the manifest"
            ),
            Self::ReceiptFieldRegistryMismatch { line } => write!(
                formatter,
                "receipt field registry on line {line} does not match the manifest"
            ),
            Self::ReceiptFileSizeMismatch {
                line,
                manifest_size_bytes,
                receipt_size_bytes,
            } => write!(
                formatter,
                "receipt file size {receipt_size_bytes} on line {line} does not match manifest artifact size {manifest_size_bytes}"
            ),
            Self::ReceiptNormalizedCountMismatch {
                line,
                normalized_rows,
                expected_rows,
                packet_count,
                packet_limit,
            } => write!(
                formatter,
                "receipt packet count {packet_count} on line {line} and packet limit {packet_limit} require {expected_rows} normalized rows, but the manifest declares {normalized_rows}"
            ),
            Self::ReceiptPacketLimitReachedMismatch {
                line,
                packet_count,
                packet_limit,
                declared,
                expected,
            } => write!(
                formatter,
                "receipt packet count {packet_count} on line {line} and packet limit {packet_limit} require packet_limit_reached={expected}, but the manifest declares {declared}"
            ),
            Self::ReceiptDigestMismatch {
                line,
                declared,
                recomputed,
            } => write!(
                formatter,
                "receipt normalized-record digest {declared:?} on line {line} does not match recomputed digest {recomputed:?}"
            ),
            Self::RecordSerialization {
                line,
                family,
                source,
            } => write!(
                formatter,
                "could not compact-serialize {family} record from line {line}: {source}"
            ),
            Self::InputTooLarge { max_bytes } => write!(
                formatter,
                "saved-capture JSONL exceeds the configured {max_bytes}-byte limit"
            ),
        }
    }
}

impl std::error::Error for SavedCaptureReadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Json { source, .. } | Self::RecordSerialization { source, .. } => Some(source),
            Self::InvalidRecord { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for SavedCaptureReadError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

/// Reads at most `max_bytes` from an opened saved-capture JSONL file.
///
/// The reader probes one additional byte through the same handle to distinguish
/// an exact-limit file from an over-limit file without an unbounded read.
pub fn read_saved_capture_jsonl(
    path: impl AsRef<Path>,
    max_bytes: u64,
) -> Result<SavedCaptureRecordStreamV0, SavedCaptureReadError> {
    let mut file = File::open(path)?;
    let mut bytes = Vec::new();
    {
        let mut bounded = file.by_ref().take(max_bytes);
        bounded.read_to_end(&mut bytes)?;
    }
    let mut beyond_limit = [0_u8; 1];
    if file.read(&mut beyond_limit)? != 0 {
        return Err(SavedCaptureReadError::InputTooLarge { max_bytes });
    }
    parse_saved_capture_jsonl(&bytes)
}

/// Strictly parses and validates a saved-capture JSONL stream.
///
/// Blank lines and malformed final fragments are errors. Accepted family order
/// is manifest, optional receipt, packets, then quarantines.
pub fn parse_saved_capture_jsonl(
    bytes: &[u8],
) -> Result<SavedCaptureRecordStreamV0, SavedCaptureReadError> {
    let mut manifest: Option<(usize, CaptureManifestV0)> = None;
    let mut receipt: Option<(usize, CaptureRunReceiptV0)> = None;
    let mut packets: Vec<(usize, PacketEnvelopeV0)> = Vec::new();
    let mut quarantines: Vec<(usize, PacketQuarantineV0)> = Vec::new();
    let mut phase = StreamPhase::Manifest;

    if bytes.is_empty() {
        return Err(SavedCaptureReadError::MissingManifest { line: 1 });
    }

    let fragments = bytes.split(|byte| *byte == b'\n');
    let fragment_count = fragments.clone().count();
    for (index, line_bytes) in fragments.enumerate() {
        let line = index + 1;
        if line_bytes.is_empty() && line == fragment_count && bytes.ends_with(b"\n") {
            continue;
        }

        let value: Value = serde_json::from_slice(line_bytes)
            .map_err(|source| SavedCaptureReadError::Json { line, source })?;
        let schema = value
            .get("schema")
            .ok_or(SavedCaptureReadError::MissingSchema { line })?
            .as_str()
            .ok_or(SavedCaptureReadError::NonStringSchema { line })?;
        let family = family_for_schema(line, schema)?;
        let record = parse_record(line, family, value)?;
        if record.compact_json(line, family)? != line_bytes {
            return Err(SavedCaptureReadError::NonCanonicalRecord { line, family });
        }

        match record {
            SavedCaptureRecord::Manifest(record) => {
                if let Some((first_line, _)) = &manifest {
                    return Err(SavedCaptureReadError::DuplicateManifest {
                        line,
                        first_line: *first_line,
                    });
                }
                if phase != StreamPhase::Manifest {
                    return Err(SavedCaptureReadError::RecordOrder {
                        line,
                        family,
                        expected: phase.expected(),
                    });
                }
                manifest = Some((line, record));
                phase = StreamPhase::ReceiptOrPacket;
            }
            SavedCaptureRecord::Receipt(record) => {
                if let Some((first_line, _)) = &receipt {
                    return Err(SavedCaptureReadError::DuplicateReceipt {
                        line,
                        first_line: *first_line,
                    });
                }
                if phase != StreamPhase::ReceiptOrPacket {
                    return Err(SavedCaptureReadError::RecordOrder {
                        line,
                        family,
                        expected: phase.expected(),
                    });
                }
                check_capture_id(line, family, &manifest, &record.capture_id)?;
                receipt = Some((line, *record));
                phase = StreamPhase::Packet;
            }
            SavedCaptureRecord::Packet(record) => {
                if !matches!(phase, StreamPhase::ReceiptOrPacket | StreamPhase::Packet) {
                    return Err(SavedCaptureReadError::RecordOrder {
                        line,
                        family,
                        expected: phase.expected(),
                    });
                }
                check_capture_id(line, family, &manifest, &record.capture_id)?;
                if let Some((previous_line, previous)) = packets.last() {
                    if record.frame.number <= previous.frame.number {
                        return Err(SavedCaptureReadError::PacketFrameOrder {
                            line,
                            previous_line: *previous_line,
                            previous_frame_number: previous.frame.number,
                            frame_number: record.frame.number,
                        });
                    }
                }
                packets.push((line, record));
                phase = StreamPhase::Packet;
            }
            SavedCaptureRecord::Quarantine(record) => {
                if !matches!(
                    phase,
                    StreamPhase::ReceiptOrPacket | StreamPhase::Packet | StreamPhase::Quarantine
                ) {
                    return Err(SavedCaptureReadError::RecordOrder {
                        line,
                        family,
                        expected: phase.expected(),
                    });
                }
                check_capture_id(line, family, &manifest, &record.capture_id)?;
                if let Some((previous_line, previous)) = quarantines.last() {
                    if record.source_line <= previous.source_line {
                        return Err(SavedCaptureReadError::QuarantineSourceLineOrder {
                            line,
                            previous_line: *previous_line,
                            previous_source_line: previous.source_line,
                            source_line: record.source_line,
                        });
                    }
                }
                quarantines.push((line, record));
                phase = StreamPhase::Quarantine;
            }
        }
    }

    let eof_line = fragment_count + usize::from(!bytes.ends_with(b"\n"));
    let (manifest_line, manifest) =
        manifest.ok_or(SavedCaptureReadError::MissingManifest { line: eof_line })?;
    check_manifest_count(
        manifest_line,
        SavedCaptureRecordFamilyV0::Packet,
        manifest.normalization.packet_rows_emitted,
        packets.len(),
    )?;
    check_manifest_count(
        manifest_line,
        SavedCaptureRecordFamilyV0::Quarantine,
        manifest.normalization.packet_rows_quarantined,
        quarantines.len(),
    )?;

    if let Some((line, value)) = &receipt {
        check_receipt_manifest_consistency(*line, value, &manifest)?;
    }
    let normalized_records_sha256 =
        normalized_records_sha256(manifest_line, &manifest, &packets, &quarantines)?;
    if let Some((line, value)) = &receipt {
        if value.normalized_records_sha256 != normalized_records_sha256 {
            return Err(SavedCaptureReadError::ReceiptDigestMismatch {
                line: *line,
                declared: value.normalized_records_sha256.clone(),
                recomputed: normalized_records_sha256,
            });
        }
    }

    Ok(SavedCaptureRecordStreamV0 {
        manifest,
        receipt: receipt.map(|(_, value)| value),
        packets: packets.into_iter().map(|(_, value)| value).collect(),
        quarantines: quarantines.into_iter().map(|(_, value)| value).collect(),
        normalized_records_sha256,
    })
}

#[derive(Debug)]
enum SavedCaptureRecord {
    Manifest(CaptureManifestV0),
    Receipt(Box<CaptureRunReceiptV0>),
    Packet(PacketEnvelopeV0),
    Quarantine(PacketQuarantineV0),
}

impl SavedCaptureRecord {
    fn compact_json(
        &self,
        line: usize,
        family: SavedCaptureRecordFamilyV0,
    ) -> Result<Vec<u8>, SavedCaptureReadError> {
        let result = match self {
            Self::Manifest(record) => serde_json::to_vec(record),
            Self::Receipt(record) => serde_json::to_vec(record),
            Self::Packet(record) => serde_json::to_vec(record),
            Self::Quarantine(record) => serde_json::to_vec(record),
        };
        result.map_err(|source| SavedCaptureReadError::RecordSerialization {
            line,
            family,
            source,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StreamPhase {
    Manifest,
    ReceiptOrPacket,
    Packet,
    Quarantine,
}

impl StreamPhase {
    fn expected(self) -> &'static str {
        match self {
            Self::Manifest => "one manifest",
            Self::ReceiptOrPacket => "an optional receipt, packets, or quarantines",
            Self::Packet => "packets or quarantines",
            Self::Quarantine => "quarantines",
        }
    }
}

fn family_for_schema(
    line: usize,
    schema: &str,
) -> Result<SavedCaptureRecordFamilyV0, SavedCaptureReadError> {
    match schema {
        CAPTURE_MANIFEST_SCHEMA_V0 => Ok(SavedCaptureRecordFamilyV0::Manifest),
        CAPTURE_RUN_RECEIPT_SCHEMA_V0 => Ok(SavedCaptureRecordFamilyV0::Receipt),
        PACKET_ENVELOPE_SCHEMA_V0 => Ok(SavedCaptureRecordFamilyV0::Packet),
        PACKET_QUARANTINE_SCHEMA_V0 => Ok(SavedCaptureRecordFamilyV0::Quarantine),
        _ => Err(SavedCaptureReadError::UnsupportedSchema {
            line,
            schema: schema.to_owned(),
        }),
    }
}

fn parse_record(
    line: usize,
    family: SavedCaptureRecordFamilyV0,
    value: Value,
) -> Result<SavedCaptureRecord, SavedCaptureReadError> {
    match family {
        SavedCaptureRecordFamilyV0::Manifest => {
            let value: CaptureManifestV0 = serde_json::from_value(value)
                .map_err(|source| SavedCaptureReadError::Json { line, source })?;
            value
                .validate()
                .map_err(|source| SavedCaptureReadError::InvalidRecord {
                    line,
                    family,
                    source,
                })?;
            Ok(SavedCaptureRecord::Manifest(value))
        }
        SavedCaptureRecordFamilyV0::Receipt => {
            let value: CaptureRunReceiptV0 = serde_json::from_value(value)
                .map_err(|source| SavedCaptureReadError::Json { line, source })?;
            value
                .validate()
                .map_err(|source| SavedCaptureReadError::InvalidRecord {
                    line,
                    family,
                    source,
                })?;
            Ok(SavedCaptureRecord::Receipt(Box::new(value)))
        }
        SavedCaptureRecordFamilyV0::Packet => {
            let value: PacketEnvelopeV0 = serde_json::from_value(value)
                .map_err(|source| SavedCaptureReadError::Json { line, source })?;
            value
                .validate()
                .map_err(|source| SavedCaptureReadError::InvalidRecord {
                    line,
                    family,
                    source,
                })?;
            Ok(SavedCaptureRecord::Packet(value))
        }
        SavedCaptureRecordFamilyV0::Quarantine => {
            let value: PacketQuarantineV0 = serde_json::from_value(value)
                .map_err(|source| SavedCaptureReadError::Json { line, source })?;
            value
                .validate()
                .map_err(|source| SavedCaptureReadError::InvalidRecord {
                    line,
                    family,
                    source,
                })?;
            Ok(SavedCaptureRecord::Quarantine(value))
        }
    }
}

fn check_capture_id(
    line: usize,
    family: SavedCaptureRecordFamilyV0,
    manifest: &Option<(usize, CaptureManifestV0)>,
    actual: &str,
) -> Result<(), SavedCaptureReadError> {
    let Some((_, manifest)) = manifest else {
        return Err(SavedCaptureReadError::RecordOrder {
            line,
            family,
            expected: StreamPhase::Manifest.expected(),
        });
    };
    if actual != manifest.capture_id {
        return Err(SavedCaptureReadError::CaptureIdMismatch {
            line,
            family,
            expected: manifest.capture_id.clone(),
            actual: actual.to_owned(),
        });
    }
    Ok(())
}

fn check_manifest_count(
    line: usize,
    family: SavedCaptureRecordFamilyV0,
    declared: u64,
    actual: usize,
) -> Result<(), SavedCaptureReadError> {
    let actual = u64::try_from(actual).unwrap_or(u64::MAX);
    if declared != actual {
        return Err(SavedCaptureReadError::ManifestCountMismatch {
            line,
            family,
            declared,
            actual,
        });
    }
    Ok(())
}

fn check_receipt_manifest_consistency(
    line: usize,
    receipt: &CaptureRunReceiptV0,
    manifest: &CaptureManifestV0,
) -> Result<(), SavedCaptureReadError> {
    if receipt.configuration_sha256 != manifest.extractor.configuration_sha256 {
        return Err(SavedCaptureReadError::ReceiptConfigurationMismatch { line });
    }
    if receipt.field_registry != manifest.extractor.field_registry {
        return Err(SavedCaptureReadError::ReceiptFieldRegistryMismatch { line });
    }
    if receipt.file.file_size_bytes != manifest.artifact.size_bytes {
        return Err(SavedCaptureReadError::ReceiptFileSizeMismatch {
            line,
            manifest_size_bytes: manifest.artifact.size_bytes,
            receipt_size_bytes: receipt.file.file_size_bytes,
        });
    }
    let normalized_rows = u128::from(manifest.normalization.packet_rows_emitted)
        + u128::from(manifest.normalization.packet_rows_quarantined);
    let expected_rows = receipt
        .file
        .packet_count
        .min(manifest.normalization.packet_limit);
    if normalized_rows != u128::from(expected_rows) {
        return Err(SavedCaptureReadError::ReceiptNormalizedCountMismatch {
            line,
            normalized_rows,
            expected_rows,
            packet_count: receipt.file.packet_count,
            packet_limit: manifest.normalization.packet_limit,
        });
    }
    let expected_limit_reached = receipt.file.packet_count > manifest.normalization.packet_limit;
    if manifest.normalization.packet_limit_reached != expected_limit_reached {
        return Err(SavedCaptureReadError::ReceiptPacketLimitReachedMismatch {
            line,
            packet_count: receipt.file.packet_count,
            packet_limit: manifest.normalization.packet_limit,
            declared: manifest.normalization.packet_limit_reached,
            expected: expected_limit_reached,
        });
    }
    Ok(())
}

fn normalized_records_sha256(
    manifest_line: usize,
    manifest: &CaptureManifestV0,
    packets: &[(usize, PacketEnvelopeV0)],
    quarantines: &[(usize, PacketQuarantineV0)],
) -> Result<String, SavedCaptureReadError> {
    normalized_records_digest(
        manifest_line,
        manifest,
        packets.iter().map(|(line, record)| (*line, record)),
        quarantines.iter().map(|(line, record)| (*line, record)),
    )
}

pub(crate) fn recompute_normalized_records_sha256(
    manifest: &CaptureManifestV0,
    packets: &[PacketEnvelopeV0],
    quarantines: &[PacketQuarantineV0],
) -> Result<String, SavedCaptureReadError> {
    normalized_records_digest(
        1,
        manifest,
        packets
            .iter()
            .enumerate()
            .map(|(index, record)| (index.saturating_add(2), record)),
        quarantines.iter().enumerate().map(|(index, record)| {
            (
                index.saturating_add(packets.len()).saturating_add(2),
                record,
            )
        }),
    )
}

fn normalized_records_digest<'a>(
    manifest_line: usize,
    manifest: &CaptureManifestV0,
    packets: impl Iterator<Item = (usize, &'a PacketEnvelopeV0)>,
    quarantines: impl Iterator<Item = (usize, &'a PacketQuarantineV0)>,
) -> Result<String, SavedCaptureReadError> {
    let mut digest = NormalizedRecordsDigest::new();
    digest.update("manifest", 0, manifest).map_err(|source| {
        SavedCaptureReadError::RecordSerialization {
            line: manifest_line,
            family: SavedCaptureRecordFamilyV0::Manifest,
            source,
        }
    })?;
    for (index, (line, packet)) in packets.enumerate() {
        digest
            .update("packet", u64::try_from(index).unwrap_or(u64::MAX), packet)
            .map_err(|source| SavedCaptureReadError::RecordSerialization {
                line,
                family: SavedCaptureRecordFamilyV0::Packet,
                source,
            })?;
    }
    for (index, (line, quarantine)) in quarantines.enumerate() {
        digest
            .update(
                "quarantine",
                u64::try_from(index).unwrap_or(u64::MAX),
                quarantine,
            )
            .map_err(|source| SavedCaptureReadError::RecordSerialization {
                line,
                family: SavedCaptureRecordFamilyV0::Quarantine,
                source,
            })?;
    }
    Ok(digest.finish())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::CaptureValidationError;
    use std::fs;

    const OTHER_DIGEST: &str =
        "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    macro_rules! jsonl {
        ($($record:expr),* $(,)?) => {{
            let mut bytes = Vec::new();
            $(
                bytes.extend(serde_json::to_vec(&$record).unwrap());
                bytes.push(b'\n');
            )*
            bytes
        }};
    }

    fn manifest() -> CaptureManifestV0 {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/capture_manifest_v0.json"
        ))
        .unwrap()
    }

    fn receipt() -> CaptureRunReceiptV0 {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/capture_run_receipt_v0.json"
        ))
        .unwrap()
    }

    fn packet() -> PacketEnvelopeV0 {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/packet_envelope_v0.json"
        ))
        .unwrap()
    }

    fn quarantine() -> PacketQuarantineV0 {
        serde_json::from_str(include_str!(
            "../../tests/fixtures/replay/evidence-v0/packet_quarantine_v0.json"
        ))
        .unwrap()
    }

    #[test]
    fn reads_deterministic_records_stream_and_recomputes_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.records.jsonl");
        let bytes = jsonl![manifest(), packet(), quarantine()];
        fs::write(&path, &bytes).unwrap();

        let records = read_saved_capture_jsonl(&path, bytes.len() as u64).unwrap();

        assert!(records.receipt.is_none());
        assert_eq!(records.packets.len(), 1);
        assert_eq!(records.quarantines.len(), 1);
        assert_eq!(
            records.normalized_records_sha256,
            receipt().normalized_records_sha256
        );
    }

    #[test]
    fn filesystem_reader_rejects_one_byte_over_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.records.jsonl");
        let bytes = jsonl![manifest(), packet(), quarantine()];
        fs::write(&path, &bytes).unwrap();
        let max_bytes = bytes.len() as u64 - 1;

        let error = read_saved_capture_jsonl(&path, max_bytes).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::InputTooLarge { max_bytes: actual }
                if actual == max_bytes
        ));
    }

    #[test]
    fn reads_full_occurrence_stream_and_verifies_receipt() {
        let records =
            parse_saved_capture_jsonl(&jsonl![manifest(), receipt(), packet(), quarantine()])
                .unwrap();

        assert_eq!(records.receipt.as_ref().unwrap().run_id, receipt().run_id);
        assert_eq!(
            records.normalized_records_sha256,
            records.receipt.as_ref().unwrap().normalized_records_sha256
        );
    }

    #[test]
    fn rejects_malformed_unterminated_tail() {
        let mut bytes = jsonl![manifest(), packet(), quarantine()];
        bytes.extend_from_slice(br#"{"schema":"netmon.packet_envelope.v0""#);

        let error = parse_saved_capture_jsonl(&bytes).unwrap_err();

        assert!(matches!(error, SavedCaptureReadError::Json { line: 4, .. }));
    }

    #[test]
    fn rejects_unknown_schema_before_deserializing_record() {
        let error = parse_saved_capture_jsonl(b"{\"schema\":\"netmon.unknown.v0\"}\n").unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::UnsupportedSchema { line: 1, schema }
                if schema == "netmon.unknown.v0"
        ));
    }

    #[test]
    fn rejects_reordered_record_keys_as_noncanonical() {
        let manifest = manifest();
        let canonical = serde_json::to_vec(&manifest).unwrap();
        let mut reordered = serde_json::to_vec(&serde_json::to_value(&manifest).unwrap()).unwrap();
        assert_ne!(reordered, canonical);
        reordered.push(b'\n');

        let error = parse_saved_capture_jsonl(&reordered).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::NonCanonicalRecord {
                line: 1,
                family: SavedCaptureRecordFamilyV0::Manifest,
            }
        ));
    }

    #[test]
    fn rejects_unknown_record_fields_as_noncanonical() {
        let mut line = serde_json::to_vec(&manifest()).unwrap();
        assert_eq!(line.pop(), Some(b'}'));
        line.extend_from_slice(b",\"unknown\":true}\n");

        let error = parse_saved_capture_jsonl(&line).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::NonCanonicalRecord {
                line: 1,
                family: SavedCaptureRecordFamilyV0::Manifest,
            }
        ));
    }

    #[test]
    fn rejects_explicit_null_for_omitted_field_as_noncanonical() {
        let mut line = serde_json::to_vec(&manifest()).unwrap();
        assert_eq!(line.pop(), Some(b'}'));
        line.extend_from_slice(b",\"acquired_time_unix_ms\":null}\n");

        let error = parse_saved_capture_jsonl(&line).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::NonCanonicalRecord {
                line: 1,
                family: SavedCaptureRecordFamilyV0::Manifest,
            }
        ));
    }

    #[test]
    fn rejects_evidence_that_fails_family_validator() {
        let manifest = manifest();
        let mut packet = packet();
        packet.frame.number = 0;

        let error = parse_saved_capture_jsonl(&jsonl![manifest, packet]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::InvalidRecord {
                line: 2,
                family: SavedCaptureRecordFamilyV0::Packet,
                source: CaptureValidationError::ZeroFrameNumber,
            }
        ));
    }

    #[test]
    fn requires_exactly_one_leading_manifest() {
        assert!(matches!(
            parse_saved_capture_jsonl(b""),
            Err(SavedCaptureReadError::MissingManifest { line: 1 })
        ));

        let error = parse_saved_capture_jsonl(&jsonl![manifest(), manifest()]).unwrap_err();
        assert!(matches!(
            error,
            SavedCaptureReadError::DuplicateManifest {
                line: 2,
                first_line: 1,
            }
        ));
    }

    #[test]
    fn allows_at_most_one_receipt() {
        let error =
            parse_saved_capture_jsonl(&jsonl![manifest(), receipt(), receipt()]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::DuplicateReceipt {
                line: 3,
                first_line: 2,
            }
        ));
    }

    #[test]
    fn enforces_record_family_order() {
        let mut manifest = manifest();
        manifest.normalization.packet_rows_emitted = 1;
        manifest.normalization.packet_rows_quarantined = 1;

        let error =
            parse_saved_capture_jsonl(&jsonl![manifest, quarantine(), packet()]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::RecordOrder {
                line: 3,
                family: SavedCaptureRecordFamilyV0::Packet,
                ..
            }
        ));
    }

    #[test]
    fn enforces_capture_id_consistency() {
        let manifest = manifest();
        let mut packet = packet();
        packet.capture_id = OTHER_DIGEST.into();
        packet.record_id = format!("{OTHER_DIGEST}:frame:1");

        let error = parse_saved_capture_jsonl(&jsonl![manifest, packet]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::CaptureIdMismatch {
                line: 2,
                family: SavedCaptureRecordFamilyV0::Packet,
                actual,
                ..
            } if actual == OTHER_DIGEST
        ));
    }

    #[test]
    fn enforces_manifest_family_counts() {
        let manifest = manifest();

        let error = parse_saved_capture_jsonl(&jsonl![manifest, packet()]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ManifestCountMismatch {
                line: 1,
                family: SavedCaptureRecordFamilyV0::Quarantine,
                declared: 1,
                actual: 0,
            }
        ));
    }

    #[test]
    fn requires_strictly_increasing_packet_frame_numbers() {
        let mut manifest = manifest();
        manifest.normalization.packet_rows_emitted = 2;
        manifest.normalization.packet_rows_quarantined = 0;
        let packet_one = packet();
        let mut packet_two = packet_one.clone();
        packet_two.frame.number = 2;
        packet_two.record_id = format!("{}:frame:2", packet_two.capture_id);

        let error =
            parse_saved_capture_jsonl(&jsonl![manifest, packet_two, packet_one]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::PacketFrameOrder {
                line: 3,
                previous_line: 2,
                previous_frame_number: 2,
                frame_number: 1,
            }
        ));
    }

    #[test]
    fn requires_strictly_increasing_quarantine_source_lines() {
        let mut manifest = manifest();
        manifest.normalization.packet_rows_emitted = 0;
        manifest.normalization.packet_rows_quarantined = 2;
        let quarantine_two = quarantine();
        let mut quarantine_one = quarantine_two.clone();
        quarantine_one.source_line = 1;

        let error = parse_saved_capture_jsonl(&jsonl![manifest, quarantine_two, quarantine_one])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::QuarantineSourceLineOrder {
                line: 3,
                previous_line: 2,
                previous_source_line: 2,
                source_line: 1,
            }
        ));
    }

    #[test]
    fn receipt_configuration_must_match_manifest() {
        let manifest = manifest();
        let mut receipt = receipt();
        receipt.configuration_sha256 = OTHER_DIGEST.into();

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet(), quarantine()])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptConfigurationMismatch { line: 2 }
        ));
    }

    #[test]
    fn receipt_field_registry_must_match_manifest() {
        let manifest = manifest();
        let mut receipt = receipt();
        receipt.field_registry = "netmon.tshark.packet_envelope.other".into();

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet(), quarantine()])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptFieldRegistryMismatch { line: 2 }
        ));
    }

    #[test]
    fn receipt_file_size_must_match_manifest_artifact() {
        let manifest = manifest();
        let mut receipt = receipt();
        receipt.file.file_size_bytes += 1;

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet(), quarantine()])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptFileSizeMismatch {
                line: 2,
                manifest_size_bytes: 136,
                receipt_size_bytes: 137,
            }
        ));
    }

    #[test]
    fn receipt_packet_count_must_explain_normalized_row_count() {
        let manifest = manifest();
        let mut receipt = receipt();
        receipt.file.packet_count = 3;

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet(), quarantine()])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptNormalizedCountMismatch {
                line: 2,
                normalized_rows: 2,
                expected_rows: 3,
                packet_count: 3,
                packet_limit: 1000,
            }
        ));
    }

    #[test]
    fn receipt_packet_count_determines_whether_limit_was_reached() {
        let mut manifest = manifest();
        manifest.normalization.packet_limit = 1;
        manifest.normalization.packet_limit_reached = false;
        manifest.normalization.packet_rows_quarantined = 0;
        let receipt = receipt();

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet()]).unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptPacketLimitReachedMismatch {
                line: 2,
                packet_count: 2,
                packet_limit: 1,
                declared: false,
                expected: true,
            }
        ));
    }

    #[test]
    fn accepts_receipt_for_consistent_limited_normalization() {
        let mut manifest = manifest();
        manifest.normalization.packet_limit = 1;
        manifest.normalization.packet_limit_reached = true;
        manifest.normalization.packet_rows_quarantined = 0;
        let packet = packet();
        let digest = parse_saved_capture_jsonl(&jsonl![manifest.clone(), packet.clone()])
            .unwrap()
            .normalized_records_sha256;
        let mut receipt = receipt();
        receipt.normalized_records_sha256 = digest;

        let records = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet]).unwrap();

        assert!(records.manifest.normalization.packet_limit_reached);
        assert_eq!(records.packets.len(), 1);
        assert!(records.quarantines.is_empty());
    }

    #[test]
    fn receipt_digest_must_match_independent_recomputation() {
        let manifest = manifest();
        let mut receipt = receipt();
        receipt.normalized_records_sha256 = OTHER_DIGEST.into();

        let error = parse_saved_capture_jsonl(&jsonl![manifest, receipt, packet(), quarantine()])
            .unwrap_err();

        assert!(matches!(
            error,
            SavedCaptureReadError::ReceiptDigestMismatch {
                line: 2,
                declared,
                ..
            } if declared == OTHER_DIGEST
        ));
    }
}
