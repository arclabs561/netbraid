//! Bounded positional projection of small SigMF IQ windows.

use std::collections::BTreeSet;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

use crate::evidence::{
    IqByteOrderProvenanceV0, IqByteOrderStateV0, IqByteOrderV0, IqComponentAggregateV0,
    IqDeterministicAggregatesV0, IqDialectV0, IqSampleIntervalV0, IqValueCountsV0,
    IqWindowCompletenessV0, IqWindowEvidenceV0,
};

const BYTES_PER_COMPLEX_SAMPLE: u64 = 8;
const DEFAULT_MAX_METADATA_BYTES: u64 = 1024 * 1024;
const DEFAULT_MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_METADATA_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_WINDOW_BYTES: u64 = 64 * 1024 * 1024;
const DUPLICATE_KEY_MARKER: &str = "netbraid_duplicate_json_key";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigmfDialect {
    #[default]
    Auto,
    SigmfCore,
    OsuLoraV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigmfByteOrder {
    Little,
    Big,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SigmfWindowOptions {
    pub dialect: SigmfDialect,
    pub first_sample: u64,
    pub sample_count: u64,
    pub max_metadata_bytes: u64,
    pub max_window_bytes: u64,
    pub byte_order_override: Option<SigmfByteOrder>,
}

impl Default for SigmfWindowOptions {
    fn default() -> Self {
        Self {
            dialect: SigmfDialect::Auto,
            first_sample: 0,
            sample_count: 1,
            max_metadata_bytes: DEFAULT_MAX_METADATA_BYTES,
            max_window_bytes: DEFAULT_MAX_WINDOW_BYTES,
            byte_order_override: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigmfSourceKind {
    Metadata,
    Data,
}

#[derive(Debug)]
#[non_exhaustive]
pub enum SigmfAdapterError {
    InvalidOption(&'static str),
    SourceMetadata {
        kind: SigmfSourceKind,
        source: io::Error,
    },
    SourceOpen {
        kind: SigmfSourceKind,
        source: io::Error,
    },
    SourceRead {
        kind: SigmfSourceKind,
        source: io::Error,
    },
    SourceSymlink(SigmfSourceKind),
    SourceNotRegular(SigmfSourceKind),
    SourceChanged(SigmfSourceKind),
    MetadataTooLarge,
    InvalidJson(serde_json::Error),
    DuplicateJsonKey,
    DialectMismatch,
    UnsupportedMetadataShape,
    UnsupportedDatatype,
    UnsupportedVersion,
    Multichannel,
    UnknownRequiredExtension,
    UnsafeSiblingDeclaration,
    ConflictingByteOrderOverride,
    OffsetOverflow,
    WindowLengthOverflow,
    WindowTooLarge,
}

impl std::fmt::Display for SigmfAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(name) => write!(formatter, "invalid SigMF option {name}"),
            Self::SourceMetadata { kind, .. } => {
                write!(formatter, "could not inspect {kind:?} source")
            }
            Self::SourceOpen { kind, .. } => write!(formatter, "could not open {kind:?} source"),
            Self::SourceRead { kind, .. } => write!(formatter, "could not read {kind:?} source"),
            Self::SourceSymlink(kind) => write!(formatter, "{kind:?} source is a symlink"),
            Self::SourceNotRegular(kind) => {
                write!(formatter, "{kind:?} source is not a regular file")
            }
            Self::SourceChanged(kind) => {
                write!(formatter, "{kind:?} source changed during projection")
            }
            Self::MetadataTooLarge => formatter.write_str("SigMF metadata exceeds its byte bound"),
            Self::InvalidJson(_) => formatter.write_str("SigMF metadata is not valid JSON"),
            Self::DuplicateJsonKey => formatter.write_str("SigMF metadata repeats a JSON key"),
            Self::DialectMismatch => {
                formatter.write_str("SigMF metadata does not match the requested dialect")
            }
            Self::UnsupportedMetadataShape => {
                formatter.write_str("SigMF metadata is outside the supported minimal shape")
            }
            Self::UnsupportedDatatype => formatter.write_str("SigMF datatype is not supported"),
            Self::UnsupportedVersion => formatter.write_str("SigMF version is not supported"),
            Self::Multichannel => formatter.write_str("multichannel SigMF is not supported"),
            Self::UnknownRequiredExtension => {
                formatter.write_str("SigMF metadata requires an unsupported extension")
            }
            Self::UnsafeSiblingDeclaration => {
                formatter.write_str("SigMF sibling data declaration is unsafe")
            }
            Self::ConflictingByteOrderOverride => {
                formatter.write_str("byte-order override conflicts with the SigMF datatype")
            }
            Self::OffsetOverflow => formatter.write_str("SigMF window byte offset overflows"),
            Self::WindowLengthOverflow => formatter.write_str("SigMF window byte length overflows"),
            Self::WindowTooLarge => formatter.write_str("SigMF window exceeds its byte bound"),
        }
    }
}

impl std::error::Error for SigmfAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceMetadata { source, .. }
            | Self::SourceOpen { source, .. }
            | Self::SourceRead { source, .. } => Some(source),
            Self::InvalidJson(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SigmfReadAudit {
    requested_byte_offset: u64,
    requested_bytes: u64,
    observed_bytes: u64,
    read_calls: u64,
    maximum_single_read_bytes: u64,
}

impl SigmfReadAudit {
    pub const fn requested_byte_offset(&self) -> u64 {
        self.requested_byte_offset
    }

    pub const fn requested_bytes(&self) -> u64 {
        self.requested_bytes
    }

    pub const fn observed_bytes(&self) -> u64 {
        self.observed_bytes
    }

    pub const fn read_calls(&self) -> u64 {
        self.read_calls
    }

    pub const fn maximum_single_read_bytes(&self) -> u64 {
        self.maximum_single_read_bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmfWindowProjection {
    evidence: IqWindowEvidenceV0,
    read_audit: SigmfReadAudit,
}

impl SigmfWindowProjection {
    pub fn evidence(&self) -> &IqWindowEvidenceV0 {
        &self.evidence
    }

    pub const fn read_audit(&self) -> SigmfReadAudit {
        self.read_audit
    }
}

pub fn project_sigmf_window(
    metadata_path: &Path,
    options: &SigmfWindowOptions,
) -> Result<SigmfWindowProjection, SigmfAdapterError> {
    project_sigmf_window_with_hook(metadata_path, options, || {})
}

fn project_sigmf_window_with_hook(
    metadata_path: &Path,
    options: &SigmfWindowOptions,
    after_data_read: impl FnOnce(),
) -> Result<SigmfWindowProjection, SigmfAdapterError> {
    validate_options(options)?;

    let (metadata_file, metadata_identity) =
        open_regular(metadata_path, SigmfSourceKind::Metadata)?;
    if metadata_identity.len > options.max_metadata_bytes {
        return Err(SigmfAdapterError::MetadataTooLarge);
    }
    let metadata_bytes = read_exact_range(
        &metadata_file,
        0,
        metadata_identity.len,
        SigmfSourceKind::Metadata,
        None,
    )?;
    let value = parse_json_without_duplicates(&metadata_bytes)?;
    fence_source(
        metadata_path,
        &metadata_file,
        &metadata_identity,
        SigmfSourceKind::Metadata,
    )?;

    let detected = detect_dialect(&value)?;
    let dialect = match options.dialect {
        SigmfDialect::Auto => detected,
        requested if requested == detected => requested,
        _ => return Err(SigmfAdapterError::DialectMismatch),
    };
    let stem = recording_stem(metadata_path)?;
    let parsed = match dialect {
        SigmfDialect::SigmfCore => parse_sigmf_core(&value, options.first_sample)?,
        SigmfDialect::OsuLoraV2 => parse_osu_lora_v2(&value, &stem, options.first_sample)?,
        SigmfDialect::Auto => unreachable!("auto dialect is resolved before parsing"),
    };

    let data_path = sibling_data_path(metadata_path, &stem, dialect);
    let (data_file, data_identity) = open_regular(&data_path, SigmfSourceKind::Data)?;
    let byte_offset = options
        .first_sample
        .checked_mul(BYTES_PER_COMPLEX_SAMPLE)
        .ok_or(SigmfAdapterError::OffsetOverflow)?;
    let requested_bytes = options
        .sample_count
        .checked_mul(BYTES_PER_COMPLEX_SAMPLE)
        .ok_or(SigmfAdapterError::WindowLengthOverflow)?;
    if requested_bytes > options.max_window_bytes {
        return Err(SigmfAdapterError::WindowTooLarge);
    }

    let requested_interval = IqSampleIntervalV0::new(options.first_sample, options.sample_count);
    let (byte_order, provenance) = resolve_byte_order(parsed.byte_order, options)?;
    if byte_order.is_none() {
        after_data_read();
        fence_source(
            &data_path,
            &data_file,
            &data_identity,
            SigmfSourceKind::Data,
        )?;
        fence_source(
            metadata_path,
            &metadata_file,
            &metadata_identity,
            SigmfSourceKind::Metadata,
        )?;
        return Ok(SigmfWindowProjection {
            evidence: IqWindowEvidenceV0::undecodable(
                parsed.dialect,
                parsed.sample_rate_hz,
                parsed.center_frequency_hz,
                requested_interval,
            ),
            read_audit: SigmfReadAudit {
                requested_byte_offset: byte_offset,
                requested_bytes,
                ..SigmfReadAudit::default()
            },
        });
    }

    let declared_len = parsed.declared_data_bytes.unwrap_or(data_identity.len);
    let effective_len = data_identity.len.min(declared_len);
    let available = effective_len.saturating_sub(byte_offset);
    let planned_bytes = available.min(requested_bytes);
    let planned_bytes = planned_bytes - (planned_bytes % BYTES_PER_COMPLEX_SAMPLE);
    let mut audit = SigmfReadAudit {
        requested_byte_offset: byte_offset,
        requested_bytes,
        ..SigmfReadAudit::default()
    };
    let bytes = read_exact_range(
        &data_file,
        byte_offset,
        planned_bytes,
        SigmfSourceKind::Data,
        Some(&mut audit),
    )?;
    after_data_read();
    fence_source(
        &data_path,
        &data_file,
        &data_identity,
        SigmfSourceKind::Data,
    )?;
    fence_source(
        metadata_path,
        &metadata_file,
        &metadata_identity,
        SigmfSourceKind::Metadata,
    )?;

    let observed_samples = u64::try_from(bytes.len()).expect("bounded window length fits u64")
        / BYTES_PER_COMPLEX_SAMPLE;
    let observed_interval = IqSampleIntervalV0::new(options.first_sample, observed_samples);
    let completeness = if observed_samples == options.sample_count {
        IqWindowCompletenessV0::Complete
    } else {
        IqWindowCompletenessV0::Truncated
    };
    let byte_order = byte_order.expect("unknown byte order returned above");
    let (counts, aggregates) = summarize_cf32(&bytes, byte_order);
    let state = match byte_order {
        SigmfByteOrder::Little => IqByteOrderStateV0::Little,
        SigmfByteOrder::Big => IqByteOrderStateV0::Big,
    };

    Ok(SigmfWindowProjection {
        evidence: IqWindowEvidenceV0::decoded(
            parsed.dialect,
            IqByteOrderV0::new(state, provenance),
            parsed.sample_rate_hz,
            parsed.center_frequency_hz,
            requested_interval,
            observed_interval,
            completeness,
            counts,
            aggregates,
        ),
        read_audit: audit,
    })
}

fn validate_options(options: &SigmfWindowOptions) -> Result<(), SigmfAdapterError> {
    if options.sample_count == 0 {
        return Err(SigmfAdapterError::InvalidOption("sample_count"));
    }
    if options.max_metadata_bytes == 0 || options.max_metadata_bytes > HARD_MAX_METADATA_BYTES {
        return Err(SigmfAdapterError::InvalidOption("max_metadata_bytes"));
    }
    if options.max_window_bytes == 0 || options.max_window_bytes > HARD_MAX_WINDOW_BYTES {
        return Err(SigmfAdapterError::InvalidOption("max_window_bytes"));
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedMetadata {
    dialect: IqDialectV0,
    byte_order: Option<SigmfByteOrder>,
    sample_rate_hz: u64,
    center_frequency_hz: Option<u64>,
    declared_data_bytes: Option<u64>,
}

fn detect_dialect(value: &Value) -> Result<SigmfDialect, SigmfAdapterError> {
    let object = value
        .as_object()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let core = object.contains_key("global")
        && object.contains_key("captures")
        && object.contains_key("annotations");
    let osu = object.contains_key("version")
        && object.contains_key("schema")
        && object.contains_key("_metadata")
        && object.contains_key("data_file");
    match (core, osu) {
        (true, false) => Ok(SigmfDialect::SigmfCore),
        (false, true) => Ok(SigmfDialect::OsuLoraV2),
        _ => Err(SigmfAdapterError::UnsupportedMetadataShape),
    }
}

fn parse_sigmf_core(value: &Value, first_sample: u64) -> Result<ParsedMetadata, SigmfAdapterError> {
    let top = exact_object(value, &["global", "captures", "annotations"], &[])?;
    let global = exact_object(
        required(top, "global")?,
        &["core:datatype", "core:sample_rate", "core:version"],
        &["core:num_channels", "core:extensions"],
    )?;
    let version = required_string(global, "core:version")?;
    if !version.starts_with("1.") {
        return Err(SigmfAdapterError::UnsupportedVersion);
    }
    let byte_order = match required_string(global, "core:datatype")? {
        "cf32_le" => SigmfByteOrder::Little,
        "cf32_be" => SigmfByteOrder::Big,
        _ => return Err(SigmfAdapterError::UnsupportedDatatype),
    };
    let sample_rate_hz = required_u64(global, "core:sample_rate")?;
    if sample_rate_hz == 0 {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    let channels = optional_u64(global, "core:num_channels")?.unwrap_or(1);
    if channels != 1 {
        return Err(SigmfAdapterError::Multichannel);
    }
    if let Some(extensions) = global.get("core:extensions") {
        let extensions = extensions
            .as_array()
            .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
        for extension in extensions {
            let extension = exact_object(extension, &["name", "version", "optional"], &[])?;
            required_string(extension, "name")?;
            required_string(extension, "version")?;
            if !required_bool(extension, "optional")? {
                return Err(SigmfAdapterError::UnknownRequiredExtension);
            }
        }
    }
    let annotations = required(top, "annotations")?
        .as_array()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    if !annotations.is_empty() {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    let center_frequency_hz = parse_core_captures(required(top, "captures")?, first_sample)?;
    Ok(ParsedMetadata {
        dialect: IqDialectV0::SigmfCore,
        byte_order: Some(byte_order),
        sample_rate_hz,
        center_frequency_hz,
        declared_data_bytes: None,
    })
}

fn parse_core_captures(value: &Value, first_sample: u64) -> Result<Option<u64>, SigmfAdapterError> {
    let captures = value
        .as_array()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let mut previous = None;
    let mut center = None;
    for capture in captures {
        let capture = exact_object(capture, &["core:sample_start"], &["core:frequency"])?;
        let start = required_u64(capture, "core:sample_start")?;
        if previous.is_none() && start != 0 || previous.is_some_and(|value| start <= value) {
            return Err(SigmfAdapterError::UnsupportedMetadataShape);
        }
        previous = Some(start);
        if start <= first_sample {
            center = optional_u64(capture, "core:frequency")?;
        }
    }
    Ok(center)
}

fn parse_osu_lora_v2(
    value: &Value,
    stem: &str,
    first_sample: u64,
) -> Result<ParsedMetadata, SigmfAdapterError> {
    let wrapper = exact_object(value, &["version", "schema", "_metadata", "data_file"], &[])?;
    let version = required_string(wrapper, "version")?;
    if version.is_empty() || version.len() > 64 {
        return Err(SigmfAdapterError::UnsupportedVersion);
    }
    let schema = exact_object(
        required(wrapper, "schema")?,
        &["global", "captures", "annotations"],
        &[],
    )?;
    if schema.values().any(|value| !value.is_object()) {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    validate_osu_data_declaration(required_string(wrapper, "data_file")?, stem)?;
    let metadata = exact_object(
        required(wrapper, "_metadata")?,
        &["global", "captures", "annotations"],
        &[],
    )?;
    let global = exact_object(
        required(metadata, "global")?,
        &[
            "core:author",
            "core:datatype",
            "core:description",
            "core:sample_rate",
        ],
        &[],
    )?;
    required_string(global, "core:author")?;
    required_string(global, "core:description")?;
    if required_string(global, "core:datatype")? != "cf32" {
        return Err(SigmfAdapterError::UnsupportedDatatype);
    }
    let sample_rate_hz = parse_scaled_quantity(required_string(global, "core:sample_rate")?)?;
    let center_frequency_hz = parse_osu_captures(required(metadata, "captures")?, first_sample)?;
    let declared_samples = parse_osu_annotations(required(metadata, "annotations")?)?;
    let declared_data_bytes = declared_samples
        .checked_mul(BYTES_PER_COMPLEX_SAMPLE)
        .ok_or(SigmfAdapterError::WindowLengthOverflow)?;
    Ok(ParsedMetadata {
        dialect: IqDialectV0::OsuLoraV2,
        byte_order: None,
        sample_rate_hz,
        center_frequency_hz,
        declared_data_bytes: Some(declared_data_bytes),
    })
}

fn parse_osu_captures(value: &Value, first_sample: u64) -> Result<Option<u64>, SigmfAdapterError> {
    let captures = value
        .as_array()
        .filter(|captures| !captures.is_empty())
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let mut previous = None;
    let mut center = None;
    for capture in captures {
        let capture = exact_object(
            capture,
            &["core:date", "core:sample_start", "frequency"],
            &[],
        )?;
        required_string(capture, "core:date")?;
        let start = required_u64(capture, "core:sample_start")?;
        if previous.is_none() && start != 0 || previous.is_some_and(|value| start <= value) {
            return Err(SigmfAdapterError::UnsupportedMetadataShape);
        }
        previous = Some(start);
        if start <= first_sample {
            center = Some(parse_scaled_quantity(required_string(
                capture,
                "frequency",
            )?)?);
        }
    }
    Ok(center)
}

fn parse_osu_annotations(value: &Value) -> Result<u64, SigmfAdapterError> {
    let annotations = value
        .as_array()
        .filter(|annotations| !annotations.is_empty())
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let mut declared_samples = 0u64;
    for annotation in annotations {
        let annotation = exact_object(
            annotation,
            &[
                "core:sample_count",
                "core:sample_start",
                "wines:reciever",
                "wines:transmitter",
            ],
            &[],
        )?;
        let start = required_u64(annotation, "core:sample_start")?;
        let count = required_u64(annotation, "core:sample_count")?;
        let end = start
            .checked_add(count)
            .ok_or(SigmfAdapterError::WindowLengthOverflow)?;
        declared_samples = declared_samples.max(end);
        validate_osu_endpoint(required(annotation, "wines:reciever")?, false)?;
        validate_osu_endpoint(required(annotation, "wines:transmitter")?, true)?;
    }
    Ok(declared_samples)
}

fn validate_osu_endpoint(value: &Value, transmitter: bool) -> Result<(), SigmfAdapterError> {
    let endpoint = if transmitter {
        exact_object(value, &["ID", "antenna", "model"], &[])?
    } else {
        exact_object(value, &["antenna", "model"], &[])?
    };
    required_string(endpoint, "model")?;
    let antenna = exact_object(
        required(endpoint, "antenna")?,
        &["gain", "model", "type"],
        &[],
    )?;
    if !required(antenna, "gain")?.is_number() {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    required_string(antenna, "model")?;
    required_string(antenna, "type")?;
    if transmitter {
        let id = exact_object(
            required(endpoint, "ID")?,
            &["Transmission ID", "Transmitter ID"],
            &[],
        )?;
        if !required(id, "Transmission ID")?.is_number()
            || !(required(id, "Transmitter ID")?.is_string()
                || required(id, "Transmitter ID")?.is_number())
        {
            return Err(SigmfAdapterError::UnsupportedMetadataShape);
        }
    }
    Ok(())
}

fn validate_osu_data_declaration(value: &str, stem: &str) -> Result<(), SigmfAdapterError> {
    if value.is_empty()
        || value.len() > 4096
        || value.chars().any(|character| character.is_control())
        || value.contains(['\\', '?', '#', '%'])
    {
        return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
    }
    let name = if let Some(rest) = value.strip_prefix("https://") {
        let (host, path) = rest
            .split_once('/')
            .ok_or(SigmfAdapterError::UnsafeSiblingDeclaration)?;
        if host.is_empty() || host.contains(['@', ':']) {
            return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
        }
        if path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
        }
        path.rsplit('/').next().expect("non-empty path")
    } else {
        if value.contains('/') || value.contains("://") {
            return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
        }
        value
    };
    let declared_stem = name
        .strip_suffix(".sigmf-meta")
        .or_else(|| name.strip_suffix(".dat"))
        .ok_or(SigmfAdapterError::UnsafeSiblingDeclaration)?;
    if declared_stem != stem {
        return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
    }
    Ok(())
}

fn parse_scaled_quantity(value: &str) -> Result<u64, SigmfAdapterError> {
    let compact: String = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    let number_and_prefix = compact
        .strip_suffix("S/s")
        .or_else(|| compact.strip_suffix("Hz"))
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let (number, scale) = match number_and_prefix.chars().last() {
        Some('k') => (&number_and_prefix[..number_and_prefix.len() - 1], 1_000u64),
        Some('M') => (
            &number_and_prefix[..number_and_prefix.len() - 1],
            1_000_000u64,
        ),
        Some('G') => (
            &number_and_prefix[..number_and_prefix.len() - 1],
            1_000_000_000u64,
        ),
        Some('T') => (
            &number_and_prefix[..number_and_prefix.len() - 1],
            1_000_000_000_000u64,
        ),
        _ => (number_and_prefix, 1u64),
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty()
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 18
    {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    let whole = whole
        .parse::<u64>()
        .map_err(|_| SigmfAdapterError::UnsupportedMetadataShape)?;
    let denominator = 10u64
        .checked_pow(u32::try_from(fraction.len()).expect("fraction length is bounded"))
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction
            .parse::<u64>()
            .map_err(|_| SigmfAdapterError::UnsupportedMetadataShape)?
    };
    let fractional_scaled = fraction
        .checked_mul(scale)
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    if fractional_scaled % denominator != 0 {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    let value = whole
        .checked_mul(scale)
        .and_then(|whole| whole.checked_add(fractional_scaled / denominator))
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    if value == 0 {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    Ok(value)
}

fn resolve_byte_order(
    declared: Option<SigmfByteOrder>,
    options: &SigmfWindowOptions,
) -> Result<(Option<SigmfByteOrder>, IqByteOrderProvenanceV0), SigmfAdapterError> {
    match (declared, options.byte_order_override) {
        (Some(declared), Some(overridden)) if declared != overridden => {
            Err(SigmfAdapterError::ConflictingByteOrderOverride)
        }
        (Some(declared), Some(_)) => Ok((
            Some(declared),
            IqByteOrderProvenanceV0::SigmfDatatypeConfirmedByCaller,
        )),
        (Some(declared), None) => Ok((Some(declared), IqByteOrderProvenanceV0::SigmfDatatype)),
        (None, Some(overridden)) => Ok((Some(overridden), IqByteOrderProvenanceV0::CallerOverride)),
        (None, None) => Ok((None, IqByteOrderProvenanceV0::Undeclared)),
    }
}

fn recording_stem(metadata_path: &Path) -> Result<String, SigmfAdapterError> {
    let name = metadata_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(SigmfAdapterError::UnsafeSiblingDeclaration)?;
    let stem = name
        .strip_suffix(".sigmf-meta")
        .ok_or(SigmfAdapterError::UnsafeSiblingDeclaration)?;
    if stem.is_empty()
        || stem.len() > 255
        || stem == "."
        || stem == ".."
        || stem.chars().any(|character| character.is_control())
        || stem.contains(['/', '\\'])
    {
        return Err(SigmfAdapterError::UnsafeSiblingDeclaration);
    }
    Ok(stem.to_owned())
}

fn sibling_data_path(metadata_path: &Path, stem: &str, dialect: SigmfDialect) -> PathBuf {
    let suffix = match dialect {
        SigmfDialect::SigmfCore => ".sigmf-data",
        SigmfDialect::OsuLoraV2 => ".dat",
        SigmfDialect::Auto => unreachable!("auto dialect is resolved before path construction"),
    };
    metadata_path.with_file_name(format!("{stem}{suffix}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;

        Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(unix)]
            changed_seconds: metadata.ctime(),
            #[cfg(unix)]
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn open_regular(
    path: &Path,
    kind: SigmfSourceKind,
) -> Result<(File, FileIdentity), SigmfAdapterError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| SigmfAdapterError::SourceMetadata { kind, source })?;
    if path_metadata.file_type().is_symlink() {
        return Err(SigmfAdapterError::SourceSymlink(kind));
    }
    if !path_metadata.is_file() {
        return Err(SigmfAdapterError::SourceNotRegular(kind));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options
        .open(path)
        .map_err(|source| SigmfAdapterError::SourceOpen { kind, source })?;
    let opened_metadata = file
        .metadata()
        .map_err(|source| SigmfAdapterError::SourceMetadata { kind, source })?;
    if !opened_metadata.is_file() {
        return Err(SigmfAdapterError::SourceNotRegular(kind));
    }
    let path_identity = FileIdentity::from_metadata(&path_metadata);
    let opened_identity = FileIdentity::from_metadata(&opened_metadata);
    if path_identity != opened_identity {
        return Err(SigmfAdapterError::SourceChanged(kind));
    }
    Ok((file, opened_identity))
}

fn fence_source(
    path: &Path,
    file: &File,
    expected: &FileIdentity,
    kind: SigmfSourceKind,
) -> Result<(), SigmfAdapterError> {
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|source| SigmfAdapterError::SourceMetadata { kind, source })?;
    if path_metadata.file_type().is_symlink() {
        return Err(SigmfAdapterError::SourceChanged(kind));
    }
    let opened_metadata = file
        .metadata()
        .map_err(|source| SigmfAdapterError::SourceMetadata { kind, source })?;
    if !path_metadata.is_file()
        || !opened_metadata.is_file()
        || FileIdentity::from_metadata(&path_metadata) != *expected
        || FileIdentity::from_metadata(&opened_metadata) != *expected
    {
        return Err(SigmfAdapterError::SourceChanged(kind));
    }
    Ok(())
}

fn read_exact_range(
    file: &File,
    offset: u64,
    length: u64,
    kind: SigmfSourceKind,
    mut audit: Option<&mut SigmfReadAudit>,
) -> Result<Vec<u8>, SigmfAdapterError> {
    let length_usize = usize::try_from(length).map_err(|_| SigmfAdapterError::WindowTooLarge)?;
    let mut bytes = vec![0u8; length_usize];
    let mut filled = 0usize;
    while filled < bytes.len() {
        let read_offset = offset
            .checked_add(u64::try_from(filled).expect("buffer length fits u64"))
            .ok_or(SigmfAdapterError::OffsetOverflow)?;
        let read = positional_read(file, &mut bytes[filled..], read_offset)
            .map_err(|source| SigmfAdapterError::SourceRead { kind, source })?;
        if let Some(audit) = audit.as_deref_mut() {
            audit.read_calls += 1;
            audit.maximum_single_read_bytes = audit
                .maximum_single_read_bytes
                .max(u64::try_from(bytes.len() - filled).expect("bounded read length fits u64"));
        }
        if read == 0 {
            break;
        }
        filled += read;
    }
    let retained = if kind == SigmfSourceKind::Data {
        filled - (filled % usize::try_from(BYTES_PER_COMPLEX_SAMPLE).unwrap())
    } else {
        filled
    };
    bytes.truncate(retained);
    if let Some(audit) = audit {
        audit.observed_bytes = u64::try_from(bytes.len()).expect("bounded read length fits u64");
    }
    Ok(bytes)
}

#[cfg(unix)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::unix::fs::FileExt;
    file.read_at(buffer, offset)
}

#[cfg(windows)]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::os::windows::fs::FileExt;
    file.seek_read(buffer, offset)
}

#[cfg(not(any(unix, windows)))]
fn positional_read(file: &File, buffer: &mut [u8], offset: u64) -> io::Result<usize> {
    use std::io::{Read, Seek, SeekFrom};
    let mut handle = file.try_clone()?;
    handle.seek(SeekFrom::Start(offset))?;
    handle.read(buffer)
}

#[derive(Debug, Default)]
struct ComponentAccumulator {
    positive_finite: u64,
    negative_finite: u64,
    subnormal: u64,
    minimum: Option<f32>,
    maximum: Option<f32>,
}

impl ComponentAccumulator {
    fn observe(&mut self, value: f32) {
        if !value.is_finite() {
            return;
        }
        if value > 0.0 {
            self.positive_finite += 1;
        } else if value < 0.0 {
            self.negative_finite += 1;
        }
        if value.is_subnormal() {
            self.subnormal += 1;
        }
        if self
            .minimum
            .is_none_or(|minimum| value.total_cmp(&minimum).is_lt())
        {
            self.minimum = Some(value);
        }
        if self
            .maximum
            .is_none_or(|maximum| value.total_cmp(&maximum).is_gt())
        {
            self.maximum = Some(value);
        }
    }

    fn finish(self) -> IqComponentAggregateV0 {
        IqComponentAggregateV0::new(
            self.positive_finite,
            self.negative_finite,
            self.subnormal,
            self.minimum.map(f32::to_bits),
            self.maximum.map(f32::to_bits),
        )
    }
}

fn summarize_cf32(
    bytes: &[u8],
    byte_order: SigmfByteOrder,
) -> (IqValueCountsV0, IqDeterministicAggregatesV0) {
    let mut finite = 0u64;
    let mut nonfinite = 0u64;
    let mut zero = 0u64;
    let mut in_phase = ComponentAccumulator::default();
    let mut quadrature = ComponentAccumulator::default();
    for sample in bytes.chunks_exact(8) {
        let decode = |component: &[u8]| {
            let encoded: [u8; 4] = component.try_into().expect("component is four bytes");
            match byte_order {
                SigmfByteOrder::Little => f32::from_le_bytes(encoded),
                SigmfByteOrder::Big => f32::from_be_bytes(encoded),
            }
        };
        let i = decode(&sample[..4]);
        let q = decode(&sample[4..]);
        for value in [i, q] {
            if value.is_finite() {
                finite += 1;
            } else {
                nonfinite += 1;
            }
            if value == 0.0 {
                zero += 1;
            }
        }
        in_phase.observe(i);
        quadrature.observe(q);
    }
    (
        IqValueCountsV0::new(finite, nonfinite, zero),
        IqDeterministicAggregatesV0::new(in_phase.finish(), quadrature.finish()),
    )
}

fn exact_object<'a>(
    value: &'a Value,
    required_keys: &[&str],
    optional_keys: &[&str],
) -> Result<&'a Map<String, Value>, SigmfAdapterError> {
    let object = value
        .as_object()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)?;
    let allowed: BTreeSet<&str> = required_keys
        .iter()
        .chain(optional_keys.iter())
        .copied()
        .collect();
    if required_keys.iter().any(|key| !object.contains_key(*key))
        || object.keys().any(|key| !allowed.contains(key.as_str()))
    {
        return Err(SigmfAdapterError::UnsupportedMetadataShape);
    }
    Ok(object)
}

fn required<'a>(object: &'a Map<String, Value>, key: &str) -> Result<&'a Value, SigmfAdapterError> {
    object
        .get(key)
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, SigmfAdapterError> {
    required(object, key)?
        .as_str()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)
}

fn required_u64(object: &Map<String, Value>, key: &str) -> Result<u64, SigmfAdapterError> {
    required(object, key)?
        .as_u64()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)
}

fn optional_u64(object: &Map<String, Value>, key: &str) -> Result<Option<u64>, SigmfAdapterError> {
    object
        .get(key)
        .map(|value| {
            value
                .as_u64()
                .ok_or(SigmfAdapterError::UnsupportedMetadataShape)
        })
        .transpose()
}

fn required_bool(object: &Map<String, Value>, key: &str) -> Result<bool, SigmfAdapterError> {
    required(object, key)?
        .as_bool()
        .ok_or(SigmfAdapterError::UnsupportedMetadataShape)
}

fn parse_json_without_duplicates(bytes: &[u8]) -> Result<Value, SigmfAdapterError> {
    serde_json::from_slice::<DuplicateSafeValue>(bytes)
        .map(|value| value.0)
        .map_err(|error| {
            if error.to_string().contains(DUPLICATE_KEY_MARKER) {
                SigmfAdapterError::DuplicateJsonKey
            } else {
                SigmfAdapterError::InvalidJson(error)
            }
        })
}

struct DuplicateSafeValue(Value);

impl<'de> Deserialize<'de> for DuplicateSafeValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(DuplicateSafeVisitor)
    }
}

struct DuplicateSafeVisitor;

impl<'de> Visitor<'de> for DuplicateSafeVisitor {
    type Value = DuplicateSafeValue;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .map(DuplicateSafeValue)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        self.visit_string(value.to_owned())
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(DuplicateSafeValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        DuplicateSafeValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<DuplicateSafeValue>()? {
            values.push(value.0);
        }
        Ok(DuplicateSafeValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, value)) = map.next_entry::<String, DuplicateSafeValue>()? {
            if values.insert(key, value.0).is_some() {
                return Err(de::Error::custom(DUPLICATE_KEY_MARKER));
            }
        }
        Ok(DuplicateSafeValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn post_read_identity_fence_detects_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let metadata_path = directory.path().join("mutation.sigmf-meta");
        let data_path = directory.path().join("mutation.sigmf-data");
        fs::write(
            &metadata_path,
            br#"{"global":{"core:datatype":"cf32_le","core:sample_rate":1,"core:version":"1.2.0"},"captures":[],"annotations":[]}"#,
        )
        .unwrap();
        fs::write(&data_path, [0u8; 8]).unwrap();

        let error =
            project_sigmf_window_with_hook(&metadata_path, &SigmfWindowOptions::default(), || {
                let mut file = OpenOptions::new().write(true).open(&data_path).unwrap();
                file.seek(SeekFrom::Start(0)).unwrap();
                file.write_all(&1.0f32.to_le_bytes()).unwrap();
                file.sync_all().unwrap();
            })
            .unwrap_err();
        assert!(matches!(
            error,
            SigmfAdapterError::SourceChanged(SigmfSourceKind::Data)
        ));
    }
}
