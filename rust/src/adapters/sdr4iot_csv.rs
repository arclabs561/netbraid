//! Bounded projection of SDR4IoT publisher detection tables.

use std::fs::OpenOptions;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::path::Path;

use csv::{ByteRecord, ReaderBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const SDR4IOT_DETECTION_STREAM_SCHEMA_V0: &str = "netbraid.sdr4iot_detection_stream.v0";
pub const DEFAULT_MAX_SDR4IOT_CSV_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_SDR4IOT_CSV_ROWS: u64 = 100_000;
pub const MAX_SDR4IOT_CSV_FIELD_BYTES: usize = 256;
pub const MAX_SDR4IOT_QUANTITY: f64 = 1_000_000_000_000.0;

const BASE_HEADER: [&[u8]; 5] = [
    b"Time",
    b"Start_trame",
    b"End_trame",
    b"Channel_frequency",
    b"Sample_rate",
];
const NODE_HEADER: [&[u8]; 8] = [
    b"Time",
    b"Start_trame",
    b"End_trame",
    b"Channel_frequency",
    b"Sample_rate",
    b"Robot_node",
    b"X",
    b"Y",
];
const POSE_HEADER: [&[u8]; 9] = [
    b"Time",
    b"Robot_Number",
    b"X",
    b"Y",
    b"Angle",
    b"Start_trame",
    b"End_trame",
    b"Central Frequency",
    b"Sample_rate",
];

/// One of the three publisher table layouts accepted by this adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Sdr4iotCsvSchemaVariantV0 {
    Base5,
    Node8,
    Pose9,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Sdr4iotSourceByteExtentV0 {
    start_byte: u64,
    end_byte: u64,
}

impl Sdr4iotSourceByteExtentV0 {
    pub const fn start_byte(&self) -> u64 {
        self.start_byte
    }

    pub const fn end_byte(&self) -> u64 {
        self.end_byte
    }
}

/// A detection row without publisher-local labels or position fields.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sdr4iotDetectionV0 {
    publisher_timestamp_us: i64,
    sample_start: u64,
    sample_end: u64,
    center_frequency_hz: f64,
    sample_rate_hz: f64,
}

impl Sdr4iotDetectionV0 {
    /// The publisher's timezone-free civil timestamp projected to microseconds.
    ///
    /// This supports ordering and clock-offset comparison within the source; it
    /// does not assert that the publisher clock was synchronized to UTC.
    pub const fn publisher_timestamp_us(&self) -> i64 {
        self.publisher_timestamp_us
    }

    pub const fn sample_start(&self) -> u64 {
        self.sample_start
    }

    pub const fn sample_end(&self) -> u64 {
        self.sample_end
    }

    pub const fn center_frequency_hz(&self) -> f64 {
        self.center_frequency_hz
    }

    pub const fn sample_rate_hz(&self) -> f64 {
        self.sample_rate_hz
    }
}

/// Ordered detections and the content boundary from which they were projected.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Sdr4iotDetectionStreamV0 {
    schema: &'static str,
    source_byte_extent: Sdr4iotSourceByteExtentV0,
    source_sha256: String,
    schema_variant: Sdr4iotCsvSchemaVariantV0,
    detections: Vec<Sdr4iotDetectionV0>,
}

impl Sdr4iotDetectionStreamV0 {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub const fn source_byte_extent(&self) -> Sdr4iotSourceByteExtentV0 {
        self.source_byte_extent
    }

    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    pub const fn schema_variant(&self) -> Sdr4iotCsvSchemaVariantV0 {
        self.schema_variant
    }

    pub fn detections(&self) -> &[Sdr4iotDetectionV0] {
        &self.detections
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Sdr4iotCsvOptions {
    pub max_bytes: u64,
    pub max_rows: u64,
}

impl Default for Sdr4iotCsvOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_SDR4IOT_CSV_BYTES,
            max_rows: DEFAULT_MAX_SDR4IOT_CSV_ROWS,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Sdr4iotCsvAdapterError {
    InvalidOption(&'static str),
    UnsupportedPlatform,
    SourceMetadata(io::Error),
    SourceOpen(io::Error),
    SourceRead(io::Error),
    SourceSymlink,
    SourceNotRegular,
    SourceChanged,
    ByteLimitExceeded,
    RowLimitExceeded,
    Csv(csv::Error),
    DuplicateHeader,
    SchemaMismatch,
    FieldSizeLimit { row: u64 },
    InvalidRow { row: u64 },
    InvalidTimestamp { row: u64 },
    InvalidSampleExtent { row: u64 },
    InvalidCenterFrequency { row: u64 },
    InvalidSampleRate { row: u64 },
    InvalidAuxiliaryField { row: u64 },
}

impl std::fmt::Display for Sdr4iotCsvAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(name) => write!(formatter, "invalid SDR4IoT CSV option {name}"),
            Self::UnsupportedPlatform => {
                formatter.write_str("SDR4IoT CSV projection requires a no-follow file boundary")
            }
            Self::SourceMetadata(_) => formatter.write_str("could not inspect SDR4IoT CSV source"),
            Self::SourceOpen(_) => formatter.write_str("could not open SDR4IoT CSV source"),
            Self::SourceRead(_) => formatter.write_str("could not read SDR4IoT CSV source"),
            Self::SourceSymlink => formatter.write_str("SDR4IoT CSV source is a symlink"),
            Self::SourceNotRegular => {
                formatter.write_str("SDR4IoT CSV source is not a regular file")
            }
            Self::SourceChanged => {
                formatter.write_str("SDR4IoT CSV source changed during projection")
            }
            Self::ByteLimitExceeded => {
                formatter.write_str("SDR4IoT CSV source exceeds its byte bound")
            }
            Self::RowLimitExceeded => {
                formatter.write_str("SDR4IoT CSV source exceeds its row bound")
            }
            Self::Csv(_) => formatter.write_str("SDR4IoT CSV is not a valid CSV document"),
            Self::DuplicateHeader => formatter.write_str("SDR4IoT CSV header contains a duplicate"),
            Self::SchemaMismatch => formatter.write_str("SDR4IoT CSV header is not registered"),
            Self::FieldSizeLimit { row } => {
                write!(formatter, "SDR4IoT CSV row {row} exceeds its field bound")
            }
            Self::InvalidRow { row } => write!(formatter, "SDR4IoT CSV row {row} is malformed"),
            Self::InvalidTimestamp { row } => {
                write!(formatter, "SDR4IoT CSV row {row} has an invalid timestamp")
            }
            Self::InvalidSampleExtent { row } => {
                write!(
                    formatter,
                    "SDR4IoT CSV row {row} has an invalid sample extent"
                )
            }
            Self::InvalidCenterFrequency { row } => {
                write!(
                    formatter,
                    "SDR4IoT CSV row {row} has an invalid center frequency"
                )
            }
            Self::InvalidSampleRate { row } => {
                write!(
                    formatter,
                    "SDR4IoT CSV row {row} has an invalid sample rate"
                )
            }
            Self::InvalidAuxiliaryField { row } => {
                write!(
                    formatter,
                    "SDR4IoT CSV row {row} has an invalid auxiliary field"
                )
            }
        }
    }
}

impl std::error::Error for Sdr4iotCsvAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceMetadata(source) | Self::SourceOpen(source) | Self::SourceRead(source) => {
                Some(source)
            }
            Self::Csv(source) => Some(source),
            _ => None,
        }
    }
}

/// Project one static publisher CSV without retaining unselected columns.
pub fn project_sdr4iot_csv(
    path: &Path,
    options: &Sdr4iotCsvOptions,
) -> Result<Sdr4iotDetectionStreamV0, Sdr4iotCsvAdapterError> {
    project_sdr4iot_csv_with_hook(path, options, || {})
}

fn project_sdr4iot_csv_with_hook(
    path: &Path,
    options: &Sdr4iotCsvOptions,
    after_read: impl FnOnce(),
) -> Result<Sdr4iotDetectionStreamV0, Sdr4iotCsvAdapterError> {
    validate_options(options)?;
    let (file, identity) = open_regular(path)?;
    if identity.len > options.max_bytes {
        return Err(Sdr4iotCsvAdapterError::ByteLimitExceeded);
    }
    let length =
        usize::try_from(identity.len).map_err(|_| Sdr4iotCsvAdapterError::ByteLimitExceeded)?;
    let mut bytes = vec![0_u8; length];
    let mut source = &file;
    source
        .read_exact(&mut bytes)
        .map_err(Sdr4iotCsvAdapterError::SourceRead)?;
    after_read();
    fence_source(path, &file, &identity)?;

    let source_sha256 = format!("sha256:{:x}", Sha256::digest(&bytes));
    let (schema_variant, detections) = parse_csv(&bytes, options.max_rows)?;
    Ok(Sdr4iotDetectionStreamV0 {
        schema: SDR4IOT_DETECTION_STREAM_SCHEMA_V0,
        source_byte_extent: Sdr4iotSourceByteExtentV0 {
            start_byte: 0,
            end_byte: identity.len,
        },
        source_sha256,
        schema_variant,
        detections,
    })
}

fn validate_options(options: &Sdr4iotCsvOptions) -> Result<(), Sdr4iotCsvAdapterError> {
    if options.max_bytes == 0 || options.max_bytes > DEFAULT_MAX_SDR4IOT_CSV_BYTES {
        return Err(Sdr4iotCsvAdapterError::InvalidOption("max_bytes"));
    }
    if options.max_rows == 0 || options.max_rows > DEFAULT_MAX_SDR4IOT_CSV_ROWS {
        return Err(Sdr4iotCsvAdapterError::InvalidOption("max_rows"));
    }
    Ok(())
}

fn parse_csv(
    bytes: &[u8],
    max_rows: u64,
) -> Result<(Sdr4iotCsvSchemaVariantV0, Vec<Sdr4iotDetectionV0>), Sdr4iotCsvAdapterError> {
    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .flexible(true)
        .from_reader(bytes);
    let mut records = reader.byte_records();
    let header = records
        .next()
        .transpose()
        .map_err(Sdr4iotCsvAdapterError::Csv)?
        .ok_or(Sdr4iotCsvAdapterError::SchemaMismatch)?;
    if duplicate_field(&header) {
        return Err(Sdr4iotCsvAdapterError::DuplicateHeader);
    }
    let layout = Layout::from_header(&header)?;
    let mut detections = Vec::new();
    for record in records {
        let record = record.map_err(Sdr4iotCsvAdapterError::Csv)?;
        if record.is_empty() {
            continue;
        }
        let row = u64::try_from(detections.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if row > max_rows {
            return Err(Sdr4iotCsvAdapterError::RowLimitExceeded);
        }
        if record.len() != layout.field_count {
            return Err(Sdr4iotCsvAdapterError::InvalidRow { row });
        }
        if record
            .iter()
            .any(|field| field.len() > MAX_SDR4IOT_CSV_FIELD_BYTES)
        {
            return Err(Sdr4iotCsvAdapterError::FieldSizeLimit { row });
        }
        detections.push(parse_detection(&record, layout, row)?);
    }
    Ok((layout.variant, detections))
}

#[derive(Debug, Clone, Copy)]
struct Layout {
    variant: Sdr4iotCsvSchemaVariantV0,
    field_count: usize,
    timestamp: usize,
    sample_start: usize,
    sample_end: usize,
    center_frequency: usize,
    sample_rate: usize,
}

impl Layout {
    fn from_header(header: &ByteRecord) -> Result<Self, Sdr4iotCsvAdapterError> {
        if header_matches(header, &BASE_HEADER) {
            Ok(Self {
                variant: Sdr4iotCsvSchemaVariantV0::Base5,
                field_count: 5,
                timestamp: 0,
                sample_start: 1,
                sample_end: 2,
                center_frequency: 3,
                sample_rate: 4,
            })
        } else if header_matches(header, &NODE_HEADER) {
            Ok(Self {
                variant: Sdr4iotCsvSchemaVariantV0::Node8,
                field_count: 8,
                timestamp: 0,
                sample_start: 1,
                sample_end: 2,
                center_frequency: 3,
                sample_rate: 4,
            })
        } else if header_matches(header, &POSE_HEADER) {
            Ok(Self {
                variant: Sdr4iotCsvSchemaVariantV0::Pose9,
                field_count: 9,
                timestamp: 0,
                sample_start: 5,
                sample_end: 6,
                center_frequency: 7,
                sample_rate: 8,
            })
        } else {
            Err(Sdr4iotCsvAdapterError::SchemaMismatch)
        }
    }

    fn selected(self, index: usize) -> bool {
        [
            self.timestamp,
            self.sample_start,
            self.sample_end,
            self.center_frequency,
            self.sample_rate,
        ]
        .contains(&index)
    }
}

fn header_matches<const N: usize>(header: &ByteRecord, expected: &[&[u8]; N]) -> bool {
    header.len() == N
        && header
            .iter()
            .zip(expected)
            .all(|(left, right)| left == *right)
}

fn duplicate_field(header: &ByteRecord) -> bool {
    header
        .iter()
        .enumerate()
        .any(|(index, field)| header.iter().take(index).any(|prior| prior == field))
}

fn parse_detection(
    record: &ByteRecord,
    layout: Layout,
    row: u64,
) -> Result<Sdr4iotDetectionV0, Sdr4iotCsvAdapterError> {
    for (index, value) in record.iter().enumerate() {
        if !layout.selected(index) && parse_i64(value).is_none() {
            return Err(Sdr4iotCsvAdapterError::InvalidAuxiliaryField { row });
        }
    }
    let sample_start = parse_nonnegative_i64(record.get(layout.sample_start).unwrap())
        .ok_or(Sdr4iotCsvAdapterError::InvalidSampleExtent { row })?;
    let sample_end = parse_nonnegative_i64(record.get(layout.sample_end).unwrap())
        .ok_or(Sdr4iotCsvAdapterError::InvalidSampleExtent { row })?;
    if sample_end <= sample_start {
        return Err(Sdr4iotCsvAdapterError::InvalidSampleExtent { row });
    }
    Ok(Sdr4iotDetectionV0 {
        publisher_timestamp_us: parse_timestamp_us(record.get(layout.timestamp).unwrap())
            .ok_or(Sdr4iotCsvAdapterError::InvalidTimestamp { row })?,
        sample_start,
        sample_end,
        center_frequency_hz: parse_quantity(record.get(layout.center_frequency).unwrap())
            .ok_or(Sdr4iotCsvAdapterError::InvalidCenterFrequency { row })?,
        sample_rate_hz: parse_quantity(record.get(layout.sample_rate).unwrap())
            .ok_or(Sdr4iotCsvAdapterError::InvalidSampleRate { row })?,
    })
}

fn parse_nonnegative_i64(value: &[u8]) -> Option<u64> {
    let parsed = parse_i64(value)?;
    u64::try_from(parsed).ok()
}

fn parse_i64(value: &[u8]) -> Option<i64> {
    if value.is_empty() {
        return None;
    }
    let digits = value.strip_prefix(b"-").unwrap_or(value);
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(value).ok()?.parse().ok()
}

fn parse_quantity(value: &[u8]) -> Option<f64> {
    let value: f64 = std::str::from_utf8(value).ok()?.parse().ok()?;
    (value.is_finite() && value > 0.0 && value <= MAX_SDR4IOT_QUANTITY).then_some(value)
}

fn parse_timestamp_us(value: &[u8]) -> Option<i64> {
    if value.len() != 26
        || value[4] != b'-'
        || value[7] != b'-'
        || value[10] != b' '
        || value[13] != b':'
        || value[16] != b':'
        || value[19] != b'.'
    {
        return None;
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19, 20..26] {
        if !value[range].iter().all(u8::is_ascii_digit) {
            return None;
        }
    }
    let year = decimal_digits(&value[0..4])?;
    let month = decimal_digits(&value[5..7])?;
    let day = decimal_digits(&value[8..10])?;
    let hour = decimal_digits(&value[11..13])?;
    let minute = decimal_digits(&value[14..16])?;
    let second = decimal_digits(&value[17..19])?;
    let microsecond = decimal_digits(&value[20..26])?;
    if year == 0
        || !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }
    let days = days_from_civil(i64::from(year), month, day);
    days.checked_mul(86_400_000_000)?
        .checked_add(i64::from(hour) * 3_600_000_000)?
        .checked_add(i64::from(minute) * 60_000_000)?
        .checked_add(i64::from(second) * 1_000_000)?
        .checked_add(i64::from(microsecond))
}

fn decimal_digits(value: &[u8]) -> Option<u32> {
    value.iter().try_fold(0_u32, |number, byte| {
        number
            .checked_mul(10)?
            .checked_add(u32::from(byte.checked_sub(b'0')?))
    })
}

fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let adjusted_year = year - i64::from(month <= 2);
    let era = if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    } / 400;
    let year_of_era = adjusted_year - era * 400;
    let shifted_month = i64::from(month) + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
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

#[cfg(not(any(unix, windows)))]
fn open_regular(_path: &Path) -> Result<(File, FileIdentity), Sdr4iotCsvAdapterError> {
    Err(Sdr4iotCsvAdapterError::UnsupportedPlatform)
}

#[cfg(any(unix, windows))]
fn open_regular(path: &Path) -> Result<(File, FileIdentity), Sdr4iotCsvAdapterError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(Sdr4iotCsvAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(Sdr4iotCsvAdapterError::SourceSymlink);
    }
    if !path_metadata.is_file() {
        return Err(Sdr4iotCsvAdapterError::SourceNotRegular);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .map_err(Sdr4iotCsvAdapterError::SourceOpen)?;
    let opened_metadata = file
        .metadata()
        .map_err(Sdr4iotCsvAdapterError::SourceMetadata)?;
    if !opened_metadata.is_file() {
        return Err(Sdr4iotCsvAdapterError::SourceNotRegular);
    }
    let identity = FileIdentity::from_metadata(&path_metadata);
    if FileIdentity::from_metadata(&opened_metadata) != identity {
        return Err(Sdr4iotCsvAdapterError::SourceChanged);
    }
    Ok((file, identity))
}

fn fence_source(
    path: &Path,
    file: &File,
    expected: &FileIdentity,
) -> Result<(), Sdr4iotCsvAdapterError> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(Sdr4iotCsvAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(Sdr4iotCsvAdapterError::SourceChanged);
    }
    let opened_metadata = file
        .metadata()
        .map_err(Sdr4iotCsvAdapterError::SourceMetadata)?;
    if !path_metadata.is_file()
        || !opened_metadata.is_file()
        || FileIdentity::from_metadata(&path_metadata) != *expected
        || FileIdentity::from_metadata(&opened_metadata) != *expected
    {
        return Err(Sdr4iotCsvAdapterError::SourceChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn source_mutation_during_projection_is_rejected() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("detections.csv");
        fs::write(
            &path,
            b"Time,Start_trame,End_trame,Channel_frequency,Sample_rate\n",
        )
        .unwrap();

        let error = project_sdr4iot_csv_with_hook(&path, &Sdr4iotCsvOptions::default(), || {
            OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap()
                .write_all(b"\n")
                .unwrap();
        })
        .unwrap_err();

        assert!(matches!(error, Sdr4iotCsvAdapterError::SourceChanged));
    }
}
