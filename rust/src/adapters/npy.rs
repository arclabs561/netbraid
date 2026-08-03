//! Bounded positional projection of row windows from narrow NPY arrays.

use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::path::Path;

use serde::Serialize;

pub const NPY_ROW_WINDOW_METADATA_SCHEMA_V0: &str = "netbraid.npy_row_window_metadata.v0";

const NPY_PREFIX_BYTES: u64 = 10;
const DEFAULT_MAX_HEADER_BYTES: u64 = 4 * 1024;
const DEFAULT_MAX_WINDOW_BYTES: u64 = 16 * 1024 * 1024;
const HARD_MAX_HEADER_BYTES: u64 = u16::MAX as u64;
const HARD_MAX_WINDOW_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NpyDtypeV0 {
    Float64,
    ComplexFloat64,
}

impl NpyDtypeV0 {
    const fn element_bytes(self) -> u64 {
        match self {
            Self::Float64 => 8,
            Self::ComplexFloat64 => 16,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NpyShapeV0 {
    rows: u64,
    columns: u64,
}

impl NpyShapeV0 {
    pub const fn rows(&self) -> u64 {
        self.rows
    }

    pub const fn columns(&self) -> u64 {
        self.columns
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NpyRowIntervalV0 {
    first_row: u64,
    row_count: u64,
}

impl NpyRowIntervalV0 {
    const fn new(first_row: u64, row_count: u64) -> Self {
        Self {
            first_row,
            row_count,
        }
    }

    pub const fn first_row(&self) -> u64 {
        self.first_row
    }

    pub const fn row_count(&self) -> u64 {
        self.row_count
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum NpyWindowCompletenessV0 {
    Complete,
    Truncated,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct NpyValueCountsV0 {
    finite_components: u64,
    nonfinite_components: u64,
    zero_components: u64,
}

impl NpyValueCountsV0 {
    pub const fn finite_components(&self) -> u64 {
        self.finite_components
    }

    pub const fn nonfinite_components(&self) -> u64 {
        self.nonfinite_components
    }

    pub const fn zero_components(&self) -> u64 {
        self.zero_components
    }
}

/// Exact binary64 component summary without floating-point reduction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct NpyComponentAggregateV0 {
    positive_finite: u64,
    negative_finite: u64,
    subnormal: u64,
    minimum_finite_bits: Option<u64>,
    maximum_finite_bits: Option<u64>,
}

impl NpyComponentAggregateV0 {
    pub const fn positive_finite(&self) -> u64 {
        self.positive_finite
    }

    pub const fn negative_finite(&self) -> u64 {
        self.negative_finite
    }

    pub const fn subnormal(&self) -> u64 {
        self.subnormal
    }

    pub const fn minimum_finite_bits(&self) -> Option<u64> {
        self.minimum_finite_bits
    }

    pub const fn maximum_finite_bits(&self) -> Option<u64> {
        self.maximum_finite_bits
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum NpyDeterministicAggregatesV0 {
    Float64 {
        values: NpyComponentAggregateV0,
    },
    ComplexFloat64 {
        real: NpyComponentAggregateV0,
        imaginary: NpyComponentAggregateV0,
    },
}

impl NpyDeterministicAggregatesV0 {
    pub const fn values(&self) -> Option<NpyComponentAggregateV0> {
        match self {
            Self::Float64 { values } => Some(*values),
            Self::ComplexFloat64 { .. } => None,
        }
    }

    pub const fn real(&self) -> Option<NpyComponentAggregateV0> {
        match self {
            Self::Float64 { .. } => None,
            Self::ComplexFloat64 { real, .. } => Some(*real),
        }
    }

    pub const fn imaginary(&self) -> Option<NpyComponentAggregateV0> {
        match self {
            Self::Float64 { .. } => None,
            Self::ComplexFloat64 { imaginary, .. } => Some(*imaginary),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NpyRowWindowMetadataV0 {
    schema: &'static str,
    dtype: NpyDtypeV0,
    shape: NpyShapeV0,
    requested_rows: NpyRowIntervalV0,
    observed_rows: NpyRowIntervalV0,
    completeness: NpyWindowCompletenessV0,
    counts: NpyValueCountsV0,
    aggregates: NpyDeterministicAggregatesV0,
}

impl NpyRowWindowMetadataV0 {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub const fn dtype(&self) -> NpyDtypeV0 {
        self.dtype
    }

    pub const fn shape(&self) -> NpyShapeV0 {
        self.shape
    }

    pub const fn requested_rows(&self) -> NpyRowIntervalV0 {
        self.requested_rows
    }

    pub const fn observed_rows(&self) -> NpyRowIntervalV0 {
        self.observed_rows
    }

    pub const fn completeness(&self) -> NpyWindowCompletenessV0 {
        self.completeness
    }

    pub const fn counts(&self) -> NpyValueCountsV0 {
        self.counts
    }

    pub const fn aggregates(&self) -> NpyDeterministicAggregatesV0 {
        self.aggregates
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NpyReadAudit {
    requested_byte_offset: u64,
    requested_bytes: u64,
    observed_bytes: u64,
    read_calls: u64,
    maximum_single_read_bytes: u64,
}

impl NpyReadAudit {
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

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NpyRowWindowOptions {
    pub first_row: u64,
    pub row_count: u64,
    pub max_header_bytes: u64,
    pub max_window_bytes: u64,
}

impl Default for NpyRowWindowOptions {
    fn default() -> Self {
        Self {
            first_row: 0,
            row_count: 1,
            max_header_bytes: DEFAULT_MAX_HEADER_BYTES,
            max_window_bytes: DEFAULT_MAX_WINDOW_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NpyRowWindowProjection {
    metadata: NpyRowWindowMetadataV0,
    read_audit: NpyReadAudit,
}

impl NpyRowWindowProjection {
    pub const fn metadata(&self) -> &NpyRowWindowMetadataV0 {
        &self.metadata
    }

    pub const fn read_audit(&self) -> NpyReadAudit {
        self.read_audit
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum NpyAdapterError {
    InvalidOption(&'static str),
    SourceMetadata(io::Error),
    SourceOpen(io::Error),
    SourceRead(io::Error),
    SourceSymlink,
    SourceNotRegular,
    SourceChanged,
    UnsupportedVersion,
    HeaderTooLarge,
    TruncatedHeader,
    InvalidHeader,
    UnsupportedDtype,
    UnsupportedOrder,
    UnsupportedRank,
    InvalidShape,
    ShapeOverflow,
    ExtentOverflow,
    ExtentMismatch {
        expected_bytes: u64,
        actual_bytes: u64,
    },
    WindowOffsetOverflow,
    WindowLengthOverflow,
    WindowTooLarge,
}

impl std::fmt::Display for NpyAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(name) => write!(formatter, "invalid NPY option {name}"),
            Self::SourceMetadata(_) => formatter.write_str("could not inspect NPY source"),
            Self::SourceOpen(_) => formatter.write_str("could not open NPY source"),
            Self::SourceRead(_) => formatter.write_str("could not read NPY source"),
            Self::SourceSymlink => formatter.write_str("NPY source is a symlink"),
            Self::SourceNotRegular => formatter.write_str("NPY source is not a regular file"),
            Self::SourceChanged => formatter.write_str("NPY source changed during projection"),
            Self::UnsupportedVersion => formatter.write_str("only NPY version 1.0 is supported"),
            Self::HeaderTooLarge => formatter.write_str("NPY header exceeds its byte bound"),
            Self::TruncatedHeader => formatter.write_str("NPY header is truncated"),
            Self::InvalidHeader => formatter.write_str("NPY header is invalid"),
            Self::UnsupportedDtype => formatter.write_str("NPY dtype is not supported"),
            Self::UnsupportedOrder => formatter.write_str("Fortran-order NPY is not supported"),
            Self::UnsupportedRank => formatter.write_str("NPY array must have rank 2"),
            Self::InvalidShape => formatter.write_str("NPY shape must contain positive extents"),
            Self::ShapeOverflow => formatter.write_str("NPY row shape byte length overflows"),
            Self::ExtentOverflow => formatter.write_str("NPY declared file extent overflows"),
            Self::ExtentMismatch { .. } => {
                formatter.write_str("NPY file extent does not match its header")
            }
            Self::WindowOffsetOverflow => formatter.write_str("NPY window byte offset overflows"),
            Self::WindowLengthOverflow => formatter.write_str("NPY window byte length overflows"),
            Self::WindowTooLarge => formatter.write_str("NPY window exceeds its byte bound"),
        }
    }
}

impl std::error::Error for NpyAdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SourceMetadata(source) | Self::SourceOpen(source) | Self::SourceRead(source) => {
                Some(source)
            }
            _ => None,
        }
    }
}

pub fn project_npy_row_window(
    path: &Path,
    options: &NpyRowWindowOptions,
) -> Result<NpyRowWindowProjection, NpyAdapterError> {
    project_npy_row_window_with_hook(path, options, || {})
}

fn project_npy_row_window_with_hook(
    path: &Path,
    options: &NpyRowWindowOptions,
    after_data_read: impl FnOnce(),
) -> Result<NpyRowWindowProjection, NpyAdapterError> {
    validate_options(options)?;
    let (file, identity) = open_regular(path)?;
    let header = read_header(&file, identity.len, options.max_header_bytes)?;

    let row_bytes = header
        .shape
        .columns
        .checked_mul(header.dtype.element_bytes())
        .ok_or(NpyAdapterError::ShapeOverflow)?;
    let payload_bytes = header
        .shape
        .rows
        .checked_mul(row_bytes)
        .ok_or(NpyAdapterError::ExtentOverflow)?;
    let expected_bytes = header
        .data_offset
        .checked_add(payload_bytes)
        .ok_or(NpyAdapterError::ExtentOverflow)?;
    if expected_bytes != identity.len {
        return Err(NpyAdapterError::ExtentMismatch {
            expected_bytes,
            actual_bytes: identity.len,
        });
    }

    let requested_row_offset = options
        .first_row
        .checked_mul(row_bytes)
        .ok_or(NpyAdapterError::WindowOffsetOverflow)?;
    let requested_byte_offset = header
        .data_offset
        .checked_add(requested_row_offset)
        .ok_or(NpyAdapterError::WindowOffsetOverflow)?;
    let requested_bytes = options
        .row_count
        .checked_mul(row_bytes)
        .ok_or(NpyAdapterError::WindowLengthOverflow)?;
    if requested_bytes > options.max_window_bytes {
        return Err(NpyAdapterError::WindowTooLarge);
    }

    let observed_row_count = header
        .shape
        .rows
        .saturating_sub(options.first_row)
        .min(options.row_count);
    let observed_bytes = observed_row_count
        .checked_mul(row_bytes)
        .ok_or(NpyAdapterError::WindowLengthOverflow)?;
    let mut read_audit = NpyReadAudit {
        requested_byte_offset,
        requested_bytes,
        ..NpyReadAudit::default()
    };
    let bytes = read_exact_range(
        &file,
        requested_byte_offset,
        observed_bytes,
        Some(&mut read_audit),
    )?;
    after_data_read();
    fence_source(path, &file, &identity)?;

    let completeness = if observed_row_count == options.row_count {
        NpyWindowCompletenessV0::Complete
    } else {
        NpyWindowCompletenessV0::Truncated
    };
    let (counts, aggregates) = summarize(&bytes, header.dtype);
    Ok(NpyRowWindowProjection {
        metadata: NpyRowWindowMetadataV0 {
            schema: NPY_ROW_WINDOW_METADATA_SCHEMA_V0,
            dtype: header.dtype,
            shape: header.shape,
            requested_rows: NpyRowIntervalV0::new(options.first_row, options.row_count),
            observed_rows: NpyRowIntervalV0::new(options.first_row, observed_row_count),
            completeness,
            counts,
            aggregates,
        },
        read_audit,
    })
}

fn validate_options(options: &NpyRowWindowOptions) -> Result<(), NpyAdapterError> {
    if options.row_count == 0 {
        return Err(NpyAdapterError::InvalidOption("row_count"));
    }
    if options.max_header_bytes == 0 || options.max_header_bytes > HARD_MAX_HEADER_BYTES {
        return Err(NpyAdapterError::InvalidOption("max_header_bytes"));
    }
    if options.max_window_bytes == 0 || options.max_window_bytes > HARD_MAX_WINDOW_BYTES {
        return Err(NpyAdapterError::InvalidOption("max_window_bytes"));
    }
    Ok(())
}

#[derive(Debug)]
struct ParsedHeader {
    dtype: NpyDtypeV0,
    shape: NpyShapeV0,
    data_offset: u64,
}

fn read_header(
    file: &File,
    file_len: u64,
    max_header_bytes: u64,
) -> Result<ParsedHeader, NpyAdapterError> {
    if file_len < NPY_PREFIX_BYTES {
        return Err(NpyAdapterError::TruncatedHeader);
    }
    let prefix = read_exact_range(file, 0, NPY_PREFIX_BYTES, None)?;
    if prefix[..6] != *b"\x93NUMPY" {
        return Err(NpyAdapterError::InvalidHeader);
    }
    if prefix[6..8] != [1, 0] {
        return Err(NpyAdapterError::UnsupportedVersion);
    }
    let header_len = u64::from(u16::from_le_bytes([prefix[8], prefix[9]]));
    if header_len == 0 {
        return Err(NpyAdapterError::InvalidHeader);
    }
    if header_len > max_header_bytes {
        return Err(NpyAdapterError::HeaderTooLarge);
    }
    let data_offset = NPY_PREFIX_BYTES
        .checked_add(header_len)
        .ok_or(NpyAdapterError::ExtentOverflow)?;
    if data_offset > file_len {
        return Err(NpyAdapterError::TruncatedHeader);
    }
    if data_offset % 16 != 0 {
        return Err(NpyAdapterError::InvalidHeader);
    }
    let bytes = read_exact_range(file, NPY_PREFIX_BYTES, header_len, None)?;
    let parsed = parse_header_dictionary(&bytes)?;
    Ok(ParsedHeader {
        dtype: parsed.dtype,
        shape: parsed.shape,
        data_offset,
    })
}

struct HeaderDictionary {
    dtype: NpyDtypeV0,
    shape: NpyShapeV0,
}

fn parse_header_dictionary(bytes: &[u8]) -> Result<HeaderDictionary, NpyAdapterError> {
    if bytes.last() != Some(&b'\n') || !bytes.is_ascii() {
        return Err(NpyAdapterError::InvalidHeader);
    }
    let mut parser = HeaderParser::new(&bytes[..bytes.len() - 1]);
    parser.skip_whitespace();
    parser.expect(b'{')?;

    let mut dtype = None;
    let mut fortran_order = None;
    let mut shape = None;
    loop {
        parser.skip_whitespace();
        if parser.consume(b'}') {
            break;
        }
        let key = parser.parse_string()?;
        parser.skip_whitespace();
        parser.expect(b':')?;
        parser.skip_whitespace();
        match key.as_str() {
            "descr" if dtype.is_none() => {
                dtype = Some(match parser.parse_string()?.as_str() {
                    "<f8" => NpyDtypeV0::Float64,
                    "<c16" => NpyDtypeV0::ComplexFloat64,
                    _ => return Err(NpyAdapterError::UnsupportedDtype),
                });
            }
            "fortran_order" if fortran_order.is_none() => {
                let value = parser.parse_bool()?;
                if value {
                    return Err(NpyAdapterError::UnsupportedOrder);
                }
                fortran_order = Some(false);
            }
            "shape" if shape.is_none() => {
                let extents = parser.parse_shape()?;
                if extents.len() != 2 {
                    return Err(NpyAdapterError::UnsupportedRank);
                }
                if extents[0] == 0 || extents[1] == 0 {
                    return Err(NpyAdapterError::InvalidShape);
                }
                shape = Some(NpyShapeV0 {
                    rows: extents[0],
                    columns: extents[1],
                });
            }
            _ => return Err(NpyAdapterError::InvalidHeader),
        }
        parser.skip_whitespace();
        if parser.consume(b',') {
            continue;
        }
        parser.expect(b'}')?;
        break;
    }
    parser.skip_whitespace();
    if !parser.is_finished() {
        return Err(NpyAdapterError::InvalidHeader);
    }
    fortran_order.ok_or(NpyAdapterError::InvalidHeader)?;
    Ok(HeaderDictionary {
        dtype: dtype.ok_or(NpyAdapterError::InvalidHeader)?,
        shape: shape.ok_or(NpyAdapterError::InvalidHeader)?,
    })
}

struct HeaderParser<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> HeaderParser<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn skip_whitespace(&mut self) {
        while self
            .bytes
            .get(self.position)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.position += 1;
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.bytes.get(self.position) == Some(&expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: u8) -> Result<(), NpyAdapterError> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(NpyAdapterError::InvalidHeader)
        }
    }

    fn parse_string(&mut self) -> Result<String, NpyAdapterError> {
        let quote = *self
            .bytes
            .get(self.position)
            .filter(|value| **value == b'\'' || **value == b'"')
            .ok_or(NpyAdapterError::InvalidHeader)?;
        self.position += 1;
        let start = self.position;
        while let Some(value) = self.bytes.get(self.position) {
            if *value == quote {
                let value = std::str::from_utf8(&self.bytes[start..self.position])
                    .map_err(|_| NpyAdapterError::InvalidHeader)?;
                self.position += 1;
                return Ok(value.to_owned());
            }
            if *value == b'\\' || value.is_ascii_control() {
                return Err(NpyAdapterError::InvalidHeader);
            }
            self.position += 1;
        }
        Err(NpyAdapterError::InvalidHeader)
    }

    fn parse_bool(&mut self) -> Result<bool, NpyAdapterError> {
        if self.bytes[self.position..].starts_with(b"False") {
            self.position += 5;
            Ok(false)
        } else if self.bytes[self.position..].starts_with(b"True") {
            self.position += 4;
            Ok(true)
        } else {
            Err(NpyAdapterError::InvalidHeader)
        }
    }

    fn parse_shape(&mut self) -> Result<Vec<u64>, NpyAdapterError> {
        self.expect(b'(')?;
        self.skip_whitespace();
        let mut extents = Vec::new();
        if self.consume(b')') {
            return Ok(extents);
        }
        loop {
            extents.push(self.parse_u64()?);
            self.skip_whitespace();
            if self.consume(b')') {
                break;
            }
            self.expect(b',')?;
            self.skip_whitespace();
            if self.consume(b')') {
                break;
            }
        }
        Ok(extents)
    }

    fn parse_u64(&mut self) -> Result<u64, NpyAdapterError> {
        let start = self.position;
        let mut value = 0u64;
        while let Some(digit) = self.bytes.get(self.position).and_then(|byte| {
            if byte.is_ascii_digit() {
                Some(u64::from(*byte - b'0'))
            } else {
                None
            }
        }) {
            value = value
                .checked_mul(10)
                .and_then(|value| value.checked_add(digit))
                .ok_or(NpyAdapterError::ShapeOverflow)?;
            self.position += 1;
        }
        if self.position == start {
            Err(NpyAdapterError::InvalidHeader)
        } else {
            Ok(value)
        }
    }

    fn is_finished(&self) -> bool {
        self.position == self.bytes.len()
    }
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

fn open_regular(path: &Path) -> Result<(File, FileIdentity), NpyAdapterError> {
    let path_metadata = fs::symlink_metadata(path).map_err(NpyAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(NpyAdapterError::SourceSymlink);
    }
    if !path_metadata.is_file() {
        return Err(NpyAdapterError::SourceNotRegular);
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(NpyAdapterError::SourceOpen)?;
    let opened_metadata = file.metadata().map_err(NpyAdapterError::SourceMetadata)?;
    if !opened_metadata.is_file() {
        return Err(NpyAdapterError::SourceNotRegular);
    }
    let path_identity = FileIdentity::from_metadata(&path_metadata);
    let opened_identity = FileIdentity::from_metadata(&opened_metadata);
    if path_identity != opened_identity {
        return Err(NpyAdapterError::SourceChanged);
    }
    Ok((file, opened_identity))
}

fn fence_source(path: &Path, file: &File, expected: &FileIdentity) -> Result<(), NpyAdapterError> {
    let path_metadata = fs::symlink_metadata(path).map_err(NpyAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(NpyAdapterError::SourceChanged);
    }
    let opened_metadata = file.metadata().map_err(NpyAdapterError::SourceMetadata)?;
    if !path_metadata.is_file()
        || !opened_metadata.is_file()
        || FileIdentity::from_metadata(&path_metadata) != *expected
        || FileIdentity::from_metadata(&opened_metadata) != *expected
    {
        return Err(NpyAdapterError::SourceChanged);
    }
    Ok(())
}

fn read_exact_range(
    file: &File,
    offset: u64,
    length: u64,
    mut audit: Option<&mut NpyReadAudit>,
) -> Result<Vec<u8>, NpyAdapterError> {
    let length_usize = usize::try_from(length).map_err(|_| NpyAdapterError::WindowTooLarge)?;
    let mut bytes = vec![0u8; length_usize];
    let mut filled = 0usize;
    while filled < bytes.len() {
        let read_offset = offset
            .checked_add(u64::try_from(filled).expect("bounded buffer length fits u64"))
            .ok_or(NpyAdapterError::WindowOffsetOverflow)?;
        if let Some(audit) = audit.as_deref_mut() {
            audit.read_calls += 1;
            audit.maximum_single_read_bytes = audit
                .maximum_single_read_bytes
                .max(u64::try_from(bytes.len() - filled).expect("bounded read length fits u64"));
        }
        let read = positional_read(file, &mut bytes[filled..], read_offset)
            .map_err(NpyAdapterError::SourceRead)?;
        if read == 0 {
            return Err(NpyAdapterError::SourceRead(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "NPY source ended during positional read",
            )));
        }
        filled += read;
    }
    if let Some(audit) = audit {
        audit.observed_bytes = length;
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
    minimum: Option<f64>,
    maximum: Option<f64>,
}

impl ComponentAccumulator {
    fn observe(&mut self, value: f64) {
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

    fn finish(self) -> NpyComponentAggregateV0 {
        NpyComponentAggregateV0 {
            positive_finite: self.positive_finite,
            negative_finite: self.negative_finite,
            subnormal: self.subnormal,
            minimum_finite_bits: self.minimum.map(f64::to_bits),
            maximum_finite_bits: self.maximum.map(f64::to_bits),
        }
    }
}

fn summarize(bytes: &[u8], dtype: NpyDtypeV0) -> (NpyValueCountsV0, NpyDeterministicAggregatesV0) {
    let mut counts = NpyValueCountsV0::default();
    let mut primary = ComponentAccumulator::default();
    let mut secondary = ComponentAccumulator::default();
    for (index, encoded) in bytes.as_chunks::<8>().0.iter().enumerate() {
        let value = f64::from_le_bytes(*encoded);
        if value.is_finite() {
            counts.finite_components += 1;
            if value == 0.0 {
                counts.zero_components += 1;
            }
        } else {
            counts.nonfinite_components += 1;
        }
        if dtype == NpyDtypeV0::ComplexFloat64 && index % 2 == 1 {
            secondary.observe(value);
        } else {
            primary.observe(value);
        }
    }
    let aggregates = match dtype {
        NpyDtypeV0::Float64 => NpyDeterministicAggregatesV0::Float64 {
            values: primary.finish(),
        },
        NpyDtypeV0::ComplexFloat64 => NpyDeterministicAggregatesV0::ComplexFloat64 {
            real: primary.finish(),
            imaginary: secondary.finish(),
        },
    };
    (counts, aggregates)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    fn npy_bytes(dictionary: &str, payload: &[u8]) -> Vec<u8> {
        let mut header = dictionary.as_bytes().to_vec();
        let padding = (16 - ((NPY_PREFIX_BYTES as usize + header.len() + 1) % 16)) % 16;
        header.extend(std::iter::repeat_n(b' ', padding));
        header.push(b'\n');
        let mut bytes = b"\x93NUMPY\x01\x00".to_vec();
        bytes.extend(u16::try_from(header.len()).unwrap().to_le_bytes());
        bytes.extend(header);
        bytes.extend(payload);
        bytes
    }

    #[test]
    fn post_read_identity_fence_detects_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mutation.npy");
        fs::write(
            &path,
            npy_bytes(
                "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), }",
                &1.0f64.to_le_bytes(),
            ),
        )
        .unwrap();

        let error =
            project_npy_row_window_with_hook(&path, &NpyRowWindowOptions::default(), || {
                let mut file = OpenOptions::new().write(true).open(&path).unwrap();
                file.seek(SeekFrom::End(-8)).unwrap();
                file.write_all(&2.0f64.to_le_bytes()).unwrap();
                file.sync_all().unwrap();
            })
            .unwrap_err();
        assert!(matches!(error, NpyAdapterError::SourceChanged));
    }
}
