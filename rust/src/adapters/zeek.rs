//! Bounded projection of canonical, full-metadata Zeek ASCII `conn.log` session evidence.

use std::collections::BTreeSet;
use std::fs::OpenOptions;
use std::fs::{self, File, Metadata};
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::Path;

use csv::ReaderBuilder;
use serde::Serialize;

pub const ZEEK_CONN_STREAM_SCHEMA_V0: &str = "netbraid.zeek_conn_stream.v0";
pub const DEFAULT_MAX_ZEEK_CONN_BYTES: u64 = 16 * 1024 * 1024;
pub const DEFAULT_MAX_ZEEK_CONN_ROWS: u64 = 100_000;
pub const HARD_MAX_ZEEK_CONN_BYTES: u64 = 64 * 1024 * 1024;
pub const HARD_MAX_ZEEK_CONN_ROWS: u64 = 1_000_000;

const REQUIRED_FIELDS: [(&str, &str); 11] = [
    ("ts", "time"),
    ("id.orig_h", "addr"),
    ("id.orig_p", "port"),
    ("id.resp_h", "addr"),
    ("id.resp_p", "port"),
    ("proto", "enum"),
    ("duration", "interval"),
    ("orig_pkts", "count"),
    ("orig_ip_bytes", "count"),
    ("resp_pkts", "count"),
    ("resp_ip_bytes", "count"),
];
const MAX_ZEEK_CONN_FIELDS: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ZeekConnProtocolV0 {
    Tcp,
    Udp,
    Icmp,
    UnknownTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ZeekConnEndpointV0 {
    address: IpAddr,
    port: u16,
}

impl ZeekConnEndpointV0 {
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    pub const fn port(&self) -> u16 {
        self.port
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct ZeekConnV0 {
    start_time_unix_ns: i64,
    originator: ZeekConnEndpointV0,
    responder: ZeekConnEndpointV0,
    protocol: ZeekConnProtocolV0,
    duration_ns: Option<u64>,
    orig_packets: Option<u64>,
    orig_ip_bytes: Option<u64>,
    resp_packets: Option<u64>,
    resp_ip_bytes: Option<u64>,
}

impl ZeekConnV0 {
    pub const fn start_time_unix_ns(&self) -> i64 {
        self.start_time_unix_ns
    }

    pub const fn originator(&self) -> &ZeekConnEndpointV0 {
        &self.originator
    }

    pub const fn responder(&self) -> &ZeekConnEndpointV0 {
        &self.responder
    }

    pub const fn protocol(&self) -> ZeekConnProtocolV0 {
        self.protocol
    }

    pub const fn duration_ns(&self) -> Option<u64> {
        self.duration_ns
    }

    pub const fn orig_packets(&self) -> Option<u64> {
        self.orig_packets
    }

    pub const fn orig_ip_bytes(&self) -> Option<u64> {
        self.orig_ip_bytes
    }

    pub const fn resp_packets(&self) -> Option<u64> {
        self.resp_packets
    }

    pub const fn resp_ip_bytes(&self) -> Option<u64> {
        self.resp_ip_bytes
    }
}

/// Zeek-sessionized connections, sorted only by retained semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZeekConnStreamV0 {
    schema: &'static str,
    connections: Vec<ZeekConnV0>,
}

impl ZeekConnStreamV0 {
    pub const fn schema(&self) -> &'static str {
        self.schema
    }

    pub fn connections(&self) -> &[ZeekConnV0] {
        &self.connections
    }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ZeekConnOptions {
    pub max_bytes: u64,
    pub max_rows: u64,
}

impl Default for ZeekConnOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_ZEEK_CONN_BYTES,
            max_rows: DEFAULT_MAX_ZEEK_CONN_ROWS,
        }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum ZeekAdapterError {
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
    MissingDirective(&'static str),
    MalformedDirective(&'static str),
    UnexpectedDirective,
    InvalidPath,
    DuplicateField,
    MissingField(&'static str),
    InvalidFieldType(&'static str),
    InvalidRow { row: u64 },
    InvalidValue { row: u64, field: &'static str },
    Csv(csv::Error),
}

impl std::fmt::Display for ZeekAdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(name) => write!(formatter, "invalid Zeek option {name}"),
            Self::UnsupportedPlatform => {
                formatter.write_str("Zeek projection requires a Unix no-follow file boundary")
            }
            Self::SourceMetadata(_) => formatter.write_str("could not inspect Zeek source"),
            Self::SourceOpen(_) => formatter.write_str("could not open Zeek source"),
            Self::SourceRead(_) => formatter.write_str("could not read Zeek source"),
            Self::SourceSymlink => formatter.write_str("Zeek source is a symlink"),
            Self::SourceNotRegular => formatter.write_str("Zeek source is not a regular file"),
            Self::SourceChanged => formatter.write_str("Zeek source changed during projection"),
            Self::ByteLimitExceeded => formatter.write_str("Zeek source exceeds its byte bound"),
            Self::RowLimitExceeded => formatter.write_str("Zeek source exceeds its row bound"),
            Self::MissingDirective(name) => write!(formatter, "Zeek source is missing {name}"),
            Self::MalformedDirective(name) => write!(formatter, "Zeek directive {name} is invalid"),
            Self::UnexpectedDirective => {
                formatter.write_str("Zeek source contains an unexpected directive")
            }
            Self::InvalidPath => formatter.write_str("Zeek log path is not conn"),
            Self::DuplicateField => formatter.write_str("Zeek field list contains a duplicate"),
            Self::MissingField(name) => write!(formatter, "Zeek conn log is missing field {name}"),
            Self::InvalidFieldType(name) => {
                write!(formatter, "Zeek conn field {name} has an invalid type")
            }
            Self::InvalidRow { row } => write!(formatter, "Zeek conn row {row} is malformed"),
            Self::InvalidValue { row, field } => {
                write!(formatter, "Zeek conn row {row} has an invalid {field}")
            }
            Self::Csv(_) => formatter.write_str("Zeek conn rows are not valid delimited records"),
        }
    }
}

impl std::error::Error for ZeekAdapterError {
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

/// Project one static, full-metadata Zeek ASCII `conn.log` using the default `#` prefix.
///
/// Source-local and unselected columns are not retained. The source is opened
/// without following filesystem links and fenced against in-place mutation.
pub fn project_zeek_conn_log(
    path: &Path,
    options: &ZeekConnOptions,
) -> Result<ZeekConnStreamV0, ZeekAdapterError> {
    project_zeek_conn_log_with_hook(path, options, || {})
}

fn project_zeek_conn_log_with_hook(
    path: &Path,
    options: &ZeekConnOptions,
    after_read: impl FnOnce(),
) -> Result<ZeekConnStreamV0, ZeekAdapterError> {
    validate_options(options)?;
    let (file, identity) = open_regular(path)?;
    if identity.len > options.max_bytes {
        return Err(ZeekAdapterError::ByteLimitExceeded);
    }
    let length = usize::try_from(identity.len).map_err(|_| ZeekAdapterError::ByteLimitExceeded)?;
    let mut bytes = vec![0_u8; length];
    let mut source = &file;
    source
        .read_exact(&mut bytes)
        .map_err(ZeekAdapterError::SourceRead)?;
    after_read();
    fence_source(path, &file, &identity)?;
    let mut connections = parse_conn_log(&bytes, options.max_rows)?;
    connections.sort();
    Ok(ZeekConnStreamV0 {
        schema: ZEEK_CONN_STREAM_SCHEMA_V0,
        connections,
    })
}

fn validate_options(options: &ZeekConnOptions) -> Result<(), ZeekAdapterError> {
    if options.max_bytes == 0 || options.max_bytes > HARD_MAX_ZEEK_CONN_BYTES {
        return Err(ZeekAdapterError::InvalidOption("max_bytes"));
    }
    if options.max_rows == 0 || options.max_rows > HARD_MAX_ZEEK_CONN_ROWS {
        return Err(ZeekAdapterError::InvalidOption("max_rows"));
    }
    Ok(())
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
fn open_regular(_path: &Path) -> Result<(File, FileIdentity), ZeekAdapterError> {
    Err(ZeekAdapterError::UnsupportedPlatform)
}

#[cfg(any(unix, windows))]
fn open_regular(path: &Path) -> Result<(File, FileIdentity), ZeekAdapterError> {
    let path_metadata = fs::symlink_metadata(path).map_err(ZeekAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(ZeekAdapterError::SourceSymlink);
    }
    if !path_metadata.is_file() {
        return Err(ZeekAdapterError::SourceNotRegular);
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
    let file = options.open(path).map_err(ZeekAdapterError::SourceOpen)?;
    let opened_metadata = file.metadata().map_err(ZeekAdapterError::SourceMetadata)?;
    if !opened_metadata.is_file() {
        return Err(ZeekAdapterError::SourceNotRegular);
    }
    let identity = FileIdentity::from_metadata(&path_metadata);
    if FileIdentity::from_metadata(&opened_metadata) != identity {
        return Err(ZeekAdapterError::SourceChanged);
    }
    Ok((file, identity))
}

fn fence_source(path: &Path, file: &File, expected: &FileIdentity) -> Result<(), ZeekAdapterError> {
    let path_metadata = fs::symlink_metadata(path).map_err(ZeekAdapterError::SourceMetadata)?;
    if path_metadata.file_type().is_symlink() {
        return Err(ZeekAdapterError::SourceChanged);
    }
    let opened_metadata = file.metadata().map_err(ZeekAdapterError::SourceMetadata)?;
    if !path_metadata.is_file()
        || !opened_metadata.is_file()
        || FileIdentity::from_metadata(&path_metadata) != *expected
        || FileIdentity::from_metadata(&opened_metadata) != *expected
    {
        return Err(ZeekAdapterError::SourceChanged);
    }
    Ok(())
}

#[derive(Debug)]
struct Line<'a> {
    value: &'a [u8],
    start: usize,
    end: usize,
}

fn lines(bytes: &[u8], max_rows: u64) -> Result<Vec<Line<'_>>, ZeekAdapterError> {
    let max_lines = usize::try_from(max_rows)
        .expect("validated Zeek row bound fits usize")
        .checked_add(9)
        .expect("validated Zeek row bound plus metadata fits usize");
    let mut lines = Vec::new();
    let mut start = 0;
    for raw in bytes.split_inclusive(|byte| *byte == b'\n') {
        if lines.len() == max_lines {
            return Err(ZeekAdapterError::RowLimitExceeded);
        }
        let end = start + raw.len();
        let mut value = raw.strip_suffix(b"\n").unwrap_or(raw);
        value = value.strip_suffix(b"\r").unwrap_or(value);
        lines.push(Line { value, start, end });
        start = end;
    }
    Ok(lines)
}

#[derive(Debug)]
struct Header {
    separator: u8,
    empty_field: Vec<u8>,
    unset_field: Vec<u8>,
    field_count: usize,
    indices: FieldIndices,
    data_start: usize,
    has_open: bool,
}

#[derive(Debug, Default)]
struct FieldIndices {
    ts: Option<usize>,
    orig_h: Option<usize>,
    orig_p: Option<usize>,
    resp_h: Option<usize>,
    resp_p: Option<usize>,
    proto: Option<usize>,
    duration: Option<usize>,
    orig_pkts: Option<usize>,
    orig_ip_bytes: Option<usize>,
    resp_pkts: Option<usize>,
    resp_ip_bytes: Option<usize>,
}

impl FieldIndices {
    fn index(&self, name: &'static str) -> Option<usize> {
        match name {
            "ts" => self.ts,
            "id.orig_h" => self.orig_h,
            "id.orig_p" => self.orig_p,
            "id.resp_h" => self.resp_h,
            "id.resp_p" => self.resp_p,
            "proto" => self.proto,
            "duration" => self.duration,
            "orig_pkts" => self.orig_pkts,
            "orig_ip_bytes" => self.orig_ip_bytes,
            "resp_pkts" => self.resp_pkts,
            "resp_ip_bytes" => self.resp_ip_bytes,
            _ => None,
        }
    }

    fn set(&mut self, name: &str, index: usize) {
        match name {
            "ts" => self.ts = Some(index),
            "id.orig_h" => self.orig_h = Some(index),
            "id.orig_p" => self.orig_p = Some(index),
            "id.resp_h" => self.resp_h = Some(index),
            "id.resp_p" => self.resp_p = Some(index),
            "proto" => self.proto = Some(index),
            "duration" => self.duration = Some(index),
            "orig_pkts" => self.orig_pkts = Some(index),
            "orig_ip_bytes" => self.orig_ip_bytes = Some(index),
            "resp_pkts" => self.resp_pkts = Some(index),
            "resp_ip_bytes" => self.resp_ip_bytes = Some(index),
            _ => {}
        }
    }
}

fn parse_conn_log(bytes: &[u8], max_rows: u64) -> Result<Vec<ZeekConnV0>, ZeekAdapterError> {
    let lines = lines(bytes, max_rows)?;
    let header = parse_header(&lines)?;
    let mut data_end = bytes.len();
    let mut close_seen = false;
    for (index, line) in lines
        .iter()
        .enumerate()
        .skip_while(|(_, line)| line.end <= header.data_start)
    {
        if line.value.is_empty() {
            return Err(ZeekAdapterError::InvalidRow {
                row: u64::try_from(index + 1).unwrap_or(u64::MAX),
            });
        }
        if line.value.starts_with(b"#") {
            if close_seen || index + 1 != lines.len() || !header.has_open {
                return Err(ZeekAdapterError::UnexpectedDirective);
            }
            parse_time_directive(line.value, header.separator, b"#close", "#close")?;
            data_end = line.start;
            close_seen = true;
        }
    }

    let mut reader = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(header.separator)
        .quoting(false)
        .flexible(true)
        .from_reader(&bytes[header.data_start..data_end]);
    let mut connections = Vec::new();
    for record in reader.byte_records() {
        let record = record.map_err(ZeekAdapterError::Csv)?;
        let row = u64::try_from(connections.len())
            .unwrap_or(u64::MAX)
            .saturating_add(1);
        if row > max_rows {
            return Err(ZeekAdapterError::RowLimitExceeded);
        }
        if record.len() != header.field_count {
            return Err(ZeekAdapterError::InvalidRow { row });
        }
        connections.push(parse_connection(&record, &header, row)?);
    }
    Ok(connections)
}

fn parse_header(lines: &[Line<'_>]) -> Result<Header, ZeekAdapterError> {
    let first = lines
        .first()
        .ok_or(ZeekAdapterError::MissingDirective("#separator"))?;
    let separator = parse_separator(first.value)?;
    let set_separator = directive_value(
        line_at(lines, 1, "#set_separator")?,
        separator,
        b"#set_separator",
        "#set_separator",
    )?;
    parse_single_separator(set_separator, separator, "#set_separator")?;
    let empty_field = directive_value(
        line_at(lines, 2, "#empty_field")?,
        separator,
        b"#empty_field",
        "#empty_field",
    )?
    .to_vec();
    let unset_field = directive_value(
        line_at(lines, 3, "#unset_field")?,
        separator,
        b"#unset_field",
        "#unset_field",
    )?
    .to_vec();
    validate_marker(&empty_field, separator, "#empty_field")?;
    validate_marker(&unset_field, separator, "#unset_field")?;
    if empty_field == unset_field {
        return Err(ZeekAdapterError::MalformedDirective("#unset_field"));
    }
    let path = directive_value(line_at(lines, 4, "#path")?, separator, b"#path", "#path")?;
    if path != b"conn" {
        return Err(ZeekAdapterError::InvalidPath);
    }

    let mut cursor = 5;
    let has_open = lines
        .get(cursor)
        .is_some_and(|line| directive_name(line.value, separator) == Some(b"#open"));
    if has_open {
        parse_time_directive(lines[cursor].value, separator, b"#open", "#open")?;
        cursor += 1;
    }
    let fields_line = line_at(lines, cursor, "#fields")?;
    let fields = directive_parts(fields_line, separator, b"#fields", "#fields")?;
    if fields.len() < 2 {
        return Err(ZeekAdapterError::MalformedDirective("#fields"));
    }
    cursor += 1;
    let types_line = line_at(lines, cursor, "#types")?;
    let types = directive_parts(types_line, separator, b"#types", "#types")?;
    if types.len() != fields.len() {
        return Err(ZeekAdapterError::MalformedDirective("#types"));
    }

    let mut seen = BTreeSet::new();
    let mut indices = FieldIndices::default();
    for (index, field) in fields.iter().skip(1).enumerate() {
        if field.is_empty() || !seen.insert(*field) {
            return Err(if field.is_empty() {
                ZeekAdapterError::MalformedDirective("#fields")
            } else {
                ZeekAdapterError::DuplicateField
            });
        }
        if let Ok(name) = std::str::from_utf8(field) {
            indices.set(name, index);
        }
    }
    for value in types.iter().skip(1) {
        if value.is_empty() || value.iter().any(|byte| byte.is_ascii_control()) {
            return Err(ZeekAdapterError::MalformedDirective("#types"));
        }
    }
    for (name, expected_type) in REQUIRED_FIELDS {
        let index = indices
            .index(name)
            .ok_or(ZeekAdapterError::MissingField(name))?;
        if types[index + 1] != expected_type.as_bytes() {
            return Err(ZeekAdapterError::InvalidFieldType(name));
        }
    }

    Ok(Header {
        separator,
        empty_field,
        unset_field,
        field_count: fields.len() - 1,
        indices,
        data_start: lines[cursor].end,
        has_open,
    })
}

fn line_at<'a>(
    lines: &'a [Line<'a>],
    index: usize,
    name: &'static str,
) -> Result<&'a [u8], ZeekAdapterError> {
    lines
        .get(index)
        .map(|line| line.value)
        .ok_or(ZeekAdapterError::MissingDirective(name))
}

fn parse_separator(line: &[u8]) -> Result<u8, ZeekAdapterError> {
    let encoded = line
        .strip_prefix(b"#separator ")
        .ok_or(ZeekAdapterError::MalformedDirective("#separator"))?;
    parse_encoded_byte(encoded, "#separator")
}

fn parse_single_separator(
    value: &[u8],
    field_separator: u8,
    name: &'static str,
) -> Result<u8, ZeekAdapterError> {
    let separator = if value.len() == 1 {
        value[0]
    } else {
        parse_encoded_byte(value, name)?
    };
    if separator == field_separator
        || matches!(separator, b'\0' | b'\r' | b'\n' | b'#')
        || separator.is_ascii_control()
    {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    Ok(separator)
}

fn parse_encoded_byte(value: &[u8], name: &'static str) -> Result<u8, ZeekAdapterError> {
    if value.len() != 4 || &value[..2] != b"\\x" {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    let encoded =
        std::str::from_utf8(&value[2..]).map_err(|_| ZeekAdapterError::MalformedDirective(name))?;
    let byte =
        u8::from_str_radix(encoded, 16).map_err(|_| ZeekAdapterError::MalformedDirective(name))?;
    if matches!(byte, b'\0' | b'\r' | b'\n' | b'#') {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    Ok(byte)
}

fn validate_marker(
    marker: &[u8],
    separator: u8,
    name: &'static str,
) -> Result<(), ZeekAdapterError> {
    if marker.is_empty()
        || marker.contains(&separator)
        || marker.iter().any(|byte| byte.is_ascii_control())
    {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    Ok(())
}

fn directive_name(line: &[u8], separator: u8) -> Option<&[u8]> {
    line.split(|byte| *byte == separator).next()
}

fn directive_parts<'a>(
    line: &'a [u8],
    separator: u8,
    expected: &[u8],
    name: &'static str,
) -> Result<Vec<&'a [u8]>, ZeekAdapterError> {
    if line.iter().filter(|byte| **byte == separator).count() > MAX_ZEEK_CONN_FIELDS {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    let parts: Vec<_> = line.split(|byte| *byte == separator).collect();
    if parts.first().copied() != Some(expected) {
        return Err(if line.starts_with(b"#") {
            ZeekAdapterError::UnexpectedDirective
        } else {
            ZeekAdapterError::MissingDirective(name)
        });
    }
    Ok(parts)
}

fn directive_value<'a>(
    line: &'a [u8],
    separator: u8,
    expected: &[u8],
    name: &'static str,
) -> Result<&'a [u8], ZeekAdapterError> {
    let parts = directive_parts(line, separator, expected, name)?;
    match parts.as_slice() {
        [_, value] if !value.is_empty() => Ok(value),
        _ => Err(ZeekAdapterError::MalformedDirective(name)),
    }
}

fn parse_time_directive(
    line: &[u8],
    separator: u8,
    expected: &[u8],
    name: &'static str,
) -> Result<(), ZeekAdapterError> {
    let value = directive_value(line, separator, expected, name)?;
    if value.len() != 19
        || value.iter().enumerate().any(|(index, byte)| match index {
            4 | 7 | 10 | 13 | 16 => *byte != b'-',
            _ => !byte.is_ascii_digit(),
        })
    {
        return Err(ZeekAdapterError::MalformedDirective(name));
    }
    Ok(())
}

fn parse_connection(
    record: &csv::ByteRecord,
    header: &Header,
    row: u64,
) -> Result<ZeekConnV0, ZeekAdapterError> {
    let value = |name: &'static str| -> Result<&[u8], ZeekAdapterError> {
        let index = header
            .indices
            .index(name)
            .expect("required field indices were validated");
        let value = record
            .get(index)
            .ok_or(ZeekAdapterError::InvalidRow { row })?;
        if value == header.empty_field || value == header.unset_field {
            return Err(ZeekAdapterError::InvalidValue { row, field: name });
        }
        Ok(value)
    };
    let duration = record
        .get(
            header
                .indices
                .duration
                .expect("duration index was validated"),
        )
        .ok_or(ZeekAdapterError::InvalidRow { row })?;
    let duration_ns = if duration == header.unset_field {
        None
    } else if duration == header.empty_field {
        return Err(ZeekAdapterError::InvalidValue {
            row,
            field: "duration",
        });
    } else {
        Some(
            parse_seconds_ns(duration).ok_or(ZeekAdapterError::InvalidValue {
                row,
                field: "duration",
            })?,
        )
    };
    let optional_count = |name: &'static str| -> Result<Option<u64>, ZeekAdapterError> {
        let index = header
            .indices
            .index(name)
            .expect("required field indices were validated");
        let value = record
            .get(index)
            .ok_or(ZeekAdapterError::InvalidRow { row })?;
        if value == header.unset_field {
            Ok(None)
        } else if value == header.empty_field {
            Err(ZeekAdapterError::InvalidValue { row, field: name })
        } else {
            parse_count(value, row, name).map(Some)
        }
    };

    Ok(ZeekConnV0 {
        start_time_unix_ns: i64::try_from(
            parse_seconds_ns(value("ts")?)
                .ok_or(ZeekAdapterError::InvalidValue { row, field: "ts" })?,
        )
        .map_err(|_| ZeekAdapterError::InvalidValue { row, field: "ts" })?,
        originator: ZeekConnEndpointV0 {
            address: parse_ip(value("id.orig_h")?, row, "id.orig_h")?,
            port: parse_port(value("id.orig_p")?, row, "id.orig_p")?,
        },
        responder: ZeekConnEndpointV0 {
            address: parse_ip(value("id.resp_h")?, row, "id.resp_h")?,
            port: parse_port(value("id.resp_p")?, row, "id.resp_p")?,
        },
        protocol: match value("proto")? {
            b"tcp" => ZeekConnProtocolV0::Tcp,
            b"udp" => ZeekConnProtocolV0::Udp,
            b"icmp" => ZeekConnProtocolV0::Icmp,
            b"unknown_transport" => ZeekConnProtocolV0::UnknownTransport,
            _ => {
                return Err(ZeekAdapterError::InvalidValue {
                    row,
                    field: "proto",
                });
            }
        },
        duration_ns,
        orig_packets: optional_count("orig_pkts")?,
        orig_ip_bytes: optional_count("orig_ip_bytes")?,
        resp_packets: optional_count("resp_pkts")?,
        resp_ip_bytes: optional_count("resp_ip_bytes")?,
    })
}

fn parse_ip(value: &[u8], row: u64, field: &'static str) -> Result<IpAddr, ZeekAdapterError> {
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(ZeekAdapterError::InvalidValue { row, field })
}

fn parse_port(value: &[u8], row: u64, field: &'static str) -> Result<u16, ZeekAdapterError> {
    let count = parse_count(value, row, field)?;
    u16::try_from(count).map_err(|_| ZeekAdapterError::InvalidValue { row, field })
}

fn parse_count(value: &[u8], row: u64, field: &'static str) -> Result<u64, ZeekAdapterError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(ZeekAdapterError::InvalidValue { row, field });
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| value.parse().ok())
        .ok_or(ZeekAdapterError::InvalidValue { row, field })
}

fn parse_seconds_ns(value: &[u8]) -> Option<u64> {
    let value = std::str::from_utf8(value).ok()?;
    let (seconds, fraction) = match value.split_once('.') {
        Some((seconds, fraction)) if !fraction.is_empty() => (seconds, fraction),
        Some(_) => return None,
        None => (value, ""),
    };
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
    {
        return None;
    }
    let seconds = seconds.parse::<u64>().ok()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>().ok()? * 10_u64.pow(u32::try_from(9 - fraction.len()).ok()?)
    };
    seconds.checked_mul(1_000_000_000)?.checked_add(fraction)
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    const LOG: &str = concat!(
        "#separator \\x09\n",
        "#set_separator\t,\n",
        "#empty_field\t(empty)\n",
        "#unset_field\t-\n",
        "#path\tconn\n",
        "#open\t2026-08-03-00-00-00\n",
        "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n",
        "#types\ttime\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tcount\tcount\n",
        "1.000000000\t192.0.2.1\t12345\t198.51.100.2\t443\ttcp\t0.1\t1\t40\t1\t40\n",
        "#close\t2026-08-03-00-00-01\n",
    );

    #[test]
    fn post_read_identity_fence_detects_mutation() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conn.log");
        fs::write(&path, LOG).unwrap();

        let error = project_zeek_conn_log_with_hook(&path, &ZeekConnOptions::default(), || {
            let mut file = OpenOptions::new().write(true).open(&path).unwrap();
            file.seek(SeekFrom::Start(
                u64::try_from(LOG.find("192").unwrap()).unwrap(),
            ))
            .unwrap();
            file.write_all(b"193").unwrap();
            file.sync_all().unwrap();
        })
        .unwrap_err();
        assert!(matches!(error, ZeekAdapterError::SourceChanged));
    }
}
