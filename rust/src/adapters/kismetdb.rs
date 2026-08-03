//! Read-only normalization of KismetDB packet tables.
//!
//! The adapter deliberately stops at packet-envelope metadata. It does not
//! interpret Kismet device JSON, tags, GPS, signal values, or packet payloads.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OpenFlags};
use sha2::{Digest, Sha256};

use crate::evidence::digest::NormalizedRecordsDigest;
use crate::evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0, CaptureNormalizationV0,
    CaptureValidationError, NormalizationStateV0, PacketEnvelopeV0, PacketFrameV0,
    PacketQuarantineV0, CAPTURE_MANIFEST_SCHEMA_V0, PACKET_ENVELOPE_SCHEMA_V0,
    PACKET_QUARANTINE_SCHEMA_V0,
};
use crate::replay::SavedCaptureRecordStreamV0;

pub const KISMETDB_ADAPTER_ID: &str = "netbraid-adapter-kismetdb";
pub const KISMETDB_FIELD_REGISTRY_V0: &str = "netmon.kismetdb.packet_envelope.v0";
pub const DEFAULT_PACKET_LIMIT: u64 = 100_000;
pub const MAX_PACKET_LIMIT: u64 = 1_000_000;
pub const DEFAULT_MMAP_SIZE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_MMAP_SIZE_BYTES: u64 = 1024 * 1024 * 1024;

/// Validated bounds and source selection for one KismetDB normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KismetDbOptions {
    packet_limit: NonZeroU64,
    datasource_id: Option<String>,
    mmap_size_bytes: u64,
}

impl KismetDbOptions {
    pub fn new(packet_limit: NonZeroU64) -> Result<Self, KismetDbOptionsError> {
        if packet_limit.get() > MAX_PACKET_LIMIT {
            return Err(KismetDbOptionsError::PacketLimitTooLarge);
        }
        Ok(Self {
            packet_limit,
            datasource_id: None,
            mmap_size_bytes: DEFAULT_MMAP_SIZE_BYTES,
        })
    }

    pub fn with_datasource_id(
        mut self,
        datasource_id: impl Into<String>,
    ) -> Result<Self, KismetDbOptionsError> {
        let datasource_id = datasource_id.into();
        if datasource_id.trim().is_empty() {
            return Err(KismetDbOptionsError::EmptyDatasourceId);
        }
        self.datasource_id = Some(datasource_id);
        Ok(self)
    }

    pub fn with_mmap_size_bytes(
        mut self,
        mmap_size_bytes: u64,
    ) -> Result<Self, KismetDbOptionsError> {
        if mmap_size_bytes > MAX_MMAP_SIZE_BYTES {
            return Err(KismetDbOptionsError::MmapSizeTooLarge);
        }
        self.mmap_size_bytes = mmap_size_bytes;
        Ok(self)
    }

    pub fn packet_limit(&self) -> NonZeroU64 {
        self.packet_limit
    }

    pub fn datasource_id(&self) -> Option<&str> {
        self.datasource_id.as_deref()
    }

    pub fn mmap_size_bytes(&self) -> u64 {
        self.mmap_size_bytes
    }
}

impl Default for KismetDbOptions {
    fn default() -> Self {
        Self::new(NonZeroU64::new(DEFAULT_PACKET_LIMIT).expect("nonzero default packet limit"))
            .expect("default KismetDB options are valid")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum KismetDbOptionsError {
    PacketLimitTooLarge,
    EmptyDatasourceId,
    MmapSizeTooLarge,
}

impl std::fmt::Display for KismetDbOptionsError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PacketLimitTooLarge => write!(
                formatter,
                "packet limit exceeds the adapter maximum of {MAX_PACKET_LIMIT}"
            ),
            Self::EmptyDatasourceId => formatter.write_str("datasource ID must not be empty"),
            Self::MmapSizeTooLarge => write!(
                formatter,
                "SQLite mmap request exceeds the adapter maximum of {MAX_MMAP_SIZE_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for KismetDbOptionsError {}

/// A normalized stream plus the KismetDB facts that controlled extraction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KismetDbReport {
    stream: SavedCaptureRecordStreamV0,
    db_version: u32,
    datasource_id: Option<String>,
    mmap_size_bytes: u64,
}

impl KismetDbReport {
    pub fn stream(&self) -> &SavedCaptureRecordStreamV0 {
        &self.stream
    }

    pub fn into_stream(self) -> SavedCaptureRecordStreamV0 {
        self.stream
    }

    pub fn db_version(&self) -> u32 {
        self.db_version
    }

    pub fn datasource_id(&self) -> Option<&str> {
        self.datasource_id.as_deref()
    }

    pub fn mmap_size_bytes(&self) -> u64 {
        self.mmap_size_bytes
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum KismetDbError {
    Io(io::Error),
    Sqlite(rusqlite::Error),
    SidecarPresent(&'static str),
    ArtifactChanged,
    MissingDatabaseVersion,
    AmbiguousDatabaseVersion,
    UnsupportedDatabaseVersion(i64),
    EmptyDatasourceId,
    MixedDatasources,
    InvalidRowId(i64),
    InvalidTimestamp {
        rowid: u64,
    },
    InvalidPacketLength {
        rowid: u64,
        field: &'static str,
    },
    PacketLengthMismatch {
        rowid: u64,
        declared: u32,
        actual: u32,
    },
    InvalidDlt {
        rowid: u64,
    },
    InvalidManifest(CaptureValidationError),
    InvalidPacket {
        rowid: u64,
        source: CaptureValidationError,
    },
    InvalidQuarantine {
        rowid: u64,
        source: CaptureValidationError,
    },
    RecordSerialization(serde_json::Error),
}

impl std::fmt::Display for KismetDbError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(formatter, "KismetDB I/O failed: {source}"),
            Self::Sqlite(source) => write!(formatter, "KismetDB query failed: {source}"),
            Self::SidecarPresent(suffix) => write!(
                formatter,
                "refusing a KismetDB with a {suffix} sidecar; copy or close it first"
            ),
            Self::ArtifactChanged => {
                formatter.write_str("KismetDB changed while it was being normalized")
            }
            Self::MissingDatabaseVersion => {
                formatter.write_str("KISMET table has no database version")
            }
            Self::AmbiguousDatabaseVersion => {
                formatter.write_str("KISMET table contains multiple database versions")
            }
            Self::UnsupportedDatabaseVersion(version) => {
                write!(
                    formatter,
                    "unsupported KismetDB version {version}; expected 9 or 10"
                )
            }
            Self::EmptyDatasourceId => formatter.write_str("packet datasource ID is empty"),
            Self::MixedDatasources => formatter
                .write_str("packet selection spans multiple datasources; select one explicitly"),
            Self::InvalidRowId(rowid) => write!(formatter, "invalid packet rowid {rowid}"),
            Self::InvalidTimestamp { rowid } => {
                write!(formatter, "packet row {rowid} has an invalid timestamp")
            }
            Self::InvalidPacketLength { rowid, field } => {
                write!(formatter, "packet row {rowid} has an invalid {field}")
            }
            Self::PacketLengthMismatch {
                rowid,
                declared,
                actual,
            } => write!(
                formatter,
                "packet row {rowid} declares {declared} captured bytes but stores {actual}"
            ),
            Self::InvalidDlt { rowid } => {
                write!(formatter, "packet row {rowid} has an out-of-range DLT")
            }
            Self::InvalidManifest(source) => write!(formatter, "invalid manifest: {source}"),
            Self::InvalidPacket { rowid, source } => {
                write!(formatter, "invalid packet row {rowid}: {source}")
            }
            Self::InvalidQuarantine { rowid, source } => {
                write!(formatter, "invalid quarantine for row {rowid}: {source}")
            }
            Self::RecordSerialization(source) => {
                write!(
                    formatter,
                    "normalized-record serialization failed: {source}"
                )
            }
        }
    }
}

impl std::error::Error for KismetDbError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Sqlite(source) => Some(source),
            Self::InvalidManifest(source)
            | Self::InvalidPacket { source, .. }
            | Self::InvalidQuarantine { source, .. } => Some(source),
            Self::RecordSerialization(source) => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for KismetDbError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<rusqlite::Error> for KismetDbError {
    fn from(source: rusqlite::Error) -> Self {
        Self::Sqlite(source)
    }
}

/// Normalize packet metadata from a closed, single-file KismetDB artifact.
pub fn normalize_kismetdb(
    path: impl AsRef<Path>,
    options: &KismetDbOptions,
) -> Result<KismetDbReport, KismetDbError> {
    normalize_kismetdb_with_after_stage(path.as_ref(), options, || Ok(()))
}

fn normalize_kismetdb_with_after_stage(
    path: &Path,
    options: &KismetDbOptions,
    after_stage: impl FnOnce() -> Result<(), KismetDbError>,
) -> Result<KismetDbReport, KismetDbError> {
    reject_sidecars(path)?;
    let staged = stage_kismetdb(path)?;
    reject_sidecars(path)?;
    after_stage()?;
    let capture_id = staged.artifact.content_sha256.clone();

    let mut connection = Connection::open_with_flags(
        &staged.path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let requested_mmap_size =
        i64::try_from(options.mmap_size_bytes).expect("validated mmap size fits SQLite integer");
    connection.pragma_update(None, "mmap_size", requested_mmap_size)?;
    let mmap_size_bytes = connection
        .pragma_query_value(None, "mmap_size", |row| row.get::<_, i64>(0))?
        .try_into()
        .unwrap_or(0);
    connection.pragma_update(None, "query_only", true)?;
    let transaction = connection.transaction()?;
    let db_version = read_database_version(&transaction)?;
    let datasource_id = select_datasource(&transaction, options.datasource_id.as_deref())?;
    let (packets, quarantines, packet_limit_reached) = read_packets(
        &transaction,
        &capture_id,
        datasource_id.as_deref(),
        options.packet_limit.get(),
    )?;
    transaction.commit()?;
    drop(connection);

    let normalization_state = if packet_limit_reached || !quarantines.is_empty() {
        NormalizationStateV0::Partial
    } else {
        NormalizationStateV0::Complete
    };
    let manifest = CaptureManifestV0 {
        schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
        capture_id: capture_id.clone(),
        artifact: staged.artifact.clone(),
        observer_id: datasource_id.clone(),
        acquired_time_unix_ms: None,
        extractor: CaptureExtractorRefV0 {
            adapter: KISMETDB_ADAPTER_ID.into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
            tool: "kismetdb".into(),
            tool_version: format!("schema-{db_version}"),
            configuration_sha256: configuration_sha256(
                db_version,
                options.packet_limit,
                datasource_id.as_deref(),
            ),
            field_registry: KISMETDB_FIELD_REGISTRY_V0.into(),
        },
        acquisition_policy: None,
        normalization: CaptureNormalizationV0 {
            state: normalization_state,
            packet_limit: options.packet_limit.get(),
            packet_limit_reached,
            packet_rows_emitted: u64::try_from(packets.len()).unwrap_or(u64::MAX),
            packet_rows_quarantined: u64::try_from(quarantines.len()).unwrap_or(u64::MAX),
        },
    };
    manifest
        .validate()
        .map_err(KismetDbError::InvalidManifest)?;
    let normalized_records_sha256 = normalized_records_sha256(&manifest, &packets, &quarantines)?;

    Ok(KismetDbReport {
        stream: SavedCaptureRecordStreamV0 {
            manifest,
            receipt: None,
            packets,
            quarantines,
            normalized_records_sha256,
        },
        db_version,
        datasource_id,
        mmap_size_bytes,
    })
}

struct StagedKismetDb {
    _directory: tempfile::TempDir,
    path: PathBuf,
    artifact: CaptureArtifactRefV0,
}

fn stage_kismetdb(input: &Path) -> Result<StagedKismetDb, KismetDbError> {
    let metadata = fs::metadata(input)?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "KismetDB input is not a regular file",
        )
        .into());
    }
    let directory = tempfile::Builder::new()
        .prefix("netbraid-kismetdb-")
        .tempdir()?;
    let path = directory.path().join("capture.kismet");
    let mut source = File::open(input)?;
    let mut destination = File::create(&path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    let mut size_bytes = 0_u64;
    loop {
        let read = source.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(u64::try_from(read).expect("read length fits u64"))
            .ok_or_else(|| io::Error::other("KismetDB size exceeds u64"))?;
        destination.write_all(&buffer[..read])?;
        hasher.update(&buffer[..read]);
    }
    destination.flush()?;
    drop(destination);

    Ok(StagedKismetDb {
        _directory: directory,
        path,
        artifact: CaptureArtifactRefV0 {
            content_sha256: format!("sha256:{:x}", hasher.finalize()),
            size_bytes,
        },
    })
}

fn reject_sidecars(path: &Path) -> Result<(), KismetDbError> {
    for suffix in ["-journal", "-wal", "-shm"] {
        if suffixed_path(path, suffix).exists() {
            return Err(KismetDbError::SidecarPresent(suffix));
        }
    }
    Ok(())
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}

fn read_database_version(connection: &Connection) -> Result<u32, KismetDbError> {
    let mut statement =
        connection.prepare("SELECT DISTINCT db_version FROM KISMET ORDER BY db_version LIMIT 2")?;
    let versions = statement
        .query_map([], |row| row.get::<_, i64>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let version = match versions.as_slice() {
        [] => return Err(KismetDbError::MissingDatabaseVersion),
        [version] => *version,
        _ => return Err(KismetDbError::AmbiguousDatabaseVersion),
    };
    if !matches!(version, 9 | 10) {
        return Err(KismetDbError::UnsupportedDatabaseVersion(version));
    }
    Ok(u32::try_from(version).expect("supported versions fit u32"))
}

fn select_datasource(
    connection: &Connection,
    requested: Option<&str>,
) -> Result<Option<String>, KismetDbError> {
    if let Some(requested) = requested {
        return Ok(Some(requested.to_owned()));
    }
    let mut statement = connection
        .prepare("SELECT DISTINCT datasource FROM packets ORDER BY datasource LIMIT 2")?;
    let datasources = statement
        .query_map([], |row| row.get::<_, Option<String>>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut selected = Vec::with_capacity(datasources.len());
    for datasource in datasources {
        let datasource = datasource.ok_or(KismetDbError::EmptyDatasourceId)?;
        if datasource.trim().is_empty() {
            return Err(KismetDbError::EmptyDatasourceId);
        }
        selected.push(datasource);
    }
    match selected.len() {
        0 => Ok(None),
        1 => Ok(selected.pop()),
        _ => Err(KismetDbError::MixedDatasources),
    }
}

#[derive(Debug)]
struct PacketRow {
    rowid: i64,
    ts_sec: i64,
    ts_usec: i64,
    packet_len: i64,
    packet_full_len: i64,
    dlt: i64,
    stored_len: i64,
    error: i64,
}

fn read_packets(
    connection: &Connection,
    capture_id: &str,
    datasource_id: Option<&str>,
    packet_limit: u64,
) -> Result<(Vec<PacketEnvelopeV0>, Vec<PacketQuarantineV0>, bool), KismetDbError> {
    let query_limit = i64::try_from(packet_limit.saturating_add(1))
        .expect("validated packet limit fits SQLite integer");
    let selected = match datasource_id {
        Some(datasource_id) => query_packet_rows(
            connection,
            "SELECT rowid, ts_sec, ts_usec, packet_len, packet_full_len, dlt, \
             length(packet), error FROM packets WHERE datasource = ?1 ORDER BY rowid LIMIT ?2",
            params![datasource_id, query_limit],
        )?,
        None => query_packet_rows(
            connection,
            "SELECT rowid, ts_sec, ts_usec, packet_len, packet_full_len, dlt, \
             length(packet), error FROM packets ORDER BY rowid LIMIT ?1",
            params![query_limit],
        )?,
    };
    let packet_limit_reached = selected.len() > usize::try_from(packet_limit).unwrap_or(usize::MAX);
    let mut packets = Vec::with_capacity(selected.len().min(packet_limit as usize));
    let mut quarantines = Vec::new();
    for row in selected.into_iter().take(packet_limit as usize) {
        let rowid = u64::try_from(row.rowid).map_err(|_| KismetDbError::InvalidRowId(row.rowid))?;
        if rowid == 0 {
            return Err(KismetDbError::InvalidRowId(row.rowid));
        }
        if row.error != 0 {
            let quarantine = PacketQuarantineV0 {
                schema: PACKET_QUARANTINE_SCHEMA_V0.into(),
                capture_id: capture_id.into(),
                source_line: rowid,
                frame_number_hint: Some(rowid),
                reason: "Kismet marked packet invalid".into(),
                raw_row: format!("kismetdb:rowid={rowid}"),
            };
            quarantine
                .validate()
                .map_err(|source| KismetDbError::InvalidQuarantine { rowid, source })?;
            quarantines.push(quarantine);
            continue;
        }
        let event_time_unix_ns = row
            .ts_sec
            .checked_mul(1_000_000_000)
            .and_then(|value| (0..1_000_000).contains(&row.ts_usec).then_some(value))
            .and_then(|value| value.checked_add(row.ts_usec * 1_000))
            .ok_or(KismetDbError::InvalidTimestamp { rowid })?;
        let captured_len = packet_length(rowid, "packet_len", row.packet_len)?;
        let original_len = packet_length(rowid, "packet_full_len", row.packet_full_len)?;
        let stored_len = packet_length(rowid, "length(packet)", row.stored_len)?;
        if stored_len != captured_len {
            return Err(KismetDbError::PacketLengthMismatch {
                rowid,
                declared: captured_len,
                actual: stored_len,
            });
        }
        let encapsulation_type =
            i16::try_from(row.dlt).map_err(|_| KismetDbError::InvalidDlt { rowid })?;
        let packet = PacketEnvelopeV0 {
            schema: PACKET_ENVELOPE_SCHEMA_V0.into(),
            record_id: format!("{capture_id}:frame:{rowid}"),
            capture_id: capture_id.into(),
            frame: PacketFrameV0 {
                number: rowid,
                event_time_unix_ns,
                original_len,
                captured_len,
                section_number: None,
                interface_id: None,
                encapsulation_type: Some(encapsulation_type),
                protocols: Vec::new(),
            },
            ethernet: None,
            ipv4: None,
            ipv6: None,
            tcp: None,
            udp: None,
            ieee802154: None,
            ieee80211: None,
            wlan_radio: None,
        };
        packet
            .validate()
            .map_err(|source| KismetDbError::InvalidPacket { rowid, source })?;
        packets.push(packet);
    }
    Ok((packets, quarantines, packet_limit_reached))
}

fn query_packet_rows<P: rusqlite::Params>(
    connection: &Connection,
    sql: &str,
    parameters: P,
) -> Result<Vec<PacketRow>, rusqlite::Error> {
    let mut statement = connection.prepare(sql)?;
    let rows = statement
        .query_map(parameters, |row| {
            Ok(PacketRow {
                rowid: row.get(0)?,
                ts_sec: row.get(1)?,
                ts_usec: row.get(2)?,
                packet_len: row.get(3)?,
                packet_full_len: row.get(4)?,
                dlt: row.get(5)?,
                stored_len: row.get(6)?,
                error: row.get(7)?,
            })
        })?
        .collect();
    rows
}

fn packet_length(rowid: u64, field: &'static str, value: i64) -> Result<u32, KismetDbError> {
    u32::try_from(value).map_err(|_| KismetDbError::InvalidPacketLength { rowid, field })
}

fn configuration_sha256(
    db_version: u32,
    packet_limit: NonZeroU64,
    datasource_id: Option<&str>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"netbraid.kismetdb.configuration.v0\0");
    hasher.update(db_version.to_le_bytes());
    hasher.update(packet_limit.get().to_le_bytes());
    if let Some(datasource_id) = datasource_id {
        hasher.update([1]);
        hasher.update(datasource_id.as_bytes());
    } else {
        hasher.update([0]);
    }
    format!("sha256:{:x}", hasher.finalize())
}

fn normalized_records_sha256(
    manifest: &CaptureManifestV0,
    packets: &[PacketEnvelopeV0],
    quarantines: &[PacketQuarantineV0],
) -> Result<String, KismetDbError> {
    let mut digest = NormalizedRecordsDigest::new();
    digest
        .update("manifest", 0, manifest)
        .map_err(KismetDbError::RecordSerialization)?;
    for (index, packet) in packets.iter().enumerate() {
        digest
            .update("packet", u64::try_from(index).unwrap_or(u64::MAX), packet)
            .map_err(KismetDbError::RecordSerialization)?;
    }
    for (index, quarantine) in quarantines.iter().enumerate() {
        digest
            .update(
                "quarantine",
                u64::try_from(index).unwrap_or(u64::MAX),
                quarantine,
            )
            .map_err(KismetDbError::RecordSerialization)?;
    }
    Ok(digest.finish())
}

#[cfg(test)]
mod tests {
    use std::fs::FileTimes;

    use rusqlite::params;

    use super::*;

    fn create_database(path: &Path, timestamp: i64) {
        let connection = Connection::open(path).unwrap();
        connection
            .execute("CREATE TABLE KISMET (db_version INTEGER NOT NULL)", [])
            .unwrap();
        connection
            .execute("INSERT INTO KISMET (db_version) VALUES (10)", [])
            .unwrap();
        connection
            .execute(
                "CREATE TABLE packets (\
                 ts_sec INTEGER NOT NULL, ts_usec INTEGER NOT NULL, \
                 packet_len INTEGER NOT NULL, packet_full_len INTEGER NOT NULL, \
                 datasource TEXT, dlt INTEGER NOT NULL, packet BLOB NOT NULL, \
                 error INTEGER NOT NULL)",
                [],
            )
            .unwrap();
        connection
            .execute(
                "INSERT INTO packets (ts_sec, ts_usec, packet_len, packet_full_len, \
                 datasource, dlt, packet, error) VALUES (?1, 0, 4, 4, 'source-a', 1, ?2, 0)",
                params![timestamp, vec![0_u8; 4]],
            )
            .unwrap();
    }

    #[test]
    fn staged_snapshot_binds_digest_and_rows_when_source_path_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("source.kismet");
        let replacement = directory.path().join("replacement.kismet");
        create_database(&source, 1_700_000_001);
        create_database(&replacement, 1_700_000_002);
        let original = fs::read(&source).unwrap();
        let original_metadata = fs::metadata(&source).unwrap();
        File::options()
            .write(true)
            .open(&replacement)
            .unwrap()
            .set_times(
                FileTimes::new()
                    .set_accessed(original_metadata.accessed().unwrap())
                    .set_modified(original_metadata.modified().unwrap()),
            )
            .unwrap();
        assert_eq!(
            fs::metadata(&replacement).unwrap().len(),
            original_metadata.len()
        );
        assert_eq!(
            fs::metadata(&replacement).unwrap().modified().unwrap(),
            original_metadata.modified().unwrap()
        );

        let report =
            normalize_kismetdb_with_after_stage(&source, &KismetDbOptions::default(), || {
                fs::remove_file(&source)?;
                fs::rename(&replacement, &source)?;
                Ok(())
            })
            .unwrap();

        assert_eq!(
            report.stream().packets[0].frame.event_time_unix_ns,
            1_700_000_001_000_000_000
        );
        assert_eq!(
            report.stream().manifest.artifact.content_sha256,
            format!("sha256:{:x}", Sha256::digest(original))
        );
        assert_eq!(
            report.stream().manifest.artifact.size_bytes,
            original_metadata.len()
        );
    }
}
