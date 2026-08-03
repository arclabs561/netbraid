use std::fs::File;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use netbraid::adapters::kismetdb::{
    normalize_kismetdb, KismetDbError, KismetDbOptions, DEFAULT_MMAP_SIZE_BYTES,
};
use netbraid::evidence::NormalizationStateV0;
use rusqlite::{params, Connection};

struct Fixture {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

struct PacketSpec<'a> {
    datasource: Option<&'a str>,
    ts_sec: i64,
    ts_usec: i64,
    packet_len: i64,
    packet_full_len: i64,
    dlt: i64,
    stored_len: usize,
    error: i64,
}

impl<'a> PacketSpec<'a> {
    fn valid(datasource: &'a str, ts_sec: i64, packet_len: usize) -> Self {
        Self {
            datasource: Some(datasource),
            ts_sec,
            ts_usec: 0,
            packet_len: packet_len as i64,
            packet_full_len: packet_len as i64,
            dlt: 1,
            stored_len: packet_len,
            error: 0,
        }
    }
}

impl Fixture {
    fn new(db_version: i64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.kismet");
        let connection = Connection::open(&path).unwrap();
        connection
            .execute("CREATE TABLE KISMET (db_version INTEGER NOT NULL)", [])
            .unwrap();
        connection
            .execute("INSERT INTO KISMET (db_version) VALUES (?1)", [db_version])
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
        drop(connection);
        Self {
            _directory: directory,
            path,
        }
    }

    fn insert_packet(&self, packet: PacketSpec<'_>) {
        let connection = Connection::open(&self.path).unwrap();
        connection
            .execute(
                "INSERT INTO packets (ts_sec, ts_usec, packet_len, packet_full_len, \
                 datasource, dlt, packet, error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    packet.ts_sec,
                    packet.ts_usec,
                    packet.packet_len,
                    packet.packet_full_len,
                    packet.datasource,
                    packet.dlt,
                    vec![0_u8; packet.stored_len],
                    packet.error
                ],
            )
            .unwrap();
    }
}

fn options(limit: u64) -> KismetDbOptions {
    KismetDbOptions::new(NonZeroU64::new(limit).unwrap()).unwrap()
}

#[test]
fn versions_nine_and_ten_map_packet_rows_without_a_run_receipt() {
    for version in [9, 10] {
        let fixture = Fixture::new(version);
        fixture.insert_packet(PacketSpec {
            datasource: Some("source-a"),
            ts_sec: 1_700_000_000,
            ts_usec: 123_456,
            packet_len: 4,
            packet_full_len: 9,
            dlt: 127,
            stored_len: 4,
            error: 0,
        });

        let report = normalize_kismetdb(&fixture.path, &options(10)).unwrap();
        let stream = report.stream();

        assert_eq!(report.db_version(), version as u32);
        assert_eq!(report.datasource_id(), Some("source-a"));
        assert!(stream.receipt.is_none());
        assert_eq!(stream.packets.len(), 1);
        assert!(stream.quarantines.is_empty());
        assert_eq!(stream.manifest.observer_id.as_deref(), Some("source-a"));
        assert_eq!(
            stream.manifest.normalization.state,
            NormalizationStateV0::Complete
        );
        assert!(!stream.manifest.normalization.packet_limit_reached);
        let frame = &stream.packets[0].frame;
        assert_eq!(frame.number, 1);
        assert_eq!(frame.event_time_unix_ns, 1_700_000_000_123_456_000);
        assert_eq!(frame.captured_len, 4);
        assert_eq!(frame.original_len, 9);
        assert_eq!(frame.encapsulation_type, Some(127));
        assert_eq!(stream.normalized_records_sha256.len(), 71);
    }
}

#[test]
fn mixed_sources_require_an_explicit_selection() {
    let fixture = Fixture::new(10);
    fixture.insert_packet(PacketSpec::valid("source-a", 1, 2));
    fixture.insert_packet(PacketSpec::valid("source-b", 2, 3));

    assert!(matches!(
        normalize_kismetdb(&fixture.path, &options(10)),
        Err(KismetDbError::MixedDatasources)
    ));

    let selected = options(10).with_datasource_id("source-b").unwrap();
    let report = normalize_kismetdb(&fixture.path, &selected).unwrap();
    assert_eq!(report.datasource_id(), Some("source-b"));
    assert_eq!(report.stream().packets.len(), 1);
    assert_eq!(report.stream().packets[0].frame.number, 2);
}

#[test]
fn packet_limit_and_flagged_rows_produce_an_explicit_partial_stream() {
    let fixture = Fixture::new(9);
    let mut flagged = PacketSpec::valid("source-a", 1, 2);
    flagged.error = 1;
    fixture.insert_packet(flagged);
    fixture.insert_packet(PacketSpec::valid("source-a", 2, 3));
    fixture.insert_packet(PacketSpec::valid("source-a", 3, 4));

    let report = normalize_kismetdb(&fixture.path, &options(2)).unwrap();
    let stream = report.stream();
    assert_eq!(
        stream.manifest.normalization.state,
        NormalizationStateV0::Partial
    );
    assert!(stream.manifest.normalization.packet_limit_reached);
    assert_eq!(stream.manifest.normalization.packet_rows_emitted, 1);
    assert_eq!(stream.manifest.normalization.packet_rows_quarantined, 1);
    assert_eq!(stream.packets[0].frame.number, 2);
    assert_eq!(stream.quarantines[0].source_line, 1);
    assert_eq!(stream.quarantines[0].raw_row, "kismetdb:rowid=1");
}

#[test]
fn malformed_packet_metadata_fails_closed() {
    let fixture = Fixture::new(10);
    let mut invalid_time = PacketSpec::valid("source-a", 1, 3);
    invalid_time.ts_usec = 1_000_000;
    fixture.insert_packet(invalid_time);
    assert!(matches!(
        normalize_kismetdb(&fixture.path, &options(10)),
        Err(KismetDbError::InvalidTimestamp { rowid: 1 })
    ));

    let fixture = Fixture::new(10);
    let mut invalid_length = PacketSpec::valid("source-a", 1, 3);
    invalid_length.stored_len = 2;
    fixture.insert_packet(invalid_length);
    assert!(matches!(
        normalize_kismetdb(&fixture.path, &options(10)),
        Err(KismetDbError::PacketLengthMismatch {
            rowid: 1,
            declared: 3,
            actual: 2
        })
    ));
}

#[test]
fn unsupported_versions_and_live_sidecars_fail_closed() {
    let fixture = Fixture::new(8);
    assert!(matches!(
        normalize_kismetdb(&fixture.path, &options(10)),
        Err(KismetDbError::UnsupportedDatabaseVersion(8))
    ));

    let fixture = Fixture::new(10);
    let sidecar = suffixed_path(&fixture.path, "-wal");
    File::create(sidecar).unwrap();
    assert!(matches!(
        normalize_kismetdb(&fixture.path, &options(10)),
        Err(KismetDbError::SidecarPresent("-wal"))
    ));
}

#[test]
fn sqlite_mmap_is_a_semantics_preserving_execution_option() {
    let fixture = Fixture::new(10);
    let mut packet = PacketSpec::valid("source-a", 1, 4);
    packet.dlt = 127;
    fixture.insert_packet(packet);

    let without_mmap =
        normalize_kismetdb(&fixture.path, &options(10).with_mmap_size_bytes(0).unwrap()).unwrap();
    let with_mmap = normalize_kismetdb(
        &fixture.path,
        &options(10)
            .with_mmap_size_bytes(DEFAULT_MMAP_SIZE_BYTES)
            .unwrap(),
    )
    .unwrap();

    assert_eq!(without_mmap.stream(), with_mmap.stream());
    assert_eq!(without_mmap.mmap_size_bytes(), 0);
    assert!(with_mmap.mmap_size_bytes() <= DEFAULT_MMAP_SIZE_BYTES);
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_owned();
    value.push(suffix);
    PathBuf::from(value)
}
