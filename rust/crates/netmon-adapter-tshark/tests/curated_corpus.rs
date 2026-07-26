use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use netmon_adapter_tshark::{normalize_saved_capture, NormalizeOptions};
use netmon_evidence::NormalizationStateV0;
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};

const CORPUS_SCHEMA: &str = "netmon.capture_fixture_corpus.v0";

#[derive(Debug, Deserialize)]
struct Corpus {
    schema: String,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    path: String,
    purpose: String,
    origin: Origin,
    content_sha256: String,
    size_bytes: u64,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
struct Origin {
    repository: String,
    revision: String,
    source_path: String,
    source_url: String,
    upstream_blob_sha1: String,
    license: String,
    license_file: String,
}

#[derive(Debug, Deserialize)]
struct Expected {
    file_type: String,
    encapsulation: String,
    timestamp_precision: String,
    packet_count: u64,
    original_data_size_bytes: u64,
    packets_emitted: u64,
    packets_quarantined: u64,
    required_protocols: Vec<String>,
}

#[test]
fn curated_corpus_is_complete_content_addressed_and_licensed() {
    let fixtures_root = fixtures_root();
    let corpus = read_corpus(&fixtures_root);
    assert_eq!(corpus.schema, CORPUS_SCHEMA);
    assert!(!corpus.fixtures.is_empty());

    let mut ids = BTreeSet::new();
    let mut manifest_paths = BTreeSet::new();
    for fixture in &corpus.fixtures {
        assert!(
            ids.insert(fixture.id.as_str()),
            "duplicate id {}",
            fixture.id
        );
        assert!(
            manifest_paths.insert(fixture.path.as_str()),
            "duplicate path {}",
            fixture.path
        );
        assert!(
            !fixture.purpose.trim().is_empty(),
            "{} has no purpose",
            fixture.id
        );
        assert_lower_hex(&fixture.origin.revision, 40, "revision", &fixture.id);
        assert_lower_hex(
            &fixture.origin.upstream_blob_sha1,
            40,
            "upstream blob SHA-1",
            &fixture.id,
        );
        assert!(
            matches!(fixture.origin.license.as_str(), "BSD-3-Clause" | "MIT"),
            "{} uses an unreviewed license {}",
            fixture.id,
            fixture.origin.license
        );

        let expected_url = format!(
            "https://raw.githubusercontent.com/{}/{}/{}",
            fixture.origin.repository, fixture.origin.revision, fixture.origin.source_path
        );
        assert_eq!(
            fixture.origin.source_url, expected_url,
            "{} does not use its immutable canonical source URL",
            fixture.id
        );

        let license_path = fixtures_root.join(&fixture.origin.license_file);
        let license = fs::read_to_string(&license_path).unwrap_or_else(|error| {
            panic!(
                "reading license for {} at {}: {error}",
                fixture.id,
                license_path.display()
            )
        });
        assert!(
            !license.trim().is_empty(),
            "{} has an empty license file",
            fixture.id
        );

        let encoded_path = fixtures_root.join(&fixture.path);
        let encoded = fs::read_to_string(&encoded_path).unwrap_or_else(|error| {
            panic!(
                "reading fixture {} at {}: {error}",
                fixture.id,
                encoded_path.display()
            )
        });
        let decoded = decode_hex(&encoded);
        assert_eq!(
            u64::try_from(decoded.len()).unwrap(),
            fixture.size_bytes,
            "{} decoded size changed",
            fixture.id
        );
        assert_eq!(
            hex_sha256(&decoded),
            fixture.content_sha256,
            "{} decoded content changed",
            fixture.id
        );
        assert_eq!(
            git_blob_sha1(&decoded),
            fixture.origin.upstream_blob_sha1,
            "{} decoded bytes do not match the pinned upstream Git blob",
            fixture.id
        );
        assert_lower_hex(&fixture.content_sha256, 64, "content SHA-256", &fixture.id);
        assert!(fixture.expected.packet_count > 0);
        assert_eq!(
            fixture.expected.packet_count,
            fixture.expected.packets_emitted + fixture.expected.packets_quarantined,
            "{} expected rows do not cover its file packets",
            fixture.id
        );
    }

    let actual_paths: BTreeSet<String> = fs::read_dir(fixtures_root.join("upstream"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.path().extension().is_some_and(|value| value == "hex"))
        .map(|entry| {
            format!(
                "upstream/{}",
                entry.file_name().to_str().expect("fixture name is UTF-8")
            )
        })
        .collect();
    let expected_paths: BTreeSet<String> = manifest_paths.into_iter().map(str::to_owned).collect();
    assert_eq!(
        actual_paths, expected_paths,
        "every upstream hex fixture must appear in the corpus manifest"
    );
}

#[test]
#[ignore = "requires installed tshark and capinfos; run through `just pcap-smoke`"]
fn installed_wireshark_tools_normalize_curated_corpus() {
    let fixtures_root = fixtures_root();
    let corpus = read_corpus(&fixtures_root);
    let directory = tempfile::tempdir().unwrap();

    for fixture in corpus.fixtures {
        let encoded = fs::read_to_string(fixtures_root.join(&fixture.path)).unwrap();
        let decoded = decode_hex(&encoded);
        let extension = Path::new(&fixture.origin.source_path)
            .extension()
            .and_then(|value| value.to_str())
            .expect("upstream capture has an extension");
        let input = directory
            .path()
            .join(format!("{}.{}", fixture.id, extension));
        fs::write(&input, decoded).unwrap();

        let report = normalize_saved_capture(
            &input,
            &NormalizeOptions {
                tshark_path: std::env::var_os("TSHARK")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("tshark")),
                capinfos_path: std::env::var_os("CAPINFOS")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("capinfos")),
                packet_limit: 100,
                ..NormalizeOptions::default()
            },
        )
        .unwrap_or_else(|error| panic!("normalizing {}: {error}", fixture.id));

        assert_eq!(
            report.manifest.capture_id,
            format!("sha256:{}", fixture.content_sha256),
            "{} content identity changed",
            fixture.id
        );
        assert!(
            report.manifest.observer_id.is_none(),
            "{} must not invent an observer for an upstream artifact",
            fixture.id
        );
        assert!(
            report.manifest.acquisition_policy.is_none(),
            "{} must not infer how the upstream artifact was acquired",
            fixture.id
        );
        assert_eq!(
            report.manifest.normalization.state,
            NormalizationStateV0::Complete,
            "{} did not normalize completely",
            fixture.id
        );
        assert_eq!(report.receipt.file.file_type, fixture.expected.file_type);
        assert_eq!(
            report.receipt.file.encapsulation,
            fixture.expected.encapsulation
        );
        assert_eq!(
            report.receipt.file.timestamp_precision,
            fixture.expected.timestamp_precision
        );
        assert_eq!(
            report.receipt.file.packet_count,
            fixture.expected.packet_count
        );
        assert_eq!(
            report.receipt.file.original_data_size_bytes,
            fixture.expected.original_data_size_bytes
        );
        assert_eq!(
            report.manifest.normalization.packet_rows_emitted,
            fixture.expected.packets_emitted
        );
        assert_eq!(
            report.manifest.normalization.packet_rows_quarantined,
            fixture.expected.packets_quarantined
        );

        let observed_protocols: BTreeSet<&str> = report
            .packets
            .iter()
            .flat_map(|packet| packet.frame.protocols.iter().map(String::as_str))
            .collect();
        for required in &fixture.expected.required_protocols {
            assert!(
                observed_protocols.contains(required.as_str()),
                "{} did not expose required protocol {required:?}; observed {observed_protocols:?}",
                fixture.id
            );
        }
    }
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn read_corpus(fixtures_root: &Path) -> Corpus {
    let path = fixtures_root.join("upstream/corpus-v0.json");
    let input = fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
    serde_json::from_str(&input)
        .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
}

fn assert_lower_hex(value: &str, length: usize, field: &str, fixture_id: &str) {
    assert_eq!(
        value.len(),
        length,
        "{fixture_id} has an invalid {field} length"
    );
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{fixture_id} has a non-lowercase-hex {field}"
    );
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn git_blob_sha1(bytes: &[u8]) -> String {
    let mut digest = Sha1::new();
    digest.update(format!("blob {}\0", bytes.len()));
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}

fn decode_hex(input: &str) -> Vec<u8> {
    let compact: String = input
        .lines()
        .flat_map(|line| line.split('#').next().unwrap_or_default().chars())
        .filter(|character| !character.is_whitespace())
        .collect();
    assert_eq!(compact.len() % 2, 0, "hex fixture has an odd digit count");
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16)
                .expect("fixture contains only hexadecimal digits")
        })
        .collect()
}
