use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use netbraid::adapters::tshark::{normalize_saved_capture, NormalizationReport, NormalizeOptions};
use netbraid::evidence::NormalizationStateV0;
use netbraid::replay::{
    parse_saved_capture_jsonl, reduce_capture_conversations, ConversationExclusionReasonV0,
    SavedCaptureRecordStreamV0,
};
use serde::{Deserialize, Serialize};
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
    #[serde(default)]
    protocol_frame_counts: Vec<ExpectedProtocolFrameCount>,
    #[serde(default)]
    ieee80211: Option<ExpectedIeee80211>,
    conversation_reduction: ExpectedConversationReduction,
}

#[derive(Debug, Deserialize)]
struct ExpectedProtocolFrameCount {
    protocol: String,
    frames: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedIeee80211 {
    frames: usize,
    radio_frames: usize,
    bssid_frames: usize,
    transmitter_frames: usize,
    nonempty_ssid_frames: usize,
    frame_mix: Vec<ExpectedFrameMix>,
    channels: Vec<u32>,
    center_frequencies_mhz: Vec<u16>,
    #[serde(default)]
    signal_dbm: Option<ExpectedSignalRange>,
    bssids: Vec<String>,
    transmitters: Vec<String>,
    ssid_hex: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct ExpectedFrameMix {
    frame_type: u8,
    frame_subtype: u8,
    frames: usize,
}

#[derive(Debug, Deserialize)]
struct ExpectedSignalRange {
    samples: usize,
    minimum: i8,
    maximum: i8,
}

#[derive(Debug, Deserialize)]
struct ExpectedConversationReduction {
    packet_envelopes_grouped: u64,
    packet_envelopes_excluded: u64,
    conversations: usize,
    #[serde(default)]
    exclusions: Vec<ExpectedConversationExclusion>,
}

#[derive(Debug, Deserialize)]
struct ExpectedConversationExclusion {
    reason: ExpectedConversationExclusionReason,
    packet_envelopes: u64,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExpectedConversationExclusionReason {
    InvalidPacketEnvelope,
    UnmodeledEncapsulation,
    AmbiguousNetworkLayer,
    AmbiguousTransportLayer,
    IndistinguishableEndpoints,
}

#[test]
fn curated_corpus_is_complete_content_addressed_and_licensed() {
    let fixtures_root = fixtures_root();
    let corpus = read_corpus(&fixtures_root);
    assert_eq!(corpus.schema, CORPUS_SCHEMA);
    assert!(!corpus.fixtures.is_empty());

    let mut ids = BTreeSet::new();
    let mut manifest_paths = BTreeSet::new();
    let mut content_digests = BTreeSet::new();
    let mut origin_coordinates = BTreeSet::new();
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
            content_digests.insert(fixture.content_sha256.as_str()),
            "duplicate content SHA-256 {}",
            fixture.content_sha256
        );
        assert!(
            origin_coordinates.insert((
                fixture.origin.repository.as_str(),
                fixture.origin.revision.as_str(),
                fixture.origin.source_path.as_str(),
            )),
            "duplicate immutable origin coordinate {}/{}:{}",
            fixture.origin.repository,
            fixture.origin.revision,
            fixture.origin.source_path
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

        let options = NormalizeOptions {
            tshark_path: std::env::var_os("TSHARK")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("tshark")),
            capinfos_path: std::env::var_os("CAPINFOS")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("capinfos")),
            packet_limit: 100,
            ..NormalizeOptions::default()
        };
        let report = normalize_saved_capture(&input, &options)
            .unwrap_or_else(|error| panic!("normalizing {} first run: {error}", fixture.id));
        let rerun = normalize_saved_capture(&input, &options)
            .unwrap_or_else(|error| panic!("normalizing {} second run: {error}", fixture.id));

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
        let mut observed_protocol_frame_counts = std::collections::BTreeMap::new();
        for protocol in report
            .packets
            .iter()
            .flat_map(|packet| packet.frame.protocols.iter())
        {
            *observed_protocol_frame_counts
                .entry(protocol.as_str())
                .or_insert(0) += 1;
        }
        for expected_count in &fixture.expected.protocol_frame_counts {
            assert_eq!(
                observed_protocol_frame_counts
                    .get(expected_count.protocol.as_str())
                    .copied()
                    .unwrap_or_default(),
                expected_count.frames,
                "{} protocol {:?} frame count",
                fixture.id,
                expected_count.protocol
            );
        }

        assert_ieee80211_expectations(&fixture, &report.packets);
        assert_replay_and_reduction_expectations(&fixture, &report, &rerun);
    }
}

fn assert_replay_and_reduction_expectations(
    fixture: &Fixture,
    report: &NormalizationReport,
    rerun: &NormalizationReport,
) {
    assert_ne!(
        report.receipt.run_id, rerun.receipt.run_id,
        "{} normalization occurrences must have distinct run IDs",
        fixture.id
    );

    let full_bytes = full_jsonl(report);
    let records_bytes = records_jsonl(report);
    let rerun_full_bytes = full_jsonl(rerun);
    let rerun_records_bytes = records_jsonl(rerun);
    assert_eq!(
        records_bytes, rerun_records_bytes,
        "{} deterministic records JSONL changed across equivalent runs",
        fixture.id
    );
    assert_ne!(
        full_bytes, rerun_full_bytes,
        "{} occurrence-bearing JSONL unexpectedly stayed byte-identical",
        fixture.id
    );

    let full = parse_stream(&fixture.id, "full first-run", &full_bytes);
    let records = parse_stream(&fixture.id, "records first-run", &records_bytes);
    let rerun_full = parse_stream(&fixture.id, "full second-run", &rerun_full_bytes);
    let rerun_records = parse_stream(&fixture.id, "records second-run", &rerun_records_bytes);

    assert_eq!(
        full.receipt.as_ref(),
        Some(&report.receipt),
        "{} full JSONL did not preserve its exact run receipt",
        fixture.id
    );
    assert_eq!(
        rerun_full.receipt.as_ref(),
        Some(&rerun.receipt),
        "{} second full JSONL did not preserve its exact run receipt",
        fixture.id
    );
    assert!(
        records.receipt.is_none() && rerun_records.receipt.is_none(),
        "{} deterministic records JSONL must omit occurrence receipts",
        fixture.id
    );
    assert_replayed_records_equal(&fixture.id, &full, &records);
    assert_replayed_records_equal(&fixture.id, &rerun_full, &rerun_records);
    assert_replayed_records_equal(&fixture.id, &records, &rerun_records);
    assert_eq!(
        records.normalized_records_sha256, report.receipt.normalized_records_sha256,
        "{} replay digest did not match the producer receipt",
        fixture.id
    );
    assert_eq!(
        rerun_records.normalized_records_sha256, rerun.receipt.normalized_records_sha256,
        "{} rerun replay digest did not match the producer receipt",
        fixture.id
    );

    let reduction = reduce_capture_conversations(&records.packets);
    let expected = &fixture.expected.conversation_reduction;
    assert_eq!(
        reduction.packet_envelopes_seen, fixture.expected.packets_emitted,
        "{} reducer input coverage",
        fixture.id
    );
    assert_eq!(
        reduction.packet_envelopes_grouped, expected.packet_envelopes_grouped,
        "{} grouped packet envelopes",
        fixture.id
    );
    assert_eq!(
        reduction.packet_envelopes_excluded, expected.packet_envelopes_excluded,
        "{} excluded packet envelopes",
        fixture.id
    );
    assert_eq!(
        reduction.conversations.len(),
        expected.conversations,
        "{} conversation count",
        fixture.id
    );
    let expected_exclusions: BTreeMap<_, _> = expected
        .exclusions
        .iter()
        .map(|exclusion| {
            (
                exclusion.reason.as_replay_reason(),
                exclusion.packet_envelopes,
            )
        })
        .collect();
    assert_eq!(
        reduction.exclusions, expected_exclusions,
        "{} conversation exclusion reasons",
        fixture.id
    );
}

impl ExpectedConversationExclusionReason {
    fn as_replay_reason(&self) -> ConversationExclusionReasonV0 {
        match self {
            Self::InvalidPacketEnvelope => ConversationExclusionReasonV0::InvalidPacketEnvelope,
            Self::UnmodeledEncapsulation => ConversationExclusionReasonV0::UnmodeledEncapsulation,
            Self::AmbiguousNetworkLayer => ConversationExclusionReasonV0::AmbiguousNetworkLayer,
            Self::AmbiguousTransportLayer => ConversationExclusionReasonV0::AmbiguousTransportLayer,
            Self::IndistinguishableEndpoints => {
                ConversationExclusionReasonV0::IndistinguishableEndpoints
            }
        }
    }
}

fn full_jsonl(report: &NormalizationReport) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_jsonl_record(&mut bytes, &report.manifest);
    push_jsonl_record(&mut bytes, &report.receipt);
    for packet in &report.packets {
        push_jsonl_record(&mut bytes, packet);
    }
    for quarantine in &report.quarantines {
        push_jsonl_record(&mut bytes, quarantine);
    }
    bytes
}

fn records_jsonl(report: &NormalizationReport) -> Vec<u8> {
    let mut bytes = Vec::new();
    push_jsonl_record(&mut bytes, &report.manifest);
    for packet in &report.packets {
        push_jsonl_record(&mut bytes, packet);
    }
    for quarantine in &report.quarantines {
        push_jsonl_record(&mut bytes, quarantine);
    }
    bytes
}

fn push_jsonl_record<T: Serialize>(output: &mut Vec<u8>, record: &T) {
    serde_json::to_writer(&mut *output, record).expect("serializing typed fixture record");
    output.push(b'\n');
}

fn parse_stream(fixture_id: &str, stream: &str, bytes: &[u8]) -> SavedCaptureRecordStreamV0 {
    parse_saved_capture_jsonl(bytes)
        .unwrap_or_else(|error| panic!("parsing {stream} JSONL for {fixture_id}: {error}"))
}

fn assert_replayed_records_equal(
    fixture_id: &str,
    left: &SavedCaptureRecordStreamV0,
    right: &SavedCaptureRecordStreamV0,
) {
    assert_eq!(
        left.manifest, right.manifest,
        "{fixture_id} replayed manifests"
    );
    assert_eq!(left.packets, right.packets, "{fixture_id} replayed packets");
    assert_eq!(
        left.quarantines, right.quarantines,
        "{fixture_id} replayed quarantines"
    );
    assert_eq!(
        left.normalized_records_sha256, right.normalized_records_sha256,
        "{fixture_id} replayed record digests"
    );
}

fn assert_ieee80211_expectations(
    fixture: &Fixture,
    packets: &[netbraid::evidence::PacketEnvelopeV0],
) {
    let Some(expected) = &fixture.expected.ieee80211 else {
        assert!(
            packets.iter().all(|packet| packet.ieee80211.is_none()),
            "{} unexpectedly exposed IEEE 802.11 fields",
            fixture.id
        );
        assert!(
            packets.iter().all(|packet| packet.wlan_radio.is_none()),
            "{} unexpectedly exposed WLAN radio fields",
            fixture.id
        );
        return;
    };

    let wireless: Vec<_> = packets
        .iter()
        .filter_map(|packet| packet.ieee80211.as_ref())
        .collect();
    assert_eq!(
        wireless.len(),
        expected.frames,
        "{} WLAN frames",
        fixture.id
    );
    assert_eq!(
        packets
            .iter()
            .filter(|packet| packet.wlan_radio.is_some())
            .count(),
        expected.radio_frames,
        "{} radio metadata coverage",
        fixture.id
    );
    assert_eq!(
        wireless
            .iter()
            .filter(|fields| fields.bssid.is_some())
            .count(),
        expected.bssid_frames,
        "{} BSSID coverage",
        fixture.id
    );
    assert_eq!(
        wireless
            .iter()
            .filter(|fields| fields.transmitter.is_some())
            .count(),
        expected.transmitter_frames,
        "{} transmitter-address coverage",
        fixture.id
    );
    assert_eq!(
        wireless
            .iter()
            .filter(|fields| fields.ssid_hex.is_some())
            .count(),
        expected.nonempty_ssid_frames,
        "{} SSID coverage",
        fixture.id
    );

    let mut frame_mix = std::collections::BTreeMap::new();
    for fields in &wireless {
        *frame_mix
            .entry((fields.frame_type, fields.frame_subtype))
            .or_insert(0) += 1;
    }
    let observed_mix: Vec<_> = frame_mix
        .into_iter()
        .map(|((frame_type, frame_subtype), frames)| ExpectedFrameMix {
            frame_type,
            frame_subtype,
            frames,
        })
        .collect();
    assert_eq!(observed_mix, expected.frame_mix, "{} frame mix", fixture.id);

    let radios: Vec<_> = packets
        .iter()
        .filter_map(|packet| packet.wlan_radio.as_ref())
        .collect();
    assert_eq!(
        unique_sorted(radios.iter().filter_map(|radio| radio.channel)),
        expected.channels,
        "{} channels",
        fixture.id
    );
    assert_eq!(
        unique_sorted(radios.iter().filter_map(|radio| radio.center_frequency_mhz)),
        expected.center_frequencies_mhz,
        "{} center frequencies",
        fixture.id
    );
    let signals: Vec<_> = radios.iter().filter_map(|radio| radio.signal_dbm).collect();
    if let Some(expected_signal) = &expected.signal_dbm {
        assert_eq!(
            signals.len(),
            expected_signal.samples,
            "{} signal sample coverage",
            fixture.id
        );
        assert_eq!(
            signals.iter().min().copied(),
            Some(expected_signal.minimum),
            "{} signal minimum",
            fixture.id
        );
        assert_eq!(
            signals.iter().max().copied(),
            Some(expected_signal.maximum),
            "{} signal maximum",
            fixture.id
        );
    } else {
        assert!(
            signals.is_empty(),
            "{} unexpectedly exposed signal strength samples",
            fixture.id
        );
    }
    assert_eq!(
        unique_sorted(wireless.iter().filter_map(|fields| fields.bssid.clone())),
        expected.bssids,
        "{} BSSIDs",
        fixture.id
    );
    assert_eq!(
        unique_sorted(
            wireless
                .iter()
                .filter_map(|fields| fields.transmitter.clone())
        ),
        expected.transmitters,
        "{} transmitter addresses",
        fixture.id
    );
    assert_eq!(
        unique_sorted(wireless.iter().filter_map(|fields| fields.ssid_hex.clone())),
        expected.ssid_hex,
        "{} SSID bytes",
        fixture.id
    );
}

fn unique_sorted<T: Ord>(values: impl IntoIterator<Item = T>) -> Vec<T> {
    values
        .into_iter()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn fixtures_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adapter")
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
