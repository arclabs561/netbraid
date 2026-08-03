#![cfg(feature = "adapter-sigmf")]

use std::fs;
use std::path::PathBuf;

use netbraid::adapters::sigmf::{
    project_sigmf_window, SigmfAdapterError, SigmfByteOrder, SigmfDialect, SigmfSourceKind,
    SigmfWindowOptions, SigmfWindowProjection,
};
use netbraid::evidence::{
    IqByteOrderProvenanceV0, IqByteOrderStateV0, IqComponentAggregateV0, IqDialectV0,
    IqValueCountsV0, IqWindowCompletenessV0, IQ_WINDOW_EVIDENCE_SCHEMA_V0,
    IQ_WINDOW_LINKABILITY_NOTICE_V0,
};
use proptest::prelude::*;
use serde_json::{json, Value};
use tempfile::TempDir;

const CORE_LE_METADATA: &str = include_str!("fixtures/adapter/sigmf/core-le.sigmf-meta");
const CORE_LE_DATA: &str = include_str!("fixtures/adapter/sigmf/core-le.sigmf-data.hex");
const CORE_BE_METADATA: &str = include_str!("fixtures/adapter/sigmf/core-be.sigmf-meta");
const CORE_BE_DATA: &str = include_str!("fixtures/adapter/sigmf/core-be.sigmf-data.hex");
const OSU_METADATA: &str = include_str!("fixtures/adapter/sigmf/osu.sigmf-meta");
const OSU_DATA: &str = include_str!("fixtures/adapter/sigmf/osu.dat.hex");

struct StagedRecording {
    _directory: TempDir,
    metadata_path: PathBuf,
}

fn stage_recording(metadata: &str, data: &[u8], stem: &str, data_suffix: &str) -> StagedRecording {
    let directory = tempfile::tempdir().unwrap();
    let metadata_path = directory.path().join(format!("{stem}.sigmf-meta"));
    fs::write(&metadata_path, metadata).unwrap();
    fs::write(directory.path().join(format!("{stem}{data_suffix}")), data).unwrap();
    StagedRecording {
        _directory: directory,
        metadata_path,
    }
}

fn stage_core_le() -> StagedRecording {
    stage_recording(
        CORE_LE_METADATA,
        &decode_hex(CORE_LE_DATA),
        "core-le",
        ".sigmf-data",
    )
}

fn stage_core_be() -> StagedRecording {
    stage_recording(
        CORE_BE_METADATA,
        &decode_hex(CORE_BE_DATA),
        "core-be",
        ".sigmf-data",
    )
}

fn stage_osu() -> StagedRecording {
    stage_recording(OSU_METADATA, &decode_hex(OSU_DATA), "osu", ".dat")
}

fn options(first_sample: u64, sample_count: u64) -> SigmfWindowOptions {
    let mut options = SigmfWindowOptions::default();
    options.first_sample = first_sample;
    options.sample_count = sample_count;
    options
}

#[test]
fn exact_cf32_little_and_big_endian_window_oracles_match() {
    let little = stage_core_le();
    let big = stage_core_be();
    let little = project_sigmf_window(&little.metadata_path, &options(0, 4)).unwrap();
    let big = project_sigmf_window(&big.metadata_path, &options(0, 4)).unwrap();

    for projection in [&little, &big] {
        let evidence = projection.evidence();
        assert_eq!(evidence.schema(), IQ_WINDOW_EVIDENCE_SCHEMA_V0);
        assert_eq!(evidence.dialect(), IqDialectV0::SigmfCore);
        assert_eq!(evidence.channel_count(), 1);
        assert_eq!(evidence.sample_rate_hz(), 1_000_000);
        assert_eq!(evidence.center_frequency_hz(), Some(915_000_000));
        assert_eq!(evidence.observed_interval().sample_count(), 4);
        assert_eq!(evidence.completeness(), IqWindowCompletenessV0::Complete);
        assert_counts(evidence.counts(), 6, 2, 2);
        let aggregates = evidence.aggregates().unwrap();
        assert_component(
            aggregates.in_phase(),
            2,
            0,
            1,
            Some(0.0f32.to_bits()),
            Some(1.0f32.to_bits()),
        );
        assert_component(
            aggregates.quadrature(),
            0,
            2,
            0,
            Some((-2.0f32).to_bits()),
            Some((-0.0f32).to_bits()),
        );
    }
    assert_eq!(
        little.evidence().aggregates(),
        big.evidence().aggregates(),
        "endian-specific decoding must produce the same exact summaries"
    );
    assert_eq!(
        little.evidence().byte_order().state(),
        IqByteOrderStateV0::Little
    );
    assert_eq!(big.evidence().byte_order().state(), IqByteOrderStateV0::Big);
}

#[test]
fn exact_window_selects_only_requested_nonfinite_and_zero_samples() {
    let recording = stage_core_le();
    let projection = project_sigmf_window(&recording.metadata_path, &options(1, 2)).unwrap();

    assert_counts(projection.evidence().counts(), 2, 2, 2);
    assert_eq!(projection.evidence().observed_interval().first_sample(), 1);
    assert_eq!(projection.evidence().observed_interval().sample_count(), 2);
    let aggregates = projection.evidence().aggregates().unwrap();
    assert_component(
        aggregates.in_phase(),
        0,
        0,
        0,
        Some(0.0f32.to_bits()),
        Some(0.0f32.to_bits()),
    );
    assert_component(
        aggregates.quadrature(),
        0,
        0,
        0,
        Some((-0.0f32).to_bits()),
        Some((-0.0f32).to_bits()),
    );
}

#[test]
fn osu_unknown_byte_order_abstains_and_override_matches_core_fixture() {
    let osu = stage_osu();
    let unknown = project_sigmf_window(&osu.metadata_path, &options(0, 4)).unwrap();
    assert_eq!(unknown.evidence().dialect(), IqDialectV0::OsuLoraV2);
    assert_eq!(
        unknown.evidence().byte_order().state(),
        IqByteOrderStateV0::Unknown
    );
    assert_eq!(
        unknown.evidence().byte_order().provenance(),
        IqByteOrderProvenanceV0::Undeclared
    );
    assert_eq!(
        unknown.evidence().completeness(),
        IqWindowCompletenessV0::UndecodableUnknownByteOrder
    );
    assert_eq!(unknown.evidence().observed_interval().sample_count(), 0);
    assert_eq!(unknown.read_audit().read_calls(), 0);

    let mut overridden_options = options(0, 4);
    overridden_options.byte_order_override = Some(SigmfByteOrder::Little);
    let overridden = project_sigmf_window(&osu.metadata_path, &overridden_options).unwrap();
    let core = stage_core_le();
    let core = project_sigmf_window(&core.metadata_path, &options(0, 4)).unwrap();
    assert_eq!(overridden.evidence().counts(), core.evidence().counts());
    assert_eq!(
        overridden.evidence().aggregates(),
        core.evidence().aggregates()
    );
    assert_eq!(
        overridden.evidence().byte_order().provenance(),
        IqByteOrderProvenanceV0::CallerOverride
    );
}

#[test]
fn static_truncation_reports_only_complete_samples() {
    let bytes = decode_hex(CORE_LE_DATA);
    let recording = stage_recording(CORE_LE_METADATA, &bytes[..20], "core-le", ".sigmf-data");
    let projection = project_sigmf_window(&recording.metadata_path, &options(0, 4)).unwrap();

    assert_eq!(
        projection.evidence().completeness(),
        IqWindowCompletenessV0::Truncated
    );
    assert_eq!(projection.evidence().observed_interval().sample_count(), 2);
    assert_eq!(projection.read_audit().observed_bytes(), 16);
    assert_counts(projection.evidence().counts(), 4, 0, 2);
}

#[test]
fn unsupported_datatype_multichannel_and_required_extension_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let data = decode_hex(CORE_LE_DATA);

    let unsupported = core_metadata("ci16_le", 1, None);
    let unsupported_path = write_core(&directory, "unsupported", &unsupported, &data);
    assert!(matches!(
        project_sigmf_window(&unsupported_path, &options(0, 1)),
        Err(SigmfAdapterError::UnsupportedDatatype)
    ));

    let multichannel = core_metadata("cf32_le", 2, None);
    let multichannel_path = write_core(&directory, "multichannel", &multichannel, &data);
    assert!(matches!(
        project_sigmf_window(&multichannel_path, &options(0, 1)),
        Err(SigmfAdapterError::Multichannel)
    ));

    let required_extension = core_metadata(
        "cf32_le",
        1,
        Some(json!([{"name":"unknown","version":"1.0.0","optional":false}])),
    );
    let extension_path = write_core(&directory, "required-extension", &required_extension, &data);
    assert!(matches!(
        project_sigmf_window(&extension_path, &options(0, 1)),
        Err(SigmfAdapterError::UnknownRequiredExtension)
    ));

    let optional_extension = core_metadata(
        "cf32_le",
        1,
        Some(json!([{"name":"unknown","version":"1.0.0","optional":true}])),
    );
    let optional_path = write_core(&directory, "optional-extension", &optional_extension, &data);
    assert!(project_sigmf_window(&optional_path, &options(0, 1)).is_ok());
}

#[test]
fn duplicate_json_keys_are_rejected_at_any_depth() {
    let metadata = r#"{
        "global": {
            "core:datatype": "cf32_le",
            "core:datatype": "cf32_be",
            "core:sample_rate": 1,
            "core:version": "1.2.0"
        },
        "captures": [],
        "annotations": []
    }"#;
    let recording = stage_recording(metadata, &[0u8; 8], "duplicate", ".sigmf-data");
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &options(0, 1)),
        Err(SigmfAdapterError::DuplicateJsonKey)
    ));
}

#[test]
fn unsafe_osu_sibling_declaration_is_rejected() {
    let metadata = OSU_METADATA.replace("\"osu.dat\"", "\"../escape.dat\"");
    let recording = stage_recording(&metadata, &decode_hex(OSU_DATA), "osu", ".dat");
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &options(0, 1)),
        Err(SigmfAdapterError::UnsafeSiblingDeclaration)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_data_source_is_rejected() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    let metadata: Value = serde_json::from_str(CORE_LE_METADATA).unwrap();
    let metadata_path = write_core(&directory, "linked", &metadata, &[]);
    let data_path = directory.path().join("linked.sigmf-data");
    fs::remove_file(&data_path).unwrap();
    let target = directory.path().join("target.bin");
    fs::write(&target, [0u8; 8]).unwrap();
    symlink(&target, &data_path).unwrap();

    assert!(matches!(
        project_sigmf_window(&metadata_path, &options(0, 1)),
        Err(SigmfAdapterError::SourceSymlink(SigmfSourceKind::Data))
    ));
}

#[test]
fn nonregular_metadata_and_data_sources_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let metadata_directory = directory.path().join("directory.sigmf-meta");
    fs::create_dir(&metadata_directory).unwrap();
    assert!(matches!(
        project_sigmf_window(&metadata_directory, &options(0, 1)),
        Err(SigmfAdapterError::SourceNotRegular(
            SigmfSourceKind::Metadata
        ))
    ));

    let metadata: Value = serde_json::from_str(CORE_LE_METADATA).unwrap();
    let data_path = directory.path().join("nonregular.sigmf-data");
    let metadata_path = directory.path().join("nonregular.sigmf-meta");
    fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    fs::create_dir(&data_path).unwrap();
    assert!(matches!(
        project_sigmf_window(&metadata_path, &options(0, 1)),
        Err(SigmfAdapterError::SourceNotRegular(SigmfSourceKind::Data))
    ));
}

#[test]
fn offset_and_length_arithmetic_fail_before_any_iq_read() {
    let recording = stage_core_le();
    let overflow = options(u64::MAX, 1);
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &overflow),
        Err(SigmfAdapterError::OffsetOverflow)
    ));

    let mut too_large = options(0, (64 * 1024 * 1024 / 8) + 1);
    too_large.max_window_bytes = 64 * 1024 * 1024;
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &too_large),
        Err(SigmfAdapterError::WindowTooLarge)
    ));
}

#[test]
fn zero_and_over_hard_limit_bounds_are_invalid_options() {
    let recording = stage_core_le();
    let mut invalid = options(0, 1);
    invalid.max_metadata_bytes = 0;
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &invalid),
        Err(SigmfAdapterError::InvalidOption("max_metadata_bytes"))
    ));

    invalid = options(0, 1);
    invalid.max_window_bytes = 64 * 1024 * 1024 + 1;
    assert!(matches!(
        project_sigmf_window(&recording.metadata_path, &invalid),
        Err(SigmfAdapterError::InvalidOption("max_window_bytes"))
    ));
}

#[test]
fn positional_read_audit_is_confined_to_the_requested_window_and_bound() {
    let recording = stage_core_le();
    let mut bounded = options(1, 2);
    bounded.max_window_bytes = 16;
    let projection = project_sigmf_window(&recording.metadata_path, &bounded).unwrap();
    let audit = projection.read_audit();

    assert_eq!(audit.requested_byte_offset(), 8);
    assert_eq!(audit.requested_bytes(), 16);
    assert_eq!(audit.observed_bytes(), 16);
    assert_eq!(audit.requested_byte_offset() + audit.observed_bytes(), 24);
    assert!(audit.read_calls() >= 1);
    assert!(audit.maximum_single_read_bytes() <= bounded.max_window_bytes);
}

#[test]
fn explicit_dialects_and_auto_detection_agree() {
    let core = stage_core_le();
    let automatic = project_sigmf_window(&core.metadata_path, &options(0, 1)).unwrap();
    let mut explicit = options(0, 1);
    explicit.dialect = SigmfDialect::SigmfCore;
    let explicit = project_sigmf_window(&core.metadata_path, &explicit).unwrap();
    assert_eq!(automatic.evidence(), explicit.evidence());

    let mut wrong = options(0, 1);
    wrong.dialect = SigmfDialect::OsuLoraV2;
    assert!(matches!(
        project_sigmf_window(&core.metadata_path, &wrong),
        Err(SigmfAdapterError::DialectMismatch)
    ));
}

#[test]
fn serialized_public_report_excludes_private_and_analytic_markers() {
    let markers = [
        "PRIVATE_AUTHOR",
        "PRIVATE_DESCRIPTION",
        "PRIVATE_RECEIVER",
        "PRIVATE_TRANSMITTER",
        "PRIVATE_ANTENNA",
        "PRIVATE_PATH",
        "PRIVATE_SOURCE",
        "2000-01-01T00:00:00Z",
    ];
    let metadata = OSU_METADATA
        .replace("synthetic bounded adapter fixture", "PRIVATE_DESCRIPTION")
        .replace("synthetic-rx-antenna", "PRIVATE_ANTENNA")
        .replace("synthetic-tx-antenna", "PRIVATE_ANTENNA")
        .replace("synthetic-rx", "PRIVATE_RECEIVER")
        .replace("synthetic-tx", "PRIVATE_TRANSMITTER")
        .replace(
            "\"core:author\": \"synthetic\"",
            "\"core:author\": \"PRIVATE_AUTHOR\"",
        )
        .replace(
            "\"osu.dat\"",
            "\"https://example.invalid/PRIVATE_SOURCE/PRIVATE_PATH.sigmf-meta\"",
        );
    let recording = stage_recording(&metadata, &decode_hex(OSU_DATA), "PRIVATE_PATH", ".dat");
    let mut overridden = options(0, 4);
    overridden.byte_order_override = Some(SigmfByteOrder::Little);
    let projection = project_sigmf_window(&recording.metadata_path, &overridden).unwrap();
    let value = serde_json::to_value(projection.evidence()).unwrap();
    let rendered = serde_json::to_string(projection.evidence()).unwrap();

    for marker in markers {
        assert!(!rendered.contains(marker), "public report leaked {marker}");
    }
    assert_eq!(value["interpretation"], IQ_WINDOW_LINKABILITY_NOTICE_V0);
    assert_forbidden_keys_absent(&value);
    assert_eq!(
        rendered,
        serde_json::to_string(projection.evidence()).unwrap(),
        "integer and fixed-bit report rendering is deterministic"
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn bounded_positional_projection_matches_naive_for_overlapping_and_adjacent_windows(
        samples in prop::collection::vec((any::<i16>(), any::<i16>()), 3..48),
        start_seed in any::<u8>(),
        count_seed in any::<u8>(),
    ) {
        let samples: Vec<(f32, f32)> = samples
            .into_iter()
            .map(|(i, q)| (f32::from(i), f32::from(q)))
            .collect();
        let mut bytes = Vec::with_capacity(samples.len() * 8);
        for (i, q) in &samples {
            bytes.extend_from_slice(&i.to_le_bytes());
            bytes.extend_from_slice(&q.to_le_bytes());
        }
        let directory = tempfile::tempdir().unwrap();
        let metadata = core_metadata("cf32_le", 1, None);
        let metadata_path = write_core(&directory, "property", &metadata, &bytes);

        let first = usize::from(start_seed) % (samples.len() - 1);
        let available_before_adjacency = samples.len() - first - 1;
        let count = 1 + (usize::from(count_seed) % available_before_adjacency);
        let overlap_first = first + count.saturating_sub(1);
        let overlap_count = (samples.len() - overlap_first).min(2);
        let adjacent_first = first + count;
        let adjacent_count = (samples.len() - adjacent_first).min(2);
        let windows = [
            (first, count),
            (overlap_first, overlap_count),
            (adjacent_first, adjacent_count),
        ];

        for (first, count) in windows {
            let projection = project_sigmf_window(
                &metadata_path,
                &options(u64::try_from(first).unwrap(), u64::try_from(count).unwrap()),
            )
            .unwrap();
            assert_matches_naive(&projection, &samples[first..first + count]);
        }
    }
}

fn core_metadata(datatype: &str, channels: u64, extensions: Option<Value>) -> Value {
    let mut global = json!({
        "core:datatype": datatype,
        "core:sample_rate": 1_000_000,
        "core:version": "1.2.0",
        "core:num_channels": channels,
    });
    if let Some(extensions) = extensions {
        global["core:extensions"] = extensions;
    }
    json!({
        "global": global,
        "captures": [{"core:sample_start": 0, "core:frequency": 915_000_000}],
        "annotations": [],
    })
}

fn write_core(directory: &TempDir, stem: &str, metadata: &Value, data: &[u8]) -> PathBuf {
    let metadata_path = directory.path().join(format!("{stem}.sigmf-meta"));
    fs::write(&metadata_path, serde_json::to_vec(metadata).unwrap()).unwrap();
    fs::write(directory.path().join(format!("{stem}.sigmf-data")), data).unwrap();
    metadata_path
}

fn assert_matches_naive(projection: &SigmfWindowProjection, samples: &[(f32, f32)]) {
    let expected = naive_summary(samples);
    assert_eq!(
        projection.evidence().completeness(),
        IqWindowCompletenessV0::Complete
    );
    assert_eq!(
        projection.evidence().observed_interval().sample_count(),
        u64::try_from(samples.len()).unwrap()
    );
    assert_counts(
        projection.evidence().counts(),
        expected.finite,
        expected.nonfinite,
        expected.zero,
    );
    let aggregates = projection.evidence().aggregates().unwrap();
    assert_component_oracle(aggregates.in_phase(), &expected.in_phase);
    assert_component_oracle(aggregates.quadrature(), &expected.quadrature);
    assert_eq!(
        projection.read_audit().observed_bytes(),
        u64::try_from(samples.len() * 8).unwrap()
    );
}

fn naive_summary(samples: &[(f32, f32)]) -> SummaryOracle {
    let components: Vec<f32> = samples.iter().flat_map(|(i, q)| [*i, *q]).collect();
    let finite = components.iter().filter(|value| value.is_finite()).count();
    let nonfinite = components.len() - finite;
    let zero = components.iter().filter(|value| **value == 0.0).count();
    let in_phase: Vec<f32> = samples.iter().map(|sample| sample.0).collect();
    let quadrature: Vec<f32> = samples.iter().map(|sample| sample.1).collect();
    SummaryOracle {
        finite: u64::try_from(finite).unwrap(),
        nonfinite: u64::try_from(nonfinite).unwrap(),
        zero: u64::try_from(zero).unwrap(),
        in_phase: naive_component(&in_phase),
        quadrature: naive_component(&quadrature),
    }
}

fn naive_component(values: &[f32]) -> ComponentOracle {
    let finite: Vec<f32> = values
        .iter()
        .copied()
        .filter(|value| value.is_finite())
        .collect();
    let minimum = finite
        .iter()
        .copied()
        .min_by(f32::total_cmp)
        .map(f32::to_bits);
    let maximum = finite
        .iter()
        .copied()
        .max_by(f32::total_cmp)
        .map(f32::to_bits);
    ComponentOracle {
        positive: u64::try_from(finite.iter().filter(|value| **value > 0.0).count()).unwrap(),
        negative: u64::try_from(finite.iter().filter(|value| **value < 0.0).count()).unwrap(),
        subnormal: u64::try_from(finite.iter().filter(|value| value.is_subnormal()).count())
            .unwrap(),
        minimum,
        maximum,
    }
}

struct ComponentOracle {
    positive: u64,
    negative: u64,
    subnormal: u64,
    minimum: Option<u32>,
    maximum: Option<u32>,
}

struct SummaryOracle {
    finite: u64,
    nonfinite: u64,
    zero: u64,
    in_phase: ComponentOracle,
    quadrature: ComponentOracle,
}

fn assert_counts(counts: IqValueCountsV0, finite: u64, nonfinite: u64, zero: u64) {
    assert_eq!(counts.finite_components(), finite);
    assert_eq!(counts.nonfinite_components(), nonfinite);
    assert_eq!(counts.zero_components(), zero);
}

fn assert_component_oracle(aggregate: IqComponentAggregateV0, oracle: &ComponentOracle) {
    assert_component(
        aggregate,
        oracle.positive,
        oracle.negative,
        oracle.subnormal,
        oracle.minimum,
        oracle.maximum,
    );
}

fn assert_component(
    aggregate: IqComponentAggregateV0,
    positive: u64,
    negative: u64,
    subnormal: u64,
    minimum: Option<u32>,
    maximum: Option<u32>,
) {
    assert_eq!(aggregate.positive_finite(), positive);
    assert_eq!(aggregate.negative_finite(), negative);
    assert_eq!(aggregate.subnormal(), subnormal);
    assert_eq!(aggregate.minimum_finite_bits(), minimum);
    assert_eq!(aggregate.maximum_finite_bits(), maximum);
}

fn assert_forbidden_keys_absent(value: &Value) {
    const FORBIDDEN: &[&str] = &[
        "transmitter",
        "receiver",
        "device",
        "source_url",
        "filename",
        "path",
        "timestamp",
        "raw_samples",
        "hash",
        "fft",
        "spectrum",
        "phase",
        "cfo",
        "transient",
        "embedding",
        "classifier",
        "identity",
        "hypothesis",
        "cause",
    ];
    match value {
        Value::Object(object) => {
            for (key, nested) in object {
                assert!(
                    !FORBIDDEN.contains(&key.as_str()),
                    "forbidden public field {key}"
                );
                assert_forbidden_keys_absent(nested);
            }
        }
        Value::Array(values) => {
            for nested in values {
                assert_forbidden_keys_absent(nested);
            }
        }
        _ => {}
    }
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
