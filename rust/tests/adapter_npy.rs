#![cfg(feature = "adapter-npy")]

use std::fs;
use std::path::PathBuf;

use netbraid::adapters::npy::{
    project_npy_row_window, NpyAdapterError, NpyComponentAggregateV0, NpyDtypeV0,
    NpyRowWindowOptions, NpyWindowCompletenessV0, NPY_ROW_WINDOW_METADATA_SCHEMA_V0,
};
use proptest::prelude::*;
use tempfile::TempDir;

const NPY_PREFIX_BYTES: usize = 10;

struct StagedNpy {
    _directory: TempDir,
    path: PathBuf,
    data_offset: u64,
}

fn encode_npy(dictionary: &str, payload: &[u8]) -> (Vec<u8>, u64) {
    let mut header = dictionary.as_bytes().to_vec();
    let padding = (16 - ((NPY_PREFIX_BYTES + header.len() + 1) % 16)) % 16;
    header.extend(std::iter::repeat_n(b' ', padding));
    header.push(b'\n');
    let data_offset = u64::try_from(NPY_PREFIX_BYTES + header.len()).unwrap();
    let mut bytes = b"\x93NUMPY\x01\x00".to_vec();
    bytes.extend(u16::try_from(header.len()).unwrap().to_le_bytes());
    bytes.extend(header);
    bytes.extend(payload);
    (bytes, data_offset)
}

fn stage_raw(bytes: &[u8]) -> StagedNpy {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("fixture.npy");
    fs::write(&path, bytes).unwrap();
    StagedNpy {
        _directory: directory,
        path,
        data_offset: 0,
    }
}

fn stage_npy(dictionary: &str, payload: &[u8]) -> StagedNpy {
    let (bytes, data_offset) = encode_npy(dictionary, payload);
    let mut staged = stage_raw(&bytes);
    staged.data_offset = data_offset;
    staged
}

fn options(first_row: u64, row_count: u64) -> NpyRowWindowOptions {
    let mut options = NpyRowWindowOptions::default();
    options.first_row = first_row;
    options.row_count = row_count;
    options
}

fn f64_payload(values: &[f64]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn assert_component(
    aggregate: NpyComponentAggregateV0,
    positive: u64,
    negative: u64,
    subnormal: u64,
    minimum: Option<u64>,
    maximum: Option<u64>,
) {
    assert_eq!(aggregate.positive_finite(), positive);
    assert_eq!(aggregate.negative_finite(), negative);
    assert_eq!(aggregate.subnormal(), subnormal);
    assert_eq!(aggregate.minimum_finite_bits(), minimum);
    assert_eq!(aggregate.maximum_finite_bits(), maximum);
}

#[test]
fn exact_f8_row_window_oracle_matches() {
    let minimum_subnormal = f64::from_bits(1);
    let values = [
        100.0,
        101.0,
        102.0,
        -0.0,
        1.0,
        -2.0,
        f64::MIN_POSITIVE,
        -minimum_subnormal,
        f64::NAN,
        f64::INFINITY,
        7.0,
        8.0,
    ];
    let staged = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (4, 3), }",
        &f64_payload(&values),
    );

    let projection = project_npy_row_window(&staged.path, &options(1, 2)).unwrap();
    let metadata = projection.metadata();
    assert_eq!(metadata.schema(), NPY_ROW_WINDOW_METADATA_SCHEMA_V0);
    assert_eq!(metadata.dtype(), NpyDtypeV0::Float64);
    assert_eq!(metadata.shape().rows(), 4);
    assert_eq!(metadata.shape().columns(), 3);
    assert_eq!(metadata.requested_rows().first_row(), 1);
    assert_eq!(metadata.requested_rows().row_count(), 2);
    assert_eq!(metadata.observed_rows(), metadata.requested_rows());
    assert_eq!(metadata.completeness(), NpyWindowCompletenessV0::Complete);
    assert_eq!(metadata.counts().finite_components(), 5);
    assert_eq!(metadata.counts().nonfinite_components(), 1);
    assert_eq!(metadata.counts().zero_components(), 1);
    assert_component(
        metadata.aggregates().values().unwrap(),
        2,
        2,
        1,
        Some((-2.0f64).to_bits()),
        Some(1.0f64.to_bits()),
    );
    assert!(metadata.aggregates().real().is_none());
    assert_eq!(
        projection.read_audit().requested_byte_offset(),
        staged.data_offset + 3 * 8
    );
    assert_eq!(projection.read_audit().requested_bytes(), 2 * 3 * 8);
    assert_eq!(projection.read_audit().observed_bytes(), 2 * 3 * 8);
    assert_eq!(projection.read_audit().read_calls(), 1);
    assert_eq!(projection.read_audit().maximum_single_read_bytes(), 48);
}

#[test]
fn exact_c16_row_window_oracle_matches() {
    let minimum_subnormal = f64::from_bits(1);
    let components = [
        100.0,
        100.0,
        101.0,
        101.0,
        1.0,
        -1.0,
        0.0,
        -0.0,
        f64::INFINITY,
        f64::NAN,
        minimum_subnormal,
        -2.0,
    ];
    let staged = stage_npy(
        "{'descr': '<c16', 'fortran_order': False, 'shape': (3, 2), }",
        &f64_payload(&components),
    );

    let projection = project_npy_row_window(&staged.path, &options(1, 2)).unwrap();
    let metadata = projection.metadata();
    assert_eq!(metadata.dtype(), NpyDtypeV0::ComplexFloat64);
    assert_eq!(metadata.counts().finite_components(), 6);
    assert_eq!(metadata.counts().nonfinite_components(), 2);
    assert_eq!(metadata.counts().zero_components(), 2);
    assert_component(
        metadata.aggregates().real().unwrap(),
        2,
        0,
        1,
        Some(0.0f64.to_bits()),
        Some(1.0f64.to_bits()),
    );
    assert_component(
        metadata.aggregates().imaginary().unwrap(),
        0,
        2,
        0,
        Some((-2.0f64).to_bits()),
        Some((-0.0f64).to_bits()),
    );
    assert!(metadata.aggregates().values().is_none());
    assert_eq!(
        projection.read_audit().requested_byte_offset(),
        staged.data_offset + 2 * 16
    );
    assert_eq!(projection.read_audit().requested_bytes(), 2 * 2 * 16);
    assert_eq!(projection.read_audit().observed_bytes(), 2 * 2 * 16);
}

#[test]
fn adjacent_overlapping_and_truncated_windows_use_whole_rows() {
    let staged = stage_npy(
        "{'shape': (4, 2), 'fortran_order': False, 'descr': '<f8', }",
        &f64_payload(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0]),
    );

    let first = project_npy_row_window(&staged.path, &options(0, 2)).unwrap();
    let adjacent = project_npy_row_window(&staged.path, &options(2, 2)).unwrap();
    let overlapping = project_npy_row_window(&staged.path, &options(1, 2)).unwrap();
    let truncated = project_npy_row_window(&staged.path, &options(3, 3)).unwrap();

    assert_component(
        first.metadata().aggregates().values().unwrap(),
        4,
        0,
        0,
        Some(1.0f64.to_bits()),
        Some(4.0f64.to_bits()),
    );
    assert_component(
        adjacent.metadata().aggregates().values().unwrap(),
        4,
        0,
        0,
        Some(5.0f64.to_bits()),
        Some(8.0f64.to_bits()),
    );
    assert_component(
        overlapping.metadata().aggregates().values().unwrap(),
        4,
        0,
        0,
        Some(3.0f64.to_bits()),
        Some(6.0f64.to_bits()),
    );
    assert_eq!(
        truncated.metadata().completeness(),
        NpyWindowCompletenessV0::Truncated
    );
    assert_eq!(truncated.metadata().observed_rows().first_row(), 3);
    assert_eq!(truncated.metadata().observed_rows().row_count(), 1);
    assert_eq!(truncated.read_audit().requested_bytes(), 48);
    assert_eq!(truncated.read_audit().observed_bytes(), 16);
    assert_eq!(
        truncated.read_audit().requested_byte_offset(),
        staged.data_offset + 3 * 16
    );
}

#[test]
fn request_beyond_array_is_explicit_empty_truncation_without_payload_read() {
    let staged = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), }",
        &f64_payload(&[1.0]),
    );
    let projection = project_npy_row_window(&staged.path, &options(2, 1)).unwrap();

    assert_eq!(
        projection.metadata().completeness(),
        NpyWindowCompletenessV0::Truncated
    );
    assert_eq!(projection.metadata().observed_rows().row_count(), 0);
    assert_eq!(projection.read_audit().observed_bytes(), 0);
    assert_eq!(projection.read_audit().read_calls(), 0);
}

#[test]
fn exact_header_contract_rejects_malformed_and_unsupported_variants() {
    let cases = [
        (
            "{'descr': '>f8', 'fortran_order': False, 'shape': (1, 1), }",
            "unsupported dtype",
        ),
        (
            "{'descr': '<f8', 'fortran_order': True, 'shape': (1, 1), }",
            "fortran order",
        ),
        (
            "{'descr': '<f8', 'fortran_order': False, 'shape': (1,), }",
            "rank one",
        ),
        (
            "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1, 1), }",
            "rank three",
        ),
        (
            "{'descr': '<f8', 'fortran_order': False, 'shape': (0, 1), }",
            "zero extent",
        ),
        (
            "{'descr': '<f8', 'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), }",
            "duplicate key",
        ),
        (
            "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), 'labels': 1, }",
            "extra key",
        ),
        ("{'descr': '<f8', 'fortran_order': False, }", "missing key"),
        ("{'descr': '<f8', 'shape': (1, 1), }", "missing order"),
    ];

    for (dictionary, label) in cases {
        let staged = stage_npy(dictionary, &f64_payload(&[1.0]));
        assert!(
            project_npy_row_window(&staged.path, &NpyRowWindowOptions::default()).is_err(),
            "{label} must fail closed"
        );
    }

    let (mut version, _) = encode_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), }",
        &f64_payload(&[1.0]),
    );
    version[6] = 2;
    let staged = stage_raw(&version);
    assert!(matches!(
        project_npy_row_window(&staged.path, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::UnsupportedVersion)
    ));

    version[6] = 1;
    version[0] = 0;
    let staged = stage_raw(&version);
    assert!(matches!(
        project_npy_row_window(&staged.path, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::InvalidHeader)
    ));

    let staged = stage_raw(b"\x93NUMPY\x01\x00\x20");
    assert!(matches!(
        project_npy_row_window(&staged.path, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::TruncatedHeader)
    ));
}

#[test]
fn checked_shape_and_window_arithmetic_rejects_overflow() {
    let huge_rows = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (18446744073709551615, 2), }",
        &[],
    );
    assert!(matches!(
        project_npy_row_window(&huge_rows.path, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::ExtentOverflow)
    ));

    let huge_columns = stage_npy(
        "{'descr': '<c16', 'fortran_order': False, 'shape': (1, 18446744073709551615), }",
        &[],
    );
    assert!(matches!(
        project_npy_row_window(&huge_columns.path, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::ShapeOverflow)
    ));

    let valid = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 2), }",
        &f64_payload(&[1.0, 2.0]),
    );
    assert!(matches!(
        project_npy_row_window(&valid.path, &options(0, u64::MAX)),
        Err(NpyAdapterError::WindowLengthOverflow)
    ));
    assert!(matches!(
        project_npy_row_window(&valid.path, &options(u64::MAX, 1)),
        Err(NpyAdapterError::WindowOffsetOverflow)
    ));
}

#[test]
fn short_payload_and_trailing_bytes_are_extent_mismatches() {
    let (complete, expected_bytes) = encode_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 2), }",
        &f64_payload(&[1.0, 2.0]),
    );

    let short = stage_raw(&complete[..complete.len() - 1]);
    let error = project_npy_row_window(&short.path, &NpyRowWindowOptions::default()).unwrap_err();
    assert!(matches!(
        error,
        NpyAdapterError::ExtentMismatch {
            expected_bytes: expected,
            actual_bytes: actual,
        } if expected == expected_bytes + 16 && actual + 1 == expected
    ));

    let mut trailing_bytes = complete;
    trailing_bytes.push(0);
    let trailing = stage_raw(&trailing_bytes);
    let error =
        project_npy_row_window(&trailing.path, &NpyRowWindowOptions::default()).unwrap_err();
    assert!(matches!(
        error,
        NpyAdapterError::ExtentMismatch {
            expected_bytes: expected,
            actual_bytes: actual,
        } if expected == expected_bytes + 16 && actual == expected + 1
    ));
}

#[test]
fn bounds_and_nonregular_sources_fail_closed() {
    let staged = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (2, 2), }",
        &f64_payload(&[1.0, 2.0, 3.0, 4.0]),
    );
    let mut bounded = options(0, 2);
    bounded.max_window_bytes = 31;
    assert!(matches!(
        project_npy_row_window(&staged.path, &bounded),
        Err(NpyAdapterError::WindowTooLarge)
    ));

    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        project_npy_row_window(directory.path(), &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::SourceNotRegular)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_source_is_rejected() {
    use std::os::unix::fs::symlink;

    let staged = stage_npy(
        "{'descr': '<f8', 'fortran_order': False, 'shape': (1, 1), }",
        &f64_payload(&[1.0]),
    );
    let link = staged.path.with_file_name("link.npy");
    symlink(&staged.path, &link).unwrap();
    assert!(matches!(
        project_npy_row_window(&link, &NpyRowWindowOptions::default()),
        Err(NpyAdapterError::SourceSymlink)
    ));
}

#[test]
fn serialized_metadata_is_deterministic_and_policy_neutral() {
    let staged = stage_npy(
        "{'descr': '<c16', 'fortran_order': False, 'shape': (1, 1), }",
        &f64_payload(&[1.0, -1.0]),
    );
    let projection = project_npy_row_window(&staged.path, &NpyRowWindowOptions::default()).unwrap();

    let first = serde_json::to_string(projection.metadata()).unwrap();
    let second = serde_json::to_string(projection.metadata()).unwrap();
    assert_eq!(first, second);
    assert!(first.contains(NPY_ROW_WINDOW_METADATA_SCHEMA_V0));
    assert!(first.contains("\"dtype\":\"complex_float64\""));
    assert!(!first.contains("label"));
    assert!(!first.contains("policy"));
    assert!(!first.contains(staged.path.to_string_lossy().as_ref()));
}

proptest! {
    #[test]
    fn f8_full_window_aggregate_matches_naive_total_order(
        bits in prop::collection::vec(any::<u64>(), 1..32),
    ) {
        let values: Vec<f64> = bits.iter().copied().map(f64::from_bits).collect();
        let dictionary = format!(
            "{{'descr': '<f8', 'fortran_order': False, 'shape': (1, {}), }}",
            values.len()
        );
        let staged = stage_npy(&dictionary, &f64_payload(&values));
        let projection = project_npy_row_window(
            &staged.path,
            &NpyRowWindowOptions::default(),
        ).unwrap();

        let finite: Vec<f64> = values.iter().copied().filter(|value| value.is_finite()).collect();
        let positive = finite.iter().filter(|value| **value > 0.0).count() as u64;
        let negative = finite.iter().filter(|value| **value < 0.0).count() as u64;
        let subnormal = finite.iter().filter(|value| value.is_subnormal()).count() as u64;
        let minimum = finite.iter().copied().min_by(f64::total_cmp).map(f64::to_bits);
        let maximum = finite.iter().copied().max_by(f64::total_cmp).map(f64::to_bits);
        assert_component(
            projection.metadata().aggregates().values().unwrap(),
            positive,
            negative,
            subnormal,
            minimum,
            maximum,
        );
        prop_assert_eq!(
            projection.metadata().counts().finite_components(),
            finite.len() as u64
        );
        prop_assert_eq!(
            projection.metadata().counts().nonfinite_components(),
            (values.len() - finite.len()) as u64
        );
    }

    #[test]
    fn c16_full_window_components_match_naive_partition(
        pairs in prop::collection::vec((any::<u64>(), any::<u64>()), 1..24),
    ) {
        let values: Vec<f64> = pairs
            .iter()
            .flat_map(|(real, imaginary)| [f64::from_bits(*real), f64::from_bits(*imaginary)])
            .collect();
        let dictionary = format!(
            "{{'descr': '<c16', 'fortran_order': False, 'shape': (1, {}), }}",
            pairs.len()
        );
        let staged = stage_npy(&dictionary, &f64_payload(&values));
        let projection = project_npy_row_window(
            &staged.path,
            &NpyRowWindowOptions::default(),
        ).unwrap();
        let aggregates = projection.metadata().aggregates();

        for (component, actual) in [
            (pairs.iter().map(|pair| f64::from_bits(pair.0)).collect::<Vec<_>>(), aggregates.real().unwrap()),
            (pairs.iter().map(|pair| f64::from_bits(pair.1)).collect::<Vec<_>>(), aggregates.imaginary().unwrap()),
        ] {
            let finite: Vec<f64> = component.into_iter().filter(|value| value.is_finite()).collect();
            assert_component(
                actual,
                finite.iter().filter(|value| **value > 0.0).count() as u64,
                finite.iter().filter(|value| **value < 0.0).count() as u64,
                finite.iter().filter(|value| value.is_subnormal()).count() as u64,
                finite.iter().copied().min_by(f64::total_cmp).map(f64::to_bits),
                finite.iter().copied().max_by(f64::total_cmp).map(f64::to_bits),
            );
        }
    }
}
