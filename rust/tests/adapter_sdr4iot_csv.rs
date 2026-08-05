#![cfg(feature = "adapter-sdr4iot-csv")]

use std::fs;
use std::path::PathBuf;

use netbraid::adapters::sdr4iot_csv::{
    project_sdr4iot_csv, Sdr4iotCsvAdapterError, Sdr4iotCsvOptions, Sdr4iotCsvSchemaVariantV0,
    SDR4IOT_DETECTION_STREAM_SCHEMA_V0,
};

const BASE_HEADER: &str = "Time,Start_trame,End_trame,Channel_frequency,Sample_rate";
const NODE_HEADER: &str = "Time,Start_trame,End_trame,Channel_frequency,Sample_rate,Robot_node,X,Y";
const POSE_HEADER: &str =
    "Time,Robot_Number,X,Y,Angle,Start_trame,End_trame,Central Frequency,Sample_rate";

struct StagedCsv {
    _directory: tempfile::TempDir,
    path: PathBuf,
    bytes: Vec<u8>,
}

fn stage(contents: &str) -> StagedCsv {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("detections.csv");
    let bytes = contents.as_bytes().to_vec();
    fs::write(&path, &bytes).unwrap();
    StagedCsv {
        _directory: directory,
        path,
        bytes,
    }
}

fn project(
    contents: &str,
) -> Result<netbraid::adapters::sdr4iot_csv::Sdr4iotDetectionStreamV0, Sdr4iotCsvAdapterError> {
    let staged = stage(contents);
    project_sdr4iot_csv(&staged.path, &Sdr4iotCsvOptions::default())
}

fn base_row(timestamp: &str, start: &str, end: &str, frequency: &str, rate: &str) -> String {
    format!("{timestamp},{start},{end},{frequency},{rate}")
}

#[test]
fn exact_two_row_oracle_preserves_order_and_content_provenance() {
    let contents = format!(
        "{BASE_HEADER}\n{}\n{}\n",
        base_row(
            "2020-01-02 03:04:05.123456",
            "20",
            "22",
            "2426000000",
            "5000000"
        ),
        base_row(
            "1969-12-31 23:59:59.999999",
            "22",
            "23",
            "915000000.5",
            "1000000.25"
        )
    );
    let staged = stage(&contents);
    let stream = project_sdr4iot_csv(&staged.path, &Sdr4iotCsvOptions::default()).unwrap();

    assert_eq!(stream.schema(), SDR4IOT_DETECTION_STREAM_SCHEMA_V0);
    assert_eq!(stream.schema_variant(), Sdr4iotCsvSchemaVariantV0::Base5);
    assert_eq!(stream.source_byte_extent().start_byte(), 0);
    assert_eq!(
        stream.source_byte_extent().end_byte(),
        u64::try_from(staged.bytes.len()).unwrap()
    );
    assert_eq!(
        stream.source_sha256(),
        "sha256:9d1bce7d38026d624ce44497dde539e11745286f92c93bbc5fd86384704de71f"
    );
    assert_eq!(stream.detections().len(), 2);
    let first = &stream.detections()[0];
    assert_eq!(first.publisher_timestamp_us(), 1_577_934_245_123_456);
    assert_eq!(first.sample_start(), 20);
    assert_eq!(first.sample_end(), 22);
    assert_eq!(first.center_frequency_hz(), 2_426_000_000.0);
    assert_eq!(first.sample_rate_hz(), 5_000_000.0);
    let second = &stream.detections()[1];
    assert_eq!(second.publisher_timestamp_us(), -1);
    assert_eq!(second.sample_start(), 22);
    assert_eq!(second.sample_end(), 23);
    assert_eq!(second.center_frequency_hz(), 915_000_000.5);
    assert_eq!(second.sample_rate_hz(), 1_000_000.25);
}

#[test]
fn all_three_registered_headers_select_an_exact_variant() {
    let cases = [
        (
            format!(
                "{BASE_HEADER}\n{}\n",
                base_row(
                    "2020-01-02 03:04:05.000000",
                    "1",
                    "2",
                    "2426000000",
                    "5000000"
                )
            ),
            Sdr4iotCsvSchemaVariantV0::Base5,
        ),
        (
            format!(
                "{NODE_HEADER}\n2020-01-02 03:04:05.000000,1,2,2426000000,5000000,73,5429,454\n"
            ),
            Sdr4iotCsvSchemaVariantV0::Node8,
        ),
        (
            format!(
                "{POSE_HEADER}\n2020-01-02 03:04:05.000000,73,5429,454,-90,1,2,2426000000,5000000\n"
            ),
            Sdr4iotCsvSchemaVariantV0::Pose9,
        ),
    ];

    for (contents, expected) in cases {
        let stream = project(&contents).unwrap();
        assert_eq!(stream.schema_variant(), expected);
        assert_eq!(stream.detections().len(), 1);
    }
}

#[test]
fn serialized_evidence_omits_auxiliary_values_and_source_location() {
    let contents = format!(
        "{NODE_HEADER}\n2020-01-02 03:04:05.000000,1,2,2426000000,5000000,987654321,5429,454\n"
    );
    let staged = stage(&contents);
    let stream = project_sdr4iot_csv(&staged.path, &Sdr4iotCsvOptions::default()).unwrap();
    let rendered = serde_json::to_string(&stream).unwrap();

    for forbidden in [
        "987654321",
        "5429",
        "454",
        "Robot_node",
        "coordinates",
        "angle",
        "filename",
        "path",
        staged.path.to_string_lossy().as_ref(),
    ] {
        assert!(
            !rendered.contains(forbidden),
            "serialized evidence leaked {forbidden}"
        );
    }
}

#[test]
fn malformed_timestamps_fail_closed() {
    for timestamp in [
        "2020-01-02T03:04:05.000000",
        "2020-02-30 03:04:05.000000",
        "2020-01-02 24:04:05.000000",
        "2020-01-02 03:04:05.00000",
    ] {
        let contents = format!(
            "{BASE_HEADER}\n{}\n",
            base_row(timestamp, "1", "2", "2426000000", "5000000")
        );
        assert!(matches!(
            project(&contents),
            Err(Sdr4iotCsvAdapterError::InvalidTimestamp { row: 1 })
        ));
    }
}

#[test]
fn negative_empty_and_reversed_sample_extents_fail_closed() {
    for (start, end) in [("-1", "2"), ("2", "2"), ("3", "2"), ("+1", "2")] {
        let contents = format!(
            "{BASE_HEADER}\n{}\n",
            base_row(
                "2020-01-02 03:04:05.000000",
                start,
                end,
                "2426000000",
                "5000000"
            )
        );
        assert!(matches!(
            project(&contents),
            Err(Sdr4iotCsvAdapterError::InvalidSampleExtent { row: 1 })
        ));
    }
}

#[test]
fn nonpositive_nonfinite_and_overbound_quantities_fail_closed() {
    for frequency in ["0", "-1", "NaN", "inf", "1000000000001"] {
        let contents = format!(
            "{BASE_HEADER}\n{}\n",
            base_row("2020-01-02 03:04:05.000000", "1", "2", frequency, "5000000")
        );
        assert!(matches!(
            project(&contents),
            Err(Sdr4iotCsvAdapterError::InvalidCenterFrequency { row: 1 })
        ));
    }
    for rate in ["0", "-1", "NaN", "inf", "1000000000001"] {
        let contents = format!(
            "{BASE_HEADER}\n{}\n",
            base_row("2020-01-02 03:04:05.000000", "1", "2", "2426000000", rate)
        );
        assert!(matches!(
            project(&contents),
            Err(Sdr4iotCsvAdapterError::InvalidSampleRate { row: 1 })
        ));
    }
}

#[test]
fn field_source_and_row_bounds_refuse_partial_output() {
    let oversized_field = "1".repeat(257);
    let contents = format!(
        "{BASE_HEADER}\n{}\n",
        base_row(&oversized_field, "1", "2", "2426000000", "5000000")
    );
    assert!(matches!(
        project(&contents),
        Err(Sdr4iotCsvAdapterError::FieldSizeLimit { row: 1 })
    ));

    let contents = format!("{BASE_HEADER}\n");
    let staged = stage(&contents);
    let mut byte_bounded = Sdr4iotCsvOptions::default();
    byte_bounded.max_bytes = u64::try_from(staged.bytes.len() - 1).unwrap();
    assert!(matches!(
        project_sdr4iot_csv(&staged.path, &byte_bounded),
        Err(Sdr4iotCsvAdapterError::ByteLimitExceeded)
    ));

    let contents = format!(
        "{BASE_HEADER}\n{}\n{}\n",
        base_row(
            "2020-01-02 03:04:05.000000",
            "1",
            "2",
            "2426000000",
            "5000000"
        ),
        base_row(
            "2020-01-02 03:04:06.000000",
            "2",
            "3",
            "2426000000",
            "5000000"
        )
    );
    let staged = stage(&contents);
    let mut row_bounded = Sdr4iotCsvOptions::default();
    row_bounded.max_rows = 1;
    assert!(matches!(
        project_sdr4iot_csv(&staged.path, &row_bounded),
        Err(Sdr4iotCsvAdapterError::RowLimitExceeded)
    ));
}

#[test]
fn duplicate_or_drifted_headers_and_malformed_rows_are_rejected() {
    let duplicate = "Time,Start_trame,End_trame,Channel_frequency,Sample_rate,Time\n";
    assert!(matches!(
        project(duplicate),
        Err(Sdr4iotCsvAdapterError::DuplicateHeader)
    ));

    let drifted = "time,Start_trame,End_trame,Channel_frequency,Sample_rate\n";
    assert!(matches!(
        project(drifted),
        Err(Sdr4iotCsvAdapterError::SchemaMismatch)
    ));

    let repeated = format!("{BASE_HEADER}\n{BASE_HEADER}\n");
    assert!(matches!(
        project(&repeated),
        Err(Sdr4iotCsvAdapterError::InvalidSampleExtent { row: 1 })
    ));

    let short = format!("{BASE_HEADER}\n2020-01-02 03:04:05.000000,1\n");
    assert!(matches!(
        project(&short),
        Err(Sdr4iotCsvAdapterError::InvalidRow { row: 1 })
    ));
}

#[test]
fn invalid_auxiliary_fields_are_validated_but_not_retained() {
    let contents = format!(
        "{NODE_HEADER}\n2020-01-02 03:04:05.000000,1,2,2426000000,5000000,not-an-integer,5429,454\n"
    );
    assert!(matches!(
        project(&contents),
        Err(Sdr4iotCsvAdapterError::InvalidAuxiliaryField { row: 1 })
    ));
}

#[test]
fn invalid_options_and_nonregular_sources_fail_before_parsing() {
    let staged = stage(&format!("{BASE_HEADER}\n"));
    let mut options = Sdr4iotCsvOptions::default();
    options.max_rows = 0;
    assert!(matches!(
        project_sdr4iot_csv(&staged.path, &options),
        Err(Sdr4iotCsvAdapterError::InvalidOption("max_rows"))
    ));

    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        project_sdr4iot_csv(directory.path(), &Sdr4iotCsvOptions::default()),
        Err(Sdr4iotCsvAdapterError::SourceNotRegular)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_source_is_rejected() {
    use std::os::unix::fs::symlink;

    let staged = stage(&format!("{BASE_HEADER}\n"));
    let link = staged.path.with_file_name("linked.csv");
    symlink(&staged.path, &link).unwrap();
    assert!(matches!(
        project_sdr4iot_csv(&link, &Sdr4iotCsvOptions::default()),
        Err(Sdr4iotCsvAdapterError::SourceSymlink)
    ));
}
