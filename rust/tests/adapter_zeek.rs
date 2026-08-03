#![cfg(feature = "adapter-zeek")]

use std::fs;
use std::path::PathBuf;

use netbraid::adapters::zeek::{
    project_zeek_conn_log, ZeekAdapterError, ZeekConnOptions, ZeekConnProtocolV0,
    ZEEK_CONN_STREAM_SCHEMA_V0,
};
use tempfile::TempDir;

const REQUIRED_FIELDS: &[&str] = &[
    "ts",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "duration",
    "orig_pkts",
    "orig_ip_bytes",
    "resp_pkts",
    "resp_ip_bytes",
];
const REQUIRED_TYPES: &[&str] = &[
    "time", "addr", "port", "addr", "port", "enum", "interval", "count", "count", "count", "count",
];

struct StagedLog {
    _directory: TempDir,
    path: PathBuf,
}

fn zeek_log(fields: &[&str], types: &[&str], rows: &[String]) -> String {
    let rows = if rows.is_empty() {
        String::new()
    } else {
        format!("{}\n", rows.join("\n"))
    };
    format!(
        "#separator \\x09\n\
         #set_separator\t,\n\
         #empty_field\t(empty)\n\
         #unset_field\t-\n\
         #path\tconn\n\
         #open\t2026-08-03-00-00-00\n\
         #fields\t{}\n\
         #types\t{}\n\
         {}\
         #close\t2026-08-03-00-00-01\n",
        fields.join("\t"),
        types.join("\t"),
        rows
    )
}

#[allow(clippy::too_many_arguments)]
fn row(
    ts: &str,
    originator: &str,
    orig_port: &str,
    responder: &str,
    resp_port: &str,
    protocol: &str,
    duration: &str,
    counters: [&str; 4],
) -> String {
    [
        ts,
        originator,
        orig_port,
        responder,
        resp_port,
        protocol,
        duration,
        counters[0],
        counters[1],
        counters[2],
        counters[3],
    ]
    .join("\t")
}

fn stage(contents: &str) -> StagedLog {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("conn.log");
    fs::write(&path, contents).unwrap();
    StagedLog {
        _directory: directory,
        path,
    }
}

fn project(contents: &str) -> Result<netbraid::adapters::zeek::ZeekConnStreamV0, ZeekAdapterError> {
    let staged = stage(contents);
    project_zeek_conn_log(&staged.path, &ZeekConnOptions::default())
}

#[test]
fn exact_ipv4_ipv6_and_optional_duration_oracle_matches() {
    let fields = [
        "ts",
        "uid",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "service",
        "duration",
        "history",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
        "label",
        "future_field",
    ];
    let types = [
        "time", "string", "addr", "port", "addr", "port", "enum", "string", "interval", "string",
        "count", "count", "count", "count", "string", "string",
    ];
    let rows = [
        [
            "1700000001.250000000",
            "PRIVATE_UID_V4",
            "192.0.2.10",
            "40000",
            "198.51.100.20",
            "443",
            "tcp",
            "PRIVATE_SERVICE",
            "0.125000001",
            "PRIVATE_HISTORY",
            "2",
            "120",
            "3",
            "240",
            "PRIVATE_LABEL",
            "PRIVATE_UNKNOWN",
        ]
        .join("\t"),
        [
            "1700000000.000000009",
            "PRIVATE_UID_V6",
            "2001:db8::10",
            "5353",
            "2001:db8::20",
            "53",
            "udp",
            "-",
            "-",
            "-",
            "1",
            "48",
            "0",
            "0",
            "PRIVATE_LABEL_V6",
            "PRIVATE_UNKNOWN_V6",
        ]
        .join("\t"),
    ];
    let stream = project(&zeek_log(&fields, &types, &rows)).unwrap();

    assert_eq!(stream.schema(), ZEEK_CONN_STREAM_SCHEMA_V0);
    assert_eq!(stream.connections().len(), 2);
    let ipv6 = &stream.connections()[0];
    assert_eq!(ipv6.start_time_unix_ns(), 1_700_000_000_000_000_009);
    assert_eq!(ipv6.originator().address().to_string(), "2001:db8::10");
    assert_eq!(ipv6.originator().port(), 5353);
    assert_eq!(ipv6.responder().address().to_string(), "2001:db8::20");
    assert_eq!(ipv6.responder().port(), 53);
    assert_eq!(ipv6.protocol(), ZeekConnProtocolV0::Udp);
    assert_eq!(ipv6.duration_ns(), None);
    assert_eq!(ipv6.orig_packets(), Some(1));
    assert_eq!(ipv6.orig_ip_bytes(), Some(48));
    assert_eq!(ipv6.resp_packets(), Some(0));
    assert_eq!(ipv6.resp_ip_bytes(), Some(0));

    let ipv4 = &stream.connections()[1];
    assert_eq!(ipv4.start_time_unix_ns(), 1_700_000_001_250_000_000);
    assert_eq!(ipv4.originator().address().to_string(), "192.0.2.10");
    assert_eq!(ipv4.responder().address().to_string(), "198.51.100.20");
    assert_eq!(ipv4.protocol(), ZeekConnProtocolV0::Tcp);
    assert_eq!(ipv4.duration_ns(), Some(125_000_001));
    assert_eq!(ipv4.orig_packets(), Some(2));
    assert_eq!(ipv4.orig_ip_bytes(), Some(120));
    assert_eq!(ipv4.resp_packets(), Some(3));
    assert_eq!(ipv4.resp_ip_bytes(), Some(240));
}

#[test]
fn reordered_required_and_extra_fields_are_projected_by_declared_name() {
    let fields = [
        "future",
        "resp_ip_bytes",
        "id.resp_p",
        "duration",
        "id.orig_h",
        "orig_pkts",
        "proto",
        "ts",
        "id.resp_h",
        "orig_ip_bytes",
        "id.orig_p",
        "resp_pkts",
        "uid",
    ];
    let types = [
        "vector[string]",
        "count",
        "port",
        "interval",
        "addr",
        "count",
        "enum",
        "time",
        "addr",
        "count",
        "port",
        "count",
        "string",
    ];
    let rows = vec![[
        "PRIVATE_FUTURE",
        "88",
        "22",
        "1.000000001",
        "203.0.113.9",
        "4",
        "tcp",
        "2.5",
        "203.0.113.10",
        "77",
        "1234",
        "5",
        "PRIVATE_UID",
    ]
    .join("\t")];
    let stream = project(&zeek_log(&fields, &types, &rows)).unwrap();
    let connection = &stream.connections()[0];

    assert_eq!(connection.start_time_unix_ns(), 2_500_000_000);
    assert_eq!(connection.originator().address().to_string(), "203.0.113.9");
    assert_eq!(connection.originator().port(), 1234);
    assert_eq!(connection.responder().address().to_string(), "203.0.113.10");
    assert_eq!(connection.responder().port(), 22);
    assert_eq!(connection.duration_ns(), Some(1_000_000_001));
    assert_eq!(connection.orig_packets(), Some(4));
    assert_eq!(connection.orig_ip_bytes(), Some(77));
    assert_eq!(connection.resp_packets(), Some(5));
    assert_eq!(connection.resp_ip_bytes(), Some(88));
}

#[test]
fn unset_optional_counters_remain_unavailable() {
    let unavailable = row(
        "1",
        "192.0.2.1",
        "1",
        "192.0.2.2",
        "2",
        "tcp",
        "-",
        ["-", "-", "-", "-"],
    );
    let stream = project(&zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &[unavailable])).unwrap();
    let connection = &stream.connections()[0];

    assert_eq!(connection.duration_ns(), None);
    assert_eq!(connection.orig_packets(), None);
    assert_eq!(connection.orig_ip_bytes(), None);
    assert_eq!(connection.resp_packets(), None);
    assert_eq!(connection.resp_ip_bytes(), None);
}

#[test]
fn documented_unknown_transport_and_utf8_in_discarded_columns_are_supported() {
    let fields = [
        "note",
        "ts",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "duration",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
    ];
    let types = [
        "string", "time", "addr", "port", "addr", "port", "enum", "interval", "count", "count",
        "count", "count",
    ];
    let rows = vec![[
        "discarded café",
        "1.000000001",
        "192.0.2.1",
        "0",
        "198.51.100.2",
        "0",
        "unknown_transport",
        "0",
        "1",
        "40",
        "0",
        "0",
    ]
    .join("\t")];

    let stream = project(&zeek_log(&fields, &types, &rows)).unwrap();
    assert_eq!(
        stream.connections()[0].protocol(),
        ZeekConnProtocolV0::UnknownTransport
    );
    assert!(!serde_json::to_string(&stream).unwrap().contains("café"));
}

#[test]
fn malformed_directives_fields_and_types_fail_closed() {
    let valid_row = row(
        "1",
        "192.0.2.1",
        "1",
        "192.0.2.2",
        "2",
        "tcp",
        "0",
        ["1", "40", "1", "40"],
    );
    let valid = zeek_log(
        REQUIRED_FIELDS,
        REQUIRED_TYPES,
        std::slice::from_ref(&valid_row),
    );
    let cases = [
        valid.replace("#separator \\x09", "#separator tab"),
        valid.replace("#set_separator\t,", "#set_separator\t\t"),
        valid.replace("#empty_field\t(empty)", "#empty_field\t-"),
        valid.replace("#path\tconn", "#path\tdns"),
        valid.replace("#separator \\x09", "!separator \\x09"),
        valid.replace("#open\t2026-08-03-00-00-00", "#rotate\t2026-08-03-00-00-00"),
        valid.replace("#close\t2026-08-03-00-00-01", "#close\tyesterday"),
        valid.replace("\tinterval\tcount", "\tdouble\tcount"),
    ];
    for contents in cases {
        assert!(project(&contents).is_err(), "malformed metadata must fail");
    }

    let mut duplicate_fields = REQUIRED_FIELDS.to_vec();
    duplicate_fields.push("orig_pkts");
    let mut duplicate_types = REQUIRED_TYPES.to_vec();
    duplicate_types.push("count");
    let duplicate_row = format!("{valid_row}\t1");
    assert!(matches!(
        project(&zeek_log(
            &duplicate_fields,
            &duplicate_types,
            &[duplicate_row]
        )),
        Err(ZeekAdapterError::DuplicateField)
    ));

    let fields_without_packets: Vec<_> = REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|field| *field != "orig_pkts")
        .collect();
    let types_without_packets: Vec<_> = REQUIRED_FIELDS
        .iter()
        .zip(REQUIRED_TYPES)
        .filter_map(|(field, field_type)| (*field != "orig_pkts").then_some(*field_type))
        .collect();
    assert!(matches!(
        project(&zeek_log(
            &fields_without_packets,
            &types_without_packets,
            &[]
        )),
        Err(ZeekAdapterError::MissingField("orig_pkts"))
    ));
}

#[test]
fn declared_field_count_is_bounded_before_row_parsing() {
    let mut fields = REQUIRED_FIELDS.to_vec();
    let mut types = REQUIRED_TYPES.to_vec();
    for _ in fields.len()..257 {
        fields.push("extra");
        types.push("string");
    }

    assert!(matches!(
        project(&zeek_log(&fields, &types, &[])),
        Err(ZeekAdapterError::MalformedDirective("#fields"))
    ));
}

#[test]
fn malformed_negative_nonfinite_and_overflow_values_fail_closed() {
    let valid = row(
        "1",
        "192.0.2.1",
        "1",
        "192.0.2.2",
        "2",
        "tcp",
        "0.1",
        ["1", "40", "1", "40"],
    );
    let invalid_rows = [
        row(
            "-1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "NaN",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "-1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "inf",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["-1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["18446744073709551616", "40", "1", "40"],
        ),
        row(
            "9223372037",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "18446744074",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "65536",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "sctp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "-",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0.1",
            ["1", "40", "1", "40"],
        ),
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "(empty)",
            ["1", "40", "1", "40"],
        ),
    ];
    assert!(project(&zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &[valid])).is_ok());
    for invalid in invalid_rows {
        assert!(
            matches!(
                project(&zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &[invalid])),
                Err(ZeekAdapterError::InvalidValue { .. })
            ),
            "invalid row must fail without retaining its value"
        );
    }

    let malformed_count = row(
        "1",
        "192.0.2.1",
        "1",
        "192.0.2.2",
        "2",
        "tcp",
        "0.1",
        ["1.0", "40", "1", "40"],
    );
    assert!(matches!(
        project(&zeek_log(
            REQUIRED_FIELDS,
            REQUIRED_TYPES,
            &[malformed_count]
        )),
        Err(ZeekAdapterError::InvalidValue {
            field: "orig_pkts",
            ..
        })
    ));
}

#[test]
fn byte_and_row_bounds_are_enforced_without_partial_output() {
    let rows = [
        row(
            "1",
            "192.0.2.1",
            "1",
            "192.0.2.2",
            "2",
            "tcp",
            "0",
            ["1", "40", "1", "40"],
        ),
        row(
            "2",
            "192.0.2.3",
            "3",
            "192.0.2.4",
            "4",
            "udp",
            "-",
            ["2", "80", "2", "80"],
        ),
    ];
    let contents = zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &rows);
    let staged = stage(&contents);

    let mut byte_bounded = ZeekConnOptions::default();
    byte_bounded.max_bytes = u64::try_from(contents.len() - 1).unwrap();
    assert!(matches!(
        project_zeek_conn_log(&staged.path, &byte_bounded),
        Err(ZeekAdapterError::ByteLimitExceeded)
    ));

    let mut row_bounded = ZeekConnOptions::default();
    row_bounded.max_rows = 1;
    assert!(matches!(
        project_zeek_conn_log(&staged.path, &row_bounded),
        Err(ZeekAdapterError::RowLimitExceeded)
    ));

    let mut invalid = ZeekConnOptions::default();
    invalid.max_rows = 0;
    assert!(matches!(
        project_zeek_conn_log(&staged.path, &invalid),
        Err(ZeekAdapterError::InvalidOption("max_rows"))
    ));
}

#[test]
fn nonregular_source_is_rejected() {
    let directory = tempfile::tempdir().unwrap();
    assert!(matches!(
        project_zeek_conn_log(directory.path(), &ZeekConnOptions::default()),
        Err(ZeekAdapterError::SourceNotRegular)
    ));
}

#[cfg(unix)]
#[test]
fn symlink_source_is_rejected() {
    use std::os::unix::fs::symlink;

    let contents = zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &[]);
    let staged = stage(&contents);
    let link = staged.path.with_file_name("linked.log");
    symlink(&staged.path, &link).unwrap();
    assert!(matches!(
        project_zeek_conn_log(&link, &ZeekConnOptions::default()),
        Err(ZeekAdapterError::SourceSymlink)
    ));
}

#[test]
fn semantic_sorting_is_independent_of_source_order() {
    let first = row(
        "2",
        "192.0.2.3",
        "3000",
        "192.0.2.4",
        "4000",
        "udp",
        "-",
        ["2", "80", "3", "120"],
    );
    let second = row(
        "1",
        "192.0.2.1",
        "1000",
        "192.0.2.2",
        "2000",
        "tcp",
        "0.5",
        ["1", "40", "1", "40"],
    );
    let forward = project(&zeek_log(
        REQUIRED_FIELDS,
        REQUIRED_TYPES,
        &[first.clone(), second.clone()],
    ))
    .unwrap();
    let reverse = project(&zeek_log(REQUIRED_FIELDS, REQUIRED_TYPES, &[second, first])).unwrap();

    assert_eq!(forward, reverse);
    assert_eq!(
        serde_json::to_string(&forward).unwrap(),
        serde_json::to_string(&reverse).unwrap()
    );
    assert_eq!(forward.connections()[0].start_time_unix_ns(), 1_000_000_000);
}

#[test]
fn serialized_output_excludes_sensitive_columns_unknown_values_and_paths() {
    let fields = [
        "uid",
        "service",
        "history",
        "label",
        "unknown_future",
        "ts",
        "id.orig_h",
        "id.orig_p",
        "id.resp_h",
        "id.resp_p",
        "proto",
        "duration",
        "orig_pkts",
        "orig_ip_bytes",
        "resp_pkts",
        "resp_ip_bytes",
    ];
    let types = [
        "string", "string", "string", "string", "string", "time", "addr", "port", "addr", "port",
        "enum", "interval", "count", "count", "count", "count",
    ];
    let rows = vec![[
        "PRIVATE_UID",
        "PRIVATE_SERVICE",
        "PRIVATE_HISTORY",
        "PRIVATE_LABEL",
        "PRIVATE_UNKNOWN_VALUE",
        "1",
        "192.0.2.1",
        "1",
        "192.0.2.2",
        "2",
        "tcp",
        "0",
        "1",
        "40",
        "1",
        "40",
    ]
    .join("\t")];
    let staged = stage(&zeek_log(&fields, &types, &rows));
    let stream = project_zeek_conn_log(&staged.path, &ZeekConnOptions::default()).unwrap();
    let rendered = serde_json::to_string(&stream).unwrap();

    for forbidden in [
        "PRIVATE_UID",
        "PRIVATE_SERVICE",
        "PRIVATE_HISTORY",
        "PRIVATE_LABEL",
        "PRIVATE_UNKNOWN_VALUE",
        "\"uid\"",
        "\"service\"",
        "\"history\"",
        "\"label\"",
        "unknown_future",
        staged.path.to_string_lossy().as_ref(),
    ] {
        assert!(
            !rendered.contains(forbidden),
            "serialized output leaked {forbidden}"
        );
    }
    assert_eq!(rendered, serde_json::to_string(&stream).unwrap());
}
