use std::ffi::OsString;
use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use netbraid::adapters::zeek::{
    project_zeek_conn_log, ZeekConnOptions, ZeekConnProtocolV0, ZeekConnStreamV0,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

const PROFILE_SCHEMA: &str = "netbraid.zeek_conn_adapter_profile.v0";

#[derive(Debug)]
struct Arguments {
    input: PathBuf,
    options: ZeekConnOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunError {
    Arguments,
    Projection,
    Profile,
    Output,
}

impl RunError {
    const fn exit_code(self) -> u8 {
        match self {
            Self::Arguments => 2,
            Self::Projection => 3,
            Self::Profile => 4,
            Self::Output => 5,
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::Arguments => "error: invalid arguments",
            Self::Projection => "error: Zeek projection failed",
            Self::Profile => "error: profile encoding failed",
            Self::Output => "error: output failed",
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct ProtocolCounts {
    icmp: u64,
    tcp: u64,
    udp: u64,
    unknown_transport: u64,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
struct MissingCounterCounts {
    orig_ip_bytes: u64,
    orig_packets: u64,
    resp_ip_bytes: u64,
    resp_packets: u64,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
struct AdapterProfileV0 {
    schema: &'static str,
    connection_count: u64,
    protocol_counts: ProtocolCounts,
    missing_duration_count: u64,
    missing_counter_counts: MissingCounterCounts,
    projection_sha256: String,
}

fn parse_limit(value: OsString) -> Result<u64, RunError> {
    let value = value.to_str().ok_or(RunError::Arguments)?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RunError::Arguments);
    }
    value.parse().map_err(|_| RunError::Arguments)
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<Arguments, RunError> {
    let mut input = None;
    let mut max_bytes = None;
    let mut max_rows = None;
    let mut args = args.into_iter();

    while let Some(argument) = args.next() {
        match argument.to_str() {
            Some("--max-bytes") => {
                if max_bytes.is_some() {
                    return Err(RunError::Arguments);
                }
                max_bytes = Some(parse_limit(args.next().ok_or(RunError::Arguments)?)?);
            }
            Some("--max-rows") => {
                if max_rows.is_some() {
                    return Err(RunError::Arguments);
                }
                max_rows = Some(parse_limit(args.next().ok_or(RunError::Arguments)?)?);
            }
            Some(value) if value.starts_with('-') => return Err(RunError::Arguments),
            _ if input.is_none() => input = Some(PathBuf::from(argument)),
            _ => return Err(RunError::Arguments),
        }
    }

    let mut options = ZeekConnOptions::default();
    if let Some(value) = max_bytes {
        options.max_bytes = value;
    }
    if let Some(value) = max_rows {
        options.max_rows = value;
    }

    Ok(Arguments {
        input: input.ok_or(RunError::Arguments)?,
        options,
    })
}

fn build_profile(stream: &ZeekConnStreamV0) -> Result<AdapterProfileV0, RunError> {
    let projection_bytes = serde_json::to_vec(stream).map_err(|_| RunError::Profile)?;
    let mut protocol_counts = ProtocolCounts::default();
    let mut missing_duration_count = 0;
    let mut missing_counter_counts = MissingCounterCounts::default();

    for connection in stream.connections() {
        match connection.protocol() {
            ZeekConnProtocolV0::Icmp => protocol_counts.icmp += 1,
            ZeekConnProtocolV0::Tcp => protocol_counts.tcp += 1,
            ZeekConnProtocolV0::Udp => protocol_counts.udp += 1,
            ZeekConnProtocolV0::UnknownTransport => protocol_counts.unknown_transport += 1,
            _ => return Err(RunError::Profile),
        }
        missing_duration_count += u64::from(connection.duration_ns().is_none());
        missing_counter_counts.orig_ip_bytes += u64::from(connection.orig_ip_bytes().is_none());
        missing_counter_counts.orig_packets += u64::from(connection.orig_packets().is_none());
        missing_counter_counts.resp_ip_bytes += u64::from(connection.resp_ip_bytes().is_none());
        missing_counter_counts.resp_packets += u64::from(connection.resp_packets().is_none());
    }

    Ok(AdapterProfileV0 {
        schema: PROFILE_SCHEMA,
        connection_count: u64::try_from(stream.connections().len())
            .map_err(|_| RunError::Profile)?,
        protocol_counts,
        missing_duration_count,
        missing_counter_counts,
        projection_sha256: format!("{:x}", Sha256::digest(projection_bytes)),
    })
}

fn run(args: impl IntoIterator<Item = OsString>, mut writer: impl Write) -> Result<(), RunError> {
    let arguments = parse_args(args)?;
    let stream = project_zeek_conn_log(&arguments.input, &arguments.options)
        .map_err(|_| RunError::Projection)?;
    let profile = build_profile(&stream)?;
    let mut output = serde_json::to_vec(&profile).map_err(|_| RunError::Profile)?;
    output.push(b'\n');
    writer.write_all(&output).map_err(|_| RunError::Output)?;
    writer.flush().map_err(|_| RunError::Output)
}

fn main() -> ExitCode {
    match run(std::env::args_os().skip(1), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error.message());
            ExitCode::from(error.exit_code())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    struct StagedLog {
        _directory: TempDir,
        path: PathBuf,
    }

    fn stage_log() -> StagedLog {
        let contents = "#separator \\x09\n\
#set_separator\t,\n\
#empty_field\t(empty)\n\
#unset_field\t-\n\
#path\tconn\n\
#open\t2026-08-03-00-00-00\n\
#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\n\
#types\ttime\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tcount\tcount\n\
1700000000.000000001\t192.0.2.1\t40000\t198.51.100.2\t443\ttcp\t1.25\t1\t40\t-\t-\n\
1700000001.000000002\t203.0.113.3\t5353\t192.0.2.4\t53\tudp\t-\t2\t80\t3\t120\n\
1700000002.000000003\t2001:db8::5\t8\t2001:db8::6\t0\ticmp\t0\t-\t64\t1\t64\n\
1700000003.000000004\t192.0.2.7\t9\t198.51.100.8\t9\tunknown_transport\t-\t-\t-\t-\t-\n\
#close\t2026-08-03-00-00-01\n";
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("conn.log");
        fs::write(&path, contents).unwrap();
        StagedLog {
            _directory: directory,
            path,
        }
    }

    fn os_args(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parses_exact_input_and_optional_numeric_bounds() {
        let arguments = parse_args(os_args(&[
            "conn.log",
            "--max-rows",
            "42",
            "--max-bytes",
            "4096",
        ]))
        .unwrap();

        assert_eq!(arguments.input, PathBuf::from("conn.log"));
        assert_eq!(arguments.options.max_rows, 42);
        assert_eq!(arguments.options.max_bytes, 4096);
    }

    #[test]
    fn rejects_missing_extra_unknown_duplicate_and_non_numeric_arguments() {
        for arguments in [
            os_args(&[]),
            os_args(&["one.log", "two.log"]),
            os_args(&["--unknown", "one.log"]),
            os_args(&["one.log", "--max-rows"]),
            os_args(&["one.log", "--max-rows", "ten"]),
            os_args(&["one.log", "--max-bytes", "1", "--max-bytes", "2"]),
        ] {
            assert_eq!(parse_args(arguments).unwrap_err(), RunError::Arguments);
        }
    }

    #[test]
    fn emits_the_exact_aggregate_shape_and_trailing_newline() {
        let staged = stage_log();
        let mut output = Vec::new();

        run([staged.path.into_os_string()], &mut output).unwrap();

        assert_eq!(output.last(), Some(&b'\n'));
        let rendered = std::str::from_utf8(&output).unwrap().trim_end();
        let value: serde_json::Value = serde_json::from_str(rendered).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 6);
        assert_eq!(value["schema"], PROFILE_SCHEMA);
        assert_eq!(value["connection_count"], 4);
        assert_eq!(value["protocol_counts"]["icmp"], 1);
        assert_eq!(value["protocol_counts"]["tcp"], 1);
        assert_eq!(value["protocol_counts"]["udp"], 1);
        assert_eq!(value["protocol_counts"]["unknown_transport"], 1);
        assert_eq!(value["missing_duration_count"], 2);
        assert_eq!(value["missing_counter_counts"]["orig_ip_bytes"], 1);
        assert_eq!(value["missing_counter_counts"]["orig_packets"], 2);
        assert_eq!(value["missing_counter_counts"]["resp_ip_bytes"], 2);
        assert_eq!(value["missing_counter_counts"]["resp_packets"], 2);

        let digest = value["projection_sha256"].as_str().unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            rendered,
            format!(
                "{{\"schema\":\"netbraid.zeek_conn_adapter_profile.v0\",\"connection_count\":4,\"protocol_counts\":{{\"icmp\":1,\"tcp\":1,\"udp\":1,\"unknown_transport\":1}},\"missing_duration_count\":2,\"missing_counter_counts\":{{\"orig_ip_bytes\":1,\"orig_packets\":2,\"resp_ip_bytes\":2,\"resp_packets\":2}},\"projection_sha256\":\"{digest}\"}}"
            )
        );
    }

    #[test]
    fn error_contract_is_static_and_stable() {
        assert_eq!(RunError::Arguments.exit_code(), 2);
        assert_eq!(RunError::Projection.exit_code(), 3);
        assert_eq!(RunError::Profile.exit_code(), 4);
        assert_eq!(RunError::Output.exit_code(), 5);
        assert_eq!(RunError::Arguments.message(), "error: invalid arguments");
        assert_eq!(
            RunError::Projection.message(),
            "error: Zeek projection failed"
        );
        assert_eq!(
            RunError::Profile.message(),
            "error: profile encoding failed"
        );
        assert_eq!(RunError::Output.message(), "error: output failed");
    }
}
