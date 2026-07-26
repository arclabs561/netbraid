use std::ffi::OsString;
use std::path::Path;

use csv::StringRecord;
use netmon_evidence::CaptureFileMetadataV0;

pub(crate) fn arguments(input: &Path) -> Vec<OsString> {
    [
        "-T", "-R", "-m", "-Q", "-K", "-P", "-t", "-E", "-F", "-c", "-s", "-d", "-l", "-u",
        "-a", "-e", "-S",
    ]
    .into_iter()
    .map(OsString::from)
    .chain(std::iter::once(input.as_os_str().to_owned()))
    .collect()
}

pub(crate) fn argument_template() -> Vec<String> {
    arguments(Path::new("$STAGED_CAPTURE"))
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

pub(crate) fn parse_table(stdout: &[u8]) -> Result<CaptureFileMetadataV0, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(true)
        .flexible(false)
        .from_reader(stdout);
    let headers = reader
        .headers()
        .map_err(|error| format!("invalid Capinfos CSV header: {error}"))?
        .clone();
    let mut records = reader.records();
    let record = records
        .next()
        .ok_or_else(|| "Capinfos table has no data row".to_owned())?
        .map_err(|error| format!("invalid Capinfos CSV row: {error}"))?;
    if records.next().is_some() {
        return Err("Capinfos table has more than one data row".into());
    }

    let packet_count = parse_required(&headers, &record, "Number of packets")?;
    let duration_ns = parse_optional(&headers, &record, "Capture duration (seconds)")?
        .map(|value| parse_duration_ns(value, "Capture duration (seconds)"))
        .transpose()?;
    let earliest_packet_time_unix_ns = parse_optional(&headers, &record, "Start time")?
        .map(|value| parse_epoch_ns(value, "Start time"))
        .transpose()?;
    let latest_packet_time_unix_ns = parse_optional(&headers, &record, "End time")?
        .map(|value| parse_epoch_ns(value, "End time"))
        .transpose()?;

    Ok(CaptureFileMetadataV0 {
        file_type: required(&headers, &record, "File type")?.to_owned(),
        encapsulation: required(&headers, &record, "File encapsulation")?.to_owned(),
        timestamp_precision: required(&headers, &record, "File time precision")?.to_owned(),
        packet_count,
        file_size_bytes: parse_required(&headers, &record, "File size (bytes)")?,
        original_data_size_bytes: parse_required(&headers, &record, "Data size (bytes)")?,
        snaplen: parse_optional(&headers, &record, "Packet size limit")?
            .map(|value| parse_integer(value, "Packet size limit"))
            .transpose()?,
        inferred_snaplen_min: parse_optional(
            &headers,
            &record,
            "Packet size limit min (inferred)",
        )?
        .map(|value| parse_integer(value, "Packet size limit min (inferred)"))
        .transpose()?,
        inferred_snaplen_max: parse_optional(
            &headers,
            &record,
            "Packet size limit max (inferred)",
        )?
        .map(|value| parse_integer(value, "Packet size limit max (inferred)"))
        .transpose()?,
        duration_ns,
        earliest_packet_time_unix_ns,
        latest_packet_time_unix_ns,
        capture_hardware: optional_owned(&headers, &record, "Capture hardware")?,
        capture_operating_system: optional_owned(&headers, &record, "Capture oper-sys")?,
        capture_application: optional_owned(&headers, &record, "Capture application")?,
    })
}

fn required<'a>(
    headers: &StringRecord,
    record: &'a StringRecord,
    name: &str,
) -> Result<&'a str, String> {
    let value = value(headers, record, name)?;
    let value = value.trim();
    if value.is_empty() || value == "n/a" {
        Err(format!("Capinfos field {name:?} is unavailable"))
    } else {
        Ok(value)
    }
}

fn parse_optional<'a>(
    headers: &StringRecord,
    record: &'a StringRecord,
    name: &str,
) -> Result<Option<&'a str>, String> {
    let Some(index) = headers.iter().position(|header| header == name) else {
        return Ok(None);
    };
    let value = record
        .get(index)
        .ok_or_else(|| format!("Capinfos row has no value for {name:?}"))?
        .trim();
    Ok((!value.is_empty() && value != "n/a" && value != "(not set)").then_some(value))
}

fn optional_owned(
    headers: &StringRecord,
    record: &StringRecord,
    name: &str,
) -> Result<Option<String>, String> {
    Ok(parse_optional(headers, record, name)?.map(str::to_owned))
}

fn value<'a>(
    headers: &StringRecord,
    record: &'a StringRecord,
    name: &str,
) -> Result<&'a str, String> {
    let index = headers
        .iter()
        .position(|header| header == name)
        .ok_or_else(|| format!("Capinfos table is missing required header {name:?}"))?;
    record
        .get(index)
        .ok_or_else(|| format!("Capinfos row has no value for {name:?}"))
}

fn parse_required<T>(headers: &StringRecord, record: &StringRecord, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    parse_integer(required(headers, record, name)?, name)
}

fn parse_integer<T>(value: &str, name: &str) -> Result<T, String>
where
    T: std::str::FromStr,
{
    value
        .parse()
        .map_err(|_| format!("Capinfos field {name:?} has invalid value {value:?}"))
}

fn parse_duration_ns(value: &str, name: &str) -> Result<u64, String> {
    let nanoseconds = parse_seconds_ns(value, name)?;
    u64::try_from(nanoseconds)
        .map_err(|_| format!("Capinfos field {name:?} is outside the u64 nanosecond range"))
}

fn parse_epoch_ns(value: &str, name: &str) -> Result<i64, String> {
    let nanoseconds = parse_seconds_ns(value, name)?;
    i64::try_from(nanoseconds)
        .map_err(|_| format!("Capinfos field {name:?} is outside the i64 nanosecond range"))
}

fn parse_seconds_ns(value: &str, name: &str) -> Result<i128, String> {
    let (negative, unsigned) = value
        .strip_prefix('-')
        .map_or((false, value), |value| (true, value));
    let (seconds, fraction) = unsigned.split_once('.').unwrap_or((unsigned, ""));
    if seconds.is_empty()
        || !seconds.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 9
    {
        return Err(format!(
            "Capinfos field {name:?} has invalid decimal-seconds value {value:?}"
        ));
    }
    let seconds: i128 = seconds
        .parse()
        .map_err(|_| format!("Capinfos field {name:?} has invalid value {value:?}"))?;
    let fraction: i128 = if fraction.is_empty() {
        0
    } else {
        let parsed: i128 = fraction
            .parse()
            .map_err(|_| format!("Capinfos field {name:?} has invalid value {value:?}"))?;
        parsed * 10_i128.pow(u32::try_from(9 - fraction.len()).unwrap())
    };
    let magnitude = seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(fraction))
        .ok_or_else(|| format!("Capinfos field {name:?} overflows nanoseconds"))?;
    Ok(if negative { -magnitude } else { magnitude })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = "\"File name\",\"File type\",\"File encapsulation\",\"File time precision\",\"Packet size limit\",\"Packet size limit min (inferred)\",\"Packet size limit max (inferred)\",\"Number of packets\",\"File size (bytes)\",\"Data size (bytes)\",\"Capture duration (seconds)\",\"Start time\",\"End time\",\"Capture hardware\",\"Capture oper-sys\",\"Capture application\"\n";

    #[test]
    fn parses_quoted_table_without_floating_point() {
        let table = format!(
            "{HEADER}\"/private/tmp/random/capture\",\"pcap\",\"ether\",\"microseconds\",\"65535\",\"n/a\",\"n/a\",\"1\",\"94\",\"54\",\"0.000000\",\"1700000000.123456\",\"1700000000.123456\",\"Mac, Inc.\",\"macOS\",\"dumpcap\"\n"
        );
        let metadata = parse_table(table.as_bytes()).unwrap();

        assert_eq!(metadata.file_type, "pcap");
        assert_eq!(metadata.encapsulation, "ether");
        assert_eq!(metadata.packet_count, 1);
        assert_eq!(metadata.snaplen, Some(65_535));
        assert_eq!(metadata.inferred_snaplen_min, None);
        assert_eq!(metadata.duration_ns, Some(0));
        assert_eq!(
            metadata.earliest_packet_time_unix_ns,
            Some(1_700_000_000_123_456_000)
        );
        assert_eq!(metadata.capture_hardware.as_deref(), Some("Mac, Inc."));
    }

    #[test]
    fn rejects_missing_required_headers_and_multiple_files() {
        let missing = b"\"File type\"\n\"pcap\"\n";
        assert!(parse_table(missing)
            .unwrap_err()
            .contains("missing required header"));

        let table = format!(
            "{HEADER}\"a\",\"pcap\",\"ether\",\"microseconds\",\"65535\",\"n/a\",\"n/a\",\"1\",\"94\",\"54\",\"0\",\"1\",\"1\",\"\",\"\",\"\"\n\"b\",\"pcap\",\"ether\",\"microseconds\",\"65535\",\"n/a\",\"n/a\",\"1\",\"94\",\"54\",\"0\",\"1\",\"1\",\"\",\"\",\"\"\n"
        );
        assert_eq!(
            parse_table(table.as_bytes()).unwrap_err(),
            "Capinfos table has more than one data row"
        );
    }

    #[test]
    fn exact_seconds_parser_handles_pre_epoch_and_rejects_excess_precision() {
        assert_eq!(
            parse_epoch_ns("-0.5", "Start time").unwrap(),
            -500_000_000
        );
        assert!(parse_epoch_ns("1.0000000001", "Start time").is_err());
        assert!(parse_duration_ns("-1", "Capture duration (seconds)").is_err());
    }
}
