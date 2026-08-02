use std::collections::HashSet;
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;

use anyhow::Result;
use netbraid_adapter_tshark::{
    normalize_saved_capture_requests, NormalizationReport, NormalizeOptions, NormalizeRequest,
};
use netbraid_replay::{
    project_saved_pcap_wlan_fingerprint_v0, SavedCaptureRecordStreamV0,
    SavedPcapWlanFingerprintCandidateV0,
};
use serde::{Deserialize, Serialize};

const MAX_LINE_BYTES: usize = 16 * 1024;
const MAX_REQUESTS: usize = 64;
const MAX_CASE_ID_BYTES: usize = 128;
const MAX_PACKET_LIMIT: usize = 100_000;
const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    case_id: String,
    path: PathBuf,
    packet_limit: usize,
}

#[derive(Debug)]
struct CaseId(String);

impl CaseId {
    fn parse(value: String, line_number: usize) -> Result<Self, String> {
        if value.is_empty()
            || value.len() > MAX_CASE_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(format!("invalid case_id on request line {line_number}"));
        }
        Ok(Self(value))
    }
}

#[derive(Debug)]
struct BatchRequest {
    case_id: CaseId,
    normalize: NormalizeRequest,
}

#[derive(Serialize)]
struct BatchOutput<'a> {
    case_id: &'a str,
    fingerprint: SavedPcapWlanFingerprintCandidateV0,
}

fn read_requests(reader: impl Read) -> Result<Vec<BatchRequest>, String> {
    let mut reader = BufReader::new(reader);
    let mut requests = Vec::new();
    let mut case_ids = HashSet::new();
    let mut line = String::new();

    for line_number in 1..=MAX_REQUESTS + 1 {
        line.clear();
        let byte_count = reader
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_line(&mut line)
            .map_err(|error| format!("read request line {line_number}: {error}"))?;
        if byte_count == 0 {
            if requests.is_empty() {
                return Err("input contains no requests".into());
            }
            return Ok(requests);
        }
        if byte_count > MAX_LINE_BYTES || !line.ends_with('\n') {
            return Err(format!(
                "request line {line_number} exceeds {MAX_LINE_BYTES} bytes or lacks a newline"
            ));
        }
        if line_number > MAX_REQUESTS {
            return Err(format!("input exceeds {MAX_REQUESTS} requests"));
        }

        let wire: WireRequest = serde_json::from_str(&line)
            .map_err(|error| format!("parse request line {line_number}: {error}"))?;
        let case_id = CaseId::parse(wire.case_id, line_number)?;
        if !case_ids.insert(case_id.0.clone()) {
            return Err(format!("duplicate case_id on request line {line_number}"));
        }
        if wire.path.as_os_str().is_empty() || !wire.path.is_absolute() {
            return Err(format!(
                "request path on line {line_number} must be non-empty and absolute"
            ));
        }
        if !(1..=MAX_PACKET_LIMIT).contains(&wire.packet_limit) {
            return Err(format!(
                "packet_limit on request line {line_number} must be in 1..={MAX_PACKET_LIMIT}"
            ));
        }

        let options = NormalizeOptions {
            packet_limit: wire.packet_limit,
            max_input_bytes: MAX_CAPTURE_BYTES,
            ..NormalizeOptions::default()
        };
        requests.push(BatchRequest {
            case_id,
            normalize: NormalizeRequest::new(wire.path, options),
        });
    }

    unreachable!("bounded request loop returns on EOF or excess input")
}

fn fingerprint(report: NormalizationReport) -> SavedPcapWlanFingerprintCandidateV0 {
    let records = SavedCaptureRecordStreamV0 {
        normalized_records_sha256: report.receipt.normalized_records_sha256.clone(),
        manifest: report.manifest,
        receipt: Some(report.receipt),
        packets: report.packets,
        quarantines: report.quarantines,
    };
    project_saved_pcap_wlan_fingerprint_v0(&records)
}

fn run_io(reader: impl Read, writer: impl Write) -> Result<(), String> {
    let requests = read_requests(reader)?;
    let request_count = requests.len();
    let mut case_ids = Vec::with_capacity(request_count);
    let mut normalize_requests = Vec::with_capacity(request_count);
    for request in requests {
        case_ids.push(request.case_id);
        normalize_requests.push(request.normalize);
    }
    let reports = normalize_saved_capture_requests(&normalize_requests, 8)
        .map_err(|error| format!("normalize request batch: {error}"))?;
    if reports.len() != request_count {
        return Err("normalizer returned a different report count".into());
    }

    let mut writer = BufWriter::new(writer);
    for (case_id, report) in case_ids.iter().zip(reports) {
        serde_json::to_writer(
            &mut writer,
            &BatchOutput {
                case_id: &case_id.0,
                fingerprint: fingerprint(report),
            },
        )
        .map_err(|error| format!("serialize batch output: {error}"))?;
        writer
            .write_all(b"\n")
            .map_err(|error| format!("write batch output: {error}"))?;
    }
    writer
        .flush()
        .map_err(|error| format!("flush batch output: {error}"))
}

pub fn run() -> Result<()> {
    run_io(io::stdin().lock(), io::stdout().lock()).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn request_parser_preserves_order_and_heterogeneous_packet_limits() {
        let input = concat!(
            "{\"case_id\":\"first\",\"path\":\"/tmp/first.pcap\",\"packet_limit\":17}\n",
            "{\"case_id\":\"second\",\"path\":\"/tmp/second.pcap\",\"packet_limit\":23}\n",
        );

        let requests = read_requests(input.as_bytes()).unwrap();

        assert_eq!(requests[0].case_id.0, "first");
        assert_eq!(requests[0].normalize.path(), Path::new("/tmp/first.pcap"));
        assert_eq!(requests[0].normalize.options().packet_limit, 17);
        assert_eq!(requests[1].case_id.0, "second");
        assert_eq!(requests[1].normalize.path(), Path::new("/tmp/second.pcap"));
        assert_eq!(requests[1].normalize.options().packet_limit, 23);
    }

    #[test]
    fn request_parser_rejects_unknown_fields_and_duplicate_case_ids() {
        let unknown =
            b"{\"case_id\":\"first\",\"path\":\"/tmp/a\",\"packet_limit\":1,\"extra\":true}\n";
        assert!(read_requests(&unknown[..])
            .unwrap_err()
            .starts_with("parse request line 1:"));

        let duplicate = concat!(
            "{\"case_id\":\"same\",\"path\":\"/tmp/a\",\"packet_limit\":1}\n",
            "{\"case_id\":\"same\",\"path\":\"/tmp/b\",\"packet_limit\":2}\n",
        );
        assert_eq!(
            read_requests(duplicate.as_bytes()).unwrap_err(),
            "duplicate case_id on request line 2"
        );
    }

    #[test]
    fn request_parser_rejects_empty_unterminated_and_out_of_range_input() {
        assert_eq!(
            read_requests(&b""[..]).unwrap_err(),
            "input contains no requests"
        );
        assert!(read_requests(&b"{}"[..])
            .unwrap_err()
            .contains("lacks a newline"));
        let zero = b"{\"case_id\":\"zero\",\"path\":\"/tmp/a\",\"packet_limit\":0}\n";
        assert_eq!(
            read_requests(&zero[..]).unwrap_err(),
            "packet_limit on request line 1 must be in 1..=100000"
        );
    }
}
