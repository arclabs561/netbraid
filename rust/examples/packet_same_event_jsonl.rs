use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::ExitCode;

use netbraid::evidence::PacketEnvelopeV0;
use netbraid::infer::{FiniteHypothesisClaimV0, ProjectFiniteHypothesisClaimV0};
use netbraid::replay::{assess_packet_same_event_v0, PacketSameEventHypothesisSetV0};
use serde::{Deserialize, Serialize};

const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_PAIRS: usize = 200_000;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PairInput {
    pair_id: String,
    left: PacketEnvelopeV0,
    right: PacketEnvelopeV0,
}

#[derive(Serialize)]
struct PairOutput {
    pair_id: String,
    assessment: PacketSameEventHypothesisSetV0,
    claim: FiniteHypothesisClaimV0,
}

fn run(reader: impl Read, writer: impl Write) -> Result<(), String> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();

    for line_number in 1..=MAX_PAIRS + 1 {
        line.clear();
        let byte_count = reader
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_line(&mut line)
            .map_err(|error| format!("read pair line {line_number}: {error}"))?;
        if byte_count == 0 {
            writer
                .flush()
                .map_err(|error| format!("flush output: {error}"))?;
            return Ok(());
        }
        if byte_count > MAX_LINE_BYTES || !line.ends_with('\n') {
            return Err(format!(
                "pair line {line_number} exceeds {MAX_LINE_BYTES} bytes or lacks a newline"
            ));
        }
        if line_number > MAX_PAIRS {
            return Err(format!("input exceeds {MAX_PAIRS} pairs"));
        }

        let input: PairInput = serde_json::from_str(&line)
            .map_err(|error| format!("parse pair line {line_number}: {error}"))?;
        let assessment = assess_packet_same_event_v0(&input.left, &input.right)
            .map_err(|error| format!("assess pair line {line_number}: {error}"))?;
        let claim = assessment
            .project_finite_hypothesis_claim_v0((&input.left, &input.right))
            .map_err(|error| format!("project pair line {line_number}: {error}"))?;
        serde_json::to_writer(
            &mut writer,
            &PairOutput {
                pair_id: input.pair_id,
                assessment,
                claim,
            },
        )
        .map_err(|error| format!("serialize pair line {line_number}: {error}"))?;
        writer
            .write_all(b"\n")
            .map_err(|error| format!("write pair line {line_number}: {error}"))?;
    }

    unreachable!("bounded pair loop returns on EOF or excess input")
}

fn main() -> ExitCode {
    match run(io::stdin().lock(), io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> PacketEnvelopeV0 {
        serde_json::from_str(include_str!(
            "../tests/fixtures/replay/evidence-v0/packet_envelope_v0.json"
        ))
        .unwrap()
    }

    #[test]
    fn streams_one_assessment_per_pair() {
        let left = packet();
        let mut right = packet();
        right.capture_id =
            "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".into();
        right.record_id = format!("{}:frame:1", right.capture_id);
        let input = serde_json::to_string(&PairInput {
            pair_id: "pair-1".into(),
            left,
            right,
        })
        .unwrap();
        let mut output = Vec::new();

        run(format!("{input}\n").as_bytes(), &mut output).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["pair_id"], "pair-1");
        assert_eq!(value["assessment"]["reference"]["hypothesis"], "unknown");
        assert_eq!(
            value["claim"]["projection"]["family_schema"],
            "netmon.packet_same_event_hypothesis_set.v0"
        );
        assert_eq!(value["claim"]["inputs"][0]["role"], "left_packet");
        assert_eq!(value["claim"]["inputs"][1]["role"], "right_packet");
    }

    #[test]
    fn rejects_non_newline_terminated_input() {
        let error = run(b"{}".as_slice(), Vec::new()).unwrap_err();
        assert!(error.contains("lacks a newline"));
    }
}
