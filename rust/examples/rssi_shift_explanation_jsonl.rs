//! Strict JSONL bridge for evaluating RSSI shift explanations.
//!
//! This example emits only bounded aggregate results. It is an evaluation
//! adapter, not a durable serialization of inference types or caller IDs.

use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::ExitCode;

use netbraid::infer::{
    infer_rssi_shift_explanations_v0, RssiReferenceFrameLinkV0, RssiReferenceFrameProfileV0,
    RssiShiftExplanationComponentOutcomeV0, RssiShiftExplanationOptionsV0,
    RssiShiftExplanationReportV0,
};
use serde::{Deserialize, Serialize};

const OUTPUT_SCHEMA: &str = "netbraid.rssi_shift_explanation_eval.v0";
const MAX_LINE_BYTES: usize = 256 * 1024;
const MAX_CASES: usize = 200_000;
const MAX_ROLE_INDEX: u8 = 15;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CaseInput {
    case_id: String,
    reference_frame_profile: RssiReferenceFrameProfileV0,
    links: Vec<RssiReferenceFrameLinkV0>,
}

#[derive(Serialize)]
struct CaseOutput {
    schema: &'static str,
    case_id: String,
    heuristic_profile: String,
    links_seen: usize,
    baseline_samples_seen: usize,
    eligible_links: usize,
    shifted_links: usize,
    heuristic_weights: HeuristicWeightsOutput,
    outcomes: OutcomeCountsOutput,
    observer_beliefs: ShiftedBeliefAggregateOutput,
    source_beliefs: ShiftedBeliefAggregateOutput,
    residual_beliefs: ResidualBeliefAggregateOutput,
}

#[derive(Serialize)]
struct HeuristicWeightsOutput {
    inactive_endpoint_potential_ppb: u64,
    active_endpoint_potential_ppb: u64,
    shifted_without_endpoint_potential_ppb: u64,
    shifted_with_one_endpoint_potential_ppb: u64,
    shifted_with_both_endpoints_potential_ppb: u64,
    stable_without_endpoint_potential_ppb: u64,
    stable_with_one_endpoint_potential_ppb: u64,
    stable_with_both_endpoints_potential_ppb: u64,
}

#[derive(Default, Serialize)]
struct OutcomeCountsOutput {
    exact_components: usize,
    infeasible_components: usize,
    abstained_components: usize,
    assignments_evaluated: u64,
}

#[derive(Default, Serialize)]
struct ShiftedBeliefAggregateOutput {
    count: usize,
    shifted_relative_belief_ppb_sum: u64,
    shifted_relative_belief_ppb_min: Option<u64>,
    shifted_relative_belief_ppb_max: Option<u64>,
}

#[derive(Default, Serialize)]
struct ResidualBeliefAggregateOutput {
    count: usize,
    residual_relative_belief_ppb_sum: u64,
    residual_relative_belief_ppb_min: Option<u64>,
    residual_relative_belief_ppb_max: Option<u64>,
}

fn synthetic_index(id: &str, prefix: &str) -> Option<u8> {
    let suffix = id.strip_prefix(prefix)?;
    let index = suffix.parse::<u8>().ok()?;
    (index <= MAX_ROLE_INDEX && suffix == index.to_string()).then_some(index)
}

fn observer_index(id: &str) -> Result<u8, &'static str> {
    synthetic_index(id, "observer-").ok_or("unsupported synthetic observer identifier")
}

fn source_index(id: &str) -> Result<u8, &'static str> {
    synthetic_index(id, "source-role-").ok_or("unsupported synthetic source identifier")
}

fn validate_synthetic_roles(links: &[RssiReferenceFrameLinkV0]) -> Result<(), &'static str> {
    for link in links {
        observer_index(link.observer_id())?;
        source_index(link.source_id())?;
    }
    Ok(())
}

fn validate_case_id(case_id: &str) -> Result<(), &'static str> {
    let valid = !case_id.is_empty()
        && case_id.len() <= 64
        && case_id.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        });
    valid
        .then_some(())
        .ok_or("unsupported synthetic case identifier")
}

fn add_assignments(total: &mut u64, assignments: u64) -> Result<(), String> {
    *total = total
        .checked_add(assignments)
        .ok_or_else(|| "assignment count overflow".to_owned())?;
    Ok(())
}

fn add_shifted_belief(
    aggregate: &mut ShiftedBeliefAggregateOutput,
    belief_ppb: u64,
) -> Result<(), String> {
    aggregate.count = aggregate
        .count
        .checked_add(1)
        .ok_or_else(|| "belief count overflow".to_owned())?;
    aggregate.shifted_relative_belief_ppb_sum = aggregate
        .shifted_relative_belief_ppb_sum
        .checked_add(belief_ppb)
        .ok_or_else(|| "belief sum overflow".to_owned())?;
    aggregate.shifted_relative_belief_ppb_min = Some(
        aggregate
            .shifted_relative_belief_ppb_min
            .map_or(belief_ppb, |minimum| minimum.min(belief_ppb)),
    );
    aggregate.shifted_relative_belief_ppb_max = Some(
        aggregate
            .shifted_relative_belief_ppb_max
            .map_or(belief_ppb, |maximum| maximum.max(belief_ppb)),
    );
    Ok(())
}

fn add_residual_belief(
    aggregate: &mut ResidualBeliefAggregateOutput,
    belief_ppb: u64,
) -> Result<(), String> {
    aggregate.count = aggregate
        .count
        .checked_add(1)
        .ok_or_else(|| "belief count overflow".to_owned())?;
    aggregate.residual_relative_belief_ppb_sum = aggregate
        .residual_relative_belief_ppb_sum
        .checked_add(belief_ppb)
        .ok_or_else(|| "belief sum overflow".to_owned())?;
    aggregate.residual_relative_belief_ppb_min = Some(
        aggregate
            .residual_relative_belief_ppb_min
            .map_or(belief_ppb, |minimum| minimum.min(belief_ppb)),
    );
    aggregate.residual_relative_belief_ppb_max = Some(
        aggregate
            .residual_relative_belief_ppb_max
            .map_or(belief_ppb, |maximum| maximum.max(belief_ppb)),
    );
    Ok(())
}

fn summarize_report(
    case_id: String,
    report: &RssiShiftExplanationReportV0,
) -> Result<CaseOutput, String> {
    let mut outcomes = OutcomeCountsOutput::default();
    let mut observer_beliefs = ShiftedBeliefAggregateOutput::default();
    let mut source_beliefs = ShiftedBeliefAggregateOutput::default();
    let mut residual_beliefs = ResidualBeliefAggregateOutput::default();

    for component in report.components() {
        match component.outcome() {
            RssiShiftExplanationComponentOutcomeV0::Exact {
                assignments_evaluated,
            } => {
                outcomes.exact_components += 1;
                add_assignments(&mut outcomes.assignments_evaluated, *assignments_evaluated)?;
            }
            RssiShiftExplanationComponentOutcomeV0::NoFeasibleAssignment {
                assignments_evaluated,
            } => {
                outcomes.infeasible_components += 1;
                add_assignments(&mut outcomes.assignments_evaluated, *assignments_evaluated)?;
            }
            RssiShiftExplanationComponentOutcomeV0::Abstained(_) => {
                outcomes.abstained_components += 1;
            }
            _ => return Err("unsupported RSSI explanation component outcome".to_owned()),
        }

        for belief in component.observer_beliefs() {
            add_shifted_belief(&mut observer_beliefs, belief.shifted_relative_belief_ppb)?;
        }
        for belief in component.source_beliefs() {
            add_shifted_belief(&mut source_beliefs, belief.shifted_relative_belief_ppb)?;
        }
        for belief in component.residual_beliefs() {
            add_residual_belief(&mut residual_beliefs, belief.residual_relative_belief_ppb)?;
        }
    }

    let profile = report.profile();
    Ok(CaseOutput {
        schema: OUTPUT_SCHEMA,
        case_id,
        heuristic_profile: report.heuristic_profile().to_owned(),
        links_seen: report.links_seen(),
        baseline_samples_seen: report.baseline_samples_seen(),
        eligible_links: report.eligible_links(),
        shifted_links: report.shifted_links(),
        heuristic_weights: HeuristicWeightsOutput {
            inactive_endpoint_potential_ppb: profile.inactive_endpoint_potential_ppb,
            active_endpoint_potential_ppb: profile.active_endpoint_potential_ppb,
            shifted_without_endpoint_potential_ppb: profile.shifted_without_endpoint_potential_ppb,
            shifted_with_one_endpoint_potential_ppb: profile
                .shifted_with_one_endpoint_potential_ppb,
            shifted_with_both_endpoints_potential_ppb: profile
                .shifted_with_both_endpoints_potential_ppb,
            stable_without_endpoint_potential_ppb: profile.stable_without_endpoint_potential_ppb,
            stable_with_one_endpoint_potential_ppb: profile.stable_with_one_endpoint_potential_ppb,
            stable_with_both_endpoints_potential_ppb: profile
                .stable_with_both_endpoints_potential_ppb,
        },
        outcomes,
        observer_beliefs,
        source_beliefs,
        residual_beliefs,
    })
}

fn run(reader: impl Read, writer: impl Write) -> Result<(), String> {
    let mut reader = BufReader::new(reader);
    let mut writer = BufWriter::new(writer);
    let mut line = String::new();

    for line_number in 1..=MAX_CASES + 1 {
        line.clear();
        let byte_count = reader
            .by_ref()
            .take((MAX_LINE_BYTES + 1) as u64)
            .read_line(&mut line)
            .map_err(|error| format!("read case line {line_number}: {error}"))?;
        if byte_count == 0 {
            writer
                .flush()
                .map_err(|error| format!("flush output: {error}"))?;
            return Ok(());
        }
        if byte_count > MAX_LINE_BYTES || !line.ends_with('\n') {
            return Err(format!(
                "case line {line_number} exceeds {MAX_LINE_BYTES} bytes or lacks a newline"
            ));
        }
        if line_number > MAX_CASES {
            return Err(format!("input exceeds {MAX_CASES} cases"));
        }

        let input: CaseInput = serde_json::from_str(&line)
            .map_err(|_| format!("parse case line {line_number}: invalid JSON input"))?;
        validate_case_id(&input.case_id)
            .map_err(|error| format!("validate case line {line_number}: {error}"))?;
        validate_synthetic_roles(&input.links)
            .map_err(|error| format!("validate case line {line_number}: {error}"))?;
        let report = infer_rssi_shift_explanations_v0(
            &input.links,
            &input.reference_frame_profile,
            &RssiShiftExplanationOptionsV0::default(),
        )
        .map_err(|error| format!("infer case line {line_number}: {error}"))?;
        let output = summarize_report(input.case_id, &report)
            .map_err(|error| format!("summarize case line {line_number}: {error}"))?;
        serde_json::to_writer(&mut writer, &output)
            .map_err(|error| format!("serialize case line {line_number}: {error}"))?;
        writer
            .write_all(b"\n")
            .map_err(|error| format!("write case line {line_number}: {error}"))?;
    }

    unreachable!("bounded case loop returns on EOF or excess input")
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
    use netbraid::infer::RssiMilliDbV0;

    fn reference_profile() -> RssiReferenceFrameProfileV0 {
        RssiReferenceFrameProfileV0::new(
            "profile:rssi-shift-explanation:jsonl-test",
            4,
            8_000,
            4_000_000_000,
            3,
            600_000_000,
        )
        .unwrap()
    }

    fn observer_wide_links() -> Vec<RssiReferenceFrameLinkV0> {
        let mut links = Vec::new();
        for observer_index in 0..3 {
            for source_index in 0..3 {
                let observer_id = format!("observer-{observer_index}");
                let source_id = format!("source-role-{source_index}");
                let baseline = -50_000 - (observer_index * 8_000 + source_index * 3_000);
                let recent = if observer_index == 0 {
                    baseline + 18_000
                } else {
                    baseline
                };
                links.push(
                    RssiReferenceFrameLinkV0::new(
                        observer_id,
                        source_id,
                        vec![RssiMilliDbV0::new(baseline); 4],
                        Some(RssiMilliDbV0::new(recent)),
                    )
                    .unwrap(),
                );
            }
        }
        links
    }

    fn case_input(links: Vec<RssiReferenceFrameLinkV0>) -> String {
        serde_json::to_string(&CaseInput {
            case_id: "case-1".into(),
            reference_frame_profile: reference_profile(),
            links,
        })
        .unwrap()
    }

    #[test]
    fn streams_one_path_free_exact_observer_wide_summary() {
        let input = case_input(observer_wide_links());
        let mut output = Vec::new();

        run(format!("{input}\n").as_bytes(), &mut output).unwrap();

        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["schema"], OUTPUT_SCHEMA);
        assert_eq!(value["case_id"], "case-1");
        assert_eq!(
            value["heuristic_profile"],
            "netbraid.rssi_shift_explanation.heuristic.v0"
        );
        assert_eq!(value["links_seen"], 9);
        assert_eq!(value["baseline_samples_seen"], 36);
        assert_eq!(value["eligible_links"], 9);
        assert_eq!(value["shifted_links"], 3);
        assert_eq!(
            value["heuristic_weights"]["shifted_with_one_endpoint_potential_ppb"],
            64_000_000_000_u64
        );
        assert_eq!(value["outcomes"]["exact_components"], 1);
        assert_eq!(value["outcomes"]["infeasible_components"], 0);
        assert_eq!(value["outcomes"]["abstained_components"], 0);
        assert_eq!(value["outcomes"]["assignments_evaluated"], 64);
        assert_eq!(value["observer_beliefs"]["count"], 3);
        assert!(
            value["observer_beliefs"]["shifted_relative_belief_ppb_max"]
                .as_u64()
                .unwrap()
                > 900_000_000
        );
        assert_eq!(value["source_beliefs"]["count"], 3);
        assert_eq!(value["residual_beliefs"]["count"], 3);
        let output_text = String::from_utf8(output).unwrap();
        assert!(!output_text.contains("observer-"));
        assert!(!output_text.contains("source-role-"));
        assert!(!output_text.contains("observer_index"));
        assert!(!output_text.contains("source_index"));
    }

    #[test]
    fn rejects_arbitrary_identifiers_without_reflecting_them() {
        let links = vec![RssiReferenceFrameLinkV0::new(
            "private-observer-path",
            "source-role-0",
            vec![RssiMilliDbV0::new(-50_000); 4],
            Some(RssiMilliDbV0::new(-50_000)),
        )
        .unwrap()];
        let input = case_input(links);

        let error = run(format!("{input}\n").as_bytes(), Vec::new()).unwrap_err();

        assert_eq!(
            error,
            "validate case line 1: unsupported synthetic observer identifier"
        );
        assert!(!error.contains("private-observer-path"));
    }

    #[test]
    fn rejects_arbitrary_case_id_without_reflecting_it() {
        let input = serde_json::to_string(&CaseInput {
            case_id: "/private/sentinel".into(),
            reference_frame_profile: reference_profile(),
            links: observer_wide_links(),
        })
        .unwrap();

        let error = run(format!("{input}\n").as_bytes(), Vec::new()).unwrap_err();

        assert_eq!(
            error,
            "validate case line 1: unsupported synthetic case identifier"
        );
        assert!(!error.contains("/private/sentinel"));
    }

    #[test]
    fn rejects_malformed_input() {
        let error = run(b"{not-json}\n".as_slice(), Vec::new()).unwrap_err();
        assert_eq!(error, "parse case line 1: invalid JSON input");
    }

    #[test]
    fn rejects_non_newline_terminated_input() {
        let error = run(b"{}".as_slice(), Vec::new()).unwrap_err();
        assert!(error.contains("lacks a newline"));
    }
}
