use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use netbraid_replay::{
    load_scenario_bundle_v0, replay_scenario_v0, ScenarioConclusionDispositionV0, ScenarioLimitsV0,
};

#[derive(Debug, Args)]
pub struct ScenarioArgs {
    #[command(subcommand)]
    command: ScenarioCommand,
}

#[derive(Debug, Subcommand)]
enum ScenarioCommand {
    /// Validate the closed manifest, artifact inventory, and oracle references.
    Validate {
        /// Directory containing scenario.json and its exact declared artifacts.
        path: PathBuf,
        /// Emit one stable JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Replay the finite source prefix at one declared checkpoint.
    Replay {
        /// Directory containing scenario.json and its exact declared artifacts.
        path: PathBuf,
        /// Declared timeline checkpoint to replay through.
        #[arg(long)]
        checkpoint: String,
        /// Emit the typed replay receipt as JSON.
        #[arg(long)]
        json: bool,
    },
}

pub fn run(args: &ScenarioArgs) -> Result<()> {
    match &args.command {
        ScenarioCommand::Validate { path, json } => {
            let bundle =
                load_scenario_bundle_v0(path, ScenarioLimitsV0::default()).with_context(|| {
                    format!(
                        "validating scenario bundle {}",
                        super::operator_text(&path.display().to_string())
                    )
                })?;
            if *json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "schema": "netbraid.scenario_validation.v0",
                        "scenario_id": bundle.manifest().scenario_id,
                        "manifest_sha256": bundle.manifest_sha256(),
                        "artifacts": bundle.manifest().artifacts.len(),
                        "checkpoints": bundle.manifest().timeline.len(),
                        "conclusions": bundle.manifest().expected.conclusions.len(),
                        "viewports": bundle.manifest().expected.viewports.len(),
                    }))?
                );
            } else {
                println!(
                    "valid scenario {} — manifest {}",
                    super::operator_text(&bundle.manifest().scenario_id),
                    bundle.manifest_sha256()
                );
                println!(
                    "{} artifact(s), {} checkpoint(s), {} conclusion(s), {} viewport assertion(s)",
                    bundle.manifest().artifacts.len(),
                    bundle.manifest().timeline.len(),
                    bundle.manifest().expected.conclusions.len(),
                    bundle.manifest().expected.viewports.len()
                );
            }
        }
        ScenarioCommand::Replay {
            path,
            checkpoint,
            json,
        } => {
            let bundle =
                load_scenario_bundle_v0(path, ScenarioLimitsV0::default()).with_context(|| {
                    format!(
                        "loading scenario bundle {}",
                        super::operator_text(&path.display().to_string())
                    )
                })?;
            let receipt = replay_scenario_v0(&bundle, checkpoint).with_context(|| {
                format!(
                    "replaying checkpoint {:?}",
                    super::operator_text(checkpoint)
                )
            })?;
            if *json {
                println!("{}", serde_json::to_string(&receipt)?);
            } else {
                println!(
                    "scenario {} @ {} ({} ms) — manifest {}",
                    super::operator_text(&receipt.scenario_id),
                    super::operator_text(&receipt.checkpoint),
                    receipt.at_ms,
                    receipt.manifest_sha256
                );
                println!(
                    "{} record reference(s) ingested",
                    receipt.ingested_record_refs.len()
                );
                if let Some(host) = &receipt.projection.host_path {
                    println!(
                        "host path: {} record(s), {} exact context key(s), {} confirmed transition(s), {} compatible/incomplete transition(s), latest {}",
                        host.records,
                        host.exact_context_keys,
                        host.confirmed_context_transitions,
                        host.compatible_incomplete_transitions,
                        super::operator_text(&host.latest_record_id)
                    );
                }
                for capture in &receipt.projection.saved_captures {
                    println!(
                        "saved capture {}: {} packet(s), {} quarantine(s), records {}",
                        super::operator_text(&capture.artifact),
                        capture.packet_records,
                        capture.quarantine_records,
                        capture.normalized_records_sha256
                    );
                }
                let supported = receipt
                    .expected_conclusions
                    .iter()
                    .filter(|conclusion| {
                        conclusion.disposition == ScenarioConclusionDispositionV0::Supported
                    })
                    .count();
                let abstained = receipt.expected_conclusions.len() - supported;
                println!(
                    "declared oracle: {supported} supported conclusion(s), {abstained} required abstention(s), {} source-coverage row(s), {} viewport assertion(s)",
                    receipt.source_coverage.len(),
                    receipt.viewport_assertions.len()
                );
            }
        }
    }
    Ok(())
}
