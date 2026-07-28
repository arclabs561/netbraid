use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use netbraid::replay::{
    load_scenario_bundle_v0, load_scenario_bundle_v1, replay_scenario_v0, replay_scenario_v1,
    ScenarioBundleV0, ScenarioBundleV1, ScenarioConclusionDispositionV0, ScenarioLimitsV0,
    ScenarioReplayProjectionV0, ScenarioReplayReceiptV0, ScenarioReplayReceiptV1,
    ScenarioSourceCoverageV0, ScenarioViewportAssertionV0,
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
            let bundle = load_scenario(path)?;
            print_validation(&bundle, *json)?;
        }
        ScenarioCommand::Replay {
            path,
            checkpoint,
            json,
        } => {
            let bundle = load_scenario(path)?;
            let receipt = bundle.replay(checkpoint).with_context(|| {
                format!(
                    "replaying checkpoint {:?}",
                    super::operator_text(checkpoint)
                )
            })?;
            if *json {
                receipt.print_json()?;
            } else {
                let view = receipt.view();
                println!(
                    "scenario {} @ {} ({} ms) — manifest {}",
                    super::operator_text(view.scenario_id),
                    super::operator_text(view.checkpoint),
                    view.at_ms,
                    view.manifest_sha256
                );
                if let LoadedReceipt::V1(receipt) = &receipt {
                    println!(
                        "PUBLIC_REVIEWED / {} evidence identifier class(es) / payload omitted from ingestible evidence",
                        receipt
                            .declared_disclosure_review
                            .retained_evidence_identifier_classes
                            .len()
                    );
                    println!("review authority: not authenticated by structural replay validation");
                }
                println!(
                    "{} record reference(s) ingested",
                    view.ingested_record_refs.len()
                );
                if let Some(host) = &view.projection.host_path {
                    println!(
                        "host path: {} record(s), {} exact context key(s), {} confirmed transition(s), {} compatible/incomplete transition(s), latest {}",
                        host.records,
                        host.exact_context_keys,
                        host.confirmed_context_transitions,
                        host.compatible_incomplete_transitions,
                        super::operator_text(&host.latest_record_id)
                    );
                }
                for capture in &view.projection.saved_captures {
                    println!(
                        "saved capture {}: {} packet(s), {} quarantine(s), records {}",
                        super::operator_text(&capture.artifact),
                        capture.packet_records,
                        capture.quarantine_records,
                        capture.normalized_records_sha256
                    );
                }
                let supported = view
                    .expected_conclusions
                    .iter()
                    .filter(|conclusion| {
                        conclusion.disposition == ScenarioConclusionDispositionV0::Supported
                    })
                    .count();
                let abstained = view.expected_conclusions.len() - supported;
                println!(
                    "declared oracle: {supported} supported conclusion(s), {abstained} required abstention(s), {} source-coverage row(s), {} viewport assertion(s)",
                    view.source_coverage.len(),
                    view.viewport_assertions.len()
                );
            }
        }
    }
    Ok(())
}

enum LoadedScenario {
    V0(ScenarioBundleV0),
    V1(ScenarioBundleV1),
}

impl LoadedScenario {
    fn replay(&self, checkpoint: &str) -> Result<LoadedReceipt, netbraid::replay::ScenarioError> {
        match self {
            Self::V0(bundle) => replay_scenario_v0(bundle, checkpoint).map(LoadedReceipt::V0),
            Self::V1(bundle) => replay_scenario_v1(bundle, checkpoint).map(LoadedReceipt::V1),
        }
    }
}

enum LoadedReceipt {
    V0(ScenarioReplayReceiptV0),
    V1(ScenarioReplayReceiptV1),
}

struct ReplayReceiptView<'a> {
    scenario_id: &'a str,
    manifest_sha256: &'a str,
    checkpoint: &'a str,
    at_ms: u64,
    ingested_record_refs: &'a [String],
    projection: &'a ScenarioReplayProjectionV0,
    source_coverage: &'a [ScenarioSourceCoverageV0],
    expected_conclusions: &'a [netbraid::replay::ScenarioConclusionV0],
    viewport_assertions: &'a [ScenarioViewportAssertionV0],
}

impl LoadedReceipt {
    fn view(&self) -> ReplayReceiptView<'_> {
        match self {
            Self::V0(receipt) => ReplayReceiptView {
                scenario_id: &receipt.scenario_id,
                manifest_sha256: &receipt.manifest_sha256,
                checkpoint: &receipt.checkpoint,
                at_ms: receipt.at_ms,
                ingested_record_refs: &receipt.ingested_record_refs,
                projection: &receipt.projection,
                source_coverage: &receipt.source_coverage,
                expected_conclusions: &receipt.expected_conclusions,
                viewport_assertions: &receipt.viewport_assertions,
            },
            Self::V1(receipt) => ReplayReceiptView {
                scenario_id: &receipt.scenario_id,
                manifest_sha256: &receipt.manifest_sha256,
                checkpoint: &receipt.checkpoint,
                at_ms: receipt.at_ms,
                ingested_record_refs: &receipt.ingested_record_refs,
                projection: &receipt.projection,
                source_coverage: &receipt.source_coverage,
                expected_conclusions: &receipt.expected_conclusions,
                viewport_assertions: &receipt.viewport_assertions,
            },
        }
    }

    fn print_json(&self) -> Result<()> {
        match self {
            Self::V0(receipt) => println!("{}", serde_json::to_string(receipt)?),
            Self::V1(receipt) => println!("{}", serde_json::to_string(receipt)?),
        }
        Ok(())
    }
}

fn load_scenario(path: &Path) -> Result<LoadedScenario> {
    let limits = ScenarioLimitsV0::default();
    match load_scenario_bundle_v0(path, limits) {
        Ok(bundle) => Ok(LoadedScenario::V0(bundle)),
        Err(v0_error) => match load_scenario_bundle_v1(path, limits) {
            Ok(bundle) => Ok(LoadedScenario::V1(bundle)),
            Err(v1_error) => anyhow::bail!(
                "validating scenario bundle {} failed as v0 ({}) and v1 ({})",
                super::operator_text(&path.display().to_string()),
                v0_error,
                v1_error
            ),
        },
    }
}

fn print_validation(bundle: &LoadedScenario, json: bool) -> Result<()> {
    match bundle {
        LoadedScenario::V0(bundle) if json => println!(
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
        ),
        LoadedScenario::V1(bundle) if json => println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "schema": "netbraid.scenario_validation.v1",
                "bundle_schema": bundle.manifest().schema,
                "scenario_id": bundle.manifest().scenario_id,
                "manifest_sha256": bundle.manifest_sha256(),
                "declared_sensitivity": bundle.manifest().sensitivity,
                "artifacts": bundle.manifest().artifacts.len(),
                "checkpoints": bundle.manifest().timeline.len(),
                "conclusions": bundle.manifest().expected.conclusions.len(),
                "viewports": bundle.manifest().expected.viewports.len(),
                "provenance_sources": bundle.manifest().provenance.sources.len(),
                "declared_evidence_identifier_classes": bundle
                    .manifest()
                    .disclosure_review
                    .retained_evidence_identifier_classes,
            }))?
        ),
        LoadedScenario::V0(bundle) => {
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
        LoadedScenario::V1(bundle) => {
            println!(
                "structurally valid v1 scenario {} — manifest {}",
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
            println!(
                "declared PUBLIC_REVIEWED: {} evidence identifier class(es), {} provenance source(s), payload omitted from ingestible evidence",
                bundle
                    .manifest()
                    .disclosure_review
                    .retained_evidence_identifier_classes
                    .len(),
                bundle.manifest().provenance.sources.len()
            );
            println!("review authority: not authenticated by structural validation");
        }
    }
    Ok(())
}
