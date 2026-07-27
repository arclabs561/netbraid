use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    parse_host_path_jsonl, parse_saved_capture_jsonl, ContextRelationV0, ReplayStateV0,
    SavedCaptureRecordStreamV0,
};

pub const SCENARIO_BUNDLE_SCHEMA_V0: &str = "netbraid.scenario_bundle.v0";
pub const SCENARIO_REPLAY_SCHEMA_V0: &str = "netbraid.scenario_replay.v0";

const MANIFEST_NAME: &str = "scenario.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScenarioLimitsV0 {
    pub max_manifest_bytes: u64,
    pub max_artifact_bytes: u64,
    pub max_total_artifact_bytes: u64,
    pub max_artifacts: usize,
    pub max_checkpoints: usize,
    pub max_conclusions: usize,
    pub max_viewport_cells: u64,
}

impl Default for ScenarioLimitsV0 {
    fn default() -> Self {
        Self {
            max_manifest_bytes: 256 * 1024,
            max_artifact_bytes: 8 * 1024 * 1024,
            max_total_artifact_bytes: 16 * 1024 * 1024,
            max_artifacts: 64,
            max_checkpoints: 128,
            max_conclusions: 256,
            max_viewport_cells: 500 * 200,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioManifestV0 {
    pub schema: String,
    pub scenario_id: String,
    pub license: String,
    pub privacy: ScenarioPrivacyV0,
    pub provenance: ScenarioProvenanceV0,
    pub artifacts: Vec<ScenarioArtifactV0>,
    pub timeline: Vec<ScenarioTimelineCheckpointV0>,
    pub expected: ScenarioExpectedV0,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScenarioPrivacyV0 {
    #[serde(rename = "PUBLIC_SYNTHETIC")]
    PublicSynthetic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioProvenanceV0 {
    pub generator: String,
    pub generator_version: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioArtifactV0 {
    pub id: String,
    pub path: String,
    pub role: ScenarioArtifactRoleV0,
    pub media_type: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioArtifactRoleV0 {
    HostPathJsonl,
    SavedCaptureJsonl,
    ViewportText,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioTimelineCheckpointV0 {
    pub name: String,
    pub at_ms: u64,
    #[serde(default)]
    pub ingest: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioExpectedV0 {
    pub source_coverage: Vec<ScenarioSourceCoverageV0>,
    pub conclusions: Vec<ScenarioConclusionV0>,
    #[serde(default)]
    pub viewports: Vec<ScenarioViewportAssertionV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSourceCoverageV0 {
    pub id: String,
    pub checkpoint: String,
    pub source: String,
    pub state: ScenarioCoverageStateV0,
    pub freshness: ScenarioCoverageFreshnessV0,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCoverageStateV0 {
    Complete,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCoverageFreshnessV0 {
    Current,
    Stale,
    NotObserved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioConclusionV0 {
    pub id: String,
    pub checkpoint: String,
    pub question: String,
    pub disposition: ScenarioConclusionDispositionV0,
    pub conclusion: String,
    #[serde(default)]
    pub evidence: Vec<String>,
    pub coverage: Vec<String>,
    #[serde(default)]
    pub limitations: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioConclusionDispositionV0 {
    Supported,
    Abstained,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioViewportAssertionV0 {
    pub checkpoint: String,
    pub artifact: String,
    pub width: u16,
    pub height: u16,
}

#[derive(Debug, Clone)]
pub struct ScenarioBundleV0 {
    manifest: ScenarioManifestV0,
    manifest_sha256: String,
    artifacts: BTreeMap<String, LoadedArtifactV0>,
}

impl ScenarioBundleV0 {
    pub fn manifest(&self) -> &ScenarioManifestV0 {
        &self.manifest
    }

    /// SHA-256 of the exact manifest bytes loaded from `scenario.json`.
    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }
}

#[derive(Debug, Clone)]
struct LoadedArtifactV0 {
    bytes: Vec<u8>,
    records: BTreeMap<String, LoadedRecordV0>,
}

#[derive(Debug, Clone)]
enum LoadedRecordV0 {
    HostPath(Box<crate::HostPathObservationV0>),
    SavedCapture,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioReplayReceiptV0 {
    pub schema: String,
    pub scenario_id: String,
    pub manifest_sha256: String,
    pub checkpoint: String,
    pub at_ms: u64,
    pub ingested_record_refs: Vec<String>,
    pub projection: ScenarioReplayProjectionV0,
    pub source_coverage: Vec<ScenarioSourceCoverageV0>,
    pub expected_conclusions: Vec<ScenarioConclusionV0>,
    pub viewport_assertions: Vec<ScenarioViewportAssertionV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioReplayProjectionV0 {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_path: Option<ScenarioReplayHostPathV0>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub saved_captures: Vec<ScenarioSavedCaptureProjectionV0>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioReplayHostPathV0 {
    pub records: u64,
    pub exact_context_keys: u64,
    pub confirmed_context_transitions: u64,
    pub compatible_incomplete_transitions: u64,
    pub latest_record_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSavedCaptureProjectionV0 {
    pub artifact: String,
    pub capture_id: String,
    pub normalized_records_sha256: String,
    pub packet_records: u64,
    pub quarantine_records: u64,
}

#[derive(Debug)]
pub enum ScenarioError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    ManifestTooLarge {
        bytes: u64,
        max_bytes: u64,
    },
    ManifestJson(serde_json::Error),
    Invalid(String),
    Artifact {
        artifact: String,
        detail: String,
    },
    UnknownCheckpoint(String),
    Replay(crate::ReplayError),
}

impl std::fmt::Display for ScenarioError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(formatter, "{}: {source}", path.display()),
            Self::ManifestTooLarge { bytes, max_bytes } => write!(
                formatter,
                "scenario manifest is {bytes} bytes; maximum is {max_bytes}"
            ),
            Self::ManifestJson(source) => write!(formatter, "invalid scenario manifest: {source}"),
            Self::Invalid(detail) => formatter.write_str(detail),
            Self::Artifact { artifact, detail } => {
                write!(formatter, "artifact {artifact:?}: {detail}")
            }
            Self::UnknownCheckpoint(checkpoint) => {
                write!(formatter, "unknown scenario checkpoint {checkpoint:?}")
            }
            Self::Replay(source) => write!(formatter, "host-path replay failed: {source}"),
        }
    }
}

impl std::error::Error for ScenarioError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::ManifestJson(source) => Some(source),
            Self::Replay(source) => Some(source),
            _ => None,
        }
    }
}

/// Loads and validates one closed, finite scenario directory.
///
/// `scenario.json` and every declared artifact must be a regular file. Symlinks,
/// undeclared files, unsafe relative paths, byte-count mismatches, and digest
/// mismatches fail closed.
pub fn load_scenario_bundle_v0(
    directory: impl AsRef<Path>,
    limits: ScenarioLimitsV0,
) -> Result<ScenarioBundleV0, ScenarioError> {
    let directory = directory.as_ref();
    let root = ScenarioDirectoryV0::open(directory)?;
    let (manifest_file, manifest_path, manifest_bytes_len) =
        root.open_regular_file(Path::new(MANIFEST_NAME))?;
    if manifest_bytes_len > limits.max_manifest_bytes {
        return Err(ScenarioError::ManifestTooLarge {
            bytes: manifest_bytes_len,
            max_bytes: limits.max_manifest_bytes,
        });
    }
    let manifest_bytes =
        read_bounded_open_file(manifest_file, &manifest_path, limits.max_manifest_bytes)?;
    let manifest: ScenarioManifestV0 =
        serde_json::from_slice(&manifest_bytes).map_err(ScenarioError::ManifestJson)?;
    validate_manifest_shape(&manifest, limits)?;

    let declared_paths = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.as_str())
        .collect::<BTreeSet<_>>();
    let max_inventory_entries = limits.max_artifacts.saturating_mul(16).saturating_add(1);
    let actual_paths = collect_files(directory, max_inventory_entries)?;
    let expected_paths = declared_paths
        .iter()
        .map(|path| (*path).to_owned())
        .chain(std::iter::once(MANIFEST_NAME.to_owned()))
        .collect::<BTreeSet<_>>();
    if actual_paths != expected_paths {
        let undeclared = actual_paths
            .difference(&expected_paths)
            .cloned()
            .collect::<Vec<_>>();
        let missing = expected_paths
            .difference(&actual_paths)
            .cloned()
            .collect::<Vec<_>>();
        return Err(ScenarioError::Invalid(format!(
            "scenario file inventory mismatch; undeclared={undeclared:?}, missing={missing:?}"
        )));
    }

    let mut loaded = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let (file, path, bytes_len) = root.open_regular_file(Path::new(&artifact.path))?;
        if bytes_len > limits.max_artifact_bytes {
            return Err(artifact_error(
                artifact,
                format!(
                    "is {} bytes; per-artifact maximum is {}",
                    bytes_len, limits.max_artifact_bytes
                ),
            ));
        }
        let bytes = read_bounded_open_file(file, &path, limits.max_artifact_bytes)?;
        loaded.insert(
            artifact.id.clone(),
            validate_artifact(artifact, bytes, limits)?,
        );
    }

    finish_bundle(manifest, &manifest_bytes, loaded, limits)
}

pub fn replay_scenario_v0(
    bundle: &ScenarioBundleV0,
    checkpoint: &str,
) -> Result<ScenarioReplayReceiptV0, ScenarioError> {
    let target_index = bundle
        .manifest
        .timeline
        .iter()
        .position(|candidate| candidate.name == checkpoint)
        .ok_or_else(|| ScenarioError::UnknownCheckpoint(checkpoint.to_owned()))?;
    let target = &bundle.manifest.timeline[target_index];
    let ingested_record_refs = bundle.manifest.timeline[..=target_index]
        .iter()
        .flat_map(|entry| entry.ingest.iter().cloned())
        .collect::<Vec<_>>();

    let mut host_records = Vec::new();
    let mut saved_ids = BTreeSet::new();
    for reference in &ingested_record_refs {
        let (artifact_id, record_id) = split_record_ref(reference)?;
        let artifact = bundle
            .artifacts
            .get(artifact_id)
            .ok_or_else(|| ScenarioError::Invalid(format!("unknown artifact {artifact_id:?}")))?;
        match artifact.records.get(record_id) {
            Some(LoadedRecordV0::HostPath(record)) => host_records.push(record.as_ref().clone()),
            Some(LoadedRecordV0::SavedCapture) => {
                saved_ids.insert(artifact_id.to_owned());
            }
            None => {
                return Err(ScenarioError::Invalid(format!(
                    "unknown record reference {reference:?}"
                )));
            }
        }
    }

    let host_path = if host_records.is_empty() {
        None
    } else {
        let replay = crate::replay(host_records).map_err(ScenarioError::Replay)?;
        Some(project_host_path(&replay))
    };
    let saved_captures = saved_ids
        .into_iter()
        .map(|artifact_id| {
            let artifact = bundle
                .manifest
                .artifacts
                .iter()
                .find(|artifact| artifact.id == artifact_id)
                .expect("validated artifact ID");
            let loaded = bundle
                .artifacts
                .get(&artifact_id)
                .expect("validated artifact data");
            project_saved_capture(&artifact.id, &loaded.bytes)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ScenarioReplayReceiptV0 {
        schema: SCENARIO_REPLAY_SCHEMA_V0.into(),
        scenario_id: bundle.manifest.scenario_id.clone(),
        manifest_sha256: bundle.manifest_sha256.clone(),
        checkpoint: target.name.clone(),
        at_ms: target.at_ms,
        ingested_record_refs,
        projection: ScenarioReplayProjectionV0 {
            host_path,
            saved_captures,
        },
        source_coverage: bundle
            .manifest
            .expected
            .source_coverage
            .iter()
            .filter(|coverage| {
                bundle
                    .manifest
                    .timeline
                    .iter()
                    .position(|candidate| candidate.name == coverage.checkpoint)
                    .is_some_and(|index| index <= target_index)
            })
            .cloned()
            .collect(),
        expected_conclusions: bundle
            .manifest
            .expected
            .conclusions
            .iter()
            .filter(|conclusion| conclusion.checkpoint == target.name)
            .cloned()
            .collect(),
        viewport_assertions: bundle
            .manifest
            .expected
            .viewports
            .iter()
            .filter(|viewport| viewport.checkpoint == target.name)
            .cloned()
            .collect(),
    })
}

fn validate_manifest_shape(
    manifest: &ScenarioManifestV0,
    limits: ScenarioLimitsV0,
) -> Result<(), ScenarioError> {
    if manifest.schema != SCENARIO_BUNDLE_SCHEMA_V0 {
        return Err(ScenarioError::Invalid(format!(
            "unsupported scenario schema {:?}",
            manifest.schema
        )));
    }
    validate_identifier("scenario_id", &manifest.scenario_id)?;
    if manifest.license.trim().is_empty()
        || manifest.provenance.generator.trim().is_empty()
        || manifest.provenance.generator_version.trim().is_empty()
        || manifest.provenance.description.trim().is_empty()
    {
        return Err(ScenarioError::Invalid(
            "license and provenance fields must not be empty".into(),
        ));
    }
    if manifest.artifacts.is_empty() || manifest.artifacts.len() > limits.max_artifacts {
        return Err(ScenarioError::Invalid(format!(
            "scenario must declare 1..={} artifacts",
            limits.max_artifacts
        )));
    }
    if manifest.timeline.is_empty() || manifest.timeline.len() > limits.max_checkpoints {
        return Err(ScenarioError::Invalid(format!(
            "scenario must declare 1..={} checkpoints",
            limits.max_checkpoints
        )));
    }
    if manifest.expected.conclusions.len() > limits.max_conclusions {
        return Err(ScenarioError::Invalid(format!(
            "scenario declares too many conclusions; maximum is {}",
            limits.max_conclusions
        )));
    }

    let mut artifact_ids = BTreeSet::new();
    let mut artifact_paths = BTreeSet::new();
    let mut declared_total_bytes = 0_u64;
    for artifact in &manifest.artifacts {
        validate_identifier("artifact id", &artifact.id)?;
        validate_relative_path(&artifact.path)?;
        if !artifact_ids.insert(artifact.id.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "duplicate artifact id {:?}",
                artifact.id
            )));
        }
        if !artifact_paths.insert(artifact.path.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "duplicate artifact path {:?}",
                artifact.path
            )));
        }
        if artifact.path == MANIFEST_NAME {
            return Err(ScenarioError::Invalid(
                "scenario.json cannot be declared as an artifact".into(),
            ));
        }
        if artifact.bytes > limits.max_artifact_bytes {
            return Err(artifact_error(
                artifact,
                format!(
                    "declares {} bytes; per-artifact maximum is {}",
                    artifact.bytes, limits.max_artifact_bytes
                ),
            ));
        }
        declared_total_bytes = declared_total_bytes
            .checked_add(artifact.bytes)
            .ok_or_else(|| {
                ScenarioError::Invalid("declared artifact byte total overflowed".into())
            })?;
        validate_sha256(&artifact.sha256).map_err(|detail| artifact_error(artifact, detail))?;
        let expected_media = match artifact.role {
            ScenarioArtifactRoleV0::HostPathJsonl | ScenarioArtifactRoleV0::SavedCaptureJsonl => {
                "application/x-ndjson"
            }
            ScenarioArtifactRoleV0::ViewportText => "text/plain",
        };
        if artifact.media_type != expected_media {
            return Err(artifact_error(
                artifact,
                format!(
                    "role {:?} requires media_type {expected_media:?}",
                    artifact.role
                ),
            ));
        }
    }
    if declared_total_bytes > limits.max_total_artifact_bytes {
        return Err(ScenarioError::Invalid(format!(
            "scenario declares {declared_total_bytes} artifact bytes; maximum is {}",
            limits.max_total_artifact_bytes
        )));
    }

    let mut checkpoint_names = BTreeSet::new();
    let mut last_time = None;
    let mut ingested_refs = BTreeSet::new();
    for checkpoint in &manifest.timeline {
        validate_identifier("checkpoint name", &checkpoint.name)?;
        if !checkpoint_names.insert(checkpoint.name.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "duplicate checkpoint name {:?}",
                checkpoint.name
            )));
        }
        if last_time.is_some_and(|last| checkpoint.at_ms <= last) {
            return Err(ScenarioError::Invalid(
                "checkpoint at_ms values must be strictly increasing".into(),
            ));
        }
        last_time = Some(checkpoint.at_ms);
        for reference in &checkpoint.ingest {
            let (artifact_id, _) = split_record_ref(reference)?;
            if !artifact_ids.contains(artifact_id) {
                return Err(ScenarioError::Invalid(format!(
                    "checkpoint {:?} cites unknown artifact {artifact_id:?}",
                    checkpoint.name
                )));
            }
            if !ingested_refs.insert(reference.as_str()) {
                return Err(ScenarioError::Invalid(format!(
                    "record reference {reference:?} is ingested more than once"
                )));
            }
        }
    }

    let mut coverage_ids = BTreeSet::new();
    let mut coverage_scopes = BTreeSet::new();
    for coverage in &manifest.expected.source_coverage {
        validate_identifier("coverage id", &coverage.id)?;
        if !coverage_ids.insert(coverage.id.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "duplicate source coverage id {:?}",
                coverage.id
            )));
        }
        if !checkpoint_names.contains(coverage.checkpoint.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "coverage {:?} names unknown checkpoint {:?}",
                coverage.id, coverage.checkpoint
            )));
        }
        if coverage.source.trim().is_empty() {
            return Err(ScenarioError::Invalid(format!(
                "coverage {:?} has an empty source",
                coverage.id
            )));
        }
        if !coverage_scopes.insert((coverage.checkpoint.as_str(), coverage.source.as_str())) {
            return Err(ScenarioError::Invalid(format!(
                "checkpoint {:?} declares source {:?} coverage more than once",
                coverage.checkpoint, coverage.source
            )));
        }
        match (coverage.state, coverage.freshness) {
            (ScenarioCoverageStateV0::Unavailable, ScenarioCoverageFreshnessV0::Current)
            | (
                ScenarioCoverageStateV0::Complete | ScenarioCoverageStateV0::Partial,
                ScenarioCoverageFreshnessV0::NotObserved,
            ) => {
                return Err(ScenarioError::Invalid(format!(
                    "coverage {:?} has contradictory state/freshness",
                    coverage.id
                )));
            }
            _ => {}
        }
        if matches!(
            coverage.freshness,
            ScenarioCoverageFreshnessV0::Stale | ScenarioCoverageFreshnessV0::NotObserved
        ) && coverage
            .limitation
            .as_deref()
            .is_none_or(|value| value.trim().is_empty())
        {
            return Err(ScenarioError::Invalid(format!(
                "non-current coverage {:?} requires a limitation",
                coverage.id
            )));
        }
        if matches!(
            (coverage.state, coverage.freshness),
            (
                ScenarioCoverageStateV0::Complete | ScenarioCoverageStateV0::Partial,
                ScenarioCoverageFreshnessV0::Current
            )
        ) && coverage.evidence.is_empty()
        {
            return Err(ScenarioError::Invalid(format!(
                "current observed coverage {:?} requires evidence",
                coverage.id
            )));
        }
    }

    let mut conclusion_ids = BTreeSet::new();
    for conclusion in &manifest.expected.conclusions {
        validate_identifier("conclusion id", &conclusion.id)?;
        if !conclusion_ids.insert(conclusion.id.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "duplicate conclusion id {:?}",
                conclusion.id
            )));
        }
        if !checkpoint_names.contains(conclusion.checkpoint.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "conclusion {:?} names unknown checkpoint {:?}",
                conclusion.id, conclusion.checkpoint
            )));
        }
        if conclusion.question.trim().is_empty() || conclusion.conclusion.trim().is_empty() {
            return Err(ScenarioError::Invalid(format!(
                "conclusion {:?} requires a question and conclusion",
                conclusion.id
            )));
        }
        if conclusion.evidence.is_empty()
            || conclusion.coverage.is_empty()
            || conclusion.limitations.is_empty()
        {
            return Err(ScenarioError::Invalid(format!(
                "conclusion {:?} must cite evidence, coverage, and limitations",
                conclusion.id
            )));
        }
        for coverage in &conclusion.coverage {
            if !coverage_ids.contains(coverage.as_str()) {
                return Err(ScenarioError::Invalid(format!(
                    "conclusion {:?} cites unknown coverage {:?}",
                    conclusion.id, coverage
                )));
            }
        }
        match conclusion.disposition {
            ScenarioConclusionDispositionV0::Abstained
                if conclusion
                    .reason
                    .as_deref()
                    .is_none_or(|value| value.trim().is_empty()) =>
            {
                return Err(ScenarioError::Invalid(format!(
                    "abstained conclusion {:?} requires a reason",
                    conclusion.id
                )));
            }
            ScenarioConclusionDispositionV0::Supported
            | ScenarioConclusionDispositionV0::Abstained => {}
        }
    }

    for viewport in &manifest.expected.viewports {
        if !checkpoint_names.contains(viewport.checkpoint.as_str()) {
            return Err(ScenarioError::Invalid(format!(
                "viewport names unknown checkpoint {:?}",
                viewport.checkpoint
            )));
        }
        let Some(artifact) = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.id == viewport.artifact)
        else {
            return Err(ScenarioError::Invalid(format!(
                "viewport names unknown artifact {:?}",
                viewport.artifact
            )));
        };
        if artifact.role != ScenarioArtifactRoleV0::ViewportText {
            return Err(artifact_error(
                artifact,
                "viewport assertion must reference a viewport_text artifact",
            ));
        }
        let cells = u64::from(viewport.width) * u64::from(viewport.height);
        if viewport.width == 0 || viewport.height == 0 || cells > limits.max_viewport_cells {
            return Err(ScenarioError::Invalid(format!(
                "viewport {}x{} is outside the configured cell bound",
                viewport.width, viewport.height
            )));
        }
    }
    Ok(())
}

fn validate_artifact(
    artifact: &ScenarioArtifactV0,
    bytes: Vec<u8>,
    _limits: ScenarioLimitsV0,
) -> Result<LoadedArtifactV0, ScenarioError> {
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes != artifact.bytes {
        return Err(artifact_error(
            artifact,
            format!(
                "byte count mismatch: declared {}, actual {actual_bytes}",
                artifact.bytes
            ),
        ));
    }
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    if digest != artifact.sha256 {
        return Err(artifact_error(
            artifact,
            format!(
                "digest mismatch: declared {}, actual {digest}",
                artifact.sha256
            ),
        ));
    }
    let records = match artifact.role {
        ScenarioArtifactRoleV0::HostPathJsonl => {
            let replay = parse_host_path_jsonl(&bytes)
                .map_err(|source| artifact_error(artifact, source.to_string()))?;
            validate_canonical_host_path_jsonl(artifact, &bytes, &replay)?;
            replay
                .records
                .into_iter()
                .map(|record| {
                    (
                        record.record_id.clone(),
                        LoadedRecordV0::HostPath(Box::new(record)),
                    )
                })
                .collect()
        }
        ScenarioArtifactRoleV0::SavedCaptureJsonl => {
            let stream = parse_saved_capture_jsonl(&bytes)
                .map_err(|source| artifact_error(artifact, source.to_string()))?;
            saved_capture_records(&stream)
        }
        ScenarioArtifactRoleV0::ViewportText => {
            validate_viewport_bytes(artifact, &bytes)?;
            BTreeMap::new()
        }
    };
    Ok(LoadedArtifactV0 { bytes, records })
}

fn validate_canonical_host_path_jsonl(
    artifact: &ScenarioArtifactV0,
    bytes: &[u8],
    replay: &ReplayStateV0,
) -> Result<(), ScenarioError> {
    let replay_by_id = replay
        .records
        .iter()
        .map(|record| (record.record_id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(line).map_err(|source| {
            artifact_error(
                artifact,
                format!("invalid host-path JSON on line {}: {source}", index + 1),
            )
        })?;
        let record_id = value
            .get("record_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                artifact_error(
                    artifact,
                    format!(
                        "host-path record on line {} has no string record_id",
                        index + 1
                    ),
                )
            })?;
        if !seen.insert(record_id.to_owned()) {
            return Err(artifact_error(
                artifact,
                format!("host-path record_id {record_id:?} occurs more than once"),
            ));
        }
        let record = replay_by_id.get(record_id).ok_or_else(|| {
            artifact_error(
                artifact,
                format!("host-path record {record_id:?} was not retained by strict replay"),
            )
        })?;
        let canonical = serde_json::to_value(record).map_err(|source| {
            artifact_error(
                artifact,
                format!("serializing host-path record {record_id:?}: {source}"),
            )
        })?;
        if canonical != value {
            return Err(artifact_error(
                artifact,
                format!(
                    "host-path record {record_id:?} has unknown, noncanonical, or redundant fields"
                ),
            ));
        }
    }
    if seen.len() != replay_by_id.len() {
        return Err(artifact_error(
            artifact,
            "host-path record inventory differs from strict replay",
        ));
    }
    Ok(())
}

fn finish_bundle(
    manifest: ScenarioManifestV0,
    manifest_bytes: &[u8],
    artifacts: BTreeMap<String, LoadedArtifactV0>,
    _limits: ScenarioLimitsV0,
) -> Result<ScenarioBundleV0, ScenarioError> {
    let available_refs = artifacts
        .iter()
        .flat_map(|(artifact_id, artifact)| {
            artifact
                .records
                .keys()
                .map(move |record_id| format!("{artifact_id}#{record_id}"))
        })
        .collect::<BTreeSet<_>>();
    for reference in &available_refs {
        split_record_ref(reference)?;
    }
    let ingested_refs = manifest
        .timeline
        .iter()
        .flat_map(|checkpoint| checkpoint.ingest.iter().cloned())
        .collect::<BTreeSet<_>>();
    if available_refs != ingested_refs {
        return Err(ScenarioError::Invalid(format!(
            "scenario record inventory mismatch; unreferenced={:?}, unknown={:?}",
            available_refs
                .difference(&ingested_refs)
                .collect::<Vec<_>>(),
            ingested_refs
                .difference(&available_refs)
                .collect::<Vec<_>>()
        )));
    }

    let checkpoint_order = manifest
        .timeline
        .iter()
        .enumerate()
        .map(|(index, checkpoint)| (checkpoint.name.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let ingest_order = manifest
        .timeline
        .iter()
        .enumerate()
        .flat_map(|(index, checkpoint)| {
            checkpoint
                .ingest
                .iter()
                .map(move |reference| (reference.as_str(), index))
        })
        .collect::<BTreeMap<_, _>>();
    for artifact in manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.role == ScenarioArtifactRoleV0::SavedCaptureJsonl)
    {
        let ingestion_checkpoints = artifacts[&artifact.id]
            .records
            .keys()
            .filter_map(|record| {
                let reference = format!("{}#{record}", artifact.id);
                ingest_order.get(reference.as_str()).copied()
            })
            .collect::<BTreeSet<_>>();
        if ingestion_checkpoints.len() != 1 {
            return Err(artifact_error(
                artifact,
                "saved-capture records must be ingested atomically at one checkpoint",
            ));
        }
    }
    for coverage in &manifest.expected.source_coverage {
        let checkpoint_index = checkpoint_order[coverage.checkpoint.as_str()];
        validate_evidence_availability(
            &coverage.evidence,
            checkpoint_index,
            &ingest_order,
            &format!("coverage {:?}", coverage.id),
        )?;
    }
    for conclusion in &manifest.expected.conclusions {
        let checkpoint_index = checkpoint_order[conclusion.checkpoint.as_str()];
        validate_evidence_availability(
            &conclusion.evidence,
            checkpoint_index,
            &ingest_order,
            &format!("conclusion {:?}", conclusion.id),
        )?;
        for coverage_id in &conclusion.coverage {
            let coverage = manifest
                .expected
                .source_coverage
                .iter()
                .find(|coverage| coverage.id == *coverage_id)
                .expect("coverage references validated");
            if checkpoint_order[coverage.checkpoint.as_str()] > checkpoint_index {
                return Err(ScenarioError::Invalid(format!(
                    "conclusion {:?} cites future coverage {:?}",
                    conclusion.id, coverage_id
                )));
            }
        }
    }
    for viewport in &manifest.expected.viewports {
        let artifact = artifacts
            .get(&viewport.artifact)
            .expect("viewport artifact validated");
        validate_viewport_dimensions(viewport, &artifact.bytes)?;
    }

    Ok(ScenarioBundleV0 {
        manifest,
        manifest_sha256: format!("sha256:{:x}", Sha256::digest(manifest_bytes)),
        artifacts,
    })
}

fn validate_evidence_availability(
    references: &[String],
    checkpoint_index: usize,
    ingest_order: &BTreeMap<&str, usize>,
    owner: &str,
) -> Result<(), ScenarioError> {
    for reference in references {
        let Some(ingested_at) = ingest_order.get(reference.as_str()) else {
            return Err(ScenarioError::Invalid(format!(
                "{owner} cites unknown evidence {reference:?}"
            )));
        };
        if *ingested_at > checkpoint_index {
            return Err(ScenarioError::Invalid(format!(
                "{owner} cites future evidence {reference:?}"
            )));
        }
    }
    Ok(())
}

fn saved_capture_records(stream: &SavedCaptureRecordStreamV0) -> BTreeMap<String, LoadedRecordV0> {
    let mut records = BTreeMap::new();
    records.insert("manifest".into(), LoadedRecordV0::SavedCapture);
    if stream.receipt.is_some() {
        records.insert("receipt".into(), LoadedRecordV0::SavedCapture);
    }
    for packet in &stream.packets {
        records.insert(
            format!("frame:{}", packet.frame.number),
            LoadedRecordV0::SavedCapture,
        );
    }
    for quarantine in &stream.quarantines {
        records.insert(
            format!("quarantine:{}", quarantine.source_line),
            LoadedRecordV0::SavedCapture,
        );
    }
    records
}

fn project_host_path(replay: &ReplayStateV0) -> ScenarioReplayHostPathV0 {
    let exact_context_keys = replay
        .records
        .iter()
        .map(crate::HostPathObservationV0::context_key)
        .collect::<BTreeSet<_>>()
        .len();
    let confirmed_context_transitions = replay
        .transitions
        .iter()
        .filter(|transition| transition.relation == ContextRelationV0::ContextChanged)
        .count();
    let compatible_incomplete_transitions = replay
        .transitions
        .iter()
        .filter(|transition| transition.relation == ContextRelationV0::CompatibleContext)
        .count();
    ScenarioReplayHostPathV0 {
        records: replay.records.len().try_into().unwrap_or(u64::MAX),
        exact_context_keys: exact_context_keys.try_into().unwrap_or(u64::MAX),
        confirmed_context_transitions: confirmed_context_transitions.try_into().unwrap_or(u64::MAX),
        compatible_incomplete_transitions: compatible_incomplete_transitions
            .try_into()
            .unwrap_or(u64::MAX),
        latest_record_id: replay
            .records
            .last()
            .expect("non-empty host replay")
            .record_id
            .clone(),
    }
}

fn project_saved_capture(
    artifact_id: &str,
    bytes: &[u8],
) -> Result<ScenarioSavedCaptureProjectionV0, ScenarioError> {
    let stream = parse_saved_capture_jsonl(bytes).map_err(|source| ScenarioError::Artifact {
        artifact: artifact_id.into(),
        detail: source.to_string(),
    })?;
    Ok(ScenarioSavedCaptureProjectionV0 {
        artifact: artifact_id.into(),
        capture_id: stream.manifest.capture_id,
        normalized_records_sha256: stream.normalized_records_sha256,
        packet_records: stream.packets.len().try_into().unwrap_or(u64::MAX),
        quarantine_records: stream.quarantines.len().try_into().unwrap_or(u64::MAX),
    })
}

fn validate_viewport_bytes(
    artifact: &ScenarioArtifactV0,
    bytes: &[u8],
) -> Result<(), ScenarioError> {
    if !bytes.is_ascii() {
        return Err(artifact_error(artifact, "viewport text must be ASCII"));
    }
    if bytes.contains(&0x1b) {
        return Err(artifact_error(
            artifact,
            "viewport text must not contain ANSI escape bytes",
        ));
    }
    if bytes.contains(&b'\r') {
        return Err(artifact_error(
            artifact,
            "viewport text must use LF line endings",
        ));
    }
    if bytes
        .iter()
        .any(|byte| *byte != b'\n' && !matches!(*byte, b' '..=b'~'))
    {
        return Err(artifact_error(
            artifact,
            "viewport text may contain only printable ASCII cells and LF",
        ));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(artifact_error(
            artifact,
            "viewport text must end with a newline",
        ));
    }
    Ok(())
}

fn validate_viewport_dimensions(
    viewport: &ScenarioViewportAssertionV0,
    bytes: &[u8],
) -> Result<(), ScenarioError> {
    let text = std::str::from_utf8(bytes).expect("ASCII validated");
    let rows = text.lines().collect::<Vec<_>>();
    if rows.len() != usize::from(viewport.height) {
        return Err(ScenarioError::Invalid(format!(
            "viewport artifact {:?} declares height {} but has {} rows",
            viewport.artifact,
            viewport.height,
            rows.len()
        )));
    }
    if let Some((line, width)) = rows
        .iter()
        .enumerate()
        .map(|(index, row)| (index + 1, row.len()))
        .find(|(_, width)| *width > usize::from(viewport.width))
    {
        return Err(ScenarioError::Invalid(format!(
            "viewport artifact {:?} line {line} is {width} cells, exceeding width {}",
            viewport.artifact, viewport.width
        )));
    }
    Ok(())
}

fn collect_files(
    root: &Path,
    max_inventory_entries: usize,
) -> Result<BTreeSet<String>, ScenarioError> {
    let mut files = BTreeSet::new();
    let mut pending = vec![root.to_owned()];
    let mut entries_seen = 0_usize;
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| ScenarioError::Io {
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            entries_seen = entries_seen.saturating_add(1);
            if entries_seen > max_inventory_entries {
                return Err(ScenarioError::Invalid(format!(
                    "scenario inventory exceeds the {max_inventory_entries}-entry bound"
                )));
            }
            let entry = entry.map_err(|source| ScenarioError::Io {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| ScenarioError::Io {
                path: path.clone(),
                source,
            })?;
            if metadata.file_type().is_symlink() {
                return Err(ScenarioError::Invalid(format!(
                    "scenario inventory contains symlink {}",
                    path.display()
                )));
            }
            if metadata.file_type().is_dir() {
                return Err(ScenarioError::Invalid(format!(
                    "scenario inventory contains nested directory {}",
                    path.display()
                )));
            } else if metadata.file_type().is_file() {
                let relative = path
                    .strip_prefix(root)
                    .expect("walked path remains under root")
                    .to_string_lossy()
                    .replace(std::path::MAIN_SEPARATOR, "/");
                files.insert(relative);
            } else {
                return Err(ScenarioError::Invalid(format!(
                    "scenario inventory contains non-file {}",
                    path.display()
                )));
            }
        }
    }
    Ok(files)
}

fn split_record_ref(reference: &str) -> Result<(&str, &str), ScenarioError> {
    let Some((artifact, record)) = reference.split_once('#') else {
        return Err(ScenarioError::Invalid(format!(
            "record reference {reference:?} must be artifact#record"
        )));
    };
    if artifact.is_empty() || record.is_empty() || record.contains('#') {
        return Err(ScenarioError::Invalid(format!(
            "invalid record reference {reference:?}"
        )));
    }
    Ok((artifact, record))
}

fn validate_relative_path(path: &str) -> Result<(), ScenarioError> {
    if path.is_empty() || path.len() > 512 || path.contains('\\') {
        return Err(ScenarioError::Invalid(format!(
            "artifact path {path:?} is not a normalized relative path"
        )));
    }
    let parsed = Path::new(path);
    let components = parsed.components().collect::<Vec<_>>();
    if parsed.is_absolute()
        || components.len() != 1
        || components
            .iter()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ScenarioError::Invalid(format!(
            "artifact path {path:?} is not a safe normalized relative path"
        )));
    }
    Ok(())
}

struct ScenarioDirectoryV0 {
    path: PathBuf,
    #[cfg(unix)]
    handle: fs::File,
}

impl ScenarioDirectoryV0 {
    fn open(path: &Path) -> Result<Self, ScenarioError> {
        let metadata = fs::symlink_metadata(path).map_err(|source| ScenarioError::Io {
            path: path.to_owned(),
            source,
        })?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(ScenarioError::Invalid(
                "scenario root must be a real directory, not a symlink".into(),
            ));
        }

        #[cfg(unix)]
        let handle = {
            use std::os::unix::fs::OpenOptionsExt;

            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
            let handle = options.open(path).map_err(|source| ScenarioError::Io {
                path: path.to_owned(),
                source,
            })?;
            if !handle
                .metadata()
                .map_err(|source| ScenarioError::Io {
                    path: path.to_owned(),
                    source,
                })?
                .is_dir()
            {
                return Err(ScenarioError::Invalid(
                    "opened scenario root is not a directory".into(),
                ));
            }
            handle
        };

        Ok(Self {
            path: path.to_owned(),
            #[cfg(unix)]
            handle,
        })
    }

    fn open_regular_file(
        &self,
        relative: &Path,
    ) -> Result<(fs::File, PathBuf, u64), ScenarioError> {
        let path = self.path.join(relative);
        #[cfg(unix)]
        let file = {
            use std::ffi::CString;
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::ffi::OsStrExt;

            let relative = CString::new(relative.as_os_str().as_bytes()).map_err(|_| {
                ScenarioError::Invalid(format!(
                    "scenario file path {} contains a NUL byte",
                    path.display()
                ))
            })?;
            // SAFETY: `relative` is a live NUL-terminated string; `openat`
            // returns a new owned descriptor on success, transferred exactly
            // once into `File`.
            let descriptor = unsafe {
                libc::openat(
                    self.handle.as_raw_fd(),
                    relative.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(ScenarioError::Io {
                    path,
                    source: std::io::Error::last_os_error(),
                });
            }
            // SAFETY: successful `openat` returned a fresh owned descriptor.
            unsafe { fs::File::from_raw_fd(descriptor) }
        };
        #[cfg(not(unix))]
        let file = {
            let mut options = OpenOptions::new();
            options.read(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;

                // Bind the open to the reparse point itself so the metadata
                // check below rejects it rather than following it.
                const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
                options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
            }
            options.open(&path).map_err(|source| ScenarioError::Io {
                path: path.clone(),
                source,
            })?
        };

        let metadata = file.metadata().map_err(|source| ScenarioError::Io {
            path: path.clone(),
            source,
        })?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(ScenarioError::Invalid(format!(
                "{} is not an opened regular file",
                path.display()
            )));
        }
        Ok((file, path, metadata.len()))
    }
}

fn read_bounded_open_file(
    file: fs::File,
    path: &Path,
    max_bytes: u64,
) -> Result<Vec<u8>, ScenarioError> {
    let metadata = file.metadata().map_err(|source| ScenarioError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(ScenarioError::Invalid(format!(
            "{} is not an opened regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ScenarioError::Io {
            path: path.to_owned(),
            source,
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(ScenarioError::Invalid(format!(
            "{} exceeds the {max_bytes}-byte read bound",
            path.display()
        )));
    }
    Ok(bytes)
}

#[cfg(all(test, unix))]
mod nofollow_tests {
    use std::os::unix::fs::symlink;

    use super::ScenarioDirectoryV0;

    #[test]
    fn bounded_reader_never_follows_a_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("outside");
        let link = directory.path().join("artifact");
        std::fs::write(&target, b"outside bytes").unwrap();
        symlink(&target, &link).unwrap();

        let root = ScenarioDirectoryV0::open(directory.path()).unwrap();
        let error = root
            .open_regular_file(std::path::Path::new(link.file_name().unwrap()))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Too many levels of symbolic links")
                || error.to_string().contains("not an opened regular file")
        );
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), ScenarioError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(ScenarioError::Invalid(format!(
            "{field} {value:?} must use 1..=128 ASCII letters, digits, '.', '-', or '_'"
        )));
    }
    Ok(())
}

fn validate_sha256(value: &str) -> Result<(), String> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err("sha256 must use the sha256:<64 lowercase hex> form".into());
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err("sha256 must use the sha256:<64 lowercase hex> form".into());
    }
    Ok(())
}

fn artifact_error(artifact: &ScenarioArtifactV0, detail: impl Into<String>) -> ScenarioError {
    ScenarioError::Artifact {
        artifact: artifact.id.clone(),
        detail: detail.into(),
    }
}

#[cfg(feature = "scenario-fixtures")]
pub fn builtin_scenario_ids_v0() -> &'static [&'static str] {
    &[
        "wifi-hotspot-wifi",
        "vpn-overlay-transition",
        "cache-source-gap",
    ]
}

#[cfg(feature = "scenario-fixtures")]
pub fn builtin_scenario_v0(id: &str) -> Result<ScenarioBundleV0, ScenarioError> {
    let (manifest_bytes, artifact_bytes): (&[u8], &[(&str, &[u8])]) = match id {
        "wifi-hotspot-wifi" => (
            include_bytes!("../tests/fixtures/scenarios/wifi-hotspot-wifi/scenario.json"),
            &[
                (
                    "host-path.jsonl",
                    include_bytes!("../tests/fixtures/scenarios/wifi-hotspot-wifi/host-path.jsonl"),
                ),
                (
                    "viewport.txt",
                    include_bytes!("../tests/fixtures/scenarios/wifi-hotspot-wifi/viewport.txt"),
                ),
            ],
        ),
        "vpn-overlay-transition" => (
            include_bytes!("../tests/fixtures/scenarios/vpn-overlay-transition/scenario.json"),
            &[
                (
                    "host-path.jsonl",
                    include_bytes!(
                        "../tests/fixtures/scenarios/vpn-overlay-transition/host-path.jsonl"
                    ),
                ),
                (
                    "viewport.txt",
                    include_bytes!(
                        "../tests/fixtures/scenarios/vpn-overlay-transition/viewport.txt"
                    ),
                ),
            ],
        ),
        "cache-source-gap" => (
            include_bytes!("../tests/fixtures/scenarios/cache-source-gap/scenario.json"),
            &[
                (
                    "host-path.jsonl",
                    include_bytes!("../tests/fixtures/scenarios/cache-source-gap/host-path.jsonl"),
                ),
                (
                    "viewport.txt",
                    include_bytes!("../tests/fixtures/scenarios/cache-source-gap/viewport.txt"),
                ),
            ],
        ),
        _ => {
            return Err(ScenarioError::Invalid(format!(
                "unknown built-in scenario {id:?}"
            )));
        }
    };
    load_scenario_bundle_from_memory_v0(manifest_bytes, artifact_bytes, ScenarioLimitsV0::default())
}

#[cfg(feature = "scenario-fixtures")]
fn load_scenario_bundle_from_memory_v0(
    manifest_bytes: &[u8],
    artifact_bytes: &[(&str, &[u8])],
    limits: ScenarioLimitsV0,
) -> Result<ScenarioBundleV0, ScenarioError> {
    let manifest_len = u64::try_from(manifest_bytes.len()).unwrap_or(u64::MAX);
    if manifest_len > limits.max_manifest_bytes {
        return Err(ScenarioError::ManifestTooLarge {
            bytes: manifest_len,
            max_bytes: limits.max_manifest_bytes,
        });
    }
    let manifest: ScenarioManifestV0 =
        serde_json::from_slice(manifest_bytes).map_err(ScenarioError::ManifestJson)?;
    validate_manifest_shape(&manifest, limits)?;
    let supplied = artifact_bytes
        .iter()
        .map(|(path, bytes)| ((*path).to_owned(), *bytes))
        .collect::<BTreeMap<_, _>>();
    let expected = manifest
        .artifacts
        .iter()
        .map(|artifact| artifact.path.clone())
        .collect::<BTreeSet<_>>();
    if supplied.keys().cloned().collect::<BTreeSet<_>>() != expected {
        return Err(ScenarioError::Invalid(
            "built-in scenario artifact inventory mismatch".into(),
        ));
    }
    let mut total = 0_u64;
    let mut loaded = BTreeMap::new();
    for artifact in &manifest.artifacts {
        let bytes = supplied[&artifact.path];
        total = total
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| ScenarioError::Invalid("artifact byte total overflowed".into()))?;
        if total > limits.max_total_artifact_bytes {
            return Err(ScenarioError::Invalid(
                "built-in scenario exceeds total artifact byte limit".into(),
            ));
        }
        loaded.insert(
            artifact.id.clone(),
            validate_artifact(artifact, bytes.to_vec(), limits)?,
        );
    }
    finish_bundle(manifest, manifest_bytes, loaded, limits)
}
