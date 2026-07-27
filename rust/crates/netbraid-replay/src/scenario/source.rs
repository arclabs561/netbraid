//! Typed, private handlers for artifacts admitted by scenario manifests.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};

use super::{ArtifactDescriptor, ArtifactKind, ScenarioError, ScenarioSavedCaptureProjectionV0};
use crate::{parse_host_path_jsonl, parse_saved_capture_jsonl, SavedCaptureRecordStreamV0};

#[derive(Debug, Clone)]
pub(super) struct LoadedArtifact {
    source: LoadedSource,
}

#[derive(Debug, Clone)]
enum LoadedSource {
    HostPath(HostPathSource),
    SavedCapture(SavedCaptureSource),
    ViewportText(Vec<u8>),
    LicenseText,
}

#[derive(Debug, Clone)]
struct HostPathSource {
    records: BTreeMap<String, crate::HostPathObservationV0>,
}

#[derive(Debug, Clone)]
struct SavedCaptureSource {
    stream: Box<SavedCaptureRecordStreamV0>,
    record_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
pub(super) enum LoadedRecord<'a> {
    HostPath(&'a crate::HostPathObservationV0),
    SavedCapture,
}

impl LoadedArtifact {
    pub(super) fn viewport_text(&self) -> Option<&[u8]> {
        match &self.source {
            LoadedSource::ViewportText(bytes) => Some(bytes),
            LoadedSource::HostPath(_)
            | LoadedSource::SavedCapture(_)
            | LoadedSource::LicenseText => None,
        }
    }

    pub(super) fn record_ids(&self) -> Vec<&str> {
        match &self.source {
            LoadedSource::HostPath(source) => source.records.keys().map(String::as_str).collect(),
            LoadedSource::SavedCapture(source) => {
                source.record_ids.iter().map(String::as_str).collect()
            }
            LoadedSource::ViewportText(_) | LoadedSource::LicenseText => Vec::new(),
        }
    }

    pub(super) fn record(&self, record_id: &str) -> Option<LoadedRecord<'_>> {
        match &self.source {
            LoadedSource::HostPath(source) => {
                source.records.get(record_id).map(LoadedRecord::HostPath)
            }
            LoadedSource::SavedCapture(source) if source.record_ids.contains(record_id) => {
                Some(LoadedRecord::SavedCapture)
            }
            LoadedSource::SavedCapture(_)
            | LoadedSource::ViewportText(_)
            | LoadedSource::LicenseText => None,
        }
    }

    pub(super) fn saved_capture(&self) -> Option<&SavedCaptureRecordStreamV0> {
        match &self.source {
            LoadedSource::SavedCapture(source) => Some(&source.stream),
            LoadedSource::HostPath(_)
            | LoadedSource::ViewportText(_)
            | LoadedSource::LicenseText => None,
        }
    }

    pub(super) fn saved_capture_projection(
        &self,
        artifact_id: &str,
    ) -> Option<ScenarioSavedCaptureProjectionV0> {
        let stream = self.saved_capture()?;
        Some(ScenarioSavedCaptureProjectionV0 {
            artifact: artifact_id.into(),
            capture_id: stream.manifest.capture_id.clone(),
            normalized_records_sha256: stream.normalized_records_sha256.clone(),
            packet_records: stream.packets.len().try_into().unwrap_or(u64::MAX),
            quarantine_records: stream.quarantines.len().try_into().unwrap_or(u64::MAX),
        })
    }
}

pub(super) fn load_artifact(
    artifact: ArtifactDescriptor<'_>,
    bytes: Vec<u8>,
) -> Result<LoadedArtifact, ScenarioError> {
    let actual_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    if actual_bytes != artifact.bytes {
        return Err(artifact.error(format!(
            "byte count mismatch: declared {}, actual {actual_bytes}",
            artifact.bytes
        )));
    }
    let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
    if digest != artifact.sha256 {
        return Err(artifact.error(format!(
            "digest mismatch: declared {}, actual {digest}",
            artifact.sha256
        )));
    }

    let source = match artifact.kind {
        ArtifactKind::HostPathJsonl => load_host_path(artifact, &bytes)?,
        ArtifactKind::SavedCaptureJsonl => load_saved_capture(artifact, &bytes)?,
        ArtifactKind::ViewportText => {
            validate_viewport_bytes(artifact, &bytes)?;
            LoadedSource::ViewportText(bytes)
        }
        ArtifactKind::LicenseText => {
            validate_license_text_bytes(artifact, &bytes)?;
            LoadedSource::LicenseText
        }
    };

    Ok(LoadedArtifact { source })
}

fn load_host_path(
    artifact: ArtifactDescriptor<'_>,
    bytes: &[u8],
) -> Result<LoadedSource, ScenarioError> {
    let replay =
        parse_host_path_jsonl(bytes).map_err(|source| artifact.error(source.to_string()))?;
    validate_canonical_host_path_jsonl(artifact, bytes, &replay.records)?;
    let records = replay
        .records
        .into_iter()
        .map(|record| (record.record_id.clone(), record))
        .collect::<BTreeMap<_, _>>();
    Ok(LoadedSource::HostPath(HostPathSource { records }))
}

fn load_saved_capture(
    artifact: ArtifactDescriptor<'_>,
    bytes: &[u8],
) -> Result<LoadedSource, ScenarioError> {
    let stream =
        parse_saved_capture_jsonl(bytes).map_err(|source| artifact.error(source.to_string()))?;
    let mut record_ids = BTreeSet::from(["manifest".into()]);
    if stream.receipt.is_some() {
        record_ids.insert("receipt".into());
    }
    record_ids.extend(
        stream
            .packets
            .iter()
            .map(|packet| format!("frame:{}", packet.frame.number)),
    );
    record_ids.extend(
        stream
            .quarantines
            .iter()
            .map(|quarantine| format!("quarantine:{}", quarantine.source_line)),
    );
    Ok(LoadedSource::SavedCapture(SavedCaptureSource {
        stream: Box::new(stream),
        record_ids,
    }))
}

fn validate_canonical_host_path_jsonl(
    artifact: ArtifactDescriptor<'_>,
    bytes: &[u8],
    records: &[crate::HostPathObservationV0],
) -> Result<(), ScenarioError> {
    let replay_by_id = records
        .iter()
        .map(|record| (record.record_id.as_str(), record))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for (index, line) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let value: serde_json::Value = serde_json::from_slice(line).map_err(|source| {
            artifact.error(format!(
                "invalid host-path JSON on line {}: {source}",
                index + 1
            ))
        })?;
        let record_id = value
            .get("record_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                artifact.error(format!(
                    "host-path record on line {} has no string record_id",
                    index + 1
                ))
            })?;
        if !seen.insert(record_id.to_owned()) {
            return Err(artifact.error(format!(
                "host-path record_id {record_id:?} occurs more than once"
            )));
        }
        let record = replay_by_id.get(record_id).ok_or_else(|| {
            artifact.error(format!(
                "host-path record {record_id:?} was not retained by strict replay"
            ))
        })?;
        let canonical = serde_json::to_value(record).map_err(|source| {
            artifact.error(format!(
                "serializing host-path record {record_id:?}: {source}"
            ))
        })?;
        if canonical != value {
            return Err(artifact.error(format!(
                "host-path record {record_id:?} has unknown, noncanonical, or redundant fields"
            )));
        }
    }
    if seen.len() != replay_by_id.len() {
        return Err(artifact.error("host-path record inventory differs from strict replay"));
    }
    Ok(())
}

fn validate_viewport_bytes(
    artifact: ArtifactDescriptor<'_>,
    bytes: &[u8],
) -> Result<(), ScenarioError> {
    if !bytes.is_ascii() {
        return Err(artifact.error("viewport text must be ASCII"));
    }
    if bytes.contains(&0x1b) {
        return Err(artifact.error("viewport text must not contain ANSI escape bytes"));
    }
    if bytes.contains(&b'\r') {
        return Err(artifact.error("viewport text must use LF line endings"));
    }
    if bytes
        .iter()
        .any(|byte| *byte != b'\n' && !matches!(*byte, b' '..=b'~'))
    {
        return Err(artifact.error("viewport text may contain only printable ASCII cells and LF"));
    }
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(artifact.error("viewport text must end with a newline"));
    }
    Ok(())
}

fn validate_license_text_bytes(
    artifact: ArtifactDescriptor<'_>,
    bytes: &[u8],
) -> Result<(), ScenarioError> {
    if bytes.is_empty() {
        return Err(artifact.error("license text must not be empty"));
    }
    std::str::from_utf8(bytes).map_err(|_| artifact.error("license text must be UTF-8"))?;
    if bytes.contains(&b'\0') || bytes.contains(&b'\r') {
        return Err(artifact.error("license text must use NUL-free LF line endings"));
    }
    if !bytes.ends_with(b"\n") {
        return Err(artifact.error("license text must end with an LF"));
    }
    Ok(())
}
