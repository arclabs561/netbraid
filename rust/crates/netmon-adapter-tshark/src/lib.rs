//! Bounded, offline normalization of saved captures through TShark.
//!
//! This crate does not capture live traffic. It invokes TShark without a shell,
//! disables name resolution, selects a fixed field registry, and returns typed
//! evidence plus explicit quarantines.

mod capinfos;
mod fields;
mod process;

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, SystemTimeError, UNIX_EPOCH};

use capinfos::{argument_template as capinfos_argument_template, parse_table};
pub use fields::FIELD_REGISTRY_ID;
use fields::{parse_rows, FIELDS};
use netmon_evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0, CaptureNormalizationV0,
    CaptureRunReceiptV0, CollectionPolicyV0, NormalizationStateV0, PacketEnvelopeV0,
    PacketQuarantineV0, ToolRunReceiptV0, CAPTURE_MANIFEST_SCHEMA_V0,
    CAPTURE_RUN_RECEIPT_SCHEMA_V0, NORMALIZED_RECORDS_DIGEST_PROFILE_V0,
};
use process::run_bounded;
pub use process::ProcessError;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

pub const DEFAULT_PACKET_LIMIT: usize = 100_000;
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_MAX_STDOUT_BYTES: usize = 128 * 1024 * 1024;
pub const DEFAULT_MAX_STDERR_BYTES: usize = 1024 * 1024;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
pub const WIRESHARK_ENVIRONMENT_POLICY_ID: &str = "netmon.wireshark.environment.v0";

static RUN_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct NormalizeOptions {
    pub tshark_path: PathBuf,
    pub capinfos_path: PathBuf,
    pub observer_id: Option<String>,
    pub acquired_time_unix_ms: Option<i64>,
    pub acquisition_policy: Option<CollectionPolicyV0>,
    pub allow_personal_plugins: bool,
    pub packet_limit: usize,
    pub max_input_bytes: u64,
    pub max_stdout_bytes: usize,
    pub max_stderr_bytes: usize,
    pub timeout: Duration,
}

impl Default for NormalizeOptions {
    fn default() -> Self {
        Self {
            tshark_path: PathBuf::from("tshark"),
            capinfos_path: PathBuf::from("capinfos"),
            observer_id: None,
            acquired_time_unix_ms: None,
            acquisition_policy: None,
            allow_personal_plugins: false,
            packet_limit: DEFAULT_PACKET_LIMIT,
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_stdout_bytes: DEFAULT_MAX_STDOUT_BYTES,
            max_stderr_bytes: DEFAULT_MAX_STDERR_BYTES,
            timeout: DEFAULT_TIMEOUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizationReport {
    pub manifest: CaptureManifestV0,
    pub receipt: CaptureRunReceiptV0,
    pub packets: Vec<PacketEnvelopeV0>,
    pub quarantines: Vec<PacketQuarantineV0>,
}

#[derive(Debug)]
pub enum AdapterError {
    InvalidOption(&'static str),
    InputMetadata {
        path: PathBuf,
        source: io::Error,
    },
    InputNotFile(PathBuf),
    InputTooLarge {
        bytes: u64,
        limit: u64,
    },
    InputRead {
        path: PathBuf,
        source: io::Error,
    },
    TemporaryWorkspace(io::Error),
    PersonalPluginInspection {
        path: PathBuf,
        source: io::Error,
    },
    PersonalPluginsPresent(PathBuf),
    InputChanged,
    ToolProcess(ProcessError),
    ToolFailed {
        operation: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    ToolDiagnostic {
        operation: String,
        stderr: String,
    },
    ToolVersionMissing,
    CapinfosProcess(ProcessError),
    CapinfosFailed {
        operation: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    CapinfosDiagnostic {
        operation: String,
        stderr: String,
    },
    CapinfosVersionMissing,
    InvalidCapinfosTable(String),
    CaptureFileSizeMismatch {
        staged_bytes: u64,
        reported_bytes: u64,
    },
    CapturePacketCountMismatch {
        file_packets: u64,
        rows_seen: u64,
        packet_limit: u64,
    },
    NonUtf8Executable(&'static str),
    ClockBeforeUnixEpoch(SystemTimeError),
    ClockOutOfRange,
    RecordSerialization(serde_json::Error),
    InvalidManifest(netmon_evidence::CaptureValidationError),
    InvalidReceipt(netmon_evidence::CaptureValidationError),
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(option) => write!(formatter, "{option} must be greater than zero"),
            Self::InputMetadata { path, source } => {
                write!(formatter, "reading metadata for {}: {source}", path.display())
            }
            Self::InputNotFile(path) => {
                write!(formatter, "{} is not a regular file", path.display())
            }
            Self::InputTooLarge { bytes, limit } => {
                write!(formatter, "capture is {bytes} bytes; limit is {limit} bytes")
            }
            Self::InputRead { path, source } => {
                write!(formatter, "reading {}: {source}", path.display())
            }
            Self::TemporaryWorkspace(source) => {
                write!(formatter, "creating isolated TShark workspace: {source}")
            }
            Self::PersonalPluginInspection { path, source } => {
                write!(
                    formatter,
                    "inspecting personal Wireshark plugins at {}: {source}",
                    path.display()
                )
            }
            Self::PersonalPluginsPresent(path) => write!(
                formatter,
                "personal Wireshark plugin {} would execute; pass explicit plugin opt-in to allow it",
                path.display()
            ),
            Self::InputChanged => {
                formatter.write_str("staged capture contents changed while TShark was reading it")
            }
            Self::ToolProcess(source) => write!(formatter, "running TShark: {source}"),
            Self::ToolFailed {
                operation,
                exit_code,
                stderr,
            } => {
                write!(
                    formatter,
                    "TShark {operation} failed with exit code {}: {}",
                    exit_code
                        .map(|code| code.to_string())
                        .unwrap_or_else(|| "signal".into()),
                    stderr.trim()
                )
            }
            Self::ToolDiagnostic { operation, stderr } => {
                write!(
                    formatter,
                    "TShark {operation} reported an error: {}",
                    stderr.trim()
                )
            }
            Self::ToolVersionMissing => {
                formatter.write_str("TShark --version returned no version line")
            }
            Self::CapinfosProcess(source) => write!(formatter, "running Capinfos: {source}"),
            Self::CapinfosFailed {
                operation,
                exit_code,
                stderr,
            } => write!(
                formatter,
                "Capinfos {operation} failed with exit code {}: {}",
                exit_code
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".into()),
                stderr.trim()
            ),
            Self::CapinfosDiagnostic { operation, stderr } => write!(
                formatter,
                "Capinfos {operation} reported an error: {}",
                stderr.trim()
            ),
            Self::CapinfosVersionMissing => {
                formatter.write_str("Capinfos --version returned no version line")
            }
            Self::InvalidCapinfosTable(reason) => {
                write!(formatter, "invalid Capinfos table: {reason}")
            }
            Self::CaptureFileSizeMismatch {
                staged_bytes,
                reported_bytes,
            } => write!(
                formatter,
                "Capinfos reported {reported_bytes} file bytes for a {staged_bytes}-byte staged artifact"
            ),
            Self::CapturePacketCountMismatch {
                file_packets,
                rows_seen,
                packet_limit,
            } => write!(
                formatter,
                "Capinfos reported {file_packets} packets but TShark emitted {rows_seen} rows with limit {packet_limit}"
            ),
            Self::NonUtf8Executable(tool) => {
                write!(formatter, "configured {tool} executable path is not valid UTF-8")
            }
            Self::ClockBeforeUnixEpoch(_) => {
                formatter.write_str("system clock is before the Unix epoch")
            }
            Self::ClockOutOfRange => {
                formatter.write_str("system clock or elapsed duration exceeds the v0 nanosecond range")
            }
            Self::RecordSerialization(source) => {
                write!(formatter, "serializing normalized record for digest: {source}")
            }
            Self::InvalidManifest(source) => write!(formatter, "invalid capture manifest: {source}"),
            Self::InvalidReceipt(source) => write!(formatter, "invalid capture receipt: {source}"),
        }
    }
}

impl std::error::Error for AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InputMetadata { source, .. } | Self::InputRead { source, .. } => Some(source),
            Self::TemporaryWorkspace(source) => Some(source),
            Self::PersonalPluginInspection { source, .. } => Some(source),
            Self::ClockBeforeUnixEpoch(source) => Some(source),
            Self::RecordSerialization(source) => Some(source),
            Self::InvalidManifest(source) | Self::InvalidReceipt(source) => Some(source),
            _ => None,
        }
    }
}

pub fn normalize_saved_capture(
    input: &Path,
    options: &NormalizeOptions,
) -> Result<NormalizationReport, AdapterError> {
    validate_options(options)?;
    let started_time_unix_ns = unix_time_ns(SystemTime::now())?;
    let started = Instant::now();
    let staged = stage_capture(input, options.max_input_bytes)?;
    reject_personal_plugins_unless_allowed(options.allow_personal_plugins)?;
    let environment = WiresharkEnvironment::new()?;

    let capinfos_identity = capinfos_version(options, &environment)?;
    let capinfos_args = capinfos::arguments(&staged.path);
    let capinfos_output = run_bounded(
        &options.capinfos_path,
        &capinfos_args,
        &environment.variables,
        options.timeout.min(Duration::from_secs(15)),
        1024 * 1024,
        options.max_stderr_bytes,
    )
    .map_err(AdapterError::CapinfosProcess)?;
    ensure_capinfos_success("capture-file metadata", &capinfos_output)?;
    let file_metadata =
        parse_table(&capinfos_output.stdout).map_err(AdapterError::InvalidCapinfosTable)?;
    if file_metadata.file_size_bytes != staged.artifact.size_bytes {
        return Err(AdapterError::CaptureFileSizeMismatch {
            staged_bytes: staged.artifact.size_bytes,
            reported_bytes: file_metadata.file_size_bytes,
        });
    }

    let tool_identity = tshark_version(options, &environment)?;
    let configuration_sha256 =
        tshark_configuration_sha256(options, &environment, &tool_identity.full_output)?;
    let tshark_args = tshark_args(&staged.path, options.packet_limit);
    let output = run_bounded(
        &options.tshark_path,
        &tshark_args,
        &environment.variables,
        options.timeout,
        options.max_stdout_bytes,
        options.max_stderr_bytes,
    )
    .map_err(AdapterError::ToolProcess)?;
    if !output.status.success() {
        return Err(AdapterError::ToolFailed {
            operation: "packet normalization".into(),
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    if !output.stderr.is_empty() {
        return Err(AdapterError::ToolDiagnostic {
            operation: "packet normalization".into(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }

    let parsed = parse_rows(&output.stdout, &staged.artifact.content_sha256);
    let after = hash_capture(&staged.path, options.max_input_bytes)?;
    if staged.artifact != after {
        return Err(AdapterError::InputChanged);
    }

    let rows_seen = u64::try_from(parsed.rows_seen).unwrap_or(u64::MAX);
    let packet_limit = u64::try_from(options.packet_limit).unwrap_or(u64::MAX);
    let expected_rows = file_metadata.packet_count.min(packet_limit);
    if rows_seen != expected_rows {
        return Err(AdapterError::CapturePacketCountMismatch {
            file_packets: file_metadata.packet_count,
            rows_seen,
            packet_limit,
        });
    }
    let packet_limit_reached = file_metadata.packet_count > packet_limit;
    let state = if packet_limit_reached || !parsed.quarantines.is_empty() {
        NormalizationStateV0::Partial
    } else {
        NormalizationStateV0::Complete
    };
    let manifest = CaptureManifestV0 {
        schema: CAPTURE_MANIFEST_SCHEMA_V0.into(),
        capture_id: staged.artifact.content_sha256.clone(),
        artifact: staged.artifact,
        observer_id: options.observer_id.clone(),
        acquired_time_unix_ms: options.acquired_time_unix_ms,
        extractor: CaptureExtractorRefV0 {
            adapter: "netmon-adapter-tshark".into(),
            adapter_version: env!("CARGO_PKG_VERSION").into(),
            tool: "tshark".into(),
            tool_version: tool_identity.version.clone(),
            configuration_sha256,
            field_registry: FIELD_REGISTRY_ID.into(),
        },
        acquisition_policy: options.acquisition_policy.clone(),
        normalization: CaptureNormalizationV0 {
            state,
            packet_limit,
            packet_limit_reached,
            packet_rows_emitted: u64::try_from(parsed.packets.len()).unwrap_or(u64::MAX),
            packet_rows_quarantined: u64::try_from(parsed.quarantines.len()).unwrap_or(u64::MAX),
        },
    };
    manifest.validate().map_err(AdapterError::InvalidManifest)?;
    let normalized_records_sha256 =
        normalized_records_sha256(&manifest, &parsed.packets, &parsed.quarantines)?;
    let finished_time_unix_ns = unix_time_ns(SystemTime::now())?;
    let elapsed_ns =
        u64::try_from(started.elapsed().as_nanos()).map_err(|_| AdapterError::ClockOutOfRange)?;
    let receipt = CaptureRunReceiptV0 {
        schema: CAPTURE_RUN_RECEIPT_SCHEMA_V0.into(),
        run_id: run_id(
            &manifest.capture_id,
            started_time_unix_ns,
            std::process::id(),
            RUN_COUNTER.fetch_add(1, Ordering::Relaxed),
        ),
        capture_id: manifest.capture_id.clone(),
        started_time_unix_ns,
        finished_time_unix_ns,
        elapsed_ns,
        file: file_metadata,
        capinfos: tool_run_receipt(
            "capinfos",
            &options.capinfos_path,
            &capinfos_identity.version,
            capinfos_argument_template(),
            &capinfos_output,
        )?,
        tshark: tool_run_receipt(
            "tshark",
            &options.tshark_path,
            &tool_identity.version,
            tshark_argument_template(options.packet_limit),
            &output,
        )?,
        configuration_sha256: manifest.extractor.configuration_sha256.clone(),
        field_registry: manifest.extractor.field_registry.clone(),
        normalized_records_digest_profile: NORMALIZED_RECORDS_DIGEST_PROFILE_V0.into(),
        normalized_records_sha256,
    };
    receipt.validate().map_err(AdapterError::InvalidReceipt)?;

    Ok(NormalizationReport {
        manifest,
        receipt,
        packets: parsed.packets,
        quarantines: parsed.quarantines,
    })
}

fn validate_options(options: &NormalizeOptions) -> Result<(), AdapterError> {
    for (value, name) in [
        (options.packet_limit, "packet_limit"),
        (options.max_stdout_bytes, "max_stdout_bytes"),
        (options.max_stderr_bytes, "max_stderr_bytes"),
    ] {
        if value == 0 {
            return Err(AdapterError::InvalidOption(name));
        }
    }
    if options.max_input_bytes == 0 {
        return Err(AdapterError::InvalidOption("max_input_bytes"));
    }
    if options.timeout.is_zero() {
        return Err(AdapterError::InvalidOption("timeout"));
    }
    Ok(())
}

fn reject_personal_plugins_unless_allowed(allowed: bool) -> Result<(), AdapterError> {
    if allowed {
        return Ok(());
    }
    if let Some(path) = first_personal_plugin(personal_plugin_roots())? {
        Err(AdapterError::PersonalPluginsPresent(path))
    } else {
        Ok(())
    }
}

fn personal_plugin_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        roots.push(home.join(".local/lib/wireshark/plugins"));
        roots.push(home.join(".config/wireshark/plugins"));
    }
    if let Some(configuration) = std::env::var_os("XDG_CONFIG_HOME") {
        roots.push(PathBuf::from(configuration).join("wireshark/plugins"));
    }
    if let Some(application_data) = std::env::var_os("APPDATA") {
        roots.push(PathBuf::from(application_data).join("Wireshark/plugins"));
    }
    roots.sort();
    roots.dedup();
    roots
}

fn first_personal_plugin(roots: Vec<PathBuf>) -> Result<Option<PathBuf>, AdapterError> {
    let mut pending = roots;
    let mut visited = 0_usize;
    while let Some(path) = pending.pop() {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
            Err(source) => {
                return Err(AdapterError::PersonalPluginInspection { path, source });
            }
        };
        if !metadata.is_dir() {
            return Ok(Some(path));
        }
        let entries =
            fs::read_dir(&path).map_err(|source| AdapterError::PersonalPluginInspection {
                path: path.clone(),
                source,
            })?;
        for entry in entries {
            let entry = entry.map_err(|source| AdapterError::PersonalPluginInspection {
                path: path.clone(),
                source,
            })?;
            visited += 1;
            if visited > 10_000 {
                return Ok(Some(path));
            }
            let entry_path = entry.path();
            let file_type =
                entry
                    .file_type()
                    .map_err(|source| AdapterError::PersonalPluginInspection {
                        path: entry_path.clone(),
                        source,
                    })?;
            if file_type.is_dir() {
                pending.push(entry_path);
            } else {
                return Ok(Some(entry_path));
            }
        }
    }
    Ok(None)
}

struct ToolIdentity {
    version: String,
    full_output: Vec<u8>,
}

fn capinfos_version(
    options: &NormalizeOptions,
    environment: &WiresharkEnvironment,
) -> Result<ToolIdentity, AdapterError> {
    let output = run_bounded(
        &options.capinfos_path,
        &[OsString::from("--version")],
        &environment.variables,
        options.timeout.min(Duration::from_secs(5)),
        64 * 1024,
        options.max_stderr_bytes,
    )
    .map_err(AdapterError::CapinfosProcess)?;
    ensure_capinfos_success("version query", &output)?;
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .ok_or(AdapterError::CapinfosVersionMissing)?;
    Ok(ToolIdentity {
        version,
        full_output: output.stdout,
    })
}

fn ensure_capinfos_success(
    operation: &str,
    output: &process::BoundedOutput,
) -> Result<(), AdapterError> {
    if !output.status.success() {
        return Err(AdapterError::CapinfosFailed {
            operation: operation.into(),
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    if !output.stderr.is_empty() {
        return Err(AdapterError::CapinfosDiagnostic {
            operation: operation.into(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    Ok(())
}

fn tshark_version(
    options: &NormalizeOptions,
    environment: &WiresharkEnvironment,
) -> Result<ToolIdentity, AdapterError> {
    let output = run_bounded(
        &options.tshark_path,
        &[OsString::from("--version")],
        &environment.variables,
        options.timeout.min(Duration::from_secs(5)),
        64 * 1024,
        options.max_stderr_bytes,
    )
    .map_err(AdapterError::ToolProcess)?;
    if !output.status.success() {
        return Err(AdapterError::ToolFailed {
            operation: "version query".into(),
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    if !output.stderr.is_empty() {
        return Err(AdapterError::ToolDiagnostic {
            operation: "version query".into(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        });
    }
    let version = String::from_utf8_lossy(&output.stdout)
        .lines()
        .find(|line| !line.trim().is_empty())
        .map(str::to_owned)
        .ok_or(AdapterError::ToolVersionMissing)?;
    Ok(ToolIdentity {
        version,
        full_output: output.stdout,
    })
}

fn tshark_configuration_sha256(
    options: &NormalizeOptions,
    environment: &WiresharkEnvironment,
    version_output: &[u8],
) -> Result<String, AdapterError> {
    const REPORTS: &[&str] = &[
        "currentprefs",
        "fields",
        "plugins",
        "protocols",
        "heuristic-decodes",
        "decodes",
    ];
    let mut hasher = Sha256::new();
    hash_named_bytes(&mut hasher, "version", version_output);
    for report in REPORTS {
        let output = run_bounded(
            &options.tshark_path,
            &[OsString::from("-G"), OsString::from(report)],
            &environment.variables,
            options.timeout.min(Duration::from_secs(15)),
            options.max_stdout_bytes,
            options.max_stderr_bytes,
        )
        .map_err(AdapterError::ToolProcess)?;
        if !output.status.success() {
            return Err(AdapterError::ToolFailed {
                operation: format!("-G {report}"),
                exit_code: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        if !output.stderr.is_empty() {
            return Err(AdapterError::ToolDiagnostic {
                operation: format!("-G {report}"),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            });
        }
        hash_named_report(&mut hasher, report, &output.stdout);
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_named_bytes(hasher: &mut Sha256, name: &str, bytes: &[u8]) {
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn hash_named_report(hasher: &mut Sha256, name: &str, bytes: &[u8]) {
    let mut lines: Vec<&[u8]> = bytes
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect();
    lines.sort_unstable();
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(u64::try_from(lines.len()).unwrap_or(u64::MAX).to_le_bytes());
    for line in lines {
        hasher.update(u64::try_from(line.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(line);
    }
}

fn tshark_args(input: &Path, packet_limit: usize) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("-n"),
        OsString::from("-Q"),
        OsString::from("-r"),
        input.as_os_str().to_owned(),
        OsString::from("-c"),
        OsString::from(packet_limit.to_string()),
        OsString::from("-T"),
        OsString::from("fields"),
        OsString::from("-E"),
        OsString::from("header=n"),
        OsString::from("-E"),
        OsString::from("separator=/t"),
        OsString::from("-E"),
        OsString::from("occurrence=f"),
        OsString::from("-E"),
        OsString::from("quote=n"),
    ];
    for field in FIELDS {
        args.push(OsString::from("-e"));
        args.push(OsString::from(field));
    }
    args
}

fn tshark_argument_template(packet_limit: usize) -> Vec<String> {
    tshark_args(Path::new("$STAGED_CAPTURE"), packet_limit)
        .into_iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

fn tool_run_receipt(
    tool: &'static str,
    configured_executable: &Path,
    version: &str,
    argument_template: Vec<String>,
    output: &process::BoundedOutput,
) -> Result<ToolRunReceiptV0, AdapterError> {
    let configured_executable = configured_executable
        .to_str()
        .ok_or(AdapterError::NonUtf8Executable(tool))?;
    Ok(ToolRunReceiptV0 {
        tool: tool.into(),
        configured_executable: configured_executable.into(),
        tool_version: version.into(),
        argument_template,
        environment_policy: WIRESHARK_ENVIRONMENT_POLICY_ID.into(),
        exit_code: output.status.code().unwrap_or(0),
        stdout_sha256: sha256_bytes(&output.stdout),
        stderr_sha256: sha256_bytes(&output.stderr),
    })
}

fn normalized_records_sha256(
    manifest: &CaptureManifestV0,
    packets: &[PacketEnvelopeV0],
    quarantines: &[PacketQuarantineV0],
) -> Result<String, AdapterError> {
    let mut hasher = Sha256::new();
    hasher.update(b"netmon.normalized_records.v0\0");

    let manifest = serde_json::to_vec(manifest).map_err(AdapterError::RecordSerialization)?;
    hash_indexed_record(&mut hasher, "manifest", 0, &manifest);
    for (index, packet) in packets.iter().enumerate() {
        let packet = serde_json::to_vec(packet).map_err(AdapterError::RecordSerialization)?;
        hash_indexed_record(
            &mut hasher,
            "packet",
            u64::try_from(index).unwrap_or(u64::MAX),
            &packet,
        );
    }
    for (index, quarantine) in quarantines.iter().enumerate() {
        let quarantine =
            serde_json::to_vec(quarantine).map_err(AdapterError::RecordSerialization)?;
        hash_indexed_record(
            &mut hasher,
            "quarantine",
            u64::try_from(index).unwrap_or(u64::MAX),
            &quarantine,
        );
    }
    Ok(format!("sha256:{:x}", hasher.finalize()))
}

fn hash_indexed_record(hasher: &mut Sha256, kind: &str, index: u64, bytes: &[u8]) {
    hasher.update(kind.as_bytes());
    hasher.update([0]);
    hasher.update(index.to_le_bytes());
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn unix_time_ns(time: SystemTime) -> Result<i64, AdapterError> {
    let duration = time
        .duration_since(UNIX_EPOCH)
        .map_err(AdapterError::ClockBeforeUnixEpoch)?;
    i64::try_from(duration.as_nanos()).map_err(|_| AdapterError::ClockOutOfRange)
}

fn run_id(capture_id: &str, started_time_unix_ns: i64, process_id: u32, counter: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"netmon.capture_run.v0\0");
    hasher.update(capture_id.as_bytes());
    hasher.update([0]);
    hasher.update(started_time_unix_ns.to_le_bytes());
    hasher.update(process_id.to_le_bytes());
    hasher.update(counter.to_le_bytes());
    format!("run:{:x}", hasher.finalize())
}

struct WiresharkEnvironment {
    _directory: TempDir,
    variables: Vec<(OsString, OsString)>,
}

impl WiresharkEnvironment {
    fn new() -> Result<Self, AdapterError> {
        let directory = tempfile::Builder::new()
            .prefix("netmon-tshark-")
            .tempdir()
            .map_err(AdapterError::TemporaryWorkspace)?;
        let configuration = directory.path().join("configuration");
        fs::create_dir_all(&configuration).map_err(AdapterError::TemporaryWorkspace)?;
        let variables = vec![(
            OsString::from("WIRESHARK_CONFIG_DIR"),
            configuration.into_os_string(),
        )];
        Ok(Self {
            _directory: directory,
            variables,
        })
    }
}

struct StagedCapture {
    _directory: TempDir,
    path: PathBuf,
    artifact: CaptureArtifactRefV0,
}

fn stage_capture(input: &Path, limit: u64) -> Result<StagedCapture, AdapterError> {
    let metadata = fs::metadata(input).map_err(|source| AdapterError::InputMetadata {
        path: input.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::InputNotFile(input.to_owned()));
    }
    if metadata.len() > limit {
        return Err(AdapterError::InputTooLarge {
            bytes: metadata.len(),
            limit,
        });
    }
    let directory = tempfile::Builder::new()
        .prefix("netmon-capture-")
        .tempdir()
        .map_err(AdapterError::TemporaryWorkspace)?;
    let path = directory.path().join("capture");
    let mut source =
        BufReader::new(File::open(input).map_err(|source| AdapterError::InputRead {
            path: input.to_owned(),
            source,
        })?);
    let mut destination = File::create(&path).map_err(AdapterError::TemporaryWorkspace)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = source
            .read(&mut buffer)
            .map_err(|source| AdapterError::InputRead {
                path: input.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        size =
            size.checked_add(u64::try_from(read).unwrap())
                .ok_or(AdapterError::InputTooLarge {
                    bytes: u64::MAX,
                    limit,
                })?;
        if size > limit {
            return Err(AdapterError::InputTooLarge { bytes: size, limit });
        }
        destination
            .write_all(&buffer[..read])
            .map_err(AdapterError::TemporaryWorkspace)?;
        hasher.update(&buffer[..read]);
    }
    destination
        .flush()
        .map_err(AdapterError::TemporaryWorkspace)?;
    drop(destination);

    Ok(StagedCapture {
        _directory: directory,
        path,
        artifact: CaptureArtifactRefV0 {
            content_sha256: format!("sha256:{:x}", hasher.finalize()),
            size_bytes: size,
        },
    })
}

fn hash_capture(path: &Path, limit: u64) -> Result<CaptureArtifactRefV0, AdapterError> {
    let metadata = fs::metadata(path).map_err(|source| AdapterError::InputMetadata {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(AdapterError::InputNotFile(path.to_owned()));
    }
    if metadata.len() > limit {
        return Err(AdapterError::InputTooLarge {
            bytes: metadata.len(),
            limit,
        });
    }

    let file = File::open(path).map_err(|source| AdapterError::InputRead {
        path: path.to_owned(),
        source,
    })?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut size = 0_u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| AdapterError::InputRead {
                path: path.to_owned(),
                source,
            })?;
        if read == 0 {
            break;
        }
        size =
            size.checked_add(u64::try_from(read).unwrap())
                .ok_or(AdapterError::InputTooLarge {
                    bytes: u64::MAX,
                    limit,
                })?;
        if size > limit {
            return Err(AdapterError::InputTooLarge { bytes: size, limit });
        }
        hasher.update(&buffer[..read]);
    }

    Ok(CaptureArtifactRefV0 {
        content_sha256: format!("sha256:{:x}", hasher.finalize()),
        size_bytes: size,
    })
}

impl std::fmt::Display for ProcessError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn(source) => write!(formatter, "could not start process: {source}"),
            Self::Poll(source) => write!(formatter, "could not poll process: {source}"),
            Self::Kill(source) => write!(formatter, "could not stop timed-out process: {source}"),
            Self::TimedOut => formatter.write_str("deadline exceeded"),
            Self::StdoutRead(source) => write!(formatter, "could not read stdout: {source}"),
            Self::StderrRead(source) => write!(formatter, "could not read stderr: {source}"),
            Self::StdoutTooLarge => formatter.write_str("stdout exceeded its byte limit"),
            Self::StderrTooLarge => formatter.write_str("stderr exceeded its byte limit"),
            Self::ReaderPanicked(stream) => write!(formatter, "{stream} reader thread panicked"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_is_offline_name_resolution_free_and_registry_owned() {
        let args = tshark_args(Path::new("capture file.pcap"), 17);
        let strings: Vec<String> = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            &strings[..8],
            [
                "-n",
                "-Q",
                "-r",
                "capture file.pcap",
                "-c",
                "17",
                "-T",
                "fields"
            ]
        );
        assert!(!strings.iter().any(|arg| arg == "-i"));
        assert!(strings
            .windows(2)
            .any(|pair| pair == ["-E", "occurrence=f"]));
        for field in FIELDS {
            assert!(strings.windows(2).any(|pair| pair == ["-e", *field]));
        }
    }

    #[test]
    fn hash_is_content_addressed_and_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("capture.pcap");
        fs::write(&path, b"abc").unwrap();

        assert_eq!(
            hash_capture(&path, 3).unwrap(),
            CaptureArtifactRefV0 {
                content_sha256:
                    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
                size_bytes: 3,
            }
        );
        assert!(matches!(
            hash_capture(&path, 2),
            Err(AdapterError::InputTooLarge { bytes: 3, limit: 2 })
        ));
    }

    #[test]
    fn staging_rejects_non_files_and_snapshots_regular_file_bytes() {
        let directory = tempfile::tempdir().unwrap();
        assert!(matches!(
            stage_capture(directory.path(), 1024),
            Err(AdapterError::InputNotFile(_))
        ));

        let input = directory.path().join("-");
        fs::write(&input, b"pcap bytes").unwrap();
        let staged = stage_capture(&input, 1024).unwrap();
        assert_ne!(staged.path.as_os_str(), "-");
        assert_eq!(fs::read(&staged.path).unwrap(), b"pcap bytes");
        assert_eq!(staged.artifact, hash_capture(&staged.path, 1024).unwrap());
    }

    #[test]
    fn configuration_report_hash_ignores_line_order_but_not_content() {
        let mut left = Sha256::new();
        hash_named_report(&mut left, "fields", b"b\na\n");
        let mut right = Sha256::new();
        hash_named_report(&mut right, "fields", b"a\nb\n");
        let left = left.finalize();
        let right = right.finalize();
        assert_eq!(left, right);

        let mut changed = Sha256::new();
        hash_named_report(&mut changed, "fields", b"a\nc\n");
        assert_ne!(right, changed.finalize());
    }

    #[test]
    fn personal_plugin_check_is_recursive_and_empty_tree_safe() {
        let directory = tempfile::tempdir().unwrap();
        let empty = directory.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert_eq!(first_personal_plugin(vec![empty]).unwrap(), None);

        let nested = directory.path().join("plugins/4-6/epan");
        fs::create_dir_all(&nested).unwrap();
        let plugin = nested.join("custom.so");
        fs::write(&plugin, b"fixture").unwrap();
        assert_eq!(
            first_personal_plugin(vec![directory.path().join("plugins")]).unwrap(),
            Some(plugin)
        );
    }

    #[test]
    fn public_capture_fixtures_form_one_receipt_bound_record_set() {
        let manifest: CaptureManifestV0 = serde_json::from_str(include_str!(
            "../../../schema-fixtures/v0/capture_manifest_v0.json"
        ))
        .unwrap();
        let receipt: CaptureRunReceiptV0 = serde_json::from_str(include_str!(
            "../../../schema-fixtures/v0/capture_run_receipt_v0.json"
        ))
        .unwrap();
        let packet: PacketEnvelopeV0 = serde_json::from_str(include_str!(
            "../../../schema-fixtures/v0/packet_envelope_v0.json"
        ))
        .unwrap();
        let quarantine: PacketQuarantineV0 = serde_json::from_str(include_str!(
            "../../../schema-fixtures/v0/packet_quarantine_v0.json"
        ))
        .unwrap();

        assert_eq!(receipt.capture_id, manifest.capture_id);
        assert_eq!(packet.capture_id, manifest.capture_id);
        assert_eq!(quarantine.capture_id, manifest.capture_id);
        assert_eq!(
            receipt.file.file_size_bytes,
            manifest.artifact.size_bytes
        );
        assert_eq!(manifest.normalization.packet_rows_emitted, 1);
        assert_eq!(manifest.normalization.packet_rows_quarantined, 1);
        assert_eq!(
            receipt.file.packet_count,
            manifest.normalization.packet_rows_emitted
                + manifest.normalization.packet_rows_quarantined
        );
        assert_eq!(
            receipt.normalized_records_sha256,
            normalized_records_sha256(&manifest, &[packet], &[quarantine]).unwrap()
        );
    }
}
