//! Bounded, offline normalization of saved captures through TShark.
//!
//! This crate does not capture live traffic. It invokes TShark without a shell,
//! disables name resolution, selects a fixed field registry, and returns typed
//! evidence plus explicit quarantines.

mod fields;
mod process;

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use fields::{parse_rows, FIELDS};
pub use fields::FIELD_REGISTRY_ID;
use netmon_evidence::{
    CaptureArtifactRefV0, CaptureExtractorRefV0, CaptureManifestV0,
    CaptureNormalizationV0, CollectionPolicyV0, NormalizationStateV0, PacketEnvelopeV0,
    PacketQuarantineV0, CAPTURE_MANIFEST_SCHEMA_V0,
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

#[derive(Debug, Clone)]
pub struct NormalizeOptions {
    pub tshark_path: PathBuf,
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
    InvalidManifest(netmon_evidence::CaptureValidationError),
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
            Self::InvalidManifest(source) => write!(formatter, "invalid capture manifest: {source}"),
        }
    }
}

impl std::error::Error for AdapterError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InputMetadata { source, .. } | Self::InputRead { source, .. } => Some(source),
            Self::TemporaryWorkspace(source) => Some(source),
            Self::PersonalPluginInspection { source, .. } => Some(source),
            Self::InvalidManifest(source) => Some(source),
            _ => None,
        }
    }
}

pub fn normalize_saved_capture(
    input: &Path,
    options: &NormalizeOptions,
) -> Result<NormalizationReport, AdapterError> {
    validate_options(options)?;
    let staged = stage_capture(input, options.max_input_bytes)?;
    reject_personal_plugins_unless_allowed(options.allow_personal_plugins)?;
    let environment = TsharkEnvironment::new()?;
    let tool_identity = tshark_version(options, &environment)?;
    let configuration_sha256 =
        tshark_configuration_sha256(options, &environment, &tool_identity.full_output)?;
    let output = run_bounded(
        &options.tshark_path,
        &tshark_args(&staged.path, options.packet_limit),
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

    let packet_limit_reached = parsed.rows_seen >= options.packet_limit;
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
            tool_version: tool_identity.version,
            configuration_sha256,
            field_registry: FIELD_REGISTRY_ID.into(),
        },
        acquisition_policy: options.acquisition_policy.clone(),
        normalization: CaptureNormalizationV0 {
            state,
            packet_limit: u64::try_from(options.packet_limit).unwrap_or(u64::MAX),
            packet_limit_reached,
            packet_rows_emitted: u64::try_from(parsed.packets.len()).unwrap_or(u64::MAX),
            packet_rows_quarantined: u64::try_from(parsed.quarantines.len())
                .unwrap_or(u64::MAX),
        },
    };
    manifest.validate().map_err(AdapterError::InvalidManifest)?;

    Ok(NormalizationReport {
        manifest,
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
            let entry =
                entry.map_err(|source| AdapterError::PersonalPluginInspection {
                    path: path.clone(),
                    source,
                })?;
            visited += 1;
            if visited > 10_000 {
                return Ok(Some(path));
            }
            let entry_path = entry.path();
            let file_type = entry.file_type().map_err(|source| {
                AdapterError::PersonalPluginInspection {
                    path: entry_path.clone(),
                    source,
                }
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

fn tshark_version(
    options: &NormalizeOptions,
    environment: &TsharkEnvironment,
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
    environment: &TsharkEnvironment,
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

struct TsharkEnvironment {
    _directory: TempDir,
    variables: Vec<(OsString, OsString)>,
}

impl TsharkEnvironment {
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
    let mut source = BufReader::new(File::open(input).map_err(|source| {
        AdapterError::InputRead {
            path: input.to_owned(),
            source,
        }
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
        size = size
            .checked_add(u64::try_from(read).unwrap())
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
        size = size
            .checked_add(u64::try_from(read).unwrap())
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

        assert_eq!(&strings[..8], ["-n", "-Q", "-r", "capture file.pcap", "-c", "17", "-T", "fields"]);
        assert!(!strings.iter().any(|arg| arg == "-i"));
        assert!(strings.windows(2).any(|pair| pair == ["-E", "occurrence=f"]));
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
                    "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                        .into(),
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
        assert_eq!(
            staged.artifact,
            hash_capture(&staged.path, 1024).unwrap()
        );
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
}
