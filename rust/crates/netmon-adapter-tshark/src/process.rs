use std::ffi::OsString;
use std::io::{self, Read};
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const CLEARED_TSHARK_ENVIRONMENT: &[&str] = &[
    "WIRESHARK_DEBUG_WMEM_OVERRIDE",
    "WIRESHARK_RUN_FROM_BUILD_DIRECTORY",
    "WIRESHARK_DATA_DIR",
    "WIRESHARK_EXTCAP_DIR",
    "WIRESHARK_PLUGIN_DIR",
    "ERF_RECORDS_TO_CHECK",
    "IPFIX_RECORDS_TO_CHECK",
    "WIRESHARK_ABORT_ON_DISSECTOR_BUG",
    "WIRESHARK_ABORT_ON_TOO_MANY_ITEMS",
    "WIRESHARK_LOG_LEVEL",
    "WIRESHARK_LOG_FATAL",
    "WIRESHARK_LOG_DOMAINS",
    "WIRESHARK_LOG_DEBUG",
    "WIRESHARK_LOG_NOISY",
];

#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub status: ExitStatus,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum ProcessError {
    Spawn(io::Error),
    Poll(io::Error),
    Kill(io::Error),
    TimedOut,
    StdoutRead(io::Error),
    StderrRead(io::Error),
    StdoutTooLarge,
    StderrTooLarge,
    ReaderPanicked(&'static str),
}

pub(crate) fn run_bounded(
    program: &Path,
    args: &[OsString],
    environment: &[(OsString, OsString)],
    timeout: Duration,
    max_stdout_bytes: usize,
    max_stderr_bytes: usize,
) -> Result<BoundedOutput, ProcessError> {
    let mut command = bounded_command(program, args, environment);
    let mut child = command.spawn().map_err(ProcessError::Spawn)?;
    let stdout = child
        .stdout
        .take()
        .expect("piped stdout is available immediately after spawn");
    let stderr = child
        .stderr
        .take()
        .expect("piped stderr is available immediately after spawn");

    let stdout_reader = thread::spawn(move || read_bounded(stdout, max_stdout_bytes));
    let stderr_reader = thread::spawn(move || read_bounded(stderr, max_stderr_bytes));

    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                let kill_result = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return match kill_result {
                    Ok(()) => Err(ProcessError::TimedOut),
                    Err(source) => Err(ProcessError::Kill(source)),
                };
            }
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(source) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = stdout_reader.join();
                let _ = stderr_reader.join();
                return Err(ProcessError::Poll(source));
            }
        }
    };

    let stdout = stdout_reader
        .join()
        .map_err(|_| ProcessError::ReaderPanicked("stdout"))?
        .map_err(|error| match error {
            ReadError::Io(source) => ProcessError::StdoutRead(source),
            ReadError::TooLarge => ProcessError::StdoutTooLarge,
        })?;
    let stderr = stderr_reader
        .join()
        .map_err(|_| ProcessError::ReaderPanicked("stderr"))?
        .map_err(|error| match error {
            ReadError::Io(source) => ProcessError::StderrRead(source),
            ReadError::TooLarge => ProcessError::StderrTooLarge,
        })?;

    Ok(BoundedOutput {
        status,
        stdout,
        stderr,
    })
}

fn bounded_command(
    program: &Path,
    args: &[OsString],
    environment: &[(OsString, OsString)],
) -> Command {
    let mut command = Command::new(program);
    for name in CLEARED_TSHARK_ENVIRONMENT {
        command.env_remove(name);
    }
    command
        .args(args)
        .envs(environment.iter().cloned())
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

#[derive(Debug)]
enum ReadError {
    Io(io::Error),
    TooLarge,
}

fn read_bounded(mut reader: impl Read, limit: usize) -> Result<Vec<u8>, ReadError> {
    let take_limit = u64::try_from(limit)
        .unwrap_or(u64::MAX)
        .saturating_add(1);
    let mut bytes = Vec::with_capacity(limit.min(64 * 1024));
    reader
        .by_ref()
        .take(take_limit)
        .read_to_end(&mut bytes)
        .map_err(ReadError::Io)?;
    if bytes.len() > limit {
        Err(ReadError::TooLarge)
    } else {
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_reader_rejects_one_byte_over_limit() {
        assert!(matches!(
            read_bounded(&b"abcd"[..], 3),
            Err(ReadError::TooLarge)
        ));
        assert_eq!(read_bounded(&b"abc"[..], 3).unwrap(), b"abc");
    }

    #[test]
    fn command_clears_tshark_behavior_and_path_overrides() {
        let command = bounded_command(
            Path::new("tshark"),
            &[OsString::from("--version")],
            &[(OsString::from("WIRESHARK_CONFIG_DIR"), OsString::from("/empty"))],
        );
        let environment: std::collections::BTreeMap<_, _> = command
            .get_envs()
            .map(|(name, value)| (name.to_owned(), value.map(OsString::from)))
            .collect();

        for name in CLEARED_TSHARK_ENVIRONMENT {
            assert_eq!(environment.get(std::ffi::OsStr::new(name)), Some(&None));
        }
        assert_eq!(
            environment.get(std::ffi::OsStr::new("WIRESHARK_CONFIG_DIR")),
            Some(&Some(OsString::from("/empty")))
        );
        assert_eq!(
            environment.get(std::ffi::OsStr::new("LC_ALL")),
            Some(&Some(OsString::from("C")))
        );
    }
}
