use std::process::Command;

#[test]
fn version_flag_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("netbraid {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn snapshot_commands_survive_an_out_of_range_timestamp() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("audit-history.jsonl");
    std::fs::write(
        &path,
        "{\"ts\":-9223372036854775808,\"clients\":[{\"name\":\"laptop\"}]}\n",
    )
    .unwrap();
    for args in [&["net"][..], &["device", "laptop"], &["here"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_netbraid"))
            .arg("--file")
            .arg(&path)
            .args(args)
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !stderr.contains("panicked"),
            "netbraid {args:?} panicked on an out-of-range timestamp:\n{stderr}"
        );
    }
}
