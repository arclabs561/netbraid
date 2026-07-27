use std::process::Command;

#[test]
fn version_flag_reports_workspace_package_version() {
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
