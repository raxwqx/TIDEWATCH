use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn cli_prints_json_report_from_stdin() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tidewatch"))
        .args(["--format", "authlog", "--output-format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch tidewatch binary");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"Oct  9 19:01:01 lab sshd[10]: Accepted password for analyst from 203.0.113.12 port 50101 ssh2\n")
        .expect("write input");

    let output = child.wait_with_output().expect("collect output");
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["tool"], "TIDEWATCH");
    assert_eq!(json["summary"]["events_emitted"], 1);
}
