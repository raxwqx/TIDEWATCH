use std::io::Write;
use std::process::{Command, Output, Stdio};

const SAMPLE: &str = concat!(
    "Oct  9 19:01:01 lab sshd[10]: Failed password for analyst from 203.0.113.12 port 50101 ssh2\n",
    "Oct  9 19:01:05 lab sshd[11]: Accepted password for analyst from 203.0.113.12 port 50102 ssh2\n"
);

fn run(args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tidewatch"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("launch tidewatch binary");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(input.as_bytes())
        .expect("write input");
    child.wait_with_output().expect("collect output")
}

#[test]
fn cli_prints_json_report_from_stdin() {
    let output = run(&["--format", "authlog", "--output-format", "json"], SAMPLE);
    assert!(output.status.success());
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(json["tool"], "TIDEWATCH");
    assert_eq!(json["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(json["schema_version"], "2");
    assert_eq!(json["summary"]["events_emitted"], 2);
    assert!(json.get("event_summary").is_none());
}

#[test]
fn cli_summary_adds_event_overview_to_text_and_json() {
    let text = run(&["--format", "authlog", "--summary", "--top", "1"], SAMPLE);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).expect("utf-8 text output");
    assert!(text.contains("Event overview"));
    assert!(text.contains("Event kinds: ssh_auth_failure=1, ssh_auth_success=1"));

    let json_output = run(
        &[
            "--format",
            "authlog",
            "--summary",
            "--top",
            "1",
            "--output-format",
            "json",
        ],
        SAMPLE,
    );
    let json: serde_json::Value =
        serde_json::from_slice(&json_output.stdout).expect("valid JSON output");
    let summary = &json["event_summary"];
    assert_eq!(summary["events_total"], 2);
    assert_eq!(summary["events_with_timestamp"], 2);
    assert_eq!(summary["by_kind"]["ssh_auth_failure"], 1);
    assert_eq!(summary["top_source_ips"].as_array().unwrap().len(), 1);
    assert_eq!(summary["top_source_ips"][0]["value"], "203.0.113.12");
    assert_eq!(summary["top_source_ips"][0]["count"], 2);
}

#[test]
fn cli_rejects_out_of_range_top_values() {
    let output = run(&["--format", "authlog", "--summary", "--top", "0"], SAMPLE);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("top must be between 1 and 100"));

    let output = run(
        &["--format", "authlog", "--summary", "--top", "101"],
        SAMPLE,
    );
    assert!(!output.status.success());
}

#[test]
fn cli_fail_on_malformed_returns_partial_report_and_status_two() {
    let malformed_input = concat!(
        "{not-json}\n",
        "{\"message\":\"Accepted password for bob from 203.0.113.9 port 22 ssh2\"}\n"
    );

    let without_flag = run(
        &["--format", "jsonl", "--output-format", "json"],
        malformed_input,
    );
    assert!(without_flag.status.success());

    let output = run(
        &[
            "--format",
            "jsonl",
            "--output-format",
            "json",
            "--fail-on-malformed",
        ],
        malformed_input,
    );
    assert_eq!(output.status.code(), Some(2));
    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("valid partial JSON report");
    assert_eq!(json["summary"]["malformed_json_lines"], 1);
    assert_eq!(json["summary"]["events_emitted"], 2);
    assert_eq!(json["alerts"].as_array().unwrap().len(), 0);
}
