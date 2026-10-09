# TIDEWATCH

**Offline Linux log threat hunting and incident triage, written in Rust.**

![Rust](https://img.shields.io/badge/Rust-1.85%2B-orange?logo=rust)
![Platform](https://img.shields.io/badge/platform-Linux-lightgrey?logo=linux)
![License](https://img.shields.io/badge/license-MIT-blue)
[![Rust CI](https://github.com/raxwqx/TIDEWATCH/actions/workflows/ci.yml/badge.svg)](https://github.com/raxwqx/TIDEWATCH/actions/workflows/ci.yml)

TIDEWATCH is a local-first command-line tool for analyzing Linux authentication and system logs. It parses supported log lines into normalized events, evaluates configurable TOML detection rules, correlates related activity over time, and produces evidence-backed findings in terminal or JSON format.

It is built for defensive security research, incident-response practice, and repeatable triage of logs you own or are authorized to examine.

> **Analyst note:** A detection is an investigative lead, not proof of compromise. Validate findings against surrounding telemetry, expected administration activity, and host policy.

## Contents

- [Why TIDEWATCH](#why-tidewatch)
- [Capabilities](#capabilities)
- [Detection coverage](#detection-coverage)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Build and install](#build-and-install)
- [Quick start](#quick-start)
- [Command-line reference](#command-line-reference)
- [Input formats](#input-formats)
- [Detection rules](#detection-rules)
- [Reports and evidence](#reports-and-evidence)
- [Testing and development](#testing-and-development)
- [Architecture](#architecture)
- [Limitations](#limitations)
- [Responsible use and data handling](#responsible-use-and-data-handling)
- [Roadmap ideas](#roadmap-ideas)
- [License](#license)

## Why TIDEWATCH

Security logs are most useful when related events can be reviewed together. TIDEWATCH focuses on a small, transparent detection pipeline that makes it easy to see **what matched, which source lines support a finding, and which rule produced it**.

- **Offline by design:** reads local files or standard input; it does not contact remote hosts or upload log data.
- **Evidence-forward output:** findings retain source line numbers, event messages, optional timestamps, grouping pivots, and MITRE ATT&CK references where configured.
- **Configurable detections:** edit TOML rules instead of changing Rust code for every threshold adjustment.
- **Automation-friendly:** JSON reports and severity-based process exit codes support scripts and CI workflows.
- **Testable foundation:** parser and correlation logic are separated into modules with unit and CLI integration tests.

## Capabilities

| Area | Current capability |
| --- | --- |
| Inputs | Common Linux authlog/syslog-style text and JSON Lines (JSONL) |
| Normalization | Event kind, timestamp where parseable, host, program, PID, user, source IP, command, message, and original line number |
| Detection | Threshold windows and failure-then-success sequence correlation |
| Rule grouping | Source IP, username, or source-IP-and-username combination |
| Results | Human-readable terminal report or structured JSON |
| Workflow integration | Standard input, output files, and configurable severity exit threshold |
| ATT&CK context | Technique IDs attached to relevant bundled rules |

## Detection coverage

TIDEWATCH ships with starter rules in [`rules/default.toml`](rules/default.toml). Their thresholds are intentionally configurable and should be tuned to the environment.

| Rule | Severity | What it flags | Default logic |
| --- | --- | --- | --- |
| `SSH-001` | High | A burst of SSH authentication failures from one source | 8 failures within 300 seconds, grouped by source IP |
| `SSH-002` | Critical | SSH login success following repeated authentication failures | 5 failures followed by a configured success event within 600 seconds, grouped by source IP |
| `SSH-003` | High | A successful SSH login for root | Single matching event |
| `SSH-004` | Medium | Repeated invalid SSH usernames from one source | 5 invalid-user events within 300 seconds, grouped by source IP |
| `ACCOUNT-001` | Medium | A local account-creation event | Single matching event, grouped by username |
| `PRIV-001` | Medium | A burst of logged sudo commands by one user | 10 events within 300 seconds, grouped by username |

These rules identify review-worthy patterns, not confirmed attacks. Legitimate administrators, automation, test activity, and misconfigured clients can trigger similar findings.

## How it works

```text
Local log file or standard input
             |
             v
   Format selection and parsing
             |
             v
     Normalized event records
             |
             v
    TOML rule loading/validation
             |
             v
  Threshold and sequence correlation
             |
             v
     Evidence-backed findings
          /          \
         v            v
   Terminal text    JSON report
```

The pipeline is intentionally straightforward so individual stages can be tested and extended without tightly coupling them to command-line handling.

## Requirements

- Linux or another environment with a supported Rust toolchain.
- Rust 1.85 or newer, as declared in `Cargo.toml`.
- A readable log file or a stream piped to standard input.

## Build and install

Clone the repository and build the optimized binary:

```bash
git clone https://github.com/raxwqx/TIDEWATCH.git
cd TIDEWATCH
cargo build --release
```

The executable is written to `target/release/tidewatch`. You can run it from the repository directory or copy the binary to a directory in your `PATH`.

No daemon, privileged service, or network connection is required for normal file analysis. Reading protected system logs may require appropriate local permissions.

## Quick start

### 1. Analyze the included authentication-log fixture

```bash
cargo run --release -- --input examples/sample-auth.log
```

The sample is synthetic training data. It is safe to use for familiarizing yourself with the report format and bundled detections.

### 2. Save a JSON report

```bash
cargo run --release -- \
  --input examples/sample-auth.log \
  --output-format json \
  --output report.json
```

### 3. Analyze a JSONL fixture

```bash
cargo run --release -- \
  --input examples/sample-jsonl.jsonl \
  --format jsonl \
  --output-format json
```

### 4. Read logs from standard input

```bash
cat /var/log/auth.log | target/release/tidewatch --format authlog
```

You can also redirect a file directly with `--input /path/to/logfile`. Use only logs you are authorized to access.

### 5. Return a non-zero status when a severity threshold is met

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --fail-on-severity high
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Analysis completed and no alert met the selected severity threshold, or no threshold was configured |
| `1` | An execution or input error occurred |
| `2` | At least one alert met or exceeded `--fail-on-severity` |

## Command-line reference

Run `tidewatch --help` or `cargo run -- --help` to view the CLI options.

| Option | Default | Description |
| --- | --- | --- |
| `-i, --input <PATH>` | `-` | Input file path; `-` reads standard input |
| `--format <FORMAT>` | `auto` | Parser selection: `auto`, `authlog`, or `jsonl` |
| `--rules <PATH>` | Bundled rules | Load a custom TOML rules file |
| `--output-format <FORMAT>` | `text` | Output as `text` or `json` |
| `-o, --output <PATH>` | Standard output | Write the report to a file instead of standard output |
| `--fail-on-severity <SEVERITY>` | Disabled | Exit with status `2` if any finding meets or exceeds `info`, `low`, `medium`, `high`, or `critical` |
| `--include-events` | Disabled | Include normalized events in JSON output; requires `--output-format json` |

Example help command:

```bash
cargo run -- --help
```

## Input formats

### Linux authlog / syslog-style text

TIDEWATCH recognizes common authentication messages, including patterns similar to:

```text
Oct  9 19:01:01 lab-host sshd[2101]: Failed password for analyst from 203.0.113.77 port 50101 ssh2
```

Classification is based on supported message patterns. Messages the parser does not recognize remain visible as `other` events instead of being silently discarded.

**Timestamp caveat:** classic syslog timestamps often omit both the year and timezone. TIDEWATCH assigns the current UTC year to these timestamps, but the original timezone cannot be inferred from the line alone. Take care when correlating events across hosts or year boundaries.

### JSON Lines (JSONL)

JSONL input contains one JSON object per line. The parser prefers a `message` field and also recognizes `MESSAGE`, `msg`, or `event.original`. Optional fields can include `timestamp`, `host`, `program`, `pid`, `user`, `source_ip`, `command`, and `event_type`.

RFC 3339 and common ISO-like timestamps are supported. A malformed JSON line is counted and retained as an unclassified event in the report rather than silently ignored.

See [`examples/sample-jsonl.jsonl`](examples/sample-jsonl.jsonl) for a fixture.

## Detection rules

Bundled rules are defined in [`rules/default.toml`](rules/default.toml). A custom rules file can tune existing detections or add new combinations of supported event types.

Supported conditions:

- `threshold`: find a group of matching events that reaches `threshold` within `window_seconds`.
- `failure_then_success`: find the configured number of matching events followed by one of the configured success event kinds from the same group key within the time window.

Supported `group_by` values are `source_ip`, `user`, and `source_ip_user`. Time-window and sequence detections need parseable timestamps. Single-event rules can still work when timestamps are missing.

### Example custom rule

```toml
version = 1

[[rules]]
id = "CUSTOM-SSH-001"
name = "Repeated SSH failures from one source"
description = "Review repeated SSH authentication failures from a single source IP."
severity = "high"
condition = "threshold"
event_kinds = ["ssh_auth_failure"]
threshold = 6
window_seconds = 180
group_by = "source_ip"
mitre = ["T1110.001"]
enabled = true
```

Save the rule, for example as `my-rules.toml`, then run:

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --rules my-rules.toml
```

For `failure_then_success`, also set `success_event_kinds`, for example `["ssh_auth_success", "ssh_root_login"]`. The complete schema and correlation semantics are documented in [`docs/DETECTION_RULES.md`](docs/DETECTION_RULES.md).

### Rule behavior and tuning

- Rule IDs must be unique and non-empty; invalid rule configuration returns an error.
- A threshold rule emits at most one alert for each rule/group key when its first qualifying time window is observed.
- Evidence contains the events used to reach the configured threshold or complete the sequence.
- ATT&CK references provide investigation context and do not prove that a technique was used.
- Tune thresholds against both positive and negative fixtures to understand noise and false positives.

## Reports and evidence

Text output is designed for interactive triage. JSON output is intended for automation and further processing.

Reports provide a schema version and tool version, input format and parsing summary, alerts, severity totals, and evidence. Each alert can include:

- Stable rule ID, title, severity, and analyst-oriented description.
- Observed event count and the available source-IP or user pivots.
- Correlation start and end times when available.
- MITRE ATT&CK technique references configured for the rule.
- Original line numbers, event kinds, timestamps where available, and source messages.

Pass `--include-events` along with `--output-format json` to include the normalized event stream in the JSON report.

**Handle reports as sensitive data.** Real logs may contain usernames, hostnames, IP addresses, command lines, and raw messages. Review and redact this information before publishing a report or attaching it to a public issue.

## Testing and development

Run the local quality checks from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

To apply Rust formatting before checking again:

```bash
cargo fmt
```

GitHub Actions currently builds the project and runs the test suite on pushes and pull requests. When adding a parser pattern or rule, include representative positive and negative fixtures and tests for timestamp or missing-field edge cases where relevant.

## Architecture

The implementation is separated into focused Rust modules:

| Module | Responsibility |
| --- | --- |
| `parser` | Format selection, syslog/JSONL parsing, event classification, parser statistics |
| `model` | Normalized events, severity levels, alerts, and evidence types |
| `detection` | TOML rule validation, grouping keys, threshold windows, and sequence correlation |
| `report` | Human-readable rendering and structured JSON report creation |
| `main` | CLI arguments, file/stdin input, report output, and exit codes |

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the pipeline and design notes.

## Limitations

- TIDEWATCH is an offline triage helper, not a full SIEM, EDR, or automated incident-response platform.
- Current bundled detections focus on selected Linux authentication and account-management patterns; coverage is not exhaustive.
- Distribution-specific log formats and heavily customized syslog templates may require parser updates.
- Missing, inaccurate, or timezone-ambiguous timestamps reduce confidence in event ordering and correlation.
- Some log fields can be absent or spoofable. A matching source IP or username is not sufficient attribution by itself.
- Bundled thresholds are starter values, not universal policy. Legitimate activity can trigger alerts, and unsupported attack patterns may not be detected.
- The current tool analyzes supplied input; it does not collect logs continuously, monitor a host in real time, or take remediation actions.

## Responsible use and data handling

Use TIDEWATCH only on logs you own or are explicitly authorized to analyze. The project is intended for defensive investigation, security learning, and incident-triage workflows.

TIDEWATCH does not scan networks, open remote connections, or upload input logs. Keep source logs and reports protected under the same access and retention requirements as the system from which they came.

For vulnerability reports about this project, consult [`SECURITY.md`](SECURITY.md).

## Roadmap ideas

Potential future work, subject to testing and design review:

- Broader, fixture-backed parsing for additional Linux audit and authentication log variants.
- More negative tests and regression fixtures for detection edge cases.
- Additional correlation primitives while keeping rule behavior deterministic and explainable.
- Optional HTML or timeline-oriented report output.

These are ideas, not capabilities in the current release.

## License

Released under the MIT License. See [`LICENSE`](LICENSE).
