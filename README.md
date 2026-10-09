# TIDEWATCH

**Offline Linux log threat hunting and incident triage, written in Rust.**

TIDEWATCH turns supported Linux authentication and system log lines into normalized events, correlates activity with local detection rules, and emits an evidence-backed report. It is designed for defensive security research, incident-response practice, and repeatable analysis of logs you are authorized to review.

> A finding is an investigative lead, not proof of compromise. Validate it against surrounding telemetry and the host's expected behavior.

## What it does

- Parses common Linux `auth.log` / syslog-style lines and JSON Lines (`JSONL`) events.
- Normalizes timestamps, host, process, user, source IP, command, and event type where present.
- Applies configurable TOML detection rules with event thresholds, time windows, grouping keys, and failure-then-success correlation.
- Includes triage rules for SSH authentication bursts, successful SSH login after repeated failures, remote root SSH logins, invalid-user probing, account creation, and repeated `sudo` command activity.
- Adds MITRE ATT&CK technique references to relevant findings.
- Produces readable terminal output or machine-readable JSON, with source line numbers and evidence messages.
- Supports threshold-based exit codes for scripts and CI pipelines.
- Runs locally and offline. It does not scan hosts, open network connections, or upload logs.

## Requirements

- Rust toolchain compatible with Rust 1.85 or newer.
- A local log file or input piped to standard input.

## Build

```bash
git clone https://github.com/raxwqx/TIDEWATCH.git
cd TIDEWATCH
cargo build --release
```

The binary will be available at `target/release/tidewatch`.

## Quick start

Analyze the included sample authentication log:

```bash
cargo run --release -- --input examples/sample-auth.log
```

Write a JSON report:

```bash
cargo run --release -- \
  --input examples/sample-auth.log \
  --output-format json \
  --output report.json
```

Analyze a JSONL feed:

```bash
cargo run --release -- \
  --input examples/sample-jsonl.jsonl \
  --format jsonl \
  --output-format json
```

Read from a pipe:

```bash
cat /var/log/auth.log | target/release/tidewatch --format authlog
```

Make a script return exit code `2` if a high-or-critical finding is present:

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --fail-on-severity high
```

The exit status is `0` when no alert meets the requested threshold, `2` when the threshold is met, and `1` for an execution or input error.

## CLI reference

```text
tidewatch --help
```

| Option | Purpose |
| --- | --- |
| `-i, --input <PATH>` | Input file, or `-` for standard input (default). |
| `--format <auto\|authlog\|jsonl>` | Select the parser. Auto mode inspects the first non-empty line. |
| `--rules <PATH>` | Load a custom TOML rules file. Bundled rules are used when omitted. |
| `--output-format <text\|json>` | Choose terminal text or JSON output. |
| `-o, --output <PATH>` | Write the rendered report to a file. |
| `--fail-on-severity <SEVERITY>` | Return status `2` when an alert is at least `info`, `low`, `medium`, `high`, or `critical`. |
| `--include-events` | Include normalized events in JSON output. Requires `--output-format json`. |

## Detection rules

Bundled rules live in [`rules/default.toml`](rules/default.toml). Rules are local, editable, and versioned with the repository. Each rule defines a stable ID, explanation, severity, event kinds, correlation condition, threshold, time window, grouping key, and optional ATT&CK references.

Supported conditions:

- `threshold`: alert when a group reaches `threshold` matching events inside `window_seconds`.
- `failure_then_success`: correlate at least `threshold` matching failure events with a later success event from the same grouping key and within the configured time window.

Supported grouping keys are `source_ip`, `user`, and `source_ip_user`. Time-window and sequence rules need parseable timestamps. Single-event rules can still run when a timestamp is missing.

Example custom rule:

```toml
version = 1

[[rules]]
id = "CUSTOM-SSH-001"
name = "Repeated SSH failures from one source"
description = "Investigate repeated SSH authentication failures from a source IP."
severity = "high"
condition = "threshold"
event_kinds = ["ssh_auth_failure"]
threshold = 6
window_seconds = 180
group_by = "source_ip"
mitre = ["T1110.001"]
enabled = true
```

Use it with:

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --rules my-rules.toml
```

A rule with `condition = "failure_then_success"` also needs `success_event_kinds`, for example `success_event_kinds = ["ssh_auth_success", "ssh_root_login"]`.

## Input formats

### Syslog / authentication log

The parser recognizes common lines such as:

```text
Oct  9 19:01:01 lab-host sshd[2101]: Failed password for analyst from 203.0.113.77 port 50101 ssh2
```

Traditional syslog timestamps usually omit the year and timezone. TIDEWATCH attaches the current UTC year to these timestamps but cannot infer the host's original timezone. Keep this caveat in mind when working across year boundaries or comparing events from multiple hosts.

### JSON Lines

Each line should be a JSON object. A `message` field is preferred; `MESSAGE`, `msg`, or `event.original` are also recognized. Optional fields include `timestamp`, `host`, `program`, `pid`, `user`, `source_ip`, `command`, and `event_type`. RFC 3339 and common ISO-like timestamps are supported. A malformed JSON line is retained as an unclassified event and counted in the report, rather than silently discarded.

See [`examples/sample-jsonl.jsonl`](examples/sample-jsonl.jsonl).

## Report fields

JSON reports include a schema version, tool version, input format, parse summary, alert list, and severity totals. Alerts include the rule ID, severity, description, grouping pivots, time window, ATT&CK references, and event evidence with original line numbers. Add `--include-events` if you also need the normalized event list.

Treat reports as sensitive data. Hostnames, usernames, IP addresses, command lines, and raw log messages may be present. Redact them before publishing or attaching a report to a public issue.

## Development

```bash
cargo test
cargo run -- --input examples/sample-auth.log
cargo run -- --input examples/sample-jsonl.jsonl --format jsonl --output-format json
```

CI builds the project and runs unit and command-line integration tests on pushes and pull requests.

## Scope and limitations

- This is an offline triage helper, not a full SIEM, EDR, or proof of compromise.
- Initial detectors cover selected Linux authentication/account-management patterns; unsupported messages remain visible as `other` events.
- The parser is intentionally conservative and may need adaptation for distro-specific log formats or heavily customized syslog templates.
- Some syslog formats omit year and timezone, which limits reliable cross-host temporal correlation.
- Event grouping uses the source fields present in a log. Missing or spoofable fields can reduce confidence.
- Detection thresholds are starter defaults, not universal policy. Tune them to the environment and review false positives.

## Responsible use

Use TIDEWATCH on logs you own or are explicitly authorized to analyze. It is designed for defensive investigation and local learning. It does not perform remote actions or attempt to access systems.

## License

MIT. See [`LICENSE`](LICENSE).
