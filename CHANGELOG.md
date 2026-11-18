# Changelog

All notable changes to TIDEWATCH are documented in this file.

## 0.2.0 - Event overview and parser hardening

### Added

- Added `--summary` for an event overview in text reports and an `event_summary` object in JSON reports. The overview includes the observed time range, timestamp coverage, event-kind counts, and top source-IP and user pivots.
- Added `--top <N>` to control how many entries each summary pivot list contains (1-100, default 5).
- Added JSON report `schema_version` 2 for the optional `event_summary` field.
- Added CLI tests for summary rendering, summary JSON, and `--top` validation.
- Added parser and correlation boundary tests for nested JSONL fields, fractional timestamps, inclusive windows, single-event timestamp selection, and invalid rule configuration.
- Added a cross-platform CI matrix with formatting, Clippy, tests, release build, and example smoke tests.
- Added Dependabot configuration for Cargo and GitHub Actions dependencies.
- Added a Turkish README (`README.tr.md`).

### Fixed

- JSONL parsing now resolves nested fields such as `event.original`, `event.kind`, `event.action`, `host.name`, `process.name`, `process.pid`, `user.name`, `source.ip`, `client.ip`, and `process.command_line`, while still accepting literal dotted keys.
- Fractional epoch timestamps are now parsed from JSON numbers and decimal strings instead of being discarded.
- `Failed none`, `Failed gssapi-with-mic`, `Failed hostbased`, and the corresponding `Accepted` SSH messages are now classified.
- Single-event rules now prefer an event with a parseable timestamp when a group also contains timestamp-less events.
- Classic syslog timestamps resolve their year once per run, avoiding inconsistent years when parsing crosses a New Year boundary.
- Rule files now reject unknown fields, so a misspelled option fails validation instead of being silently ignored.
- Rule parsing is exposed through `parse_rules` for direct validation and testing.
- Expanded security guidance and clarified report data handling.

## 0.1.0 - Initial release

- Added offline parsing for common Linux authlog/syslog and JSONL records.
- Added normalized event models and parser statistics.
- Added TOML-configurable threshold and failure-then-success detections.
- Added starter SSH, account-creation, and sudo activity rules.
- Added terminal and JSON reports with event evidence and ATT&CK references.
- Added unit tests, CLI integration test, examples, documentation, and GitHub Actions CI.
