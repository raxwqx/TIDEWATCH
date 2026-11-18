# Architecture

TIDEWATCH separates ingestion, normalized event data, detection logic, and report rendering so each part can be extended and tested without coupling it to the command-line interface.

```text
File / stdin
    |
    v
Input format selection (authlog / JSONL)
    |
    v
Parser + conservative event classification
    |
    v
Normalized LogEvent records
    |
    +--> Optional event overview (--summary)
    |
    v
TOML rule validation
    |
    v
Threshold + sequence correlation engine
    |
    v
Evidence-backed Alert records
    |
    +--> Terminal report
    +--> JSON report
```

## Modules

- `parser`: format selection, syslog/JSONL parsing, nested-field lookup, event classification, and parser statistics.
- `model`: serializable normalized event, severity, alert, and evidence types.
- `detection`: rule schema validation, group-key construction, windowed thresholds, and failure-then-success correlation.
- `report`: stable JSON structure, event-overview aggregation, and human-readable rendering.
- `main`: argument validation, file/stdin I/O, and process exit behavior.

## Design principles

1. **Offline-first:** no network client or upload path is implemented.
2. **Evidence over verdicts:** alerts include event lines and use investigative language rather than asserting compromise.
3. **Deterministic correlation:** groups and output order are stabilized to keep reports reviewable and tests repeatable, except for report generation time and year inference for classic syslog timestamps.
4. **Visible parsing gaps:** unsupported messages remain in the event stream as `other`; malformed JSONL is counted.
5. **Configurable detections:** thresholds and grouping keys are data-driven TOML, not hard-coded command-line switches.
6. **Explicit schemas:** unknown rule fields fail validation, and the JSON report carries a schema version so optional additions stay traceable.

## Timestamp handling

RFC 3339 timestamps are normalized to UTC. Plain ISO-like timestamps remain naive timestamps. Classic syslog timestamps are assigned the current UTC year because the source format has no year; the year is resolved once per run so a single report does not mix years. The source timezone cannot be inferred from a bare syslog line; users should avoid treating cross-host ordering as authoritative without corroborating timestamps.

JSONL timestamps support RFC 3339 strings, plain ISO-like strings, integer epoch values, and fractional epoch values in numeric or string form. `__REALTIME_TIMESTAMP` is interpreted as microseconds; other timestamp fields are interpreted as seconds.

## Event overview

`--summary` is computed from the normalized event stream before alerts are rendered. It aggregates event-kind counts, timestamp coverage, the first and last observed timestamps, and top source-IP and user pivots. `--top` bounds each pivot list. The overview is optional so the default JSON schema remains small, and it is included as `event_summary` in schema version 2 reports.

## Exit status

`0` means the analysis completed without a configured failure condition. `1` means an execution, input, or rule-loading error. `2` means an alert met `--fail-on-severity` or, when enabled, malformed JSONL was observed. A status `2` report is still written so automation can retain the partial analysis.
