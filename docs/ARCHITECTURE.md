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

- `parser`: format selection, syslog/JSONL parsing, event classification, and parser statistics.
- `model`: serializable normalized event, severity, alert, and evidence types.
- `detection`: rule schema validation, group-key construction, windowed thresholds, and failure-then-success correlation.
- `report`: stable JSON structure and human-readable rendering.
- `main`: argument validation, file/stdin I/O, and process exit behavior.

## Design principles

1. **Offline-first:** no network client or upload path is implemented.
2. **Evidence over verdicts:** alerts include event lines and use investigative language rather than asserting compromise.
3. **Deterministic correlation:** groups and output order are stabilized to keep reports reviewable and tests repeatable, except for report generation time and year inference for classic syslog timestamps.
4. **Visible parsing gaps:** unsupported messages remain in the event stream as `other`; malformed JSONL is counted.
5. **Configurable detections:** thresholds and grouping keys are data-driven TOML, not hard-coded command-line switches.

## Timestamp handling

RFC 3339 timestamps are normalized to UTC. Plain ISO-like timestamps remain naive timestamps. Classic syslog timestamps are assigned the current UTC year because the source format has no year. The source timezone cannot be inferred from a bare syslog line; users should avoid treating cross-host ordering as authoritative without corroborating timestamps.
