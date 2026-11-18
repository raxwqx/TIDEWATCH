# Detection rule schema

Rules are stored in TOML and the root `version` field must be `1`.

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable, unique rule identifier. |
| `name` | yes | Short alert title. |
| `description` | yes | Analyst-oriented explanation and next step. |
| `severity` | yes | `info`, `low`, `medium`, `high`, or `critical`. |
| `condition` | no | `threshold` by default, or `failure_then_success`. |
| `event_kinds` | yes | Event kinds to count as failures/matches. |
| `success_event_kinds` | sequence only | Event kinds that complete a sequence. |
| `threshold` | yes | Number of matching events required. |
| `window_seconds` | yes | Maximum correlation window in seconds. |
| `group_by` | yes | `source_ip`, `user`, or `source_ip_user`. |
| `mitre` | no | MITRE ATT&CK technique IDs for triage context. |
| `enabled` | no | Defaults to `true`. |

Unknown fields are rejected. A misspelled option such as `threshhold` fails rule loading instead of being silently ignored. The same applies to unknown top-level keys in the rules file.

## Current normalized event kinds

- `ssh_auth_failure`
- `ssh_auth_success`
- `ssh_invalid_user`
- `ssh_root_login`
- `sudo_command`
- `user_added`
- `password_changed`
- `session_opened`
- `other`

## Correlation semantics

A threshold rule emits at most one alert for each rule/group key, when the first qualifying time window is observed. Its evidence contains the events needed to reach the threshold. A sequence rule looks for the configured failure count followed by a configured success kind from the same group key within `window_seconds`; the successful event is included in the evidence. The engine does not deduplicate based on connection port or session ID, so rules should be tuned with the source log's semantics in mind.

Both correlation windows are inclusive: an event exactly `window_seconds` after the first event in a threshold window still counts, and a success exactly `window_seconds` after a failure still completes a sequence.

Time-window and sequence rules require parseable timestamps. Rules with `threshold = 1` also work on timestamp-less records; when a group contains both timestamped and timestamp-less events, the alert prefers a timestamped event.

Events without a usable grouping key (for example, an event missing a source IP for a `source_ip` rule) are skipped for that rule. They remain visible in the normalized event stream and in `--summary` counts.

ATT&CK IDs are triage references, not a claim that a technique was conclusively used. Keep custom rules under version control and test them against both positive and negative fixtures.

## Validating custom rules

Run the tool with the custom rule file and an input that you control. Rule-loading errors are reported with a non-zero exit code before detection starts:

```bash
target/release/tidewatch \
  --input examples/sample-auth.log \
  --rules my-rules.toml \
  --summary
```

Use `--summary` to confirm that the parser sees the event kinds your rule expects. A rule that never matches may be looking for a kind that the input does not produce.
