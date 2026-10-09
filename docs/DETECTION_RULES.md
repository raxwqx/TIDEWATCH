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

ATT&CK IDs are triage references, not a claim that a technique was conclusively used. Keep custom rules under version control and test them against both positive and negative fixtures.
