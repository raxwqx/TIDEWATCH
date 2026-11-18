use std::net::IpAddr;
use std::sync::LazyLock;

use chrono::{DateTime, Datelike, NaiveDateTime, Utc};
use clap::ValueEnum;
use regex::Regex;
use serde_json::Value;

use crate::model::{EventKind, LogEvent};

static SYSLOG_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<program>[^\s\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$",
    )
    .expect("valid syslog header regex")
});
static SSH_FAILURE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)Failed (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased|none) for (?:(?:invalid|illegal) user\s+)?(?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)")
        .expect("valid SSH failure regex")
});
static SSH_INVALID_USER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bInvalid user (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)")
        .expect("valid invalid-user regex")
});
static SSH_SUCCESS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\bAccepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic|hostbased) for (?P<user>[^\s]+) from (?P<ip>[0-9a-fA-F:.]+)")
        .expect("valid SSH success regex")
});
static SUDO_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^(?P<user>[^\s:]+)\s*:.*\bCOMMAND=(?P<command>.+)$").expect("valid sudo regex")
});
static USER_ADDED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(?:new user:\s*name=|added user\s+)(?P<user>[A-Za-z0-9_.-]+)")
        .expect("valid user-add regex")
});
static PASSWORD_CHANGED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)password (?:changed|updated) for (?P<user>[^\s.]+)")
        .expect("valid password-change regex")
});
static SESSION_OPENED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)session opened for user (?P<user>[^\s(]+)").expect("valid session-open regex")
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum InputFormat {
    Auto,
    Authlog,
    Jsonl,
}

#[derive(Debug, Clone, Default)]
pub struct ParseStats {
    pub lines_seen: usize,
    pub blank_lines: usize,
    pub events_emitted: usize,
    pub classified_events: usize,
    pub unclassified_events: usize,
    pub malformed_json_lines: usize,
}

pub struct ParsedInput {
    pub events: Vec<LogEvent>,
    pub stats: ParseStats,
    pub detected_format: InputFormat,
}

pub fn parse_input(input: &str, requested_format: InputFormat) -> ParsedInput {
    let detected_format = match requested_format {
        InputFormat::Auto => detect_format(input),
        explicit => explicit,
    };
    let mut events = Vec::new();
    let mut stats = ParseStats::default();
    // Resolve the year once so every classic syslog timestamp in one run uses the
    // same year, even if parsing crosses a New Year boundary.
    let syslog_year = Utc::now().year();

    for (index, line) in input.lines().enumerate() {
        stats.lines_seen += 1;
        let line_number = index + 1;
        if line.trim().is_empty() {
            stats.blank_lines += 1;
            continue;
        }

        let (event, malformed_json) = match detected_format {
            InputFormat::Jsonl => parse_jsonl_line(line, line_number),
            InputFormat::Authlog | InputFormat::Auto => {
                (parse_authlog_line(line, line_number, syslog_year), false)
            }
        };
        if malformed_json {
            stats.malformed_json_lines += 1;
        }
        if event.kind == EventKind::Other {
            stats.unclassified_events += 1;
        } else {
            stats.classified_events += 1;
        }
        stats.events_emitted += 1;
        events.push(event);
    }

    ParsedInput {
        events,
        stats,
        detected_format,
    }
}

fn detect_format(input: &str) -> InputFormat {
    if let Some(line) = input.lines().map(str::trim).find(|line| !line.is_empty()) {
        return if line.starts_with('{') {
            InputFormat::Jsonl
        } else {
            InputFormat::Authlog
        };
    }
    InputFormat::Authlog
}

fn parse_authlog_line(line: &str, line_number: usize, syslog_year: i32) -> LogEvent {
    let (timestamp, host, program, pid, message) =
        if let Some(captures) = SYSLOG_HEADER.captures(line) {
            let timestamp = captures
                .name("ts")
                .and_then(|value| parse_syslog_timestamp(value.as_str(), syslog_year));
            let host = captures.name("host").map(|value| value.as_str().to_owned());
            let program = captures
                .name("program")
                .map(|value| value.as_str().to_owned());
            let pid = captures
                .name("pid")
                .and_then(|value| value.as_str().parse::<u32>().ok());
            let message = captures
                .name("message")
                .map(|value| value.as_str())
                .unwrap_or_default();
            (timestamp, host, program, pid, message)
        } else {
            (None, None, None, None, line)
        };

    classify_message(line_number, timestamp, host, program, pid, message)
}

fn parse_jsonl_line(line: &str, line_number: usize) -> (LogEvent, bool) {
    let value: Value = match serde_json::from_str(line) {
        Ok(value) => value,
        Err(_) => {
            return (
                LogEvent {
                    line_number,
                    timestamp: None,
                    host: None,
                    program: None,
                    pid: None,
                    kind: EventKind::Other,
                    user: None,
                    source_ip: None,
                    command: None,
                    message: line.to_owned(),
                },
                true,
            );
        }
    };

    let message = string_field(
        &value,
        &[
            "message",
            "MESSAGE",
            "msg",
            "event.original",
            "event.message",
        ],
    )
    .map(str::to_owned)
    .unwrap_or_else(|| value.to_string());
    let timestamp = parse_json_timestamp(&value);
    let host =
        string_field(&value, &["host", "hostname", "HOSTNAME", "host.name"]).map(str::to_owned);
    let program = string_field(
        &value,
        &["program", "SYSLOG_IDENTIFIER", "process", "process.name"],
    )
    .map(str::to_owned);
    let pid = ["pid", "_PID", "process.pid"]
        .iter()
        .find_map(|key| lookup_field(&value, key))
        .and_then(value_to_u32);

    let mut event = classify_message(line_number, timestamp, host, program, pid, &message);

    if event.user.is_none() {
        event.user =
            string_field(&value, &["user", "username", "USER", "user.name"]).map(str::to_owned);
    }
    if event.source_ip.is_none() {
        event.source_ip = string_field(
            &value,
            &["source_ip", "src_ip", "client_ip", "source.ip", "client.ip"],
        )
        .and_then(|raw| raw.parse::<IpAddr>().ok());
    }
    if event.command.is_none() {
        event.command = string_field(
            &value,
            &["command", "COMMAND", "process.command_line", "process.args"],
        )
        .map(str::to_owned);
    }
    if let Some(raw_kind) = string_field(
        &value,
        &["event_type", "kind", "event.kind", "event.action"],
    ) {
        let normalized = raw_kind.to_ascii_lowercase();
        if let Ok(kind) = serde_json::from_value::<EventKind>(Value::String(normalized)) {
            event.kind = kind;
        }
    }

    (event, false)
}

fn classify_message(
    line_number: usize,
    timestamp: Option<NaiveDateTime>,
    host: Option<String>,
    program: Option<String>,
    pid: Option<u32>,
    message: &str,
) -> LogEvent {
    let mut event = LogEvent {
        line_number,
        timestamp,
        host,
        program,
        pid,
        kind: EventKind::Other,
        user: None,
        source_ip: None,
        command: None,
        message: message.to_owned(),
    };

    if let Some(captures) = SSH_FAILURE.captures(message) {
        event.kind = EventKind::SshAuthFailure;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        event.source_ip = captures
            .name("ip")
            .and_then(|value| value.as_str().parse::<IpAddr>().ok());
        return event;
    }
    if let Some(captures) = SSH_SUCCESS.captures(message) {
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        event.source_ip = captures
            .name("ip")
            .and_then(|value| value.as_str().parse::<IpAddr>().ok());
        event.kind = if event.user.as_deref() == Some("root") {
            EventKind::SshRootLogin
        } else {
            EventKind::SshAuthSuccess
        };
        return event;
    }
    if let Some(captures) = SSH_INVALID_USER.captures(message) {
        event.kind = EventKind::SshInvalidUser;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        event.source_ip = captures
            .name("ip")
            .and_then(|value| value.as_str().parse::<IpAddr>().ok());
        return event;
    }
    if let Some(captures) = SUDO_COMMAND.captures(message) {
        event.kind = EventKind::SudoCommand;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        event.command = captures
            .name("command")
            .map(|value| value.as_str().to_owned());
        return event;
    }
    if let Some(captures) = USER_ADDED.captures(message) {
        event.kind = EventKind::UserAdded;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        return event;
    }
    if let Some(captures) = PASSWORD_CHANGED.captures(message) {
        event.kind = EventKind::PasswordChanged;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
        return event;
    }
    if let Some(captures) = SESSION_OPENED.captures(message) {
        event.kind = EventKind::SessionOpened;
        event.user = captures.name("user").map(|value| value.as_str().to_owned());
    }

    event
}

fn parse_syslog_timestamp(raw: &str, year: i32) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(&format!("{year} {raw}"), "%Y %b %e %H:%M:%S").ok()
}

fn parse_json_timestamp(value: &Value) -> Option<NaiveDateTime> {
    for key in [
        "timestamp",
        "ts",
        "@timestamp",
        "time",
        "event.created",
        "event.ingested",
    ] {
        if let Some(raw) = lookup_field(value, key) {
            if let Some(parsed) = timestamp_value(raw, 1) {
                return Some(parsed);
            }
        }
    }
    lookup_field(value, "__REALTIME_TIMESTAMP").and_then(|raw| timestamp_value(raw, 1_000_000))
}

fn timestamp_value(value: &Value, units_per_second: i64) -> Option<NaiveDateTime> {
    if let Some(raw) = value.as_str() {
        if let Ok(parsed) = DateTime::parse_from_rfc3339(raw) {
            return Some(parsed.naive_utc());
        }
        for format in [
            "%Y-%m-%d %H:%M:%S%.f",
            "%Y-%m-%dT%H:%M:%S%.f",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ] {
            if let Ok(parsed) = NaiveDateTime::parse_from_str(raw, format) {
                return Some(parsed);
            }
        }
        if let Ok(epoch) = raw.parse::<i64>() {
            return epoch_to_naive(epoch, units_per_second);
        }
        if let Ok(epoch) = raw.parse::<f64>() {
            return epoch_f64_to_naive(epoch, units_per_second);
        }
    }
    if let Some(epoch) = value.as_i64() {
        return epoch_to_naive(epoch, units_per_second);
    }
    if let Some(epoch) = value.as_f64() {
        return epoch_f64_to_naive(epoch, units_per_second);
    }
    None
}

fn epoch_to_naive(epoch: i64, units_per_second: i64) -> Option<NaiveDateTime> {
    let seconds = epoch.div_euclid(units_per_second);
    let remainder = epoch.rem_euclid(units_per_second);
    let nanos = ((remainder as i128 * 1_000_000_000_i128) / units_per_second as i128) as u32;
    DateTime::from_timestamp(seconds, nanos).map(|value| value.naive_utc())
}

fn epoch_f64_to_naive(epoch: f64, units_per_second: i64) -> Option<NaiveDateTime> {
    if !epoch.is_finite() {
        return None;
    }
    let seconds_f = epoch / units_per_second as f64;
    if seconds_f < i64::MIN as f64 || seconds_f > i64::MAX as f64 {
        return None;
    }
    let whole = seconds_f.floor();
    let nanos = ((seconds_f - whole) * 1_000_000_000_f64).round();
    let mut seconds = whole as i64;
    let nanos = if nanos >= 1_000_000_000_f64 {
        seconds = seconds.checked_add(1)?;
        0
    } else {
        nanos as u32
    };
    DateTime::from_timestamp(seconds, nanos).map(|value| value.naive_utc())
}

/// Look up a JSON field, supporting both a literal dotted key such as
/// `"event.original"` and a nested path such as `{"event":{"original": ...}}`.
fn lookup_field<'a>(value: &'a Value, key: &str) -> Option<&'a Value> {
    if let Some(found) = value.get(key) {
        return Some(found);
    }
    let mut current = value;
    for part in key.split('.') {
        current = current.get(part)?;
    }
    Some(current)
}

fn string_field<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a str> {
    keys.iter()
        .find_map(|key| lookup_field(value, key).and_then(Value::as_str))
}

fn value_to_u32(value: &Value) -> Option<u32> {
    value
        .as_u64()
        .and_then(|number| u32::try_from(number).ok())
        .or_else(|| value.as_str().and_then(|raw| raw.parse::<u32>().ok()))
}

#[cfg(test)]
mod tests {
    use super::{InputFormat, parse_input};
    use crate::model::EventKind;

    #[test]
    fn parses_failed_ssh_authentication() {
        let input = "Oct  9 19:01:01 lab-host sshd[100]: Failed password for alice from 203.0.113.8 port 50444 ssh2\n";
        let parsed = parse_input(input, InputFormat::Authlog);
        assert_eq!(parsed.events.len(), 1);
        assert_eq!(parsed.events[0].kind, EventKind::SshAuthFailure);
        assert_eq!(parsed.events[0].user.as_deref(), Some("alice"));
        assert_eq!(
            parsed.events[0].source_ip.unwrap().to_string(),
            "203.0.113.8"
        );
    }

    #[test]
    fn auto_detects_jsonl_and_keeps_malformed_lines_visible() {
        let input = "{\"timestamp\":\"2026-10-09T19:00:00Z\",\"message\":\"Accepted password for styx from 198.51.100.9 port 2200 ssh2\"}\nnot-json\n";
        let parsed = parse_input(input, InputFormat::Auto);
        assert_eq!(parsed.detected_format, InputFormat::Jsonl);
        assert_eq!(parsed.stats.malformed_json_lines, 1);
        assert_eq!(parsed.events[0].kind, EventKind::SshAuthSuccess);
        assert_eq!(parsed.events[1].kind, EventKind::Other);
    }

    #[test]
    fn parses_root_ssh_login_as_a_distinct_event() {
        let input = "Oct  9 19:01:01 lab-host sshd[100]: Accepted publickey for root from 192.0.2.14 port 50444 ssh2\n";
        let parsed = parse_input(input, InputFormat::Authlog);
        assert_eq!(parsed.events[0].kind, EventKind::SshRootLogin);
    }

    #[test]
    fn parses_failed_none_and_gssapi_authentication() {
        let input = concat!(
            "Oct  9 19:01:01 lab-host sshd[100]: Failed none for alice from 203.0.113.8 port 50444 ssh2\n",
            "Oct  9 19:01:02 lab-host sshd[100]: Failed gssapi-with-mic for bob from 203.0.113.9 port 50445 ssh2\n",
            "Oct  9 19:01:03 lab-host sshd[100]: Accepted gssapi-with-mic for carol from 203.0.113.10 port 50446 ssh2\n"
        );
        let parsed = parse_input(input, InputFormat::Authlog);
        assert_eq!(parsed.events[0].kind, EventKind::SshAuthFailure);
        assert_eq!(parsed.events[0].user.as_deref(), Some("alice"));
        assert_eq!(parsed.events[1].kind, EventKind::SshAuthFailure);
        assert_eq!(parsed.events[2].kind, EventKind::SshAuthSuccess);
    }

    #[test]
    fn reads_nested_ecs_fields_and_nested_event_kind() {
        let input = concat!(
            r#"{"@timestamp":"2026-10-09T19:00:00.250Z","event":{"original":"session note","kind":"ssh_auth_failure"},"#,
            r#""host":{"name":"lab-host"},"user":{"name":"bob"},"source":{"ip":"198.51.100.9"},"process":{"pid":4242,"name":"sshd"},"command":"/usr/bin/id"}"#,
            "\n"
        );
        let parsed = parse_input(input, InputFormat::Jsonl);
        let event = &parsed.events[0];
        assert_eq!(event.kind, EventKind::SshAuthFailure);
        assert_eq!(event.message, "session note");
        assert_eq!(event.host.as_deref(), Some("lab-host"));
        assert_eq!(event.user.as_deref(), Some("bob"));
        assert_eq!(event.source_ip.unwrap().to_string(), "198.51.100.9");
        assert_eq!(event.program.as_deref(), Some("sshd"));
        assert_eq!(event.pid, Some(4242));
        assert_eq!(event.command.as_deref(), Some("/usr/bin/id"));
        assert_eq!(
            event.timestamp.unwrap().and_utc().timestamp_subsec_nanos(),
            250_000_000
        );
    }

    #[test]
    fn reads_fractional_epoch_timestamps() {
        let input = "{\"timestamp\":1760036400.5,\"message\":\"Failed password for bob from 203.0.113.9 port 22 ssh2\"}\n";
        let parsed = parse_input(input, InputFormat::Jsonl);
        assert_eq!(parsed.events[0].kind, EventKind::SshAuthFailure);
        assert_eq!(
            parsed.events[0].timestamp.unwrap().and_utc().timestamp(),
            1_760_036_400
        );
        assert_eq!(
            parsed.events[0]
                .timestamp
                .unwrap()
                .and_utc()
                .timestamp_subsec_nanos(),
            500_000_000
        );

        let string_input = "{\"time\":\"1760036400.25\",\"message\":\"Accepted password for bob from 203.0.113.9 port 22 ssh2\"}\n";
        let parsed = parse_input(string_input, InputFormat::Jsonl);
        assert_eq!(
            parsed.events[0]
                .timestamp
                .unwrap()
                .and_utc()
                .timestamp_subsec_nanos(),
            250_000_000
        );
    }
}
