use std::collections::BTreeMap;

use chrono::{NaiveDateTime, Utc};
use serde::Serialize;

use crate::model::{Alert, LogEvent, Severity};
use crate::parser::ParseStats;

#[derive(Debug, Clone, Serialize)]
pub struct CountEntry {
    pub value: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EventSummary {
    pub events_total: usize,
    pub events_with_timestamp: usize,
    pub events_without_timestamp: usize,
    pub first_timestamp: Option<NaiveDateTime>,
    pub last_timestamp: Option<NaiveDateTime>,
    pub duration_seconds: Option<i64>,
    pub by_kind: BTreeMap<String, usize>,
    pub top_source_ips: Vec<CountEntry>,
    pub top_users: Vec<CountEntry>,
}

impl EventSummary {
    /// Build an analyst-facing overview of the normalized event stream.
    pub fn from_events(events: &[LogEvent], top: usize) -> Self {
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        let mut source_ips: BTreeMap<String, usize> = BTreeMap::new();
        let mut users: BTreeMap<String, usize> = BTreeMap::new();
        let mut first_timestamp: Option<NaiveDateTime> = None;
        let mut last_timestamp: Option<NaiveDateTime> = None;
        let mut events_with_timestamp = 0usize;

        for event in events {
            *by_kind.entry(event.kind.as_str().to_owned()).or_insert(0) += 1;
            if let Some(ip) = event.source_ip {
                *source_ips.entry(ip.to_string()).or_insert(0) += 1;
            }
            if let Some(user) = event.user.as_deref().filter(|user| !user.is_empty()) {
                *users.entry(user.to_owned()).or_insert(0) += 1;
            }
            if let Some(timestamp) = event.timestamp {
                events_with_timestamp += 1;
                first_timestamp =
                    Some(first_timestamp.map_or(timestamp, |current| current.min(timestamp)));
                last_timestamp =
                    Some(last_timestamp.map_or(timestamp, |current| current.max(timestamp)));
            }
        }

        let duration_seconds = first_timestamp
            .zip(last_timestamp)
            .map(|(start, end)| (end - start).num_seconds());

        Self {
            events_total: events.len(),
            events_with_timestamp,
            events_without_timestamp: events.len() - events_with_timestamp,
            first_timestamp,
            last_timestamp,
            duration_seconds,
            by_kind,
            top_source_ips: top_entries(source_ips, top),
            top_users: top_entries(users, top),
        }
    }
}

fn top_entries(counts: BTreeMap<String, usize>, top: usize) -> Vec<CountEntry> {
    let mut entries: Vec<CountEntry> = counts
        .into_iter()
        .map(|(value, count)| CountEntry { value, count })
        .collect();
    entries.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.value.cmp(&right.value))
    });
    entries.truncate(top);
    entries
}

#[derive(Debug, Serialize)]
pub struct ReportSummary {
    pub lines_seen: usize,
    pub events_emitted: usize,
    pub classified_events: usize,
    pub unclassified_events: usize,
    pub malformed_json_lines: usize,
    pub alerts_total: usize,
    pub alerts_by_severity: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    pub generated_at: String,
    pub input: String,
    pub detected_input_format: String,
    pub summary: ReportSummary,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_summary: Option<EventSummary>,
    pub alerts: Vec<Alert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<LogEvent>>,
}

impl Report {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        input: String,
        detected_input_format: String,
        stats: &ParseStats,
        alerts: Vec<Alert>,
        event_summary: Option<EventSummary>,
        events: Option<Vec<LogEvent>>,
        version: &str,
    ) -> Self {
        let mut alerts_by_severity = BTreeMap::new();
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            alerts_by_severity.insert(severity.as_str().to_owned(), 0);
        }
        for alert in &alerts {
            *alerts_by_severity
                .entry(alert.severity.as_str().to_owned())
                .or_insert(0) += 1;
        }
        let summary = ReportSummary {
            lines_seen: stats.lines_seen,
            events_emitted: stats.events_emitted,
            classified_events: stats.classified_events,
            unclassified_events: stats.unclassified_events,
            malformed_json_lines: stats.malformed_json_lines,
            alerts_total: alerts.len(),
            alerts_by_severity,
        };
        Self {
            schema_version: "2".to_owned(),
            tool: "TIDEWATCH".to_owned(),
            version: version.to_owned(),
            generated_at: Utc::now().to_rfc3339(),
            input,
            detected_input_format,
            summary,
            event_summary,
            alerts,
            events,
        }
    }
}

pub fn render_text(report: &Report) -> String {
    let summary = &report.summary;
    let mut output = String::new();
    output.push_str(&format!(
        "TIDEWATCH {} | Offline threat-hunting report\n",
        report.version
    ));
    output.push_str(&format!(
        "Input: {} ({})\n",
        report.input, report.detected_input_format
    ));
    output.push_str(&format!(
        "Events: {} parsed | {} classified | {} unclassified | {} malformed JSON\n",
        summary.events_emitted,
        summary.classified_events,
        summary.unclassified_events,
        summary.malformed_json_lines
    ));
    output.push_str(&format!("Alerts: {}\n", summary.alerts_total));
    if let Some(event_summary) = &report.event_summary {
        render_event_overview(&mut output, event_summary);
    }
    output.push_str(&"=".repeat(76));
    output.push('\n');

    if report.alerts.is_empty() {
        output.push_str("No configured detection rules matched the input.\n");
    }

    for (index, alert) in report.alerts.iter().enumerate() {
        output.push_str(&format!(
            "[{}] {} | {} | {} event(s)\n",
            alert.severity.as_str().to_ascii_uppercase(),
            alert.rule_id,
            alert.title,
            alert.observed_count
        ));
        output.push_str(&format!("  {}\n", alert.description));
        if let Some(source_ip) = alert.source_ip {
            output.push_str(&format!("  Source IP: {source_ip}\n"));
        }
        if let Some(user) = &alert.user {
            output.push_str(&format!("  User: {user}\n"));
        }
        if let (Some(start), Some(end)) = (alert.window_start, alert.window_end) {
            output.push_str(&format!("  Window: {start} -> {end}\n"));
        }
        if !alert.mitre_attack.is_empty() {
            output.push_str(&format!(
                "  MITRE ATT&CK: {}\n",
                alert.mitre_attack.join(", ")
            ));
        }
        output.push_str("  Evidence:\n");
        for evidence in &alert.evidence {
            let timestamp = evidence
                .timestamp
                .map(|time| time.to_string())
                .unwrap_or_else(|| "time-unknown".to_owned());
            output.push_str(&format!(
                "    L{} [{}] {} | {}\n",
                evidence.line_number,
                evidence.kind.as_str(),
                timestamp,
                evidence.message
            ));
        }
        if index + 1 < report.alerts.len() {
            output.push('\n');
        }
    }
    output.push_str(&"=".repeat(76));
    output.push('\n');
    output.push_str("Note: findings are investigative leads, not proof of compromise. Validate against surrounding telemetry.\n");
    output
}

fn render_event_overview(output: &mut String, summary: &EventSummary) {
    output.push_str("Event overview\n");
    match (summary.first_timestamp, summary.last_timestamp) {
        (Some(start), Some(end)) => {
            let duration = summary
                .duration_seconds
                .map(|seconds| format!(" ({seconds}s)"))
                .unwrap_or_default();
            output.push_str(&format!("  Time range: {start} -> {end}{duration}\n"));
        }
        _ => output.push_str("  Time range: unavailable (no parseable timestamps)\n"),
    }
    output.push_str(&format!(
        "  Timestamps: {}/{} events\n",
        summary.events_with_timestamp, summary.events_total
    ));
    if !summary.by_kind.is_empty() {
        output.push_str(&format!(
            "  Event kinds: {}\n",
            format_count_pairs(
                summary
                    .by_kind
                    .iter()
                    .map(|(kind, count)| (kind.as_str(), *count))
            )
        ));
    }
    if !summary.top_source_ips.is_empty() {
        output.push_str(&format!(
            "  Top source IPs: {}\n",
            format_count_entries(&summary.top_source_ips)
        ));
    }
    if !summary.top_users.is_empty() {
        output.push_str(&format!(
            "  Top users: {}\n",
            format_count_entries(&summary.top_users)
        ));
    }
}

fn format_count_entries(entries: &[CountEntry]) -> String {
    format_count_pairs(
        entries
            .iter()
            .map(|entry| (entry.value.as_str(), entry.count)),
    )
}

fn format_count_pairs<'a>(pairs: impl Iterator<Item = (&'a str, usize)>) -> String {
    pairs
        .map(|(value, count)| format!("{value}={count}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, NaiveDate};

    use super::EventSummary;
    use crate::model::{EventKind, LogEvent};

    fn event(kind: EventKind, user: &str, ip: &str, offset: i64) -> LogEvent {
        let start = NaiveDate::from_ymd_opt(2026, 10, 9)
            .unwrap()
            .and_hms_opt(19, 0, 0)
            .unwrap();
        LogEvent {
            line_number: 1,
            timestamp: Some(start + Duration::seconds(offset)),
            host: Some("lab".to_owned()),
            program: Some("sshd".to_owned()),
            pid: Some(1),
            kind,
            user: Some(user.to_owned()),
            source_ip: Some(ip.parse().unwrap()),
            command: None,
            message: "test".to_owned(),
        }
    }

    #[test]
    fn builds_event_summary_counts_and_time_range() {
        let events = vec![
            event(EventKind::SshAuthFailure, "alice", "203.0.113.7", 0),
            event(EventKind::SshAuthFailure, "alice", "203.0.113.7", 30),
            event(EventKind::SshAuthSuccess, "bob", "203.0.113.8", 90),
        ];
        let summary = EventSummary::from_events(&events, 1);
        assert_eq!(summary.events_total, 3);
        assert_eq!(summary.events_with_timestamp, 3);
        assert_eq!(summary.events_without_timestamp, 0);
        assert_eq!(summary.duration_seconds, Some(90));
        assert_eq!(summary.by_kind["ssh_auth_failure"], 2);
        assert_eq!(summary.top_source_ips.len(), 1);
        assert_eq!(summary.top_source_ips[0].value, "203.0.113.7");
        assert_eq!(summary.top_source_ips[0].count, 2);
        assert_eq!(summary.top_users.len(), 1);
        assert_eq!(summary.top_users[0].value, "alice");
    }
}
