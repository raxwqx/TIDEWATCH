use std::collections::BTreeMap;

use chrono::Utc;
use serde::Serialize;

use crate::model::{Alert, LogEvent, Severity};
use crate::parser::ParseStats;

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
    pub alerts: Vec<Alert>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<LogEvent>>,
}

impl Report {
    pub fn new(
        input: String,
        detected_input_format: String,
        stats: &ParseStats,
        alerts: Vec<Alert>,
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
            schema_version: "1".to_owned(),
            tool: "TIDEWATCH".to_owned(),
            version: version.to_owned(),
            generated_at: Utc::now().to_rfc3339(),
            input,
            detected_input_format,
            summary,
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
