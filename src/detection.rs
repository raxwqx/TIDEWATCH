use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use chrono::{Duration, NaiveDateTime};
use serde::Deserialize;

use crate::model::{Alert, EventKind, Evidence, LogEvent, Severity};

const DEFAULT_RULES: &str = include_str!("../rules/default.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RuleCondition {
    #[default]
    Threshold,
    FailureThenSuccess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupBy {
    SourceIp,
    User,
    SourceIpUser,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: Severity,
    #[serde(default)]
    pub condition: RuleCondition,
    pub event_kinds: Vec<EventKind>,
    #[serde(default)]
    pub success_event_kinds: Vec<EventKind>,
    pub threshold: usize,
    pub window_seconds: i64,
    pub group_by: GroupBy,
    #[serde(default)]
    pub mitre: Vec<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    version: u32,
    rules: Vec<DetectionRule>,
}

fn default_true() -> bool {
    true
}

pub fn load_rules(path: Option<&Path>) -> Result<Vec<DetectionRule>> {
    let content = if let Some(path) = path {
        fs::read_to_string(path)
            .with_context(|| format!("could not read rules file {}", path.display()))?
    } else {
        DEFAULT_RULES.to_owned()
    };
    let parsed: RuleFile = toml::from_str(&content).context("rules file is not valid TOML")?;
    ensure!(
        parsed.version == 1,
        "unsupported rules schema version: {}",
        parsed.version
    );

    let mut seen_ids = HashSet::new();
    for rule in &parsed.rules {
        ensure!(!rule.id.trim().is_empty(), "rule IDs cannot be empty");
        ensure!(
            seen_ids.insert(rule.id.clone()),
            "duplicate rule ID: {}",
            rule.id
        );
        ensure!(
            !rule.name.trim().is_empty(),
            "rule {} has an empty name",
            rule.id
        );
        ensure!(
            !rule.event_kinds.is_empty(),
            "rule {} needs at least one event kind",
            rule.id
        );
        ensure!(
            rule.threshold > 0,
            "rule {} threshold must be at least 1",
            rule.id
        );
        ensure!(
            rule.window_seconds >= 0,
            "rule {} window_seconds cannot be negative",
            rule.id
        );
        if rule.condition == RuleCondition::FailureThenSuccess {
            ensure!(
                !rule.success_event_kinds.is_empty(),
                "rule {} needs success_event_kinds for failure_then_success",
                rule.id
            );
            ensure!(
                rule.window_seconds > 0,
                "rule {} needs a positive window for correlation",
                rule.id
            );
        }
    }
    Ok(parsed.rules)
}

pub fn detect(events: &[LogEvent], rules: &[DetectionRule]) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for rule in rules.iter().filter(|rule| rule.enabled) {
        match rule.condition {
            RuleCondition::Threshold => detect_threshold(events, rule, &mut alerts),
            RuleCondition::FailureThenSuccess => {
                detect_failure_then_success(events, rule, &mut alerts)
            }
        }
    }
    alerts.sort_by(|left, right| {
        right
            .severity
            .cmp(&left.severity)
            .then_with(|| left.window_end.cmp(&right.window_end))
            .then_with(|| left.rule_id.cmp(&right.rule_id))
    });
    alerts
}

fn detect_threshold(events: &[LogEvent], rule: &DetectionRule, alerts: &mut Vec<Alert>) {
    let groups = group_matching_events(events, rule, false);
    for group in groups.into_values() {
        let mut group = group;
        group.sort_by_key(|event| event.timestamp);

        // Single-event rules also work when a source log has no parseable timestamp.
        if rule.threshold == 1 {
            if let Some(event) = group.first() {
                alerts.push(build_alert(
                    rule,
                    vec![*event],
                    event.timestamp,
                    event.timestamp,
                ));
            }
            continue;
        }

        let timed: Vec<&LogEvent> = group
            .into_iter()
            .filter(|event| event.timestamp.is_some())
            .collect();
        let mut left = 0usize;
        for right in 0..timed.len() {
            let end_time = timed[right]
                .timestamp
                .expect("filtered timestamps are present");
            while left < right {
                let start_time = timed[left]
                    .timestamp
                    .expect("filtered timestamps are present");
                if end_time - start_time > Duration::seconds(rule.window_seconds) {
                    left += 1;
                } else {
                    break;
                }
            }
            if right - left + 1 >= rule.threshold {
                let first = right + 1 - rule.threshold;
                let evidence = timed[first..=right].to_vec();
                let start = evidence.first().and_then(|event| event.timestamp);
                alerts.push(build_alert(rule, evidence, start, Some(end_time)));
                break; // one alert per rule/group keeps reports useful instead of noisy
            }
        }
    }
}

fn detect_failure_then_success(events: &[LogEvent], rule: &DetectionRule, alerts: &mut Vec<Alert>) {
    let groups = group_matching_events(events, rule, true);
    for group in groups.into_values() {
        let mut group = group;
        group.sort_by_key(|event| event.timestamp);

        for (success_index, success) in group.iter().enumerate() {
            if !rule.success_event_kinds.contains(&success.kind) {
                continue;
            }
            let Some(success_time) = success.timestamp else {
                continue;
            };
            let failures: Vec<&LogEvent> = group[..success_index]
                .iter()
                .copied()
                .filter(|event| rule.event_kinds.contains(&event.kind))
                .filter(|event| {
                    event.timestamp.is_some_and(|time| {
                        time <= success_time
                            && success_time - time <= Duration::seconds(rule.window_seconds)
                    })
                })
                .collect();
            if failures.len() >= rule.threshold {
                let selected_failures = failures[failures.len() - rule.threshold..].to_vec();
                let start = selected_failures.first().and_then(|event| event.timestamp);
                let mut evidence = selected_failures;
                evidence.push(*success);
                alerts.push(build_alert(rule, evidence, start, Some(success_time)));
                break; // first correlated success per key is the most useful pivot
            }
        }
    }
}

fn group_matching_events<'a>(
    events: &'a [LogEvent],
    rule: &DetectionRule,
    include_success_events: bool,
) -> BTreeMap<String, Vec<&'a LogEvent>> {
    let mut groups: BTreeMap<String, Vec<&LogEvent>> = BTreeMap::new();
    for event in events {
        let matches_failure = rule.event_kinds.contains(&event.kind);
        let matches_success =
            include_success_events && rule.success_event_kinds.contains(&event.kind);
        if !matches_failure && !matches_success {
            continue;
        }
        if let Some(key) = grouping_key(event, rule.group_by) {
            groups.entry(key).or_default().push(event);
        }
    }
    groups
}

fn grouping_key(event: &LogEvent, group_by: GroupBy) -> Option<String> {
    match group_by {
        GroupBy::SourceIp => event.source_ip.map(|ip| ip.to_string()),
        GroupBy::User => event.user.clone().filter(|user| !user.is_empty()),
        GroupBy::SourceIpUser => Some(format!(
            "{}|{}",
            event.source_ip?,
            event.user.as_deref().filter(|user| !user.is_empty())?
        )),
    }
}

fn build_alert(
    rule: &DetectionRule,
    events: Vec<&LogEvent>,
    window_start: Option<NaiveDateTime>,
    window_end: Option<NaiveDateTime>,
) -> Alert {
    let last_event = events.last().copied();
    let source_ip = events.iter().rev().find_map(|event| event.source_ip);
    let user = events.iter().rev().find_map(|event| event.user.clone());
    let evidence: Vec<Evidence> = events.iter().map(|event| Evidence::from(*event)).collect();
    Alert {
        rule_id: rule.id.clone(),
        title: rule.name.clone(),
        description: rule.description.clone(),
        severity: rule.severity,
        observed_count: events.len(),
        source_ip,
        user,
        window_start,
        window_end: window_end.or_else(|| last_event.and_then(|event| event.timestamp)),
        mitre_attack: rule.mitre.clone(),
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, NaiveDate};

    use super::{DetectionRule, GroupBy, RuleCondition, detect, load_rules};
    use crate::model::{EventKind, LogEvent, Severity};

    fn event(index: usize, kind: EventKind, minute_offset: i64) -> LogEvent {
        let start = NaiveDate::from_ymd_opt(2025, 1, 1)
            .unwrap()
            .and_hms_opt(12, 0, 0)
            .unwrap();
        LogEvent {
            line_number: index,
            timestamp: Some(start + Duration::seconds(minute_offset)),
            host: Some("lab".to_owned()),
            program: Some("sshd".to_owned()),
            pid: Some(10),
            kind,
            user: Some("analyst".to_owned()),
            source_ip: Some("203.0.113.45".parse().unwrap()),
            command: None,
            message: format!("test event {index}"),
        }
    }

    fn sequence_rule() -> DetectionRule {
        DetectionRule {
            id: "TEST-001".to_owned(),
            name: "Failure then success".to_owned(),
            description: "A test rule".to_owned(),
            severity: Severity::High,
            condition: RuleCondition::FailureThenSuccess,
            event_kinds: vec![EventKind::SshAuthFailure],
            success_event_kinds: vec![EventKind::SshAuthSuccess],
            threshold: 3,
            window_seconds: 600,
            group_by: GroupBy::SourceIp,
            mitre: vec!["T1110".to_owned()],
            enabled: true,
        }
    }

    #[test]
    fn detects_failures_followed_by_success_from_same_ip() {
        let events = vec![
            event(1, EventKind::SshAuthFailure, 0),
            event(2, EventKind::SshAuthFailure, 10),
            event(3, EventKind::SshAuthFailure, 20),
            event(4, EventKind::SshAuthSuccess, 30),
        ];
        let alerts = detect(&events, &[sequence_rule()]);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].observed_count, 4);
        assert_eq!(
            alerts[0].evidence.last().unwrap().kind,
            EventKind::SshAuthSuccess
        );
    }

    #[test]
    fn does_not_correlate_events_outside_the_time_window() {
        let events = vec![
            event(1, EventKind::SshAuthFailure, 0),
            event(2, EventKind::SshAuthFailure, 1),
            event(3, EventKind::SshAuthFailure, 2),
            event(4, EventKind::SshAuthSuccess, 700),
        ];
        assert!(detect(&events, &[sequence_rule()]).is_empty());
    }

    #[test]
    fn bundled_rules_load_and_have_unique_ids() {
        let rules = load_rules(None).unwrap();
        assert!(rules.len() >= 4);
    }
}
