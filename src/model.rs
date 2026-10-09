use std::net::IpAddr;

use chrono::NaiveDateTime;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    SshAuthFailure,
    SshAuthSuccess,
    SshInvalidUser,
    SshRootLogin,
    SudoCommand,
    UserAdded,
    PasswordChanged,
    SessionOpened,
    Other,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SshAuthFailure => "ssh_auth_failure",
            Self::SshAuthSuccess => "ssh_auth_success",
            Self::SshInvalidUser => "ssh_invalid_user",
            Self::SshRootLogin => "ssh_root_login",
            Self::SudoCommand => "sudo_command",
            Self::UserAdded => "user_added",
            Self::PasswordChanged => "password_changed",
            Self::SessionOpened => "session_opened",
            Self::Other => "other",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEvent {
    pub line_number: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<NaiveDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub kind: EventKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub line_number: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<NaiveDateTime>,
    pub kind: EventKind,
    pub message: String,
}

impl From<&LogEvent> for Evidence {
    fn from(event: &LogEvent) -> Self {
        Self {
            line_number: event.line_number,
            timestamp: event.timestamp,
            kind: event.kind,
            message: event.message.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub observed_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_ip: Option<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_start: Option<NaiveDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window_end: Option<NaiveDateTime>,
    pub mitre_attack: Vec<String>,
    pub evidence: Vec<Evidence>,
}
