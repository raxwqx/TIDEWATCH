use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use clap::{Parser, ValueEnum};
use tidewatch::detection::{detect, load_rules};
use tidewatch::model::Severity;
use tidewatch::parser::{InputFormat, parse_input};
use tidewatch::report::{Report, render_text};

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Parser)]
#[command(
    name = "tidewatch",
    version,
    about = "Offline Linux log threat-hunting and incident triage",
    long_about = "TIDEWATCH normalizes supported Linux log lines, applies local detection rules, and produces a human-readable or JSON report. It does not connect to remote hosts."
)]
struct Cli {
    /// Input log file, or '-' to read from standard input.
    #[arg(short, long, default_value = "-")]
    input: String,

    /// Input parser. 'auto' selects JSONL when the first non-empty line is a JSON object.
    #[arg(long, value_enum, default_value = "auto")]
    format: InputFormat,

    /// Optional TOML detection-rule file. The bundled rules are used when omitted.
    #[arg(long)]
    rules: Option<PathBuf>,

    /// Report format.
    #[arg(long = "output-format", value_enum, default_value = "text")]
    output_format: OutputFormat,

    /// Write the report to this file instead of standard output.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Return exit status 2 when any alert meets or exceeds this severity.
    #[arg(long, value_enum)]
    fail_on_severity: Option<Severity>,

    /// Include normalized events in JSON output. Logs may contain sensitive information.
    #[arg(long, default_value_t = false)]
    include_events: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

fn main() -> ExitCode {
    match execute() {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("tidewatch: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn execute() -> Result<u8> {
    let cli = Cli::parse();
    ensure!(
        !cli.include_events || cli.output_format == OutputFormat::Json,
        "--include-events requires --output-format json"
    );

    let input_text = read_input(&cli.input)?;
    let parsed = parse_input(&input_text, cli.format);
    let rules = load_rules(cli.rules.as_deref())?;
    let alerts = detect(&parsed.events, &rules);
    let include_events = if cli.include_events {
        Some(parsed.events.clone())
    } else {
        None
    };
    let report = Report::new(
        if cli.input == "-" {
            "<stdin>".to_owned()
        } else {
            cli.input.clone()
        },
        format!("{:?}", parsed.detected_format).to_ascii_lowercase(),
        &parsed.stats,
        alerts,
        include_events,
        VERSION,
    );

    let rendered = match cli.output_format {
        OutputFormat::Text => render_text(&report),
        OutputFormat::Json => {
            serde_json::to_string_pretty(&report).context("could not serialize report")?
        }
    };

    if let Some(path) = &cli.output {
        fs::write(path, rendered.as_bytes())
            .with_context(|| format!("could not write report to {}", path.display()))?;
        eprintln!("Report written to {}", path.display());
    } else {
        print!("{rendered}");
    }

    let threshold_hit = cli.fail_on_severity.is_some_and(|threshold| {
        report
            .alerts
            .iter()
            .any(|alert| alert.severity >= threshold)
    });
    Ok(if threshold_hit { 2 } else { 0 })
}

fn read_input(input: &str) -> Result<String> {
    if input == "-" {
        let mut content = String::new();
        io::stdin()
            .read_to_string(&mut content)
            .context("could not read standard input")?;
        Ok(content)
    } else {
        fs::read_to_string(input).with_context(|| format!("could not read input file {input}"))
    }
}
