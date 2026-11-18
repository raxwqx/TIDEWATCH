# Security policy

## Scope

TIDEWATCH is an offline log-analysis utility. Security reports should focus on defects in its parser, correlation logic, data handling, or generated reports.

## Supported versions

Security fixes are applied to the latest release on the `main` branch. Please reproduce the issue against the newest version before reporting it.

## Reporting a vulnerability

Please do not publish private logs, personal data, credentials, or a weaponized proof of concept in a public issue. Use the repository's private vulnerability reporting flow when it is available, or contact the repository owner through a private channel.

Include, where possible:

- the affected TIDEWATCH version and platform,
- a minimal sanitized log sample that reproduces the issue,
- the exact command line and rule file used,
- expected behavior and observed behavior,
- any relevant exit code, panic message, or malformed report output.

Never attach real credentials, private keys, production logs, or personal data. Redact hostnames, usernames, IP addresses, and command lines before sharing a sample.

## Data handling

TIDEWATCH does not intentionally send data over the network. It reads local files or standard input and writes reports to standard output or a local path. Input logs and generated reports may contain sensitive operational data; store, share, and redact them accordingly.

JSON reports produced with `--include-events` preserve normalized event messages and pivots. Treat those reports with at least the same care as the source logs.

## Dependency and CI hygiene

The repository uses Dependabot for Cargo and GitHub Actions updates, runs formatting, linting, tests, and release builds in CI, and keeps dependency vulnerabilities visible through GitHub security alerts. Reports about a vulnerable dependency are welcome even when TIDEWATCH itself is not directly exploitable.
