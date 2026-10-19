# Linux Security Log Analyzer

A Python-based security tool that analyzes simulated Linux SSH authentication logs, counts failed and successful login attempts, and flags source IP addresses that meet a configurable failed-login threshold.

## Project Objectives

- Identify failed and successful SSH authentication events.
- Count failed login attempts by source IP address.
- Flag repeated failed logins for further investigation.
- Report log lines that do not match the supported event patterns.
- Practise Python scripting and basic security monitoring concepts.

## Technologies Used

- Python 3
- Regular expressions
- `collections.Counter`
- `pathlib`
- `ipaddress`

## How It Works

The analyzer reads an authentication log file and searches for supported SSH authentication messages. It counts failed and successful login events by source IP address and generates a simple terminal report.

The default alert threshold is three failed login attempts per source IP across the supplied file.

**Important:** The current version does not use a time window. An alert is a triage indicator, not proof of malicious activity.

## Requirements

- Python 3.10 or later
- No third-party Python packages required

## Project Files

- `analyzer.py` — main analysis script
- `sample_auth.log` — simulated authentication events
- `README.md` — project documentation
- `.gitignore` — excludes temporary and local files

## Installation and Usage

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/linux-security-log-analyzer.git
cd linux-security-log-analyzer
```

Run the analyzer:

```bash
python analyzer.py
```

Analyze another log file:

```bash
python analyzer.py another_auth.log
```

Replace `YOUR-USERNAME` with the actual GitHub username. Ensure the alternative log file exists in the working directory or provide its correct path.

## Testing

The included sample dataset is designed to test:

- Repeated failed login attempts from one source IP.
- Failed attempts from other source IPs.
- Successful authentication events.
- Unmatched log lines.

Expected sample results include eight failed login attempts, two successful login events, and one threshold alert.

## Limitations

- Supports specific SSH authentication log formats.
- Does not currently detect attacks using time-window analysis.
- Does not correlate events across multiple systems.
- Does not block IP addresses or respond automatically to alerts.
- Does not determine whether an IP address is malicious.
- Uses simulated data rather than live production logs.

## Future Improvements

- Add time-based detection rules.
- Export findings to CSV.
- Add automated unit tests.
- Support more authentication log formats.
- Improve event validation and error reporting.

## Ethical Use

Use this tool only on logs you are authorized to access. The supplied dataset contains simulated events for educational and testing purposes.

## Author

Phidmah Steve

Cybersecurity student developing practical skills in Python, Linux, security monitoring, and incident analysis.
