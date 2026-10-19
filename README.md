
# Linux Security Log Analyzer

A beginner-friendly Python project that analyzes simulated Linux SSH
authentication logs to identify repeated failed login attempts.

## Objectives

- Count failed and successful SSH login events.
- Group failed attempts by source IP address.
- Flag IP addresses reaching a configurable alert threshold.
- Report log lines that do not match the expected event patterns.

## Technologies

- Python 3
- Regular expressions
- Collections Counter
- pathlib and ipaddress

## Requirements

Python 3.10 or later. No third-party packages required.

## How to Run

1. Clone or download this repository.
2. Open the project folder in a terminal.
3. Run:

   `python analyzer.py`

4. To analyze a different log file:

   `python analyzer.py another_auth.log`

## Detection Logic

The default threshold is three failed login attempts per source IP
within the supplied log file.

This project does not currently group events into time windows.
The alert is a triage indicator, not proof of malicious activity.

## Testing

Tested with simulated authentication events containing failed
logins, successful logins, and unrelated lines.

## Limitations

- Supports specific OpenSSH authentication log patterns.
- Does not correlate events across multiple log sources.
- Does not automatically block IP addresses.
- Does not establish whether a source is malicious.
- Does not currently detect distributed attacks or time-based patterns.

## Security and Ethics

The included log data is simulated. Use this tool only with logs
you are authorized to access.

## Future Improvements

- Add time-window-based detection.
- Export alerts to a CSV report.
- Add automated unit tests.
- Support additional log formats.

## Author

Phidmah Steve
