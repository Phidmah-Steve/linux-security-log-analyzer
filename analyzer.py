
import re
import sys
from collections import Counter
from pathlib import Path
from ipaddress import ip_address

FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for "
    r"(?:invalid user )?\S+ from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

THRESHOLD = 3


def analyze_log(file_path):
    failed_by_ip = Counter()
    successful_by_ip = Counter()
    failed_total = 0
    success_total = 0
    unmatched = 0

    with open(file_path, "r", encoding="utf-8") as log_file:
        for line in log_file:
            failed_match = FAILED_PATTERN.search(line)
            success_match = SUCCESS_PATTERN.search(line)

            if failed_match:
                ip = failed_match.group("ip")

                try:
                    ip_address(ip)
                except ValueError:
                    unmatched += 1
                    continue

                failed_by_ip[ip] += 1
                failed_total += 1

            elif success_match:
                ip = success_match.group("ip")

                try:
                    ip_address(ip)
                except ValueError:
                    unmatched += 1
                    continue

                successful_by_ip[ip] += 1
                success_total += 1

            else:
                unmatched += 1

    return (
        failed_by_ip,
        successful_by_ip,
        failed_total,
        success_total,
        unmatched,
    )


def main():
    file_path = (
        Path(sys.argv[1])
        if len(sys.argv) > 1
        else Path("sample_auth.log")
    )

    if not file_path.is_file():
        print(f"Error: Log file not found: {file_path}")
        sys.exit(1)

    try:
        (
            failed_by_ip,
            successful_by_ip,
            failed_total,
            success_total,
            unmatched,
        ) = analyze_log(file_path)
    except (OSError, UnicodeError) as error:
        print(f"Error reading log file: {error}")
        sys.exit(1)

    print("\n=== LINUX SECURITY LOG ANALYZER ===")
    print(f"Log file: {file_path}")
    print(f"Failed login attempts: {failed_total}")
    print(f"Successful logins: {success_total}")
    print(f"Unmatched log lines: {unmatched}")

    print("\nFailed attempts by IP:")
    if failed_by_ip:
        for ip, count in failed_by_ip.most_common():
            print(f"  {ip}: {count}")
    else:
        print("  None found")

    print(f"\nAlerts (threshold: {THRESHOLD}+ failed attempts):")
    alerts = {
        ip: count
        for ip, count in failed_by_ip.items()
        if count >= THRESHOLD
    }

    if alerts:
        for ip, count in sorted(
            alerts.items(), key=lambda item: item[1], reverse=True
        ):
            print(f"  ALERT: {ip} had {count} failed attempts")
    else:
        print("  No threshold alerts")

    print("\nSuccessful logins by IP:")
    if successful_by_ip:
        for ip, count in successful_by_ip.most_common():
            print(f"  {ip}: {count}")
    else:
        print("  None found")

    print("\nInvestigation note:")
    print(
        "Threshold alerts require further investigation. "
        "They do not prove malicious activity."
    )


if __name__ == "__main__":
    main()
