
import csv
from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path

INPUT_FILE = Path("data/auth_logs.csv")
OUTPUT_FILE = Path("reports/security_alerts.csv")

# Detection configuration
FAILURE_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=5)


def detect_brute_force(events):
    """Detect repeated failed logins from the same IP address."""

    alerts = []
    failed_attempts = defaultdict(deque)

    # Process events chronologically.
    events = sorted(
        events,
        key=lambda event: datetime.fromisoformat(event["timestamp"])
    )

    for event in events:
        ip = event["ip_address"]
        timestamp = datetime.fromisoformat(event["timestamp"])

        if event["status"] != "failure":
            continue

        # Store the time of this failed login.
        attempts = failed_attempts[ip]
        attempts.append(timestamp)

        # Remove attempts older than five minutes.
        while attempts and timestamp - attempts[0] > TIME_WINDOW:
            attempts.popleft()

        # Generate one alert when the threshold is first reached.
        if len(attempts) == FAILURE_THRESHOLD:
            alerts.append({
                "timestamp": timestamp.isoformat(),
                "ip_address": ip,
                "alert_type": "Potential Brute Force",
                "severity": "HIGH",
                "failed_attempts": len(attempts)
            })

    return alerts


def main():
    # Extract authentication logs.
    with INPUT_FILE.open("r", newline="") as file:
        events = list(csv.DictReader(file))

    # Analyze events for suspicious behavior.
    alerts = detect_brute_force(events)

    # Export security alerts.
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "ip_address",
                "alert_type",
                "severity",
                "failed_attempts"
            ]
        )
        writer.writeheader()
        writer.writerows(alerts)

    print(f"Analyzed {len(events)} authentication events")
    print(f"Generated {len(alerts)} security alerts")
    print(f"Alerts saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
