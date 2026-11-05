
import csv
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Use a fixed seed so the generated dataset is reproducible.
random.seed(42)

OUTPUT_FILE = Path("data/auth_logs.csv")
TOTAL_EVENTS = 1500

def generate_logs():
    events = []
    start_time = datetime(2026, 10, 1, tzinfo=timezone.utc)

    # Generate normal authentication activity.
    for i in range(TOTAL_EVENTS - 20):
        event = {
            "event_id": f"EVT{i + 1:04d}",
            "timestamp": (
                start_time + timedelta(minutes=i * 3)
            ).isoformat(),
            "username": f"user{random.randint(1, 50)}",
            "ip_address": f"192.0.2.{random.randint(1, 254)}",
            "status": random.choices(
                ["success", "failure"],
                weights=[90, 10]
            )[0]
        }
        events.append(event)

    # Simulate 20 failed login attempts from the same IP
    # within a short time window.
    attack_time = start_time + timedelta(days=2)

    for i in range(20):
        events.append({
            "event_id": f"EVT{len(events) + 1:04d}",
            "timestamp": (
                attack_time + timedelta(seconds=i * 10)
            ).isoformat(),
            "username": "admin",
            "ip_address": "203.0.113.50",
            "status": "failure"
        })

    # Sort logs chronologically.
    events.sort(key=lambda event: event["timestamp"])

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with OUTPUT_FILE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "event_id",
                "timestamp",
                "username",
                "ip_address",
                "status"
            ]
        )
        writer.writeheader()
        writer.writerows(events)

    print(f"Generated {len(events)} authentication events")
    print(f"Saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_logs()
