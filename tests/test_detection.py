
from datetime import datetime, timedelta, timezone

from detect_threats import detect_brute_force


def make_event(ip, status, minute):
    """Create a synthetic authentication event for testing."""
    timestamp = datetime(
        2026, 10, 1, tzinfo=timezone.utc
    ) + timedelta(minutes=minute)

    return {
        "timestamp": timestamp.isoformat(),
        "ip_address": ip,
        "username": "test_user",
        "status": status
    }


def test_detects_brute_force():
    """Five failures within five minutes should trigger an alert."""
    events = [
        make_event("203.0.113.50", "failure", i)
        for i in range(5)
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["severity"] == "HIGH"
    assert alerts[0]["failed_attempts"] == 5


def test_normal_activity():
    """Successful logins should not trigger alerts."""
    events = [
        make_event("192.0.2.10", "success", i)
        for i in range(10)
    ]

    assert detect_brute_force(events) == []


def test_failures_outside_window():
    """Failures spread over time should not trigger alerts."""
    events = [
        make_event("192.0.2.10", "failure", i * 10)
        for i in range(5)
    ]

    assert detect_brute_force(events) == []


def test_separate_ip_addresses():
    """Failures from different IPs should not be combined."""
    events = [
        make_event(f"192.0.2.{i + 1}", "failure", 0)
        for i in range(5)
    ]

    assert detect_brute_force(events) == []


def test_unsorted_events():
    """The detector should handle logs that are out of order."""
    events = [
        make_event("203.0.113.50", "failure", i)
        for i in range(5)
    ]

    alerts = detect_brute_force(list(reversed(events)))

    assert len(alerts) == 1
