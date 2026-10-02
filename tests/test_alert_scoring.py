from app.detection.alert_scoring import (
    calculate_confidence,
    assign_severity
)


def test_three_failed_logins_are_medium():
    alert = {
        "type": "brute_force",
        "failed_attempts": 3
    }

    assert assign_severity(alert) == "medium"


def test_five_failed_logins_are_high():
    alert = {
        "type": "brute_force",
        "failed_attempts": 5
    }

    assert assign_severity(alert) == "high"


def test_ten_failed_logins_are_critical():
    alert = {
        "type": "brute_force",
        "failed_attempts": 10
    }

    assert assign_severity(alert) == "critical"


def test_bruteforce_confidence():
    alert = {
        "type": "brute_force",
        "failed_attempts": 10
    }

    assert calculate_confidence(alert) == 97