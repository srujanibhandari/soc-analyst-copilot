import pandas as pd

from app.detection.bruteforce_detector import detect_bruteforce
def test_bruteforce_detected():

    logs = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-09-26 10:00:00"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": pd.Timestamp("2026-09-26 10:00:30"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": pd.Timestamp("2026-09-26 10:01:10"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
    ])

    alerts = detect_bruteforce(logs)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "brute_force"
    assert alerts[0]["user"] == "alice"
    assert alerts[0]["ip"] == "10.0.0.5"
    assert alerts[0]["failed_attempts"] == 3
def test_no_bruteforce_when_attempts_are_too_far_apart():

    logs = pd.DataFrame([
        {
            "timestamp": pd.Timestamp("2026-09-26 10:00:00"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": pd.Timestamp("2026-09-26 10:01:00"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
        {
            "timestamp": pd.Timestamp("2026-09-26 10:02:30"),
            "user": "alice",
            "ip": "10.0.0.5",
            "action": "login",
            "status": "failed",
        },
    ])

    alerts = detect_bruteforce(logs)

    assert len(alerts) == 0