import pandas as pd

from app.parser.event_normalizer import normalize_logs


def test_normalize_logs():
    logs = pd.DataFrame([
        {
            "timestamp": "2026-09-26 10:00:00",
            "user": " Alice ",
            "ip": " 10.0.0.5 ",
            "action": "LOGIN",
            "status": " FAILED ",
            "device": " Windows-PC ",
            "location": " INDIA ",
            "port": "22",
        }
    ])

    result = normalize_logs(logs)

    assert result.iloc[0]["user"] == "alice"
    assert result.iloc[0]["ip"] == "10.0.0.5"
    assert result.iloc[0]["action"] == "login"
    assert result.iloc[0]["status"] == "failed"
    assert result.iloc[0]["location"] == "india"
    assert result.iloc[0]["port"] == 22