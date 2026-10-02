from app.detection.alert_deduplicator import deduplicate_alerts

def test_duplicate_alerts_are_removed():

    alerts = [
        {
            "type": "brute_force",
            "user": "alice",
            "ip": "10.0.0.5"
        },
        {
            "type": "brute_force",
            "user": "alice",
            "ip": "10.0.0.5"
        },
        {
            "type": "impossible_travel",
            "user": "charlie",
            "ip": "10.0.0.20"
        }
    ]

    result = deduplicate_alerts(alerts)

    assert len(result) == 2
def test_different_alerts_are_kept():

    alerts = [
        {
            "type": "brute_force",
            "user": "alice",
            "ip": "10.0.0.5"
        },
        {
            "type": "brute_force",
            "user": "bob",
            "ip": "10.0.0.5"
        }
    ]

    result = deduplicate_alerts(alerts)

    assert len(result) == 2