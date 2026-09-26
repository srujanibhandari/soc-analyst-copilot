def detect_privilege_escalation(logs):
    alerts = []

    suspicious_events = logs[
        (logs["action"] == "privilege_change") &
        (logs["status"] == "success")
    ]

    for _, event in suspicious_events.iterrows():
        alerts.append({
            "type": "privilege_escalation",
            "user": event["user"],
            "ip": event["ip"],
            "severity": "high"
        })

    return alerts