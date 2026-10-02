def deduplicate_alerts(alerts):
    unique_alerts = []
    seen = set()

    for alert in alerts:
        key = (
            alert.get("type"),
            alert.get("user"),
            alert.get("ip", alert.get("source_ip"))
        )

        if key not in seen:
            seen.add(key)
            unique_alerts.append(alert)

    return unique_alerts