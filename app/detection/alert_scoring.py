def calculate_confidence(alert):
    alert_type = alert["type"]

    if alert_type == "brute_force":
        attempts = alert.get("failed_attempts", 0)

        if attempts >= 10:
            return 95
        elif attempts >= 5:
            return 90
        elif attempts >= 3:
            return 80

    elif alert_type == "impossible_travel":
        minutes = alert.get("time_difference_minutes", 999)

        if minutes <= 5:
            return 95
        elif minutes <= 15:
            return 90
        elif minutes <= 30:
            return 80

    elif alert_type == "privilege_escalation":
        return 85

    elif alert_type == "port_scan":
        ports = alert.get("unique_ports", 0)

        if ports >= 20:
            return 95
        elif ports >= 10:
            return 90
        elif ports >= 5:
            return 80

    return 50


def assign_severity(alert):
    alert_type = alert["type"]

    if alert_type in {
        "brute_force",
        "impossible_travel",
        "privilege_escalation"
    }:
        return "high"

    if alert_type == "port_scan":
        return "medium"

    return "low"