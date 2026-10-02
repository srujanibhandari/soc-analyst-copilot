def calculate_confidence(alert):
    alert_type = alert["type"]

    if alert_type == "brute_force":
        attempts = alert.get("failed_attempts", 0)

        if attempts >= 10:
            return 97
        elif attempts >= 5:
            return 90
        elif attempts >= 3:
            return 75

    elif alert_type == "impossible_travel":
        minutes = alert.get(
            "time_difference_minutes",
            999
        )

        if minutes <= 5:
            return 95
        elif minutes <= 15:
            return 85
        elif minutes <= 30:
            return 70

    elif alert_type == "privilege_escalation":
        return 90

    elif alert_type == "port_scan":
        ports = alert.get("unique_ports", 0)

        if ports >= 20:
            return 95
        elif ports >= 10:
            return 90
        elif ports >= 5:
            return 75

    return 50


def assign_severity(alert):
    alert_type = alert["type"]

    # -----------------------------------------
    # Brute-force
    # -----------------------------------------

    if alert_type == "brute_force":
        attempts = alert.get("failed_attempts", 0)

        if attempts >= 10:
            return "critical"

        elif attempts >= 5:
            return "high"

        elif attempts >= 3:
            return "medium"

    # -----------------------------------------
    # Impossible travel
    # -----------------------------------------

    if alert_type == "impossible_travel":
        minutes = alert.get(
            "time_difference_minutes",
            999
        )

        if minutes <= 5:
            return "high"

        elif minutes <= 30:
            return "medium"

    # -----------------------------------------
    # Privilege escalation
    # -----------------------------------------

    if alert_type == "privilege_escalation":
        return "high"

    # -----------------------------------------
    # Port scanning
    # -----------------------------------------

    if alert_type == "port_scan":
        ports = alert.get("unique_ports", 0)

        if ports >= 20:
            return "high"

        elif ports >= 5:
            return "medium"

    return "low"