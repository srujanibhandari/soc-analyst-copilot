def detect_impossible_travel(logs, max_minutes=30):
    alerts = []

    login_logs = logs[
        (logs["action"] == "login") &
        (logs["status"] == "success")
    ].copy()

    login_logs = login_logs.sort_values("timestamp")

    for user, group in login_logs.groupby("user"):
        previous_location = None
        previous_time = None

        for _, event in group.iterrows():
            current_location = event["location"]
            current_time = event["timestamp"]

            if previous_location is not None:
                time_difference = (
                    current_time - previous_time
                ).total_seconds() / 60

                if (
                    current_location != previous_location
                    and time_difference <= max_minutes
                ):
                    alerts.append({
                        "type": "impossible_travel",
                        "user": user,
                        "from_location": previous_location,
                        "to_location": current_location,
                        "time_difference_minutes": time_difference,
                        "severity": "high"
                    })

            previous_location = current_location
            previous_time = current_time

    return alerts