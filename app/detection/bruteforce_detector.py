def detect_bruteforce(logs, threshold=3, window_seconds=120):
    alerts = []

    failed_logs = logs[
        (logs["action"] == "login") &
        (logs["status"] == "failed")
    ].copy()

    failed_logs = failed_logs.sort_values("timestamp")

    # Analyze each user + IP combination separately
    for (user, ip), group in failed_logs.groupby(["user", "ip"]):

        timestamps = group["timestamp"].tolist()

        for i in range(len(timestamps)):
            count = 1

            for j in range(i + 1, len(timestamps)):
                time_difference = (
                    timestamps[j] - timestamps[i]
                ).total_seconds()

                if time_difference <= window_seconds:
                    count += 1
                else:
                    break

            if count >= threshold:
                first_seen = timestamps[i]
                last_seen = timestamps[i + count - 1]

                alerts.append({
    "type": "brute_force",
    "user": user,
    "ip": ip,
    "failed_attempts": count,
    "first_seen": first_seen.isoformat(),
    "last_seen": last_seen.isoformat(),
    "window_seconds": window_seconds,
    "severity": "high",
    "evidence": [
        f"{count} failed login attempts",
        f"source IP: {ip}",
        f"user: {user}",
        f"activity occurred within {window_seconds} seconds"
    ]
})

                break

    return alerts