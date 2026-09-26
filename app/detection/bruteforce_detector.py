import pandas as pd


def detect_bruteforce(logs):
    alerts = []

    failed_logs = logs[
        (logs["action"] == "login") &
        (logs["status"] == "failed")
    ].copy()

    failed_logs = failed_logs.sort_values("timestamp")

    for ip, group in failed_logs.groupby("ip"):
        timestamps = group["timestamp"].tolist()

        for i in range(len(timestamps)):
            count = 1

            for j in range(i + 1, len(timestamps)):
                time_difference = (
                    timestamps[j] - timestamps[i]
                ).total_seconds()

                if time_difference <= 120:
                    count += 1
                else:
                    break

            if count >= 3:
                alerts.append({
                    "type": "brute_force",
                    "ip": ip,
                    "failed_attempts": count,
                    "severity": "high"
                })
                break

    return alerts