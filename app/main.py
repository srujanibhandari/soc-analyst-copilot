from datetime import datetime, timezone

from ingestion.log_reader import load_logs
from parser.event_normalizer import normalize_logs

from detection.bruteforce_detector import detect_bruteforce
from detection.impossible_travel_detector import detect_impossible_travel
from detection.privilege_detector import detect_privilege_escalation
from detection.port_scan_detector import detect_port_scan

from database.event_repository import save_events
from database.alert_repository import save_alerts


def main():
    file_path = "data/security_logs.csv"

    # 1. Load logs
    logs = load_logs(file_path)

    # 2. Normalize logs
    normalized_logs = normalize_logs(logs)

    # 3. Save events to PostgreSQL
    save_events(normalized_logs)

    # 4. Run detection rules
    brute_force_alerts = detect_bruteforce(normalized_logs)
    travel_alerts = detect_impossible_travel(normalized_logs)
    privilege_alerts = detect_privilege_escalation(normalized_logs)
    port_scan_alerts = detect_port_scan(normalized_logs)

    raw_alerts = (
        brute_force_alerts
        + travel_alerts
        + privilege_alerts
        + port_scan_alerts
    )

    # 5. Add IDs and timestamps
    alerts = []

    for index, alert in enumerate(raw_alerts, start=1):
        alert_copy = alert.copy()

        alert_copy["id"] = f"ALT-{index:03d}"
        alert_copy["timestamp"] = datetime.now(timezone.utc)

        alerts.append(alert_copy)

    # 6. Save alerts
    save_alerts(alerts)

    print("SOC Analyst Copilot started!")
    print()
    print(f"Events stored: {len(normalized_logs)}")
    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(alert)


if __name__ == "__main__":
    main()