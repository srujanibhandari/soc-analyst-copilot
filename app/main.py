from datetime import datetime
from ingestion.log_reader import load_logs
from parser.event_normalizer import normalize_logs
from detection.bruteforce_detector import detect_bruteforce
from models.alert_manager import AlertManager
from models.alert import Alert
from models.alert_id import generate_alert_id


def main():
    logs = load_logs("data/security_logs.csv")
    normalized_logs = normalize_logs(logs)
    raw_alerts = detect_bruteforce(normalized_logs)
    
    alert_manager = AlertManager()
    
    # Generate and store initial alerts
    for index, raw_alert in enumerate(raw_alerts, start=1):
        alert = Alert(
            id=generate_alert_id(index),
            type=raw_alert["type"],
            severity=raw_alert["severity"],
            status="new",
            timestamp=datetime.now(),
            description="Multiple failed login attempts detected",
            source_ip=raw_alert["ip"],
            evidence=[
                f'{raw_alert["failed_attempts"]} failed login attempts',
                "same source IP",
                "within 2 minutes"
            ]
        )
        alert_manager.add_alert(alert)

    print("SOC Analyst Copilot started!\n")
    print("Initial alerts:")
    for alert in alert_manager.get_all_alerts():
        print(alert)

    # --- SIMULATE ANALYST INVESTIGATION ---
    # Update the status of ALT-001 to 'investigating'
    alert_manager.update_status("ALT-001", "investigating")

    # Fetch and verify the updated alert
    updated_alert = alert_manager.get_alert_by_id("ALT-001")
    print("\nUpdated Alert Status:")
    print(f"ID: {updated_alert.id} | Status: {updated_alert.status}")


if __name__ == "__main__":
    main()