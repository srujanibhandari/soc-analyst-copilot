from typing import List

from app.models.alert import Alert


class AlertManager:
    def __init__(self):
        self.alerts: List[Alert] = []

    def add_alert(self, alert: Alert):
        self.alerts.append(alert)

    def get_all_alerts(self):
        return self.alerts

    def get_alert_by_id(self, alert_id: str):
        for alert in self.alerts:
            if alert.id == alert_id:
                return alert

        return None

    def update_status(self, alert_id: str, new_status: str):
        alert = self.get_alert_by_id(alert_id)

        if alert is None:
            return False

        alert.status = new_status
        return True