import json
from app.database.db import get_connection

def save_alerts(alerts):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            for alert in alerts:
                user = alert.get("user")
                source_ip = alert.get("source_ip", alert.get("ip"))
                description = f"Detected suspicious activity: {alert['type']}"
                
                cursor.execute(
                    """
                    INSERT INTO alerts (
                        id,
                        type,
                        severity,
                        status,
                        timestamp,
                        user_name,
                        source_ip,
                        description,
                        evidence
                    )
                    VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (id) DO NOTHING
                    """,
                    (
                        alert["id"],
                        alert["type"],
                        alert["severity"],
                        "new",
                        alert["timestamp"],
                        user,
                        source_ip,
                        description,
                        json.dumps(alert, default=str),  # <--- Added default=str here
                    ),
                )