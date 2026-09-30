import pandas as pd
from app.database.db import get_connection

def save_events(logs):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            for _, event in logs.iterrows():
                port = None
                if not pd.isna(event["port"]):
                    port = int(event["port"])
                
                cursor.execute(
                    """
                    INSERT INTO events (
                        timestamp,
                        user_name,
                        ip,
                        action,
                        status,
                        device,
                        location,
                        port
                    )
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        event["timestamp"].to_pydatetime(),
                        event["user"],
                        event["ip"],
                        event["action"],
                        event["status"],
                        event["device"],
                        event["location"],
                        port,
                    ),
                )