import uuid
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd

from fastapi import FastAPI, HTTPException, UploadFile
from app.parser.event_normalizer import normalize_logs

from app.detection.bruteforce_detector import detect_bruteforce
from app.detection.impossible_travel_detector import detect_impossible_travel
from app.detection.privilege_detector import detect_privilege_escalation
from app.detection.port_scan_detector import detect_port_scan

from app.database.event_repository import save_events
from app.database.alert_repository import save_alerts
from app.database.db import get_connection

app = FastAPI(
    title="SOC Analyst Copilot",
    description="Cybersecurity monitoring and investigation API",
    version="0.1.0"
)

@app.get("/")
def root():
    return {"message": "SOC Analyst Copilot API is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/events")
def get_events():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, timestamp, user_name, ip, action, status, device, location, port
                FROM events
                ORDER BY timestamp DESC
                LIMIT 100
            """)
            rows = cursor.fetchall()
            events = [
                {
                    "id": row[0],
                    "timestamp": row[1],
                    "user": row[2],
                    "ip": row[3],
                    "action": row[4],
                    "status": row[5],
                    "device": row[6],
                    "location": row[7],
                    "port": row[8]
                }
                for row in rows
            ]
            return {"count": len(events), "events": events}

@app.get("/alerts")
def get_alerts():
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute("""
                SELECT id, type, severity, status, timestamp, user_name, source_ip, description, evidence
                FROM alerts
                ORDER BY timestamp DESC
            """)
            rows = cursor.fetchall()
            alerts = [
                {
                    "id": row[0],
                    "type": row[1],
                    "severity": row[2],
                    "status": row[3],
                    "timestamp": row[4],
                    "user": row[5],
                    "source_ip": row[6],
                    "description": row[7],
                    "evidence": row[8]
                }
                for row in rows
            ]
            return {"count": len(alerts), "alerts": alerts}
@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    id,
                    type,
                    severity,
                    status,
                    timestamp,
                    user_name,
                    source_ip,
                    description,
                    evidence
                FROM alerts
                WHERE id = %s
                """,
                (alert_id,)
            )

            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return {
        "id": row[0],
        "type": row[1],
        "severity": row[2],
        "status": row[3],
        "timestamp": row[4],
        "user": row[5],
        "source_ip": row[6],
        "description": row[7],
        "evidence": row[8]
    }
@app.patch("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    status: str
):
    allowed_statuses = {
        "new",
        "investigating",
        "resolved",
        "false_positive"
    }

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail="Invalid status"
        )

    with get_connection() as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE alerts
                SET status = %s
                WHERE id = %s
                RETURNING id, status
                """,
                (status, alert_id)
            )

            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found"
        )

    return {
        "message": "Alert status updated",
        "id": row[0],
        "status": row[1]
    }
@app.post("/logs/upload")
async def upload_logs(file: UploadFile):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File name is missing"
        )

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are supported"
        )

    try:
        contents = await file.read()

        logs = pd.read_csv(BytesIO(contents))

        normalized_logs = normalize_logs(logs)

        save_events(normalized_logs)

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

        alerts = []

        for raw_alert in raw_alerts:
            alert = raw_alert.copy()
            alert["id"] = f"ALT-{uuid.uuid4().hex[:8].upper()}"
            alert["timestamp"] = datetime.now(timezone.utc)

            alerts.append(alert)

        save_alerts(alerts)

        return {
            "message": "Logs processed successfully",
            "filename": file.filename,
            "events_processed": len(normalized_logs),
            "alerts_generated": len(alerts)
        }

    except Exception as error:
        raise HTTPException(
            status_code=400,
            detail=f"Could not process file: {error}"
        )