import uuid
from datetime import datetime, timezone
from io import BytesIO

import pandas as pd
from fastapi import FastAPI, HTTPException, UploadFile

from app.database.alert_repository import save_alerts
from app.database.db import get_connection
from app.database.event_repository import save_events

from app.detection.alert_scoring import (
    calculate_confidence,
    assign_severity,
)
from app.detection.bruteforce_detector import detect_bruteforce
from app.detection.impossible_travel_detector import detect_impossible_travel
from app.detection.privilege_detector import detect_privilege_escalation
from app.detection.port_scan_detector import detect_port_scan

from app.parser.event_normalizer import normalize_logs


app = FastAPI(
    title="SOC Analyst Copilot",
    description="Cybersecurity monitoring and investigation API",
    version="0.1.0",
)


# ---------------------------------------------------------
# ROOT
# ---------------------------------------------------------

@app.get("/")
def root():
    return {
        "message": "SOC Analyst Copilot API is running"
    }


# ---------------------------------------------------------
# HEALTH CHECK
# ---------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


# ---------------------------------------------------------
# GET EVENTS
# ---------------------------------------------------------

@app.get("/events")
def get_events():

    with get_connection() as connection:
        with connection.cursor() as cursor:

            cursor.execute(
                """
                SELECT
                    id,
                    timestamp,
                    user_name,
                    ip,
                    action,
                    status,
                    device,
                    location,
                    port
                FROM events
                ORDER BY timestamp DESC
                LIMIT 100
                """
            )

            rows = cursor.fetchall()

    events = []

    for row in rows:

        events.append({
            "id": row[0],
            "timestamp": row[1],
            "user": row[2],
            "ip": row[3],
            "action": row[4],
            "status": row[5],
            "device": row[6],
            "location": row[7],
            "port": row[8],
        })

    return {
        "count": len(events),
        "events": events,
    }


# ---------------------------------------------------------
# GET ALL ALERTS
# ---------------------------------------------------------

@app.get("/alerts")
def get_alerts():

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
                ORDER BY timestamp DESC
                """
            )

            rows = cursor.fetchall()

    alerts = []

    for row in rows:

        evidence = row[8]

        confidence = None

        if isinstance(evidence, dict):
            confidence = evidence.get("confidence")

        alerts.append({
            "id": row[0],
            "type": row[1],
            "severity": row[2],
            "confidence": confidence,
            "status": row[3],
            "timestamp": row[4],
            "user": row[5],
            "source_ip": row[6],
            "description": row[7],
            "evidence": evidence,
        })

    return {
        "count": len(alerts),
        "alerts": alerts,
    }


# ---------------------------------------------------------
# GET SINGLE ALERT
# ---------------------------------------------------------

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
                (alert_id,),
            )

            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    evidence = row[8]

    confidence = None

    if isinstance(evidence, dict):
        confidence = evidence.get("confidence")

    return {
        "id": row[0],
        "type": row[1],
        "severity": row[2],
        "confidence": confidence,
        "status": row[3],
        "timestamp": row[4],
        "user": row[5],
        "source_ip": row[6],
        "description": row[7],
        "evidence": evidence,
    }


# ---------------------------------------------------------
# UPDATE ALERT STATUS
# ---------------------------------------------------------

@app.patch("/alerts/{alert_id}/status")
def update_alert_status(
    alert_id: str,
    status: str,
):

    allowed_statuses = {
        "new",
        "investigating",
        "resolved",
        "false_positive",
    }

    if status not in allowed_statuses:
        raise HTTPException(
            status_code=400,
            detail=(
                "Invalid status. "
                "Use: new, investigating, resolved, "
                "false_positive"
            ),
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
                (status, alert_id),
            )

            row = cursor.fetchone()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Alert not found",
        )

    return {
        "message": "Alert status updated",
        "id": row[0],
        "status": row[1],
    }


# ---------------------------------------------------------
# UPLOAD LOGS
# ---------------------------------------------------------

@app.post("/logs/upload")
async def upload_logs(file: UploadFile):

    if not file.filename:
        raise HTTPException(
            status_code=400,
            detail="File name is missing",
        )

    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Only CSV files are supported",
        )

    try:

        # ---------------------------------------------
        # 1. Read uploaded file
        # ---------------------------------------------

        contents = await file.read()

        logs = pd.read_csv(
            BytesIO(contents)
        )

        # ---------------------------------------------
        # 2. Normalize logs
        # ---------------------------------------------

        normalized_logs = normalize_logs(logs)

        # ---------------------------------------------
        # 3. Save events
        # ---------------------------------------------

        save_events(normalized_logs)

        # ---------------------------------------------
        # 4. Run detection engines
        # ---------------------------------------------

        brute_force_alerts = detect_bruteforce(
            normalized_logs,
            threshold=3,
            window_seconds=120,
        )

        travel_alerts = detect_impossible_travel(
            normalized_logs
        )

        privilege_alerts = detect_privilege_escalation(
            normalized_logs
        )

        port_scan_alerts = detect_port_scan(
            normalized_logs
        )

        raw_alerts = (
            brute_force_alerts
            + travel_alerts
            + privilege_alerts
            + port_scan_alerts
        )

        # ---------------------------------------------
        # 5. Add ID, timestamp, severity, confidence
        # ---------------------------------------------

        alerts = []

        for raw_alert in raw_alerts:

            alert = raw_alert.copy()

            # Unique alert ID
            alert["id"] = (
                f"ALT-{uuid.uuid4().hex[:8].upper()}"
            )

            # Alert creation time
            alert["timestamp"] = (
                datetime.now(timezone.utc)
            )

            # Calculate severity
            alert["severity"] = assign_severity(
                alert
            )

            # Calculate rule-based confidence
            alert["confidence"] = calculate_confidence(
                alert
            )

            # Default status
            alert["status"] = "new"

            alerts.append(alert)

        # ---------------------------------------------
        # 6. Save alerts
        # ---------------------------------------------

        save_alerts(alerts)

        # ---------------------------------------------
        # 7. Return result
        # ---------------------------------------------

        return {
            "message": "Logs processed successfully",
            "filename": file.filename,
            "events_processed": len(
                normalized_logs
            ),
            "alerts_generated": len(
                alerts
            ),
        }

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=f"Could not process file: {error}",
        )