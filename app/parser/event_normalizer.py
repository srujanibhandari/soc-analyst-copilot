import pandas as pd


REQUIRED_COLUMNS = [
    "timestamp",
    "user",
    "ip",
    "action",
    "status",
    "device",
    "location",
    "port",
]


def normalize_logs(df: pd.DataFrame) -> pd.DataFrame:
    """Cleans and standardizes raw security log data for downstream analysis."""
    # Work on a copy to avoid mutating original DataFrame
    logs = df.copy()

    # Validate required columns
    for col in REQUIRED_COLUMNS:
        if col not in logs.columns:
            raise ValueError(f"Missing required column in logs: {col}")

    # Convert timestamps to datetime objects
    logs["timestamp"] = pd.to_datetime(logs["timestamp"], errors="coerce")

    # Clean text columns: trim whitespace and convert to lowercase
    text_columns = ["user", "ip", "action", "status", "device", "location"]
    for col in text_columns:
        logs[col] = logs[col].astype(str).str.strip().str.lower()

    # Convert port to numeric (NaN for non-port events like standard logins)
    logs["port"] = pd.to_numeric(logs["port"], errors="coerce")

    # Drop any rows where timestamp failed to parse
    logs = logs.dropna(subset=["timestamp"])

    return logs