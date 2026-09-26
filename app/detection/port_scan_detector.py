def detect_port_scan(logs, port_threshold=5):
    alerts = []

    connection_logs = logs[
        logs["action"] == "connection"
    ].copy()

    for ip, group in connection_logs.groupby("ip"):
        unique_ports = group["port"].nunique()

        if unique_ports >= port_threshold:
            alerts.append({
                "type": "port_scan",
                "source_ip": ip,
                "unique_ports": unique_ports,
                "severity": "medium"
            })

    return alerts