CREATE TABLE IF NOT EXISTS events (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    user_name TEXT NOT NULL,
    ip TEXT NOT NULL,
    action TEXT NOT NULL,
    status TEXT NOT NULL,
    device TEXT,
    location TEXT,
    port INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    user_name TEXT,
    source_ip TEXT,
    description TEXT NOT NULL,
    evidence JSONB
);