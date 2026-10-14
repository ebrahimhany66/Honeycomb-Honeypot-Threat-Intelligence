# honeycomb/src/storage/schema.py

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    event_id   TEXT PRIMARY KEY,
    ts_utc     TEXT NOT NULL,
    src_ip     TEXT NOT NULL,
    session_id TEXT,
    event_type TEXT NOT NULL,
    username   TEXT,
    password   TEXT,
    command    TEXT,
    url        TEXT,
    sha256     TEXT,
    raw_json   TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
"""

def init_db(conn):
    """Create tables if they don't exist yet."""
    conn.executescript(SCHEMA)
    conn.commit()