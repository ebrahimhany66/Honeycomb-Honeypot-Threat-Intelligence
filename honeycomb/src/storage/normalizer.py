import json
from datetime import datetime, timezone

from .ids import make_event_id


def normalize_line(raw_line: str):
    """Take one raw JSON log line and return a clean dict.
    Returns None if the line is broken or missing key fields."""
    try:
        d = json.loads(raw_line)
    except json.JSONDecodeError:
        return None

    if not isinstance(d, dict):
        return None

    ts = d.get("timestamp")
    ip = d.get("src_ip")
    etype = d.get("eventid")
    if not (ts and ip and etype):
        return None

    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    ts_utc = dt.astimezone(timezone.utc).isoformat()

    return {
        "event_id": make_event_id(raw_line),
        "ts_utc": ts_utc,
        "src_ip": ip,
        "session_id": d.get("session"),
        "event_type": etype,
        "username": d.get("username"),
        "password": d.get("password"),
        "command": d.get("input"),
        "url": d.get("url"),
        "sha256": d.get("shasum"),
        "raw_json": raw_line.strip(),
    }