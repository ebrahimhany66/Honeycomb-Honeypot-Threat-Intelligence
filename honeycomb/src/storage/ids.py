# honeycomb/src/storage/ids.py

import hashlib

def make_event_id(raw_line: str) -> str:
    """Stable ID: the same line always gives the same ID."""
    return hashlib.sha256(raw_line.strip().encode("utf-8")).hexdigest()