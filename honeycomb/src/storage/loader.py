import sqlite3
import sys

from .schema import init_db
from .normalizer import normalize_line

COLUMNS = [
    "event_id", "ts_utc", "src_ip", "session_id", "event_type",
    "username", "password", "command", "url", "sha256", "raw_json",
]

INSERT_SQL = (
    f"INSERT OR IGNORE INTO events ({','.join(COLUMNS)}) "
    f"VALUES ({','.join('?' for _ in COLUMNS)})"
)


def load_file(db_path: str, log_path: str) -> dict:
    """Load a log file into SQLite. Safe to run twice on the same file."""
    conn = sqlite3.connect(db_path)
    init_db(conn)

    inserted = duplicates = bad_lines = 0
    with open(log_path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            if not line.strip():
                continue
            row = normalize_line(line)
            if row is None:
                bad_lines += 1
                continue
            cur = conn.execute(INSERT_SQL, [row[c] for c in COLUMNS])
            if cur.rowcount == 1:
                inserted += 1
            else:
                duplicates += 1

    conn.commit()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    conn.close()
    return {
        "inserted": inserted,
        "duplicates": duplicates,
        "bad_lines": bad_lines,
        "total_in_db": total,
    }


if __name__ == "__main__":
    print(load_file(sys.argv[1], sys.argv[2]))