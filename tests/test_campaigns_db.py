import sqlite3
from honeycomb.src.storage.schema import init_db
from honeycomb.src.campaigns_db import build_campaigns, load_sessions


def make_db():
    conn = sqlite3.connect(":memory:")
    init_db(conn)
    return conn


def add(conn, n, ip, sid, **kw):
    conn.execute(
        "INSERT INTO events (event_id, ts_utc, src_ip, session_id, event_type, command, url, sha256) "
        "VALUES (?,?,?,?,?,?,?,?)",
        (f"e{n}", f"2026-10-24T00:00:{n:02d}Z", ip, sid, kw.get("t", "x"),
         kw.get("command"), kw.get("url"), kw.get("sha256")))


def test_same_hash_two_ips_one_campaign_in_db():
    c = make_db()
    add(c, 1, "203.0.113.5", "a", sha256="abc")
    add(c, 2, "198.51.100.7", "b", sha256="abc")
    assert build_campaigns(c) == 1
    rule, conf = c.execute("SELECT rule, confidence FROM campaigns").fetchone()
    assert (rule, conf) == ("C1", "high")
    assert c.execute("SELECT count(*) FROM campaign_sessions").fetchone()[0] == 2


def test_same_24_only_no_campaign_in_db():
    c = make_db()
    add(c, 1, "203.0.113.5", "a")
    add(c, 2, "203.0.113.6", "b")
    assert build_campaigns(c) == 0


def test_running_twice_does_not_duplicate():
    c = make_db()
    add(c, 1, "1.1.1.1", "a", sha256="abc")
    add(c, 2, "2.2.2.2", "b", sha256="abc")
    build_campaigns(c)
    build_campaigns(c)
    assert c.execute("SELECT count(*) FROM campaigns").fetchone()[0] == 1
    assert c.execute("SELECT count(*) FROM campaign_sessions").fetchone()[0] == 2


def test_sessions_group_events_and_keep_command_order():
    c = make_db()
    add(c, 1, "1.1.1.1", "a", command="uname -a")
    add(c, 2, "1.1.1.1", "a", command="id")
    add(c, 3, "1.1.1.1", None, command="ignored")
    s = load_sessions(c)
    assert len(s) == 1 and s[0]["commands"] == ["uname -a", "id"]
