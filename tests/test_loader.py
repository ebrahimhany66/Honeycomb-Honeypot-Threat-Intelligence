from honeycomb.src.storage.loader import load_file

SAMPLE = "tests/sample.jsonl"


def test_loads_all_events(tmp_path):
    db = str(tmp_path / "t.db")
    r = load_file(db, SAMPLE)
    assert r["inserted"] == 4
    assert r["total_in_db"] == 4


def test_loading_twice_does_not_duplicate(tmp_path):
    db = str(tmp_path / "t.db")
    load_file(db, SAMPLE)
    r = load_file(db, SAMPLE)
    assert r["inserted"] == 0
    assert r["duplicates"] == 4
    assert r["total_in_db"] == 4


def test_bad_line_is_skipped(tmp_path):
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json\n", encoding="utf-8")
    r = load_file(str(tmp_path / "t.db"), str(bad))
    assert r["bad_lines"] == 1
    assert r["total_in_db"] == 0