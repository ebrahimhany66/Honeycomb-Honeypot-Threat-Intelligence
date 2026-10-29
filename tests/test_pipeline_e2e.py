import sqlite3
from honeycomb.src.storage.loader import load_file

def test_e2e_pipeline(tmp_path):
    # 1. إنشاء مسار مؤقت لقاعدة البيانات وملف لوجات تجريبي
    db_file = tmp_path / "test_nexus.db"
    log_file = tmp_path / "sample.log"

    # 2. استخدام JSON صحيح متوافق مع normalizer.py (دخول ناجح + أمر)
    sample_log_data = (
        '{"timestamp": "2026-10-21T12:00:00Z", "src_ip": "192.168.1.50", '
        '"session": "sess_123", "eventid": "cowrie.login.success", '
        '"username": "root", "password": "123456"}\n'
        '{"timestamp": "2026-10-21T12:00:05Z", "src_ip": "192.168.1.50", '
        '"session": "sess_123", "eventid": "cowrie.command.input", '
        '"input": "whoami"}\n'
    )
    log_file.write_text(sample_log_data, encoding="utf-8")

    # 3. تشغيل الـ loader لتغذية الداتابيز
    result = load_file(str(db_file), str(log_file))

    # التأكد من نجاح عملية الإدخال (حدثين)
    assert result["inserted"] == 2
    assert result["bad_lines"] == 0

    # 4. التحقق من تخزين البيانات في جدول events وجدول sessions
    conn = sqlite3.connect(str(db_file))

    event_count = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    session_count = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]

    assert event_count == 2
    assert session_count == 1

    # التحقق من بيانات الجلسة التي تم استخراجها تلقائياً
    session_row = conn.execute("SELECT session_id, src_ip, username, command_count FROM sessions").fetchone()
    conn.close()

    assert session_row[0] == "sess_123"
    assert session_row[1] == "192.168.1.50"
    assert session_row[2] == "root"
    assert session_row[3] == 1