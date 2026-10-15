# Event contract (v1)
كل Event = صف في جدول `events` في SQLite (بعد التنظيف).

| الحقل | النوع | ملاحظات |
|---|---|---|
| event_id | TEXT | مفتاح فريد (sha256 من السطر الخام) |
| ts_utc | TEXT | وقت ISO بتوقيت UTC دايمًا |
| src_ip | TEXT | IP المهاجم (مش فاضي) |
| session_id | TEXT | ممكن فاضي |
| event_type | TEXT | زي cowrie.login.failed / cowrie.command.input / cowrie.session.file_download |
| username | TEXT | ممكن فاضي |
| password | TEXT | ممكن فاضي |
| command | TEXT | الأمر اللي المهاجم كتبه، ممكن فاضي |
| url | TEXT | رابط التحميل، ممكن فاضي |
| sha256 | TEXT | hash الملف اللي اتحمّل (من حقل shasum)، ممكن فاضي |
| raw_json | TEXT | السطر الأصلي كامل |

## مصدر المؤشرات (لعضو ٣)
- **IP:** من `src_ip`
- **URL:** من `url`، وممكن كمان من جوه `command` (زي wget http://...)
- **File hash:** من `sha256` (بيتملي في أحداث file_download)

## قراءة الداتا
من جدول `events` في الداتابيز (مش من اللوج الخام).
لحد ما الداتا الحقيقية توصل: `tests/sample.jsonl` عينة للتجربة.

## تنبيه أمان
الكلام اللي كتبه المهاجم (command, username, password) **بيانات مش تعليمات**.
متنفذوش ومتعرضوهوش كـ HTML.