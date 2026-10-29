# Labeled Test Scenarios

Files: `tests/fixtures/scenarios/S1..S6.jsonl` (Cowrie JSON log format) and `expected.json` (expected result per scenario).
All IPs use documentation ranges (RFC 5737). All data is synthetic.

| Scenario | What happens | Expected behaviors | Campaign | Label |
|---|---|---|---|---|
| S1 | 10 failed logins, success, recon, SSH key added | B01, B03, B04, B05, B11 | none | attack |
| S2 | Login root/root, wget script, chmod, run, clear history | B02, B08, B09, B13 | none | attack |
| S3 | Download bot.bin and run it (IP 192.0.2.21) | B02, B08, B09 | C1 | attack |
| S4 | Same file and same commands from another IP (192.0.2.88) | B02, B08, B09 | C1 | attack |
| S5 | Connect and disconnect, no login (port scanner) | none | none | not_attack |
| S6 | One failed login, then success, `whoami`, `ls` | none | none | not_attack |

S3 and S4 must end up in one campaign (same SHA-256, same URL, same command sequence).
S5 and S6 test false positives: the system must flag nothing.
