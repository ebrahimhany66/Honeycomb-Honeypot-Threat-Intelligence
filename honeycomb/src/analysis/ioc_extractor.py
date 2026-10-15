import ipaddress
import re
import sqlite3
from collections import defaultdict


URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")


def extract_urls(text):
    """Extract HTTP/HTTPS URLs from text."""
    if not text:
        return set()

    urls = set()

    for match in URL_PATTERN.findall(text):
        url = match.rstrip(".,;:!?)]}")

        if url:
            urls.add(url)

    return urls


def extract_iocs(db_path):
    """
    Read normalized events from SQLite and extract unique IOCs.

    Returns a list of indicators with their associated event IDs.
    """
    indicators = defaultdict(set)

    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row

        rows = conn.execute(
            """
            SELECT event_id, ts_utc, src_ip, url, command, sha256
            FROM events
            """
        ).fetchall()

    for row in rows:
        event_id = row["event_id"]

        # Extract the attacker's source IP.
        src_ip = row["src_ip"]

        if src_ip:
            try:
                normalized_ip = str(ipaddress.ip_address(src_ip.strip()))
                indicators[("ip", normalized_ip)].add(event_id)
            except ValueError:
                pass

        # Extract URLs from the dedicated URL field.
        for url in extract_urls(row["url"]):
            indicators[("url", url)].add(event_id)

        # Extract URLs embedded in attacker commands, e.g. wget or curl.
        for url in extract_urls(row["command"]):
            indicators[("url", url)].add(event_id)

        # Extract valid SHA-256 file hashes.
        file_hash = row["sha256"]

        if file_hash and SHA256_PATTERN.fullmatch(file_hash.strip()):
            indicators[("sha256", file_hash.strip().lower())].add(event_id)

    results = []

    for (ioc_type, value), event_ids in sorted(indicators.items()):
        results.append(
            {
                "type": ioc_type,
                "value": value,
                "event_ids": sorted(event_ids),
            }
        )

    return results