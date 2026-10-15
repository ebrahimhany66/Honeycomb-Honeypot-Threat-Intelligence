from honeycomb.src.analysis.ioc_extractor import extract_iocs
from honeycomb.src.analysis.threat_intel import (
    check_ip_abuseipdb,
    check_virustotal,
)


def enrich_iocs(db_path: str) -> list:
    """Extract IOCs from SQLite and enrich supported indicators."""
    indicators = extract_iocs(db_path)
    results = []

    for indicator in indicators:
        ioc_type = indicator["type"]
        value = indicator["value"]

        # Preserve the original event references.
        result = {
            "type": ioc_type,
            "value": value,
            "event_ids": indicator["event_ids"],
            "threat_intel": {},
        }

        if ioc_type == "ip":
            result["threat_intel"]["abuseipdb"] = (
                check_ip_abuseipdb(value)
            )
            result["threat_intel"]["virustotal"] = (
                check_virustotal("ip", value)
            )

        elif ioc_type == "sha256":
            result["threat_intel"]["virustotal"] = (
                check_virustotal("sha256", value)
            )

        results.append(result)

    return results