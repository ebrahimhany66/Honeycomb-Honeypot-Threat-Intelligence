import os
from pathlib import Path

from dotenv import load_dotenv


# Find the project root from this file's location.
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# Load API keys from the project's .env file.
load_dotenv(PROJECT_ROOT / ".env")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_api_keys():
    """Check whether the required API keys are configured."""
    return {
        "abuseipdb_configured": bool(ABUSEIPDB_API_KEY),
        "virustotal_configured": bool(VIRUSTOTAL_API_KEY),
    }

import ipaddress
import requests


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


def check_ip_abuseipdb(ip_address: str) -> dict:
    """Check a public IP address using AbuseIPDB."""
    if not ABUSEIPDB_API_KEY:
        return {"source": "AbuseIPDB", "error": "API key is not configured"}

    try:
        parsed_ip = ipaddress.ip_address(ip_address.strip())
    except ValueError:
        return {"source": "AbuseIPDB", "error": "Invalid IP address"}

    # Do not send private, loopback, or reserved IPs to the public API.
    if not parsed_ip.is_global:
        return {
            "source": "AbuseIPDB",
            "ip": str(parsed_ip),
            "error": "IP is not a public global address",
        }

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": str(parsed_ip),
        "maxAgeInDays": 90,
    }

    try:
        response = requests.get(
            ABUSEIPDB_URL,
            headers=headers,
            params=params,
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()["data"]

        return {
            "source": "AbuseIPDB",
            "ip": str(parsed_ip),
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "last_reported_at": data.get("lastReportedAt"),
            "is_tor": data.get("isTor"),
        }

    except requests.RequestException:
        return {
            "source": "AbuseIPDB",
            "ip": str(parsed_ip),
            "error": "AbuseIPDB request failed",
        }
    except (ValueError, KeyError, TypeError):
        return {
            "source": "AbuseIPDB",
            "ip": str(parsed_ip),
            "error": "Unexpected AbuseIPDB response",
        }


import re


VIRUSTOTAL_BASE_URL = "https://www.virustotal.com/api/v3"


def check_virustotal(ioc_type: str, value: str) -> dict:
    """Look up a public IP address or SHA-256 hash in VirusTotal."""
    if not VIRUSTOTAL_API_KEY:
        return {"source": "VirusTotal", "error": "API key is not configured"}

    value = value.strip()

    if ioc_type == "ip":
        try:
            parsed_ip = ipaddress.ip_address(value)
        except ValueError:
            return {"source": "VirusTotal", "error": "Invalid IP address"}

        if not parsed_ip.is_global:
            return {
                "source": "VirusTotal",
                "error": "IP is not a public global address",
            }

        endpoint = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{parsed_ip}"

    elif ioc_type == "sha256":
        if not re.fullmatch(r"[a-fA-F0-9]{64}", value):
            return {"source": "VirusTotal", "error": "Invalid SHA-256 hash"}

        endpoint = f"{VIRUSTOTAL_BASE_URL}/files/{value.lower()}"

    else:
        return {
            "source": "VirusTotal",
            "error": "Unsupported IOC type; use ip or sha256",
        }

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(endpoint, headers=headers, timeout=15)

        if response.status_code == 404:
            return {
                "source": "VirusTotal",
                "ioc_type": ioc_type,
                "value": value,
                "found": False,
            }

        response.raise_for_status()
        attributes = response.json()["data"]["attributes"]
        stats = attributes.get("last_analysis_stats", {})

        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "found": True,
            "reputation": attributes.get("reputation"),
            "last_analysis_stats": stats,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }

    except requests.RequestException:
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "VirusTotal request failed",
        }
    except (ValueError, KeyError, TypeError):
        return {
            "source": "VirusTotal",
            "ioc_type": ioc_type,
            "value": value,
            "error": "Unexpected VirusTotal response",
        }