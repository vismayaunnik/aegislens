from __future__ import annotations

import json
import os
from typing import Any

import requests
from dotenv import load_dotenv

import database


_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(_ROOT_DIR, ".env"))


ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "").strip()
VT_API_KEY = (
    os.getenv("VT_API_KEY", "").strip()
    or os.getenv("VIRUSTOTAL_API_KEY", "").strip()
)


_DEFAULT_TIMEOUT_S = 12


def _ensure_db_ready() -> None:
    # Keep this lightweight and idempotent.
    database.init_db()


def _normalize(
    *,
    ioc: str,
    ioc_type: str,
    risk_score: int | None,
    source: str,
    raw: Any,
    status: str = "ok",
    error: str | None = None,
) -> dict[str, Any]:
    """
    Normalized return shape.

    Always includes {ioc, ioc_type, risk_score, source, raw}.
    Adds {status, error} for clear non-crashing error reporting.
    """
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": risk_score,
        "source": source,
        "raw": raw,
        "status": status,
        "error": error,
    }


def _cache_key(ioc_type: str, ioc: str) -> str:
    # The DB uses a single unique `ioc` column; prefix to avoid collisions.
    return f"{ioc_type}:{ioc}"


def _try_load_cached(ioc_type: str, ioc: str) -> dict[str, Any] | None:
    _ensure_db_ready()
    row = database.get_cached(_cache_key(ioc_type, ioc))
    if not row:
        return None

    raw_val = row.get("api_risk_score")
    if isinstance(raw_val, str) and raw_val:
        try:
            parsed = json.loads(raw_val)
            if isinstance(parsed, dict) and {"ioc", "ioc_type", "risk_score", "source", "raw"}.issubset(
                parsed.keys()
            ):
                # Mark as cached while preserving the original raw payload.
                parsed["source"] = "cache"
                parsed.setdefault("status", "ok")
                parsed.setdefault("error", None)
                return parsed
        except json.JSONDecodeError:
            pass

    # Fallback if previous cache content was not JSON.
    return _normalize(
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=None,
        source="cache",
        raw={"cached_row": row},
        status="ok",
        error=None,
    )


def _save_cache(ioc_type: str, ioc: str, normalized: dict[str, Any]) -> None:
    _ensure_db_ready()
    database.save_cached(
        _cache_key(ioc_type, ioc),
        ioc_type,
        json.dumps(normalized, ensure_ascii=False),
        "",  # llm_verdict (not used here)
    )


def enrich_ip(ip: str) -> dict[str, Any]:
    """
    Enrich an IP using AbuseIPDB.

    - Checks local cache first (database.get_cached)
    - If not cached, calls AbuseIPDB /check and caches normalized result
    """
    cached = _try_load_cached("ip", ip)
    if cached:
        return cached

    if not ABUSEIPDB_API_KEY:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw=None,
            status="error",
            error="missing ABUSEIPDB_API_KEY",
        )

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}

    try:
        resp = requests.get(url, headers=headers, params=params, timeout=_DEFAULT_TIMEOUT_S)
    except requests.Timeout:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw=None,
            status="error",
            error="timeout contacting AbuseIPDB",
        )
    except requests.RequestException as e:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw={"exception": str(e)},
            status="error",
            error="request error contacting AbuseIPDB",
        )

    if resp.status_code == 429:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="rate limited by AbuseIPDB (HTTP 429)",
        )
    if resp.status_code in (401, 403):
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="invalid AbuseIPDB API key or forbidden",
        )
    if resp.status_code >= 400:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error=f"AbuseIPDB error (HTTP {resp.status_code})",
        )

    try:
        data = resp.json()
    except ValueError:
        return _normalize(
            ioc=ip,
            ioc_type="ip",
            risk_score=None,
            source="abuseipdb",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="invalid JSON from AbuseIPDB",
        )

    ip_data = (data or {}).get("data", {}) if isinstance(data, dict) else {}
    abuse_score = ip_data.get("abuseConfidenceScore")
    total_reports = ip_data.get("totalReports")

    try:
        risk_score = int(abuse_score) if abuse_score is not None else None
    except (TypeError, ValueError):
        risk_score = None

    normalized = _normalize(
        ioc=ip,
        ioc_type="ip",
        risk_score=risk_score,
        source="abuseipdb",
        raw={
            "abuseConfidenceScore": abuse_score,
            "totalReports": total_reports,
            "response": data,
        },
        status="ok",
        error=None,
    )
    _save_cache("ip", ip, normalized)
    return normalized


def enrich_domain(domain: str) -> dict[str, Any]:
    """
    Enrich a domain using VirusTotal.

    - Checks local cache first (database.get_cached)
    - If not cached, calls VirusTotal domains/{domain} and caches normalized result
    """
    cached = _try_load_cached("domain", domain)
    if cached:
        return cached

    if not VT_API_KEY:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw=None,
            status="error",
            error="missing VT_API_KEY",
        )

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY, "Accept": "application/json"}

    try:
        resp = requests.get(url, headers=headers, timeout=_DEFAULT_TIMEOUT_S)
    except requests.Timeout:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw=None,
            status="error",
            error="timeout contacting VirusTotal",
        )
    except requests.RequestException as e:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw={"exception": str(e)},
            status="error",
            error="request error contacting VirusTotal",
        )

    if resp.status_code == 429:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="rate limited by VirusTotal (HTTP 429)",
        )
    if resp.status_code in (401, 403):
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="invalid VirusTotal API key or forbidden",
        )
    if resp.status_code >= 400:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error=f"VirusTotal error (HTTP {resp.status_code})",
        )

    try:
        data = resp.json()
    except ValueError:
        return _normalize(
            ioc=domain,
            ioc_type="domain",
            risk_score=None,
            source="virustotal",
            raw={"status_code": resp.status_code, "body": resp.text},
            status="error",
            error="invalid JSON from VirusTotal",
        )

    attrs = (
        (((data or {}).get("data") or {}).get("attributes") or {})
        if isinstance(data, dict)
        else {}
    )
    stats = attrs.get("last_analysis_stats") if isinstance(attrs, dict) else None
    stats = stats if isinstance(stats, dict) else {}

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    timeout = int(stats.get("timeout") or 0)
    total = malicious + suspicious + harmless + undetected + timeout
    risk_score = int(round(100 * (malicious + suspicious) / total)) if total > 0 else 0

    normalized = _normalize(
        ioc=domain,
        ioc_type="domain",
        risk_score=risk_score,
        source="virustotal",
        raw={
            "last_analysis_stats": stats,
            "computed": {"malicious": malicious, "suspicious": suspicious, "total": total},
            "response": data,
        },
        status="ok",
        error=None,
    )
    _save_cache("domain", domain, normalized)
    return normalized
