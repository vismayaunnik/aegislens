from __future__ import annotations

import re
from typing import Iterable


_IPV4_RE = re.compile(
    r"""
    (?<![\d.])                           # don't start mid-number / dotted token
    (?:                                  # IPv4 (0-255).(0-255).(0-255).(0-255)
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.
        (?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)
    )
    (?![\d.])                            # don't end mid-number / dotted token
    """,
    re.VERBOSE,
)

# Conservative domain matching:
# - requires at least one dot
# - labels are alnum with internal hyphens only
# - no underscores
# - TLD is alpha-only (2-24)
# - tries to avoid common log noise like paths and dotted version strings
_DOMAIN_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_./\\-])               # avoid file paths / dotted tokens
    (
        (?:                               # one or more labels + trailing dot
            [A-Za-z0-9]
            (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
            \.
        )+
        [A-Za-z]{2,24}                    # TLD (alpha only)
    )
    (?![A-Za-z0-9_-])                    # don't run into a longer token
    """,
    re.VERBOSE,
)


def _unique_in_order(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 addresses from unstructured text."""
    if not text:
        return []
    return _unique_in_order(m.group(0) for m in _IPV4_RE.finditer(text))


def extract_domains(text: str) -> list[str]:
    """Extract conservative domain matches from unstructured text."""
    if not text:
        return []

    candidates: list[str] = []
    for m in _DOMAIN_RE.finditer(text):
        d = m.group(1).rstrip(".").lower()
        if _IPV4_RE.fullmatch(d):
            continue
        candidates.append(d)

    return _unique_in_order(candidates)


def extract_iocs(text: str) -> list[tuple[str, str]]:
    """
    Extract IOCs from text, returning a combined list of (value, type) tuples.

    Types returned:
    - "ip"
    - "domain"
    """
    if not text:
        return []

    matches: list[tuple[int, int, str, str]] = []

    for m in _IPV4_RE.finditer(text):
        matches.append((m.start(), m.end(), m.group(0), "ip"))

    for m in _DOMAIN_RE.finditer(text):
        d = m.group(1).rstrip(".").lower()
        if _IPV4_RE.fullmatch(d):
            continue
        matches.append((m.start(1), m.end(1), d, "domain"))

    matches.sort(key=lambda t: (t[0], t[1]))

    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for _s, _e, value, typ in matches:
        key = (value, typ)
        if key in seen:
            continue
        seen.add(key)
        out.append(key)

    return out


if __name__ == "__main__":
    sample_log = """
    2026-06-30 12:38:01Z INFO request from 8.8.8.8 to api.example.com path=/v1/health
    2026-06-30 12:38:02Z WARN open failed: C:\\Windows\\System32\\drivers\\etc\\hosts
    2026-06-30 12:38:03Z DEBUG file=/var/log/nginx/access.log version=1.2.3
    """

    print("IPs:", extract_ips(sample_log))
    print("Domains:", extract_domains(sample_log))
    print("IOCs:", extract_iocs(sample_log))
