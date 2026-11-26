"""
Passive URL inspection copied from PHISHGUARD SecurityAnalyzer.

Extracts and defangs URLs already present in the message. It does not
request those URLs.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".tk", ".pw", ".buzz", ".ru", ".cn", ".club", ".work",
    ".support", ".live", ".stream", ".icu", ".monster", ".gq", ".ga", ".ml", ".cf",
}
URL_REGEX = re.compile(r'https?://[^\s<>"\'\)]+|www\.[^\s<>"\'\)]+', re.IGNORECASE)
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def defang_url(url: str) -> str:
    return url.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def suspicious_urls(text: str, limit: int = 10) -> list[dict]:
    """Return defanged suspicious URLs. Live URLs are not included."""
    if not text:
        return []
    found = []
    seen = set()
    for raw in URL_REGEX.findall(text):
        url = raw.rstrip(".,;)>'\"")
        if url in seen:
            continue
        seen.add(url)
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower().split(":")[0]
        reason = None
        if domain and IP_REGEX.fullmatch(domain):
            reason = "Direct IP-address host"
        elif domain and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
            reason = f"High-risk top-level domain: {domain}"
        elif "@" in url:
            reason = "URL contains an @ sign"
        if reason:
            found.append({"defanged": defang_url(url), "reason": reason})
        if len(found) >= limit:
            break
    return found
