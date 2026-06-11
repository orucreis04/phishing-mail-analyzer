"""URL extraction and suspicious URL heuristics."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

import tldextract
from bs4 import BeautifulSoup

from .utils import URL_RE, get_url_domain


SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "s.id",
    "rb.gy",
}

SUSPICIOUS_TLDS = {
    "zip",
    "mov",
    "top",
    "xyz",
    "click",
    "link",
    "work",
    "country",
    "gq",
    "tk",
    "ml",
    "cf",
}

SENSITIVE_KEYWORDS = {
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "password",
}

SIGNAL_WEIGHTS = {
    "ip_address_host": 25,
    "very_long_url": 10,
    "userinfo_in_url": 20,
    "suspicious_tld": 15,
    "many_subdomains": 10,
    "non_https": 10,
    "sensitive_keyword": 10,
    "punycode_domain": 20,
    "url_shortener": 15,
    "link_text_href_mismatch": 25,
}

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=())


@dataclass(slots=True)
class URLFinding:
    url: str
    domain: str
    risk_score: int = 0
    signals: list[str] = field(default_factory=list)

    @property
    def risk_flags(self) -> list[str]:
        """Backward-compatible alias used by earlier analyzer code."""
        return self.signals


@dataclass(slots=True)
class URLAnalysisResult:
    urls: list[URLFinding]
    findings: list[str]
    indicators: list[str]
    score: int = 0
    total_urls: int = 0


def analyze_urls(plain_body: str, html_body: str) -> dict[str, Any]:
    """Extract URLs from plain text and HTML, then score phishing indicators."""
    candidates = _extract_url_candidates(plain_body, html_body)
    analyzed_urls: list[dict[str, Any]] = []

    for candidate in candidates:
        url = _normalize_url(candidate["url"])
        if not url:
            continue

        domain = get_url_domain(url)
        signals = _signals_for_url(url, candidate)
        risk_score = min(sum(SIGNAL_WEIGHTS.get(signal, 5) for signal in signals), 100)
        analyzed_urls.append(
            {
                "url": url,
                "domain": domain,
                "risk_score": risk_score,
                "signals": signals,
            }
        )

    total_score = max((item["risk_score"] for item in analyzed_urls), default=0)
    return {
        "urls": analyzed_urls,
        "score": total_score,
        "total_urls": len(analyzed_urls),
    }


class URLAnalyzer:
    """Extract and score URLs with deterministic heuristics."""

    def extract_urls(self, text: str) -> list[str]:
        return [candidate["url"] for candidate in _extract_url_candidates(text, "")]

    def analyze(self, text: str, html_text: str = "") -> URLAnalysisResult:
        result = analyze_urls(text, html_text)
        url_findings = [
            URLFinding(
                url=item["url"],
                domain=item["domain"],
                risk_score=item["risk_score"],
                signals=item["signals"],
            )
            for item in result["urls"]
        ]
        findings = [
            f"Suspicious URL signal '{signal}' on {finding.domain or finding.url}"
            for finding in url_findings
            for signal in finding.signals
        ]
        indicators = [
            "link_text_href_mismatch" if signal == "link_text_href_mismatch" else f"url_{signal}"
            for finding in url_findings
            for signal in finding.signals
        ]

        return URLAnalysisResult(
            urls=url_findings,
            findings=findings,
            indicators=indicators,
            score=result["score"],
            total_urls=result["total_urls"],
        )

    def _flags_for_url(self, url: str) -> list[str]:
        """Backward-compatible helper retained for existing callers."""
        return _signals_for_url(url, {"url": url, "visible_text": "", "source": "manual"})


def _extract_url_candidates(plain_body: str, html_body: str) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []

    for url in URL_RE.findall(plain_body or ""):
        candidates.append({"url": url, "visible_text": "", "source": "plain"})

    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")
        for url in URL_RE.findall(soup.get_text(" ") or ""):
            candidates.append({"url": url, "visible_text": "", "source": "html_text"})

        for anchor in soup.find_all("a", href=True):
            href = str(anchor.get("href", "")).strip()
            if not href:
                continue
            text = anchor.get_text(" ", strip=True)
            candidates.append({"url": href, "visible_text": text, "source": "html_href"})

    return _deduplicate_candidates(candidates)


def _deduplicate_candidates(candidates: list[dict[str, str]]) -> list[dict[str, str]]:
    seen: dict[str, dict[str, str]] = {}
    unique: list[dict[str, str]] = []
    for candidate in candidates:
        url = _normalize_url(candidate["url"])
        if not url:
            continue
        if url in seen:
            existing = seen[url]
            if not existing.get("visible_text") and candidate.get("visible_text"):
                existing["visible_text"] = candidate["visible_text"]
            if candidate.get("source") and candidate["source"] not in existing.get("source", ""):
                existing["source"] = f"{existing.get('source', '')},{candidate['source']}".strip(",")
            continue
        normalized_candidate = {**candidate, "url": url}
        seen[url] = normalized_candidate
        unique.append(normalized_candidate)
    return unique


def _normalize_url(url: str) -> str:
    cleaned = (url or "").strip().rstrip(".,;])}")
    if cleaned.startswith("//"):
        cleaned = f"https:{cleaned}"
    if not cleaned.lower().startswith(("http://", "https://")):
        return ""
    parsed = urlparse(cleaned)
    if not parsed.netloc:
        return ""
    return urljoin(cleaned, parsed.path or "/") if cleaned.endswith(parsed.netloc) else cleaned


def _signals_for_url(url: str, candidate: dict[str, str]) -> list[str]:
    parsed = urlparse(url)
    domain = get_url_domain(url)
    extracted = _TLD_EXTRACTOR(domain)
    registered_domain = ".".join(part for part in (extracted.domain, extracted.suffix) if part)
    signals: list[str] = []

    if parsed.scheme.lower() != "https":
        signals.append("non_https")

    if _is_ip_host(domain):
        signals.append("ip_address_host")

    if "@" in parsed.netloc:
        signals.append("userinfo_in_url")

    if len(url) > 120:
        signals.append("very_long_url")

    if extracted.suffix.lower() in SUSPICIOUS_TLDS:
        signals.append("suspicious_tld")

    subdomain_count = len([part for part in extracted.subdomain.split(".") if part])
    if subdomain_count >= 3:
        signals.append("many_subdomains")

    if any(keyword in url.lower() for keyword in SENSITIVE_KEYWORDS):
        signals.append("sensitive_keyword")

    if "xn--" in domain:
        signals.append("punycode_domain")

    if domain in SHORTENER_DOMAINS or registered_domain in SHORTENER_DOMAINS:
        signals.append("url_shortener")

    visible_text = candidate.get("visible_text", "")
    visible_domain = get_url_domain(visible_text) if visible_text.startswith(("http://", "https://")) else ""
    if visible_domain and domain and visible_domain != domain:
        signals.append("link_text_href_mismatch")

    return signals


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
