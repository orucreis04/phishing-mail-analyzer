"""Plain text and HTML body analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from bs4 import BeautifulSoup

from .url_analyzer import URLAnalyzer, URLAnalysisResult
from .utils import get_url_domain


URGENCY_PHRASES = (
    "urgent",
    "immediately",
    "action required",
    "account suspended",
    "verify now",
)

CREDENTIAL_PHRASES = (
    "password",
    "login",
    "credentials",
    "verify your account",
)

FINANCIAL_PHRASES = (
    "invoice",
    "payment",
    "bank",
    "transaction",
    "refund",
)

THREAT_PHRASES = (
    "your account will be closed",
    "suspended",
    "blocked",
)

BRAND_WORDS = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "amazon",
    "netflix",
    "bank",
)

UPPERCASE_RATIO_THRESHOLD = 0.45
UPPERCASE_MIN_LETTERS = 20


@dataclass(slots=True)
class LinkTarget:
    text: str
    href: str


@dataclass(slots=True)
class BodyAnalysisResult:
    url_analysis: URLAnalysisResult
    html_links: list[LinkTarget]
    body_score: int = 0
    keywords_found: list[str] = field(default_factory=list)
    signals: list[dict[str, str]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)


def analyze_body(plain_body: str, html_body: str) -> dict[str, Any]:
    """Analyze email text and HTML content for phishing body indicators."""
    combined_text = _combined_visible_text(plain_body, html_body)
    lowered = combined_text.lower()
    soup = BeautifulSoup(html_body or "", "html.parser")
    signals: list[dict[str, str]] = []
    keywords_found: list[str] = []
    score = 0

    for phrase in URGENCY_PHRASES:
        if _contains_phrase(lowered, phrase):
            score += 5
            keywords_found.append(phrase)
            signals.append(_signal("urgency_phrase", "low", f"Urgency phrase found: {phrase}"))

    for phrase in CREDENTIAL_PHRASES:
        if _contains_phrase(lowered, phrase):
            score += 15
            keywords_found.append(phrase)
            signals.append(_signal("credential_request", "high", f"Credential-related phrase found: {phrase}"))

    for phrase in FINANCIAL_PHRASES:
        if _contains_phrase(lowered, phrase):
            keywords_found.append(phrase)
            signals.append(_signal("financial_phrase", "medium", f"Financial phrase found: {phrase}"))

    for phrase in THREAT_PHRASES:
        if _contains_phrase(lowered, phrase):
            score += 15
            keywords_found.append(phrase)
            signals.append(_signal("threat_language", "high", f"Threat language found: {phrase}"))

    for brand in BRAND_WORDS:
        if _contains_phrase(lowered, brand):
            score += 10
            keywords_found.append(brand)
            signals.append(_signal("brand_impersonation", "medium", f"Brand keyword found: {brand}"))

    uppercase_ratio = _uppercase_ratio(combined_text)
    if uppercase_ratio >= UPPERCASE_RATIO_THRESHOLD:
        signals.append(
            _signal(
                "high_uppercase_ratio",
                "medium",
                f"Uppercase letter ratio is high: {uppercase_ratio:.2f}",
            )
        )

    if soup.find("form") is not None:
        score += 20
        signals.append(_signal("html_form", "high", "HTML form tag found"))

    if soup.find("script") is not None:
        score += 15
        signals.append(_signal("html_script", "high", "HTML script tag found"))

    if _has_hidden_content(html_body):
        score += 10
        signals.append(_signal("hidden_text", "medium", "Hidden text or display:none content found"))

    return {
        "signals": signals,
        "score": min(score, 100),
        "keywords_found": sorted(set(keywords_found)),
    }


class BodyAnalyzer:
    """Analyze email body text, HTML links, and social engineering cues."""

    def __init__(self, url_analyzer: URLAnalyzer | None = None) -> None:
        self.url_analyzer = url_analyzer or URLAnalyzer()

    def analyze(self, plain_text: str, html_text: str) -> BodyAnalysisResult:
        body_result = analyze_body(plain_text, html_text)
        url_analysis = self.url_analyzer.analyze(plain_text, html_text)
        html_links = _extract_html_links(html_text)
        findings = list(url_analysis.findings)
        indicators = list(url_analysis.indicators)

        for signal in body_result["signals"]:
            findings.append(signal["description"])
            indicators.append(_signal_to_indicator(signal["name"]))

        for link in html_links:
            visible_domain = get_url_domain(link.text) if link.text.startswith(("http://", "https://")) else ""
            href_domain = get_url_domain(link.href)
            if visible_domain and href_domain and visible_domain != href_domain:
                finding = f"Visible link domain differs from target: {visible_domain} -> {href_domain}"
                if finding not in findings:
                    findings.append(finding)
                    indicators.append("link_text_href_mismatch")

        return BodyAnalysisResult(
            url_analysis=url_analysis,
            html_links=html_links,
            body_score=body_result["score"],
            keywords_found=body_result["keywords_found"],
            signals=body_result["signals"],
            findings=findings,
            indicators=indicators,
        )


def _combined_visible_text(plain_body: str, html_body: str) -> str:
    html_text = BeautifulSoup(html_body or "", "html.parser").get_text(" ", strip=True)
    return "\n".join(part for part in (plain_body, html_text) if part)


def _contains_phrase(text: str, phrase: str) -> bool:
    escaped = re.escape(phrase.lower())
    return re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", text, re.IGNORECASE) is not None


def _uppercase_ratio(text: str) -> float:
    letters = [char for char in text if char.isalpha()]
    if len(letters) < UPPERCASE_MIN_LETTERS:
        return 0.0
    uppercase = sum(1 for char in letters if char.isupper())
    return uppercase / len(letters)


def _has_hidden_content(html_body: str) -> bool:
    if not html_body:
        return False
    soup = BeautifulSoup(html_body, "html.parser")
    if soup.find(attrs={"hidden": True}) is not None:
        return True
    for tag in soup.find_all(style=True):
        style = str(tag.get("style", ""))
        if re.search(r"display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0", style, re.IGNORECASE):
            return True
    return False


def _extract_html_links(html_body: str) -> list[LinkTarget]:
    soup = BeautifulSoup(html_body or "", "html.parser")
    links: list[LinkTarget] = []
    for anchor in soup.find_all("a", href=True):
        links.append(LinkTarget(text=anchor.get_text(" ", strip=True), href=str(anchor.get("href", ""))))
    return links


def _signal(name: str, severity: str, description: str) -> dict[str, str]:
    return {"name": name, "severity": severity, "description": description}


def _signal_to_indicator(name: str) -> str:
    mapping = {
        "urgency_phrase": "phishing_language",
        "credential_request": "credential_request",
        "financial_phrase": "financial_phrase",
        "threat_language": "threat_language",
        "brand_impersonation": "brand_impersonation",
        "high_uppercase_ratio": "high_uppercase_ratio",
        "html_form": "html_form",
        "html_script": "html_script",
        "hidden_text": "hidden_html_content",
    }
    return mapping.get(name, name)
