"""Header and sender authentication checks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .parser import ParsedEmail
from .utils import (
    extract_domain_from_email_header,
    extract_domain_from_message_id,
)


AUTH_RESULT_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*(pass|fail|softfail|none|neutral|temperror|permerror)\b",
    re.IGNORECASE,
)
RECEIVED_FROM_RE = re.compile(r"\bfrom\s+([^\s;()]+)", re.IGNORECASE)
RECEIVED_BY_RE = re.compile(r"\bby\s+([^\s;()]+)", re.IGNORECASE)

FAIL_RESULTS = {"fail", "softfail"}
NONE_RESULTS = {"none"}


@dataclass(slots=True)
class HeaderAnalysisResult:
    from_domain: str
    return_path_domain: str
    reply_to_domain: str
    message_id_domain: str
    authentication: dict[str, str]
    received_chain: list[dict[str, str]]
    findings: list[str] = field(default_factory=list)
    indicators: list[str] = field(default_factory=list)


def analyze_headers(headers: dict[str, Any]) -> dict[str, Any]:
    """Analyze email headers and return phishing signals plus a 0-100 score."""
    normalized = _normalize_headers(headers)

    from_domain = extract_domain_from_email_header(_first_header(normalized, "from"))
    return_path_domain = extract_domain_from_email_header(_first_header(normalized, "return-path"))
    reply_to_domain = extract_domain_from_email_header(_first_header(normalized, "reply-to"))
    message_id_domain = extract_domain_from_message_id(_first_header(normalized, "message-id"))
    auth_results = _parse_authentication_results(normalized)
    received_chain = _parse_received_chain(_all_headers(normalized, "received"))

    signals: list[dict[str, str]] = []
    score = 0

    if not _all_headers(normalized, "authentication-results"):
        score += 10
        signals.append(
            _signal(
                "missing_authentication_headers",
                "medium",
                "Authentication-Results header is missing",
            )
        )

    for mechanism, fail_score in (("spf", 25), ("dkim", 20), ("dmarc", 25)):
        result = auth_results.get(mechanism, "missing")
        if result in FAIL_RESULTS:
            score += fail_score
            signals.append(
                _signal(
                    f"{mechanism}_{result}",
                    "high",
                    f"{mechanism.upper()} authentication result is {result}",
                )
            )
        elif result in NONE_RESULTS:
            signals.append(
                _signal(
                    f"{mechanism}_none",
                    "medium",
                    f"{mechanism.upper()} authentication result is none",
                )
            )
        elif result == "missing" and _all_headers(normalized, "authentication-results"):
            signals.append(
                _signal(
                    f"{mechanism}_missing",
                    "low",
                    f"{mechanism.upper()} result is not present in Authentication-Results",
                )
            )

    if from_domain and return_path_domain and from_domain != return_path_domain:
        score += 15
        signals.append(
            _signal(
                "from_return_path_mismatch",
                "medium",
                "From domain and Return-Path domain do not match",
            )
        )

    if from_domain and reply_to_domain and from_domain != reply_to_domain:
        score += 20
        signals.append(
            _signal(
                "from_reply_to_mismatch",
                "high",
                "From domain and Reply-To domain do not match",
            )
        )

    if from_domain and message_id_domain and from_domain != message_id_domain:
        score += 10
        signals.append(
            _signal(
                "message_id_domain_mismatch",
                "medium",
                "Message-ID domain does not match From domain",
            )
        )

    if not received_chain:
        signals.append(_signal("missing_received_chain", "low", "Received header chain is missing"))

    return {
        "signals": signals,
        "score": min(score, 100),
        "details": {
            "from_domain": from_domain,
            "return_path_domain": return_path_domain,
            "reply_to_domain": reply_to_domain,
            "message_id_domain": message_id_domain,
            "authentication": auth_results,
            "received_chain": received_chain,
            "received_count": len(received_chain),
        },
    }


class HeaderAnalyzer:
    """Analyze email headers for authentication and spoofing signals."""

    def analyze(self, parsed_email: ParsedEmail) -> HeaderAnalysisResult:
        result = analyze_headers(parsed_email.headers)
        details = result["details"]
        findings = [signal["description"] for signal in result["signals"]]
        indicators = _signals_to_legacy_indicators(result["signals"])

        return HeaderAnalysisResult(
            from_domain=details["from_domain"],
            return_path_domain=details["return_path_domain"],
            reply_to_domain=details["reply_to_domain"],
            message_id_domain=details["message_id_domain"],
            authentication=details["authentication"],
            received_chain=details["received_chain"],
            findings=findings,
            indicators=indicators,
        )

    @staticmethod
    def _parse_authentication_results(headers: dict[str, Any]) -> dict[str, str]:
        return _parse_authentication_results(_normalize_headers(headers))


def _normalize_headers(headers: dict[str, Any]) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key, value in headers.items():
        header_name = str(key).strip().lower()
        if not header_name:
            continue
        values = value if isinstance(value, list) else [value]
        normalized.setdefault(header_name, []).extend(str(item) for item in values if item is not None)
    return normalized


def _first_header(headers: dict[str, list[str]], name: str) -> str:
    values = _all_headers(headers, name)
    return values[0] if values else ""


def _all_headers(headers: dict[str, list[str]], name: str) -> list[str]:
    return headers.get(name.lower(), [])


def _parse_authentication_results(headers: dict[str, list[str]]) -> dict[str, str]:
    auth_text = "\n".join(_all_headers(headers, "authentication-results"))
    results = {name.lower(): value.lower() for name, value in AUTH_RESULT_RE.findall(auth_text)}
    return {key: results.get(key, "missing") for key in ("spf", "dkim", "dmarc")}


def _parse_received_chain(received_headers: list[str]) -> list[dict[str, str]]:
    chain: list[dict[str, str]] = []
    for index, header in enumerate(received_headers, start=1):
        from_match = RECEIVED_FROM_RE.search(header)
        by_match = RECEIVED_BY_RE.search(header)
        chain.append(
            {
                "position": str(index),
                "from": _clean_received_host(from_match.group(1)) if from_match else "",
                "by": _clean_received_host(by_match.group(1)) if by_match else "",
            }
        )
    return chain


def _clean_received_host(value: str) -> str:
    return value.strip().strip("[]<>(),;").lower()


def _signal(name: str, severity: str, description: str) -> dict[str, str]:
    return {"name": name, "severity": severity, "description": description}


def _signals_to_legacy_indicators(signals: list[dict[str, str]]) -> list[str]:
    mapping = {
        "from_return_path_mismatch": "sender_domain_mismatch",
        "from_reply_to_mismatch": "reply_to_mismatch",
        "message_id_domain_mismatch": "message_id_domain_mismatch",
        "missing_authentication_headers": "authentication_missing",
        "spf_fail": "spf_fail",
        "spf_softfail": "spf_softfail",
        "dkim_fail": "dkim_fail",
        "dkim_softfail": "dkim_fail",
        "dmarc_fail": "dmarc_fail",
        "dmarc_softfail": "dmarc_fail",
        "spf_none": "spf_missing",
        "dkim_none": "dkim_missing",
        "dmarc_none": "dmarc_missing",
        "spf_missing": "spf_missing",
        "dkim_missing": "dkim_missing",
        "dmarc_missing": "dmarc_missing",
    }
    return [mapping.get(signal["name"], signal["name"]) for signal in signals]
