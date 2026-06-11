"""Risk scoring engine."""

from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass, asdict
from typing import Any


RISK_WEIGHTS = {
    "header": 0.30,
    "url": 0.35,
    "body": 0.20,
    "attachment": 0.15,
}

RECOMMENDATIONS = {
    "Critical": "Do not open links or attachments. Report to security team.",
    "High": "Verify sender identity through another channel.",
    "Medium": "Review suspicious indicators before interacting.",
    "Low": "No major phishing indicators found, but remain cautious.",
}


WEIGHTS = {
    "sender_domain_mismatch": 12,
    "reply_to_mismatch": 14,
    "spf_fail": 18,
    "spf_softfail": 12,
    "spf_permerror": 10,
    "spf_missing": 6,
    "dkim_fail": 16,
    "dkim_permerror": 10,
    "dkim_missing": 8,
    "dmarc_fail": 20,
    "dmarc_permerror": 12,
    "dmarc_missing": 8,
    "url_non_https": 6,
    "url_ip_address_host": 16,
    "url_url_shortener": 10,
    "url_userinfo_in_url": 18,
    "url_very_long_url": 8,
    "url_many_subdomains": 8,
    "url_encoded_or_punycode": 10,
    "url_brand_keyword_with_dash": 10,
    "phishing_language": 10,
    "html_only_message": 5,
    "hidden_html_content": 12,
    "link_text_href_mismatch": 18,
    "attachment_dangerous_extension": 24,
    "attachment_office_macro_risk": 22,
    "attachment_double_extension": 14,
    "attachment_phishing_filename_keyword": 8,
    "attachment_archive_attachment": 8,
    "attachment_large_attachment": 4,
    "attachment_unnamed": 8,
}


@dataclass(slots=True)
class RiskResult:
    score: int
    level: str
    weighted_indicators: dict[str, int]
    final_score: int | None = None
    risk_level: str | None = None
    summary: str = ""
    recommendations: list[str] = field(default_factory=list)


def calculate_final_risk(
    header_result: Any,
    url_result: Any,
    body_result: Any,
    attachment_result: Any,
) -> dict[str, Any]:
    """Combine analyzer scores into one normalized phishing risk result."""
    component_scores = {
        "header": _extract_score(header_result, preferred_keys=("score",)),
        "url": _extract_score(url_result, preferred_keys=("score",)),
        "body": _extract_score(body_result, preferred_keys=("score", "body_score")),
        "attachment": _extract_score(attachment_result, preferred_keys=("score",)),
    }

    final_score = round(
        component_scores["header"] * RISK_WEIGHTS["header"]
        + component_scores["url"] * RISK_WEIGHTS["url"]
        + component_scores["body"] * RISK_WEIGHTS["body"]
        + component_scores["attachment"] * RISK_WEIGHTS["attachment"]
    )
    final_score = _clamp_score(final_score)
    risk_level = _risk_level(final_score)

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "summary": _summary_for_score(final_score, risk_level, component_scores),
        "recommendations": [RECOMMENDATIONS[risk_level]],
    }


class RiskEngine:
    """Convert analyzer indicators into a normalized phishing risk score."""

    def calculate(self, indicators: list[str]) -> RiskResult:
        weighted: dict[str, int] = {}
        for indicator in indicators:
            weighted[indicator] = max(weighted.get(indicator, 0), WEIGHTS.get(indicator, 3))

        score = _clamp_score(sum(weighted.values()))
        level = _risk_level(score)

        return RiskResult(
            score=score,
            level=level.lower(),
            weighted_indicators=weighted,
            final_score=score,
            risk_level=level,
            summary=_summary_for_score(score, level, {}),
            recommendations=[RECOMMENDATIONS[level]],
        )

    def calculate_final(
        self,
        header_result: Any,
        url_result: Any,
        body_result: Any,
        attachment_result: Any,
    ) -> RiskResult:
        result = calculate_final_risk(header_result, url_result, body_result, attachment_result)
        return RiskResult(
            score=result["final_score"],
            level=result["risk_level"].lower(),
            weighted_indicators={},
            final_score=result["final_score"],
            risk_level=result["risk_level"],
            summary=result["summary"],
            recommendations=result["recommendations"],
        )


def _extract_score(result: Any, preferred_keys: tuple[str, ...]) -> int:
    data = _to_mapping(result)
    for key in preferred_keys:
        if key in data:
            return _clamp_score(data[key])

    nested_candidates = (
        ("url_analysis", "score"),
        ("body", "score"),
        ("attachments", "score"),
    )
    for parent_key, score_key in nested_candidates:
        parent = data.get(parent_key)
        parent_data = _to_mapping(parent)
        if score_key in parent_data:
            return _clamp_score(parent_data[score_key])

    return 0


def _to_mapping(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if is_dataclass(value):
        return asdict(value)
    return {
        name: getattr(value, name)
        for name in dir(value)
        if not name.startswith("_") and not callable(getattr(value, name))
    }


def _clamp_score(value: Any) -> int:
    try:
        score = int(round(float(value)))
    except (TypeError, ValueError):
        return 0
    return max(0, min(score, 100))


def _risk_level(score: int) -> str:
    if score >= 75:
        return "Critical"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Medium"
    return "Low"


def _summary_for_score(score: int, level: str, component_scores: dict[str, int]) -> str:
    if component_scores:
        return (
            f"Final phishing risk is {level} ({score}/100). "
            f"Component scores: header={component_scores['header']}, "
            f"url={component_scores['url']}, body={component_scores['body']}, "
            f"attachment={component_scores['attachment']}."
        )
    return f"Phishing risk is {level} ({score}/100)."
