"""Attachment metadata analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .parser import AttachmentInfo


DANGEROUS_EXTENSIONS = {
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".jar",
    ".iso",
    ".lnk",
}

OFFICE_MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z"}
PHISHING_FILENAME_WORDS = {
    "invoice",
    "payment",
    "receipt",
    "bank",
    "document",
    "urgent",
}
LARGE_ATTACHMENT_BYTES = 10 * 1024 * 1024

SIGNAL_WEIGHTS = {
    "suspicious_extension": 35,
    "office_macro_risk": 30,
    "archive_attachment": 10,
    "double_extension": 20,
    "phishing_filename_keyword": 10,
    "large_attachment": 10,
    "unnamed_attachment": 15,
}


@dataclass(slots=True)
class AttachmentFinding:
    filename: str
    content_type: str
    size_bytes: int
    risk_score: int = 0
    signals: list[str] = field(default_factory=list)

    @property
    def risk_flags(self) -> list[str]:
        """Backward-compatible alias used by earlier code."""
        return self.signals


@dataclass(slots=True)
class AttachmentAnalysisResult:
    attachments: list[AttachmentFinding]
    findings: list[str]
    indicators: list[str]
    score: int = 0
    total_attachments: int = 0


def analyze_attachments(attachments: list[Any]) -> dict[str, Any]:
    """Analyze attachment metadata without opening or executing file content."""
    analyzed: list[dict[str, Any]] = []

    for raw_attachment in attachments:
        attachment = _normalize_attachment(raw_attachment)
        signals = _signals_for_attachment(attachment)
        risk_score = min(sum(SIGNAL_WEIGHTS.get(signal, 5) for signal in signals), 100)
        analyzed.append(
            {
                "filename": attachment["filename"],
                "content_type": attachment["content_type"],
                "size_bytes": attachment["size_bytes"],
                "risk_score": risk_score,
                "signals": signals,
            }
        )

    return {
        "attachments": analyzed,
        "score": max((item["risk_score"] for item in analyzed), default=0),
        "total_attachments": len(analyzed),
    }


class AttachmentAnalyzer:
    """Analyze attachment names, types, and sizes without executing content."""

    def analyze(self, attachments: list[AttachmentInfo]) -> AttachmentAnalysisResult:
        result = analyze_attachments(attachments)
        analyzed = [
            AttachmentFinding(
                filename=item["filename"],
                content_type=item["content_type"],
                size_bytes=item["size_bytes"],
                risk_score=item["risk_score"],
                signals=item["signals"],
            )
            for item in result["attachments"]
        ]
        findings = [
            f"Attachment '{finding.filename}' flagged as {signal}"
            for finding in analyzed
            for signal in finding.signals
        ]
        indicators = [
            _signal_to_indicator(signal)
            for finding in analyzed
            for signal in finding.signals
        ]

        return AttachmentAnalysisResult(
            attachments=analyzed,
            findings=findings,
            indicators=indicators,
            score=result["score"],
            total_attachments=result["total_attachments"],
        )


def _normalize_attachment(attachment: Any) -> dict[str, Any]:
    if isinstance(attachment, dict):
        filename = str(attachment.get("filename") or "").strip()
        content_type = str(attachment.get("content_type") or "").strip()
        size_bytes = attachment.get("size_bytes") or 0
    else:
        filename = str(getattr(attachment, "filename", "") or "").strip()
        content_type = str(getattr(attachment, "content_type", "") or "").strip()
        size_bytes = getattr(attachment, "size_bytes", 0) or 0

    try:
        normalized_size = max(int(size_bytes), 0)
    except (TypeError, ValueError):
        normalized_size = 0

    return {
        "filename": filename,
        "content_type": content_type or "application/octet-stream",
        "size_bytes": normalized_size,
    }


def _signals_for_attachment(attachment: dict[str, Any]) -> list[str]:
    filename = attachment["filename"]
    normalized_name = filename.lower()
    suffixes = [suffix.lower() for suffix in Path(filename).suffixes]
    final_suffix = suffixes[-1] if suffixes else ""
    signals: list[str] = []

    if not filename or filename == "unnamed":
        signals.append("unnamed_attachment")

    if final_suffix in DANGEROUS_EXTENSIONS:
        signals.append("suspicious_extension")

    if final_suffix in OFFICE_MACRO_EXTENSIONS:
        signals.append("office_macro_risk")

    if final_suffix in ARCHIVE_EXTENSIONS:
        signals.append("archive_attachment")

    if _has_double_extension(suffixes):
        signals.append("double_extension")

    if any(_contains_word(normalized_name, word) for word in PHISHING_FILENAME_WORDS):
        signals.append("phishing_filename_keyword")

    if attachment["size_bytes"] > LARGE_ATTACHMENT_BYTES:
        signals.append("large_attachment")

    return signals


def _has_double_extension(suffixes: list[str]) -> bool:
    if len(suffixes) < 2:
        return False
    final_suffix = suffixes[-1]
    previous_suffixes = suffixes[:-1]
    risky_final = final_suffix in DANGEROUS_EXTENSIONS | OFFICE_MACRO_EXTENSIONS
    known_decoy = any(suffix in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".txt", ".jpg", ".png"} for suffix in previous_suffixes)
    return risky_final or known_decoy


def _contains_word(text: str, word: str) -> bool:
    return re.search(rf"(?<![a-z0-9]){re.escape(word)}(?![a-z0-9])", text, re.IGNORECASE) is not None


def _signal_to_indicator(signal: str) -> str:
    mapping = {
        "suspicious_extension": "attachment_dangerous_extension",
        "office_macro_risk": "attachment_office_macro_risk",
        "archive_attachment": "attachment_archive_attachment",
        "double_extension": "attachment_double_extension",
        "phishing_filename_keyword": "attachment_phishing_filename_keyword",
        "large_attachment": "attachment_large_attachment",
        "unnamed_attachment": "attachment_unnamed",
    }
    return mapping.get(signal, f"attachment_{signal}")
