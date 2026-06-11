"""Report serialization and terminal rendering."""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .utils import truncate


DEFAULT_REPORT_DIR = Path("reports")


def generate_report(
    parsed_email: Any,
    header_result: Any,
    url_result: Any,
    body_result: Any,
    attachment_result: Any,
    risk_result: Any,
) -> dict[str, Any]:
    """Build a complete JSON-serializable phishing analysis report."""
    parsed = _parsed_email_summary(parsed_email)
    headers = _headers_from_parsed(parsed)
    header = _serialize(header_result)
    url = _serialize(url_result)
    body = _serialize(body_result)
    attachments = _serialize(attachment_result)
    risk = _serialize(risk_result)

    findings = [
        *_list_from(header.get("findings")),
        *_list_from(url.get("findings")),
        *_list_from(body.get("findings")),
        *_list_from(attachments.get("findings")),
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "phishing-mail-analyzer",
        "email": {
            "path": str(parsed.get("path", "")),
            "sha256": parsed.get("sha256", ""),
            "subject": parsed.get("subject") or headers.get("Subject", ""),
            "from": _first_header_value(headers, "From"),
            "to": parsed.get("to_addresses", []),
            "date": _first_header_value(headers, "Date"),
            "message_id": _first_header_value(headers, "Message-ID"),
        },
        "analysis": {
            "metadata": {
                "path": str(parsed.get("path", "")),
                "sha256": parsed.get("sha256", ""),
                "subject": parsed.get("subject") or headers.get("Subject", ""),
                "from_addresses": parsed.get("from_addresses", []),
                "to_addresses": parsed.get("to_addresses", []),
                "date": _first_header_value(headers, "Date"),
            },
            "header": header,
            "url": url,
            "body": body,
            "attachments": attachments,
            "risk": risk,
            "findings": findings,
        },
    }


def save_json_report(report: dict[str, Any], output_path: str) -> None:
    """Save a report as JSON. Directory paths receive a timestamped filename."""
    path = _resolve_output_path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def print_terminal_report(report: dict[str, Any], no_color: bool = False) -> None:
    """Print a professional terminal summary for a phishing analysis report."""
    try:
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
    except ImportError:
        print(_render_plain_terminal_report(report))
        return

    console = Console(no_color=no_color)
    email = report.get("email", {})
    analysis = report.get("analysis", {})
    risk = analysis.get("risk", {})
    header = analysis.get("header", {})
    body = analysis.get("body", {})
    url = analysis.get("url") or body.get("url_analysis", {})
    attachments = analysis.get("attachments", {})
    risk_score = risk.get("final_score", risk.get("score", 0))
    risk_level = risk.get("risk_level", risk.get("level", "Unknown"))
    level_style = _risk_style(str(risk_level))

    summary = Table.grid(expand=True)
    summary.add_column(justify="left", ratio=1)
    summary.add_column(justify="left", ratio=3)
    summary.add_row("[bold]Subject[/bold]", truncate(str(email.get("subject") or "(empty)"), 100))
    summary.add_row("[bold]From[/bold]", str(email.get("from") or "(unknown)"))
    summary.add_row("[bold]Date[/bold]", str(email.get("date") or "(unknown)"))
    summary.add_row("[bold]Final risk score[/bold]", f"[{level_style}]{risk_score}/100[/{level_style}]")
    summary.add_row("[bold]Risk level[/bold]", f"[{level_style}]{risk_level}[/{level_style}]")

    metrics = Table(title="Analysis Metrics", show_header=True, header_style="bold")
    metrics.add_column("Metric")
    metrics.add_column("Value", justify="right")
    metrics.add_row("Header signals", str(_signal_count(header)))
    metrics.add_row("URL count", str(_url_count(url)))
    metrics.add_row("Suspicious URL count", str(_suspicious_url_count(url)))
    metrics.add_row("Attachment count", str(_attachment_count(attachments)))

    indicators = _top_indicators(analysis)
    recommendations = _list_from(risk.get("recommendations"))

    console.print(Panel(summary, title="Phishing Mail Analysis", border_style=level_style))
    console.print(metrics)
    console.print(_list_panel("Top Suspicious Indicators", indicators or ["No suspicious indicators found"], "yellow"))
    console.print(_list_panel("Recommendations", recommendations, level_style))


class ReportGenerator:
    """Backward-compatible wrapper around module-level report functions."""

    def build_report(self, analysis: dict[str, Any]) -> dict[str, Any]:
        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool": "phishing-mail-analyzer",
            "analysis": _serialize(analysis),
        }

    def write_json(self, report: dict[str, Any], output_path: str | Path) -> Path:
        path = _resolve_output_path(str(output_path))
        save_json_report(report, str(path))
        return path

    def render_summary(self, report: dict[str, Any]) -> str:
        return _render_plain_terminal_report(report)


def _serialize(value: Any) -> Any:
    if is_dataclass(value):
        return _serialize(asdict(value))
    if isinstance(value, dict):
        return {key: _serialize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    return value


def _parsed_email_summary(parsed_email: Any) -> dict[str, Any]:
    if isinstance(parsed_email, dict):
        return _serialize(parsed_email)
    return {
        "path": getattr(parsed_email, "path", ""),
        "sha256": getattr(parsed_email, "sha256", ""),
        "headers": getattr(parsed_email, "headers", {}),
        "subject": getattr(parsed_email, "subject", ""),
        "from_addresses": getattr(parsed_email, "from_addresses", []),
        "to_addresses": getattr(parsed_email, "to_addresses", []),
    }


def _headers_from_parsed(parsed: dict[str, Any]) -> dict[str, Any]:
    headers = parsed.get("headers", {})
    return headers if isinstance(headers, dict) else {}


def _first_header_value(headers: dict[str, Any], name: str) -> str:
    value = headers.get(name) or headers.get(name.lower()) or ""
    if isinstance(value, list):
        return str(value[0]) if value else ""
    return str(value)


def _resolve_output_path(output_path: str) -> Path:
    path = Path(output_path or DEFAULT_REPORT_DIR).expanduser()
    if path.suffix.lower() != ".json":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = path / f"phishing_report_{timestamp}.json"
    return path.resolve()


def _render_plain_terminal_report(report: dict[str, Any]) -> str:
    email = report.get("email", {})
    analysis = report.get("analysis", {})
    risk = analysis.get("risk", {})
    header = analysis.get("header", {})
    body = analysis.get("body", {})
    url = analysis.get("url") or body.get("url_analysis", {})
    attachments = analysis.get("attachments", {})
    risk_score = risk.get("final_score", risk.get("score", 0))
    risk_level = risk.get("risk_level", risk.get("level", "Unknown"))

    lines = [
        "Phishing Mail Analysis Report",
        "=" * 36,
        f"Subject              : {truncate(str(email.get('subject') or '(empty)'), 100)}",
        f"From                 : {email.get('from') or '(unknown)'}",
        f"Date                 : {email.get('date') or '(unknown)'}",
        f"Final risk score     : {risk_score}/100",
        f"Risk level           : {risk_level}",
        f"Header signals count : {_signal_count(header)}",
        f"URL count            : {_url_count(url)}",
        f"Suspicious URL count : {_suspicious_url_count(url)}",
        f"Attachment count     : {_attachment_count(attachments)}",
        "",
        "Top Suspicious Indicators:",
    ]
    lines.extend(f"- {truncate(indicator, 120)}" for indicator in (_top_indicators(analysis) or ["No suspicious indicators found"]))
    lines.extend(["", "Recommendations:"])
    lines.extend(f"- {item}" for item in _list_from(risk.get("recommendations")))
    return "\n".join(lines)


def _signal_count(section: dict[str, Any]) -> int:
    signals = section.get("signals")
    if isinstance(signals, list):
        return len(signals)
    indicators = section.get("indicators")
    if isinstance(indicators, list):
        return len(indicators)
    findings = section.get("findings")
    return len(findings) if isinstance(findings, list) else 0


def _url_count(url_result: dict[str, Any]) -> int:
    if "total_urls" in url_result:
        return int(url_result.get("total_urls") or 0)
    urls = url_result.get("urls", [])
    return len(urls) if isinstance(urls, list) else 0


def _suspicious_url_count(url_result: dict[str, Any]) -> int:
    urls = url_result.get("urls", [])
    if not isinstance(urls, list):
        return 0
    return sum(1 for item in urls if item.get("risk_score", 0) > 0 or item.get("signals") or item.get("risk_flags"))


def _attachment_count(attachment_result: dict[str, Any]) -> int:
    if "total_attachments" in attachment_result:
        return int(attachment_result.get("total_attachments") or 0)
    attachments = attachment_result.get("attachments", [])
    return len(attachments) if isinstance(attachments, list) else 0


def _top_indicators(analysis: dict[str, Any], limit: int = 8) -> list[str]:
    findings = _list_from(analysis.get("findings"))
    if findings:
        return findings[:limit]

    indicators: list[str] = []
    for key in ("header", "url", "body", "attachments"):
        section = analysis.get(key, {})
        indicators.extend(_list_from(section.get("findings")))
        indicators.extend(signal.get("description", signal.get("name", "")) for signal in _list_from(section.get("signals")))
    return [item for item in indicators if item][:limit]


def _list_from(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _risk_style(level: str) -> str:
    return {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "green",
    }.get(level.lower(), "white")


def _list_panel(title: str, items: list[str], style: str) -> Any:
    from rich.panel import Panel

    text = "\n".join(f"- {truncate(str(item), 120)}" for item in items)
    return Panel(text or "-", title=title, border_style=style)
