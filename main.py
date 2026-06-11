#!/usr/bin/env python3
"""Professional CLI entrypoint for phishing-mail-analyzer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from phishing_analyzer import __version__
from phishing_analyzer.parser import EmailParseError


DEFAULT_REPORT_DIR = "reports"


def analyze_email(eml_path: str | Path, output_path: str | Path | None = None) -> tuple[dict[str, Any], Path]:
    """Run the complete phishing analysis pipeline and save a JSON report."""
    from phishing_analyzer.parser import EmailParser

    parsed_email = EmailParser().parse(eml_path)

    from phishing_analyzer.attachment_analyzer import AttachmentAnalyzer
    from phishing_analyzer.body_analyzer import BodyAnalyzer
    from phishing_analyzer.header_analyzer import HeaderAnalyzer
    from phishing_analyzer.report_generator import generate_report, save_json_report
    from phishing_analyzer.risk_engine import RiskEngine, calculate_final_risk

    header_result = HeaderAnalyzer().analyze(parsed_email)
    body_result = BodyAnalyzer().analyze(parsed_email.plain_text, parsed_email.html_text)
    url_result = body_result.url_analysis
    attachment_result = AttachmentAnalyzer().analyze(parsed_email.attachments)

    header_score_result = RiskEngine().calculate(header_result.indicators)
    risk_result = calculate_final_risk(
        header_score_result,
        url_result,
        body_result,
        attachment_result,
    )

    report = generate_report(
        parsed_email,
        header_result,
        url_result,
        body_result,
        attachment_result,
        risk_result,
    )

    target = Path(output_path or DEFAULT_REPORT_DIR).expanduser()
    save_json_report(report, str(target))
    written_path = _latest_report_path(target)
    return report, written_path


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="phishing-mail-analyzer",
        description="Analyze .eml files for phishing indicators and generate security reports.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Analyze an .eml file",
        description="Parse and analyze an .eml file for phishing indicators.",
    )
    analyze_parser.add_argument("eml_file", help="Path to the .eml file to analyze")
    analyze_parser.add_argument(
        "--json",
        action="store_true",
        help="Print the full JSON report to stdout instead of the terminal summary.",
    )
    analyze_parser.add_argument(
        "--output",
        default=None,
        help="JSON output file or directory. Default: reports/phishing_report_<timestamp>.json",
    )
    analyze_parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored terminal output.",
    )
    analyze_parser.set_defaults(handler=handle_analyze)

    version_parser = subparsers.add_parser("version", help="Show tool version")
    version_parser.set_defaults(handler=handle_version)

    return parser


def handle_analyze(args: argparse.Namespace) -> int:
    try:
        report, written_path = analyze_email(args.eml_file, args.output)
    except ModuleNotFoundError as exc:
        missing = exc.name or "required package"
        print(
            f"Error: Missing dependency '{missing}'. Run: pip install -r requirements.txt",
            file=sys.stderr,
        )
        return 3
    except EmailParseError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Error: Analysis interrupted by user.", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"Error: Analysis failed unexpectedly: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        from phishing_analyzer.report_generator import print_terminal_report

        print_terminal_report(report, no_color=args.no_color)
        print(f"\nJSON report written to: {written_path}")

    return 0


def handle_version(_: argparse.Namespace) -> int:
    print(f"phishing-mail-analyzer {__version__}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


def _latest_report_path(target: Path) -> Path:
    resolved = target.expanduser().resolve()
    if resolved.suffix.lower() == ".json":
        return resolved
    reports = sorted(resolved.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not reports:
        raise FileNotFoundError(f"JSON report was not created in {resolved}")
    return reports[0]


if __name__ == "__main__":
    raise SystemExit(main())
