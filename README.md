# phishing-mail-analyzer

**Python:** 3.11+ | **Platform:** Linux/Fedora | **Lisans:** MIT | **GitHub:** [orucreis04/phishing-mail-analyzer](https://github.com/orucreis04/phishing-mail-analyzer)

## Project Overview

`phishing-mail-analyzer` is a Python 3.11+ CLI tool for static analysis of `.eml` email files. It extracts email headers, body content, URLs, HTML indicators, and attachment metadata, then produces a normalized phishing risk score with both a readable terminal report and a JSON report.

The project is designed as a SOC / Blue Team portfolio tool: modular, testable, Linux-friendly, and focused on safe static analysis workflows.

## Features

- Parse `.eml` email files with Python's standard `email` library
- Extract Subject, From, To, Date, Message-ID, Return-Path, and Reply-To
- Analyze sender domain mismatches across From, Return-Path, Reply-To, and Message-ID
- Check SPF, DKIM, and DMARC results from `Authentication-Results`
- Parse Received header chains
- Extract URLs from plain text and HTML bodies
- Analyze suspicious URLs, URL shorteners, IP-based links, punycode domains, and link text mismatches
- Detect phishing language, urgency, credential requests, financial terms, threat language, and brand impersonation
- Detect HTML forms, scripts, and hidden content
- Analyze attachment metadata without executing or opening file content
- Generate weighted final risk scoring from header, URL, body, and attachment results
- Save timestamped JSON reports under `reports/`
- Print professional terminal summaries with optional color output

## Architecture

The analyzer follows a staged static-analysis pipeline:

1. `parser.py` reads and normalizes the `.eml` file.
2. `header_analyzer.py` evaluates sender identity and authentication signals.
3. `url_analyzer.py` extracts and scores URLs from text and HTML.
4. `body_analyzer.py` evaluates social-engineering and HTML indicators.
5. `attachment_analyzer.py` evaluates attachment metadata.
6. `risk_engine.py` combines component scores into a final phishing risk score.
7. `report_generator.py` writes JSON output and renders the terminal report.
8. `main.py` exposes the workflow through a professional CLI.

## Folder Structure

```text
phishing-mail-analyzer/
├── main.py
├── requirements.txt
├── README.md
├── samples/
│   └── sample_phishing.eml
├── reports/
├── phishing_analyzer/
│   ├── __init__.py
│   ├── parser.py
│   ├── header_analyzer.py
│   ├── body_analyzer.py
│   ├── url_analyzer.py
│   ├── attachment_analyzer.py
│   ├── risk_engine.py
│   ├── report_generator.py
│   └── utils.py
```

## Installation on Fedora/Linux

Install Python tooling if needed:

```bash
sudo dnf install -y python3 python3-pip python3-virtualenv
```

Create a virtual environment and install dependencies:

```bash
cd phishing-mail-analyzer
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python main.py analyze samples/sample_phishing.eml
```

## Usage

The CLI provides two commands:

```bash
python main.py analyze <email.eml>
python main.py version
```

Analyze an email and write a timestamped JSON report to `reports/`:

```bash
python main.py analyze samples/sample_phishing.eml
```

Print the full JSON report to stdout:

```bash
python main.py analyze samples/sample_phishing.eml --json
```

Write the JSON report to a specific path:

```bash
python main.py analyze samples/sample_phishing.eml --output reports/report.json
```

Disable colored terminal output:

```bash
python main.py analyze samples/sample_phishing.eml --no-color
```

## Example Commands

```bash
# Show CLI help
python main.py --help

# Show analyzer command help
python main.py analyze --help

# Analyze the included safe sample
python main.py analyze samples/sample_phishing.eml

# Save a report to a fixed file path
python main.py analyze samples/sample_phishing.eml --output reports/sample_report.json

# Generate machine-readable output
python main.py analyze samples/sample_phishing.eml --json

# Check the version
python main.py version
```

## Sample Output

Example terminal summary:

```text
Phishing Mail Analysis
Subject            Urgent action required: Account suspended - verify now
From               PayPal Security <support@paypal-security.example>
Date               Thu, 11 Jun 2026 13:45:00 +0000
Final risk score   79/100
Risk level         Critical

Analysis Metrics
Header signals       6
URL count            3
Suspicious URL count 3
Attachment count     1

Top Suspicious Indicators
- SPF authentication result is fail
- DKIM authentication result is fail
- DMARC authentication result is fail
- From domain and Return-Path domain do not match
- Suspicious URL signal 'ip_address_host' on 192.0.2.10

Recommendations
- Do not open links or attachments. Report to security team.
```

JSON reports include metadata, parsed email fields, component analysis results, final risk scoring, and recommendations.

## Risk Scoring Model

The final risk score is normalized to `0-100` and combines component scores with these weights:

- Header analysis: `30%`
- URL analysis: `35%`
- Body analysis: `20%`
- Attachment analysis: `15%`

Risk levels:

```text
0-24   Low
25-49  Medium
50-74  High
75-100 Critical
```

Recommendations are generated from the final risk level:

- Critical: Do not open links or attachments. Report to security team.
- High: Verify sender identity through another channel.
- Medium: Review suspicious indicators before interacting.
- Low: No major phishing indicators found, but remain cautious.

## Security Notes

- This tool performs static analysis only.
- It does not execute attachments.
- It does not submit URLs to external services.
- It does not perform active credential collection.
- The included `samples/sample_phishing.eml` file is a safe, fake phishing sample for testing analyzer behavior.
- The sample intentionally contains suspicious-looking headers, links, HTML form markup, hidden text, and attachment metadata, but it does not contain real malware or a working phishing payload.

## Roadmap

- Add unit tests for all analyzer modules
- Add CSV and SARIF export options
- Add optional DNS-based SPF/DMARC enrichment
- Add IOC extraction for SOC workflows
- Add YARA-compatible attachment metadata tagging
- Add configurable scoring profiles
- Add CI workflow for linting and tests
- Add packaged console entry point

## Disclaimer

`phishing-mail-analyzer` is intended for defensive security education, SOC portfolio work, and internal Blue Team analysis workflows. It is not a replacement for a secure email gateway, EDR, sandbox, or full incident response process. Always handle suspicious email samples in a controlled environment and follow your organization's security procedures.
