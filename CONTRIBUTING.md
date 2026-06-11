# Contributing

Thank you for your interest in contributing to `phishing-mail-analyzer`.

## Code Standards

- Use Python 3.11+.
- Keep modules small, readable, and focused on one responsibility.
- Prefer deterministic static analysis logic over network-dependent behavior.
- Do not execute attachment content or fetch suspicious URLs during analysis.
- Use clear function names, type hints, and concise comments where they add value.
- Keep CLI output professional and suitable for SOC / Blue Team workflows.

## Running Tests and Checks

Create a virtual environment and install dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Run the basic syntax check:

```bash
python3 -m compileall .
```

Run the sample analysis:

```bash
python main.py analyze samples/sample_phishing.eml --no-color
```

If tests are added later, run them before opening a pull request:

```bash
python -m pytest
```

## Pull Request Process

1. Create a focused branch for your change.
2. Keep commits small and descriptive.
3. Update documentation when behavior, CLI options, reports, or scoring logic changes.
4. Include sample output or screenshots when changing terminal reporting.
5. Confirm that the included safe sample still analyzes successfully.
6. Open a pull request with a clear summary, rationale, and validation steps.

## Security Issue Reporting

Do not open public issues for security-sensitive findings.

If you discover a vulnerability, unsafe behavior, or a way the tool could mishandle malicious samples, report it privately to the project maintainer first. Include a minimal reproduction, affected version or commit, and recommended mitigation if available.

This project is intended for defensive security analysis only.
