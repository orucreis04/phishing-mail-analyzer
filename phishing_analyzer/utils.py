"""Shared helpers for phishing mail analysis."""

from __future__ import annotations

import hashlib
import re
from email.utils import parseaddr
from pathlib import Path
from urllib.parse import urlparse


URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
MESSAGE_ID_DOMAIN_RE = re.compile(r"@([^>\s]+)")


def sha256_file(path: Path) -> str:
    """Return SHA-256 hash for a file."""
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def normalize_domain(value: str | None) -> str:
    """Extract and normalize a domain-like value."""
    if not value:
        return ""
    value = value.strip().lower().strip("<>[]()\"' ")
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    value = value.rstrip(".")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    return value if is_valid_domain(value) else ""


def is_valid_domain(domain: str) -> bool:
    """Return True when a value is a conservative DNS-style domain."""
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(DOMAIN_LABEL_RE.fullmatch(label) for label in labels)


def extract_domain_from_email_header(value: str | None) -> str:
    """Extract a domain from an RFC 5322 mailbox header."""
    _, address = parseaddr(value or "")
    return normalize_domain(address)


def extract_domain_from_message_id(value: str | None) -> str:
    """Extract the right-hand domain from a Message-ID header."""
    if not value:
        return ""
    match = MESSAGE_ID_DOMAIN_RE.search(value.strip())
    if not match:
        return ""
    return normalize_domain(match.group(1))


def get_url_domain(url: str) -> str:
    """Return the hostname for a URL."""
    parsed = urlparse(url)
    return (parsed.hostname or "").lower().strip(".")


def truncate(value: str, max_length: int = 120) -> str:
    """Trim long text for terminal output."""
    if len(value) <= max_length:
        return value
    return f"{value[: max_length - 3]}..."
