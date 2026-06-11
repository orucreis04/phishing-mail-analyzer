"""EML parsing primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from .utils import sha256_file


HEADER_FIELDS = (
    "Subject",
    "From",
    "To",
    "Date",
    "Message-ID",
    "Return-Path",
    "Reply-To",
)


class EmailParseError(RuntimeError):
    """Raised when an .eml file cannot be parsed safely."""


@dataclass(slots=True)
class AttachmentInfo:
    filename: str
    content_type: str
    size_bytes: int
    content_disposition: str


@dataclass(slots=True)
class ParsedEmail:
    path: Path
    sha256: str
    message: EmailMessage | Message
    headers: dict[str, Any]
    from_addresses: list[str]
    to_addresses: list[str]
    subject: str
    plain_text: str
    html_text: str
    attachments: list[AttachmentInfo] = field(default_factory=list)


class EmailParser:
    """Parse .eml files into normalized data structures."""

    def parse(self, eml_path: str | Path) -> ParsedEmail:
        path, message = _load_message(eml_path)
        plain_text, html_text, attachments = _extract_parts(message)

        return ParsedEmail(
            path=path,
            sha256=sha256_file(path),
            message=message,
            headers=_message_headers(message),
            from_addresses=[addr for _, addr in getaddresses(message.get_all("from", []))],
            to_addresses=[addr for _, addr in getaddresses(message.get_all("to", []))],
            subject=str(message.get("subject", "")),
            plain_text=plain_text,
            html_text=html_text,
            attachments=attachments,
        )


def parse_email(file_path: str | Path) -> dict[str, Any]:
    """Parse an .eml file and return headers, bodies, and attachment metadata.

    Raises:
        EmailParseError: when the file cannot be read as a usable .eml message.
    """
    _, message = _load_message(file_path)
    plain_body, html_body, attachments = _extract_parts(message)

    return {
        "headers": {field: str(message.get(field, "")) for field in HEADER_FIELDS},
        "plain_body": plain_body,
        "html_body": html_body,
        "attachments": [
            {
                "filename": attachment.filename,
                "content_type": attachment.content_type,
                "size_bytes": attachment.size_bytes,
            }
            for attachment in attachments
        ],
    }


def _load_message(file_path: str | Path) -> tuple[Path, EmailMessage | Message]:
    path = Path(file_path).expanduser().resolve()
    if not path.exists():
        raise EmailParseError(f"EML file not found: {path}")
    if not path.is_file():
        raise EmailParseError(f"Path is not a file: {path}")
    if path.suffix.lower() != ".eml":
        raise EmailParseError("Input file must have a .eml extension")
    if path.stat().st_size == 0:
        raise EmailParseError(f"EML file is empty: {path}")

    try:
        with path.open("rb") as file_obj:
            message = BytesParser(policy=policy.default).parse(file_obj)
    except OSError as exc:
        raise EmailParseError(f"EML file could not be read: {path}") from exc
    except Exception as exc:
        raise EmailParseError(f"EML file could not be parsed: {path}") from exc

    if not message.items() and not message.get_payload():
        raise EmailParseError(f"EML file does not contain a usable email message: {path}")

    defects = _collect_defects(message)
    if defects:
        defect_names = ", ".join(defect.__class__.__name__ for defect in defects[:3])
        raise EmailParseError(f"Malformed EML structure detected: {defect_names}")

    return path, message


def _extract_parts(message: EmailMessage | Message) -> tuple[str, str, list[AttachmentInfo]]:
    plain_parts: list[str] = []
    html_parts: list[str] = []
    attachments: list[AttachmentInfo] = []

    for part in message.walk():
        if part.is_multipart():
            continue

        content_disposition = part.get_content_disposition() or ""
        content_type = part.get_content_type()
        filename = part.get_filename()

        if content_disposition == "attachment" or filename:
            payload = part.get_payload(decode=True) or b""
            attachments.append(
                AttachmentInfo(
                    filename=filename or "unnamed",
                    content_type=content_type,
                    size_bytes=len(payload),
                    content_disposition=content_disposition,
                )
            )
            continue

        if content_type == "text/plain":
            plain_parts.append(_safe_get_content(part))
        elif content_type == "text/html":
            html_parts.append(_safe_get_content(part))

    return "\n".join(plain_parts).strip(), "\n".join(html_parts).strip(), attachments


def _message_headers(message: EmailMessage | Message) -> dict[str, str | list[str]]:
    headers: dict[str, str | list[str]] = {}
    for key, value in message.items():
        value_text = str(value)
        if key not in headers:
            headers[key] = value_text
            continue
        existing = headers[key]
        if isinstance(existing, list):
            existing.append(value_text)
        else:
            headers[key] = [existing, value_text]
    return headers


def _safe_get_content(part: Message) -> str:
    try:
        return str(part.get_content())
    except Exception:
        payload = part.get_payload(decode=True) or b""
        return payload.decode(errors="replace")


def _collect_defects(message: EmailMessage | Message) -> list[Exception]:
    defects: list[Exception] = list(getattr(message, "defects", []))
    for part in message.walk():
        if part is message:
            continue
        defects.extend(getattr(part, "defects", []))
    return defects
