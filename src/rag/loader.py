import json
import hashlib
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

from .schemas import Card, Document

_TEXT_SUFFIXES = {".txt", ".md", ".markdown"}


def load_cards(path):
    """Only locally reviewed cards can become remediation; this is a trust boundary.

    'approved' is a human-maintained review flag, not an OWASP certification.
    """
    rows = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(rows, list) or not rows:
        raise ValueError("Knowledge file must be a nonempty JSON list")
    cards, ids = [], set()
    for row in rows:
        card = Card(**row)
        for name, value in row.items():
            if name != "approved" and (not isinstance(value, str) or not value.strip()):
                raise ValueError(f"Invalid card field: {name}")
        if type(card.approved) is not bool:
            raise ValueError("approved must be boolean")
        url = urlparse(card.url)
        host = url.hostname or ""
        if (url.scheme != "https" or url.username or url.password
                or not (host == "owasp.org" or host.endswith(".owasp.org"))):
            raise ValueError("Knowledge source must use an official OWASP HTTPS URL")
        if not re.fullmatch(r"CWE-\d+", card.cwe):
            raise ValueError("Card requires a specific CWE")
        date.fromisoformat(card.reviewed_on)
        if card.id in ids:
            raise ValueError("Duplicate knowledge ID")
        ids.add(card.id)
        cards.append(card)
    return cards


def load_document(path):
    """Helper for future corpus expansion. Importing text does NOT approve guidance."""
    path = Path(path)
    if path.suffix.lower() in _TEXT_SUFFIXES:
        return path.read_text(encoding="utf-8-sig")
    if path.suffix.lower() == ".pdf":
        from pypdf import PdfReader
        return "\n\n".join(page.extract_text() or "" for page in PdfReader(path).pages)
    raise ValueError("Supported documents: .md, .markdown, .txt, .pdf")


@dataclass
class LoadResult:
    documents: list[Document]
    skipped: list[dict]


def load_documents(directory):
    """Recursively load a corpus. Empty/unsupported files are reported and skipped.

    Invalid text, corrupt PDFs and invalid metadata fail explicitly. Metadata is
    descriptive provenance only; it never grants approval to generate remediation.
    """
    root = Path(directory).resolve()
    if not root.is_dir():
        raise ValueError(f"Not a document directory: {root}")
    documents, skipped = [], []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        source = path.relative_to(root).as_posix()
        if not path.resolve().is_relative_to(root):
            skipped.append({"source": source, "reason": "outside corpus directory"})
            continue
        if path.name.endswith(".meta.json"):
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES | {".pdf"}:
            skipped.append({"source": source, "reason": "unsupported format"})
            continue
        if path.stat().st_size == 0:
            skipped.append({"source": source, "reason": "empty file"})
            continue
        try:
            text = load_document(path)
        except Exception as exc:
            raise ValueError(f"Cannot read {source}: {type(exc).__name__}: {exc}") from exc
        if not text.strip():
            reason = "no extractable text (OCR not included)" if path.suffix.lower() == ".pdf" else "empty text"
            skipped.append({"source": source, "reason": reason})
            continue
        metadata_path = path.with_name(path.name + ".meta.json")
        metadata = {}
        if metadata_path.exists():
            if not metadata_path.resolve().is_relative_to(root):
                raise ValueError(f"Metadata outside corpus: {source}")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8-sig"))
            if not isinstance(metadata, dict):
                raise ValueError(f"Metadata must be an object: {source}")
        documents.append(Document(source, text, hashlib.sha256(path.read_bytes()).hexdigest(), metadata))
    return LoadResult(documents, skipped)
