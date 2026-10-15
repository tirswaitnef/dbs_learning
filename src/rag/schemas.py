import hashlib
import json
from dataclasses import asdict, dataclass
from dataclasses import field


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=False).encode()).hexdigest()


@dataclass(frozen=True)
class Finding:
    id: str
    title: str
    cwe: str
    severity: str
    location: str
    evidence: tuple[str, ...]
    tool: str
    source_ref: str
    kind: str = "scanner_alert"
    details: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Card:
    id: str
    cwe: str
    title: str
    section: str
    url: str
    reviewed_on: str
    reviewed_by: str
    approved: bool
    source_excerpt: str
    guidance_vi: str
    applicability_vi: str

    def text(self):
        return "\n".join((self.title, self.section, self.cwe, self.source_excerpt,
                          self.guidance_vi, self.applicability_vi))


def card_digest(cards):
    return digest([asdict(c) for c in cards])


@dataclass(frozen=True)
class Document:
    """One file; source is a path relative to the selected corpus directory."""
    source: str
    text: str
    source_sha256: str = ""
    metadata: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Chunk:
    source: str
    index: int
    start: int
    end: int
    text: str
    source_sha256: str
    metadata: dict = field(default_factory=dict)
