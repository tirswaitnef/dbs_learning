import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    embed_model: str = "intfloat/multilingual-e5-small"
    embed_revision: str = ""
    chunk_size: int = 800
    chunk_overlap: int = 120
    top_k: int = 4
    min_score: float = 0.75
    api_key: str = ""
    chat_model: str = ""

    def __post_init__(self):
        if not 0 <= self.chunk_overlap < self.chunk_size:
            raise ValueError("Require 0 <= chunk overlap < chunk size")
        if self.top_k < 1 or not -1 <= self.min_score <= 1:
            raise ValueError("Invalid top_k or min_score")


def load_settings():
    if (ROOT / ".env").exists():
        try:
            from dotenv import load_dotenv
        except ImportError as exc:
            raise RuntimeError("Install requirements.txt to read .env") from exc
        load_dotenv(ROOT / ".env", override=False)
    return Settings(
        embed_model=os.getenv("EMBED_MODEL", Settings.embed_model),
        embed_revision=os.getenv("EMBED_REVISION", ""),
        chunk_size=int(os.getenv("RAG_CHUNK_SIZE", "800")),
        chunk_overlap=int(os.getenv("RAG_CHUNK_OVERLAP", "120")),
        top_k=int(os.getenv("RAG_TOP_K", "4")),
        min_score=float(os.getenv("RAG_MIN_SCORE", "0.75")),
        api_key=os.getenv("GEMINI_API_KEY", ""),
        chat_model=os.getenv("GEMINI_CHAT_MODEL", ""),
    )
