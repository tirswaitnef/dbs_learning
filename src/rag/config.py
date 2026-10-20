import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PROVIDERS = {"ollama", "gemini"}


def _read_env_file(path):
    if not path.is_file():
        return {}
    try:
        from dotenv import dotenv_values
        return {k.lstrip("\ufeff"): v for k, v in dotenv_values(path, encoding="utf-8-sig").items()
                if k and v is not None}
    except ImportError:
        values = {}
        for raw in path.read_text(encoding="utf-8-sig").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            values[key.strip()] = val.strip().strip("\"'")
        return values


@dataclass(frozen=True)
class Settings:
    embed_model: str = "intfloat/multilingual-e5-small"
    embed_revision: str = ""
    chunk_size: int = 800
    chunk_overlap: int = 120
    top_k: int = 4
    min_score: float = 0.75
    llm_provider: str = ""
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = ""
    ollama_num_ctx: int = 8192
    ollama_timeout: int = 300
    api_key: str = ""
    chat_model: str = ""

    def __post_init__(self):
        if not 0 <= self.chunk_overlap < self.chunk_size:
            raise ValueError("Require 0 <= chunk overlap < chunk size")
        if self.top_k < 1 or not -1 <= self.min_score <= 1:
            raise ValueError("Invalid top_k or min_score")
        provider = self.llm_provider.strip().lower()
        if provider and provider not in PROVIDERS:
            raise ValueError("LLM_PROVIDER must be 'ollama' or 'gemini'")
        if self.ollama_num_ctx < 1024 or self.ollama_timeout < 5:
            raise ValueError("Invalid OLLAMA_NUM_CTX or OLLAMA_TIMEOUT")

    @property
    def resolved_provider(self) -> str:
        provider = self.llm_provider.strip().lower()
        if provider:
            return provider
        if self.ollama_model.strip():
            return "ollama"
        return "gemini"

    @property
    def active_model(self) -> str:
        return self.ollama_model.strip() if self.resolved_provider == "ollama" else self.chat_model.strip()

    @property
    def model_label(self) -> str:
        if self.resolved_provider == "ollama":
            model = self.ollama_model.strip()
            return f"ollama/{model}" if model else ""
        return self.chat_model.strip()


def load_settings():
    file_env = _read_env_file(ROOT / ".env")

    def env(name, default=""):
        if name in os.environ:
            return os.environ[name]
        return file_env.get(name, default)

    return Settings(
        embed_model=env("EMBED_MODEL", Settings.embed_model) or Settings.embed_model,
        embed_revision=env("EMBED_REVISION", ""),
        chunk_size=int(env("RAG_CHUNK_SIZE", "800") or "800"),
        chunk_overlap=int(env("RAG_CHUNK_OVERLAP", "120") or "120"),
        top_k=int(env("RAG_TOP_K", "4") or "4"),
        min_score=float(env("RAG_MIN_SCORE", "0.75") or "0.75"),
        llm_provider=env("LLM_PROVIDER", ""),
        ollama_base_url=env("OLLAMA_BASE_URL", Settings.ollama_base_url) or Settings.ollama_base_url,
        ollama_model=env("OLLAMA_MODEL", ""),
        ollama_num_ctx=int(env("OLLAMA_NUM_CTX", "8192") or "8192"),
        ollama_timeout=int(env("OLLAMA_TIMEOUT", "300") or "300"),
        api_key=env("GEMINI_API_KEY", ""),
        chat_model=env("GEMINI_CHAT_MODEL", ""),
    )
