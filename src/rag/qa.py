"""Episode 04. Citation integrity checks are NOT semantic entailment verification."""
import json
import re
from dataclasses import asdict, dataclass, field

from .context import build_context, build_prompt
from .llm import GeminiLLM, OllamaLLM
from .prompts import ANSWER_SCHEMA, SYSTEM_PROMPT

NOT_FOUND = "Tôi không tìm thấy đủ thông tin để trả lời trong các đoạn tài liệu được cung cấp."
_CJK = re.compile(r"[\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af]")


def _quote_matches(quote, chunk_text):
    if quote in chunk_text:
        return True
    norm_q = re.sub(r"\s+", " ", quote).strip()
    norm_c = re.sub(r"\s+", " ", chunk_text)
    return bool(norm_q) and norm_q in norm_c


@dataclass
class RAGAnswer:
    status: str
    answer: str
    sources: list
    retrieved_sources: list
    statements: list = field(default_factory=list)
    generation_calls: int = 0
    grounding_check: str = "citation IDs and exact quote membership only; semantic support not verified"

    def to_dict(self):
        return asdict(self)


def validate_answer(data, sources):
    if not isinstance(data, dict) or set(data) != {"status", "statements"}:
        raise ValueError("Invalid answer schema")
    if not isinstance(data["statements"], list):
        raise ValueError("statements must be a list")
    if data["status"] == "insufficient_context":
        if data["statements"]:
            raise ValueError("Abstention must not contain claims")
        return []
    if data["status"] != "answered" or not 1 <= len(data["statements"]) <= 20:
        raise ValueError("Invalid status or statement count")
    source_map = {s["source_id"]: s for s in sources}
    used = []
    for statement in data["statements"]:
        if not isinstance(statement, dict) or set(statement) != {"text", "citations"}:
            raise ValueError("Invalid statement")
        text = statement["text"]
        if not isinstance(text, str) or not text.strip() or len(text) > 3000 or _CJK.search(text):
            raise ValueError("Invalid statement text")
        if re.search(r"https?://|www\.|\[nguồn\s*:|\[S\d+\]", text, re.I):
            raise ValueError("Model must use structured citations, not invent inline sources")
        citations = statement["citations"]
        if not isinstance(citations, list) or not 1 <= len(citations) <= len(sources):
            raise ValueError("Every statement needs citations")
        cited = set()
        for citation in citations:
            if not isinstance(citation, dict) or set(citation) != {"source_id", "quote"}:
                raise ValueError("Invalid citation")
            id_, quote = citation["source_id"], citation["quote"]
            if not isinstance(id_, str) or id_ not in source_map or id_ in cited:
                raise ValueError("Unknown/duplicate source ID")
            if not isinstance(quote, str) or len(quote.strip()) < 12 or not _quote_matches(quote, source_map[id_]["text"]):
                raise ValueError("Quote not found verbatim in cited chunk")
            cited.add(id_)
            if id_ not in used:
                used.append(id_)
    return [source_map[id_] for id_ in used]


def answer_from_results(question, results, settings, *, llm=None, max_context_chars=12000):
    if not isinstance(question, str) or not question.strip() or len(question) > 4000:
        raise ValueError("Question must contain 1–4000 characters")
    sources = build_context(results, max_context_chars)
    if not sources:
        return RAGAnswer("insufficient_context", NOT_FOUND, [], sources)
    if llm is not None:
        model = llm
    elif settings.resolved_provider == "ollama":
        model = OllamaLLM(settings)
    else:
        model = GeminiLLM(settings)
    raw = model.generate(build_prompt(question, sources), system=SYSTEM_PROMPT, schema=ANSWER_SCHEMA)
    try:
        data = json.loads(raw)
        used_sources = validate_answer(data, sources)
    except (ValueError, TypeError, KeyError):
        # Never render unsupported model output or mislabel it as an evidence absence.
        return RAGAnswer("rejected_output",
                         "Câu trả lời không vượt qua kiểm tra cấu trúc/trích nguồn nên chưa được hiển thị.",
                         [], sources, generation_calls=1)
    if data["status"] == "insufficient_context":
        return RAGAnswer("insufficient_context", NOT_FOUND, [], sources, generation_calls=1)
    rendered = []
    for item in data["statements"]:
        ids = " ".join(f"[{c['source_id']}]" for c in item["citations"])
        rendered.append(f"{item['text'].strip()} {ids}")
    return RAGAnswer("answered", "\n\n".join(rendered), used_sources, sources,
                     statements=data["statements"], generation_calls=1)


class RAGPipeline:
    def __init__(self, settings, store_directory, raw_directory, *, llm=None):
        self.settings = settings
        self.store_directory = store_directory
        self.raw_directory = raw_directory
        self.llm = llm

    def answer(self, question, *, top_k=None, min_score=None, offline_embeddings=False):
        # Lazy import keeps citation/abstention tests independent of NumPy/E5.
        from .document_store import retrieve_documents
        results = retrieve_documents(question, self.store_directory, self.raw_directory,
                                     self.settings, top_k=top_k, min_score=min_score,
                                     offline=offline_embeddings)
        return answer_from_results(question, results, self.settings, llm=self.llm)
