def fits_token_limit(encoder, text, *, query=False):
    model = getattr(encoder, "model", None)
    max_len = getattr(model, "max_seq_length", None)
    tokenizer = getattr(model, "tokenizer", None)
    if model is None or max_len is None or tokenizer is None:
        return True
    prefix = "query: " if query else "passage: "
    return len(tokenizer(prefix + text, truncation=False, verbose=False)["input_ids"]) <= max_len


def split_spans_for_encoder(text, start, end, encoder, *, overlap=120, query=False):
    segment = text[start:end]
    if not segment.strip():
        return []
    span = end - start
    if fits_token_limit(encoder, segment, query=query) or span <= 1:
        return [(start, end)]
    step_overlap = min(max(0, overlap), span // 4)
    left_end = start + (span + step_overlap) // 2
    right_start = left_end - step_overlap
    return (split_spans_for_encoder(text, start, left_end, encoder, overlap=overlap, query=query)
            + split_spans_for_encoder(text, right_start, end, encoder, overlap=overlap, query=query))


def embed_query_safe(encoder, text, *, overlap=64):
    import numpy as np
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Embedding inputs must be nonempty text")
    if fits_token_limit(encoder, text, query=True):
        return encoder.embed_query(text)
    spans = split_spans_for_encoder(text, 0, len(text), encoder, overlap=overlap, query=True)
    windows = [text[s:e] for s, e in spans if text[s:e].strip()]
    vectors = np.asarray([encoder.embed_query(w) for w in windows], dtype=np.float32)
    pooled = vectors.mean(axis=0)
    norm = float(np.linalg.norm(pooled))
    if not np.isfinite(norm) or norm == 0.0:
        raise ValueError("Cannot normalize zero/invalid query vector")
    return np.asarray(pooled / norm, dtype=np.float32)


class E5Embedding:
    def __init__(self, model_name, revision="", *, local_files_only=False):
        from sentence_transformers import SentenceTransformer
        kwargs = {"revision": revision} if revision else {}
        try:
            self.model = SentenceTransformer(model_name, device="cpu",
                                             local_files_only=local_files_only, **kwargs)
        except OSError:
            if local_files_only:
                raise
            self.model = SentenceTransformer(model_name, device="cpu",
                                             local_files_only=True, **kwargs)

    def encode(self, texts, *, query=False):
        import numpy as np
        if not texts or any(not isinstance(t, str) or not t.strip() for t in texts):
            raise ValueError("Embedding inputs must be nonempty text")
        prefix = "query: " if query else "passage: "
        inputs = [prefix + t for t in texts]
        # Prevent silently discarding evidence from oversized chunks/queries.
        for item in inputs:
            tokens = self.model.tokenizer(item, truncation=False, verbose=False)["input_ids"]
            if len(tokens) > self.model.max_seq_length:
                raise ValueError("Embedding input exceeds model limit; reduce chunk size/query")
        vectors = self.model.encode(inputs, normalize_embeddings=True, convert_to_numpy=True,
                                    prompt="", show_progress_bar=False)
        return np.asarray(vectors, dtype=np.float32)

    def embed_documents(self, texts):
        return self.encode(texts, query=False)

    def embed_query(self, text):
        return self.encode([text], query=True)[0]
