class E5Embedding:
    def __init__(self, model_name, revision="", *, local_files_only=False):
        from sentence_transformers import SentenceTransformer
        kwargs = {"revision": revision} if revision else {}
        self.model = SentenceTransformer(model_name, device="cpu",
                                         local_files_only=local_files_only, **kwargs)

    def encode(self, texts, *, query=False):
        import numpy as np
        if not texts or any(not isinstance(t, str) or not t.strip() for t in texts):
            raise ValueError("Embedding inputs must be nonempty text")
        prefix = "query: " if query else "passage: "
        inputs = [prefix + t for t in texts]
        # Prevent silently discarding evidence from oversized chunks/queries.
        for item in inputs:
            tokens = self.model.tokenizer(item, truncation=False)["input_ids"]
            if len(tokens) > self.model.max_seq_length:
                raise ValueError("Embedding input exceeds model limit; reduce chunk size/query")
        vectors = self.model.encode(inputs, normalize_embeddings=True, convert_to_numpy=True,
                                    prompt="", show_progress_bar=False)
        return np.asarray(vectors, dtype=np.float32)

    def embed_documents(self, texts):
        return self.encode(texts, query=False)

    def embed_query(self, text):
        return self.encode([text], query=True)[0]
