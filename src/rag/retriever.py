from .top10 import allowed

def retrieve(finding, cards, *, store=None, top_k=4, min_score=0.75):
    """CWE is a conservative gate, not a semantic correctness guarantee.

    In demo mode return curated CWE matches, explicitly without embeddings.
    """
    if not allowed(finding):
        return []
    eligible = {c.id: c for c in cards if c.approved and c.cwe == finding.cwe}
    if not eligible or not finding.evidence or finding.kind == "observation":
        return []
    if store is None:
        return [{"card_id": id_, "score": None, "method": "demo-cwe-map"}
                for id_ in sorted(eligible)[:top_k]]
    scores = {}
    for id_, score in store.scores(f"{finding.cwe} {finding.title}"):
        if id_ in eligible and score >= min_score:
            scores[id_] = max(scores.get(id_, -1), score)
    return [{"card_id": k, "score": v, "method": "e5-cosine+cwe"}
            for k, v in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:top_k]]
