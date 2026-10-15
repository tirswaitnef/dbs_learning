from .top10 import allowed, finding_cwes

def retrieve(finding, cards, *, store=None, top_k=4, min_score=0.75):
    """CWE is a conservative gate, not a semantic correctness guarantee.

    In demo mode return curated CWE matches, explicitly without embeddings.
    A card is eligible if its CWE is one of the CWEs supplied by the input; several
    CWEs only get here when the Top 10 gate found them all in one category.
    """
    if not allowed(finding):
        return []
    cwes = finding_cwes(finding)
    eligible = {c.id: c for c in cards if c.approved and c.cwe in cwes}
    if not eligible or not finding.evidence or finding.kind == "observation":
        return []
    if store is None:
        return [{"card_id": id_, "score": None, "method": "demo-cwe-map"}
                for id_ in sorted(eligible)[:top_k]]
    scores = {}
    for id_, score in store.scores(f"{' '.join(cwes)} {finding.title}"):
        if id_ in eligible and score >= min_score:
            scores[id_] = max(scores.get(id_, -1), score)
    return [{"card_id": k, "score": v, "method": "e5-cosine+cwe"}
            for k, v in sorted(scores.items(), key=lambda item: (-item[1], item[0]))[:top_k]]
