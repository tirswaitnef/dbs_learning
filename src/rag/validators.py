from .top10 import allowed as in_top10

def validate_plan(plan, findings, candidates):
    """Reject, never silently fix, AI references outside the supplied evidence."""
    if not isinstance(plan, dict) or set(plan) != {"items"} or not isinstance(plan["items"], list):
        raise ValueError("Invalid AI plan schema")
    by_id = {f.id: f for f in findings}
    seen = set()
    for item in plan["items"]:
        if not isinstance(item, dict) or set(item) != {"finding_id", "guidance_ids"}:
            raise ValueError("AI may output only finding_id and guidance_ids")
        id_ = item["finding_id"]
        if not isinstance(id_, str) or id_ not in by_id or id_ in seen:
            raise ValueError("Unknown or duplicate finding ID")
        seen.add(id_)
        ids = item["guidance_ids"]
        if not isinstance(ids, list) or any(not isinstance(x, str) for x in ids):
            raise ValueError("guidance_ids must be strings")
        allowed = {c["card_id"] for c in candidates[id_]}
        if len(ids) != len(set(ids)) or not set(ids) <= allowed:
            raise ValueError("Unsupported or duplicate OWASP guidance ID")
        if ids and not in_top10(by_id[id_]):
            raise ValueError("Outside supported OWASP Top 10 scope: cannot attach guidance")
        if not by_id[id_].evidence and ids:
            raise ValueError("No evidence: cannot attach guidance")
    if seen != set(by_id):
        raise ValueError("AI omitted a finding")
    return plan
