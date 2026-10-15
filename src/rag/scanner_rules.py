"""Hand-written CWE rules for scanner checks whose output carries no CWE.

Rules live in data/scanner-rules.json and are keyed only by stable tool identifiers:
a Nessus pluginID, or an Nmap NSE script id plus a fixed output pattern taken from
the script source. They never look at titles or free-text descriptions, and parsers
apply them only when the input itself supplies no CWE. This is the same kind of
explicit adapter rule as "classic sqlmap injection block -> CWE-89", kept as data so
every mapping is reviewable, cited and tested.
"""
import json
import re
from functools import lru_cache
from pathlib import Path

RULES_PATH = Path(__file__).parent / "data/scanner-rules.json"
_RULE_ID = re.compile(r"(nessus|nmap)-[a-z0-9-]+")
_CWE = re.compile(r"CWE-[1-9]\d*")
_SHEET = re.compile(r"[A-Za-z0-9_-]+\.md")
_SCRIPT = re.compile(r"[a-z0-9-]+")
_COMMON = {"id", "tool", "cwe", "cheatsheets", "rationale_vi", "sources"}
_FIELDS = {"nessus": _COMMON | {"plugin_id", "plugin_name", "plugin_family"},
           "nmap": _COMMON | {"script_id", "output_pattern", "title"}}


def _text(rule, key):
    value = rule.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Scanner rule {rule.get('id')!r}: {key} must be nonempty text")
    return value


def validate(data):
    """Return an index of the rules; raise ValueError on any malformed rule."""
    from .top10 import mapping
    if not isinstance(data, dict) or data.get("schema_version") != 1 or not isinstance(data.get("rules"), list):
        raise ValueError("Scanner rules file must have schema_version=1 and a rules array")
    top10_cwes = {cwe for category in mapping()["categories"] for cwe in category["cwes"]}
    index = {"by_id": {}, "nessus": {}, "nmap": {}}
    for rule in data["rules"]:
        if not isinstance(rule, dict) or rule.get("tool") not in _FIELDS:
            raise ValueError("Scanner rule must be an object with tool nessus or nmap")
        if set(rule) != _FIELDS[rule["tool"]]:
            raise ValueError(f"Scanner rule {rule.get('id')!r}: unexpected or missing fields")
        rule_id = _text(rule, "id")
        if not _RULE_ID.fullmatch(rule_id) or not rule_id.startswith(rule["tool"] + "-"):
            raise ValueError(f"Scanner rule id {rule_id!r} must look like '{rule['tool']}-...'")
        if rule_id in index["by_id"]:
            raise ValueError(f"Duplicate scanner rule id {rule_id!r}")
        if not _CWE.fullmatch(_text(rule, "cwe")):
            raise ValueError(f"Scanner rule {rule_id!r}: invalid CWE")
        # A rule exists to let a finding pass the Top 10 gate; an unmapped CWE would be dead weight.
        if rule["cwe"] not in top10_cwes:
            raise ValueError(f"Scanner rule {rule_id!r}: {rule['cwe']} is not mapped in OWASP Top 10:2025")
        _text(rule, "rationale_vi")
        sources = rule["sources"]
        if not isinstance(sources, list) or not sources or any(
                not isinstance(s, str) or not re.fullmatch(r"https://\S+", s) for s in sources):
            raise ValueError(f"Scanner rule {rule_id!r}: sources must be a nonempty list of HTTPS URLs")
        sheets = rule["cheatsheets"]
        if not isinstance(sheets, list) or any(not isinstance(s, str) or not _SHEET.fullmatch(s) for s in sheets):
            raise ValueError(f"Scanner rule {rule_id!r}: cheatsheets must be Cheat Sheet file names")
        if rule["tool"] == "nessus":
            plugin_id = _text(rule, "plugin_id")
            _text(rule, "plugin_name")
            _text(rule, "plugin_family")
            if not plugin_id.isdigit() or plugin_id in index["nessus"]:
                raise ValueError(f"Scanner rule {rule_id!r}: plugin_id must be digits and unique")
            index["nessus"][plugin_id] = rule
        else:
            script_id = _text(rule, "script_id")
            _text(rule, "title")
            if not _SCRIPT.fullmatch(script_id):
                raise ValueError(f"Scanner rule {rule_id!r}: invalid NSE script id")
            try:
                pattern = re.compile(_text(rule, "output_pattern"))
            except re.error as exc:
                raise ValueError(f"Scanner rule {rule_id!r}: invalid output_pattern") from exc
            index["nmap"].setdefault(script_id, []).append((pattern, rule))
        index["by_id"][rule_id] = rule
    return index


@lru_cache(maxsize=1)
def rules():
    return validate(json.loads(RULES_PATH.read_text(encoding="utf-8")))


def nessus_rule(plugin_id):
    return rules()["nessus"].get(str(plugin_id or "").strip())


def nmap_rule(script_id, output):
    for pattern, rule in rules()["nmap"].get(script_id or "", []):
        if pattern.search(output or ""):
            return rule
    return None


def cheatsheets_for(rule_id):
    """Cheat Sheet names for a rule id taken from the bundled file; unknown ids give nothing."""
    rule = rules()["by_id"].get(rule_id) if isinstance(rule_id, str) else None
    return list(rule["cheatsheets"]) if rule else []


def rule_details(rule, identifier):
    """Fields a parser adds to details when a rule supplies the CWE."""
    return {"scanner_rule": rule["id"],
            "cwe_mapping": (f"project rule {rule['id']}: {identifier} -> {rule['cwe']}; "
                            "the scanner supplied no CWE (src/rag/data/scanner-rules.json)")}
