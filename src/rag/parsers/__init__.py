import json
import re
from pathlib import Path

from ..schemas import Finding

SUPPORTED_FORMATS = ("normalized", "zap", "burp", "nuclei", "sqlmap-log", "nessus", "nmap")


def normalize_cwe(value):
    if value is None or str(value).strip() in {"", "-1", "0", "unknown"}:
        return "unknown"
    value = str(value).upper().strip()
    if value.isdigit():
        value = "CWE-" + value
    if not re.fullmatch(r"CWE-\d+", value):
        raise ValueError(f"Invalid CWE: {value}")
    return value


def _text(value, label):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be nonempty text")
    return value.strip()


def parse_normalized(data, source_name):
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("Require normalized schema_version=1")
    tool = _text(data.get("tool"), "tool")
    rows = data.get("findings")
    if not isinstance(rows, list):
        raise ValueError("findings must be an array")
    findings = []
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError("Finding must be an object")
        evidence = row.get("evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(e, str) for e in evidence):
            raise ValueError("evidence must be an array of strings")
        details = row.get("details", {})
        if not isinstance(details, dict):
            raise ValueError("details must be an object")
        kind = row.get("kind", "scanner_alert")
        if kind not in {"scanner_alert", "observation"}:
            raise ValueError("kind must be scanner_alert or observation")
        findings.append(Finding(
            _text(row.get("id"), "id"), _text(row.get("title"), "title"),
            normalize_cwe(row.get("cwe")), _text(row.get("severity", "unknown"), "severity"),
            _text(row.get("location", "unknown"), "location"),
            tuple(e for e in evidence if e.strip()), _text(row.get("tool", tool), "tool"),
            _text(row.get("source_ref", f"{source_name}#/findings/{i}"), "source_ref"),
            kind, details))
    return findings


def parse_zap(data, source_name):
    """ZAP traditional JSON: site[].alerts[].instances[]. Other exports are rejected."""
    if not isinstance(data, dict) or not isinstance(data.get("site"), list):
        raise ValueError("Expected ZAP JSON with site[]")
    findings = []
    severity = {"0": "informational", "1": "low", "2": "medium", "3": "high"}
    for si, site in enumerate(data["site"]):
        if not isinstance(site.get("alerts"), list):
            raise ValueError("Expected ZAP alerts[]")
        for ai, alert in enumerate(site["alerts"]):
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                raise ValueError("Expected ZAP instances[]")
            for ii, instance in enumerate(instances or [{}]):
                # Attack payload alone is not treated as observed response evidence.
                evidence = instance.get("evidence", "")
                if not isinstance(evidence, str):
                    raise ValueError("ZAP evidence must be text")
                observed = ([evidence] if evidence.strip() else [])
                for key in ("response-header", "response-body", "responseHeader", "responseBody"):
                    if instance.get(key):
                        observed.append(f"{key}: {instance[key]}")
                findings.append(Finding(
                    f"ZAP-{si}-{ai}-{ii}", _text(alert.get("alert") or alert.get("name"), "alert"),
                    normalize_cwe(alert.get("cweid")),
                    severity.get(str(alert.get("riskcode")), "unknown"),
                    instance.get("uri") or site.get("@name") or "unknown",
                    tuple(observed),
                    "OWASP ZAP", f"{source_name}#/site/{si}/alerts/{ai}" + (f"/instances/{ii}" if instances else ""),
                    details={"confidence": alert.get("confidence", "unknown"),
                             "parameter": instance.get("param", ""), "method": instance.get("method", ""),
                             "rule_id": alert.get("pluginid", ""),
                             "scanner_solution": alert.get("solution", ""),
                             "description": alert.get("desc", ""),
                             "raw_instance": instance,
                             "raw_alert": {k: v for k, v in alert.items() if k != "instances"}}))
    return findings


def load_findings(path, format_="normalized"):
    path = Path(path)
    if path.stat().st_size > 10 * 1024 * 1024:
        raise ValueError("Input exceeds starter limit of 10 MiB")
    if format_ not in SUPPORTED_FORMATS:
        raise ValueError(f"Unsupported format: {format_}")
    from .native import parse_burp, parse_nuclei, parse_sqlmap_log, parse_nessus, parse_nmap
    if format_ in {"normalized", "zap"}:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
        findings = {"normalized": parse_normalized, "zap": parse_zap}[format_](data, path.name)
    elif format_ in {"burp", "nessus", "nmap"}:
        findings = {"burp": parse_burp, "nessus": parse_nessus, "nmap": parse_nmap}[format_](path.read_bytes(), path.name)
    else:
        findings = {"nuclei": parse_nuclei, "sqlmap-log": parse_sqlmap_log}[format_](path.read_text(encoding="utf-8-sig"), path.name)
    for finding in findings:
        for field_name in ("id", "title", "cwe", "severity", "location", "tool", "source_ref"):
            _text(getattr(finding, field_name), field_name)
        if any(not isinstance(item, str) for item in finding.evidence):
            raise ValueError("Invalid evidence data")
    ids = [f.id for f in findings]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate finding IDs")
    if len(findings) > 10000:
        raise ValueError("Import supports at most 10000 records per file")
    return findings
