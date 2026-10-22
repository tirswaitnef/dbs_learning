import json
import re
from pathlib import Path

from ..schemas import Finding

SUPPORTED_FORMATS = ("normalized", "zap", "burp", "nuclei", "sqlmap-log", "nessus", "nmap", "pentest-report")


def decode_text(raw, *, errors="strict"):
    """Decode text exported as UTF-8 or redirected by Windows PowerShell '>' (UTF-16 BOM)."""
    if raw.startswith(b"\xff\xfe"):
        return raw[2:].decode("utf-16-le", errors=errors)
    if raw.startswith(b"\xfe\xff"):
        return raw[2:].decode("utf-16-be", errors=errors)
    return raw.decode("utf-8-sig", errors=errors)


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


def _infer_zap_dbms_hint(blob: str) -> str:
    m = re.search(
        r'\b(MariaDB|MySQL|PostgreSQL|Microsoft SQL Server|SQL Server|Oracle|SQLite|MongoDB|Redis)\b',
        blob or '',
        re.I,
    )
    if m:
        return m.group(1)
    low = (blob or '').lower()
    if 'ora-' in low:
        return 'Oracle Database'
    if 'pg_query' in low or 'sqlstate[42' in low:
        return 'PostgreSQL'
    if 'sqlite3::' in low or 'sqlite_error' in low:
        return 'SQLite'
    return ''


def parse_zap_xml(raw_bytes, source_name):
    """Support OWASP ZAP Traditional XML Report (`<OWASPZAPReport>`)."""
    from .native import safe_xml, text as xml_text
    root = safe_xml(raw_bytes, "OWASPZAPReport")
    data_sites = []
    for site_el in root.findall("site"):
        alerts_out = []
        for item_el in site_el.findall("alerts/alertitem"):
            inst_list = []
            for inst_el in item_el.findall("instances/instance"):
                inst_obj = {
                    "uri": xml_text(inst_el, "uri"),
                    "method": xml_text(inst_el, "method"),
                    "param": xml_text(inst_el, "param"),
                    "attack": xml_text(inst_el, "attack"),
                    "evidence": xml_text(inst_el, "evidence"),
                    "otherinfo": xml_text(inst_el, "otherinfo"),
                }
                for rk in ("requestheader", "requestbody", "responseheader", "responsebody"):
                    val = xml_text(inst_el, rk)
                    if val:
                        mapped_k = (
                            rk.replace("request", "request-").replace("response", "response-")
                        )
                        inst_obj[mapped_k] = val
                inst_list.append(inst_obj)
            if not inst_list and (xml_text(item_el, "uri") or xml_text(item_el, "param")):
                inst_list.append({
                    "uri": xml_text(item_el, "uri"),
                    "method": xml_text(item_el, "method"),
                    "param": xml_text(item_el, "param"),
                    "attack": xml_text(item_el, "attack"),
                    "evidence": xml_text(item_el, "evidence"),
                })
            alerts_out.append({
                "pluginid": xml_text(item_el, "pluginid"),
                "alert": xml_text(item_el, "alert") or xml_text(item_el, "name"),
                "riskcode": xml_text(item_el, "riskcode"),
                "confidence": xml_text(item_el, "confidence"),
                "desc": re.sub(r"<[^>]+>", " ", xml_text(item_el, "desc")).strip(),
                "solution": re.sub(r"<[^>]+>", " ", xml_text(item_el, "solution")).strip(),
                "cweid": xml_text(item_el, "cweid"),
                "instances": inst_list,
            })
        data_sites.append({
            "@name": site_el.get("name", ""),
            "@host": site_el.get("host", ""),
            "@port": site_el.get("port", ""),
            "@ssl": site_el.get("ssl", ""),
            "alerts": alerts_out,
        })
    return parse_zap(
        {
            "@version": root.get("version", ""),
            "@generated": root.get("generated", ""),
            "site": data_sites,
        },
        source_name,
    )


def parse_zap(data, source_name):
    """ZAP traditional JSON (`site[].alerts[].instances[]`), plus normalized ZAP XML dictionary."""
    if not isinstance(data, dict) or not isinstance(data.get("site"), list):
        raise ValueError("Expected ZAP JSON with site[]")
    findings = []
    severity = {"0": "informational", "1": "low", "2": "medium", "3": "high"}
    zap_meta = {}
    if data.get("@version"):
        zap_meta["tool_version"] = str(data["@version"]).strip()
    if data.get("@generated"):
        zap_meta["scan_start"] = str(data["@generated"]).strip()
    for si, site in enumerate(data["site"]):
        if not isinstance(site.get("alerts"), list):
            raise ValueError("Expected ZAP alerts[]")
        site_meta = {**zap_meta}
        if site.get("@name"):
            site_meta["target_site"] = str(site["@name"]).strip()
        for ai, alert in enumerate(site["alerts"]):
            instances = alert.get("instances", [])
            if not isinstance(instances, list):
                raise ValueError("Expected ZAP alerts instances[]")
            for ii, instance in enumerate(instances or [{}]):
                # Attack payload alone is not treated as observed response evidence.
                evidence = instance.get("evidence", "")
                if not isinstance(evidence, str):
                    raise ValueError("ZAP evidence must be text")
                observed = ([evidence] if evidence.strip() else [])
                for key in ("response-header", "response-body", "responseHeader", "responseBody"):
                    if instance.get(key):
                        observed.append(f"{key}: {instance[key]}")
                inst_meta = dict(site_meta)
                req_hdr = str(instance.get("request-header") or instance.get("requestHeader") or "")
                if re.search(r"(?im)^\s*(?:Cookie|Authorization)\s*:", req_hdr):
                    inst_meta["auth_context"] = "Authenticated HTTP session header recorded in ZAP traffic ([REDACTED])"
                dbms_hint = _infer_zap_dbms_hint(
                    " ".join([str(alert.get("alert") or ""), evidence, str(instance.get("response-body") or "")])
                )
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
                             **({"dbms": dbms_hint} if dbms_hint else {}),
                             **({"scan_telemetry": inst_meta} if inst_meta else {}),
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
    raw = path.read_bytes()
    if format_ == "pentest-report":
        from ..ai_ingest import extract_pentest_text, parse_pentest_report_fallback
        findings = parse_pentest_report_fallback(extract_pentest_text(path), path.name)
    elif format_ == "zap" and raw.lstrip().startswith((b"<", b"\xff\xfe<", b"\xfe\xff\x00<")):
        findings = parse_zap_xml(raw, path.name)
    elif format_ in {"normalized", "zap"}:
        data = json.loads(decode_text(raw))
        findings = {"normalized": parse_normalized, "zap": parse_zap}[format_](data, path.name)
    elif format_ in {"burp", "nessus", "nmap"}:
        findings = {"burp": parse_burp, "nessus": parse_nessus, "nmap": parse_nmap}[format_](raw, path.name)
    else:
        findings = {"nuclei": parse_nuclei, "sqlmap-log": parse_sqlmap_log}[format_](decode_text(raw), path.name)
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
