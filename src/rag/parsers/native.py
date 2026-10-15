"""Explicit format adapters. Scanner observations are not independent verification."""
import base64
import json
import re
from urllib.parse import urljoin
from xml.etree import ElementTree as ET
from xml.parsers import expat

from ..schemas import Finding
from . import normalize_cwe


def safe_xml(content, expected_root):
    """Allow Burp element-only internal DTD, forbid entities and external DTDs."""
    parser = expat.ParserCreate()
    def reject(*_):
        raise ValueError("XML entities/external DTDs are not allowed")
    def doctype(name, system_id, public_id, internal):
        if system_id or public_id:
            reject()
    depth = 0
    def start(*_):
        nonlocal depth
        depth += 1
        if depth > 80:
            raise ValueError("XML nesting exceeds limit")
    def end(*_):
        nonlocal depth
        depth -= 1
    parser.EntityDeclHandler = reject
    parser.ExternalEntityRefHandler = reject
    parser.StartDoctypeDeclHandler = doctype
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    try:
        parser.Parse(content, True)
        root = ET.fromstring(content)
    except (expat.ExpatError, ET.ParseError) as exc:
        raise ValueError("Malformed XML") from exc
    if root.tag != expected_root:
        raise ValueError(f"Expected XML root <{expected_root}>, got <{root.tag}>")
    return root


def text(node, path, default=""):
    found = node.find(path)
    return "".join(found.itertext()).strip() if found is not None else default


def cwes(value):
    """Preserve every explicit CWE; no name-based guessing."""
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    out = []
    for item in values:
        if not isinstance(item, (str, int)):
            raise ValueError("CWE must be a string, integer or list")
        for part in re.split(r"[,;\s]+", str(item).strip()):
            if part:
                cwe = normalize_cwe(part)
                if cwe != "unknown" and cwe not in out:
                    out.append(cwe)
    return out


def primary_cwe(values):
    # Ambiguous multiple CWEs are kept in details, not silently narrowed for remediation.
    return values[0] if len(values) == 1 else "unknown"


def decode_message(node):
    if node is None:
        return ""
    value = "".join(node.itertext())
    if node.get("base64", "false").lower() == "true":
        try:
            value = base64.b64decode(re.sub(r"\s+", "", value), validate=True).decode("utf-8", errors="replace")
        except (ValueError, base64.binascii.Error) as exc:
            raise ValueError("Invalid Base64 in Burp HTTP message") from exc
    return value


def parse_burp(content, source):
    root = safe_xml(content, "issues")
    findings = []
    for i, issue in enumerate(root.findall("issue")):
        name = text(issue, "name")
        if not name:
            raise ValueError("Burp issue is missing name")
        host, path = text(issue, "host"), text(issue, "path")
        location = urljoin(host.rstrip("/") + "/", path) if host else path or "unknown"
        cw = cwes(["".join(n.itertext()).strip() for n in issue.findall(".//vulnerabilityClassifications/cwe")])
        for value in re.findall(r"\bCWE-\d+\b", text(issue, "vulnerabilityClassifications"), flags=re.I):
            if value.upper() not in cw:
                cw.append(value.upper())
        detail = text(issue, "issueDetail")
        evidence = ["issueDetail: " + detail] if detail else []
        messages = []
        for rr in issue.findall("requestresponse"):
            request, response = decode_message(rr.find("request")), decode_message(rr.find("response"))
            messages.append({"request": request, "response": response})
            if response.strip():
                evidence.append("HTTP response: " + response)
        findings.append(Finding(f"BURP-{i}", name, primary_cwe(cw), text(issue, "severity", "unknown").lower(),
                                location, tuple(evidence), "Burp Suite", f"{source}#/issues/issue[{i}]",
                                details={"confidence": text(issue, "confidence", "unknown"),
                                         "rule_id": text(issue, "type"), "serial_number": text(issue, "serialNumber"),
                                         "insertion_point": text(issue, "location"), "cwes": cw,
                                         "scanner_solution": text(issue, "remediationDetail") or text(issue, "remediationBackground"),
                                         "http_messages": messages, "raw_xml": ET.tostring(issue, encoding="unicode")}))
    return findings


def parse_nuclei(content, source):
    findings = []
    for line_number, line in enumerate(content.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError as exc:
            raise ValueError(f"Invalid Nuclei JSONL at line {line_number}") from exc
        if not isinstance(row, dict) or "template-id" not in row or not isinstance(row.get("info"), dict):
            raise ValueError(f"Not a Nuclei result at line {line_number}")
        if row.get("matcher-status") is False:
            continue  # Explicit failed matcher is not a finding.
        info = row["info"]
        classification = info.get("classification") or {}
        cw = cwes(classification.get("cwe-id"))
        evidence = []
        if row.get("response"):
            evidence.append("HTTP response: " + str(row["response"]))
        extracted = row.get("extracted-results") or []
        if not isinstance(extracted, list):
            raise ValueError("Nuclei extracted-results must be an array")
        evidence.extend("extracted-result: " + str(value) for value in extracted if str(value).strip())
        findings.append(Finding(f"NUCLEI-L{line_number}", info.get("name") or str(row["template-id"]),
                                primary_cwe(cw), info.get("severity") or "unknown",
                                row.get("matched-at") or row.get("url") or row.get("host") or "unknown",
                                tuple(evidence), "Nuclei", f"{source}#line={line_number}",
                                details={"rule_id": row["template-id"], "cwes": cw,
                                         "cves": classification.get("cve-id", []),
                                         "cvss_score": classification.get("cvss-score"),
                                         "scanner_solution": info.get("remediation", ""),
                                         "raw_result": row}))
    return findings


def parse_nessus(content, source):
    root = safe_xml(content, "NessusClientData_v2")
    report = root.find("Report")
    if report is None:
        raise ValueError("Missing Nessus Report element")
    findings = []
    severity = {"0": "informational", "1": "low", "2": "medium", "3": "high", "4": "critical"}
    for hi, host in enumerate(report.findall("ReportHost")):
        for ri, item in enumerate(host.findall("ReportItem")):
            cw = cwes([n.text or "" for n in item.findall("cwe")])
            outputs = ["".join(n.itertext()).strip() for n in item.findall("plugin_output")]
            findings.append(Finding(f"NESSUS-{hi}-{ri}", item.get("pluginName") or text(item, "plugin_name") or "Unnamed plugin",
                                    primary_cwe(cw), severity.get(item.get("severity"), "unknown"),
                                    f"{host.get('name', 'unknown')}:{item.get('port', '0')}/{item.get('protocol', 'unknown')}",
                                    tuple(value for value in outputs if value), "Nessus",
                                    f"{source}#/Report/ReportHost[{hi}]/ReportItem[{ri}]",
                                    kind="observation" if item.get("severity") == "0" else "scanner_alert",
                                    details={"rule_id": item.get("pluginID", ""), "cwes": cw,
                                             "cves": [n.text for n in item.findall("cve") if n.text],
                                             "cvss_score": text(item, "cvss3_base_score") or text(item, "cvss_base_score"),
                                             "scanner_solution": text(item, "solution"),
                                             "description": text(item, "description"),
                                             "raw_xml": ET.tostring(item, encoding="unicode")}))
    return findings


def parse_nmap(content, source):
    root = safe_xml(content, "nmaprun")
    findings = []
    for hi, host in enumerate(root.findall("host")):
        address = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") in {"ipv4", "ipv6"}), "unknown")
        for pi, port in enumerate(host.findall("ports/port")):
            state_node, service = port.find("state"), port.find("service")
            state = state_node.get("state", "unknown") if state_node is not None else "unknown"
            if state not in {"open", "open|filtered"}:
                continue
            service_details = dict(service.attrib) if service is not None else {}
            observation = f"port_state={state}; service={json.dumps(service_details, ensure_ascii=False)}"
            scripts = [{"id": s.get("id"), "output": s.get("output", ""),
                        "raw_xml": ET.tostring(s, encoding="unicode")} for s in port.findall("script")]
            findings.append(Finding(f"NMAP-{hi}-{pi}", f"Service observation: {service_details.get('name', 'unknown')}",
                                    "unknown", "informational", f"{address}:{port.get('portid')}/{port.get('protocol')}",
                                    (observation,) + tuple("NSE: " + s["output"] for s in scripts if s["output"]),
                                    "Nmap", f"{source}#/host[{hi}]/ports/port[{pi}]", kind="observation",
                                    details={"state": state, "service": service_details, "scripts": scripts,
                                             "raw_xml": ET.tostring(port, encoding="unicode")}))
        for si, script in enumerate(host.findall("hostscript/script")):
            output = script.get("output", "")
            findings.append(Finding(f"NMAP-H{hi}-S{si}", f"NSE observation: {script.get('id', 'unknown')}",
                                    "unknown", "unknown", address, (output,) if output else (), "Nmap",
                                    f"{source}#/host[{hi}]/hostscript/script[{si}]", kind="observation",
                                    details={"raw_xml": ET.tostring(script, encoding="unicode")}))
    return findings


def parse_sqlmap_log(content, source):
    """Classic sqlmap confirmed injection-point blocks only; no heuristic parsing."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", content)
    blocks = list(re.finditer(r"^Parameter:\s*(.+?)\s*\(([^\n]+)\)\s*$", clean, re.M))
    findings = []
    for i, match in enumerate(blocks):
        end = blocks[i + 1].start() if i + 1 < len(blocks) else len(clean)
        block = clean[match.start():end]
        block = re.split(r"(?m)^---\s*$", block, maxsplit=1)[0]
        if not re.search(r"(?m)^\s+Type:\s*\S", block) or not re.search(r"(?m)^\s+Payload:\s*\S", block):
            raise ValueError("Incomplete sqlmap injection block; provide full log")
        techniques = re.findall(r"(?m)^\s+Type:\s*(.+)$", block)
        allowed = {"boolean-based blind", "error-based", "union query", "time-based blind", "stacked queries", "inline query"}
        if any(t.strip().lower() not in allowed for t in techniques) or not re.search(r"(?m)^\s+Title:\s*\S", block):
            raise ValueError("Unsupported/incomplete sqlmap technique block")
        # This adapter explicitly supports classic SQLi logs, not newer other-injection modes.
        if any(re.search(r"LDAP|XPath|NoSQL|GraphQL", t, re.I) for t in re.findall(r"(?m)^\s+Title:\s*(.+)$", block)):
            raise ValueError("sqlmap-log adapter supports classic SQL injection only")
        line_number = clean[:match.start()].count("\n") + 1
        findings.append(Finding(f"SQLMAP-{i}", "SQL Injection (sqlmap-reported)", "CWE-89", "unknown",
                                f"parameter={match.group(1)} ({match.group(2)}); target URL not established by parser",
                                (block.rstrip(),), "sqlmap", f"{source}#line={line_number}",
                                details={"parameter": match.group(1), "place": match.group(2), "techniques": techniques,
                                         "cwe_mapping": "adapter rule: classic sqlmap injection-point block -> CWE-89",
                                         "evidence_type": "scanner finding block, not independent raw HTTP confirmation"}))
    if not findings:
        if re.search(r"all tested parameters do not appear to be injectable", clean, re.I):
            return []
        raise ValueError("No recognized final sqlmap finding/negative result; heuristic messages are insufficient")
    return findings
