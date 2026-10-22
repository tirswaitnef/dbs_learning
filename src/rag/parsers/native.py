"""Explicit format adapters. Scanner observations are not independent verification."""
import base64
import json
import re
from urllib.parse import urljoin
from xml.etree import ElementTree as ET
from xml.parsers import expat

from ..scanner_rules import nessus_rule, nmap_rule, rule_details
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
            plugin_id = item.get("pluginID", "")
            # A CWE supplied by Nessus always wins; the project rule only fills a missing one.
            rule = None if cw else nessus_rule(plugin_id)
            details = {"rule_id": plugin_id, "cwes": cw,
                       "cves": [n.text for n in item.findall("cve") if n.text],
                       "cvss_score": text(item, "cvss3_base_score") or text(item, "cvss_base_score"),
                       "scanner_solution": text(item, "solution"),
                       "description": text(item, "description"),
                       "raw_xml": ET.tostring(item, encoding="unicode")}
            if rule:
                details.update(rule_details(rule, f"Nessus pluginID {plugin_id}"))
            findings.append(Finding(f"NESSUS-{hi}-{ri}", item.get("pluginName") or text(item, "plugin_name") or "Unnamed plugin",
                                    rule["cwe"] if rule else primary_cwe(cw), severity.get(item.get("severity"), "unknown"),
                                    f"{host.get('name', 'unknown')}:{item.get('port', '0')}/{item.get('protocol', 'unknown')}",
                                    tuple(value for value in outputs if value), "Nessus",
                                    f"{source}#/Report/ReportHost[{hi}]/ReportItem[{ri}]",
                                    kind="observation" if item.get("severity") == "0" else "scanner_alert",
                                    details=details))
    return findings


def nse_finding(rule, script, finding_id, location, source_ref, extra):
    """Finding for an NSE script whose output matches a project rule. Nmap gives no severity."""
    output = script.get("output", "").strip()
    return Finding(finding_id, f"{rule['title']} (Nmap {rule['script_id']})", rule["cwe"], "unknown", location,
                   (f"NSE {rule['script_id']}: {output}",), "Nmap", source_ref,
                   details={"rule_id": rule["script_id"], **extra,
                            **rule_details(rule, f"Nmap NSE {rule['script_id']} output"),
                            "evidence_type": "NSE script output reported by Nmap; not independently verified",
                            "raw_xml": ET.tostring(script, encoding="unicode")})


def _sanitize_cli(text_value):
    return re.sub(r'[A-Za-z]:\\Users\\[^\\\s"\']+', r'C:\\Users\\[REDACTED]', text_value)


def parse_nmap(content, source):
    root = safe_xml(content, "nmaprun")
    nmap_meta = {}
    if root.get("version"):
        nmap_meta["tool_version"] = root.get("version").strip()
    if root.get("startstr"):
        nmap_meta["scan_start"] = root.get("startstr").strip()
    if root.get("args"):
        nmap_meta["cli_hint"] = _sanitize_cli(root.get("args").strip())[:300]
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
            location = f"{address}:{port.get('portid')}/{port.get('protocol')}"
            obs_details = {"state": state, "service": service_details, "scripts": scripts,
                           **({"scan_telemetry": nmap_meta} if nmap_meta else {}),
                           "raw_xml": ET.tostring(port, encoding="unicode")}
            findings.append(Finding(f"NMAP-{hi}-{pi}", f"Service observation: {service_details.get('name', 'unknown')}",
                                    "unknown", "informational", location,
                                    (observation,) + tuple("NSE: " + s["output"] for s in scripts if s["output"]),
                                    "Nmap", f"{source}#/host[{hi}]/ports/port[{pi}]", kind="observation",
                                    details=obs_details))
            # The port record stays an observation; a script result that matches a rule is a finding of its own.
            for si, script in enumerate(port.findall("script")):
                rule = nmap_rule(script.get("id"), script.get("output", ""))
                if rule:
                    extra = {"state": state, "service": service_details,
                             **({"scan_telemetry": nmap_meta} if nmap_meta else {})}
                    findings.append(nse_finding(rule, script, f"NMAP-{hi}-{pi}-S{si}", location,
                                                f"{source}#/host[{hi}]/ports/port[{pi}]/script[{si}]",
                                                extra))
        for si, script in enumerate(host.findall("hostscript/script")):
            output = script.get("output", "")
            ref = f"{source}#/host[{hi}]/hostscript/script[{si}]"
            extra_meta = {"scan_telemetry": nmap_meta} if nmap_meta else {}
            rule = nmap_rule(script.get("id"), output)
            if rule:
                findings.append(nse_finding(rule, script, f"NMAP-H{hi}-S{si}", address, ref, extra_meta))
                continue
            findings.append(Finding(f"NMAP-H{hi}-S{si}", f"NSE observation: {script.get('id', 'unknown')}",
                                    "unknown", "unknown", address, (output,) if output else (), "Nmap",
                                    ref, kind="observation",
                                    details={**extra_meta, "raw_xml": ET.tostring(script, encoding="unicode")}))
    return findings


def _sqlmap_telemetry(clean):
    telemetry = {}
    ver = re.search(r"\{(\d+\.\d+[A-Za-z0-9.#_-]*)\}", clean)
    if ver:
        telemetry["tool_version"] = ver.group(1)
    start_m = re.search(r"\[\*\]\s*starting\s*@\s*([0-9:]+)\s*/(\d{4}-\d{2}-\d{2})/", clean)
    end_m = re.search(r"\[\*\]\s*ending\s*@\s*([0-9:]+)\s*/(\d{4}-\d{2}-\d{2})/", clean)
    if start_m:
        telemetry["scan_start"] = f"{start_m.group(2)} {start_m.group(1)}"
    if end_m:
        telemetry["scan_end"] = f"{end_m.group(2)} {end_m.group(1)}"
    req_m = re.search(r"with a total of (\d+) HTTP\(s\) requests", clean, re.I)
    if req_m:
        telemetry["request_count"] = int(req_m.group(1))
    lvl_m = re.search(r"level \((\d+)\) and risk \((\d+)\) values\?\s*\[Y/n\]\s*([YyNn])", clean)
    if lvl_m:
        telemetry["level"] = int(lvl_m.group(1))
        telemetry["risk"] = int(lvl_m.group(2))
        telemetry["extended_dbms_tests"] = lvl_m.group(3).upper() == "Y"
    if re.search(r"checking if the target is protected by some kind of WAF/IPS", clean, re.I):
        waf_warn = re.search(r"(?im)^.*\[(?:WARNING|CRITICAL)\].*\b(?:WAF|IPS)\b.*$", clean)
        telemetry["waf_status"] = waf_warn.group(0).strip() if waf_warn else "checked; no WAF/IPS warning reported"
    non_dyn = [f"{m.group(1)} '{m.group(2)}'" for m in re.finditer(
        r"(?im)\[WARNING\]\s+(\S+)\s+parameter\s+'([^']+)'\s+does not appear to be dynamic", clean)]
    if non_dyn:
        telemetry["non_dynamic_parameters"] = non_dyn
    if re.search(r"reflective value\(s\) found and filtering out", clean, re.I):
        telemetry["reflection_filtered"] = True
    not_str = re.search(r'\(with --not-string="([^"]+)"\)', clean)
    if not_str:
        telemetry["not_string"] = not_str.group(1)
    if re.search(r"is vulnerable\. Do you want to keep testing the others \(if any\)\?\s*\[y/N\]\s*N", clean):
        telemetry["stopped_after_first_vulnerable_param"] = True
    os_m = re.search(r"(?im)^\s*web server operating system:\s*(.+?)\s*$", clean)
    if os_m:
        telemetry["os_banner"] = os_m.group(1).strip()
    tech_m = re.search(r"(?im)^\s*web application technology:\s*(.+?)\s*$", clean)
    if tech_m:
        telemetry["web_tech"] = tech_m.group(1).strip()
    auth_m = re.search(r"(?im)^\s*Authentication\s+Context:\s*(.+?)\s*$", clean)
    if auth_m:
        telemetry["auth_context"] = _sanitize_cli(auth_m.group(1).strip())[:240]
    cli_m = re.search(r"(?im)^\s*(?:Command|CLI\s+Command):\s*(.+?)\s*$", clean)
    if cli_m:
        telemetry["cli_hint"] = _sanitize_cli(cli_m.group(1).strip())[:300]
    cu_m = re.search(r"(?im)^\s*current user:\s*['\"]?([^'\"\r\n]+)['\"]?\s*$", clean)
    if cu_m:
        telemetry["current_user"] = cu_m.group(1).strip()
    cdb_m = re.search(r"(?im)^\s*current database:\s*['\"]?([^'\"\r\n]+)['\"]?\s*$", clean)
    if cdb_m:
        telemetry["current_db"] = cdb_m.group(1).strip()
    dba_m = re.search(r"(?im)^\s*current user is DBA:\s*(True|False)\s*$", clean)
    if dba_m:
        telemetry["is_dba"] = dba_m.group(1).lower() == "true"
    dbs_m = re.search(r"(?im)^available databases \[\d+\]:\n(?:\[\*\] .+\n?)+", clean)
    if dbs_m:
        telemetry["databases"] = [m.group(1).strip() for m in re.finditer(r"^\[\*\]\s+(.+?)\s*$", dbs_m.group(0), re.M)]
    tables_by_db = {}
    for tbl_m in re.finditer(
        r"(?im)^Database:\s*(\S+)\s*\n\[\d+\s+tables?\]\s*\n\+[-+]+\+\n((?:\|[^\n]+\|\n)+)\+[-+]+\+",
        clean,
    ):
        db_name = tbl_m.group(1).strip()
        tbls = [r.strip(" |\t") for r in tbl_m.group(2).splitlines() if r.strip(" |\t")]
        if tbls:
            tables_by_db[db_name] = tbls
    if tables_by_db:
        telemetry["tables_by_db"] = tables_by_db
    return telemetry


def parse_sqlmap_log(content, source):
    """Confirmed sqlmap injection-point blocks, plus explicit heuristic XSS observations when present."""
    clean = re.sub(r"\x1b\[[0-9;]*m", "", content).replace("\r\n", "\n").replace("\r", "\n")
    blocks = list(re.finditer(r"^Parameter:\s*(.+?)\s*\(([^\n]+)\)\s*$", clean, re.M))
    # The documented "back-end DBMS:" line states the engine sqlmap fingerprinted.
    # Kept as a recorded fact; no CWE, severity or target is derived from it.
    dbms = re.search(r"(?im)^\s*back-end DBMS:\s*(.+?)\s*$", clean)
    target_url = re.search(r"(?im)^\s*(?:Target\s+)?URL:\s*(https?://\S+)\s*$", clean)
    output_host = re.search(r"sqlmap[/\\]output[/\\]([A-Za-z0-9._-]+)", clean, re.I)
    telemetry = _sqlmap_telemetry(clean)
    meta_lines = []
    for label_re in (
        r"(?im)^\s*web server operating system:\s*.+$",
        r"(?im)^\s*web application technology:\s*.+$",
        r"(?im)^\s*back-end DBMS:\s*.+$",
        r"(?im)^\s*current user:\s*.+$",
        r"(?im)^\s*current database:\s*.+$",
        r"(?im)^\s*current user is DBA:\s*.+$",
    ):
        found = re.search(label_re, clean)
        if found:
            meta_lines.append(found.group(0).strip())
    dbs_match = re.search(r"(?im)^available databases \[\d+\]:\n(?:\[\*\] .+\n?)+", clean)
    if dbs_match:
        meta_lines.append(dbs_match.group(0).strip())
    for tbl_block in re.finditer(
        r"(?im)^Database:\s*\S+\s*\n\[\d+\s+tables?\]\s*\n\+[-+]+\+\n(?:\|[^\n]+\|\n)+\+[-+]+\+",
        clean,
    ):
        meta_lines.append(tbl_block.group(0).strip())
    has_post_enum = bool(dbs_match or any(k in telemetry for k in ("current_user", "current_db", "is_dba", "tables_by_db")))
    post_text = "\n\n" + "\n".join(meta_lines) if has_post_enum else ""

    def _location_for(param_name, place_name):
        if target_url:
            return f"{target_url.group(1)} (parameter={param_name}, {place_name})"
        if output_host:
            return f"host={output_host.group(1)} (sqlmap output log); parameter={param_name} ({place_name})"
        return f"parameter={param_name} ({place_name}); target URL not established by parser"

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
        place = match.group(2).strip()
        location = _location_for(match.group(1), place)
        http_method = place.upper() if place.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} else ""
        findings.append(Finding(f"SQLMAP-{i}", "SQL Injection (sqlmap-reported)", "CWE-89", "unknown",
                                location,
                                (block.rstrip() + post_text,), "sqlmap", f"{source}#line={line_number}",
                                details={"parameter": match.group(1), "place": place,
                                         **({"method": http_method} if http_method else {}),
                                         "techniques": techniques,
                                         **({"dbms": dbms.group(1)} if dbms else {}),
                                         **({"scan_telemetry": telemetry} if telemetry else {}),
                                         "cwe_mapping": "adapter rule: classic sqlmap injection-point block -> CWE-89",
                                         "evidence_type": "scanner finding block, not independent raw HTTP confirmation"}))
    negative_end = bool(re.search(r"all tested parameters do not appear to be injectable", clean, re.I))
    if not findings and not negative_end:
        raise ValueError("No recognized final sqlmap finding/negative result; heuristic messages are insufficient")

    reflect_line = re.search(r"(?im)^.*reflective value\(s\) found and filtering out.*$", clean)
    for j, xss_m in enumerate(re.finditer(
        r"(?im)^.*heuristic \(XSS\) test shows that (\S+) parameter '([^']+)' might be vulnerable to cross-site scripting \(XSS\) attacks.*$",
        clean,
    )):
        xss_place, xss_param = xss_m.group(1).strip(), xss_m.group(2).strip()
        xss_line_no = clean[:xss_m.start()].count("\n") + 1
        xss_method = xss_place.upper() if xss_place.upper() in {"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"} else ""
        ev_parts = [xss_m.group(0).strip()]
        if reflect_line:
            ev_parts.append(reflect_line.group(0).strip())
        xss_tel = {k: telemetry[k] for k in ("tool_version", "scan_start", "scan_end", "reflection_filtered", "non_dynamic_parameters")
                   if k in telemetry}
        findings.append(Finding(
            f"SQLMAP-OBS-{j}",
            "Heuristic XSS indicator (sqlmap-reported, unconfirmed)",
            "CWE-79",
            "informational",
            _location_for(xss_param, xss_place),
            ("\n".join(ev_parts),),
            "sqlmap",
            f"{source}#line={xss_line_no}",
            kind="observation",
            details={
                "parameter": xss_param,
                "place": xss_place,
                **({"method": xss_method} if xss_method else {}),
                "confidence": "Heuristic (unconfirmed)",
                **({"scan_telemetry": xss_tel} if xss_tel else {}),
                "cwe_mapping": "adapter rule: sqlmap heuristic XSS notice -> CWE-79 observation",
                "evidence_type": "heuristic reflection check only; requires manual XSS context verification",
            },
        ))
    return findings
