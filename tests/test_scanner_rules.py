"""Project CWE rules for database checks that Nessus and Nmap report without a CWE."""
import copy
import json
import sys
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.config import Settings
from rag.official_report import build_corpus_report, preferred_sources
from rag.parsers import load_findings, parse_normalized
from rag.parsers.native import parse_nessus, parse_nmap
from rag.pipeline import run_report
from rag.report_builder import md_text
from rag.scanner_rules import RULES_PATH, cheatsheets_for, nmap_rule, rules, validate
from rag.schemas import Document
from rag.template_report import render_template_pdf
from rag.top10 import classify

CHEATSHEETS = ROOT / "data/raw/owasp/official/CheatSheetSeries-master/cheatsheets"


def nessus(plugin_id, name, cwes=(), severity="3", output="SYNTHETIC: login without password succeeded."):
    tags = "".join(f"<cwe>{c}</cwe>" for c in cwes)
    return (f'<NessusClientData_v2><Report name="SYNTHETIC"><ReportHost name="192.0.2.20">'
            f'<ReportItem port="3306" svc_name="mysql" protocol="tcp" severity="{severity}" pluginID="{plugin_id}" '
            f'pluginName="{name}" pluginFamily="Databases"><description>SYNTHETIC</description>'
            f'<plugin_output>{output}</plugin_output>{tags}</ReportItem></ReportHost></Report></NessusClientData_v2>').encode()


def nmap(port_scripts="", state="open", host_scripts=""):
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>'
            f'<address addr="192.0.2.20" addrtype="ipv4"/><ports>'
            f'<port protocol="tcp" portid="3306"><state state="{state}"/>'
            f'<service name="mysql" product="MySQL" version="5.0.51a"/>{port_scripts}</port>'
            f'</ports>{host_scripts}</host></nmaprun>').encode()


MYSQL_EMPTY = '<script id="mysql-empty-password" output="&#xa;  anonymous account has empty password&#xa;  root account has empty password"/>'
MSSQL_EMPTY = '<script id="ms-sql-empty-password" output="&#xa;  [192.0.2.20\\PROD]&#xa;    sa:&lt;empty&gt; =&gt; Login Success"/>'


class RuleFileTests(unittest.TestCase):
    def test_bundled_rules_are_valid_cited_and_in_top10(self):
        data = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(data["rules"]), 12)
        for rule in data["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertTrue(any(s.startswith(("https://www.tenable.com/plugins/nessus/", "https://nmap.org/nsedoc/"))
                                    for s in rule["sources"]), "cite the tool's own documentation")
                self.assertTrue(any(s.startswith("https://cwe.mitre.org/") for s in rule["sources"]))
                self.assertTrue(any(s.startswith("https://top10.owasp.org/2025/") for s in rule["sources"]))
                probe = {"cwe": rule["cwe"], "kind": "scanner_alert", "details": {}}
                self.assertEqual(classify(probe)["status"], "in_scope")
                for sheet in rule["cheatsheets"]:
                    self.assertTrue((CHEATSHEETS / sheet).is_file(), f"{sheet} is not in the vendored corpus")

    def test_malformed_rules_are_rejected(self):
        base = json.loads(RULES_PATH.read_text(encoding="utf-8"))
        nessus_rule = base["rules"][0]
        nmap_entry = next(r for r in base["rules"] if r["tool"] == "nmap")
        cases = {
            "duplicate id": lambda d: d["rules"].append(copy.deepcopy(nessus_rule)),
            "unmapped CWE": lambda d: d["rules"][0].update(cwe="CWE-119"),
            "plain http source": lambda d: d["rules"][0].update(sources=["http://example.test"]),
            "no sources": lambda d: d["rules"][0].update(sources=[]),
            "extra field": lambda d: d["rules"][0].update(match_title="MySQL"),
            "non-numeric plugin": lambda d: d["rules"][0].update(plugin_id="10481a"),
            "path in cheat sheet name": lambda d: d["rules"][0].update(cheatsheets=["../secret.md"]),
            "bad regex": lambda d: next(r for r in d["rules"] if r["id"] == nmap_entry["id"]).update(output_pattern="("),
            "wrong schema": lambda d: d.update(schema_version=2),
        }
        for label, mutate in cases.items():
            with self.subTest(label), self.assertRaises(ValueError):
                data = copy.deepcopy(base)
                mutate(data)
                validate(data)

    def test_unknown_rule_ids_give_no_cheatsheets(self):
        self.assertEqual(cheatsheets_for("nessus-10481"), ["Database_Security_Cheat_Sheet.md"])
        for value in ["nessus-0", "", None, ["nessus-10481"]]:
            self.assertEqual(cheatsheets_for(value), [])


class NessusRuleTests(unittest.TestCase):
    def test_rule_fills_missing_cwe_for_database_plugin(self):
        f = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check"), "scan.nessus")[0]
        self.assertEqual(f.cwe, "CWE-1393")
        self.assertEqual(f.details["cwes"], [])
        self.assertEqual(f.details["scanner_rule"], "nessus-10481")
        self.assertIn("Nessus pluginID 10481 -> CWE-1393", f.details["cwe_mapping"])
        self.assertEqual(f.severity, "high")  # severity is still the tool's
        scope = classify(f)
        self.assertEqual((scope["status"], [c["id"] for c in scope["categories"]]), ("in_scope", ["A07:2025"]))

    def test_cwe_supplied_by_nessus_always_wins(self):
        one = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check", ["521"]), "x")[0]
        self.assertEqual(one.cwe, "CWE-521")
        self.assertNotIn("scanner_rule", one.details)
        several = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check", ["521", "1393"]), "x")[0]
        self.assertEqual((several.cwe, several.details["cwes"]), ("unknown", ["CWE-521", "CWE-1393"]))
        self.assertNotIn("scanner_rule", several.details)

    def test_rules_match_plugin_id_not_name(self):
        renamed = parse_nessus(nessus("10481", "Renamed by Tenable"), "x")[0]
        self.assertEqual(renamed.cwe, "CWE-1393")
        lookalike = parse_nessus(nessus("999999", "MySQL Unpassworded Account Check"), "x")[0]
        self.assertEqual(lookalike.cwe, "unknown")
        self.assertNotIn("scanner_rule", lookalike.details)

    def test_informational_item_stays_an_observation(self):
        f = parse_nessus(nessus("57558", "MySQL Unsupported Version Detection", severity="0"), "x")[0]
        self.assertEqual((f.cwe, f.kind), ("CWE-1104", "observation"))
        self.assertEqual(classify(f)["status"], "observation")


class NmapRuleTests(unittest.TestCase):
    def test_empty_password_script_becomes_a_finding_next_to_the_observation(self):
        observation, alert = parse_nmap(nmap(MYSQL_EMPTY), "scan.xml")
        self.assertEqual((observation.kind, observation.cwe), ("observation", "unknown"))
        self.assertEqual(alert.id, "NMAP-0-0-S0")
        self.assertEqual((alert.kind, alert.cwe, alert.severity), ("scanner_alert", "CWE-1393", "unknown"))
        self.assertEqual(alert.location, "192.0.2.20:3306/tcp")
        self.assertIn("root account has empty password", alert.evidence[0])
        self.assertEqual(alert.details["scanner_rule"], "nmap-mysql-empty-password")
        self.assertEqual(alert.source_ref, "scan.xml#/host[0]/ports/port[0]/script[0]")
        self.assertEqual(classify(alert)["status"], "in_scope")

    def test_output_that_does_not_report_success_is_ignored(self):
        for script in ['<script id="mysql-empty-password" output="ERROR: Failed to connect to mysql server"/>',
                       '<script id="ms-sql-empty-password" output="&#xa;  \'sa\' account password is not blank."/>',
                       '<script id="ms-sql-empty-password" output="&#xa;  \'sa\' account is locked out."/>',
                       '<script id="mysql-info" output="root account has empty password"/>']:
            with self.subTest(script=script):
                findings = parse_nmap(nmap(script), "x")
                self.assertEqual([f.kind for f in findings], ["observation"])

    def test_mssql_sa_empty_password_on_port_and_as_host_script(self):
        port_findings = parse_nmap(nmap(MSSQL_EMPTY), "x")
        self.assertEqual(port_findings[1].details["scanner_rule"], "nmap-ms-sql-empty-password")
        host = parse_nmap(nmap(host_scripts=f"<hostscript>{MSSQL_EMPTY}</hostscript>"), "x")
        self.assertEqual([f.id for f in host], ["NMAP-0-0", "NMAP-H0-S0"])
        self.assertEqual((host[1].kind, host[1].cwe, host[1].location), ("scanner_alert", "CWE-1393", "192.0.2.20"))

    def test_closed_ports_produce_nothing(self):
        self.assertEqual(parse_nmap(nmap(MYSQL_EMPTY, state="closed"), "x"), [])

    def test_nmap_rule_needs_exact_script_id(self):
        self.assertIsNone(nmap_rule("mysql-empty-password-x", "root account has empty password"))
        self.assertIsNotNone(nmap_rule("mysql-empty-password", "\n  root account has empty password"))


class EndToEndTests(unittest.TestCase):
    def test_rule_findings_roundtrip_through_normalized_json(self):
        findings = parse_nmap(nmap(MYSQL_EMPTY), "scan.xml") + parse_nessus(nessus("10483", "PostgreSQL Default Unpassworded Account"), "scan.nessus")
        data = json.loads(json.dumps({"schema_version": 1, "tool": "imported", "findings": [asdict(f) for f in findings]}))
        again = parse_normalized(data, "findings.json")
        self.assertEqual(again, findings)
        self.assertEqual([classify(f)["status"] for f in again], [classify(f)["status"] for f in findings])

    def test_database_scan_report_marks_rule_cwe_and_renders(self):
        with tempfile.TemporaryDirectory() as d:
            scan = Path(d) / "db.xml"
            scan.write_bytes(nmap(MYSQL_EMPTY))
            md, js, *_ = run_report(scan, ROOT / "data/raw/owasp/cards.json", Path(d) / "out", Settings(), format_="nmap")
            report = json.loads(js.read_text(encoding="utf-8"))
            observation, alert = report["findings"]
            self.assertEqual(observation["status"], "scope_blocked")
            # In scope, but the two bundled cards cover only SQLi and XSS: no card, and the report says so.
            self.assertEqual((alert["owasp_top10"]["status"], alert["status"]), ("in_scope", "no_supported_guidance"))
            self.assertIn("Chưa truy xuất được hướng dẫn", alert["guidance_reason"])
            self.assertIn(md_text("CWE-1393 (gán theo quy tắc ánh xạ của dự án; công cụ không ghi CWE)"),
                          md.read_text(encoding="utf-8"))
            template = Path(d) / "template.pdf"
            render_template_pdf(report, template)
            self.assertGreater(template.stat().st_size, 1000)

    def test_owasp_mode_prefers_database_security_sheet(self):
        f = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check"), "scan.nessus")[0]
        self.assertEqual(preferred_sources(f), {"Database_Security_Cheat_Sheet.md"})
        text = "# {0}\n\n## Configuring Secure Authentication\n\nThe database should always require authentication, including connections from the local server ({0}).\n"
        documents = [Document(n, text.format(n[:-3]), "sha") for n in ("Password_Storage_Cheat_Sheet.md", "Database_Security_Cheat_Sheet.md")]
        results = [{"source": d.source, "start": 0, "end": len(d.text), "score": s} for d, s in zip(documents, (0.93, 0.86))]
        queries = []

        class Model:
            def generate(self, prompt, *, system, schema):
                return json.dumps({"source_ids": ["S1"]})

        report = build_corpus_report([f], Settings(), documents, lambda q: queries.append(q) or results,
                                     corpus_sha256="c", scan_sha256="s", llm=Model())
        row = report["findings"][0]
        self.assertTrue(queries[0].startswith("CWE-1393 MySQL Unpassworded Account Check"))
        self.assertEqual([c["source"] for c in row["retrieval"]],
                         ["Database_Security_Cheat_Sheet.md", "Password_Storage_Cheat_Sheet.md"])
        self.assertEqual(row["guidance"][0]["url"], "https://cheatsheetseries.owasp.org/cheatsheets/Database_Security_Cheat_Sheet.html")

    def test_all_rule_ids_resolve(self):
        self.assertEqual(set(rules()["by_id"]), {r["id"] for r in json.loads(RULES_PATH.read_text(encoding="utf-8"))["rules"]})


if __name__ == "__main__":
    unittest.main()
