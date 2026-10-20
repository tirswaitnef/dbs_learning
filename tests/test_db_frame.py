"""The database frame must come from the record only, never from a title or from AI."""
import dataclasses
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.db_scope import CONTROLS, RULE_ENGINES, ai_source, db_frame, frame_line, scope_lines
from rag.parsers import load_findings
from rag.parsers.native import parse_burp, parse_nessus, parse_nmap, parse_sqlmap_log
from rag.scanner_rules import rules

FIXTURES = ROOT / "tests/fixtures/scanners"


def row(finding):
    return dataclasses.asdict(finding)


def nmap(port_id="3306", service="mysql", script=""):
    return f'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="up"/>' \
           f'<address addr="192.0.2.30" addrtype="ipv4"/><ports><port protocol="tcp" portid="{port_id}">' \
           f'<state state="open"/><service name="{service}" product="X" version="1"/>' \
           f'{script}</port></ports></host></nmaprun>'.encode()


def nessus(plugin_id, name, cwes=(), family="Databases"):
    tags = "".join(f"<cwe>{c}</cwe>" for c in cwes)
    return (f'<NessusClientData_v2><Report name="SYNTHETIC"><ReportHost name="192.0.2.30">'
            f'<ReportItem port="3306" svc_name="mysql" protocol="tcp" severity="4" pluginID="{plugin_id}" '
            f'pluginName="{name}" pluginFamily="{family}"><description>SYNTHETIC</description>'
            f'<plugin_output>SYNTHETIC: login without password succeeded.</plugin_output>{tags}'
            f'</ReportItem></ReportHost></Report></NessusClientData_v2>').encode()


def sqlmap_log(dbms_line=""):
    return ("sqlmap identified the following injection point(s) with a total of 9 HTTP(s) requests:\n"
            "---\nParameter: id (GET)\n    Type: boolean-based blind\n"
            "    Title: AND boolean-based blind - WHERE or HAVING clause\n    Payload: id=1 AND 1=1\n---\n"
            + dbms_line + "\n")


class DbFrameTests(unittest.TestCase):
    def test_nmap_rule_finding_is_server_scope_with_authentication_control(self):
        content = nmap(script='<script id="mysql-empty-password" output="&#xa;root account has empty password"/>')
        finding = [f for f in parse_nmap(content, "n.xml") if f.kind == "scanner_alert"][0]
        frame = db_frame(row(finding))
        self.assertEqual(frame["relevance"], "server_db")
        self.assertEqual(frame["engine"], "MySQL/MariaDB")
        self.assertEqual(frame["port"], 3306)
        self.assertTrue(frame["control_label"].startswith("Xác thực"))
        self.assertIn("nmap-mysql-empty-password", " ".join(frame["basis"]))
        self.assertIn("máy chủ CSDL", frame_line(frame))

    def test_nessus_plugin_rule_is_server_scope(self):
        finding = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check"), "n.nessus")[0]
        frame = db_frame(row(finding))
        self.assertEqual((frame["relevance"], frame["engine"], frame["control"]),
                         ("server_db", "MySQL/MariaDB", "authentication"))

    def test_open_port_without_any_check_is_server_scope_without_control(self):
        finding = parse_nmap(nmap(), "n.xml")[0]
        frame = db_frame(row(finding))
        self.assertEqual((frame["relevance"], frame["engine"], frame["control_label"]),
                         ("server_db", "MySQL/MariaDB", ""))
        self.assertIn("chưa xác định kiểm soát", frame_line(frame))

    def test_sqlmap_log_is_application_layer_and_records_engine_from_dbms_line(self):
        finding = parse_sqlmap_log(sqlmap_log("back-end DBMS: MySQL >= 5.0.12 (MariaDB fork)"), "t.log")[0]
        frame = db_frame(row(finding))
        self.assertEqual(frame["relevance"], "app_db")
        self.assertEqual(frame["control"], "query_handling")
        self.assertEqual(frame["engine"], "MySQL >= 5.0.12 (MariaDB fork)")
        self.assertIn("back-end DBMS", " ".join(frame["basis"]))

    def test_plugin_rule_wins_over_the_port_it_was_reported_on(self):
        # A rule names the engine; a port that disagrees must not override it.
        content = (b'<NessusClientData_v2><Report name="S"><ReportHost name="192.0.2.30">'
                   b'<ReportItem port="5432" svc_name="postgresql" protocol="tcp" severity="4" '
                   b'pluginID="10481" pluginName="MySQL Unpassworded Account Check" pluginFamily="Databases">'
                   b'<description>S</description><plugin_output>S</plugin_output></ReportItem>'
                   b'</ReportHost></Report></NessusClientData_v2>')
        frame = db_frame(row(parse_nessus(content, "n.nessus")[0]))
        self.assertEqual((frame["engine"], frame["port"]), ("MySQL/MariaDB", 5432))
        self.assertNotIn("cổng 5432", frame_line(frame))

    def test_unrelated_finding_gets_no_database_engine(self):
        finding = parse_nmap(nmap("443", "https"), "n.xml")[0]
        frame = db_frame(row(finding))
        self.assertEqual((frame["relevance"], frame["engine"], frame["control"]), ("unrelated", "", ""))
        self.assertEqual(frame_line(frame), "Không thấy thông tin riêng về CSDL trong bản ghi này.")

    def test_sql_injection_cwe_is_application_layer_even_without_a_known_tool(self):
        finding = parse_burp(FIXTURES.joinpath("burp.xml").read_bytes(), "burp.xml")[0]
        row_dict = row(finding)
        row_dict["cwe"], row_dict["details"]["cwes"] = "CWE-89", ["CWE-89"]
        row_dict["tool"] = "Synthetic scanner — DEMO ONLY"
        frame = db_frame(row_dict)
        self.assertEqual((frame["relevance"], frame["control"]), ("app_db", "query_handling"))
        self.assertIn("tầng ứng dụng", frame_line(frame))

    def test_xss_fixture_is_not_given_a_database_frame(self):
        finding = parse_burp(FIXTURES.joinpath("burp.xml").read_bytes(), "burp.xml")[0]
        self.assertEqual(db_frame(row(finding))["relevance"], "unrelated")

    def test_only_one_bucket_gives_a_control_and_unmapped_cwes_are_recorded(self):
        content = (b'<issues><issue><name>SQL injection</name><severity>High</severity>'
                   b'<host>https://example.test</host><path>/search</path>'
                   b'<vulnerabilityClassifications><cwe>89</cwe><cwe>94</cwe><cwe>116</cwe>'
                   b'</vulnerabilityClassifications></issue></issues>')
        finding = parse_burp(content, "burp.xml")[0]
        frame = db_frame(row(finding))
        self.assertEqual(frame["control"], "query_handling")
        self.assertIn("chưa có trong bảng kiểm soát", " ".join(frame["basis"]))

    def test_cwes_in_two_buckets_give_no_control(self):
        content = (b'<issues><issue><name>Mixed</name><severity>High</severity>'
                   b'<host>https://example.test</host><path>/search</path>'
                   b'<vulnerabilityClassifications><cwe>89</cwe><cwe>1393</cwe>'
                   b'</vulnerabilityClassifications></issue></issues>')
        finding = parse_burp(content, "burp.xml")[0]
        frame = db_frame(row(finding))
        self.assertEqual((frame["relevance"], frame["control"]), ("db_related", ""))
        self.assertIn("chưa xác định được tầng", frame_line(frame))

    def test_ai_source_states_it_is_computed_by_code_not_by_ai(self):
        finding = parse_nessus(nessus("10483", "PostgreSQL Default Unpassworded Account"), "n.nessus")[0]
        text = ai_source(row(finding))
        self.assertIn("không do AI suy đoán", text)
        self.assertIn("PostgreSQL", text)
        self.assertIn("Xác thực", text)

    def test_scope_lines_count_layers_and_keep_the_caution(self):
        rows = [row(parse_nessus(nessus("10481", "MySQL Unpassworded Account Check"), "n.nessus")[0]),
                row(parse_burp(FIXTURES.joinpath("burp.xml").read_bytes(), "burp.xml")[0])]
        text = " ".join(scope_lines(rows))
        self.assertIn("máy chủ CSDL: 1", text)
        self.assertIn("ngoài phạm vi CSDL: 1", text)
        self.assertIn("không xác nhận lỗ hổng", text)

    def test_rule_engine_table_covers_every_project_rule(self):
        index = rules()["by_id"]
        self.assertEqual(set(index), set(RULE_ENGINES))
        self.assertTrue(all(rule["cwe"] in CONTROLS for rule in index.values()))

    def test_frame_is_pure_json_data(self):
        finding = parse_nessus(nessus("10481", "MySQL Unpassworded Account Check"), "n.nessus")[0]
        json.dumps(db_frame(row(finding)), ensure_ascii=False)

    def test_web_http_encryption_headers_stay_unrelated_and_withhold_db_cards(self):
        from rag.loader import load_cards
        from rag.parsers import parse_zap
        from rag.retriever import retrieve
        cards = load_cards(ROOT / "data/raw/owasp/cards.json")
        zap_doc = {"site": [{"@name": "http://198.51.100.10", "alerts": [
            {"alert": "HTTP Only Site", "cweid": "311", "riskcode": "2",
             "instances": [{"uri": "http://198.51.100.10", "evidence": "http://198.51.100.10"}]},
            {"alert": "Strict-Transport-Security Header Not Set", "cweid": "319", "riskcode": "1",
             "instances": [{"uri": "http://198.51.100.10/", "evidence": "HTTP/1.1 200 OK"}]},
        ]}]}
        for finding in parse_zap(zap_doc, "zap.json"):
            with self.subTest(alert=finding.title):
                frame = db_frame(row(finding))
                self.assertEqual((frame["relevance"], frame["control"]), ("unrelated", ""))
                self.assertEqual(retrieve(finding, cards), [])


if __name__ == "__main__":
    unittest.main()
