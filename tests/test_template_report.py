import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from rag.config import Settings
from rag.pipeline import run_report
from rag.template_report import readable_vi, render_template_pdf


class TemplateReportTests(unittest.TestCase):
    def test_readable_vi(self):
        self.assertTrue(readable_vi('Cảnh báo từ bộ quét ghi nhận mức độ high và CWE-89 tại FAKE-01.'))
        self.assertTrue(readable_vi('Dịch vụ MySQL và MariaDB mở cổng 3306 cùng HttpOnly chưa bật.'))
        self.assertFalse(readable_vi('Endpoint quản trỈ trả HTTP 200'))          # capital mid-word
        self.assertFalse(readable_vi('Bằng chứng đěợc ghi nhận'))                 # non-Vietnamese letter
        self.assertFalse(readable_vi('Cong cu kiem thu ghi nhan canh bao muc do medium tai vi tri'))  # no diacritics

    def test_pdf_from_demo_report_has_no_invented_cvss_or_method(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, js, _ = run_report(ROOT / 'data/raw/scans/example.json', ROOT / 'data/raw/owasp/cards.json',
                                  Path(tmp) / 'out', Settings(), mode='demo')
            report = json.loads(Path(js).read_text(encoding='utf-8'))
            pdf = render_template_pdf(report, Path(tmp) / 't.pdf', client='X')
            self.assertEqual(Path(pdf).read_bytes()[:4], b'%PDF')
            self.assertTrue(all('cvss_score' not in (f.get('details') or {}) for f in report['findings']))


if __name__ == '__main__':
    unittest.main()
