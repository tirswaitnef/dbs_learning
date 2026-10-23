"""The report must follow its input; these checks measure that without AI."""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from rag.report_variety import (ai_prose, code_text, compare_reports, duplicate_groups,
                                evidence_text, norm, prose_check, prose_line, sentences, similarity)


def report(rows, **extra):
    base = {"mode": "gemini-top10-analysis-extractive", "input_format": "normalized",
            "findings": rows}
    return {**base, **extra}


def row(id_, prose="", evidence=(), code_text_=""):
    item = {"id": id_, "evidence": list(evidence), "guidance": []}
    if prose:
        item["ai_analysis"] = {"claims": {"observations": [{"text_vi": prose}]}}
    if code_text_:
        item["analysis_vi"] = code_text_
    return item


CODE = "Kiểm thử cung cấp 1 mục bằng chứng. Giữ nguyên mức độ và phân loại từ đầu vào; chưa xác minh độc lập lỗ hổng."
TEMPLATE = ("Bản ghi này cho thấy một cảnh báo từ công cụ tại tham số id của ứng dụng web. "
            "Bằng chứng đầu vào chưa được xác minh độc lập trong lần chạy này.")


class VarietyTests(unittest.TestCase):
    def test_sentences_drop_short_noise(self):
        self.assertEqual(sentences("Ngắn. Đây là một câu đủ dài để được giữ lại trong so sánh."),
                         ["Đây là một câu đủ dài để được giữ lại trong so sánh."])

    def test_similarity_is_token_based_and_empty_safe(self):
        self.assertAlmostEqual(similarity("Cảnh báo SQL injection tại tham số id",
                                          "Cảnh báo SQL injection tại tham số id"), 1.0)
        self.assertEqual(similarity("", "bất kỳ"), 0.0)
        self.assertLess(similarity("Cảnh báo SQL injection tại tham số id",
                                   "Cổng 5432 mở và dịch vụ PostgreSQL trả lời"), 0.3)

    def test_only_the_model_prose_is_compared_for_duplicates(self):
        left = report([row("A", TEMPLATE, evidence=("Bằng chứng riêng của A",), code_text_=CODE),
                       row("B", TEMPLATE, evidence=("Bằng chứng riêng của B",), code_text_=CODE)])
        probe = prose_check(left)
        self.assertEqual((probe["status"], probe["duplicate_groups"]), ("duplicate_prose", [["A", "B"]]))
        self.assertIn("phát hiện nhóm bản ghi", prose_line(probe))

    def test_shared_code_sentence_is_not_reported_as_ai_repetition(self):
        left = report([row("A", "Cổng 3306 mở và script xác nhận tài khoản root không mật khẩu.", code_text_=CODE),
                       row("B", "Tham số id cho thấy SQL injection boolean-based blind theo công cụ.", code_text_=CODE)])
        probe = prose_check(left)
        self.assertEqual((probe["status"], probe["duplicate_groups"]), ("ok", []))
        self.assertEqual(probe["records_sharing_code_generated_text"], 1)
        self.assertIn("câu mô tả do code sinh", prose_line(probe))

    def test_report_without_ai_prose_says_so_instead_of_claiming_ok(self):
        probe = prose_check(report([row("A", evidence=("B",), code_text_=CODE),
                                    row("B", evidence=("C",), code_text_=CODE)]))
        self.assertEqual(probe["status"], "no_ai_prose")
        self.assertIn("không có diễn giải AI cho từng bản ghi", prose_line(probe))

    def test_similarity_threshold_ignores_evidence_but_groups_repeated_prose(self):
        rows = [row("A", TEMPLATE, evidence=("E1",)), row("B", TEMPLATE, evidence=("E2",))]
        self.assertEqual(duplicate_groups(report(rows)), [["A", "B"]])
        self.assertEqual(duplicate_groups(report(rows), text_of=evidence_text, threshold=0.6), [])

    def test_ai_prose_and_code_text_are_kept_apart(self):
        item = row("A", "Diễn giải AI cho bản ghi A.", code_text_=CODE)
        self.assertEqual(ai_prose(item), "Diễn giải AI cho bản ghi A.")
        self.assertEqual(code_text(item), CODE)
        self.assertEqual(evidence_text(row("A", evidence=("E1", "E2"))), "E1 E2")

    def test_compare_reports_splits_prose_from_evidence(self):
        left = report([row("A", "Cổng 3306 mở và script xác nhận tài khoản root không mật khẩu.",
                           evidence=("NSE: root account has empty password",), code_text_=CODE)])
        right = report([row("B", "Tham số id cho thấy SQL injection boolean-based blind theo công cụ.",
                            evidence=("Parameter: id",), code_text_=CODE)])
        diff = compare_reports(left, right)
        self.assertEqual(diff["ai_prose_overlap"], 0.0)
        self.assertEqual(diff["evidence_overlap"], 0.0)
        self.assertEqual(diff["code_text_overlap"], 1.0)
        self.assertIn("Jaccard", diff["method"])

    def test_compare_identical_reports_is_full_overlap(self):
        rows = [row("A", "Cổng 3306 mở và script xác nhận tài khoản root không mật khẩu.",
                    evidence=("NSE: root account has empty password",))]
        diff = compare_reports(report(rows), report(rows))
        self.assertEqual((diff["ai_prose_overlap"], diff["evidence_overlap"]), (1.0, 1.0))
        self.assertEqual(norm(diff["shared_ai_prose"][0]),
                         norm("Cổng 3306 mở và script xác nhận tài khoản root không mật khẩu."))


if __name__ == "__main__":
    unittest.main()
