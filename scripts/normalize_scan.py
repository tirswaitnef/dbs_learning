"""Read scanner export -> normalized JSON + import summary. No LLM/OWASP required."""
import argparse
import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from _bootstrap import ROOT
from rag.parsers import SUPPORTED_FORMATS, load_findings
from rag.report_builder import md_text
from rag.report_view import cwe_text
from rag.top10 import finding_cwes


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Normalize scanner output locally without AI")
    p.add_argument("--input", required=True, type=Path)
    p.add_argument("--format", required=True, choices=SUPPORTED_FORMATS)
    p.add_argument("--output", type=Path, default=ROOT / "data/processed/scan-import")
    args = p.parse_args()
    try:
        if args.input.resolve() in {(args.output / "findings.json").resolve(),
                                    (args.output / "import-summary.md").resolve()}:
            raise ValueError("Output would overwrite input; choose a separate directory")
        findings = load_findings(args.input, args.format)
        input_sha = hashlib.sha256(args.input.read_bytes()).hexdigest()
        tools = sorted({f.tool for f in findings})
        data = {"schema_version": 1, "tool": ", ".join(tools) or args.format,
                "import_metadata": {"input_file": args.input.name, "format": args.format,
                                    "input_sha256": input_sha, "parser_version": "0.5.0",
                                    "notice": "Imported scanner records, not independently verified findings. Zero records does not prove a safe target."},
                "findings": [asdict(f) for f in findings]}
        lines = ["# Kết quả đọc output công cụ", "",
                 f"File: {md_text(args.input.name)}", f"Định dạng: {md_text(args.format)}", "",
                 f"Tổng số bản ghi: {len(findings)}", "",
                 "Đây là bản chuẩn hóa dữ liệu, chưa dùng AI, chưa đề xuất sửa và chưa xác minh lỗ hổng.",
                 "Không có bản ghi không đồng nghĩa hệ thống an toàn. Giữ file gốc để đối chiếu.", "",
                 "| ID | Tên | Loại | Mức độ từ tool | CWE | Số mục bằng chứng |", "|---|---|---|---|---|---|"]
        for f in findings:
            lines.append(f"| {md_text(f.id)} | {md_text(f.title)} | {md_text(f.kind)} | {md_text(f.severity)} | {md_text(cwe_text(asdict(f)))} | {len(f.evidence)} |")
        lines += ["", "## Trường cần kiểm tra", "",
                  f"- Thiếu bằng chứng đính kèm: {sum(not f.evidence for f in findings)}",
                  f"- Không có CWE: {sum(not finding_cwes(f) for f in findings)}",
                  f"- Công cụ gắn nhiều CWE (chỉ được gợi ý khi mọi CWE cùng một nhóm Top 10): {sum(len(finding_cwes(f)) > 1 for f in findings)}",
                  f"- CWE gán theo quy tắc của dự án vì công cụ không ghi CWE: {sum(bool(f.details.get('cwe_mapping')) for f in findings)}",
                  f"- Quan sát, không tự xem là lỗ hổng: {sum(f.kind == 'observation' for f in findings)}",
                  "- Số mục bằng chứng chỉ là số trường đã lấy được, không đo độ mạnh bằng chứng.",
                  "- details giữ confidence, payload/request và lời khuyên của tool nếu có; chúng không tự trở thành nguồn OWASP.",
                  "", f"SHA-256 file gốc: `{input_sha}`", ""]
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "findings.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        (args.output / "import-summary.md").write_text("\n".join(lines), encoding="utf-8")
    except Exception as exc:
        p.exit(1, f"Import failed ({type(exc).__name__}): {exc}\n")
    print(f"Imported {len(findings)} records. AI calls = 0.")
    print(args.output.resolve() / "findings.json")
    print(args.output.resolve() / "import-summary.md")
