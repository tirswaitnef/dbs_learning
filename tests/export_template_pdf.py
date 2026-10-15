"""Export an existing report.json to the 7-section pentest template PDF. No AI calls."""
import argparse
import json
from pathlib import Path
from _bootstrap import ROOT
from rag.template_report import render_template_pdf

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True, type=Path)
    p.add_argument('--output', type=Path)
    p.add_argument('--client', default='[Chưa cung cấp]')
    p.add_argument('--tester', default='[Chưa cung cấp]')
    p.add_argument('--application', default='[Chưa cung cấp]')
    p.add_argument('--classification', default='CONFIDENTIAL')
    args = p.parse_args()
    output = args.output or args.input.with_name('report-template.pdf')
    try:
        report = json.loads(args.input.read_text(encoding='utf-8-sig'))
        if not isinstance(report, dict) or not isinstance(report.get('findings'), list):
            raise ValueError('Expected project report.json, not raw scanner output')
        output.parent.mkdir(parents=True, exist_ok=True)
        render_template_pdf(report, output, client=args.client, tester=args.tester,
                            application=args.application, classification=args.classification)
    except Exception as exc:
        p.exit(1, f'Template PDF export failed ({type(exc).__name__}): {exc}\n')
    print(output.resolve())
    print('AI calls = 0. Content is from existing report JSON.')
