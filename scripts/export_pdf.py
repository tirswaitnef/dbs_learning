"""Export an existing report.json to PDF without calling AI again."""
import argparse
import json
from pathlib import Path
from _bootstrap import ROOT
from rag.pdf_report import render_pdf

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', required=True, type=Path)
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    output = args.output or args.input.with_suffix('.pdf')
    try:
        if args.input.resolve() == output.resolve():
            raise ValueError('Output must not overwrite input JSON')
        report = json.loads(args.input.read_text(encoding='utf-8-sig'))
        if not isinstance(report, dict) or not isinstance(report.get('findings'), list):
            raise ValueError('Expected project report.json, not raw scanner output')
        output.parent.mkdir(parents=True, exist_ok=True)
        render_pdf(report, output)
    except Exception as exc:
        p.exit(1, f'PDF export failed ({type(exc).__name__}): {exc}\n')
    print(output.resolve())
    print('AI calls = 0. Content is from existing report JSON.')
