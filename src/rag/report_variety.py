"""Prose-variety checks: the report follows the input, it is not one template.

Three kinds of text are kept apart on purpose, because only one of them is
supposed to differ between records:

- **AI prose** (`ai_analysis` claims): must differ between different records, so
  this is what `duplicate_groups` and `prose_check` measure.
- **Code-generated text** (`analysis_vi` in the corpus branch): written by
  `official_report.build_corpus_report`, identical across records by
  construction. `prose_check` counts how many records share it instead of
  treating it as a fault.
- **Evidence** and **OWASP excerpts**: copied from the input/sources; equal
  evidence means the scans produced the same data, not that the AI repeated
  itself.

The measure is token-set overlap (Jaccard), not a semantic judgement: it shows
two reports are not copies of each other, it does not show the prose is correct.
"""
import re

SPLIT = re.compile(r'(?<=[.!?])\s+|\n+')
MIN_SENTENCE = 25  # shorter fragments are punctuation noise, not sentences


def sentences(text):
    """Sentence-ish fragments with enough content to compare."""
    out = []
    for piece in SPLIT.split(str(text or '')):
        piece = piece.strip()
        if len(piece) >= MIN_SENTENCE:
            out.append(piece)
    return out


def norm(text):
    return re.sub(r'\s+', ' ', re.sub(r'[^\w\s]', ' ', str(text or '').lower(), flags=re.UNICODE)).strip()


def similarity(left, right):
    """Token-set Jaccard of two strings; 0.0 when either side is empty."""
    a, b = set(norm(left).split()), set(norm(right).split())
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def ai_prose(row):
    """Only prose the model wrote for this record."""
    narrative = row.get('ai_analysis') or {}
    parts = []
    for section in ('observations', 'potential_impacts', 'limitations'):
        for claim in (narrative.get('claims') or {}).get(section) or []:
            parts.append(str(claim.get('text_vi') or ''))
    return ' '.join(part for part in parts if part)


def code_text(row):
    """Deterministic per-record sentence written by code, not by a model."""
    return str(row.get('analysis_vi') or '')


def evidence_text(row):
    return ' '.join(str(item) for item in row.get('evidence') or [])


def duplicate_groups(report, *, text_of=ai_prose, threshold=0.7):
    """Pairs of records whose given text looks like the same generated prose."""
    rows = [(str(row.get('id', '?')), text_of(row)) for row in report.get('findings') or []]
    rows = [(rid, text) for rid, text in rows if norm(text)]
    groups = []
    for i, (left_id, left) in enumerate(rows):
        for right_id, right in rows[i + 1:]:
            if similarity(left, right) < threshold:
                continue
            merged = next((g for g in groups if left_id in g or right_id in g), None)
            if merged is None:
                groups.append([left_id, right_id])
            else:
                merged.extend(x for x in (left_id, right_id) if x not in merged)
    # Keep report order so the reader sees records in the same order as the report.
    return [list(dict.fromkeys(group)) for group in groups]


def prose_check(report, threshold=0.7):
    """Stored in report.json so the duplicate check is visible, not hidden."""
    rows = [row for row in report.get('findings') or [] if norm(ai_prose(row))]
    groups = duplicate_groups(report, threshold=threshold) if len(rows) > 1 else []
    code_texts = [norm(code_text(row)) for row in report.get('findings') or [] if norm(code_text(row))]
    repeated_code = len(code_texts) - len(set(code_texts))
    status = 'duplicate_prose' if groups else ('no_ai_prose' if not rows else 'ok')
    return {'status': status, 'records_with_ai_prose': len(rows), 'duplicate_groups': groups,
            'records_sharing_code_generated_text': repeated_code,
            'threshold': threshold,
            'method': ('token-set Jaccard trên diễn giải do AI sinh cho từng bản ghi, ngưỡng '
                       f'{threshold}; không tính câu do code sinh, bằng chứng hay trích nguyên văn OWASP; '
                       'đo bằng code, không dùng AI và không đánh giá nội dung đúng/sai')}


def prose_line(probe):
    """One report line explaining the result, including the no-AI case."""
    if not probe.get('records_with_ai_prose') and not probe.get('records_sharing_code_generated_text'):
        return 'Kiểm tra trùng lặp văn bản: không có diễn giải AI cho từng bản ghi và câu do code sinh chưa lặp lại.'
    if probe.get('duplicate_groups'):
        return ('Kiểm tra trùng lặp văn bản đặc thù: phát hiện nhóm bản ghi có diễn giải AI gần giống nhau: '
                + '; '.join(', '.join(group) for group in probe['duplicate_groups']))
    if probe.get('status') == 'no_ai_prose':
        return (f"Kiểm tra trùng lặp văn bản: lần chạy này không có diễn giải AI cho từng bản ghi, nên không có "
                f"gì để so; {probe.get('records_sharing_code_generated_text', 0)} bản ghi dùng câu mô tả do code sinh "
                f"(giống nhau là đúng thiết kế, không phải lỗi AI lặp lại).")
    return ('Kiểm tra trùng lặp văn bản đặc thù: không có nhóm bản ghi nào có diễn giải AI gần giống nhau'
            + (f"; {probe['records_sharing_code_generated_text']} bản ghi dùng chung câu mô tả do code sinh."
               if probe.get('records_sharing_code_generated_text') else '.'))


def _overlap(left, right, text_of, limit=5):
    a = {norm(text) for text in (text_of(row) for row in left.get('findings') or []) if norm(text)}
    b = {norm(text) for text in (text_of(row) for row in right.get('findings') or []) if norm(text)}
    union = len(a | b)
    return (len(a & b) / union) if union else 0.0, sorted(a & b)[:limit]


def compare_reports(left, right, limit=5):
    """Overlap between two reports, split by where the text came from."""
    prose_overlap, shared_prose = _overlap(left, right, ai_prose, limit)
    code_overlap, _ = _overlap(left, right, code_text)
    evidence_overlap, shared_evidence = _overlap(left, right, evidence_text, limit)
    return {'ai_prose_overlap': prose_overlap, 'shared_ai_prose': shared_prose,
            'code_text_overlap': code_overlap,
            'evidence_overlap': evidence_overlap, 'shared_evidence': shared_evidence,
            'a_mode': str(left.get('mode') or ''), 'b_mode': str(right.get('mode') or ''),
            'method': 'Jaccard theo tập từ, tách riêng văn bản AI, câu do code sinh và bằng chứng'}
