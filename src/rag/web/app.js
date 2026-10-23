'use strict';

const TERMINAL = new Set(['completed', 'partial', 'failed']);
const STORAGE_KEY = 'dbsec-selected-job';
const IS_DEBUG = /^\/debug(?:\/|$)/i.test(window.location.pathname || '')
  || new URLSearchParams(window.location.search || '').get('debug') === '1';
const META_KEYS = [
  'report_id',
  'project_name',
  'target_object',
  'dbms_override',
  'assessment_period',
  'retest_status',
  'retest_evidence',
  'force_fresh_ai',
];

const PIPELINE_STEPS = [
  { num: 1, title: 'AI (Ollama) đọc trực tiếp dữ liệu đầu vào (Mục 1–2)', detail: 'Đọc linh hoạt mọi phiên bản log công cụ & Báo cáo Pentest, đối khớp bằng chứng gốc I-01+ / E-01+' },
  { num: 2, title: 'Nạp kho tri thức OWASP chuyên biệt CSDL (Mục 3)', detail: '25 OWASP Cheat Sheets & mô hình nhúng ngữ nghĩa E5' },
  { num: 3, title: 'Đối chiếu OWASP Top 10:2025 & Truy xuất RAG (Mục 6.4 & 7)', detail: 'Chọn đoạn hướng dẫn gốc & ví dụ mã an toàn phù hợp CWE' },
  { num: 4, title: 'Phân tích bằng chứng E-01+, nguyên nhân & tác động (Mục 6)', detail: 'Tách rõ bằng chứng thực nghiệm và giả thuyết tầng mã nguồn' },
  { num: 5, title: 'Tổng hợp ma trận 4.1, độ tin cậy & kết luận (Mục 4, 8, 9)', detail: 'Giữ nguyên mức độ gốc, không tự tạo số liệu hay khẳng định quá mức' },
  { num: 6, title: 'Kết xuất Báo cáo 10 mục chuẩn PDF, Markdown & JSON', detail: 'Đầy đủ Mục 1–10 kèm Phụ lục nguồn dữ liệu & tài liệu OWASP' },
];

const state = {
  token: document.querySelector('meta[name="app-token"]')?.content || '',
  config: null,
  jobs: [],
  selectedId: null,
  selectedFiles: [],
  pollTimer: null,
  clockTimer: null,
  toastTimer: null,
  traceCache: {},
  submitting: false,
  debugTab: 'eval',
  debugOverview: null,
  debugJobId: null,
  debugCommsSig: '',
};

const el = (id) => document.getElementById(id);

function create(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  file: [['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }], ['polyline', { points: '14 2 14 8 20 8' }], ['line', { x1: 16, y1: 13, x2: 8, y2: 13 }], ['line', { x1: 16, y1: 17, x2: 8, y2: 17 }]],
  bot: [
    ['ellipse', { cx: 12, cy: 5, rx: 8, ry: 3 }],
    ['path', { d: 'M4 5v6c0 1.66 3.58 3 8 3s8-1.34 8-3V5' }],
    ['path', { d: 'M4 11v6c0 1.66 3.58 3 8 3s8-1.34 8-3v-6' }],
  ],
  download: [['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }], ['polyline', { points: '7 10 12 15 17 10' }], ['line', { x1: 12, y1: 15, x2: 12, y2: 3 }]],
  eye: [['path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  clock: [['circle', { cx: 12, cy: 12, r: 10 }], ['polyline', { points: '12 6 12 12 16 14' }]],
};

function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.85');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  for (const [tag, attrs] of ICONS[name]) {
    const part = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) part.setAttribute(k, String(v));
    svg.appendChild(part);
  }
  return svg;
}

function formatBytes(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function formatClock(totalSec) {
  const sec = Math.max(0, Math.floor(totalSec));
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function formatDurationHuman(totalSec) {
  const sec = Math.max(0.1, Number(totalSec) || 0);
  if (sec < 60) return `${sec.toFixed(1)}s`;
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return `${m}p ${String(s).padStart(2, '0')}s`;
}

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleString('vi-VN', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' });
}

function formatEventTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString('vi-VN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function statusText(job) {
  if (job.status === 'queued') return 'Đang chờ xử lý';
  if (job.status === 'running') return `${job.percent || 10}% · ${job.stage || 'Đang phân tích'}`;
  if (job.status === 'completed') return 'Báo cáo 10 mục hoàn tất';
  if (job.status === 'partial') return 'Hoàn tất (một phần AI)';
  return 'Chưa hoàn tất';
}

function showToast(text) {
  const box = el('toast');
  box.textContent = text;
  box.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { box.hidden = true; }, 4200);
}

function setFormError(text) {
  const box = el('form-error');
  box.textContent = text || '';
  box.hidden = !text;
}

async function api(path, options = {}) {
  const headers = Object.assign({}, options.headers || {});
  if (state.token) headers['X-App-Token'] = state.token;
  const response = await fetch(path, Object.assign({}, options, { headers, credentials: 'same-origin' }));
  const type = response.headers.get('Content-Type') || '';
  const data = type.includes('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    const message = data && typeof data === 'object' && data.error ? data.error : 'Yêu cầu chưa thực hiện được.';
    const err = new Error(message);
    err.status = response.status;
    throw err;
  }
  return data;
}

function guessFormatByName(name) {
  const lower = (name || '').toLowerCase();
  if (lower.endsWith('.nessus')) return 'nessus';
  if (lower.endsWith('.jsonl')) return 'nuclei';
  if (lower.endsWith('.log') || lower.endsWith('.txt')) return 'sqlmap-log';
  return 'auto';
}

function updateSelectedFiles(incoming, append = true) {
  const list = Array.from(incoming || []).filter(Boolean);
  if (!append) state.selectedFiles = [];
  for (const f of list) {
    const dup = state.selectedFiles.some((x) => x.name === f.name && x.size === f.size && x.lastModified === f.lastModified);
    if (!dup && state.selectedFiles.length < 10) state.selectedFiles.push(f);
  }
  setFormError('');
  const wrap = el('file-list-wrap');
  const chips = el('file-chips');
  chips.replaceChildren();
  if (!state.selectedFiles.length) {
    wrap.hidden = true;
    return;
  }
  wrap.hidden = false;
  const totalBytes = state.selectedFiles.reduce((acc, f) => acc + f.size, 0);
  el('file-count-label').textContent = state.selectedFiles.length === 1
    ? `1 nguồn dữ liệu đầu vào (I-01) · ${formatBytes(totalBytes)}`
    : `${state.selectedFiles.length} nguồn dữ liệu (I-01..I-${String(state.selectedFiles.length).padStart(2, '0')}) · ${formatBytes(totalBytes)}`;

  state.selectedFiles.forEach((f, idx) => {
    const chip = create('div', 'single-chip');
    chip.appendChild(icon('file', 15));
    chip.appendChild(create('strong', '', `I-${String(idx + 1).padStart(2, '0')}: ${f.name}`));
    chip.appendChild(create('span', '', formatBytes(f.size)));
    const rm = create('button', '', '×');
    rm.type = 'button';
    rm.setAttribute('aria-label', `Bỏ tệp ${f.name}`);
    rm.addEventListener('click', () => {
      state.selectedFiles.splice(idx, 1);
      updateSelectedFiles([], true);
    });
    chip.appendChild(rm);
    chips.appendChild(chip);
  });
}

function renderBanner() {
  const banner = el('banner');
  const pill = el('mode-pill');
  banner.className = 'banner';
  if (!state.config) {
    banner.hidden = true;
    return;
  }
  if (state.config.demo) {
    pill.textContent = 'Chế độ Demo cục bộ';
    banner.classList.add('demo');
    banner.textContent = 'Đang chạy ở chế độ Demo cục bộ (không gọi LLM): phân loại OWASP Top 10:2025 và đối chiếu thẻ tri thức OWASP đã phê duyệt.';
    banner.hidden = false;
    return;
  }
  if (!state.config.configured) {
    pill.textContent = 'Chờ kết nối Ollama Local';
    banner.textContent = (state.config.issues || []).join(' ') || 'Hãy mở Ollama local (ollama serve) trước khi tạo báo cáo có phân tích AI.';
    banner.hidden = false;
    return;
  }
  const label = state.config.provider === 'ollama' ? `Ollama Local · ${state.config.model}` : `AI · ${state.config.model}`;
  pill.textContent = label;
  banner.hidden = true;
}

function renderHistory() {
  const nav = el('history');
  nav.replaceChildren();
  if (!state.jobs.length) {
    nav.appendChild(create('div', 'history-empty', 'Chưa có báo cáo nào. Hãy tải tệp kết quả kiểm thử để tạo báo cáo 10 mục.'));
    return;
  }
  for (const job of state.jobs) {
    const item = create('button', 'history-item' + (job.id === state.selectedId ? ' active' : ''));
    item.type = 'button';
    const dot = create('span', `status-dot ${job.status}`);
    const body = create('div', 'history-body');
    body.appendChild(create('strong', '', job.filename));
    body.appendChild(create('span', '', `${statusText(job)} · ${formatTime(job.created_at)}`));
    item.append(dot, body);
    item.addEventListener('click', () => selectJob(job.id));
    nav.appendChild(item);
  }
}

function assistantAvatar() {
  const wrap = create('div', 'message-avatar');
  wrap.appendChild(icon('bot', 18));
  return wrap;
}

function renderEventList(events) {
  const ul = create('ul', 'event-list');
  const items = (events || []).slice(-18);
  for (const ev of items) {
    const li = create('li');
    li.appendChild(create('span', 'event-time', formatEventTime(ev.at)));
    li.appendChild(create('span', '', ev.text || ''));
    ul.appendChild(li);
  }
  return ul;
}

async function fetchJobTrace(jobId, force = false) {
  const existing = state.traceCache[jobId];
  if (existing && existing.loading) return;
  if (existing && existing.done && !force) return;
  state.traceCache[jobId] = Object.assign({}, existing || {}, { loading: true });
  try {
    const q = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
    const data = await api(`/api/jobs/${jobId}/trace${q}`);
    const currentJob = state.jobs.find((j) => j.id === jobId);
    const isDone = Boolean(currentJob && TERMINAL.has(currentJob.status));
    state.traceCache[jobId] = { data, loading: false, done: isDone };
    renderWorkspace();
  } catch (_) {
    state.traceCache[jobId] = { data: null, loading: false, done: false };
  }
}

function buildTracePanel(job, opts = {}) {
  const details = create('details', 'event-panel trace-panel');
  const cached = state.traceCache[job.id];
  const entries = (cached && cached.data && cached.data.entries) || [];
  const fromCache = Boolean(cached && cached.data && cached.data.from_cache);
  if (opts.alwaysOpen || job.status === 'running' || entries.length > 0) details.open = true;

  const countLabel = cached && cached.data
    ? (fromCache
      ? `${entries.length} lượt gọi AI (tái sử dụng từ Cache SHA-256)`
      : `${entries.length} lượt gọi trực tiếp mô hình AI`)
    : 'Nhấn để tải chi tiết';
  details.appendChild(create('summary', '', `Chi tiết câu lệnh gửi mô hình AI & phản hồi nguyên văn (${countLabel})`));

  const wrap = create('div', 'trace-body');
  const qTok = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
  const topBar = create('div', 'trace-topbar');
  const modeInfo = create('span', 'trace-mode-info',
    fromCache
      ? 'Báo cáo này dùng lại kết quả AI đã lưu theo SHA-256. Để buộc gọi mới Ollama từng bước, chọn "Luôn gọi trực tiếp Ollama mới" trong khung tùy chọn.'
      : (job.demo
        ? 'Chế độ Demo cục bộ không gửi câu lệnh sang LLM.'
        : 'Ghi nhận đầy đủ System Prompt, User Payload (JSON) và phản hồi JSON nguyên văn của mô hình AI.'));
  topBar.appendChild(modeInfo);

  const dlTrace = create('a', 'json-link trace-dl', 'Tải bản ghi lệnh AI (.txt)');
  dlTrace.href = `/api/jobs/${job.id}/trace-txt${qTok}`;
  dlTrace.download = `lenh-gui-ai-${job.id.slice(0, 8)}.txt`;
  topBar.appendChild(dlTrace);
  wrap.appendChild(topBar);

  if (!cached || cached.loading) {
    wrap.appendChild(create('p', 'muted', 'Đang tải chi tiết lệnh gửi AI...'));
    details.appendChild(wrap);
    if (!cached) fetchJobTrace(job.id);
    return details;
  }

  if (!entries.length) {
    wrap.appendChild(create('p', 'muted',
      job.demo
        ? 'Không có lượt gọi LLM nào trong phiên Demo.'
        : 'Đang chờ lượt gọi mô hình AI đầu tiên hoặc đầu vào không có phát hiện cần gọi AI.'));
    details.appendChild(wrap);
    return details;
  }

  for (const item of entries) {
    const card = create('div', `trace-item trace-${item.status || 'ok'}`);
    const head = create('div', 'trace-item-head');
    head.appendChild(create('strong', '', `#${item.seq} · ${item.step || 'Gọi mô hình AI'}`));
    const statusBadge = item.status === 'running'
      ? 'Đang chờ AI trả lời...'
      : item.status === 'ok'
        ? `Hoàn tất · ${(item.duration_ms / 1000).toFixed(1)}s`
        : `${item.status} · ${(item.duration_ms / 1000).toFixed(1)}s`;
    head.appendChild(create('span', `trace-pill trace-${item.status || 'ok'}`, statusBadge));
    card.appendChild(head);

    card.appendChild(create('div', 'trace-meta',
      `${item.endpoint || ''} · Model: ${item.model || ''} · Tham số: ${JSON.stringify(item.options || {})}`));

    const sysBox = create('details', 'trace-sub');
    sysBox.appendChild(create('summary', '', '1. Lệnh hệ thống (System Prompt)'));
    sysBox.appendChild(create('pre', 'trace-pre', item.system_prompt || ''));
    card.appendChild(sysBox);

    const usrBox = create('details', 'trace-sub');
    usrBox.appendChild(create('summary', '', '2. Dữ liệu đầu vào gửi AI (User Prompt JSON)'));
    usrBox.appendChild(create('pre', 'trace-pre', item.user_prompt || ''));
    card.appendChild(usrBox);

    const outBox = create('details', 'trace-sub');
    if (item.status === 'running' || entries.length <= 6) outBox.open = true;
    outBox.appendChild(create('summary', '', '3. Phản hồi nguyên văn từ AI (Raw JSON Output)'));
    outBox.appendChild(create('pre', 'trace-pre', item.raw_response || item.error || '(Đang sinh phản hồi...)'));
    card.appendChild(outBox);

    wrap.appendChild(card);
  }
  details.appendChild(wrap);
  return details;
}

function buildLiveProgressCard(job) {
  const process = create('div', 'process');
  const head = create('div', 'process-header');
  const titleWrap = create('div', 'process-title');
  titleWrap.append(create('span', 'spinner'), create('strong', '', job.stage || 'Đang khởi tạo...'));

  const badges = create('div', 'process-badges');
  const pct = Math.max(5, Math.min(99, Number(job.percent) || 8));
  badges.appendChild(create('span', 'pct-pill', `${pct}%`));

  const timerPill = create('span', 'timer-pill');
  timerPill.dataset.startedAt = job.started_at || job.created_at || '';
  timerPill.appendChild(icon('clock', 13));
  const elapsedSec = Math.max(0, (Date.now() - new Date(timerPill.dataset.startedAt).getTime()) / 1000);
  const timerTxt = create('span', 'timer-val', formatClock(elapsedSec));
  timerPill.appendChild(timerTxt);
  badges.appendChild(timerPill);

  head.append(titleWrap, badges);
  process.appendChild(head);

  const meter = create('progress', 'progress-meter');
  meter.max = 100;
  meter.value = pct;
  process.appendChild(meter);

  const curStep = Math.max(1, Math.min(6, Number(job.step) || 1));
  const grid = create('ol', 'pipeline-steps');
  for (const s of PIPELINE_STEPS) {
    const cls = s.num < curStep ? 'step-card done' : (s.num === curStep ? 'step-card current' : 'step-card');
    const li = create('li', cls);
    li.appendChild(create('span', 'step-num', s.num < curStep ? '✓' : String(s.num)));
    const meta = create('div', 'step-meta');
    meta.appendChild(create('strong', '', `${s.num}. ${s.title}`));
    meta.appendChild(create('small', '', s.detail));
    li.appendChild(meta);
    grid.appendChild(li);
  }
  process.appendChild(grid);

  if (!job.demo) {
    process.appendChild(create('p', 'cpu-hint',
      'Mẹo: Lần chạy đầu tiên nạp kho 25 OWASP Cheat Sheets & mô hình E5 mất khoảng 15–30s; các tệp cùng mã SHA-256 sau đó được xuất tức thì.'));
  }

  if ((job.events || []).length) {
    const logBox = create('div', 'event-log-box');
    const logHead = create('div', 'event-log-head');
    logHead.appendChild(create('span', '', 'Tiến trình xử lý thời gian thực'));
    logHead.appendChild(create('span', '', `${job.events.length} mốc`));
    logBox.append(logHead, renderEventList(job.events));
    process.appendChild(logBox);
  }
  if (IS_DEBUG) process.appendChild(buildTracePanel(job));
  return process;
}

function buildCompletedCard(job) {
  const s = job.summary || {};
  const card = create('div', 'download-card');

  const head = create('div', 'report-head');
  const left = create('div', 'report-head-left');
  const badge = create('div', 'pdf-icon');
  badge.appendChild(icon('file', 22));
  const titleInfo = create('div');
  titleInfo.appendChild(create('strong', '', 'Báo cáo Kiểm thử Bảo mật CSDL & Đề xuất Remediation theo OWASP'));
  const formatName = (state.config && state.config.formats && state.config.formats[job.format]) || job.format;
  titleInfo.appendChild(create('p', '',
    `Định dạng gốc: ${formatName} · Khung chuẩn 10 mục (Mục 1 → Mục 10) · Hoàn tất lúc ${formatTime(job.updated_at)}`));
  left.append(badge, titleInfo);
  head.appendChild(left);

  if (job.input_sha256) {
    head.appendChild(create('span', 'sha-tag', `SHA-256: ${job.input_sha256.slice(0, 12)}…`));
  }
  card.appendChild(head);

  const metrics = create('div', 'metrics');
  const confirmedNum = s.confirmed_findings !== undefined ? s.confirmed_findings : (s.findings ?? job.count ?? 0);
  const unconfirmedNum = (s.tentative_findings ?? 0) + (s.insufficient_findings ?? 0);
  const metricItems = [
    [String(confirmedNum), 'Phát hiện Đã xác nhận (Mục 4.1)'],
    [String(unconfirmedNum), 'Có dấu hiệu / Chưa đủ DL (Mục 4.1)'],
    [String(s.with_guidance ?? 0), 'Mục có tham chiếu OWASP (Mục 7)'],
    [formatDurationHuman(s.duration_sec || 0), 'Tổng thời gian xử lý'],
  ];
  for (const [val, label] of metricItems) {
    const m = create('div', 'metric');
    m.appendChild(create('strong', '', val));
    m.appendChild(create('span', '', label));
    metrics.appendChild(m);
  }
  card.appendChild(metrics);

  const preview = s.findings_preview || [];
  if (preview.length) {
    const wrap = create('div', 'preview-wrap');
    wrap.appendChild(create('div', 'preview-title', `Mục 5 — Danh sách phát hiện (${preview.length} mục F-01..F-${String(preview.length).padStart(2, '0')})`));
    for (const f of preview) {
      const row = create('div', 'preview-row');
      const main = create('div', 'preview-main');
      const sevKey = (f.severity || 'unknown').toLowerCase();
      const sevLabel = f.severity_label || sevKey.toUpperCase();
      main.appendChild(create('span', `sev-badge sev-${sevKey}`, sevLabel));
      main.appendChild(create('strong', '', `${f.id}: ${f.title || 'Phát hiện'}`));

      const tags = create('div', 'preview-tags');
      if (f.state) {
        const stCls = f.state === 'Đã xác nhận' ? 'tag-mini ok' : 'tag-mini warn';
        tags.appendChild(create('span', stCls, f.state));
      }
      if (f.owasp) tags.appendChild(create('span', 'tag-mini', f.owasp));
      if (f.guidance_count > 0) {
        tags.appendChild(create('span', 'tag-mini ok', `${f.guidance_count} tài liệu OWASP`));
      }
      row.append(main, tags);
      wrap.appendChild(row);
    }
    card.appendChild(wrap);
  }

  const actions = create('div', 'download-actions');
  const qTok = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
  const qInline = state.token ? `?inline=1&token=${encodeURIComponent(state.token)}` : '?inline=1';

  const dl = create('a', 'download');
  dl.href = `/api/jobs/${job.id}/pdf${qTok}`;
  dl.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.pdf`;
  dl.append(icon('download', 15), create('span', '', 'Tải Báo cáo PDF (10 mục)'));

  const viewBtn = create('a', 'download secondary');
  viewBtn.href = `/api/jobs/${job.id}/pdf${qInline}`;
  viewBtn.target = '_blank';
  viewBtn.rel = 'noopener';
  viewBtn.append(icon('eye', 15), create('span', '', 'Mở xem PDF trực tiếp'));

  const mdLink = create('a', 'json-link', 'Tải Markdown (.md)');
  mdLink.href = `/api/jobs/${job.id}/md${qTok}`;
  mdLink.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.md`;

  const jsonLink = create('a', 'json-link', 'Tải JSON chuẩn hóa');
  jsonLink.href = `/api/jobs/${job.id}/json${qTok}`;
  jsonLink.download = `du-lieu-bao-cao-${job.id.slice(0, 8)}.json`;

  const syncLogLink = create('a', 'json-link', 'Tải dữ liệu đã che nhạy cảm');
  syncLogLink.href = `/api/jobs/${job.id}/log${qTok}`;
  syncLogLink.download = `du-lieu-da-lam-sach-${job.id.slice(0, 8)}.txt`;

  actions.append(dl, viewBtn, mdLink, jsonLink, syncLogLink);
  card.appendChild(actions);
  return card;
}

function renderMessageForJob(job) {
  const fragment = document.createDocumentFragment();

  const user = create('div', 'message user');
  const userBody = create('div', 'message-body');
  userBody.appendChild(create('div', 'message-name', 'Nguồn dữ liệu kiểm thử đầu vào'));
  const fileCard = create('div', 'upload-card');
  const formatName = (state.config && state.config.formats && state.config.formats[job.format]) || job.format;
  fileCard.appendChild(icon('file', 22));
  const meta = create('div');
  meta.appendChild(create('strong', '', job.filename));
  meta.appendChild(create('span', '', `${formatName} · ${formatBytes(job.size)} · ${job.count} bản ghi phát hiện`));
  fileCard.appendChild(meta);
  userBody.appendChild(fileCard);
  if (job.note) userBody.appendChild(create('p', '', `Phạm vi / Ghi chú: ${job.note}`));
  user.appendChild(userBody);
  fragment.appendChild(user);

  const bot = create('div', 'message assistant');
  bot.appendChild(assistantAvatar());
  const body = create('div', 'message-body');
  body.appendChild(create('div', 'message-name', 'DBSec OWASP · Bộ phân tích & xuất báo cáo 10 mục'));

  if (!TERMINAL.has(job.status)) {
    body.appendChild(create('p', '',
      'Đang chuẩn hóa dữ liệu đầu vào (I-01+), trích xuất bằng chứng (E-01+), đối chiếu OWASP Top 10:2025 & Cheat Sheet Series và kết xuất báo cáo 10 mục:'));
    body.appendChild(buildLiveProgressCard(job));
  } else if (job.status === 'failed') {
    body.appendChild(create('p', 'failure', job.error || 'Chưa tạo được báo cáo từ tệp đầu vào này.'));
    if ((job.events || []).length) {
      const details = create('details', 'event-panel');
      details.open = true;
      details.appendChild(create('summary', '', `Chi tiết các bước trước khi dừng (${job.events.length} mốc)`));
      details.appendChild(renderEventList(job.events));
      body.appendChild(details);
    }
    if (IS_DEBUG) body.appendChild(buildTracePanel(job));
    const retry = create('button', 'again', 'Tải tệp khác để tạo báo cáo mới');
    retry.type = 'button';
    retry.addEventListener('click', showNewReport);
    body.appendChild(retry);
  } else {
    const s = job.summary || {};
    const intro = job.demo
      ? `Đã hoàn tất báo cáo 10 mục ở chế độ Demo cục bộ cho ${s.findings ?? job.count} phát hiện.`
      : `Đã hoàn tất phân tích & kết xuất Báo cáo Kiểm thử Bảo mật CSDL & Đề xuất Remediation theo OWASP (10 mục) cho ${s.findings ?? job.count} phát hiện.`;
    body.appendChild(create('p', '', intro));
    if (job.status === 'partial') {
      body.appendChild(create('p', 'result-warning',
        `Một số mục diễn giải AI chưa hoàn tất (AI đã kiểm chứng: ${s.ai_reviewed ?? 0}/${s.findings ?? 0}). Các bảng thống kê, bằng chứng E-xx và trích đoạn OWASP gốc vẫn đầy đủ 100%.`));
    }
    body.appendChild(buildCompletedCard(job));

    if ((job.events || []).length) {
      const details = create('details', 'event-panel');
      details.appendChild(create('summary', '', `Xem tiến trình thực thi chi tiết (${job.events.length} mốc)`));
      details.appendChild(renderEventList(job.events));
      body.appendChild(details);
    }
    if (IS_DEBUG) body.appendChild(buildTracePanel(job));

    const again = create('button', 'again', '＋ Phân tích & tạo báo cáo mới');
    again.type = 'button';
    again.addEventListener('click', showNewReport);
    body.appendChild(again);
  }

  bot.appendChild(body);
  fragment.appendChild(bot);
  return fragment;
}

function syncElapsedClock() {
  const pill = document.querySelector('.timer-pill');
  if (!pill || !pill.dataset.startedAt) return;
  const valEl = pill.querySelector('.timer-val');
  if (!valEl) return;
  const elapsedSec = Math.max(0, (Date.now() - new Date(pill.dataset.startedAt).getTime()) / 1000);
  valEl.textContent = formatClock(elapsedSec);
}

function renderWorkspace() {
  const job = state.jobs.find((item) => item.id === state.selectedId) || null;
  el('empty-state').hidden = Boolean(job);
  el('info-cards').hidden = Boolean(job);
  el('privacy-note').hidden = Boolean(job);
  el('upload-form').hidden = Boolean(job);
  const messages = el('messages');
  messages.hidden = !job;
  messages.replaceChildren();
  if (job) messages.appendChild(renderMessageForJob(job));
  renderHistory();
  if (IS_DEBUG) renderDebugComms(false);
}

function showNewReport() {
  state.selectedId = null;
  localStorage.removeItem(STORAGE_KEY);
  closeSidebar();
  renderWorkspace();
}

function selectJob(id) {
  state.selectedId = id;
  if (IS_DEBUG) state.debugJobId = id;
  localStorage.setItem(STORAGE_KEY, id);
  closeSidebar();
  renderWorkspace();
}

async function refreshJobs() {
  try {
    state.jobs = await api('/api/jobs');
    if (state.selectedId && !state.jobs.some((j) => j.id === state.selectedId)) state.selectedId = null;
    if (IS_DEBUG) {
      const targetId = state.selectedId || state.debugJobId || (state.jobs[0] && state.jobs[0].id) || null;
      if (targetId) {
        const sel = state.jobs.find((j) => j.id === targetId);
        if (sel && !TERMINAL.has(sel.status)) fetchJobTrace(sel.id, true);
        else if (sel && (!state.traceCache[sel.id] || !state.traceCache[sel.id].done)) fetchJobTrace(sel.id, true);
      }
    }
    renderWorkspace();
    schedulePoll();
  } catch (err) {
    if (err.status === 401) await loadConfig();
  }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  const active = state.jobs.some((job) => !TERMINAL.has(job.status));
  state.pollTimer = setTimeout(refreshJobs, active ? 1000 : 12000);
}

function collectMetadata() {
  const out = {};
  for (const key of META_KEYS) {
    const input = el(`meta-${key}`);
    const value = input ? input.value.trim() : '';
    if (value) out[key] = value;
  }
  return out;
}

function resetForm() {
  el('file-input').value = '';
  el('note').value = '';
  for (const key of META_KEYS) {
    const input = el(`meta-${key}`);
    if (!input) continue;
    input.value = (IS_DEBUG && key === 'force_fresh_ai') ? '1' : '';
  }
  updateSelectedFiles([], false);
}

function fileToBase64(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      const s = String(reader.result || '');
      const comma = s.indexOf(',');
      resolve(comma >= 0 ? s.slice(comma + 1) : s);
    };
    reader.onerror = () => reject(new Error(`Không đọc được tệp ${file.name}`));
    reader.readAsDataURL(file);
  });
}

async function submitReport(event) {
  event.preventDefault();
  if (state.submitting) return;
  const files = state.selectedFiles;
  if (!files.length) {
    setFormError('Vui lòng chọn ít nhất một tệp kết quả kiểm thử để tạo báo cáo.');
    return;
  }
  const maxBytes = (state.config && state.config.max_bytes) || 10 * 1024 * 1024;
  const totalBytes = files.reduce((s, f) => s + f.size, 0);
  if (totalBytes <= 0 || totalBytes > maxBytes) {
    setFormError('Tổng dung lượng tệp đầu vào phải lớn hơn 0 và không vượt quá 10 MB.');
    return;
  }
  state.submitting = true;
  el('submit-btn').disabled = true;
  setFormError('');
  try {
    const chosenFmt = el('format').value;
    const params = new URLSearchParams({
      filename: files.map((f) => f.name).join(' + '),
      format: chosenFmt,
      note: el('note').value.trim(),
      metadata: JSON.stringify(collectMetadata()),
    });
    let job;
    if (files.length === 1) {
      job = await api(`/api/jobs?${params}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: await files[0].arrayBuffer(),
      });
    } else {
      params.set('bundle', '1');
      const encoded = await Promise.all(files.map(async (f) => ({
        filename: f.name,
        format: chosenFmt === 'auto' ? guessFormatByName(f.name) : chosenFmt,
        content_b64: await fileToBase64(f),
      })));
      job = await api(`/api/jobs?${params}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify({ bundle_version: 1, files: encoded }),
      });
    }
    resetForm();
    state.jobs = [job, ...state.jobs.filter((item) => item.id !== job.id)];
    selectJob(job.id);
    showToast('Đã tiếp nhận dữ liệu đầu vào · Đang tạo Báo cáo 10 mục chuẩn OWASP...');
    schedulePoll();
  } catch (err) {
    setFormError(err.message);
  } finally {
    state.submitting = false;
    el('submit-btn').disabled = false;
  }
}

async function loadConfig() {
  const initTok = document.querySelector('meta[name="app-token"]')?.content || '';
  if (initTok && !state.token) state.token = initTok;
  state.config = await api('/api/config');
  state.token = state.config.token;
  renderBanner();
}

function openSidebar() {
  el('sidebar').classList.add('open');
  el('backdrop').hidden = false;
}

function closeSidebar() {
  el('sidebar').classList.remove('open');
  el('backdrop').hidden = true;
}

function wireEvents() {
  el('pick-file').addEventListener('click', () => el('file-input').click());
  el('file-input').addEventListener('change', (e) => {
    updateSelectedFiles(e.target.files, true);
    e.target.value = '';
  });
  el('clear-file').addEventListener('click', () => {
    el('file-input').value = '';
    updateSelectedFiles([], false);
  });
  el('upload-form').addEventListener('submit', submitReport);
  el('new-chat').addEventListener('click', showNewReport);
  el('mobile-new').addEventListener('click', showNewReport);
  el('brand-link').addEventListener('click', (e) => { e.preventDefault(); showNewReport(); });
  el('open-sidebar').addEventListener('click', openSidebar);
  el('close-sidebar').addEventListener('click', closeSidebar);
  el('backdrop').addEventListener('click', closeSidebar);

  const zone = el('dropzone');
  ['dragenter', 'dragover'].forEach((type) => zone.addEventListener(type, (e) => {
    e.preventDefault();
    zone.classList.add('dragging');
  }));
  ['dragleave', 'drop'].forEach((type) => zone.addEventListener(type, (e) => {
    e.preventDefault();
    zone.classList.remove('dragging');
  }));
  zone.addEventListener('drop', (e) => {
    if (e.dataTransfer.files && e.dataTransfer.files.length) updateSelectedFiles(e.dataTransfer.files, true);
  });

  state.clockTimer = setInterval(syncElapsedClock, 1000);
}

function pctText(v) {
  return `${(Number(v || 0) * 100).toFixed(1)}%`;
}

function buildDebugTable(headers, rows) {
  const wrap = create('div', 'debug-table-wrap');
  const table = create('table', 'debug-table');
  const thead = create('thead');
  const trHead = create('tr');
  for (const h of headers) trHead.appendChild(create('th', '', h));
  thead.appendChild(trHead);
  table.appendChild(thead);

  const tbody = create('tbody');
  for (const row of rows) {
    const tr = create('tr', row.highlight ? 'highlight-row' : '');
    for (const cell of row.cells) {
      const td = create('td');
      if (cell instanceof Node) td.appendChild(cell);
      else td.textContent = String(cell ?? '');
      tr.appendChild(td);
    }
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  wrap.appendChild(table);
  return wrap;
}

function renderDebugEvaluation(payload) {
  const host = el('debug-eval-content');
  if (!host || !payload || !payload.evaluation) return;
  host.replaceChildren();

  const ev = payload.evaluation;
  const pruned = ev.pruned_db_corpus || {};
  const methods = pruned.methods || {};
  const hyb = methods.hybrid_rrf || {};
  const den = methods.dense_only || {};
  const comp = ev.pruning_comparison || null;
  const guard = ev.guardrails || {};
  const rt = payload.runtime || {};

  const rtLabel = el('debug-runtime-label');
  if (rtLabel) {
    const llmDesc = rt.demo ? 'Chế độ Demo cục bộ' : `${rt.provider || 'ollama'} · ${rt.model || 'qwen2.5'}`;
    rtLabel.textContent = `LLM: ${llmDesc} · Vector: ${pruned.encoder || rt.embed_model || 'E5'} · Kho OWASP CSDL: ${pruned.document_count || 25} tệp (${pruned.chunk_count || 0} chunks)`;
  }

  const metaLine = create('div', 'debug-meta-line');
  metaLine.appendChild(create('span', '',
    `Bộ kiểm chuẩn: ${ev.benchmark_query_count || 24} kịch bản CSDL & Web-to-DB thực tế · Đo lúc ${formatTime(payload.computed_at)} (${payload.wall_ms} ms trên máy chủ)`));
  metaLine.appendChild(create('span', '', payload.cached ? 'Nguồn: Cache phiên máy chủ' : 'Nguồn: Vừa đo trực tiếp trên máy chủ'));
  host.appendChild(metaLine);

  const kpis = create('div', 'debug-kpi-grid');
  const mrrGain = ((Number(hyb.doc_mrr || 0) - Number(den.doc_mrr || 0)) * 100).toFixed(2);
  const kpiItems = [
    [
      pctText(hyb.doc_hit_at_1),
      `Hybrid Doc Hit@1 (MRR ${Number(hyb.doc_mrr || 0).toFixed(4)})`,
      `Tăng +${mrrGain} điểm % MRR so với Dense thuần`,
    ],
    [
      comp ? `-${Number(comp.sheet_reduction_pct || 0).toFixed(1)}%` : '25 tệp',
      'Thu gọn nhiễu Kho OWASP CSDL',
      comp ? `137 tệp gốc → ${pruned.document_count} tệp CSDL (${comp.hybrid_latency_speedup_x}x nhanh hơn)` : `${pruned.chunk_count} chunks chuyên biệt`,
    ],
    [
      pctText(guard.f1),
      'F1-Score Trích xuất & Ánh xạ CWE',
      `Precision ${pctText(guard.precision)} · Recall ${pctText(guard.recall)} · CWE ${pctText(guard.cwe_accuracy)}`,
    ],
    [
      `${guard.hallucinations_blocked || 0}/${guard.hallucinations_injected || 0} (${pctText(guard.hallucination_block_rate)})`,
      'Chặn Ảo giác Đối kháng AI',
      'Tự động hạ mức độ bịa về Chưa xác định & lọc trích dẫn giả',
    ],
  ];
  for (const [val, title, sub] of kpiItems) {
    const box = create('div', 'debug-kpi');
    box.appendChild(create('strong', '', val));
    box.appendChild(create('span', '', title));
    box.appendChild(create('small', '', sub));
    kpis.appendChild(box);
  }
  host.appendChild(kpis);

  host.appendChild(create('div', 'debug-section-title',
    'Bảng 1 — Thực nghiệm Ablation 4 kiến trúc truy xuất trên kho 25 OWASP Cheat Sheets CSDL'));
  const order = ['dense_only', 'bm25_plain', 'bm25_heading', 'hybrid_rrf'];
  const ablationRows = order.filter((k) => methods[k]).map((k) => {
    const m = methods[k];
    return {
      highlight: k === 'hybrid_rrf',
      cells: [
        m.label,
        pctText(m.doc_hit_at_1),
        pctText(m.doc_hit_at_3),
        pctText(m.doc_hit_at_5),
        Number(m.doc_mrr || 0).toFixed(4),
        pctText(m.sec_hit_at_1),
        pctText(m.sec_hit_at_3),
        Number(m.sec_mrr || 0).toFixed(4),
        `${Number(m.avg_latency_ms || 0).toFixed(2)} ms`,
      ],
    };
  });
  host.appendChild(buildDebugTable(
    ['Phương pháp truy xuất', 'Doc Hit@1', 'Doc Hit@3', 'Doc Hit@5', 'Doc MRR', 'Sec Hit@1', 'Sec Hit@3', 'Sec MRR', 'Độ trễ TB'],
    ablationRows,
  ));

  if (comp && comp.full_corpus) {
    const full = comp.full_corpus;
    const fDen = (full.methods && full.methods.dense_only) || {};
    const fHyb = (full.methods && full.methods.hybrid_rrf) || {};
    host.appendChild(create('div', 'debug-section-title',
      'Bảng 2 — Hiệu quả thu gọn kho tri thức OWASP chuyên biệt CSDL (137 tệp đầy đủ vs 25 tệp CSDL)'));
    host.appendChild(buildDebugTable(
      ['Chỉ số đo lường', `Kho OWASP Đầy đủ (${full.document_count} tệp)`, `Kho OWASP CSDL (${pruned.document_count} tệp)`, 'Mức cải thiện thực nghiệm'],
      [
        { cells: ['Số lượng tệp Cheat Sheet (.md)', `${full.document_count} tệp`, `${pruned.document_count} tệp`, `Giảm ${comp.sheet_reduction_pct}% tài liệu ngoài phạm vi CSDL`] },
        { cells: ['Dung lượng văn bản nạp chỉ mục', formatBytes(full.total_bytes || 0), formatBytes(pruned.total_bytes || 0), `Giảm ${comp.bytes_reduction_pct}% dung lượng`] },
        { cells: ['Tổng số Chunks vector hóa', `${full.chunk_count} chunks`, `${pruned.chunk_count} chunks`, `Giảm ${comp.chunk_reduction_pct}% không gian tìm kiếm`] },
        { cells: ['Dense Cosine Doc MRR', Number(fDen.doc_mrr || 0).toFixed(4), Number(den.doc_mrr || 0).toFixed(4), `${((den.doc_mrr - fDen.doc_mrr) * 100 >= 0 ? '+' : '') + ((den.doc_mrr - fDen.doc_mrr) * 100).toFixed(2)} điểm %`] },
        { highlight: true, cells: ['Hybrid RRF Doc MRR', Number(fHyb.doc_mrr || 0).toFixed(4), Number(hyb.doc_mrr || 0).toFixed(4), `+${((hyb.doc_mrr - fHyb.doc_mrr) * 100).toFixed(2)} điểm % · Nhanh hơn ${comp.hybrid_latency_speedup_x}x`] },
      ],
    ));
  }

  host.appendChild(create('div', 'debug-section-title',
    'Bảng 3 — Kiểm chứng độ chính xác trích xuất AI, tương quan đa nguồn (Nmap + ZAP) & chống ảo giác'));
  host.appendChild(buildDebugTable(
    ['Hạng mục kiểm chứng bảo vệ tính trung thực báo cáo', 'Kết quả đo lường'],
    [
      { cells: ['Precision / Recall / F1-Score trích xuất phát hiện kiểm thử', `${pctText(guard.precision)} / ${pctText(guard.recall)} / ${pctText(guard.f1)} (TP=${guard.true_positives}, FP=${guard.false_positives}, FN=${guard.false_negatives})`] },
      { cells: ['Độ chính xác phân loại mã CWE & trạng thái xác minh (Đã xác nhận / Có dấu hiệu / Không xác nhận được)', `CWE: ${pctText(guard.cwe_accuracy)} · Trạng thái: ${pctText(guard.state_accuracy)}`] },
      { highlight: true, cells: ['Tỷ lệ chặn đứng ảo giác đối kháng (Severity tự bịa + Trích dẫn không có trong tệp gốc)', `${guard.hallucinations_blocked}/${guard.hallucinations_injected} (${pctText(guard.hallucination_block_rate)})`] },
    ],
  ));
}

async function loadDebugOverview(forceRefresh = false) {
  if (!IS_DEBUG) return;
  const btn = el('debug-run-eval');
  if (btn) btn.disabled = true;
  try {
    const q = forceRefresh ? '?refresh=1' : '';
    const data = await api(`/api/debug/overview${q}`);
    state.debugOverview = data;
    renderDebugEvaluation(data);
    if (forceRefresh) {
      showToast(`Đã chạy lại toàn bộ thực nghiệm định lượng trên máy chủ trong ${data.wall_ms} ms.`);
    }
  } catch (err) {
    const host = el('debug-eval-content');
    if (host) host.textContent = `Không tải được số liệu debug: ${err.message || err}`;
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function runDebugPlaygroundQuery(event) {
  if (event) event.preventDefault();
  if (!IS_DEBUG) return;
  const out = el('debug-query-results');
  if (!out) return;
  const query = (el('debug-q-input')?.value || '').trim();
  const cwe = (el('debug-cwe-input')?.value || '').trim();
  const stackHint = (el('debug-stack-input')?.value || '').trim();
  if (!query) return;

  out.replaceChildren(create('div', 'debug-loading', 'Đang chạy đối chiếu Dense vs Heading-BM25 vs Hybrid RRF...'));
  try {
    const res = await api('/api/debug/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, cwe, stack_hint: stackHint, top_k: 6 }),
    });
    out.replaceChildren();
    const expBox = create('div', 'expanded-box');
    expBox.appendChild(create('strong', '',
      `Mở rộng truy vấn tự động (${(res.expanded_queries || []).length} sub-queries · Độ trễ ${res.latency_ms} ms · Encoder: ${res.encoder}):`));
    const ul = create('ul');
    for (const sq of (res.expanded_queries || [])) ul.appendChild(create('li', '', sq));
    expBox.appendChild(ul);
    out.appendChild(expBox);

    const rows = (res.results || []).map((r) => {
      const titleCell = create('div');
      const link = create('a', 'json-link', r.source);
      link.href = r.url;
      link.target = '_blank';
      link.rel = 'noopener';
      titleCell.appendChild(link);
      titleCell.appendChild(create('div', 'hit-snippet', `Mục: ${r.section}`));
      titleCell.appendChild(create('div', 'hit-snippet', r.snippet));

      const rankBadge = create('span', r.rank === 1 ? 'rank-pill top' : 'rank-pill', `#${r.rank}`);
      return {
        highlight: r.rank === 1,
        cells: [
          rankBadge,
          titleCell,
          r.dense_only_rank ? `#${r.dense_only_rank} (${r.dense_score})` : `Ngoài Top 30 (${r.dense_score})`,
          r.bm25_only_rank ? `#${r.bm25_only_rank} (${r.bm25_score})` : `Ngoài Top 30 (${r.bm25_score})`,
          String(r.hybrid_score),
        ],
      };
    });
    out.appendChild(buildDebugTable(
      ['Hạng RRF', 'Tài liệu OWASP & Đoạn trích đối chiếu', 'Hạng Dense-only', 'Hạng BM25-Heading', 'Điểm Hybrid RRF'],
      rows,
    ));
  } catch (err) {
    out.replaceChildren(create('p', 'failure', err.message || 'Không thực hiện được truy vấn thử.'));
  }
}

function renderDebugComms(force = false) {
  if (!IS_DEBUG) return;
  const select = el('debug-job-select');
  const host = el('debug-comms-body');
  if (!select || !host) return;

  if (!state.jobs.length) {
    select.replaceChildren(create('option', '', 'Chưa có phiên phân tích nào'));
    state.debugCommsSig = 'empty';
    host.replaceChildren(create('div', 'debug-loading',
      'Chưa có phiên gọi AI nào. Hãy tải một tệp báo cáo Pentest hoặc kết quả quét bên dưới (chế độ /debug đã tự bật "Luôn gọi trực tiếp Ollama mới") để xem trực tiếp toàn bộ System Prompt, User Payload và phản hồi nguyên văn từ AI theo thời gian thực.'));
    return;
  }

  const wantedId = (state.debugJobId && state.jobs.some((j) => j.id === state.debugJobId))
    ? state.debugJobId
    : (state.selectedId || state.jobs[0].id);
  state.debugJobId = wantedId;

  const optsSig = state.jobs.map((j) => `${j.id}:${j.status}`).join('|');
  if (select.dataset.sig !== optsSig) {
    select.dataset.sig = optsSig;
    select.replaceChildren();
    for (const j of state.jobs) {
      const opt = create('option', '', `${j.filename} — ${statusText(j)} (${formatTime(j.created_at)})`);
      opt.value = j.id;
      if (j.id === wantedId) opt.selected = true;
      select.appendChild(opt);
    }
  } else if (select.value !== wantedId) {
    select.value = wantedId;
  }

  const targetJob = state.jobs.find((j) => j.id === wantedId) || state.jobs[0];
  const cached = state.traceCache[targetJob.id];
  const entriesLen = (cached && cached.data && cached.data.entries) ? cached.data.entries.length : -1;
  const renderSig = `${targetJob.id}:${targetJob.status}:${entriesLen}:${Boolean(cached && cached.loading)}`;
  if (!force && state.debugCommsSig === renderSig) return;
  state.debugCommsSig = renderSig;

  host.replaceChildren(buildTracePanel(targetJob, { alwaysOpen: true }));
}

function setDebugTab(tabName) {
  state.debugTab = tabName;
  document.querySelectorAll('.debug-tab').forEach((btn) => {
    const active = btn.dataset.tab === tabName;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  el('debug-panel-eval').hidden = tabName !== 'eval';
  el('debug-panel-playground').hidden = tabName !== 'playground';
  el('debug-panel-comms').hidden = tabName !== 'comms';
  if (tabName === 'playground' && !el('debug-query-results').children.length) {
    runDebugPlaygroundQuery();
  }
  if (tabName === 'comms') {
    if (state.debugJobId) fetchJobTrace(state.debugJobId, true);
    renderDebugComms(true);
  }
}

function initDebugMode() {
  if (!IS_DEBUG) return;
  document.title = '[DEBUG] DBSec OWASP — Thực nghiệm AI, Hybrid RAG & Giao tiếp Mô hình';
  el('debug-mode-bar').hidden = false;
  el('debug-console').hidden = false;
  document.querySelectorAll('.debug-only').forEach((node) => { node.hidden = false; });

  const freshSelect = el('meta-force_fresh_ai');
  if (freshSelect) freshSelect.value = '1';
  const reportOpts = el('report-options');
  if (reportOpts) reportOpts.open = true;

  document.querySelectorAll('.debug-tab').forEach((btn) => {
    btn.addEventListener('click', () => setDebugTab(btn.dataset.tab));
  });
  el('debug-run-eval').addEventListener('click', () => loadDebugOverview(true));
  el('debug-query-form').addEventListener('submit', runDebugPlaygroundQuery);
  document.querySelectorAll('.preset-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      el('debug-q-input').value = chip.dataset.q || '';
      el('debug-cwe-input').value = chip.dataset.cwe || '';
      el('debug-stack-input').value = chip.dataset.stack || '';
      runDebugPlaygroundQuery();
    });
  });
  el('debug-job-select').addEventListener('change', (e) => {
    state.debugJobId = e.target.value;
    state.debugCommsSig = '';
    fetchJobTrace(state.debugJobId, true);
    renderDebugComms(true);
  });
  el('debug-refresh-trace').addEventListener('click', () => {
    if (state.debugJobId) {
      state.debugCommsSig = '';
      fetchJobTrace(state.debugJobId, true);
    }
    refreshJobs();
  });
}

async function boot() {
  wireEvents();
  initDebugMode();
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) state.selectedId = saved;
  try {
    await loadConfig();
    if (IS_DEBUG && state.token) {
      const exitLink = el('debug-exit-link');
      if (exitLink && document.querySelector('meta[name="app-token"]')) {
        exitLink.href = '/';
      }
    }
    await refreshJobs();
    if (IS_DEBUG) await loadDebugOverview(false);
  } catch (_) {
    setFormError('Chưa kết nối được máy chủ Web cục bộ. Hãy kiểm tra cửa sổ chạy start-web.bat.');
  }
}

boot();
