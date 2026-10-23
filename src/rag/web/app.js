'use strict';

const TERMINAL = new Set(['completed', 'partial', 'failed']);
const STORAGE_KEY = 'dbsec-selected-thread';
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
  'report_profile',
  'force_fresh_ai',
];

const PIPELINE_STEPS = [
  { num: 1, title: 'Đọc hiểu dữ liệu đầu vào & trích xuất bằng chứng gốc', detail: 'Nhận diện tự động log công cụ / tài liệu Pentest và đối khớp gói tin HTTP chứng minh' },
  { num: 2, title: 'Nạp kho tri thức OWASP chuyên biệt CSDL', detail: '25 OWASP Cheat Sheets & mô hình nhúng ngữ nghĩa E5' },
  { num: 3, title: 'Đối chiếu OWASP Top 10:2025 & Truy xuất Hybrid RAG', detail: 'Chọn biện pháp khắc phục chính & đoạn mã an toàn đúng ngăn xếp' },
  { num: 4, title: 'Gộp lỗi trùng (F-xx), tách Quan sát (Mục 3) & Âm tính (Mục 4)', detail: 'Không tự chấm CVSS; chỉ gán CWE khi có bằng chứng trực tiếp' },
  { num: 5, title: 'Tách bạch Tác động Đã chứng minh & Giả thuyết', detail: 'Tập trung Giới hạn & việc cần xác minh duy nhất tại Mục 5' },
  { num: 6, title: 'Kết xuất Báo cáo Kiểm thử Gọn 6 mục (PDF & Markdown)', detail: 'Đánh số trang Page X of Y, che khóa phiên [REDACTED] & lưu Phụ lục SHA-256' },
];

const SAMPLE_SQLMAP_LOG = [
  'Target URL: http://198.51.100.79/vulnerabilities/sqli/?id=1&Submit=Submit',
  '[11:21:57] [INFO] testing connection to the target URL',
  "[11:21:57] [INFO] heuristic (XSS) test shows that GET parameter 'id' might be vulnerable to cross-site scripting (XSS) attacks",
  "[11:22:01] [WARNING] GET parameter 'Submit' does not seem to be dynamic",
  '---',
  'Parameter: id (GET)',
  '    Type: boolean-based blind',
  '    Title: OR boolean-based blind - WHERE or HAVING clause (NOT)',
  "    Payload: id=1' OR NOT 5452=5452-- -&Submit=Submit",
  '',
  '    Type: error-based',
  '    Title: MySQL >= 5.1 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (EXTRACTVALUE)',
  "    Payload: id=1' AND EXTRACTVALUE(5879,CONCAT(0x5c,0x7170787671,1))-- nWty&Submit=Submit",
  '',
  '    Type: UNION query',
  '    Title: Generic UNION query (NULL) - 2 columns',
  "    Payload: id=1' UNION ALL SELECT NULL,CONCAT(0x7170787671,schema_name,0x71706a7871) FROM INFORMATION_SCHEMA.SCHEMATA-- -&Submit=Submit",
  '---',
  'web application technology: Apache 2.4.25, PHP 7.0.33',
  'back-end DBMS: MySQL >= 5.1 (MariaDB fork)',
  "current user: 'app@localhost'",
  "current database: 'dvwa'",
  'current user is DBA: False',
  'available databases [2]:',
  '[*] dvwa',
  '[*] information_schema',
  'Database: dvwa',
  '[2 tables]',
  '+-----------+',
  '| guestbook |',
  '| users     |',
  '+-----------+',
  'HTTP request [#239]:',
  'GET /vulnerabilities/sqli/?id=1%27%20AND%20EXTRACTVALUE%285879%2C1%29--%20nWty&Submit=Submit HTTP/1.1',
  'Host: 198.51.100.79',
  'Cookie: PHPSESSID=demo_session_secret_991; security=low',
  '',
  'HTTP response [#239] (200 OK):',
  'HTTP/1.1 200 OK',
  'Server: Apache/2.4.25 (Debian)',
  "<pre>XPATH syntax error: '\\qpxvq1qpjxq'</pre>",
  '############################################################################',
].join('\n');

const state = {
  token: document.querySelector('meta[name="app-token"]')?.content || '',
  config: null,
  jobs: [],
  threads: [],
  selectedId: null, // selected thread id
  pendingUserText: '',
  selectedFiles: [],
  pollTimer: null,
  clockTimer: null,
  toastTimer: null,
  traceCache: {},
  submitting: false,
  lastRenderSig: '',
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
    ['path', { d: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z' }],
    ['path', { d: 'M9 12l2 2 4-4' }],
  ],
  chat: [
    ['path', { d: 'M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z' }],
  ],
  download: [['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }], ['polyline', { points: '7 10 12 15 17 10' }], ['line', { x1: 12, y1: 15, x2: 12, y2: 3 }]],
  eye: [['path', { d: 'M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z' }], ['circle', { cx: 12, cy: 12, r: 3 }]],
  clock: [['circle', { cx: 12, cy: 12, r: 10 }], ['polyline', { points: '12 6 12 12 16 14' }]],
  link: [['path', { d: 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6' }], ['polyline', { points: '15 3 21 3 21 9' }], ['line', { x1: 10, y1: 14, x2: 21, y2: 3 }]],
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
  for (const [tag, attrs] of (ICONS[name] || ICONS.bot)) {
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

function pctText(v) {
  return `${(Number(v || 0) * 100).toFixed(1)}%`;
}

function statusText(job) {
  if (!job) return 'Trò chuyện với trợ lý';
  if (job.status === 'queued') return 'Đang chờ phân tích';
  if (job.status === 'running') return `${job.percent || 10}% · ${job.stage || 'Đang phân tích'}`;
  if (job.status === 'completed') return 'Báo cáo 6 mục sẵn sàng';
  if (job.status === 'partial') return 'Hoàn tất (một phần AI)';
  return 'Cần kiểm tra lại';
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

function autoResizeTextarea() {
  const ta = el('note');
  if (!ta) return;
  ta.rows = 1;
  const lines = Math.min(7, Math.max(1, Math.ceil(ta.scrollHeight / 22)));
  ta.rows = lines;
}

function scrollChatToBottom(smooth = true) {
  const scroller = el('chat-scroll');
  if (!scroller) return;
  requestAnimationFrame(() => {
    scroller.scrollTo({ top: scroller.scrollHeight, behavior: smooth ? 'smooth' : 'auto' });
  });
}

/* ============================================================================
   Safe CSP-Clean Markdown DOM Renderer (headings, bold, inline code, links,
   bullet/numbered lists, and copyable code blocks — zero innerHTML!)
   ============================================================================ */
function appendInlineFormatted(parent, rawText) {
  const text = String(rawText || '');
  const tokenRe = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\(https?:\/\/[^)\s]+\))/g;
  let last = 0;
  let match;
  while ((match = tokenRe.exec(text)) !== null) {
    if (match.index > last) {
      parent.appendChild(document.createTextNode(text.slice(last, match.index)));
    }
    const tok = match[0];
    if (tok.startsWith('**') && tok.endsWith('**')) {
      parent.appendChild(create('strong', '', tok.slice(2, -2)));
    } else if (tok.startsWith('`') && tok.endsWith('`')) {
      parent.appendChild(create('code', '', tok.slice(1, -1)));
    } else if (tok.startsWith('[')) {
      const mLink = tok.match(/^\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)$/);
      if (mLink) {
        const a = create('a', 'json-link', mLink[1]);
        a.href = mLink[2];
        a.target = '_blank';
        a.rel = 'noopener';
        parent.appendChild(a);
      } else {
        parent.appendChild(document.createTextNode(tok));
      }
    }
    last = match.index + tok.length;
  }
  if (last < text.length) {
    parent.appendChild(document.createTextNode(text.slice(last)));
  }
}

function renderMarkdownSafe(markdownText) {
  const container = create('div', 'md-prose');
  const src = String(markdownText || '').replace(/\r\n/g, '\n');
  const segments = src.split(/(```[A-Za-z0-9_+#.-]*\n[\s\S]*?```)/g);

  for (const seg of segments) {
    if (!seg) continue;
    const fenceMatch = seg.match(/^```([A-Za-z0-9_+#.-]*)\n([\s\S]*?)```$/);
    if (fenceMatch) {
      const lang = fenceMatch[1] || 'code';
      const codeBody = fenceMatch[2].replace(/\n$/, '');
      const wrap = create('div', 'md-code-wrap');
      const bar = create('div', 'md-code-bar');
      bar.appendChild(create('span', '', lang));
      const copyBtn = create('button', 'md-copy-btn', 'Sao chép');
      copyBtn.type = 'button';
      copyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(codeBody);
          copyBtn.textContent = 'Đã chép ✓';
          setTimeout(() => { copyBtn.textContent = 'Sao chép'; }, 1800);
        } catch (_) {
          copyBtn.textContent = 'Không chép được';
        }
      });
      bar.appendChild(copyBtn);
      const pre = create('pre', '', codeBody);
      wrap.append(bar, pre);
      container.appendChild(wrap);
      continue;
    }

    const lines = seg.split('\n');
    let currentList = null;
    let currentListTag = '';
    const flushList = () => {
      if (currentList) {
        container.appendChild(currentList);
        currentList = null;
        currentListTag = '';
      }
    };

    for (const rawLine of lines) {
      const line = rawLine.trimEnd();
      const trimmed = line.trim();
      if (!trimmed) {
        flushList();
        continue;
      }
      const hMatch = trimmed.match(/^(#{1,4})\s+(.*)$/);
      if (hMatch) {
        flushList();
        const tag = hMatch[1].length <= 3 ? 'h3' : 'h4';
        const hEl = create(tag);
        appendInlineFormatted(hEl, hMatch[2]);
        container.appendChild(hEl);
        continue;
      }
      const ulMatch = trimmed.match(/^[-*•]\s+(.*)$/);
      if (ulMatch) {
        if (currentListTag !== 'ul') {
          flushList();
          currentList = create('ul');
          currentListTag = 'ul';
        }
        const li = create('li');
        appendInlineFormatted(li, ulMatch[1]);
        currentList.appendChild(li);
        continue;
      }
      const olMatch = trimmed.match(/^\d+\.\s+(.*)$/);
      if (olMatch) {
        if (currentListTag !== 'ol') {
          flushList();
          currentList = create('ol');
          currentListTag = 'ol';
        }
        const li = create('li');
        appendInlineFormatted(li, olMatch[1]);
        currentList.appendChild(li);
        continue;
      }
      flushList();
      const p = create('p');
      appendInlineFormatted(p, trimmed);
      container.appendChild(p);
    }
    flushList();
  }
  return container;
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
  const btnLabel = el('submit-btn-label');
  if (!state.selectedFiles.length) {
    wrap.hidden = true;
    if (btnLabel) btnLabel.textContent = 'Gửi';
    return;
  }
  wrap.hidden = false;
  if (btnLabel) btnLabel.textContent = 'Phân tích tệp';
  const totalBytes = state.selectedFiles.reduce((acc, f) => acc + f.size, 0);
  el('file-count-label').textContent = state.selectedFiles.length === 1
    ? `1 tệp đính kèm · ${formatBytes(totalBytes)}`
    : `${state.selectedFiles.length} tệp đính kèm · ${formatBytes(totalBytes)}`;

  state.selectedFiles.forEach((f, idx) => {
    const chip = create('div', 'single-chip');
    chip.appendChild(icon('file', 15));
    chip.appendChild(create('strong', '', f.name));
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
    pill.textContent = 'Trợ lý Demo · OWASP RAG Sẵn sàng';
    banner.hidden = true;
    return;
  }
  if (!state.config.configured) {
    pill.textContent = 'Chế độ RAG cục bộ (Chờ Ollama)';
    banner.textContent = 'Ollama chưa bật — trợ lý vẫn trả lời hỏi đáp từ kho OWASP Cheat Sheet & phân tích tệp quét cục bộ.';
    banner.hidden = false;
    return;
  }
  const label = state.config.provider === 'ollama' ? `Ollama · ${state.config.model}` : `AI · ${state.config.model}`;
  pill.textContent = label;
  banner.hidden = true;
}

function findJob(jobId) {
  return state.jobs.find((j) => j.id === jobId) || null;
}

function renderHistory() {
  const nav = el('history');
  nav.replaceChildren();
  if (!state.threads.length) {
    nav.appendChild(create('div', 'history-empty', 'Chưa có cuộc trò chuyện nào. Hãy đặt câu hỏi hoặc đính kèm tệp quét để bắt đầu.'));
    return;
  }
  for (const th of state.threads) {
    const activeJob = th.active_job_id ? findJob(th.active_job_id) : null;
    const item = create('button', 'history-item' + (th.id === state.selectedId ? ' active' : ''));
    item.type = 'button';
    const dotCls = activeJob ? `status-dot ${activeJob.status}` : 'status-dot completed';
    const dot = create('span', dotCls);
    const body = create('div', 'history-body');
    body.appendChild(create('strong', '', th.title || 'Cuộc trò chuyện bảo mật'));
    const sub = activeJob
      ? `${statusText(activeJob)} · ${formatTime(th.updated_at)}`
      : `${(th.messages || []).length} tin nhắn · ${formatTime(th.updated_at)}`;
    body.appendChild(create('span', '', sub));
    item.append(dot, body);
    item.addEventListener('click', () => selectThread(th.id));
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
    const currentJob = findJob(jobId);
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
      ? `${entries.length} lượt gọi AI (Cache SHA-256)`
      : `${entries.length} lượt gọi trực tiếp mô hình AI`)
    : 'Nhấn để tải chi tiết';
  details.appendChild(create('summary', '', `Chi tiết câu lệnh gửi mô hình AI & phản hồi nguyên văn (${countLabel})`));

  const wrap = create('div', 'trace-body');
  const qTok = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
  const topBar = create('div', 'trace-topbar');
  topBar.appendChild(create('span', 'trace-mode-info',
    fromCache
      ? 'Phiên này tái sử dụng kết quả AI đã lưu theo SHA-256.'
      : (job.demo ? 'Chế độ Demo cục bộ không gửi câu lệnh sang LLM.' : 'Ghi nhận đầy đủ System Prompt, User Payload và phản hồi nguyên văn.')));

  const dlTrace = create('a', 'json-link trace-dl', 'Tải bản ghi lệnh AI (.txt)');
  dlTrace.href = `/api/jobs/${job.id}/trace-txt${qTok}`;
  dlTrace.download = `lenh-gui-ai-${job.id.slice(0, 8)}.txt`;
  topBar.appendChild(dlTrace);
  wrap.appendChild(topBar);

  if (!cached) {
    details.addEventListener('toggle', () => {
      if (details.open) fetchJobTrace(job.id);
    }, { once: true });
    wrap.appendChild(create('p', 'trace-empty', 'Mở mục này để tải danh sách câu lệnh đã gửi cho AI.'));
  } else if (cached.loading && !entries.length) {
    wrap.appendChild(create('p', 'trace-empty', 'Đang tải nhật ký câu lệnh AI...'));
  } else if (!entries.length) {
    wrap.appendChild(create('p', 'trace-empty', 'Chưa ghi nhận lượt gọi LLM nào.'));
  } else {
    entries.forEach((item, idx) => {
      const box = create('details', 'trace-item');
      if (idx === entries.length - 1) box.open = true;
      const head = `${idx + 1}. [${formatEventTime(item.at)}] Mô hình ${item.model || 'AI'} · ${item.duration_sec ?? 0}s · Prompt ${(item.prompt || '').length} ký tự`;
      box.appendChild(create('summary', '', head));
      const inner = create('div', 'trace-pre-group');
      if (item.system) {
        inner.appendChild(create('div', 'trace-label', '1. Chỉ dẫn hệ thống (System Prompt):'));
        inner.appendChild(create('pre', 'trace-pre', item.system));
      }
      inner.appendChild(create('div', 'trace-label', '2. Dữ liệu & Câu lệnh gửi AI (User Prompt):'));
      inner.appendChild(create('pre', 'trace-pre', item.prompt || ''));
      inner.appendChild(create('div', 'trace-label', '3. Phản hồi nguyên văn từ AI:'));
      inner.appendChild(create('pre', 'trace-pre', item.response || ''));
      box.appendChild(inner);
      wrap.appendChild(box);
    });
  }
  details.appendChild(wrap);
  return details;
}

function buildLiveProgressCard(job) {
  const pct = Math.min(99, Math.max(6, Number(job.percent) || 8));
  const curStep = Math.min(6, Math.max(1, Number(job.step) || 1));

  const process = create('div', 'process-card');
  const top = create('div', 'process-top');
  const titleWrap = create('div', 'process-stage-wrap');
  titleWrap.appendChild(create('span', 'live-pulse'));
  titleWrap.appendChild(create('strong', 'process-stage-title', job.stage || 'Đang phân tích dữ liệu...'));

  const rightMeta = create('div', 'process-meta-right');
  const timerPill = create('span', 'timer-pill');
  timerPill.dataset.startedAt = job.started_at || job.created_at || new Date().toISOString();
  timerPill.appendChild(icon('clock', 13));
  const elapsedSec = Math.max(0, (Date.now() - new Date(timerPill.dataset.startedAt).getTime()) / 1000);
  timerPill.appendChild(create('span', 'timer-val', formatClock(elapsedSec)));
  rightMeta.appendChild(timerPill);
  rightMeta.appendChild(create('span', 'pct-badge', `${pct}%`));
  top.append(titleWrap, rightMeta);
  process.appendChild(top);

  const prog = document.createElement('progress');
  prog.className = 'chat-progress';
  prog.max = 100;
  prog.value = pct;
  process.appendChild(prog);

  const stepList = create('div', 'step-checklist');
  for (const s of PIPELINE_STEPS) {
    const stateCls = s.num < curStep ? 'done' : (s.num === curStep ? 'active' : 'pending');
    const row = create('div', `step-item ${stateCls}`);
    const badge = create('span', 'step-badge', s.num < curStep ? '✓' : String(s.num));
    const info = create('div', 'step-text');
    info.appendChild(create('strong', '', s.title));
    info.appendChild(create('small', '', s.detail));
    row.append(badge, info);
    stepList.appendChild(row);
  }
  process.appendChild(stepList);
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
  titleInfo.appendChild(create('strong', '', 'Báo cáo Kiểm thử Bảo mật Gọn (Mục 1 → Mục 6)'));
  const formatName = (state.config && state.config.formats && state.config.formats[job.format]) || job.format;
  titleInfo.appendChild(create('p', '',
    `Nguồn: ${formatName} · Chuẩn Template Gọn 6 mục (2–3 trang) · Hoàn tất lúc ${formatTime(job.updated_at)}`));
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
    [String(confirmedNum), 'Lỗ hổng Đã xác nhận (Mục 1–2)'],
    [String(unconfirmedNum), 'Có dấu hiệu / Cần xác minh (Mục 5)'],
    [String(s.with_guidance ?? 0), 'Khuyến nghị OWASP Cheat Sheet'],
    [formatDurationHuman(s.duration_sec || 0), 'Thời gian xử lý'],
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
    wrap.appendChild(create('div', 'preview-title', `Mục 1 & Mục 2 — Tóm tắt phát hiện (${preview.length} mục)`));
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
      row.append(main, tags);
      wrap.appendChild(row);
    }
    card.appendChild(wrap);
  }

  const actions = create('div', 'download-actions');
  const tokSuffix = state.token ? `&token=${encodeURIComponent(state.token)}` : '';

  const dl = create('a', 'download');
  dl.href = `/api/jobs/${job.id}/pdf?profile=compact${tokSuffix}`;
  dl.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.pdf`;
  dl.append(icon('download', 15), create('span', '', 'Tải PDF Gọn (6 mục)'));

  const viewBtn = create('a', 'download secondary');
  viewBtn.href = `/api/jobs/${job.id}/pdf?inline=1&profile=compact${tokSuffix}`;
  viewBtn.target = '_blank';
  viewBtn.rel = 'noopener';
  viewBtn.append(icon('eye', 15), create('span', '', 'Mở xem PDF trực tiếp'));

  const mdLink = create('a', 'json-link', 'Tải Markdown (.md)');
  mdLink.href = `/api/jobs/${job.id}/md?profile=compact${tokSuffix}`;
  mdLink.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.md`;

  const fullPdfLink = create('a', 'json-link', 'PDF Đầy đủ (10 mục)');
  fullPdfLink.href = `/api/jobs/${job.id}/pdf?profile=full${tokSuffix}`;
  fullPdfLink.download = `bao-cao-bao-mat-csdl-day-du-${job.id.slice(0, 8)}.pdf`;

  const qTok = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
  const jsonLink = create('a', 'json-link', 'Tải JSON');
  jsonLink.href = `/api/jobs/${job.id}/json${qTok}`;
  jsonLink.download = `du-lieu-bao-cao-${job.id.slice(0, 8)}.json`;

  const syncLogLink = create('a', 'json-link', 'Tải Log đã che nhạy cảm');
  syncLogLink.href = `/api/jobs/${job.id}/log${qTok}`;
  syncLogLink.download = `du-lieu-da-lam-sach-${job.id.slice(0, 8)}.txt`;

  actions.append(dl, viewBtn, mdLink, fullPdfLink, jsonLink, syncLogLink);
  card.appendChild(actions);
  return card;
}

function renderJobExchangeNode(job, userNote) {
  const frag = document.createDocumentFragment();

  // User attachment bubble
  const uRow = create('div', 'chat-row is-user');
  const uStack = create('div', 'chat-user-stack');
  const fileCard = create('div', 'upload-card');
  const formatName = (state.config && state.config.formats && state.config.formats[job.format]) || job.format;
  fileCard.appendChild(icon('file', 20));
  const meta = create('div');
  meta.appendChild(create('strong', '', job.filename));
  meta.appendChild(create('span', '', `${formatName} · ${formatBytes(job.size)} · ${job.count} bản ghi`));
  fileCard.appendChild(meta);
  uStack.appendChild(fileCard);
  const noteTxt = (userNote || job.note || '').trim();
  if (noteTxt) {
    uStack.appendChild(create('div', 'chat-bubble-user', noteTxt));
  }
  uRow.appendChild(uStack);
  frag.appendChild(uRow);

  // Assistant report bubble
  const bRow = create('div', 'chat-row is-assistant');
  bRow.appendChild(assistantAvatar());
  const body = create('div', 'chat-assistant-col');
  const head = create('div', 'chat-msg-head');
  head.appendChild(create('span', 'chat-msg-author', 'Trợ lý Bảo mật OWASP'));
  head.appendChild(create('span', 'chat-msg-time', formatTime(job.updated_at || job.created_at)));
  body.appendChild(head);

  if (!TERMINAL.has(job.status)) {
    body.appendChild(create('p', '', 'Mình đang phân tích dữ liệu kiểm thử, gộp lỗi trùng, lọc quan sát thụ động vào Mục 3 và kết xuất Báo cáo Gọn 6 mục:'));
    body.appendChild(buildLiveProgressCard(job));
  } else if (job.status === 'failed') {
    body.appendChild(create('p', 'failure', job.error || 'Chưa tạo được báo cáo từ dữ liệu này.'));
    if ((job.events || []).length) {
      const details = create('details', 'event-panel');
      details.open = true;
      details.appendChild(create('summary', '', `Chi tiết các bước trước khi dừng (${job.events.length} mốc)`));
      details.appendChild(renderEventList(job.events));
      body.appendChild(details);
    }
    if (IS_DEBUG) body.appendChild(buildTracePanel(job));
  } else {
    const s = job.summary || {};
    body.appendChild(renderMarkdownSafe(
      `Mình đã hoàn tất phân tích **${job.filename}** và kết xuất **Báo cáo Kiểm thử Bảo mật Gọn (Mục 1–6)** với **${s.findings ?? job.count} mục phát hiện**. Bạn có thể mở xem trực tiếp PDF bên dưới hoặc hỏi tiếp bất kỳ câu hỏi nào về cách vá lỗi, ý nghĩa bằng chứng và quy trình Retest ngay tại đây!`
    ));
    if (job.status === 'partial') {
      body.appendChild(create('p', 'result-warning',
        `Một số đoạn diễn giải AI chưa hoàn tất (${s.ai_reviewed ?? 0}/${s.findings ?? 0}), nhưng toàn bộ bảng thống kê, bằng chứng gốc và khuyến nghị OWASP đều đầy đủ.`));
    }
    body.appendChild(buildCompletedCard(job));
    if ((job.events || []).length) {
      const details = create('details', 'event-panel');
      details.appendChild(create('summary', '', `Xem nhật ký xử lý (${job.events.length} bước)`));
      details.appendChild(renderEventList(job.events));
      body.appendChild(details);
    }
    if (IS_DEBUG) body.appendChild(buildTracePanel(job));
  }

  bRow.appendChild(body);
  frag.appendChild(bRow);
  return frag;
}

function buildFollowupRow(prompts) {
  const row = create('div', 'followup-row');
  for (const p of prompts) {
    const btn = create('button', 'followup-chip', p);
    btn.type = 'button';
    btn.addEventListener('click', () => sendTextPrompt(p));
    row.appendChild(btn);
  }
  return row;
}

function renderThreadMessages(thread) {
  const frag = document.createDocumentFragment();
  const entries = thread.messages || [];
  let latestSuggestions = [];
  let lastFinishedJob = null;

  for (const m of entries) {
    if (m.role === 'job') {
      const job = findJob(m.job_id);
      if (job) {
        frag.appendChild(renderJobExchangeNode(job, m.text));
        if (job.status === 'completed' || job.status === 'partial') lastFinishedJob = job;
      }
      continue;
    }
    if (m.role === 'user') {
      const uRow = create('div', 'chat-row is-user');
      uRow.appendChild(create('div', 'chat-bubble-user', m.text || ''));
      frag.appendChild(uRow);
      continue;
    }
    if (m.role === 'assistant') {
      const bRow = create('div', 'chat-row is-assistant');
      bRow.appendChild(assistantAvatar());
      const bCol = create('div', 'chat-assistant-col');
      const head = create('div', 'chat-msg-head');
      head.appendChild(create('span', 'chat-msg-author', 'Trợ lý Bảo mật OWASP'));
      head.appendChild(create('span', 'chat-msg-time', formatTime(m.at)));
      bCol.appendChild(head);
      bCol.appendChild(renderMarkdownSafe(m.text || ''));

      const cites = m.citations || [];
      if (cites.length) {
        const citeRow = create('div', 'cite-row');
        for (const c of cites) {
          const a = create('a', 'cite-chip');
          a.href = c.url;
          a.target = '_blank';
          a.rel = 'noopener';
          a.append(icon('link', 12), create('span', '', c.title || 'OWASP Reference'));
          citeRow.appendChild(a);
        }
        bCol.appendChild(citeRow);
      }
      bRow.appendChild(bCol);
      frag.appendChild(bRow);
      if ((m.suggestions || []).length) latestSuggestions = m.suggestions;
    }
  }

  // Optimistic pending user message + animated typing indicator
  if (state.pendingUserText) {
    const uRow = create('div', 'chat-row is-user');
    uRow.appendChild(create('div', 'chat-bubble-user', state.pendingUserText));
    frag.appendChild(uRow);

    const tRow = create('div', 'chat-row is-assistant');
    tRow.appendChild(assistantAvatar());
    const tCol = create('div', 'chat-assistant-col');
    const dots = create('div', 'typing-indicator');
    dots.append(create('i'), create('i'), create('i'));
    tCol.appendChild(dots);
    tRow.appendChild(tCol);
    frag.appendChild(tRow);
  } else {
    const prompts = latestSuggestions.length
      ? latestSuggestions
      : (lastFinishedJob ? [
        'Giải thích chi tiết lỗ hổng F-01 và viết code vá an toàn',
        'Hướng dẫn từng bước kiểm thử lại (Retest) không dùng --dump',
        'Phân tích ý nghĩa các dịch vụ ở Mục 3 và kết quả âm tính ở Mục 4',
      ] : []);
    if (prompts.length) frag.appendChild(buildFollowupRow(prompts));
  }

  return frag;
}

function syncElapsedClock() {
  const pill = document.querySelector('.timer-pill');
  if (!pill || !pill.dataset.startedAt) return;
  const valEl = pill.querySelector('.timer-val');
  if (!valEl) return;
  const elapsedSec = Math.max(0, (Date.now() - new Date(pill.dataset.startedAt).getTime()) / 1000);
  valEl.textContent = formatClock(elapsedSec);
}

function renderWorkspace(forceScroll = false) {
  const thread = state.threads.find((t) => t.id === state.selectedId) || null;
  const showChat = Boolean(thread || state.pendingUserText);

  el('empty-state').hidden = showChat;
  const messagesEl = el('messages');
  messagesEl.hidden = !showChat;

  const titleEl = el('chat-thread-title');
  const subEl = el('chat-thread-sub');
  if (thread) {
    const activeJob = thread.active_job_id ? findJob(thread.active_job_id) : null;
    if (titleEl) titleEl.textContent = thread.title || 'Cuộc trò chuyện bảo mật';
    if (subEl) {
      subEl.textContent = activeJob
        ? `${statusText(activeJob)} · Có thể hỏi đáp trực tiếp trên dữ liệu báo cáo này`
        : 'Đang trò chuyện cùng Trợ lý Bảo mật & Kho tri thức OWASP CSDL';
    }
  } else {
    if (titleEl) titleEl.textContent = 'Trợ lý Kiểm thử Bảo mật & OWASP';
    if (subEl) subEl.textContent = 'Hỏi đáp kỹ thuật CSDL, phân tích log quét & kết xuất Báo cáo Gọn 6 mục';
  }

  const sig = JSON.stringify({
    tid: state.selectedId,
    pending: state.pendingUserText,
    msgs: thread ? (thread.messages || []).length : 0,
    jobs: state.jobs.map((j) => `${j.id}:${j.status}:${j.percent}:${(j.events || []).length}`),
  });
  if (forceScroll || sig !== state.lastRenderSig) {
    state.lastRenderSig = sig;
    messagesEl.replaceChildren();
    if (thread) messagesEl.appendChild(renderThreadMessages(thread));
    else if (state.pendingUserText) messagesEl.appendChild(renderThreadMessages({ messages: [] }));
    scrollChatToBottom(true);
  }

  renderHistory();
  if (IS_DEBUG) renderDebugComms(false);
}

function startNewThread() {
  state.selectedId = null;
  state.lastRenderSig = '';
  localStorage.removeItem(STORAGE_KEY);
  closeSidebar();
  renderWorkspace(true);
  el('note')?.focus();
}

function selectThread(id) {
  state.selectedId = id;
  state.lastRenderSig = '';
  const th = state.threads.find((t) => t.id === id);
  if (IS_DEBUG && th && th.active_job_id) state.debugJobId = th.active_job_id;
  localStorage.setItem(STORAGE_KEY, id);
  closeSidebar();
  renderWorkspace(true);
}

async function refreshState() {
  try {
    const [jobs, threads] = await Promise.all([api('/api/jobs'), api('/api/threads')]);
    state.jobs = jobs;
    state.threads = threads;
    if (state.selectedId && !state.threads.some((t) => t.id === state.selectedId)) {
      // Check if saved key was a legacy job id
      const matching = state.threads.find((t) => (t.job_ids || []).includes(state.selectedId));
      state.selectedId = matching ? matching.id : null;
    }
    if (IS_DEBUG) {
      const targetId = state.debugJobId || (state.jobs[0] && state.jobs[0].id) || null;
      if (targetId) {
        const sel = findJob(targetId);
        if (sel && (!TERMINAL.has(sel.status) || !state.traceCache[sel.id] || !state.traceCache[sel.id].done)) {
          fetchJobTrace(sel.id, true);
        }
      }
    }
    renderWorkspace(false);
    schedulePoll();
  } catch (err) {
    if (err.status === 401) await loadConfig();
  }
}

function schedulePoll() {
  clearTimeout(state.pollTimer);
  const active = state.jobs.some((job) => !TERMINAL.has(job.status));
  state.pollTimer = setTimeout(refreshState, active ? 1000 : 10000);
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

async function sendTextPrompt(text) {
  el('note').value = text;
  autoResizeTextarea();
  await handleComposerSubmit(new Event('submit'));
}

async function handleComposerSubmit(event) {
  if (event && event.preventDefault) event.preventDefault();
  if (state.submitting) return;

  const files = state.selectedFiles.slice();
  const msgText = (el('note').value || '').trim();

  if (!files.length && !msgText) {
    setFormError('Hãy nhập câu hỏi bảo mật, dán log kiểm thử, hoặc đính kèm tệp quét.');
    return;
  }

  state.submitting = true;
  el('submit-btn').disabled = true;
  setFormError('');

  try {
    if (files.length > 0) {
      const maxBytes = (state.config && state.config.max_bytes) || 10 * 1024 * 1024;
      const totalBytes = files.reduce((s, f) => s + f.size, 0);
      if (totalBytes <= 0 || totalBytes > maxBytes) {
        throw new Error('Tổng dung lượng tệp đính kèm không được vượt quá 10 MB.');
      }
      const chosenFmt = el('format').value;
      const params = new URLSearchParams({
        filename: files.map((f) => f.name).join(' + '),
        format: chosenFmt,
        note: msgText.slice(0, 1000),
        thread_id: state.selectedId || '',
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
      el('file-input').value = '';
      el('note').value = '';
      autoResizeTextarea();
      updateSelectedFiles([], false);
      if (job.thread_id) {
        state.selectedId = job.thread_id;
        localStorage.setItem(STORAGE_KEY, job.thread_id);
      }
      await refreshState();
      scrollChatToBottom(true);
      showToast('Đã tiếp nhận tệp · Trợ lý đang phân tích & kết xuất Báo cáo Gọn 6 mục...');
    } else {
      const currentThread = state.threads.find((t) => t.id === state.selectedId);
      const activeJobId = (currentThread && currentThread.active_job_id) || '';
      el('note').value = '';
      autoResizeTextarea();
      state.pendingUserText = msgText.length > 260 ? `${msgText.slice(0, 260)}…` : msgText;
      renderWorkspace(true);

      const res = await api('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8' },
        body: JSON.stringify({
          thread_id: state.selectedId || '',
          job_id: activeJobId,
          message: msgText,
          metadata: collectMetadata(),
        }),
      });
      state.pendingUserText = '';
      if (res.thread && res.thread.id) {
        state.selectedId = res.thread.id;
        localStorage.setItem(STORAGE_KEY, res.thread.id);
        const idx = state.threads.findIndex((t) => t.id === res.thread.id);
        if (idx >= 0) state.threads[idx] = res.thread;
        else state.threads.unshift(res.thread);
      }
      if (res.auto_job) {
        state.jobs = [res.auto_job, ...state.jobs.filter((j) => j.id !== res.auto_job.id)];
        showToast('Phát hiện log công cụ dán trực tiếp · Đang tạo Báo cáo Gọn 6 mục...');
      }
      await refreshState();
      scrollChatToBottom(true);
    }
  } catch (err) {
    state.pendingUserText = '';
    setFormError(err.message || 'Chưa gửi được tin nhắn.');
    renderWorkspace(false);
  } finally {
    state.submitting = false;
    el('submit-btn').disabled = false;
    el('note')?.focus();
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

/* ============================================================================
   Debug Console (/debug) Support Preserved 100% Intact
   ============================================================================ */
function buildDebugTable(headers, rows) {
  const wrap = create('div', 'debug-table-wrap');
  const table = create('table', 'debug-table');
  const thead = create('thead');
  const headTr = create('tr');
  for (const h of headers) headTr.appendChild(create('th', '', h));
  thead.appendChild(headTr);
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

  const kpis = create('div', 'debug-kpi-grid');
  const mrrGain = ((Number(hyb.doc_mrr || 0) - Number(den.doc_mrr || 0)) * 100).toFixed(2);
  const kpiItems = [
    [pctText(hyb.doc_hit_at_1), `Hybrid Doc Hit@1 (MRR ${Number(hyb.doc_mrr || 0).toFixed(4)})`, `Tăng +${mrrGain} điểm % MRR so với Dense thuần`],
    [comp ? `-${Number(comp.sheet_reduction_pct || 0).toFixed(1)}%` : '25 tệp', 'Thu gọn nhiễu Kho OWASP CSDL', `${pruned.chunk_count || 0} chunks chuyên biệt`],
    [pctText(guard.f1), 'F1-Score Trích xuất & Ánh xạ CWE', `Precision ${pctText(guard.precision)} · Recall ${pctText(guard.recall)}`],
    [`${guard.hallucinations_blocked || 0}/${guard.hallucinations_injected || 0}`, 'Chặn Ảo giác Đối kháng AI', 'Tự động giữ Chưa xác định khi thiếu CVSS'],
  ];
  for (const [val, title, sub] of kpiItems) {
    const box = create('div', 'debug-kpi');
    box.appendChild(create('strong', '', val));
    box.appendChild(create('span', '', title));
    box.appendChild(create('small', '', sub));
    kpis.appendChild(box);
  }
  host.appendChild(kpis);
}

async function loadDebugOverview(forceRefresh = false) {
  if (!IS_DEBUG) return;
  const btn = el('debug-run-eval');
  if (btn) btn.disabled = true;
  try {
    const data = await api(`/api/debug/overview${forceRefresh ? '?refresh=1' : ''}`);
    state.debugOverview = data;
    renderDebugEvaluation(data);
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
  out.replaceChildren(create('div', 'debug-loading', 'Đang chạy đối chiếu Hybrid RRF...'));
  try {
    const res = await api('/api/debug/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, cwe, stack_hint: stackHint, top_k: 6 }),
    });
    out.replaceChildren();
    const rows = (res.results || []).map((r) => {
      const titleCell = create('div');
      const link = create('a', 'json-link', r.source);
      link.href = r.url;
      link.target = '_blank';
      link.rel = 'noopener';
      titleCell.appendChild(link);
      titleCell.appendChild(create('div', 'hit-snippet', r.snippet));
      return {
        highlight: r.rank === 1,
        cells: [`#${r.rank}`, titleCell, String(r.dense_score), String(r.bm25_score), String(r.hybrid_score)],
      };
    });
    out.appendChild(buildDebugTable(['Hạng', 'Tài liệu OWASP', 'Dense', 'BM25', 'Hybrid RRF'], rows));
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
    host.replaceChildren(create('div', 'debug-loading', 'Hãy gửi một tệp quét để xem chi tiết lệnh gửi AI.'));
    return;
  }
  const wantedId = (state.debugJobId && state.jobs.some((j) => j.id === state.debugJobId))
    ? state.debugJobId
    : state.jobs[0].id;
  state.debugJobId = wantedId;
  select.replaceChildren();
  for (const j of state.jobs) {
    const opt = create('option', '', `${j.filename} — ${statusText(j)}`);
    opt.value = j.id;
    if (j.id === wantedId) opt.selected = true;
    select.appendChild(opt);
  }
  const targetJob = findJob(wantedId) || state.jobs[0];
  if (force || state.debugCommsSig !== `${targetJob.id}:${targetJob.status}`) {
    state.debugCommsSig = `${targetJob.id}:${targetJob.status}`;
    host.replaceChildren(buildTracePanel(targetJob, { alwaysOpen: true }));
  }
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
  if (tabName === 'playground' && !el('debug-query-results').children.length) runDebugPlaygroundQuery();
  if (tabName === 'comms') renderDebugComms(true);
}

function initDebugMode() {
  if (!IS_DEBUG) return;
  document.title = '[DEBUG] Trợ lý Bảo mật OWASP — Thực nghiệm AI & Hybrid RAG';
  el('debug-mode-bar').hidden = false;
  el('debug-console').hidden = false;
  document.querySelectorAll('.debug-only').forEach((node) => { node.hidden = false; });
  const freshSelect = el('meta-force_fresh_ai');
  if (freshSelect) freshSelect.value = '1';
  document.querySelectorAll('.debug-tab').forEach((btn) => {
    btn.addEventListener('click', () => setDebugTab(btn.dataset.tab));
  });
  el('debug-run-eval')?.addEventListener('click', () => loadDebugOverview(true));
  el('debug-query-form')?.addEventListener('submit', runDebugPlaygroundQuery);
  document.querySelectorAll('.preset-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      el('debug-q-input').value = chip.dataset.q || '';
      el('debug-cwe-input').value = chip.dataset.cwe || '';
      el('debug-stack-input').value = chip.dataset.stack || '';
      runDebugPlaygroundQuery();
    });
  });
  el('debug-job-select')?.addEventListener('change', (e) => {
    state.debugJobId = e.target.value;
    fetchJobTrace(state.debugJobId, true);
    renderDebugComms(true);
  });
  el('debug-refresh-trace')?.addEventListener('click', () => {
    if (state.debugJobId) fetchJobTrace(state.debugJobId, true);
    refreshState();
  });
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
  el('toggle-options-btn')?.addEventListener('click', () => {
    const opts = el('report-options');
    if (opts) opts.open = !opts.open;
  });

  const ta = el('note');
  ta.addEventListener('input', autoResizeTextarea);
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
      e.preventDefault();
      handleComposerSubmit(e);
    }
  });
  ta.addEventListener('paste', (e) => {
    const items = e.clipboardData && e.clipboardData.files;
    if (items && items.length) {
      e.preventDefault();
      updateSelectedFiles(items, true);
    }
  });

  el('upload-form').addEventListener('submit', handleComposerSubmit);
  el('new-chat').addEventListener('click', startNewThread);
  el('mobile-new')?.addEventListener('click', startNewThread);
  el('desktop-new')?.addEventListener('click', startNewThread);
  el('brand-link')?.addEventListener('click', (e) => {
    e.preventDefault();
    startNewThread();
  });
  el('open-sidebar')?.addEventListener('click', openSidebar);
  el('close-sidebar')?.addEventListener('click', closeSidebar);
  el('backdrop')?.addEventListener('click', closeSidebar);

  // Starter prompt cards on welcome screen
  document.querySelectorAll('.starter-card').forEach((card) => {
    card.addEventListener('click', () => {
      if (card.dataset.action === 'sample-scan') {
        sendTextPrompt(SAMPLE_SQLMAP_LOG);
      } else if (card.dataset.prompt) {
        sendTextPrompt(card.dataset.prompt);
      }
    });
  });

  // Drag & drop anywhere on composer or main chat window
  const dropTarget = el('main');
  const composer = el('dropzone');
  ['dragenter', 'dragover'].forEach((evName) => {
    dropTarget.addEventListener(evName, (e) => {
      e.preventDefault();
      composer.classList.add('drag');
    });
  });
  ['dragleave', 'drop'].forEach((evName) => {
    dropTarget.addEventListener(evName, (e) => {
      e.preventDefault();
      composer.classList.remove('drag');
      if (evName === 'drop' && e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        updateSelectedFiles(e.dataTransfer.files, true);
      }
    });
  });

  clearInterval(state.clockTimer);
  state.clockTimer = setInterval(syncElapsedClock, 1000);
}

async function boot() {
  wireEvents();
  initDebugMode();
  const saved = localStorage.getItem(STORAGE_KEY);
  if (saved) state.selectedId = saved;
  try {
    await loadConfig();
    await refreshState();
    if (IS_DEBUG) await loadDebugOverview(false);
  } catch (_) {
    setFormError('Chưa kết nối được máy chủ Web cục bộ. Hãy kiểm tra cửa sổ chạy start-web.bat.');
  }
}

boot();
