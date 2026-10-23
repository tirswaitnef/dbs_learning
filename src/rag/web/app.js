/* ============================================================================
   DBSec OWASP Assistant — Complete Web UI Controller (CSP-Safe, Zero Inline JS)
   Matches IMG_8610 design with 100% genuine backend-connected features
   ============================================================================ */

const STORAGE_KEY = 'dbsec_active_thread_v2';
const TERMINAL = new Set(['completed', 'partial', 'failed']);
const IS_DEBUG = window.location.pathname === '/debug' || window.location.pathname.startsWith('/debug/');

const META_KEYS = [
  'report_id',
  'project_name',
  'target_object',
  'dbms_override',
  'assessment_period',
  'retest_status',
  'retest_evidence',
  'prepared_by',
  'excluded_areas',
  'mask_public_ips',
  'xss_decision',
  'force_fresh_ai',
];

const PIPELINE_STEPS = [
  { num: 1, title: 'Đọc & chuẩn hóa đầu vào', detail: 'Tách bản ghi, gộp cảnh báo trùng & che dữ liệu nhạy cảm' },
  { num: 2, title: 'Phân loại CWE & ngữ cảnh CSDL', detail: 'Đối chiếu mã CWE, trạng thái xác nhận và quan sát thụ động' },
  { num: 3, title: 'Truy xuất OWASP Hybrid RAG', detail: 'Kết hợp Dense Vector + Heading BM25 RRF trên 25 Cheat Sheets' },
  { num: 4, title: 'Phân tích & kiểm duyệt chéo AI', detail: 'Sinh mô tả kỹ thuật và xác minh trích dẫn nguyên văn' },
  { num: 5, title: 'Dựng cấu trúc Báo cáo Gọn 6 mục', detail: 'Phân tách rõ Phát hiện (Mục 2), Quan sát (Mục 3) & Âm tính (Mục 4)' },
  { num: 6, title: 'Kết xuất PDF, Markdown & SHA-256', detail: 'Đóng gói báo cáo tiếng Việt sẵn sàng xem trực tiếp và tải về' },
];

const SVG_NS = 'http://www.w3.org/2000/svg';
const ICONS = {
  bot: [
    ['rect', { x: 4, y: 4, width: 16, height: 16, rx: 5 }],
    ['path', { d: 'M9.5 12.2l1.8 1.8 3.6-3.8' }],
  ],
  file: [
    ['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }],
    ['polyline', { points: '14 2 14 8 20 8' }],
  ],
  download: [
    ['path', { d: 'M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4' }],
    ['polyline', { points: '7 10 12 15 17 10' }],
    ['line', { x1: 12, y1: 15, x2: 12, y2: 3 }],
  ],
  eye: [
    ['path', { d: 'M7 17L17 7' }],
    ['polyline', { points: '9 7 17 7 17 15' }],
  ],
  copy: [
    ['rect', { x: 9, y: 9, width: 13, height: 13, rx: 2 }],
    ['path', { d: 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1' }],
  ],
  clock: [
    ['circle', { cx: 12, cy: 12, r: 9 }],
    ['polyline', { points: '12 7 12 12 15 15' }],
  ],
  link: [
    ['path', { d: 'M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71' }],
    ['path', { d: 'M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71' }],
  ],
};

const state = {
  token: '',
  config: null,
  jobs: [],
  threads: [],
  selectedId: null,
  checkedThreadIds: new Set(),
  activeView: 'chat',
  searchQuery: '',
  selectedFiles: [],
  submitting: false,
  pendingUserText: '',
  lastRenderSig: '',
  pollTimer: null,
  clockTimer: null,
  toastTimer: null,
  reportCache: {},
  mdCache: {},
  traceCache: {},
  debugTab: 'eval',
  debugJobId: null,
  debugCommsSig: '',
  debugOverview: null,
};

function el(id) {
  return document.getElementById(id);
}

function create(tag, cls = '', text = '') {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== '' && text !== null && text !== undefined) node.textContent = String(text);
  return node;
}

function icon(name, size = 16) {
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
  if (!job) return 'Trò chuyện bảo mật';
  if (job.status === 'queued') return 'Đang chờ phân tích';
  if (job.status === 'running') return `${job.percent || 10}% · ${job.stage || 'Đang phân tích'}`;
  if (job.status === 'completed') return 'Báo cáo 6 mục sẵn sàng';
  if (job.status === 'partial') return 'Hoàn tất (một phần AI)';
  return 'Cần kiểm tra lại';
}

function showToast(text) {
  const box = el('toast');
  if (!box) return;
  box.textContent = text;
  box.hidden = false;
  clearTimeout(state.toastTimer);
  state.toastTimer = setTimeout(() => { box.hidden = true; }, 4000);
}

function setFormError(text) {
  const box = el('form-error');
  if (!box) return;
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
   CSP-Clean Line-Numbered Syntax Code Block Renderer (IMG_8610 style)
   ============================================================================ */
function appendHighlightedLine(cell, lineText) {
  const trimmed = lineText.trimStart();
  if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('-- ')) {
    cell.appendChild(create('span', 'tok-cmt', lineText));
    return;
  }
  const tokenRe = /("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|\b(?:const|let|var|function|return|async|await|if|else|new|try|catch|SELECT|FROM|WHERE|AND|OR|UNION|INSERT|UPDATE|DELETE|GRANT|REVOKE|PREPARE|EXECUTE|PDO)\b|\b[A-Za-z_$][A-Za-z0-9_$]*(?=\s*\())/g;
  let last = 0;
  let m;
  while ((m = tokenRe.exec(lineText)) !== null) {
    if (m.index > last) cell.appendChild(document.createTextNode(lineText.slice(last, m.index)));
    const tok = m[0];
    if (tok.startsWith('"') || tok.startsWith('\'')) {
      cell.appendChild(create('span', 'tok-str', tok));
    } else if (/^(const|let|var|function|return|async|await|if|else|new|try|catch|SELECT|FROM|WHERE|AND|OR|UNION|INSERT|UPDATE|DELETE|GRANT|REVOKE|PREPARE|EXECUTE|PDO)$/.test(tok)) {
      cell.appendChild(create('span', 'tok-kw', tok));
    } else {
      cell.appendChild(create('span', 'tok-fn', tok));
    }
    last = m.index + tok.length;
  }
  if (last < lineText.length) cell.appendChild(document.createTextNode(lineText.slice(last)));
}

function buildLinedCodeSurface(codeText) {
  const surface = create('div', 'code-window-surface');
  const table = create('table', 'lined-code-table');
  const tbody = create('tbody');
  const lines = String(codeText || '').replace(/\r\n/g, '\n').split('\n');
  lines.forEach((ln, idx) => {
    const tr = create('tr');
    tr.appendChild(create('td', 'ln-col', String(idx + 1)));
    const srcTd = create('td', 'src-col');
    appendHighlightedLine(srcTd, ln);
    tr.appendChild(srcTd);
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  surface.appendChild(table);
  return surface;
}

function buildCopyButton(getTextFn, label = 'Sao chép') {
  const btn = create('button', 'code-copy-btn');
  btn.type = 'button';
  const txtSpan = create('span', '', label);
  btn.append(icon('copy', 14), txtSpan);
  btn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(getTextFn());
      txtSpan.textContent = 'Đã chép ✓';
      setTimeout(() => { txtSpan.textContent = label; }, 1700);
    } catch (_) {
      txtSpan.textContent = 'Không chép được';
    }
  });
  return btn;
}

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
      const lang = (fenceMatch[1] || 'CODE').toUpperCase();
      const codeBody = fenceMatch[2].replace(/\n$/, '');
      const wrap = create('div', 'md-code-wrap');
      const topBar = create('div', 'code-window-topbar');
      const tabs = create('div', 'card-tab-list');
      tabs.appendChild(create('span', 'card-tab-btn active', lang));
      topBar.append(tabs, buildCopyButton(() => codeBody, 'Sao chép mã'));
      wrap.append(topBar, buildLinedCodeSurface(codeBody));
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
      const trimmed = rawLine.trim();
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

/* ============================================================================
   View Navigation (Chat, Templates, Live OWASP Lookup, Session Stats, Settings)
   ============================================================================ */
function switchMainView(viewName) {
  state.activeView = viewName;
  document.querySelectorAll('.rail-item').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.view === viewName);
  });

  const isChat = viewName === 'chat';
  el('composer-wrap').hidden = !isChat;
  el('view-templates').hidden = viewName !== 'templates';
  el('view-owasp').hidden = viewName !== 'owasp';
  el('view-stats').hidden = viewName !== 'stats';
  el('view-settings').hidden = viewName !== 'settings';

  if (!isChat) {
    el('empty-state').hidden = true;
    el('messages').hidden = true;
    const titles = {
      templates: ['Kịch bản Mẫu Kiểm thử', 'Chọn nhanh câu hỏi kỹ thuật có thể gửi trực tiếp cho Trợ lý AI'],
      owasp: ['Tra cứu Kho OWASP CSDL', 'Hybrid Search (Dense E5 + Heading BM25 + RRF) trên 25 Cheat Sheets cục bộ'],
      stats: ['Thống kê Phiên Phân tích', 'Tổng hợp trực tiếp từ các tệp kiểm thử và hội thoại đã thực hiện'],
      settings: ['Cấu hình Báo cáo & Phiên', 'Thiết lập tùy chọn đầu trang cho PDF & Markdown'],
    };
    const [t, s] = titles[viewName] || titles.settings;
    el('chat-thread-title').textContent = t;
    el('chat-thread-sub').textContent = s;
    if (viewName === 'owasp' && !el('owasp-results-list').children.length) runLiveOwaspLookup();
    if (viewName === 'stats') renderLiveStatistics();
  } else {
    renderWorkspace(false);
  }
  closeSidebar();
}

async function runLiveOwaspLookup(event) {
  if (event) event.preventDefault();
  const host = el('owasp-results-list');
  if (!host) return;
  const query = (el('owasp-q')?.value || '').trim();
  const cwe = (el('owasp-cwe')?.value || '').trim();
  if (!query) return;
  host.replaceChildren(create('div', 'event-panel', 'Đang truy xuất kho OWASP Cheat Sheet Series cục bộ...'));
  try {
    const res = await api('/api/debug/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ query, cwe, stack_hint: '', top_k: 6 }),
    });
    host.replaceChildren();
    const hits = res.results || [];
    if (!hits.length) {
      host.appendChild(create('div', 'history-empty', 'Không tìm thấy đoạn hướng dẫn khớp trực tiếp. Hãy thử từ khóa khác.'));
      return;
    }
    for (const h of hits) {
      const card = create('article', 'owasp-hit-card');
      const head = create('div', 'owasp-hit-head');
      const titleLink = create('a', 'json-link', `#${h.rank} · ${h.source}`);
      titleLink.href = h.url;
      titleLink.target = '_blank';
      titleLink.rel = 'noopener';
      head.append(titleLink, create('span', 'tag-mini ok', `Hybrid RRF ${h.hybrid_score}`));
      card.appendChild(head);
      if (h.section) card.appendChild(create('div', 'preview-title', h.section));
      card.appendChild(renderMarkdownSafe(h.snippet || ''));
      const askBtn = create('button', 'followup-chip', 'Hỏi Trợ lý áp dụng hướng dẫn này →');
      askBtn.type = 'button';
      askBtn.addEventListener('click', () => {
        switchMainView('chat');
        sendTextPrompt(`Dựa trên tài liệu ${h.source} (${h.section || 'OWASP'}), hãy hướng dẫn chi tiết cách triển khai thực tế kèm code mẫu.`);
      });
      card.appendChild(askBtn);
      host.appendChild(card);
    }
  } catch (err) {
    host.replaceChildren(create('p', 'failure', err.message || 'Không thực hiện được tra cứu OWASP.'));
  }
}

function renderLiveStatistics() {
  const host = el('stats-live-body');
  if (!host) return;
  host.replaceChildren();

  const totalJobs = state.jobs.length;
  const completedJobs = state.jobs.filter((j) => j.status === 'completed' || j.status === 'partial');
  let confirmedTotal = 0;
  let tentativeTotal = 0;
  let guidanceTotal = 0;
  const sevCounts = {};

  for (const j of completedJobs) {
    const s = j.summary || {};
    confirmedTotal += Number(s.confirmed_findings ?? 0);
    tentativeTotal += Number(s.tentative_findings ?? 0) + Number(s.insufficient_findings ?? 0);
    guidanceTotal += Number(s.with_guidance ?? 0);
    for (const f of (s.findings_preview || [])) {
      const k = f.severity_label || f.severity || 'Chưa xác định';
      sevCounts[k] = (sevCounts[k] || 0) + 1;
    }
  }

  const metrics = create('div', 'metrics');
  for (const [val, label] of [
    [String(state.threads.length), 'Cuộc trò chuyện lưu trữ'],
    [String(totalJobs), 'Tệp kiểm thử đã phân tích'],
    [String(confirmedTotal), 'Lỗ hổng Đã xác nhận'],
    [String(guidanceTotal), 'Khuyến nghị OWASP đối chiếu'],
  ]) {
    const m = create('div', 'metric');
    m.append(create('strong', '', val), create('span', '', label));
    metrics.appendChild(m);
  }
  host.appendChild(metrics);

  const detailCard = create('div', 'settings-card');
  detailCard.appendChild(create('div', 'preview-title', 'Phân bố Mức độ Nghiêm trọng trên các Báo cáo Hiện có'));
  const entries = Object.entries(sevCounts);
  if (!entries.length) {
    detailCard.appendChild(create('p', '', `Chưa có phát hiện lỗ hổng nào được ghi nhận (${tentativeTotal} mục cần xác minh). Hãy đính kèm tệp quét ở mục Trợ lý AI để thống kê.`));
  } else {
    for (const [sevLabel, cnt] of entries) {
      const row = create('div', 'preview-row');
      row.append(create('strong', '', sevLabel), create('span', 'tag-mini ok', `${cnt} phát hiện`));
      detailCard.appendChild(row);
    }
  }
  host.appendChild(detailCard);
}

/* ============================================================================
   PDF Modal Viewer + Lazy Job Markdown / Evidence Fetcher
   ============================================================================ */
function openPdfModal(job) {
  const tokSuffix = state.token ? `&token=${encodeURIComponent(state.token)}` : '';
  const inlineUrl = `/api/jobs/${job.id}/pdf?inline=1&profile=compact${tokSuffix}`;
  const dlUrl = `/api/jobs/${job.id}/pdf?profile=compact${tokSuffix}`;
  el('pdf-modal-title').textContent = `Báo cáo Kiểm thử Bảo mật — ${job.filename}`;
  el('pdf-modal-frame').src = inlineUrl;
  el('pdf-modal-download').href = dlUrl;
  el('pdf-modal-download').download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.pdf`;
  el('pdf-modal-newtab').href = inlineUrl;
  el('pdf-modal').hidden = false;
}

function closePdfModal() {
  const modal = el('pdf-modal');
  if (!modal) return;
  modal.hidden = true;
  el('pdf-modal-frame').src = 'about:blank';
}

async function ensureJobMarkdownLoaded(jobId) {
  if (state.mdCache[jobId]) return state.mdCache[jobId];
  const tokSuffix = state.token ? `&token=${encodeURIComponent(state.token)}` : '';
  const text = await api(`/api/jobs/${jobId}/md?profile=compact${tokSuffix}`);
  state.mdCache[jobId] = String(text || '');
  return state.mdCache[jobId];
}

function extractEvidenceSnippetFromMarkdown(mdText) {
  const blocks = [];
  const rx = /```[A-Za-z0-9_+#.-]*\n([\s\S]*?)```/g;
  let m;
  while ((m = rx.exec(mdText)) !== null) {
    if (m[1] && m[1].trim()) blocks.push(m[1].trim());
  }
  if (blocks.length) return blocks.join('\n\n// ─────────────────────────────────────────\n\n');
  return mdText;
}

/* ============================================================================
   File Selection, History Sidebar (Checkboxes + Real Delete), & Completed Card
   ============================================================================ */
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
    chip.appendChild(icon('file', 14));
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
  const dot = document.querySelector('.engine-dot');
  if (!banner || !pill || !state.config) return;
  banner.className = 'banner';
  if (state.config.demo) {
    pill.textContent = 'Chế độ Demo · OWASP RAG';
    if (dot) dot.classList.remove('offline');
    banner.hidden = true;
    return;
  }
  if (!state.config.configured) {
    pill.textContent = 'RAG Cục bộ (Chờ Ollama)';
    if (dot) dot.classList.add('offline');
    banner.textContent = 'Mô hình Ollama chưa sẵn sàng — chế độ phân tích AI chưa khả dụng.';
    banner.hidden = false;
    return;
  }
  if (dot) dot.classList.remove('offline');
  pill.textContent = state.config.provider === 'ollama'
    ? `Ollama · ${state.config.model}`
    : `AI · ${state.config.model}`;
  banner.hidden = true;
}

function findJob(jobId) {
  return state.jobs.find((j) => j.id === jobId) || null;
}

function updateClearHistoryLabel() {
  const lbl = el('clear-history-label');
  if (!lbl) return;
  const cnt = state.checkedThreadIds.size;
  lbl.textContent = cnt > 0 ? `Xóa đã chọn (${cnt})` : 'Xóa lịch sử';
}

function renderHistory() {
  const nav = el('history');
  const badge = el('history-count-badge');
  if (!nav) return;
  nav.replaceChildren();

  const q = state.searchQuery.trim().toLowerCase();
  const visibleThreads = q
    ? state.threads.filter((th) => {
      const hay = `${th.title || ''} ${(th.messages || []).map((m) => m.text || '').join(' ')}`.toLowerCase();
      return hay.includes(q);
    })
    : state.threads;

  if (badge) {
    badge.textContent = q
      ? `${visibleThreads.length}/${state.threads.length}`
      : `${state.threads.length}`;
  }

  for (const checkedId of Array.from(state.checkedThreadIds)) {
    if (!state.threads.some((t) => t.id === checkedId)) state.checkedThreadIds.delete(checkedId);
  }
  updateClearHistoryLabel();

  if (!visibleThreads.length) {
    nav.appendChild(create(
      'div',
      'history-empty',
      q
        ? 'Không có cuộc trò chuyện nào khớp từ khóa tìm kiếm.'
        : 'Chưa có lịch sử trò chuyện. Hãy đặt câu hỏi hoặc gửi tệp quét để bắt đầu.'
    ));
    return;
  }

  for (const th of visibleThreads) {
    const activeJob = th.active_job_id ? findJob(th.active_job_id) : null;
    const card = create('div', 'history-card' + (th.id === state.selectedId ? ' active' : ''));

    const chk = document.createElement('input');
    chk.type = 'checkbox';
    chk.className = 'history-check';
    chk.checked = state.checkedThreadIds.has(th.id);
    chk.setAttribute('aria-label', `Chọn ${th.title || 'cuộc trò chuyện'}`);
    chk.addEventListener('click', (e) => e.stopPropagation());
    chk.addEventListener('change', () => {
      if (chk.checked) state.checkedThreadIds.add(th.id);
      else state.checkedThreadIds.delete(th.id);
      updateClearHistoryLabel();
    });

    const body = create('div', 'history-card-body');
    body.appendChild(create('strong', '', th.title || 'Phiên kiểm thử bảo mật'));
    const lastMsg = [...(th.messages || [])].reverse().find((m) => m.text && m.text.trim());
    const previewTxt = activeJob
      ? `${statusText(activeJob)} · ${formatTime(th.updated_at)}`
      : (lastMsg ? lastMsg.text.trim().slice(0, 96) : `${(th.messages || []).length} tin nhắn`);
    body.appendChild(create('p', '', previewTxt));

    card.append(chk, body);
    card.addEventListener('click', () => {
      if (state.activeView !== 'chat') switchMainView('chat');
      selectThread(th.id);
    });
    nav.appendChild(card);
  }
}

async function handleClearHistory() {
  if (!state.threads.length) {
    showToast('Lịch sử hiện đang trống.');
    return;
  }
  const selectedIds = Array.from(state.checkedThreadIds);
  const query = selectedIds.length ? `?ids=${encodeURIComponent(selectedIds.join(','))}` : '';
  try {
    const res = await api(`/api/threads${query}`, { method: 'DELETE' });
    state.checkedThreadIds.clear();
    if (!selectedIds.length || selectedIds.includes(state.selectedId)) {
      state.selectedId = null;
      localStorage.removeItem(STORAGE_KEY);
    }
    state.lastRenderSig = '';
    await refreshState();
    showToast(`Đã xóa ${res.deleted_threads || 0} cuộc trò chuyện khỏi lịch sử.`);
  } catch (err) {
    showToast(err.message || 'Không xóa được lịch sử.');
  }
}

function assistantAvatar() {
  const wrap = create('div', 'message-avatar');
  wrap.appendChild(icon('bot', 17));
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
  const dlTrace = create('a', 'json-link', 'Tải bản ghi lệnh AI (.txt)');
  dlTrace.href = `/api/jobs/${job.id}/trace-txt${qTok}`;
  dlTrace.download = `lenh-gui-ai-${job.id.slice(0, 8)}.txt`;
  wrap.appendChild(dlTrace);

  if (!cached) {
    details.addEventListener('toggle', () => {
      if (details.open) fetchJobTrace(job.id);
    }, { once: true });
    wrap.appendChild(create('p', '', 'Mở mục này để tải danh sách câu lệnh đã gửi cho AI.'));
  } else if (cached.loading && !entries.length) {
    wrap.appendChild(create('p', '', 'Đang tải nhật ký câu lệnh AI...'));
  } else if (!entries.length) {
    wrap.appendChild(create('p', '', 'Chưa ghi nhận lượt gọi LLM nào.'));
  } else {
    entries.forEach((item, idx) => {
      const box = create('details', 'event-panel');
      if (idx === entries.length - 1) box.open = true;
      box.appendChild(create('summary', '', `${idx + 1}. [${formatEventTime(item.at)}] ${item.model || 'AI'} · ${item.duration_sec ?? 0}s`));
      if (item.system) box.appendChild(create('pre', 'trace-pre', item.system));
      box.appendChild(create('pre', 'trace-pre', item.prompt || ''));
      box.appendChild(create('pre', 'trace-pre', item.response || ''));
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
  titleWrap.appendChild(create('strong', 'process-stage-title', job.stage || 'Đang phân tích dữ liệu kiểm thử...'));

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

/* Signature IMG_8610 Tabbed Halo Card for Completed Scan Reports */
function buildCompletedCard(job) {
  const s = job.summary || {};
  const card = create('div', 'assistant-halo-card');

  let activeCopyText = '';
  const topBar = create('div', 'code-window-topbar');
  const tabBar = create('div', 'card-tab-list');
  const btnOverview = create('button', 'card-tab-btn active', 'Báo cáo gọn');
  btnOverview.type = 'button';
  const btnEvidence = create('button', 'card-tab-btn', 'Bằng chứng & Mã vá');
  btnEvidence.type = 'button';
  const btnMarkdown = create('button', 'card-tab-btn', 'Markdown 6 mục');
  btnMarkdown.type = 'button';
  tabBar.append(btnOverview, btnEvidence, btnMarkdown);

  const copyBtn = buildCopyButton(() => activeCopyText, 'Sao chép');
  topBar.append(tabBar, copyBtn);
  card.appendChild(topBar);

  // Panel 1: Summary & Findings Overview
  const overviewPanel = create('div', 'report-tab-panel');
  const confirmedNum = s.confirmed_findings !== undefined ? s.confirmed_findings : (s.findings ?? job.count ?? 0);
  const unconfirmedNum = (s.tentative_findings ?? 0) + (s.insufficient_findings ?? 0);

  const metrics = create('div', 'metrics');
  for (const [val, label] of [
    [String(confirmedNum), 'Lỗ hổng Đã xác nhận (Mục 1–2)'],
    [String(unconfirmedNum), 'Cần xác minh (Mục 5)'],
    [String(s.with_guidance ?? 0), 'Khuyến nghị OWASP'],
    [formatDurationHuman(s.duration_sec || 0), 'Thời gian xử lý'],
  ]) {
    const m = create('div', 'metric');
    m.append(create('strong', '', val), create('span', '', label));
    metrics.appendChild(m);
  }
  overviewPanel.appendChild(metrics);

  const preview = s.findings_preview || [];
  const summaryLines = [`Báo cáo Kiểm thử Bảo mật — ${job.filename}`];
  if (preview.length) {
    const wrap = create('div', 'preview-wrap');
    wrap.appendChild(create('div', 'preview-title', `Phát hiện ghi nhận (${preview.length} mục)`));
    for (const f of preview) {
      const row = create('div', 'preview-row');
      const main = create('div', 'preview-main');
      const sevKey = (f.severity || 'unknown').toLowerCase();
      const sevLabel = f.severity_label || sevKey.toUpperCase();
      main.appendChild(create('span', `sev-badge sev-${sevKey}`, sevLabel));
      main.appendChild(create('strong', '', `${f.id}: ${f.title || 'Phát hiện'}`));

      const tags = create('div', 'preview-tags');
      if (f.state) {
        tags.appendChild(create('span', f.state === 'Đã xác nhận' ? 'tag-mini ok' : 'tag-mini warn', f.state));
      }
      if (f.owasp) tags.appendChild(create('span', 'tag-mini', f.owasp));
      row.append(main, tags);
      wrap.appendChild(row);
      summaryLines.push(`- ${f.id}: ${f.title} [${sevLabel} | ${f.state || ''}]`);
    }
    overviewPanel.appendChild(wrap);
  } else {
    overviewPanel.appendChild(create('p', '', 'Không có lỗ hổng xác nhận ở Mục 2 — các dịch vụ/cổng mở và phép thử âm tính được trình bày sạch tại Mục 3, Mục 4 và Mục 5 trong bản PDF.'));
  }
  activeCopyText = summaryLines.join('\n');

  // Panel 2: Line-Numbered Evidence & Remediation Code (IMG_8610 signature pane)
  const evidencePanel = create('div', 'code-window-surface');
  evidencePanel.hidden = true;

  // Panel 3: Full 6-Section Markdown with Line Numbers
  const mdPanel = create('div', 'code-window-surface');
  mdPanel.hidden = true;

  const setTab = async (tabKey) => {
    btnOverview.classList.toggle('active', tabKey === 'overview');
    btnEvidence.classList.toggle('active', tabKey === 'evidence');
    btnMarkdown.classList.toggle('active', tabKey === 'md');
    overviewPanel.hidden = tabKey !== 'overview';
    evidencePanel.hidden = tabKey !== 'evidence';
    mdPanel.hidden = tabKey !== 'md';

    if (tabKey === 'overview') {
      activeCopyText = summaryLines.join('\n');
      return;
    }
    const targetBox = tabKey === 'evidence' ? evidencePanel : mdPanel;
    targetBox.replaceChildren(create('p', '', 'Đang tải nội dung từ báo cáo...'));
    try {
      const mdText = await ensureJobMarkdownLoaded(job.id);
      const codeStr = tabKey === 'evidence' ? extractEvidenceSnippetFromMarkdown(mdText) : mdText;
      activeCopyText = codeStr;
      targetBox.replaceChildren(buildLinedCodeSurface(codeStr).firstChild);
    } catch (err) {
      targetBox.replaceChildren(create('p', 'failure', err.message || 'Không tải được dữ liệu.'));
    }
  };

  btnOverview.addEventListener('click', () => setTab('overview'));
  btnEvidence.addEventListener('click', () => setTab('evidence'));
  btnMarkdown.addEventListener('click', () => setTab('md'));

  card.append(overviewPanel, evidencePanel, mdPanel);

  // Bottom White Project Bar + View / Download Buttons (matching IMG_8610 bottom bar)
  const tokSuffix = state.token ? `&token=${encodeURIComponent(state.token)}` : '';
  const qTok = state.token ? `?token=${encodeURIComponent(state.token)}` : '';
  const projectBar = create('div', 'card-project-bar');
  projectBar.appendChild(create(
    'div',
    'card-project-label',
    `Đã xuất Báo cáo Gọn 6 mục · ${job.filename}`
  ));

  const actionGroup = create('div', 'card-project-actions');

  const viewPdfBtn = create('button', 'card-action-btn');
  viewPdfBtn.type = 'button';
  viewPdfBtn.append(icon('eye', 14), create('span', '', 'Xem PDF'));
  viewPdfBtn.addEventListener('click', () => openPdfModal(job));

  const dlPdfLink = create('a', 'card-action-btn primary');
  dlPdfLink.href = `/api/jobs/${job.id}/pdf?profile=compact${tokSuffix}`;
  dlPdfLink.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.pdf`;
  dlPdfLink.append(icon('download', 14), create('span', '', 'Tải PDF'));

  const dlMdLink = create('a', 'card-action-btn');
  dlMdLink.href = `/api/jobs/${job.id}/md?profile=compact${tokSuffix}`;
  dlMdLink.download = `bao-cao-bao-mat-csdl-${job.id.slice(0, 8)}.md`;
  dlMdLink.textContent = 'Markdown';

  const dlFullLink = create('a', 'card-action-btn');
  dlFullLink.href = `/api/jobs/${job.id}/pdf?profile=full${tokSuffix}`;
  dlFullLink.download = `bao-cao-bao-mat-csdl-day-du-${job.id.slice(0, 8)}.pdf`;
  dlFullLink.textContent = 'PDF Đầy đủ';

  const dlJsonLink = create('a', 'card-action-btn');
  dlJsonLink.href = `/api/jobs/${job.id}/json${qTok}`;
  dlJsonLink.download = `du-lieu-bao-cao-${job.id.slice(0, 8)}.json`;
  dlJsonLink.textContent = 'JSON';

  actionGroup.append(viewPdfBtn, dlPdfLink, dlMdLink, dlFullLink, dlJsonLink);
  projectBar.appendChild(actionGroup);
  card.appendChild(projectBar);

  return card;
}

function renderJobExchangeNode(job, userNote) {
  const frag = document.createDocumentFragment();

  const uRow = create('div', 'chat-row is-user');
  const uStack = create('div', 'chat-user-stack');
  const fileCard = create('div', 'upload-card');
  const formatName = (state.config && state.config.formats && state.config.formats[job.format]) || job.format;
  fileCard.appendChild(icon('file', 19));
  const meta = create('div');
  meta.appendChild(create('strong', '', job.filename));
  meta.appendChild(create('span', '', `${formatName} · ${formatBytes(job.size)} · ${job.count} bản ghi`));
  fileCard.appendChild(meta);
  uStack.appendChild(fileCard);
  const noteTxt = (userNote || job.note || '').trim();
  if (noteTxt) uStack.appendChild(create('div', 'chat-bubble-user', noteTxt));
  uRow.appendChild(uStack);
  frag.appendChild(uRow);

  const bRow = create('div', 'chat-row is-assistant');
  bRow.appendChild(assistantAvatar());
  const body = create('div', 'chat-assistant-col');
  const head = create('div', 'chat-msg-head');
  head.appendChild(create('span', 'chat-msg-author', 'DBSec OWASP Assistant'));
  head.appendChild(create('span', 'chat-msg-time', formatTime(job.updated_at || job.created_at)));
  body.appendChild(head);

  if (!TERMINAL.has(job.status)) {
    body.appendChild(create('p', '', 'Đang phân tích dữ liệu kiểm thử, gộp cảnh báo cùng nguyên nhân gốc và kết xuất Báo cáo Gọn 6 mục:'));
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
    body.appendChild(buildCompletedCard(job));
    const s = job.summary || {};
    body.appendChild(renderMarkdownSafe(
      `Ghi chú: Báo cáo **${job.filename}** tuân thủ nghiêm ngặt quy tắc không tự bịa điểm CVSS/mức độ nghiêm trọng, tách riêng quan sát thụ động sang **Mục 3** và phép thử âm tính sang **Mục 4**. Bạn có thể nhấn **Xem PDF**, chuyển sang tab **Bằng chứng & Mã vá**, hoặc hỏi tiếp bên dưới.`
    ));
    if (job.status === 'partial') {
      body.appendChild(create('p', 'result-warning',
        `Một số đoạn diễn giải AI chưa hoàn tất (${s.ai_reviewed ?? 0}/${s.findings ?? 0}), nhưng toàn bộ bảng tổng hợp, bằng chứng gốc và khuyến nghị OWASP đều đầy đủ.`));
    }
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
  const q = state.searchQuery.trim().toLowerCase();
  const entries = (thread.messages || []).filter((m) => {
    if (!q || m.role === 'job') return true;
    return String(m.text || '').toLowerCase().includes(q);
  });

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
      head.appendChild(create('span', 'chat-msg-author', 'DBSec OWASP Assistant'));
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

      const utilRow = create('div', 'msg-utility-row');
      const copyReplyBtn = create('button', 'msg-util-btn');
      copyReplyBtn.type = 'button';
      const lbl = create('span', '', 'Sao chép phản hồi');
      copyReplyBtn.append(icon('copy', 13), lbl);
      copyReplyBtn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(m.text || '');
          lbl.textContent = 'Đã chép ✓';
          setTimeout(() => { lbl.textContent = 'Sao chép phản hồi'; }, 1600);
        } catch (_) {
          lbl.textContent = 'Không chép được';
        }
      });
      utilRow.appendChild(copyReplyBtn);
      bCol.appendChild(utilRow);

      bRow.appendChild(bCol);
      frag.appendChild(bRow);
      if ((m.suggestions || []).length) latestSuggestions = m.suggestions;
    }
  }

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
        'Giải thích chi tiết lỗ hổng chính và viết code vá an toàn',
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
  renderHistory();
  if (IS_DEBUG) renderDebugComms(false);
  if (state.activeView !== 'chat') {
    if (state.activeView === 'stats') renderLiveStatistics();
    return;
  }

  const thread = state.threads.find((t) => t.id === state.selectedId) || null;
  const showChat = Boolean(thread || state.pendingUserText);

  el('empty-state').hidden = showChat;
  const messagesEl = el('messages');
  messagesEl.hidden = !showChat;

  const titleEl = el('chat-thread-title');
  const subEl = el('chat-thread-sub');
  if (thread) {
    const activeJob = thread.active_job_id ? findJob(thread.active_job_id) : null;
    if (titleEl) titleEl.textContent = thread.title || 'Trợ lý AI Kiểm thử Bảo mật';
    if (subEl) {
      subEl.textContent = activeJob
        ? `${statusText(activeJob)} · Hỏi đáp trực tiếp trên dữ liệu báo cáo này`
        : 'Đang trò chuyện cùng Trợ lý AI & Kho tri thức OWASP CSDL';
    }
  } else {
    if (titleEl) titleEl.textContent = 'Trợ lý AI Kiểm thử Bảo mật';
    if (subEl) subEl.textContent = 'Hỏi đáp kỹ thuật CSDL, phân tích tệp quét & xuất Báo cáo Gọn 6 mục';
  }

  const sig = JSON.stringify({
    tid: state.selectedId,
    q: state.searchQuery,
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
}

function startNewThread() {
  state.selectedId = null;
  state.lastRenderSig = '';
  localStorage.removeItem(STORAGE_KEY);
  if (state.activeView !== 'chat') switchMainView('chat');
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
  if (state.activeView !== 'chat') switchMainView('chat');
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
    setFormError('Hãy nhập câu hỏi bảo mật, dán kết quả kiểm thử, hoặc đính kèm tệp quét.');
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
      showToast('Đã tiếp nhận tệp · Đang phân tích & xuất Báo cáo Gọn 6 mục...');
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
    renderWorkspace(false);
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
    const llmDesc = rt.demo ? 'Chế độ Demo cục bộ' : `${rt.provider || 'ollama'} · ${rt.model || 'qwen3.5'}`;
    rtLabel.textContent = `LLM: ${llmDesc} · Vector: ${pruned.encoder || rt.embed_model || 'E5'} · Kho OWASP CSDL: ${pruned.document_count || 25} tệp (${pruned.chunk_count || 0} chunks)`;
  }

  const kpis = create('div', 'debug-kpi-grid');
  const mrrGain = ((Number(hyb.doc_mrr || 0) - Number(den.doc_mrr || 0)) * 100).toFixed(2);
  for (const [val, title, sub] of [
    [pctText(hyb.doc_hit_at_1), `Hybrid Doc Hit@1 (MRR ${Number(hyb.doc_mrr || 0).toFixed(4)})`, `Tăng +${mrrGain} điểm % MRR so với Dense thuần`],
    [comp ? `-${Number(comp.sheet_reduction_pct || 0).toFixed(1)}%` : '25 tệp', 'Thu gọn nhiễu Kho OWASP CSDL', `${pruned.chunk_count || 0} chunks chuyên biệt`],
    [pctText(guard.f1), 'F1-Score Trích xuất & Ánh xạ CWE', `Precision ${pctText(guard.precision)} · Recall ${pctText(guard.recall)}`],
    [`${guard.hallucinations_blocked || 0}/${guard.hallucinations_injected || 0}`, 'Chặn Ảo giác Đối kháng AI', 'Tự động giữ Chưa xác định khi thiếu CVSS'],
  ]) {
    const box = create('div', 'debug-kpi');
    box.append(create('strong', '', val), create('span', '', title), create('small', '', sub));
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
      titleCell.appendChild(create('div', '', r.snippet));
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
  document.title = '[DEBUG] DBSec OWASP — Thực nghiệm AI & Hybrid RAG';
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
  // Left rail navigation items
  document.querySelectorAll('.rail-item').forEach((btn) => {
    btn.addEventListener('click', () => switchMainView(btn.dataset.view));
  });

  // Collapsible left dark rail
  el('collapse-rail-btn')?.addEventListener('click', () => {
    el('app-shell').classList.toggle('rail-collapsed');
  });

  // Collapsible right history panel + reopen button
  el('collapse-history-btn')?.addEventListener('click', () => {
    const collapsed = el('app-shell').classList.toggle('history-collapsed');
    el('reopen-history-btn').hidden = !collapsed;
  });
  el('reopen-history-btn')?.addEventListener('click', () => {
    el('app-shell').classList.remove('history-collapsed');
    el('reopen-history-btn').hidden = true;
  });

  // Live search input
  el('global-search-input')?.addEventListener('input', (e) => {
    state.searchQuery = e.target.value || '';
    state.lastRenderSig = '';
    renderWorkspace(false);
  });

  // History clear / bulk delete button
  el('clear-history-btn')?.addEventListener('click', handleClearHistory);

  // Templates & OWASP Lookup & Settings actions
  document.querySelectorAll('.tpl-use-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      if (btn.dataset.tplPrompt) sendTextPrompt(btn.dataset.tplPrompt);
    });
  });
  el('owasp-live-form')?.addEventListener('submit', runLiveOwaspLookup);
  document.querySelectorAll('.owasp-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      el('owasp-q').value = chip.dataset.q || '';
      el('owasp-cwe').value = chip.dataset.cwe || '';
      runLiveOwaspLookup();
    });
  });
  el('save-settings-back-btn')?.addEventListener('click', () => {
    switchMainView('chat');
    showToast('Đã lưu cấu hình thông tin báo cáo cho phiên này.');
  });

  // File upload controls
  el('pick-file').addEventListener('click', () => el('file-input').click());
  el('file-input').addEventListener('change', (e) => {
    updateSelectedFiles(e.target.files, true);
    e.target.value = '';
  });
  el('clear-file').addEventListener('click', () => {
    el('file-input').value = '';
    updateSelectedFiles([], false);
  });

  // Composer textarea
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

  // PDF Preview Modal close handlers
  el('pdf-modal-close')?.addEventListener('click', closePdfModal);
  el('pdf-modal-backdrop')?.addEventListener('click', closePdfModal);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !el('pdf-modal').hidden) closePdfModal();
  });

  // Starter prompt cards on welcome screen
  document.querySelectorAll('.starter-card').forEach((card) => {
    card.addEventListener('click', () => {
      if (card.dataset.prompt) sendTextPrompt(card.dataset.prompt);
    });
  });

  // Drag & drop anywhere on main panel
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
