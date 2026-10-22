'use strict';
const $ = id => document.getElementById(id);

const STATUSES = {
  queued: 'Đang chờ xử lý',
  running: 'Đang xử lý',
  completed: 'Đã hoàn tất PDF',
  partial: 'PDF · có lưu ý',
  failed: 'Chưa hoàn tất'
};

const SEVERITY_VI = {
  critical: 'Nghiêm trọng',
  high: 'Cao',
  medium: 'Trung bình',
  low: 'Thấp',
  informational: 'Thông tin',
  info: 'Thông tin',
  unknown: 'Chưa rõ'
};

const PIPELINE_STEPS = [
  { num: 1, title: 'Đọc & chuẩn hóa dữ liệu kiểm thử', desc: 'Nhận diện công cụ quét, lọc nhiễu & rà soát dữ liệu nhạy cảm' },
  { num: 2, title: 'Nạp cơ sở tri thức bảo mật OWASP', desc: 'Đối chiếu 137 tài liệu hướng dẫn OWASP chính thức' },
  { num: 3, title: 'Chọn lọc hướng khắc phục trọng tâm', desc: 'Tổng hợp biện pháp khắc phục ngắn gọn & ví dụ mã nguồn' },
  { num: 4, title: 'Phân tích chi tiết lỗ hổng & tác động', desc: 'Biên soạn mô tả kỹ thuật & tác động nghiệp vụ dễ hiểu' },
  { num: 5, title: 'Biên tập Tóm tắt điều hành Pentest', desc: 'Tổng hợp mức độ rủi ro tổng thể & lộ trình ưu tiên xử lý' },
  { num: 6, title: 'Dàn trang & xuất Báo cáo Pentest PDF', desc: 'Tạo trang bìa, mục lục, chi tiết W-001+ & phụ lục bằng chứng' }
];

let config = null, jobs = [], selected = null, files = [], uploading = false, timer = null, tickTimer = null, lastSignature = '';

function element(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

function icon(name) {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', '#i-' + name);
  svg.append(use);
  return svg;
}

function formatBytes(bytes) {
  return bytes < 1024 * 1024 ? (bytes / 1024).toFixed(1) + ' KB' : (bytes / 1024 / 1024).toFixed(2) + ' MB';
}

function formatClock(sec) {
  const s = Math.max(0, Math.floor(sec));
  const m = Math.floor(s / 60);
  const rem = s % 60;
  return String(m).padStart(2, '0') + ':' + String(rem).padStart(2, '0');
}

function formatDurationHuman(sec) {
  if (!sec && sec !== 0) return '—';
  if (sec < 60) return sec.toFixed(1) + 's';
  const m = Math.floor(sec / 60);
  const s = Math.round(sec % 60);
  return m + 'p ' + String(s).padStart(2, '0') + 's';
}

function formatTimeHHMMSS(iso) {
  if (!iso) return '--:--:--';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString('vi-VN', { hour12: false });
}

function toast(msg) {
  $('toast').textContent = msg;
  $('toast').hidden = false;
  setTimeout(() => { $('toast').hidden = true; }, 4500);
}

function error(msg) {
  $('form-error').textContent = msg;
  $('form-error').hidden = !msg;
}

const BOOT_TOKEN = document.querySelector('meta[name="app-token"]')?.content || '';

async function api(url, options = {}) {
  const tok = config?.token || BOOT_TOKEN;
  const headers = { ...(options.headers || {}) };
  if (tok && !headers['X-App-Token']) headers['X-App-Token'] = tok;
  const r = await fetch(url, { credentials: 'same-origin', ...options, headers });
  let data;
  try {
    data = await r.json();
  } catch {
    throw new Error('Máy chủ cục bộ chưa phản hồi dữ liệu. Kiểm tra cửa sổ chạy start-web.bat.');
  }
  if (!r.ok) throw new Error(data.error || 'Không thực hiện được yêu cầu.');
  return data;
}

function applyConfig(c) {
  config = c;
  const badge = $('engine-badge');
  const dot = $('engine-dot');
  const txt = $('engine-text');
  if (config.demo) {
    badge.classList.add('warn');
    dot.classList.add('warn');
    txt.textContent = 'Chế độ Demo · Không gọi AI';
    $('config-notice').hidden = false;
    $('config-notice').textContent = 'ĐANG CHẠY CHẾ ĐỘ DEMO GIAO DIỆN — Không gọi AI và không truy xuất vector. Mở start-web.bat để chạy đầy đủ RAG + Ollama local.';
    $('privacy').textContent = 'Chế độ demo: chỉ kiểm tra luồng dữ liệu và xuất PDF mẫu cục bộ.';
    return;
  }
  if (config.issues && config.issues.length) {
    badge.classList.add('warn');
    dot.classList.add('warn');
    txt.textContent = 'Cần kiểm tra kết nối AI';
    $('config-notice').hidden = false;
    $('config-notice').textContent = config.issues.join(' ');
  } else {
    badge.classList.remove('warn');
    dot.classList.remove('warn');
    const engineLabel = config.provider === 'ollama'
      ? 'Ollama local' + (config.model ? ' · ' + config.model : '') + ' · Sẵn sàng'
      : 'Gemini · ' + (config.model || 'Sẵn sàng');
    txt.textContent = engineLabel;
    $('config-notice').hidden = true;
    $('config-notice').textContent = '';
  }
  $('privacy').textContent = config.provider === 'ollama'
    ? 'AI cục bộ (Ollama' + (config.model ? ' · ' + config.model : '') + '): toàn bộ file kiểm thử, kho vector OWASP 137 bài và quá trình sinh báo cáo chạy 100% trên máy này, không gửi dữ liệu ra internet.'
    : 'File kiểm thử và báo cáo lưu cục bộ trên máy này.';
}

function closeSidebar() {
  document.body.classList.remove('sidebar-open');
  $('scrim').hidden = true;
}

function fileToBase64(f) {
  return new Promise((res, rej) => {
    const rd = new FileReader();
    rd.onload = () => {
      const s = String(rd.result || '');
      res(s.slice(s.indexOf(',') + 1));
    };
    rd.onerror = () => rej(new Error('Không đọc được file ' + f.name));
    rd.readAsDataURL(f);
  });
}

function renderFileChips() {
  const wrap = $('file-chip');
  const box = $('file-chips');
  box.replaceChildren();
  if (!files.length) {
    wrap.hidden = true;
    $('note').placeholder = 'Kéo thả file kết quả kiểm thử vào khung này hoặc bấm “Đính kèm file” bên dưới… (có thể thêm ghi chú ngữ cảnh nếu cần)';
    return;
  }
  wrap.hidden = false;
  const total = files.reduce((acc, f) => acc + f.size, 0);
  $('file-summary').textContent = files.length === 1
    ? 'Đã đính kèm 1 file kiểm thử (' + formatBytes(total) + ')'
    : 'Đã chọn ' + files.length + ' file kiểm thử — sẽ gộp chung vào 1 báo cáo PDF (' + formatBytes(total) + ')';
  $('note').placeholder = 'Thêm ghi chú ngữ cảnh cho lần kiểm thử này (không bắt buộc)…';
  files.forEach((f, idx) => {
    const chip = element('div', 'single-chip');
    chip.append(icon('file'), element('strong', '', f.name), element('span', '', formatBytes(f.size)));
    const rm = element('button', '', '×');
    rm.type = 'button';
    rm.setAttribute('aria-label', 'Bỏ file ' + f.name);
    rm.addEventListener('click', () => {
      files.splice(idx, 1);
      $('file').value = '';
      renderFileChips();
    });
    chip.append(rm);
    box.append(chip);
  });
}

function chooseFiles(list) {
  const incoming = Array.from(list || []);
  if (!incoming.length) return;
  const merged = [...files];
  for (const f of incoming) {
    if (f.size === 0) {
      error('File "' + f.name + '" đang rỗng (0 byte).');
      return;
    }
    if (/\.pdf$/i.test(f.name)) {
      error('PDF là định dạng báo cáo đầu ra, không phải file log đầu vào. Hãy chọn file .txt, .log, .xml, .json hoặc .jsonl.');
      return;
    }
    const exists = merged.some(x => x.name === f.name && x.size === f.size);
    if (!exists) merged.push(f);
  }
  if (merged.length > 10) {
    error('Mỗi báo cáo gộp tối đa 10 file kiểm thử.');
    return;
  }
  const total = merged.reduce((acc, f) => acc + f.size, 0);
  if (total > 10 * 1024 * 1024) {
    error('Tổng dung lượng các file vượt quá giới hạn 10 MB.');
    return;
  }
  files = merged;
  $('file').value = '';
  error('');
  renderFileChips();
}

function reset() {
  selected = null;
  localStorage.removeItem('auditnote-selected');
  files = [];
  $('file').value = '';
  renderFileChips();
  $('note').value = '';
  error('');
  lastSignature = '';
  render();
  closeSidebar();
}

function select(id) {
  selected = id;
  localStorage.setItem('auditnote-selected', id);
  lastSignature = '';
  render();
  closeSidebar();
}

function renderHistory() {
  const history = $('history');
  history.replaceChildren();
  if (!jobs.length) {
    history.append(element('p', 'history-empty', 'Các phiên phân tích và file PDF của bạn sẽ lưu tại đây.'));
    return;
  }
  for (const job of jobs) {
    const b = element('button', 'history-item' + (selected === job.id ? ' active' : ''));
    b.type = 'button';
    b.append(icon('chat'));
    const text = element('div');
    let sub = STATUSES[job.status] || job.status;
    if (job.status === 'running' || job.status === 'queued') {
      sub = (STATUSES[job.status] || 'Đang xử lý') + ' · ' + (job.percent || 5) + '%';
    } else if (job.summary && typeof job.summary.findings === 'number') {
      sub = STATUSES[job.status] + ' · ' + job.summary.findings + ' bản ghi';
    } else {
      sub += ' · ' + new Date(job.created_at).toLocaleDateString('vi-VN');
    }
    text.append(element('strong', '', job.filename), element('small', '', sub));
    b.append(text, element('span', 'status-dot ' + job.status));
    b.addEventListener('click', () => select(job.id));
    history.append(b);
  }
}

function message(role, label) {
  const wrap = element('article', 'message ' + role);
  if (role !== 'user') {
    const avatar = element('span', 'message-avatar');
    avatar.append(icon('shield'));
    wrap.append(avatar);
  }
  const body = element('div', 'message-body');
  body.append(element('div', 'message-name', label));
  wrap.append(body);
  $('messages').append(wrap);
  return body;
}

function updateLiveTimers() {
  const activeJob = jobs.find(j => j.id === selected && (j.status === 'queued' || j.status === 'running'));
  if (!activeJob) return;
  const timerEl = $('live-timer-text');
  const hintEl = $('live-cpu-hint');
  const nowMs = Date.now();
  const startMs = Date.parse(activeJob.started_at || activeJob.created_at || '') || nowMs;
  const stageMs = Date.parse(activeJob.stage_started_at || activeJob.updated_at || '') || startMs;
  const totalSec = Math.max(0, (nowMs - startMs) / 1000);
  const stepSec = Math.max(0, (nowMs - stageMs) / 1000);
  if (timerEl) {
    timerEl.textContent = 'Tổng: ' + formatClock(totalSec) + ' · Bước này: ' + Math.floor(stepSec) + 's';
  }
  if (hintEl) {
    hintEl.hidden = stepSec < 8;
  }
}

function buildEventList(events) {
  const ul = element('ul', 'event-list');
  for (const ev of (events || [])) {
    const li = element('li');
    li.append(element('span', 'event-time', formatTimeHHMMSS(ev.at)), element('span', '', ev.text));
    ul.append(li);
  }
  return ul;
}

function renderJob(job) {
  const area = $('messages');
  area.replaceChildren();

  const user = message('user', ' Đầu vào kiểm thử');
  if (job.note) user.append(element('p', '', job.note));
  const card = element('div', 'upload-card');
  card.append(icon('file'));
  const info = element('div');
  const fmtText = (job.input_formats && job.input_formats.length)
    ? 'Gộp ' + job.input_formats.join(' + ')
    : (config?.formats[job.format] || job.format);
  info.append(
    element('strong', '', job.filename),
    element('span', '', fmtText + ' · ' + job.count + ' bản ghi phát hiện · ' + formatBytes(job.size || 0))
  );
  card.append(info);
  user.append(card);

  const bot = message('assistant', 'AuditNote');
  if (job.demo) {
    bot.append(element('p', 'result-warning', 'CHẾ ĐỘ DEMO: không gọi mô hình ngôn ngữ hoặc embedding. Báo cáo này chỉ minh họa bố cục PDF.'));
  }

  if (job.status === 'queued' || job.status === 'running') {
    const curStep = Number(job.step) || 1;
    const curPct = Math.min(99, Math.max(5, Number(job.percent) || 8));

    const process = element('div', 'process');
    const header = element('div', 'process-header');
    const title = element('div', 'process-title');
    title.setAttribute('role', 'status');
    title.append(element('span', 'spinner'), element('span', '', job.stage || 'Đang xử lý dữ liệu…'));

    const badges = element('div', 'process-badges');
    badges.append(element('span', 'pct-pill', curPct + '%'));
    const timerBadge = element('span', 'timer-pill');
    timerBadge.append(icon('clock'));
    const timerSpan = element('span', '', 'Tổng: 00:00 · Bước này: 0s');
    timerSpan.id = 'live-timer-text';
    timerBadge.append(timerSpan);
    badges.append(timerBadge);
    header.append(title, badges);
    process.append(header);

    const meter = document.createElement('progress');
    meter.className = 'progress-meter';
    meter.max = 100;
    meter.value = curPct;
    process.append(meter);

    const grid = element('ol', 'pipeline-steps');
    for (const s of PIPELINE_STEPS) {
      const stateClass = s.num < curStep ? ' done' : (s.num === curStep ? ' current' : '');
      const li = element('li', 'step-card' + stateClass);
      li.append(element('span', 'step-num', s.num < curStep ? '✓' : String(s.num)));
      const meta = element('div', 'step-meta');
      meta.append(
        element('strong', '', s.title),
        element('small', '', s.num === curStep ? (job.stage || s.desc) : s.desc)
      );
      li.append(meta);
      grid.append(li);
    }
    process.append(grid);

    const cpuHint = element(
      'p',
      'cpu-hint',
      'Mô hình AI cục bộ đang suy luận trực tiếp trên CPU máy bạn (mỗi lượt viết nháp & rà soát chéo thường mất 20–90 giây tùy cấu hình máy). Tiến trình vẫn đang chạy bình thường.'
    );
    cpuHint.id = 'live-cpu-hint';
    cpuHint.hidden = true;
    process.append(cpuHint);

    if (job.events && job.events.length) {
      const logBox = element('div', 'event-log-box');
      const logHead = element('div', 'event-log-head');
      logHead.append(
        element('span', '', 'Nhật ký hoạt động trực tiếp'),
        element('span', '', job.events.length + ' mốc sự kiện')
      );
      const listEl = buildEventList(job.events);
      logBox.append(logHead, listEl);
      process.append(logBox);
      requestAnimationFrame(() => { listEl.scrollTop = listEl.scrollHeight; });
    }

    bot.append(
      process,
      element('p', '', 'Bạn có thể mở “Tạo báo cáo mới” để chuẩn bị file khác — phiên xử lý hiện tại vẫn tiếp tục chạy nền cho đến khi xuất xong PDF.')
    );
    updateLiveTimers();
  } else if (job.status === 'failed') {
    bot.append(element('p', 'failure', job.error || 'Chưa tạo được báo cáo.'));
    if (job.events && job.events.length) {
      const details = element('details', 'audit-log');
      details.open = true;
      details.append(element('summary', '', 'Xem nhật ký trước khi dừng (' + job.events.length + ' mốc)'), buildEventList(job.events));
      bot.append(details);
    }
  } else {
    const s = job.summary || { findings: 0, with_guidance: 0, scope_blocked: 0 };
    if (job.status === 'partial') {
      bot.append(
        element(
          'p',
          'result-warning',
          'Đã xuất báo cáo PDF, nhưng có một phần diễn giải AI chưa hoàn tất hoặc bị bộ kiểm tra từ chối. Toàn bộ dữ kiện gốc, bằng chứng HTTP và hướng dẫn OWASP vẫn được giữ đầy đủ trong PDF.'
        )
      );
    }

    const download = element('div', 'download-card');
    const head = element('div', 'report-head');
    const headLeft = element('div', 'report-head-left');
    const badge = element('div', 'pdf-icon');
    badge.append(icon('file'));
    const label = element('div');
    const subMeta = ['Báo cáo Pentest A4 chuẩn OWASP', 'Đã rà soát ẩn dữ liệu nhạy cảm'];
    label.append(element('strong', '', 'Báo cáo Kiểm thử Xâm nhập đã sẵn sàng'), element('p', '', subMeta.join(' · ')));
    headLeft.append(badge, label);
    head.append(headLeft);
    const maskedTotal = (s.privacy_audit?.ips_masked || 0) + (s.privacy_audit?.secrets_masked || 0) + (s.privacy_audit?.paths_masked || 0);
    head.append(element('span', 'sha-tag', maskedTotal > 0 ? ('Đã ẩn ' + maskedTotal + ' mục IP/nhạy cảm') : 'Không phát hiện IP công khai rò rỉ'));
    download.append(head);

    const thirdMetric = [String(s.dropped_observations || 0), 'Cảnh báo nhiễu đã lọc'];
    const metrics = element('div', 'metrics');
    for (const [val, txt] of [
      [String(s.confirmed_findings ?? s.findings), 'Lỗ hổng xác nhận'],
      [String(s.with_guidance), 'Khuyến nghị khắc phục'],
      thirdMetric,
      [formatDurationHuman(s.duration_sec), 'Thời gian xử lý']
    ]) {
      const item = element('div', 'metric');
      item.append(element('strong', '', val), element('span', '', txt));
      metrics.append(item);
    }
    download.append(metrics);

    if (Array.isArray(s.findings_preview) && s.findings_preview.length) {
      const pv = element('div', 'preview-wrap');
      pv.append(element('div', 'preview-title', 'Tóm tắt nhanh các bản ghi trong báo cáo'));
      for (const r of s.findings_preview) {
        const rowEl = element('div', 'preview-row');
        const main = element('div', 'preview-main');
        const sevKey = String(r.severity || 'unknown').toLowerCase();
        main.append(
          element('span', 'sev-badge sev-' + sevKey, SEVERITY_VI[sevKey] || r.severity),
          element('strong', '', r.id + ' — ' + r.title)
        );
        const tags = element('div', 'preview-tags');
        if (r.cwe && r.cwe !== 'unknown') tags.append(element('span', 'tag-mini', r.cwe));
        tags.append(element('span', 'tag-mini', r.guidance_count ? r.guidance_count + ' mục khắc phục' : 'Đã ghi nhận'));
        rowEl.append(main, tags);
        pv.append(rowEl);
      }
      download.append(pv);
    }

    const actions = element('div', 'download-actions');
    const qTok = BOOT_TOKEN ? ('token=' + encodeURIComponent(BOOT_TOKEN)) : '';
    const viewPdf = element('a', 'download');
    viewPdf.href = '/api/jobs/' + encodeURIComponent(job.id) + '/pdf?inline=1' + (qTok ? '&' + qTok : '');
    viewPdf.target = '_blank';
    viewPdf.rel = 'noopener';
    viewPdf.append(icon('eye'), document.createTextNode('Mở xem PDF trực tiếp'));

    const dlPdf = element('a', 'download secondary');
    dlPdf.href = '/api/jobs/' + encodeURIComponent(job.id) + '/pdf' + (qTok ? '?' + qTok : '');
    dlPdf.download = 'bao-cao-pentest-' + job.id.slice(0, 8) + '.pdf';
    dlPdf.append(icon('down'), document.createTextNode('Tải file PDF về máy'));

    const dlMd = element('a', 'json-link', 'Tải bản Markdown (.md)');
    dlMd.href = '/api/jobs/' + encodeURIComponent(job.id) + '/md' + (qTok ? '?' + qTok : '');
    dlMd.download = 'bao-cao-pentest-' + job.id.slice(0, 8) + '.md';

    const dlJson = element('a', 'json-link', 'Tải dữ liệu JSON');
    dlJson.href = '/api/jobs/' + encodeURIComponent(job.id) + '/json' + (qTok ? '?' + qTok : '');
    dlJson.download = 'bao-cao-pentest-' + job.id.slice(0, 8) + '.json';

    actions.append(viewPdf, dlPdf, dlMd, dlJson);
    download.append(actions);

    if (job.events && job.events.length) {
      const details = element('details', 'audit-log');
      details.append(
        element('summary', '', 'Xem nhật ký chi tiết quá trình xử lý (' + job.events.length + ' mốc thời gian)'),
        buildEventList(job.events)
      );
      download.append(details);
    }

    bot.append(download);
  }

  const again = element('button', 'again', '+ Tạo báo cáo mới');
  again.type = 'button';
  again.addEventListener('click', reset);
  bot.append(again);
}

function render() {
  renderHistory();
  const job = jobs.find(j => j.id === selected);
  $('welcome').hidden = !!job;
  $('compose-zone').hidden = !!job;
  $('messages').hidden = !job;
  if (job) {
    const signature = JSON.stringify(job);
    if (signature !== lastSignature) {
      lastSignature = signature;
      renderJob(job);
    }
  }
}

async function refresh() {
  try {
    if (config && !config.demo && !config.configured) {
      applyConfig(await api('/api/config'));
    }
    jobs = await api('/api/jobs');
    render();
  } catch (e) {
    $('config-notice').hidden = false;
    $('config-notice').textContent = e.message;
  } finally {
    const active = jobs.some(j => ['queued', 'running'].includes(j.status));
    clearTimeout(timer);
    timer = setTimeout(refresh, active ? 1000 : 4500);
  }
}

$('new-chat').addEventListener('click', reset);
$('attach').addEventListener('click', () => $('file').click());
$('file').addEventListener('change', e => chooseFiles(e.target.files));
$('remove-file').addEventListener('click', () => {
  files = [];
  $('file').value = '';
  renderFileChips();
});

$('menu').addEventListener('click', () => {
  document.body.classList.add('sidebar-open');
  $('scrim').hidden = false;
});
$('scrim').addEventListener('click', closeSidebar);
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeSidebar();
});

const form = $('upload-form');
let dragDepth = 0;
form.addEventListener('dragenter', e => {
  e.preventDefault();
  dragDepth++;
  form.classList.add('dragging');
});
form.addEventListener('dragover', e => e.preventDefault());
form.addEventListener('dragleave', () => {
  if (--dragDepth <= 0) {
    dragDepth = 0;
    form.classList.remove('dragging');
  }
});
form.addEventListener('drop', e => {
  e.preventDefault();
  dragDepth = 0;
  form.classList.remove('dragging');
  chooseFiles(e.dataTransfer.files);
});
window.addEventListener('dragover', e => e.preventDefault());
window.addEventListener('drop', e => e.preventDefault());

$('note').addEventListener('keydown', e => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
    e.preventDefault();
    form.requestSubmit();
  }
});

form.addEventListener('submit', async e => {
  e.preventDefault();
  if (uploading) return;
  error('');
  if (!files.length) {
    error('Hãy đính kèm ít nhất một file kết quả kiểm thử trước khi bấm Tạo báo cáo PDF.');
    return;
  }
  if (!config) {
    error('Chưa kết nối được máy chủ cục bộ. Hãy tải lại trang.');
    return;
  }
  if (!config.configured) {
    applyConfig(await api('/api/config'));
  }
  if (!config.configured) {
    error(config.issues.join(' ') || 'Chưa sẵn sàng kết nối model AI. Kiểm tra ứng dụng Ollama và file .env.');
    return;
  }
  uploading = true;
  $('send').disabled = true;
  try {
    const metaJson = JSON.stringify(
      Object.fromEntries(
        ['application', 'client', 'prepared_by', 'assessment_period', 'classification', 'xss_decision', 'xss_poc', 'mask_public_ips', 'target_alias']
          .map(k => [k, ($('meta-' + k)?.value || '').trim()])
      )
    );
    let job;
    if (files.length === 1) {
      const query = new URLSearchParams({
        filename: files[0].name,
        format: $('format').value,
        note: $('note').value.trim(),
        metadata: metaJson
      });
      job = await api('/api/jobs?' + query, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream', 'X-App-Token': config.token },
        body: files[0]
      });
    } else {
      const fmtVal = $('format').value;
      const bundleFiles = await Promise.all(
        files.map(async f => ({ filename: f.name, format: fmtVal, content_b64: await fileToBase64(f) }))
      );
      const query = new URLSearchParams({ bundle: '1', note: $('note').value.trim(), metadata: metaJson });
      job = await api('/api/jobs?' + query, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json; charset=utf-8', 'X-App-Token': config.token },
        body: JSON.stringify({ bundle_version: 1, files: bundleFiles })
      });
    }
    files = [];
    renderFileChips();
    jobs.unshift(job);
    select(job.id);
    toast('Đã bắt đầu xử lý! Theo dõi trực tiếp từng bước ngay bên dưới.');
  } catch (err) {
    error(err.message);
  } finally {
    uploading = false;
    $('send').disabled = false;
  }
});

tickTimer = setInterval(updateLiveTimers, 1000);

(async () => {
  try {
    applyConfig(await api('/api/config'));
    selected = localStorage.getItem('auditnote-selected');
    await refresh();
  } catch (err) {
    error(err.message);
  }
})();
