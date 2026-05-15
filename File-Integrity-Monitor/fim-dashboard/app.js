/**
 * FIM Dashboard — app.js
 * All UI logic: state, API calls, table rendering, scan (SSE), baseline modal.
 */

const API_BASE = "https://fim-backend-67ex.onrender.com";
const API = API_BASE;
const DEMO_USER = 'admin';
const DEMO_PASS = 'admin123';
let quarantineActive = false;

// ─── State ────────────────────────────────────────────────────────────────────
let FILES          = [];   // Latest scan results from backend
let filteredPath   = 'all';
let filteredStatus = 'all';
let searchTerm     = '';
let selectedIdx    = null;
let baselineExists = false;

// Paths shown in the baseline confirmation modal (must match backend MONITORED_FILES)
const MONITORED_PATHS = [
  'C:\\Users\\info soft\\Downloads\\File-Integrity-Monitor\\File-Integrity-Monitor\\test.txt',
  'C:\\Windows\\System32\\drivers\\etc\\hosts',
  'C:\\Windows\\System32\\cmd.exe',
  'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
  'C:\\Windows\\explorer.exe',
  'C:\\Windows\\System32\\notepad.exe',
  'C:\\Windows\\System32\\taskmgr.exe',
  'C:\\Windows\\regedit.exe',
  'C:\\Windows\\System32\\services.exe',
  'C:\\Windows\\System32\\svchost.exe',
  'C:\\Windows\\System32\\winlogon.exe',
  'C:\\Windows\\System32\\drivers\\etc\\networks',
  'C:\\Windows\\System32\\drivers\\etc\\protocol',
  'C:\\Windows\\System32\\drivers\\etc\\services',
];


// ─── Login / Session ─────────────────────────────────────────────────────────
function login() {
  const user = document.getElementById('login-user').value.trim();
  const pass = document.getElementById('login-pass').value;
  const err = document.getElementById('login-error');

  if (user === DEMO_USER && pass === DEMO_PASS) {
    sessionStorage.setItem('fim-auth', 'true');
    document.body.classList.add('authenticated');
    document.getElementById('fim-root').classList.remove('locked');
    terminalLog('AUTH', 'Admin session established');
    checkBackend();
  } else {
    err.textContent = 'Invalid credentials. Use admin / admin123 for demo.';
  }
}

function logout() {
  sessionStorage.removeItem('fim-auth');
  document.body.classList.remove('authenticated');
  document.getElementById('fim-root').classList.add('locked');
  document.getElementById('login-pass').value = '';
}

function restoreSession() {
  if (sessionStorage.getItem('fim-auth') === 'true') {
    document.body.classList.add('authenticated');
    document.getElementById('fim-root').classList.remove('locked');
  }
}

function terminalLog(tag, msg) {
  const box = document.getElementById('terminal-lines');
  if (!box) return;
  const line = document.createElement('div');
  line.textContent = `[${tag}] ${msg}`;
  box.appendChild(line);
  box.scrollTop = box.scrollHeight;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function hashShort(h) {
  if (!h || h === '—') return '<span style="color:var(--fim-muted)">—</span>';
  if (h === 'MISSING')          return '<span style="color:var(--fim-amber)">MISSING</span>';
  if (h === 'PERMISSION_DENIED')return '<span style="color:var(--fim-purple)">PERM DENIED</span>';
  if (h === 'ERROR')            return '<span style="color:var(--fim-red)">ERROR</span>';
  return h.slice(0, 8) + '…' + h.slice(-8);
}

function getBadge(s) {
  const labels = { ok: 'Intact', modified: 'Modified', missing: 'Missing', new: 'Unverified', error: 'Error' };
  return `<span class="badge ${s}">${labels[s] || s}</span>`;
}

function getRiskBadge(r) {
  return `<span class="badge ${r}">${r}</span>`;
}

function nowStr() {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

function showToast(msg) {
  const t = document.getElementById('err-toast');
  t.textContent = '⚠ ' + msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 5000);
}

// ─── Backend Status Check ─────────────────────────────────────────────────────
async function checkBackend() {
  const dot = document.getElementById('api-status-dot');
  try {
    const res = await fetch(`${API}/api/status`);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const data = await res.json();

    dot.textContent = '✓ connected';
    dot.style.color = 'var(--green)';

    baselineExists = data.baseline_exists;
    document.getElementById('st-total').textContent = data.file_count;
    document.getElementById('st-ok').textContent     = '—';
    document.getElementById('st-alerts').textContent = '—';

    if (data.baseline_exists) {
      const ts = data.baseline_timestamp;
      document.getElementById('st-base').textContent        = ts ? ts.slice(11, 16) + ' UTC' : 'Set';
      document.getElementById('last-scan-label').textContent = 'Baseline: ' + (ts ? ts.slice(0, 10) : '');
      document.getElementById('no-baseline-banner').classList.remove('show');
    } else {
      document.getElementById('st-base').textContent = 'Not set';
      document.getElementById('no-baseline-banner').classList.add('show');
    }
  } catch (e) {
    dot.textContent = '✗ offline';
    dot.style.color = 'var(--fim-red)';
    showToast('Cannot reach backend at ' + API + ' — is monitor.py running?');
  }
}

// ─── Filter / Search / Sort ───────────────────────────────────────────────────
function getVisible() {
  return FILES.filter(f => {
    if (filteredStatus !== 'all' && f.status !== filteredStatus)
      return false;

    if (filteredPath !== 'all' && !f.path.toLowerCase().startsWith(filteredPath.toLowerCase()))
      return false;

    if (
      searchTerm &&
      !f.path.toLowerCase().includes(searchTerm.toLowerCase())
    )
      return false;

    return true;
  });
}
function filterPath(p, el) {
  filteredPath = p;
  document.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
  el.classList.add('active');
  renderTable();
}

function filterStatus(s, el) {
  filteredStatus = s;
  renderTable();
}

function searchFiles(v) {
  searchTerm = v;
  renderTable();
}

function sortFiles(by) {
  const riskOrder   = { critical: 0, high: 1, medium: 2, low: 3 };
  const statusOrder = { modified: 0, missing: 1, error: 2, new: 3, ok: 4 };
  FILES.sort((a, b) => {
    if (by === 'path') return a.path.localeCompare(b.path);
    if (by === 'risk') return (riskOrder[a.risk] ?? 4) - (riskOrder[b.risk] ?? 4);
    return (statusOrder[a.status] ?? 5) - (statusOrder[b.status] ?? 5);
  });
  renderTable();
}

// ─── Table Rendering ──────────────────────────────────────────────────────────
function renderTable() {
  const tbody = document.getElementById('file-tbody');
  const rows  = getVisible();

  if (rows.length === 0) {
    tbody.innerHTML = FILES.length === 0
      ? '<tr class="empty-row"><td colspan="6">Run a scan to load real file data from the backend.</td></tr>'
      : '<tr class="empty-row"><td colspan="6">No files match the current filter.</td></tr>';
    return;
  }

  tbody.innerHTML = rows.map(f => {
    const idx        = FILES.indexOf(f);
    const isAlert    = f.status !== 'ok';
    const isSelected = selectedIdx === idx;
    return `<tr onclick="selectRow(${idx})" class="${isSelected ? 'selected' : ''} ${isAlert ? 'alert-row' : ''}">
      <td class="path-cell">${f.path}</td>
      <td>${getBadge(f.status)}</td>
      <td class="hash-cell">${hashShort(f.base)}</td>
      <td class="hash-cell ${f.status === 'modified' ? 'hash-mismatch' : ''}">${hashShort(f.curr)}</td>
      <td class="hash-cell">${f.checked || '—'}</td>
      <td>${getRiskBadge(f.risk)}</td>
    </tr>`;
  }).join('');

  updateStats();
  updateSidebarCounts();
}

function updateStats() {
  const ok = FILES.filter(f => f.status === 'ok').length;
  const alerts = FILES.filter(f => f.status !== 'ok').length;

  document.getElementById('st-total').textContent = FILES.length;
  document.getElementById('st-ok').textContent = ok;
  document.getElementById('st-alerts').textContent = alerts;
  document.getElementById('alert-count').textContent = ` ${alerts} files `;

  const banner = document.getElementById('alert-banner');
  alerts > 0 ? banner.classList.add('show') : banner.classList.remove('show');

  // Quarantine only when a critical file is MODIFIED
  const criticalModified = FILES.filter(
    f => f.status === 'modified' && f.risk === 'critical'
  ).length;

  if (criticalModified > 0) {
    activateQuarantine(criticalModified);
  }
}
function activateQuarantine(count) {
  quarantineActive = true;
  document.body.classList.add('quarantine-active');
  document.getElementById('quarantine-banner').classList.add('show');
  document.getElementById('st-quarantine').textContent = 'ACTIVE';
  document.getElementById('st-quarantine').className = 'stat-val red';
  terminalLog('LOCKDOWN', `${count} critical integrity violation(s) triggered quarantine mode`);
}

function releaseQuarantine() {
  quarantineActive = false;
  document.body.classList.remove('quarantine-active');
  document.getElementById('quarantine-banner').classList.remove('show');
  document.getElementById('st-quarantine').textContent = 'Standby';
  document.getElementById('st-quarantine').className = 'stat-val amber';
  terminalLog('RELEASE', 'Quarantine mode manually released by admin');
}

function updateSidebarCounts() {
  const lower = p => p.toLowerCase();
  const map = {
    'cnt-all':       () => FILES.length,
    'cnt-hosts':     () => FILES.filter(f => lower(f.path).includes('drivers\\etc\\hosts')).length,
    'cnt-config':    () => FILES.filter(f => lower(f.path).includes('system32\\config')).length,
    'cnt-system32':  () => FILES.filter(f => lower(f.path).includes('system32')).length,
    'cnt-syswow64':  () => FILES.filter(f => lower(f.path).includes('syswow64')).length,
    'cnt-explorer':  () => FILES.filter(f => lower(f.path).includes('explorer.exe')).length,
    'cnt-cmd':       () => FILES.filter(f => lower(f.path).includes('cmd.exe')).length,
    'cnt-powershell':() => FILES.filter(f => lower(f.path).includes('powershell.exe')).length,
  };
  for (const [id, fn] of Object.entries(map)) {
    const el = document.getElementById(id);
    if (el) el.textContent = fn();
  }
}

// ─── Row Detail Panel ─────────────────────────────────────────────────────────
function selectRow(idx) {
  selectedIdx = idx;
  const f = FILES[idx];

  document.getElementById('detail-panel').classList.add('open');
  document.getElementById('detail-title').innerHTML =
    `${getBadge(f.status)}&nbsp;<span style="color:var(--blue)">${f.path}</span>
     <button class="close-detail" onclick="closeDetail()">✕ close</button>`;

  let hashSection;
  if (f.status === 'modified') {
    hashSection = `<div class="diff-hash">
      <div class="hash-line"><span class="hash-tag base">Baseline</span><span style="color:var(--green)">${f.base}</span></div>
      <div class="hash-line"><span class="hash-tag curr">Current</span><span style="color:var(--fim-red)">${f.curr}</span></div>
    </div>`;
  } else if (f.status === 'missing') {
    hashSection = `<div class="detail-val" style="color:var(--fim-amber)">File not found on disk — was present in baseline</div>`;
  } else if (f.status === 'new') {
    hashSection = `<div class="detail-val" style="color:var(--blue)">No baseline set — current hash: ${f.curr}</div>`;
  } else if (f.status === 'error') {
    hashSection = `<div class="detail-val" style="color:var(--fim-purple)">Could not read file (permission denied or I/O error)</div>`;
  } else {
    hashSection = `<div class="detail-val" style="color:var(--green)">${f.base}</div>`;
  }

  document.getElementById('detail-grid').innerHTML = `
    <div class="detail-row">
      <div class="detail-lbl">SHA-256 Comparison</div>
      ${hashSection}
    </div>
    <div class="detail-row">
      <div class="detail-lbl">File Metadata</div>
      <div class="detail-val">Size: ${f.size  || 'N/A'}</div>
      <div class="detail-val">Permissions: ${f.perms || 'N/A'}</div>
      <div class="detail-val">Owner: ${f.owner || 'N/A'}</div>
      <div class="detail-val">Risk Level: ${(f.risk || '').toUpperCase()}</div>
      <div class="detail-val">Last Checked: ${f.checked || '—'}</div>
    </div>`;

  renderTable();
}

function closeDetail() {
  document.getElementById('detail-panel').classList.remove('open');
  selectedIdx = null;
  renderTable();
}

// ─── Live Scan (Server-Sent Events) ──────────────────────────────────────────
function startScan() {
  const btn        = document.getElementById('scan-btn');
  const baselineBtn = document.getElementById('baseline-btn');
  const logEl      = document.getElementById('scan-log');

  btn.classList.add('scanning');
  btn.textContent  = '⟳ Scanning...';
  btn.disabled     = true;
  baselineBtn.disabled = true;

  document.getElementById('scan-overlay').classList.add('show');
  logEl.innerHTML  = '';
  document.getElementById('scan-bar').style.width    = '0%';
  document.getElementById('scan-result').textContent = '';
  document.getElementById('scan-result').className   = 'scan-result';
  document.getElementById('scan-close').style.display= 'none';
  document.getElementById('scan-spinner').style.display = '';
  document.getElementById('scan-status').textContent = 'Connecting to backend…';

  function addLog(cls, msg) {
    const line = document.createElement('div');
    line.className = 'scan-log-line';
    line.innerHTML = `<span class="${cls}">[${cls.toUpperCase()}]</span><span>${msg}</span>`;
    logEl.appendChild(line);
    logEl.scrollTop = logEl.scrollHeight;
  }

  let evtSource;
  try {
    evtSource = new EventSource(`${API}/api/scan/stream`);
  } catch (e) {
    addLog('err', 'Failed to open SSE stream: ' + e.message);
    finishScan(btn, baselineBtn);
    return;
  }

  evtSource.onmessage = function (event) {
    let msg;
    try { msg = JSON.parse(event.data); } catch { return; }

    if (msg.type === 'start') {
      addLog('inf', `Starting scan — ${msg.total} files queued`);
      terminalLog('SCAN', `${msg.total} files queued for verification`);
      document.getElementById('scan-status').textContent = 'Scanning…';
    }
    else if (msg.type === 'hashing') {
      addLog('inf', `Hashing ${msg.path} …`);
      const pct = Math.round((msg.index + 1) / msg.total * 80);
      document.getElementById('scan-bar').style.width    = pct + '%';
      document.getElementById('scan-status').textContent = `Scanning… ${msg.index + 1}/${msg.total}`;
    }
    else if (msg.type === 'result') {
      const f     = msg.file;
      const cls   = f.status === 'ok' ? 'ok' : 'err';
      const icon  = f.status === 'ok' ? '✓' : '⚠';
      const label = { ok: 'MATCH', modified: 'MISMATCH', missing: 'MISSING', new: 'NO BASELINE', error: 'ERROR' }[f.status] || f.status.toUpperCase();
      addLog(cls, `${f.path} → ${label} ${icon}`);
      if (f.status !== 'ok') terminalLog('ALERT', `${f.risk.toUpperCase()} ${label}: ${f.path}`);
    }
    else if (msg.type === 'done') {
      evtSource.close();
      FILES = msg.files;

      document.getElementById('last-scan-label').textContent = 'Last scan: ' + nowStr().slice(11, 16) + ' UTC';
      document.getElementById('scan-bar').style.width         = '100%';
      document.getElementById('scan-status').textContent      = 'Scan complete.';

      const resultEl = document.getElementById('scan-result');
      if (msg.alerts > 0) {
        resultEl.innerHTML = `<span class="warn">⚠ ${msg.alerts} violation${msg.alerts > 1 ? 's' : ''} found</span>`;
      } else {
        resultEl.innerHTML = `<span class="safe">✓ All ${msg.ok} files intact</span>`;
      }

      renderTable();
      terminalLog('DONE', `${msg.alerts} alert(s), ${msg.ok} file(s) intact`);
      finishScan(btn, baselineBtn);
    }
  };

  evtSource.onerror = function () {
    evtSource.close();
    addLog('err', 'Stream error — check that monitor.py is running on port 5000');
    finishScan(btn, baselineBtn);
  };
}

function finishScan(btn, baselineBtn) {
  document.getElementById('scan-spinner').style.display = 'none';
  document.getElementById('scan-close').style.display   = 'inline-block';
  btn.classList.remove('scanning');
  btn.textContent      = '▶ Run Scan';
  btn.disabled         = false;
  baselineBtn.disabled = false;
}

function closeScan() {
  document.getElementById('scan-overlay').classList.remove('show');
}

// ─── Baseline Generation ──────────────────────────────────────────────────────
function openBaselineModal() {
  const container = document.getElementById('modal-paths');
  container.innerHTML = MONITORED_PATHS.map(p =>
    `<div class="modal-path-row">${p}</div>`
  ).join('');
  document.getElementById('baseline-modal').classList.add('show');
}

function closeBaselineModal() {
  document.getElementById('baseline-modal').classList.remove('show');
}

async function confirmBaseline() {
  closeBaselineModal();

  const btn = document.getElementById('baseline-btn');
  btn.disabled = true;
  btn.textContent = '⟳ Hashing…';

  try {
    const res = await fetch(`${API}/api/baseline`, {
      method: 'POST'
    });

    if (!res.ok) {
      throw new Error('HTTP ' + res.status);
    }

    const data = await res.json();

    baselineExists = true;

    const ts = data.timestamp;

    document.getElementById('st-base').textContent =
      ts.slice(11, 16) + ' UTC';

    document.getElementById('last-scan-label').textContent =
      'Baseline: ' + ts.slice(0, 10);

    document.getElementById('no-baseline-banner')
      .classList.remove('show');

    // FIXED: properly map backend hash -> frontend table
    FILES = data.files.map(f => ({
      path: f.path,
      status: 'ok',
      risk: f.risk,
      base: f.hash,
      curr: f.hash,
      size: f.size,
      perms: f.perms,
      owner: f.owner,
      checked: f.timestamp
    }));

    renderTable();
    releaseQuarantine();
    terminalLog('BASELINE', `New baseline generated with ${FILES.length} monitored files`);

  } catch (e) {
    showToast('Baseline generation failed: ' + e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '⊕ Generate Baseline';
  }
}
async function simulateAttack() {
  const btn = document.getElementById('attack-btn');

  btn.disabled = true;
  btn.textContent = '⚠ Simulating…';

  try {
    const res = await fetch(`${API}/api/simulate-attack`, {
      method: 'POST'
    });

    if (!res.ok) {
      throw new Error('HTTP ' + res.status);
    }

    const data = await res.json();

    showToast('Simulated attack completed on: ' + data.path);
    terminalLog('SIMULATION', 'Critical file modified: ' + data.path);

    setTimeout(() => {
      startScan();
    }, 700);

  } catch (e) {
    showToast('Attack simulation failed: ' + e.message);
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.textContent = '⚠ Simulate Attack';
    }, 1200);
  }
}

async function generateIncidentReport() {
  try {
    terminalLog('REPORT', 'Generating incident report...');

    const response = await fetch(`${API}/incident-report`);

    const data = await response.json();

    if (!data.ok) {
      throw new Error(data.error || 'Report generation failed');
    }

    terminalLog('REPORT', 'Incident report generated successfully');

    alert(
      `Incident Report Generated\n\n` +
      `Incidents Found: ${data.incidents.length}\n` +
      `Saved To:\n${data.report_path}`
    );

  } catch (err) {
    console.error(err);
    alert(`⚠ Incident report failed: ${err.message}`);
  }
}
// ─── Footer Clock ─────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById('footer-time').textContent = nowStr() + ' UTC';
}

// ─── Init ─────────────────────────────────────────────────────────────────────
restoreSession();
checkBackend();
updateClock();
setInterval(updateClock, 1000);