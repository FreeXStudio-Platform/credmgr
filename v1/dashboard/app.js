'use strict';

// ─── PWA Service Worker ───────────────────────────────────────────────────
// Skip SW entirely when running inside the macOS native shell (?native=1) —
// the native shell already manages caching and we never want stale UI.
var IS_NATIVE_SHELL = /[?&]native=1\b/.test(window.location.search) ||
                      /credmgr-native/i.test(navigator.userAgent || '');
if (IS_NATIVE_SHELL && 'serviceWorker' in navigator) {
  // Aggressively unregister any previously installed SW + purge caches
  navigator.serviceWorker.getRegistrations().then(function(regs) {
    regs.forEach(function(r) { r.unregister(); });
  }).catch(function() {});
  if (window.caches && caches.keys) {
    caches.keys().then(function(keys) { keys.forEach(function(k) { caches.delete(k); }); }).catch(function() {});
  }
} else if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').then(function(reg) {
    // Force check for a newer SW on every page load
    if (reg && reg.update) reg.update();
    // If a new SW is waiting, tell it to activate immediately
    if (reg && reg.waiting) reg.waiting.postMessage('SKIP_WAITING');
    // When a new SW takes control, reload once so the user always sees fresh code
    var refreshing = false;
    navigator.serviceWorker.addEventListener('controllerchange', function() {
      if (refreshing) return;
      refreshing = true;
      window.location.reload();
    });
  }).catch(function() {});
}

// ─── State ─────────────────────────────────────────────────────────────────
var allCredentials   = [];
var projects         = [];
var currentSens      = '';   // active sensitivity pill value
var currentSmartView = '';   // active smart-view chip: '' | wallets | expiring | never-accessed
var searchTimeout    = null; // shared debounce timer (palette input)
var currentAddType   = 'simple';
var addFields        = [];   // { label, value }
var mergeMode        = false;
var mergeSelected    = {};   // { name: true }
var activeTotpTimer  = null; // live-code interval for whichever detail panel is open
var mergeFields      = [];   // { label, value } for right panel

// ─── Type Presets ─────────────────────────────────────────────────────────
var PRESETS = {
  vps:      [{ label: 'host' }, { label: 'username' }, { label: 'password' }],
  api:      [{ label: 'apiKey' }, { label: 'apiSecret' }],
  database: [{ label: 'host' }, { label: 'port' }, { label: 'username' }, { label: 'password' }, { label: 'database' }],
  wallet:   [{ label: 'address' }, { label: 'privateKey' }, { label: 'seedPhrase' }],
};
// Add-form preset key → server schema key (drives the extra-column chips)
var PRESET_SCHEMA_KEY = { vps: 'server', api: 'api-key', database: 'database', wallet: 'wallet' };
// Canonical column sets per item type, loaded from GET /api/schemas at init.
var typeSchemas = {};

// ─── DOM refs ──────────────────────────────────────────────────────────────
var $list            = document.getElementById('cred-list');
var $filterProject   = document.getElementById('filter-project');
var $filterCategory  = document.getElementById('filter-category');
var $statsBar        = document.getElementById('stats-bar');
var $healthBadge     = document.getElementById('health-badge');
var $healthText      = document.getElementById('health-text');
var $footerStats     = document.getElementById('footer-stats');
var $detailPanel     = document.getElementById('detail-panel');
var $detailBackdrop  = document.getElementById('detail-backdrop');
var $panelTitle      = document.getElementById('panel-title');
var $detailSensDot   = document.getElementById('detail-sens-dot');
var $panelBody       = document.getElementById('panel-body');
var $addModal        = document.getElementById('add-modal');
var $changelogModal  = document.getElementById('changelog-modal');
var $changelogBody   = document.getElementById('changelog-body');
var $deleteModal     = document.getElementById('delete-modal');
var $deleteMsg       = document.getElementById('delete-msg');
var $simpleSection   = document.getElementById('simple-value-section');
var $fieldsSection   = document.getElementById('fields-section');
var $fieldsList      = document.getElementById('fields-list');

// ─── Safe DOM ──────────────────────────────────────────────────────────────
function el(tag, attrs, children) {
  var node = document.createElement(tag);
  if (attrs) {
    for (var k in attrs) {
      if (!attrs.hasOwnProperty(k)) continue;
      var v = attrs[k];
      if (k === 'className')   node.className = v;
      else if (k === 'text')   node.textContent = v;
      else if (k === 'html')   {} // never used — no innerHTML
      else if (k === 'onclick') node.addEventListener('click', v);
      else if (k === 'style')  node.style.cssText = v;
      else if (k === 'type')   node.type = v;
      else if (k === 'rows')   node.rows = v;
      else if (k === 'required') node.required = v;
      else node.setAttribute(k, v);
    }
  }
  if (children) {
    var list = Array.isArray(children) ? children : [children];
    for (var i = 0; i < list.length; i++) {
      var c = list[i];
      if (c == null) continue;
      if (typeof c === 'string') node.appendChild(document.createTextNode(c));
      else node.appendChild(c);
    }
  }
  return node;
}

// ─── SVG helper ────────────────────────────────────────────────────────────
function svgIcon(path, size) {
  var ns = 'http://www.w3.org/2000/svg';
  var svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width',  size || '14');
  svg.setAttribute('height', size || '14');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '2');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.innerHTML = path; // safe — no user content
  return svg;
}

// ─── Toast ─────────────────────────────────────────────────────────────────
function toast(msg, type) {
  var t = el('div', { className: 'toast toast-' + (type || 'success'), text: msg });
  document.body.appendChild(t);
  setTimeout(function() { t.remove(); }, 3000);
}

// ─── Panel helpers ─────────────────────────────────────────────────────────
function openDetailPanel(sensClass) {
  $detailSensDot.className = 'detail-sens-dot';
  $detailSensDot.style.background = sensColor(sensClass);
  $detailSensDot.style.boxShadow  = sensGlow(sensClass);
  $detailPanel.classList.add('open');
  $detailBackdrop.classList.add('open');
}

function closeDetailPanel() {
  $detailPanel.classList.remove('open');
  $detailBackdrop.classList.remove('open');
  clearTotpTimer();
}

function clearTotpTimer() {
  if (activeTotpTimer) { clearInterval(activeTotpTimer); activeTotpTimer = null; }
}

function openModal(modal) {
  modal.classList.add('open');
}

function closeModal(modal) {
  modal.classList.remove('open');
}

// ─── Native-safe confirm / prompt ──────────────────────────────────────────
// window.confirm() / window.prompt() are silent no-ops inside the macOS
// native shell (WKWebView with no JS-panel delegate): confirm returns false,
// prompt returns null — so every flow that relied on them (archive delete,
// keep-both restore, project reassign, PIN setup) simply "did nothing".
// These promise-based modals work identically in every shell.
var $confirmModal = document.getElementById('confirm-modal');
var $promptModal  = document.getElementById('prompt-modal');

function appConfirm(message, opts) {
  var o = opts || {};
  return new Promise(function(resolve) {
    document.getElementById('confirm-title').textContent = o.title || 'Confirm';
    document.getElementById('confirm-msg').textContent = message;
    var okBtn = document.getElementById('confirm-ok');
    okBtn.textContent = o.okLabel || 'OK';
    okBtn.classList.toggle('btn-danger', !!o.danger);
    okBtn.classList.toggle('btn-primary', !o.danger);

    function cleanup(result) {
      closeModal($confirmModal);
      okBtn.removeEventListener('click', onOk);
      document.getElementById('confirm-cancel').removeEventListener('click', onCancel);
      $confirmModal.removeEventListener('click', onBackdrop);
      resolve(result);
    }
    function onOk() { cleanup(true); }
    function onCancel() { cleanup(false); }
    function onBackdrop(e) { if (e.target === $confirmModal) cleanup(false); }

    okBtn.addEventListener('click', onOk);
    document.getElementById('confirm-cancel').addEventListener('click', onCancel);
    $confirmModal.addEventListener('click', onBackdrop);
    openModal($confirmModal);
    setTimeout(function() { okBtn.focus(); }, 0);
  });
}

function appPrompt(message, opts) {
  var o = opts || {};
  return new Promise(function(resolve) {
    document.getElementById('prompt-title').textContent = o.title || 'Input';
    document.getElementById('prompt-msg').textContent = message;
    var input = document.getElementById('prompt-input');
    input.type = o.type || 'text';
    input.value = o.value || '';
    input.placeholder = o.placeholder || '';
    var okBtn = document.getElementById('prompt-ok');

    function cleanup(result) {
      closeModal($promptModal);
      okBtn.removeEventListener('click', onOk);
      document.getElementById('prompt-cancel').removeEventListener('click', onCancel);
      input.removeEventListener('keydown', onKey);
      $promptModal.removeEventListener('click', onBackdrop);
      resolve(result);
    }
    function onOk() { cleanup(input.value); }
    function onCancel() { cleanup(null); }
    function onKey(e) {
      if (e.key === 'Enter')  { e.preventDefault(); cleanup(input.value); }
      if (e.key === 'Escape') { e.preventDefault(); cleanup(null); }
    }
    function onBackdrop(e) { if (e.target === $promptModal) cleanup(null); }

    okBtn.addEventListener('click', onOk);
    document.getElementById('prompt-cancel').addEventListener('click', onCancel);
    input.addEventListener('keydown', onKey);
    $promptModal.addEventListener('click', onBackdrop);
    openModal($promptModal);
    setTimeout(function() { input.focus(); }, 0);
  });
}

// ─── Sensitivity Rules (enforcement for agents) ──────────────────────────
var SENS_RULES = {
  critical: 'CRITICAL: Never log, never display, never include in prompts. Agent must pipe directly — no intermediate storage.',
  high:     'HIGH: Reveal only when actively needed. Clear after use. Do not embed in code or config files.',
  medium:   'MEDIUM: Standard handling. Use credmgr CLI to read. Do not hardcode.',
  low:      'LOW: Non-sensitive. Safe to display and reference freely.',
};

// ─── Sensitivity helpers ───────────────────────────────────────────────────
// Values match --crit/--high/--med/--low in style.css exactly (both themes
// read those vars for everything else; these two functions need raw values
// because they're used in inline style="" for the detail-panel sens dot).
function sensColor(s) {
  return s === 'critical' ? '#DC2626' :
         s === 'high'     ? '#D97706' :
         s === 'medium'   ? '#3B82F6' : '#64748B';
}

function sensGlow(s) {
  return s === 'critical' ? '0 0 8px rgba(220,38,38,0.5)'  :
         s === 'high'     ? '0 0 8px rgba(217,119,6,0.5)' :
         s === 'medium'   ? '0 0 8px rgba(59,130,246,0.4)' : 'none';
}

// Sensitivity glyph: filled triangle (critical) → filled dot (high) → half-filled
// ring (medium) → open ring (low) — a shape ramp so severity reads even without color.
function sensIcon(s) {
  var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', '8');
  svg.setAttribute('height', '8');
  svg.setAttribute('class', 'sens-icon');
  var markup = {
    critical: '<path d="M12 2 1 21h22L12 2Z" fill="currentColor"/>',
    high:     '<circle cx="12" cy="12" r="10" fill="currentColor"/>',
    medium:   '<path d="M12 2a10 10 0 0 0 0 20Z" fill="currentColor"/><circle cx="12" cy="12" r="9.2" fill="none" stroke="currentColor" stroke-width="1.6"/>',
    low:      '<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/>',
  };
  svg.innerHTML = markup[s] || markup.low; // safe — fixed, non-user-controlled markup
  return svg;
}

function projClass(proj) {
  // Every project renders through the deterministic hash colour below; only
  // 'global' has a fixed class. No user's project names live in this source.
  return proj === 'global' ? 'proj-global' : 'proj-generic';
}

// ─── Deterministic color system ────────────────────────────────────────────
// Scales beyond a hand-picked palette: known projects/categories get a fixed,
// intentional color; anything new gets a stable hash→hue so it's still
// legible and on-brand without ever needing a code change.
function hashHue(str) {
  var h = 0;
  str = String(str || 'unknown');
  for (var i = 0; i < str.length; i++) { h = (h * 31 + str.charCodeAt(i)) >>> 0; }
  return h % 360;
}

var PROJECT_COLORS = {
  global: '#8b93f0',
};
function projectColor(proj) {
  return PROJECT_COLORS[proj] || ('hsl(' + hashHue(proj) + ',55%,65%)');
}
function projectDotStyle(proj) {
  return 'width:7px;height:7px;border-radius:50%;flex-shrink:0;background:' + projectColor(proj);
}

var CATEGORY_HUES = {
  'api-key': 217, wallet: 280, server: 160, 'ssh-key': 191, database: 18,
  cloudflare: 30, github: 0, rpc: 261, 'rpc-endpoint': 261, 'encryption-key': 340,
  'jwt-secret': 45, oauth: 200, 'web-admin': 120, supabase: 152, '2fa': 122,
};
function categoryColor(cat) {
  var hue = CATEGORY_HUES.hasOwnProperty(cat) ? CATEGORY_HUES[cat] : hashHue(cat);
  var sat = cat === 'github' ? 0 : 42;
  return {
    fg:     'hsl(' + hue + ',' + sat + '%,68%)',
    bg:     'hsla(' + hue + ',' + sat + '%,55%,.14)',
    border: 'hsla(' + hue + ',' + sat + '%,55%,.3)',
  };
}
function categoryChipStyle(cat) {
  var c = categoryColor(cat);
  return 'font-size:11px;font-weight:500;padding:2.5px 8px;border-radius:6px;white-space:nowrap;' +
    'background:' + c.bg + ';color:' + c.fg + ';border:1px solid ' + c.border;
}

// ─── API ───────────────────────────────────────────────────────────────────
async function api(path, opts) {
  var headers = { 'Content-Type': 'application/json' };
  var sid = sessionStorage.getItem('credmgr-session');
  if (sid) headers['X-Credmgr-Session'] = sid;
  var o = opts || {};
  // Merge, don't replace: Object.assign({headers}, o) would let a caller's
  // own `headers` silently drop Content-Type/X-Credmgr-Session entirely
  // (both objects have a top-level `headers` key, so the second wins whole).
  if (o.headers) headers = Object.assign(headers, o.headers);
  var res = await fetch('/api' + path, Object.assign({}, o, { headers: headers }));
  if (!res.ok) {
    var err = await res.json().catch(function() { return { error: res.statusText }; });
    // The daemon says the vault is locked — reflect it. The lock screen is a
    // mirror of server state, never the mechanism itself.
    if (res.status === 401 && err && err.locked) showLockScreen();
    throw new Error(err.error || res.statusText);
  }
  var ct = res.headers.get('content-type') || '';
  return ct.includes('json') ? res.json() : res.text();
}

// ─── Init ──────────────────────────────────────────────────────────────────
async function init() {
  await refreshHealthBadge();
  await loadProjects();
  await loadCredentials();
  loadStats();
  await loadSuggestions();
  refreshHub();
  updateTrustPill();
  try { typeSchemas = await api('/schemas'); } catch (e) { typeSchemas = {}; }
}

// "Encrypted · Verified · N secrets" — encryption OK (/health) + checksum OK
// (/verify) + the live count, in one glance. Falls back gracefully per-signal
// so a slow/failed sub-check doesn't hide the ones that succeeded.
async function refreshHealthBadge() {
  var okEncryption = false, okChecksum = false, count = null;
  try {
    var health = await api('/health');
    okEncryption = !!health.ok;
  } catch (e) { okEncryption = false; }
  try {
    var verify = await api('/verify');
    okChecksum = verify.checksum === 'ok' || verify.ok === true;
  } catch (e) { okChecksum = false; }
  try {
    var stats = await api('/stats');
    count = stats.total;
  } catch (e) { count = null; }

  var ok = okEncryption && okChecksum;
  $healthBadge.className = 'health-badge ' + (ok ? 'ok' : 'err');
  if (!okEncryption) {
    $healthText.textContent = 'error';
  } else {
    var parts = ['Encrypted'];
    parts.push(okChecksum ? 'Verified' : 'checksum issue');
    if (count != null) parts.push(count + ' secret' + (count === 1 ? '' : 's'));
    $healthText.textContent = parts.join(' · ');
  }
  return { okEncryption: okEncryption, okChecksum: okChecksum, count: count };
}

// "Trusted local" vs "exposed" — driven by the daemon's own self-description
// (GET /api/status: bind + tokenRequired), with the page-origin heuristic kept
// only as the fallback when the endpoint is unreachable.
async function updateTrustPill() {
  var pill = document.getElementById('trust-pill');
  var text = document.getElementById('trust-pill-text');
  if (!pill || !text) return;
  try {
    var s = await api('/status');
    var isLocal = s.bind === '127.0.0.1' || s.bind === 'localhost' || s.bind === '::1';
    pill.classList.toggle('exposed', !isLocal);
    if (isLocal) {
      text.textContent = 'Trusted local';
      pill.title = 'Daemon bound to ' + s.bind + ' — no network exposure' +
        (s.version ? ' · v' + s.version : '');
    } else {
      text.textContent = s.tokenRequired ? 'Exposed — token enforced' : 'Exposed — NO TOKEN';
      pill.title = 'Daemon bound to ' + s.bind +
        (s.tokenRequired ? ' with bearer-token auth' : ' WITHOUT a token — anyone on the network can read secrets');
    }
  } catch (e) {
    // Fallback: infer from the page origin
    var h = window.location.hostname;
    var local = h === 'localhost' || h === '127.0.0.1' || h === '::1' || h === '';
    pill.classList.toggle('exposed', !local);
    text.textContent = local ? 'Trusted local' : 'Exposed — token required';
    pill.title = local
      ? 'Local dashboard — no network egress'
      : 'Reachable beyond localhost — make sure a daemon bearer token is set';
  }
}

async function loadProjects() {
  try {
    projects = await api('/projects');

    // Filter dropdown
    $filterProject.textContent = '';
    $filterProject.appendChild(el('option', { value: '', text: 'All Projects' }));
    for (var i = 0; i < projects.length; i++) {
      $filterProject.appendChild(el('option', { value: projects[i].id, text: projects[i].name }));
    }

    // Add form dropdown
    var $addProj = document.getElementById('add-project');
    $addProj.textContent = '';
    for (var j = 0; j < projects.length; j++) {
      $addProj.appendChild(el('option', { value: projects[j].id, text: projects[j].name }));
    }

    // Bulk-ops dropdowns in Settings modal
    var $rFrom = document.getElementById('reassign-from');
    var $rTo   = document.getElementById('reassign-to');
    var $bProj = document.getElementById('batch-project');
    if ($rFrom && $rTo && $bProj) {
      $rFrom.textContent = '';
      $rTo.textContent   = '';
      $bProj.textContent = '';
      $rFrom.appendChild(el('option', { value: '', text: 'From…' }));
      $rTo.appendChild(el('option',   { value: '', text: 'To…' }));
      for (var k = 0; k < projects.length; k++) {
        $rFrom.appendChild(el('option', { value: projects[k].id, text: projects[k].name }));
        $rTo.appendChild(el('option',   { value: projects[k].id, text: projects[k].name }));
        $bProj.appendChild(el('option', { value: projects[k].id, text: projects[k].name }));
      }
    }

    // Export dropdown in Settings modal
    var $exp = document.getElementById('export-project');
    if ($exp) {
      $exp.textContent = '';
      $exp.appendChild(el('option', { value: '', text: 'Project…' }));
      for (var m = 0; m < projects.length; m++) {
        $exp.appendChild(el('option', { value: projects[m].id, text: projects[m].name }));
      }
    }

    // Remove-empty-project dropdown in Settings modal — global excluded,
    // it's the one project that must always exist (removeProject refuses it
    // server-side too, but no point offering it here).
    var $rmProj = document.getElementById('remove-project-select');
    if ($rmProj) {
      $rmProj.textContent = '';
      $rmProj.appendChild(el('option', { value: '', text: 'Project…' }));
      for (var n = 0; n < projects.length; n++) {
        if (projects[n].id === 'global') continue;
        $rmProj.appendChild(el('option', { value: projects[n].id, text: projects[n].name }));
      }
    }
  } catch (err) {
    toast('Failed to load projects: ' + err.message, 'error');
  }
}

async function loadCredentials() {
  try {
    var params = new URLSearchParams();
    if ($filterProject.value)  params.set('project', $filterProject.value);
    if ($filterCategory.value) params.set('category', $filterCategory.value);
    if (currentSens)           params.set('sensitivity', currentSens);

    var creds = await api('/credentials?' + params.toString());
    creds = await applySmartView(creds);
    allCredentials = creds;
    renderList(allCredentials);
    updateCategoryFilter(allCredentials);
    updateStatsBar(allCredentials);
  } catch (err) {
    toast('Failed to load credentials: ' + err.message, 'error');
  }
}

// ─── Smart Views (Wallets / Expiring / Never accessed) ────────────────────
// Quick, real filters layered on top of the normal project/category/
// sensitivity ones — "Wallets" narrows client-side by category; "Expiring"
// and "Never accessed" reuse the server's own /expiring and /audit logic so
// the definition of "expiring" or "never accessed" never drifts from the
// health hub's.
async function applySmartView(creds) {
  if (!currentSmartView) return creds;
  if (currentSmartView === 'wallets') {
    return creds.filter(function(c) { return c.category === 'wallet'; });
  }
  if (currentSmartView === 'expiring') {
    try {
      var expiring = await api('/expiring?days=30');
      var names = {};
      expiring.forEach(function(e) { names[e.name] = true; });
      return creds.filter(function(c) { return names[c.name]; });
    } catch (e) { return creds; }
  }
  if (currentSmartView === 'never-accessed') {
    try {
      var audit = await api('/audit');
      var never = {};
      (audit.issues || []).forEach(function(i) { if (i.type === 'never-accessed') never[i.name] = true; });
      return creds.filter(function(c) { return never[c.name]; });
    } catch (e) { return creds; }
  }
  return creds;
}

function setSmartView(view) {
  currentSmartView = currentSmartView === view ? '' : view; // click active chip again to clear
  var chips = document.querySelectorAll('.smart-view-chip');
  for (var i = 0; i < chips.length; i++) {
    chips[i].classList.toggle('active', chips[i].getAttribute('data-view') === currentSmartView);
  }
  loadCredentials();
}

(function wireSmartViews() {
  var chips = document.querySelectorAll('.smart-view-chip');
  for (var i = 0; i < chips.length; i++) {
    chips[i].addEventListener('click', function() { setSmartView(this.getAttribute('data-view')); });
  }
})();

async function loadStats() {
  try {
    var s = await api('/stats');
    $footerStats.textContent = s.total + ' credentials · ' + s.projectCount + ' projects · ' + Object.keys(s.byCategory).length + ' categories';
    renderCharts(s);
  } catch (e) { /* ignore */ }
}

function updateStatsBar(creds) {
  $statsBar.textContent = creds.length + ' shown';
}

// ─── Charts (donut + horizontal bars) ──────

var CATEGORY_COLORS = {
  'api-key':        '#60a5fa',
  'server':         '#f97316',
  'wallet':         '#fbbf24',
  'database':       '#34d399',
  'supabase':       '#3ecf8e',
  'cloudflare':     '#f38020',
  'ssh-key':        '#a78bfa',
  'rpc':            '#22d3ee',
  'encryption-key': '#ef4444',
  'jwt-secret':     '#818cf8',
  'github':         '#c9d1d9',
  'oauth':          '#fb923c',
  'web-admin':      '#f472b6',
  'ai-service':     '#67e8f9',
  'integration':    '#94a3b8',
};

var PROJECT_TONES = {
  global:           'purple',
};

function renderCharts(stats) {
  renderDonutChart(stats.byCategory, stats.total);
  renderProjectBars(stats.byProject);
  renderSensitivityBars(stats.bySensitivity);
}

function renderDonutChart(byCategory, total) {
  var container = document.getElementById('donut-category');
  var legend = document.getElementById('donut-legend');
  container.textContent = '';
  legend.textContent = '';

  // Sort by count desc, take top 8, group rest as "other"
  var entries = Object.entries(byCategory).sort(function(a, b) { return b[1] - a[1]; });
  var segments = [];
  var otherCount = 0;
  for (var i = 0; i < entries.length; i++) {
    if (i < 8) {
      segments.push({ label: entries[i][0], value: entries[i][1], color: CATEGORY_COLORS[entries[i][0]] || '#6b7280' });
    } else {
      otherCount += entries[i][1];
    }
  }
  if (otherCount > 0) segments.push({ label: 'other', value: otherCount, color: '#374560' });

  var radius = 38;
  var circ = 2 * Math.PI * radius;
  var ns = 'http://www.w3.org/2000/svg';
  var svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 100 100');

  // Track
  var track = document.createElementNS(ns, 'circle');
  track.setAttribute('cx', '50'); track.setAttribute('cy', '50'); track.setAttribute('r', String(radius));
  track.setAttribute('class', 'donut-track');
  svg.appendChild(track);

  // Segments
  var offset = 0;
  for (var si = 0; si < segments.length; si++) {
    var seg = segments[si];
    var segLen = total === 0 ? 0 : (seg.value / total) * circ;
    var circle = document.createElementNS(ns, 'circle');
    circle.setAttribute('cx', '50'); circle.setAttribute('cy', '50'); circle.setAttribute('r', String(radius));
    circle.setAttribute('class', 'donut-seg');
    circle.setAttribute('stroke', seg.color);
    circle.setAttribute('stroke-dasharray', segLen + ' ' + (circ - segLen));
    circle.setAttribute('stroke-dashoffset', String(-offset));
    svg.appendChild(circle);
    offset += segLen;
  }

  // Center label
  var txt = document.createElementNS(ns, 'text');
  txt.setAttribute('x', '50'); txt.setAttribute('y', '47');
  txt.setAttribute('text-anchor', 'middle'); txt.setAttribute('class', 'donut-center-val');
  txt.textContent = String(total);
  svg.appendChild(txt);

  var cap = document.createElementNS(ns, 'text');
  cap.setAttribute('x', '50'); cap.setAttribute('y', '58');
  cap.setAttribute('text-anchor', 'middle'); cap.setAttribute('class', 'donut-center-cap');
  cap.textContent = 'total';
  svg.appendChild(cap);

  container.appendChild(svg);

  // Legend
  for (var li = 0; li < segments.length; li++) {
    var item = el('li', {}, [
      el('span', { className: 'donut-legend-dot', style: 'background:' + segments[li].color }),
      el('span', { text: segments[li].label }),
      el('span', { className: 'donut-legend-val', text: String(segments[li].value) }),
    ]);
    legend.appendChild(item);
  }
}

function renderProjectBars(byProject) {
  var container = document.getElementById('bars-project');
  container.textContent = '';
  var entries = Object.entries(byProject).sort(function(a, b) { return b[1] - a[1]; });
  var max = entries.length > 0 ? entries[0][1] : 1;

  for (var i = 0; i < entries.length; i++) {
    var proj = entries[i][0];
    var count = entries[i][1];
    var pct = Math.max(4, (count / max) * 100);
    var tone = PROJECT_TONES[proj] || 'muted';

    var fill = el('span', { className: 'hbar-fill', style: 'width:' + pct + '%' });
    fill.setAttribute('data-tone', tone);

    container.appendChild(el('div', { className: 'hbar-row' }, [
      el('div', { className: 'hbar-labels' }, [
        el('span', { text: proj }),
        el('strong', { text: String(count) }),
      ]),
      el('div', { className: 'hbar-track' }, [fill]),
    ]));
  }
}

function renderSensitivityBars(bySens) {
  var container = document.getElementById('bars-sensitivity');
  container.textContent = '';
  var order = ['critical', 'high', 'medium', 'low'];
  var max = 0;
  for (var i = 0; i < order.length; i++) {
    var v = bySens[order[i]] || 0;
    if (v > max) max = v;
  }
  if (max === 0) max = 1;

  for (var si = 0; si < order.length; si++) {
    var level = order[si];
    var count = bySens[level] || 0;
    var pct = Math.max(4, (count / max) * 100);

    var fill = el('span', { className: 'hbar-fill', style: 'width:' + pct + '%' });
    fill.setAttribute('data-tone', level);

    container.appendChild(el('div', { className: 'hbar-row' }, [
      el('div', { className: 'hbar-labels' }, [
        el('span', { text: level }),
        el('strong', { text: String(count) }),
      ]),
      el('div', { className: 'hbar-track' }, [fill]),
    ]));
  }
}

// ─── Render List ───────────────────────────────────────────────────────────
function renderList(creds) {
  $list.textContent = '';
  kbFocusIdx = -1;

  if (creds.length === 0) {
    var emptyIcon = svgIcon('<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', '40');
    $list.appendChild(el('div', { className: 'empty-state' }, [
      emptyIcon,
      el('h3', { text: 'No credentials found' }),
      el('p',  { text: 'Try adjusting your filters or add a new credential.' }),
    ]));
    return;
  }

  // Separate favorites from the rest
  var favCreds = [];
  var restCreds = [];
  for (var fi = 0; fi < creds.length; fi++) {
    if (isFavorite(creds[fi].name)) { favCreds.push(creds[fi]); } else { restCreds.push(creds[fi]); }
  }

  // Render favorites group
  if (favCreds.length > 0) {
    $list.appendChild(el('div', { className: 'fav-group-header' }, [
      el('span', { className: 'fav-group-dot' }),
      'PINNED',
      el('span', { className: 'group-count', text: String(favCreds.length) }),
    ]));
    for (var fv = 0; fv < favCreds.length; fv++) {
      $list.appendChild(renderCredItem(favCreds[fv]));
    }
  }

  // Group rest by project
  var grouped = {};
  var order   = [];
  for (var i = 0; i < restCreds.length; i++) {
    var p = restCreds[i].project || 'global';
    if (!grouped[p]) { grouped[p] = []; order.push(p); }
    grouped[p].push(restCreds[i]);
  }

  for (var g = 0; g < order.length; g++) {
    var proj  = order[g];
    var items = grouped[proj];
    var pInfo = null;
    for (var k = 0; k < projects.length; k++) {
      if (projects[k].id === proj) { pInfo = projects[k]; break; }
    }
    var label = pInfo ? pInfo.name : proj;

    // Group header — pencil edit button reveals on hover via CSS
    var dot = el('span', { className: 'group-dot', style: 'background:' + projectColor(proj) });
    var cnt = el('span', { className: 'group-count', text: String(items.length) });
    var editBtn = el('button', { className: 'group-edit-btn', title: 'Rename group' });
    editBtn.appendChild(svgIcon('<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>', '11'));
    var headerEl = el('div', { className: 'group-header' }, [dot, label.toUpperCase(), editBtn, cnt]);
    // Wire edit button after headerEl is created so closure captures the right reference
    (function(pid, lbl, hdr) {
      editBtn.addEventListener('click', function(e) {
        e.stopPropagation();
        startGroupRename(pid, lbl, hdr);
      });
    })(proj, label, headerEl);
    $list.appendChild(headerEl);

    // Items
    for (var m = 0; m < items.length; m++) {
      $list.appendChild(renderCredItem(items[m]));
    }
  }
}

// ─── Inline Project Group Rename ──────────────────────────────────────────
function startGroupRename(projectId, currentLabel, headerEl) {
  // Replace header content with an inline input + save/cancel
  headerEl.textContent = '';

  var dot = el('span', { className: 'group-dot', style: 'background:' + projectColor(projectId) });
  var input = el('input', {
    type: 'text',
    className: 'group-rename-input',
    value: currentLabel,
  });
  var saveBtn  = el('button', { className: 'group-rename-save',   type: 'button', text: 'Save' });
  var cancelBtn = el('button', { className: 'group-rename-cancel', type: 'button', text: 'Cancel' });
  var wrap = el('div', { className: 'group-rename-wrap' }, [input, saveBtn, cancelBtn]);
  headerEl.appendChild(dot);
  headerEl.appendChild(wrap);

  input.focus();
  input.select();

  async function doSave() {
    var newName = input.value.trim();
    if (!newName) { toast('Name cannot be empty', 'error'); return; }
    if (newName === currentLabel) { cancelRename(); return; }
    try {
      await api('/projects/' + encodeURIComponent(projectId), {
        method: 'PATCH',
        body: JSON.stringify({ name: newName }),
      });
      // Update local projects array so filter dropdown stays in sync
      for (var i = 0; i < projects.length; i++) {
        if (projects[i].id === projectId) { projects[i].name = newName; break; }
      }
      toast('Renamed to "' + newName + '"');
      await loadCredentials();   // re-renders list with updated label
      loadProjects();            // re-populates filter dropdown
    } catch (err) {
      toast('Rename failed: ' + err.message, 'error');
      cancelRename();
    }
  }

  function cancelRename() {
    // Re-render the list to restore original header
    renderList(allCredentials);
  }

  saveBtn.addEventListener('click', doSave);
  cancelBtn.addEventListener('click', cancelRename);
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  { e.preventDefault(); doSave(); }
    if (e.key === 'Escape') { e.preventDefault(); cancelRename(); }
  });
}

function renderCredItem(c) {
  var refLabel  = el('span', { className: 'cred-ref', text: '#' + String(c.ref || 0).padStart(4, '0') });
  var projDot   = el('span', { className: 'proj-dot', style: projectDotStyle(c.project), title: c.project });
  var catBadge  = el('span', { style: categoryChipStyle(c.category), text: c.category });
  var sensBadge = el('span', { className: 'sens-badge ' + c.sensitivity }, [sensIcon(c.sensitivity), ' ' + c.sensitivity]);

  // Expiry badge
  var expiryBadge = makeExpiryBadge(c.expiresAt);

  var metaChildren = [projDot, catBadge, sensBadge];
  if (expiryBadge) metaChildren.push(expiryBadge);
  if (!mergeMode) metaChildren.push(makeFavStar(c.name));
  var meta = el('div', { className: 'cred-meta' }, metaChildren);
  var nameRow = el('div', { className: 'cred-name-row' }, [refLabel, el('span', { className: 'cred-name', text: c.name })]);

  var children = [];

  // Merge mode checkbox
  if (mergeMode) {
    var cb = el('input', { type: 'checkbox', className: 'merge-cb' });
    if (mergeSelected[c.name]) cb.checked = true;
    cb.addEventListener('change', function(e) {
      e.stopPropagation();
      if (cb.checked) { mergeSelected[c.name] = true; } else { delete mergeSelected[c.name]; }
      updateMergeCount();
    });
    cb.addEventListener('click', function(e) { e.stopPropagation(); });
    children.push(cb);
  }

  children.push(nameRow, meta);

  var row = el('div', {
    className: 'cred-item sens-' + c.sensitivity + (mergeSelected[c.name] ? ' merge-selected' : ''),
    onclick: function() {
      if (mergeMode) {
        // Toggle checkbox on row click
        var checkbox = row.querySelector('.merge-cb');
        if (checkbox) { checkbox.checked = !checkbox.checked; checkbox.dispatchEvent(new Event('change')); }
        row.classList.toggle('merge-selected');
      } else {
        openDetail(c.name, c.sensitivity);
      }
    },
  }, children);

  return row;
}

function updateCategoryFilter(creds) {
  var cats = [], seen = {};
  for (var i = 0; i < creds.length; i++) {
    if (!seen[creds[i].category]) { cats.push(creds[i].category); seen[creds[i].category] = true; }
  }
  cats.sort();
  var current = $filterCategory.value;
  $filterCategory.textContent = '';
  $filterCategory.appendChild(el('option', { value: '', text: 'All Categories' }));
  for (var j = 0; j < cats.length; j++) {
    var opt = el('option', { value: cats[j], text: cats[j] });
    if (cats[j] === current) opt.selected = true;
    $filterCategory.appendChild(opt);
  }
}

// ─── Command Palette (⌘K) — primary nav: search + every command ──────────
// Replaces the old inline search dropdown + its separate "full results"
// modal. One surface: type to fuzzy-search credentials (or #ref to jump),
// or leave it empty to browse every command. ↑/↓ + Enter drive both.
var $paletteModal = document.getElementById('palette-modal');
var $paletteInput = document.getElementById('palette-input');
var $paletteBody  = document.getElementById('palette-body');
var $paletteCount = document.getElementById('palette-count');
var paletteKbIdx  = -1;
var PALETTE_RESULT_CAP = 30; // safety cap on a very generic query; palette body scrolls

function clickById(id) { var b = document.getElementById(id); if (b) b.click(); }

// Opens Settings then clicks a button inside it — settings-modal has no open
// animation delay (openModal is a synchronous class toggle), so no timeout needed.
function runSettingsAction(btnId) {
  openModal($settingsModal);
  clickById(btnId);
}

var PALETTE_COMMANDS = [
  { label: 'New credential', kbd: 'N', icon: '<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>', action: function() { clickById('add-btn'); } },
  { label: 'Batch import…', icon: '<polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/>', action: function() { clickById('batch-add-btn'); } },
  { label: mergeMode ? 'Cancel merge' : 'Merge credentials…', icon: '<path d="M8 6L21 6"/><path d="M8 12L21 12"/><path d="M8 18L21 18"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>', action: function() { toggleMergeMode(); } },
  { label: 'Vault stats', kbd: 'H', icon: '<line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/>', action: function() { openStatsModal(); } },
  { label: 'Run doctor — diagnose & repair', icon: '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>', action: function() { runSettingsAction('doctor-btn'); } },
  { label: 'Back up vault (encrypted)', icon: '<rect x="2" y="7" width="20" height="14" rx="2"/><path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"/>', action: function() { runSettingsAction('backup-btn'); } },
  { label: 'Verify integrity', icon: '<path d="M9 12l2 2 4-4"/><path d="M12 2 3 6v6c0 5.4 3.8 9.6 9 11 5.2-1.4 9-5.6 9-11V6l-9-4Z"/>', action: function() { clickById('verify-btn'); } },
  { label: 'Health audit', icon: '<path d="M9 18h6M10 22h4M12 2v2M12 6a6 6 0 0 1 6 6c0 2.5-1.5 4.5-3 5.5H9C7.5 18.5 6 16.5 6 12a6 6 0 0 1 6-6Z"/>', action: function() { clickById('audit-btn'); } },
  { label: 'View changelog', icon: '<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>', action: function() { clickById('changelog-btn'); } },
  { label: 'View access log', icon: '<path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>', action: function() { clickById('access-log-btn'); } },
  { label: 'Toggle activity sidebar', icon: '<rect x="3" y="4" width="18" height="16" rx="2"/><line x1="9" y1="4" x2="9" y2="20"/>', action: function() { clickById('activity-toggle'); } },
  { label: 'Settings', icon: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1Z"/>', action: function() { openModal($settingsModal); } },
  { label: 'Keyboard shortcuts', kbd: '?', icon: '<circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/>', action: function() { clickById('shortcuts-btn'); } },
  { label: 'Toggle theme', kbd: 'T', icon: '<path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79Z"/>', action: function() { clickById('theme-toggle'); } },
  { label: 'Lock vault', kbd: '⌘L', icon: '<rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>', action: function() { requestLock(); } },
];

function openPalette() {
  $paletteInput.value = '';
  openModal($paletteModal);
  renderPaletteBody('');
  setTimeout(function() { $paletteInput.focus(); }, 0);
}
function closePalette() {
  closeModal($paletteModal);
  paletteKbIdx = -1;
}

function paletteRows() { return $paletteBody.querySelectorAll('.palette-row'); }
function setPaletteKbFocus(idx) {
  var rows = paletteRows();
  if (!rows.length) { paletteKbIdx = -1; return; }
  var old = $paletteBody.querySelector('.palette-row.kb-focus');
  if (old) old.classList.remove('kb-focus');
  paletteKbIdx = Math.max(-1, Math.min(idx, rows.length - 1));
  if (paletteKbIdx >= 0) {
    rows[paletteKbIdx].classList.add('kb-focus');
    rows[paletteKbIdx].scrollIntoView({ block: 'nearest' });
  }
}

function paletteCredRow(c) {
  var dot = el('span', { className: 'sr-dot dot-' + c.sensitivity });
  var name = el('span', { className: 'sr-name', text: c.name });
  var ref = el('span', { className: 'sr-ref', text: '#' + (c.ref || '?') });
  var row = el('div', { className: 'palette-row' }, [dot, name, ref]);
  row.addEventListener('click', function() {
    // Remember the query so Back/Esc from the detail panel returns straight
    // to these results — no retyping, pick the next candidate directly.
    paletteReturnQuery = $paletteInput.value;
    closePalette();
    openDetail(c.name, c.sensitivity, { fromSearch: true });
  });
  return row;
}

// ─── Search → detail → back-to-results navigation ─────────────────────────
var paletteReturnQuery = null;  // last query a detail panel was opened from
var detailFromSearch   = false; // is the open detail panel a search result?
var lastDetailName     = null;

function returnToSearchResults() {
  detailFromSearch = false;
  closeDetailPanel();
  openPalette();
  if (paletteReturnQuery) {
    $paletteInput.value = paletteReturnQuery;
    renderPaletteBody(paletteReturnQuery);
  }
}

function paletteCommandRow(cmd) {
  var children = [svgIcon(cmd.icon, '14'), el('span', { className: 'palette-row-label', text: cmd.label })];
  if (cmd.kbd) children.push(el('kbd', { text: cmd.kbd }));
  var row = el('div', { className: 'palette-row' }, children);
  row.addEventListener('click', function() { closePalette(); cmd.action(); });
  return row;
}

async function renderPaletteBody(q) {
  $paletteBody.textContent = '';
  paletteKbIdx = -1;
  q = (q || '').trim();

  var credMatches = [];
  if (q) {
    try {
      credMatches = await api('/search?q=' + encodeURIComponent(q));
      // Ref jump: "#3060" or bare digits also match by ref number — client-side
      // against already-loaded metadata, no decryption needed to search.
      var refMatch = q.match(/^#?(\d{1,4})$/);
      if (refMatch) {
        var refStr = refMatch[1];
        var have = {};
        for (var ri = 0; ri < credMatches.length; ri++) have[credMatches[ri].name] = true;
        for (var ci = 0; ci < allCredentials.length; ci++) {
          var c = allCredentials[ci];
          if (c.ref && String(c.ref).indexOf(refStr) === 0 && !have[c.name]) credMatches.unshift(c);
        }
      }
    } catch (err) { credMatches = []; }
  }

  var cmdMatches = PALETTE_COMMANDS.filter(function(cmd) {
    return !q || cmd.label.toLowerCase().indexOf(q.toLowerCase()) !== -1;
  });

  if (q && credMatches.length) {
    $paletteBody.appendChild(el('div', { className: 'palette-section-label', text: 'Credentials' }));
    var shown = credMatches.slice(0, PALETTE_RESULT_CAP);
    for (var i = 0; i < shown.length; i++) $paletteBody.appendChild(paletteCredRow(shown[i]));
    if (credMatches.length > shown.length) {
      $paletteBody.appendChild(el('div', { className: 'palette-more', text: '+' + (credMatches.length - shown.length) + ' more — refine your search' }));
    }
  }

  if (cmdMatches.length) {
    $paletteBody.appendChild(el('div', { className: 'palette-section-label', text: 'Commands' }));
    for (var j = 0; j < cmdMatches.length; j++) $paletteBody.appendChild(paletteCommandRow(cmdMatches[j]));
  }

  if (!credMatches.length && !cmdMatches.length) {
    $paletteBody.appendChild(el('div', { className: 'palette-empty', text: 'No results for "' + q + '"' }));
  }

  $paletteCount.textContent = (credMatches.length + cmdMatches.length) + (q ? ' result' : ' command') + ((credMatches.length + cmdMatches.length) === 1 ? '' : 's');
}

$paletteInput.addEventListener('input', function() {
  clearTimeout(searchTimeout);
  var q = $paletteInput.value;
  searchTimeout = setTimeout(function() { renderPaletteBody(q); }, 150);
});

$paletteInput.addEventListener('keydown', function(e) {
  if (e.key === 'ArrowDown') { e.preventDefault(); setPaletteKbFocus(paletteKbIdx + 1); return; }
  if (e.key === 'ArrowUp')   { e.preventDefault(); setPaletteKbFocus(paletteKbIdx - 1); return; }
  if (e.key === 'Enter') {
    e.preventDefault();
    var rows = paletteRows();
    var idx = paletteKbIdx >= 0 ? paletteKbIdx : 0; // default to the first row (usually top match)
    if (rows[idx]) rows[idx].click();
    return;
  }
  if (e.key === 'Escape') { closePalette(); }
});

$paletteModal.addEventListener('click', function(e) { if (e.target === $paletteModal) closePalette(); });
document.getElementById('cm-search-btn').addEventListener('click', openPalette);
// ⌘K / ⌘L / Escape for the palette and lock are handled in the single
// consolidated keydown listener further down (search "Global keyboard
// shortcuts") — kept in one place so Escape's priority chain can't race
// across two independent listeners.

// ─── Filters ───────────────────────────────────────────────────────────────
$filterProject.addEventListener('change', loadCredentials);
$filterCategory.addEventListener('change', loadCredentials);

// Sensitivity pills
var pills = document.querySelectorAll('.sens-pill');
for (var pi = 0; pi < pills.length; pi++) {
  (function(pill) {
    pill.addEventListener('click', function() {
      currentSens = pill.getAttribute('data-val');
      for (var i = 0; i < pills.length; i++) pills[i].classList.remove('active');
      pill.classList.add('active');
      loadCredentials();
    });
  })(pills[pi]);
}

// ─── TOTP (RFC 6238) — HMAC-SHA1 one-time codes via Web Crypto, no deps ────
function base32Decode(input) {
  var ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  var clean = String(input).toUpperCase().replace(/[^A-Z2-7]/g, '');
  var bits = '';
  for (var i = 0; i < clean.length; i++) {
    var idx = ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, '0');
  }
  var bytes = [];
  for (var j = 0; j + 8 <= bits.length; j += 8) { bytes.push(parseInt(bits.substr(j, 8), 2)); }
  return new Uint8Array(bytes);
}

async function totpCode(secretBase32, digits, step) {
  digits = digits || 6;
  step = step || 30;
  var counter = Math.floor(Date.now() / 1000 / step);

  var counterBuf = new ArrayBuffer(8);
  var view = new DataView(counterBuf);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  var key = await crypto.subtle.importKey(
    'raw', base32Decode(secretBase32), { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']
  );
  var sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));

  var offset = sig[sig.length - 1] & 0x0f;
  var binCode = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) |
                ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  var codeStr = String(binCode % Math.pow(10, digits));
  while (codeStr.length < digits) codeStr = '0' + codeStr;
  return codeStr;
}

function looksLikeTotp(meta) {
  var cat = (meta.category || '').toLowerCase();
  var fmt = (meta.format || '').toLowerCase();
  return cat === '2fa' || cat === 'totp' || fmt.indexOf('totp') !== -1;
}

function renderTotpValue(container, secretRaw) {
  var STEP = 30;
  var CIRC = 2 * Math.PI * 18; // r=18, matches ring markup below

  container.appendChild(el('div', { className: 'detail-label', text: 'Live one-time code', style: 'margin-bottom:8px' }));

  var ns = 'http://www.w3.org/2000/svg';
  var ringSvg = document.createElementNS(ns, 'svg');
  ringSvg.setAttribute('width', '44'); ringSvg.setAttribute('height', '44');
  ringSvg.setAttribute('viewBox', '0 0 44 44');
  ringSvg.style.transform = 'rotate(-90deg)';
  ringSvg.innerHTML =
    '<circle cx="22" cy="22" r="18" fill="none" stroke="var(--border)" stroke-width="3.4"/>' +
    '<circle class="totp-ring-arc" cx="22" cy="22" r="18" fill="none" stroke="var(--accent)" stroke-width="3.4" ' +
    'stroke-linecap="round" stroke-dasharray="' + CIRC.toFixed(2) + '"/>';
  var ringArc = ringSvg.querySelector('.totp-ring-arc');
  var secEl = el('span', { className: 'totp-seconds', text: '' });
  var ringWrap = el('div', { className: 'totp-ring-wrap' }, [ringSvg, secEl]);

  var codeEl = el('div', { className: 'totp-code', text: '· · ·' });
  var copyBtn = makeCopyBtn(function() { return codeEl.textContent.replace(/\s/g, ''); });
  copyBtn.style.marginLeft = 'auto';

  container.appendChild(el('div', { className: 'totp-box' }, [ringWrap, codeEl, copyBtn]));

  clearTotpTimer(); // only one live ticker running at a time
  async function tick() {
    var now = Date.now() / 1000;
    var remaining = Math.ceil(STEP - (now % STEP));
    secEl.textContent = remaining + 's';
    ringArc.style.strokeDashoffset = String(CIRC * (1 - remaining / STEP));
    try {
      var code = await totpCode(secretRaw);
      codeEl.textContent = code.slice(0, 3) + ' ' + code.slice(3);
    } catch (e) {
      codeEl.textContent = 'invalid secret';
    }
  }
  tick();
  activeTotpTimer = setInterval(tick, 1000);
}

// ─── Wallet Value Helpers ──────────────────────────────────────────────────
var WALLET_CRITICAL_LABELS = ['privatekey', 'seedphrase', 'mnemonic', 'recoveryphrase'];
function normalizeFieldLabel(label) { return String(label || '').toLowerCase().replace(/[^a-z0-9]/g, ''); }
// camelCase or snake_case → "TITLE CASE WORDS" for display (publicKey → PUBLIC KEY)
function humanizeFieldLabel(label) {
  return String(label || '')
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .toUpperCase();
}
function isWalletCriticalField(label) { return WALLET_CRITICAL_LABELS.indexOf(normalizeFieldLabel(label)) !== -1; }

function renderWalletValue(container, fields) {
  var byLabel = {};
  for (var i = 0; i < fields.length; i++) { byLabel[normalizeFieldLabel(fields[i].label)] = fields[i]; }

  var chain = byLabel.chain, walletType = byLabel.wallettype, address = byLabel.address;
  var rest = fields.filter(function(f) {
    var n = normalizeFieldLabel(f.label);
    return n !== 'chain' && n !== 'wallettype' && n !== 'address';
  });

  if (chain || walletType) {
    var chainLine = [chain ? chain.value : null, walletType ? walletType.value : null].filter(Boolean).join(' · ');
    container.appendChild(el('div', { className: 'detail-row' }, [
      el('div', { className: 'detail-label', text: 'Chain / Type' }),
      el('div', { className: 'detail-value', text: chainLine }),
    ]));
  }

  if (address) {
    var addrEl = el('span', { className: 'wallet-address', text: address.value });
    var addrCopy = makeCopyBtn(function() { return address.value; });
    container.appendChild(el('div', { className: 'detail-row' }, [
      el('div', { className: 'detail-label', text: 'Address' }),
      el('div', { className: 'wallet-address-row' }, [addrEl, addrCopy]),
    ]));
  }

  if (!rest.length) return;

  container.appendChild(el('div', { className: 'detail-label', text: 'Wallet fields', style: 'margin:14px 0 6px' }));
  var box = el('div', { className: 'wallet-fields' });

  for (var j = 0; j < rest.length; j++) {
    (function(field) {
      var critical = isWalletCriticalField(field.label);
      var isSeed = normalizeFieldLabel(field.label) === 'seedphrase' || normalizeFieldLabel(field.label) === 'mnemonic';
      var revealed = false;

      var labelEl = el('span', {
        className: 'wallet-field-label' + (critical ? ' critical' : ''),
        text: humanizeFieldLabel(field.label),
      });

      var valueEl;
      if (isSeed) {
        valueEl = el('div', { className: 'wallet-seed-grid masked' });
        var words = String(field.value).trim().split(/\s+/);
        for (var w = 0; w < words.length; w++) {
          valueEl.appendChild(el('span', { className: 'wallet-seed-word' }, [
            el('span', { className: 'wallet-seed-idx', text: (w + 1) + '.' }), ' ' + words[w],
          ]));
        }
      } else {
        valueEl = el('div', { className: 'wallet-field-value masked', text: '••••••••' });
      }

      var eyeBtn = el('button', { className: 'btn-icon field-eye-btn', title: 'Reveal' });
      eyeBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
      eyeBtn.addEventListener('click', function() {
        revealed = !revealed;
        if (isSeed) {
          valueEl.classList.toggle('masked', !revealed);
        } else {
          valueEl.textContent = revealed ? field.value : '••••••••';
          valueEl.classList.toggle('masked', !revealed);
        }
        eyeBtn.innerHTML = '';
        eyeBtn.appendChild(svgIcon(revealed
          ? '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/>'
          : '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
        eyeBtn.title = revealed ? 'Hide' : 'Reveal';
      });

      var cpBtn = makeCopyBtn(function() { return field.value; });
      box.appendChild(el('div', { className: 'wallet-field-box' }, [
        el('div', { className: 'wallet-field-head' }, [labelEl, el('div', { className: 'wallet-field-actions' }, [eyeBtn, cpBtn])]),
        valueEl,
      ]));
    })(rest[j]);
  }
  container.appendChild(box);
}

// ─── Structured Value Helpers ──────────────────────────────────────────────
function isStructuredValue(val) {
  if (!val || typeof val !== 'string') return false;
  try { var p = JSON.parse(val); return p && Array.isArray(p._fields); }
  catch (_) { return false; }
}

function renderStructuredValue(container, rawVal, credName) {
  var parsed = JSON.parse(rawVal);
  var fields = parsed._fields;

  container.appendChild(el('div', { className: 'detail-label', text: 'Fields', style: 'margin-bottom:6px' }));

  var wrap = el('div', { className: 'fields-display' });
  var allRevealed = false;

  var fieldEls = [];
  for (var i = 0; i < fields.length; i++) {
    (function(field, idx) {
      var labelEl = el('div', { className: 'field-display-label', text: field.label });
      var valueEl = el('div', { className: 'field-display-value masked', text: '••••••••' });
      var fieldRevealed = false;

      // Eye toggle button per field
      var eyeBtn = el('button', { className: 'btn-icon field-eye-btn', title: 'Reveal' });
      eyeBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
      eyeBtn.addEventListener('click', function() {
        if (!fieldRevealed) {
          valueEl.textContent = field.value;
          valueEl.classList.remove('masked');
          fieldRevealed = true;
          eyeBtn.innerHTML = '';
          eyeBtn.appendChild(svgIcon('<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/>', '12'));
          eyeBtn.title = 'Hide';
        } else {
          valueEl.textContent = '••••••••';
          valueEl.classList.add('masked');
          fieldRevealed = false;
          eyeBtn.innerHTML = '';
          eyeBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
          eyeBtn.title = 'Reveal';
        }
      });

      fieldEls.push({ valueEl: valueEl, eyeBtn: eyeBtn, field: field, isRevealed: function() { return fieldRevealed; }, setRevealed: function(v) { fieldRevealed = v; } });

      var cpBtn = makeCopyBtn(function() { return field.value; });
      var actions = el('div', { className: 'field-display-actions' }, [eyeBtn, cpBtn]);
      wrap.appendChild(el('div', { className: 'field-display-row' }, [labelEl, valueEl, actions]));
    })(fields[i], i);
  }
  container.appendChild(wrap);

  // Reveal All / Hide All + Copy All
  var revealAllBtn = el('button', { className: 'btn btn-sm reveal-all-btn', style: 'margin-top:8px' });
  revealAllBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
  revealAllBtn.appendChild(document.createTextNode(' Reveal All'));
  revealAllBtn.addEventListener('click', function() {
    allRevealed = !allRevealed;
    for (var j = 0; j < fieldEls.length; j++) {
      var fe = fieldEls[j];
      if (allRevealed && !fe.isRevealed()) { fe.eyeBtn.click(); }
      else if (!allRevealed && fe.isRevealed()) { fe.eyeBtn.click(); }
    }
    revealAllBtn.innerHTML = '';
    if (allRevealed) {
      revealAllBtn.appendChild(svgIcon('<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/>', '12'));
      revealAllBtn.appendChild(document.createTextNode(' Hide All'));
    } else {
      revealAllBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
      revealAllBtn.appendChild(document.createTextNode(' Reveal All'));
    }
  });

  var copyAllBtn = el('button', { className: 'btn btn-sm', style: 'margin-top:8px' });
  copyAllBtn.appendChild(svgIcon('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>', '12'));
  copyAllBtn.appendChild(document.createTextNode(' Copy All'));
  copyAllBtn.addEventListener('click', async function() {
    var text = fields.map(function(f) { return f.label + ': ' + f.value; }).join('\n');
    try {
      await copySecretToClipboard(text);
      copyAllBtn.textContent = 'Copied All!';
      copyAllBtn.classList.add('btn-copied');
      setTimeout(function() {
        copyAllBtn.innerHTML = '';
        copyAllBtn.appendChild(svgIcon('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>', '12'));
        copyAllBtn.appendChild(document.createTextNode(' Copy All'));
        copyAllBtn.classList.remove('btn-copied');
      }, 1500);
    } catch (e) { toast('Copy failed', 'error'); }
  });
  container.appendChild(el('div', { className: 'secret-actions' }, [revealAllBtn, copyAllBtn]));
}

function renderSimpleValue(container, rawVal, credName) {
  container.appendChild(el('div', { className: 'detail-label', text: 'Value', style: 'margin-bottom:6px' }));

  var secretBox = el('div', { className: 'detail-secret blurred', text: '••••••••••••••••' });
  var hint = el('div', { className: 'detail-secret-hint', text: 'Click Reveal to show · Click Copy to copy without revealing' });
  var revealed = false;

  var revealBtn = el('button', { className: 'btn btn-sm' });
  revealBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
  revealBtn.appendChild(document.createTextNode(' Reveal'));
  var copyBtn = makeCopyBtn(function() { return rawVal; });

  revealBtn.addEventListener('click', function() {
    if (!revealed) {
      secretBox.textContent = rawVal;
      secretBox.classList.remove('blurred');
      hint.style.display = 'none';
      revealed = true;
      revealBtn.innerHTML = '';
      revealBtn.appendChild(svgIcon('<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/>', '12'));
      revealBtn.appendChild(document.createTextNode(' Hide'));
    } else {
      secretBox.textContent = '••••••••••••••••';
      secretBox.classList.add('blurred');
      hint.style.display = '';
      revealed = false;
      revealBtn.innerHTML = '';
      revealBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
      revealBtn.appendChild(document.createTextNode(' Reveal'));
    }
  });

  container.appendChild(secretBox);
  container.appendChild(hint);
  container.appendChild(el('div', { className: 'secret-actions' }, [revealBtn, copyBtn]));
}

// Clipboard hygiene: secrets are cleared after 30 s.
// NOTE: this used to ALSO clear on window blur ("app switch"), but that was a
// bug, not a feature — switching windows is the exact action required to
// reach the target app you're pasting INTO, so a blur-triggered clear wiped
// the secret before every single copy-then-paste-elsewhere workflow could
// complete. Password managers (1Password, Bitwarden) clear on a fixed timer
// only, never on blur, for this reason — matched here.
var clipboardClearTimer = null;
var clipboardHoldsSecret = false;

// Native-shell bridge: inside the macOS app, secrets go through NSPasteboard
// tagged org.nspasteboard.ConcealedType so clipboard managers skip them —
// something navigator.clipboard cannot express.
function nativeClipboard() {
  return (window.webkit && window.webkit.messageHandlers) || null;
}

function clearSecretClipboard(reason) {
  if (!clipboardHoldsSecret) return;
  clipboardHoldsSecret = false;
  if (clipboardClearTimer) { clearTimeout(clipboardClearTimer); clipboardClearTimer = null; }
  var native = nativeClipboard();
  if (native && native.clearClipboard) {
    native.clearClipboard.postMessage('');
    toast('Clipboard cleared (' + reason + ')', 'info');
    return;
  }
  // NOTE: browsers may reject clipboard writes while the document is losing
  // focus — only claim success when the write actually landed. The native
  // shell path above has no such restriction.
  navigator.clipboard.writeText('').then(function() {
    toast('Clipboard cleared (' + reason + ')', 'info');
  }).catch(function() {
    clipboardHoldsSecret = true; // clear didn't land; let the timer retry
    if (!clipboardClearTimer) {
      clipboardClearTimer = setTimeout(function() {
        clipboardClearTimer = null;
        clearSecretClipboard('30s');
      }, 5000);
    }
  });
}

function scheduleClearClipboard() {
  clipboardHoldsSecret = true;
  if (clipboardClearTimer) clearTimeout(clipboardClearTimer);
  clipboardClearTimer = setTimeout(function() {
    clipboardClearTimer = null;
    clearSecretClipboard('30s');
  }, 30000);
}

// Central copy path for secret values — always schedules the auto-clear.
// In the native shell the write is concealed from clipboard managers.
async function copySecretToClipboard(value) {
  var native = nativeClipboard();
  if (native && native.copySecret) {
    native.copySecret.postMessage(value);
    scheduleClearClipboard();
    return;
  }
  await navigator.clipboard.writeText(value);
  scheduleClearClipboard();
}

function makeCopyBtn(getVal) {
  var btn = el('button', { className: 'btn btn-sm btn-copy' });
  btn.appendChild(svgIcon('<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>', '12'));
  btn.appendChild(document.createTextNode(' Copy'));
  btn.addEventListener('click', async function() {
    var orig = btn.innerHTML;
    btn.disabled = true;
    try {
      await copySecretToClipboard(getVal());
      btn.innerHTML = '';
      btn.appendChild(svgIcon('<polyline points="20 6 9 17 4 12"/>', '12'));
      btn.appendChild(document.createTextNode(' Copied!'));
      btn.classList.add('btn-copied');
      setTimeout(function() { btn.innerHTML = orig; btn.classList.remove('btn-copied'); btn.disabled = false; }, 1500);
    } catch (e) {
      toast('Copy failed', 'error');
      btn.innerHTML = orig;
      btn.disabled = false;
    }
  });
  return btn;
}

// ─── Delete Confirmation ──────────────────────────────────────────────────
var pendingDeleteResolve = null;

function requestDelete(name) {
  $deleteMsg.textContent = 'Delete "' + name + '"?';
  pendingDeleteResolve = function(confirmed) {
    if (!confirmed) return;
    (async function() {
      try {
        await api('/credentials/' + encodeURIComponent(name), { method: 'DELETE' });
        toast('Deleted ' + name);
        if (detailFromSearch) { returnToSearchResults(); } else { closeDetailPanel(); }
        await loadCredentials();
        loadStats();
      } catch (err) {
        toast('Delete failed: ' + err.message, 'error');
      }
    })();
  };
  openModal($deleteModal);
}

document.getElementById('delete-confirm').addEventListener('click', function() {
  closeModal($deleteModal);
  if (pendingDeleteResolve) pendingDeleteResolve(true);
  pendingDeleteResolve = null;
});
document.getElementById('delete-cancel').addEventListener('click', function() {
  closeModal($deleteModal);
  if (pendingDeleteResolve) pendingDeleteResolve(false);
  pendingDeleteResolve = null;
});
$deleteModal.addEventListener('click', function(e) {
  if (e.target === $deleteModal) {
    closeModal($deleteModal);
    if (pendingDeleteResolve) pendingDeleteResolve(false);
    pendingDeleteResolve = null;
  }
});

// ─── Edit Panel (replaces detail body with editable form) ─────────────────
async function openEditPanel(meta) {
  $panelTitle.textContent = 'Edit: ' + meta.name;
  $panelBody.textContent = '';

  // Fetch current value
  var currentValue = '';
  var isStructured = false;
  var editFields = [];
  try {
    var valData = await api('/credentials/' + encodeURIComponent(meta.name) + '/value');
    currentValue = valData.value || '';
    isStructured = isStructuredValue(currentValue);
    if (isStructured) {
      editFields = JSON.parse(currentValue)._fields.map(function(f) { return { label: f.label, value: f.value }; });
    }
  } catch (_) {}

  var nameField = buildEditField('Name', meta.name, 'text');

  // Value section
  var valueWrap = el('div', { style: 'margin-bottom:10px' });
  var valueLabelEl = el('div', { className: 'detail-label', text: 'Value', style: 'margin-bottom:4px' });
  valueWrap.appendChild(valueLabelEl);

  var simpleValueInput = null;
  var editFieldsList = null;

  if (isStructured) {
    editFieldsList = el('div', { className: 'fields-list' });
    for (var efi = 0; efi < editFields.length; efi++) {
      editFieldsList.appendChild(buildEditFieldRow(editFields[efi], editFields, editFieldsList));
    }
    valueWrap.appendChild(editFieldsList);
    var addFieldBtn = el('button', { type: 'button', className: 'btn btn-sm', style: 'margin-top:6px' });
    addFieldBtn.appendChild(svgIcon('<line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>', '11'));
    addFieldBtn.appendChild(document.createTextNode(' Add Field'));
    addFieldBtn.addEventListener('click', function() {
      var f = { label: '', value: '' };
      editFields.push(f);
      editFieldsList.appendChild(buildEditFieldRow(f, editFields, editFieldsList));
      renderEditSchemaChips();
    });
    valueWrap.appendChild(addFieldBtn);

    // Missing schema columns → one-click add (wallet: derivationPath,
    // accountIndex, xpub…; server: port, sshKey…)
    var editSchemaChips = el('div');
    function renderEditSchemaChips() {
      editSchemaChips.textContent = '';
      var chips = schemaChipRow(meta.category, editFields, function(label) {
        var f = { label: label, value: '' };
        editFields.push(f);
        editFieldsList.appendChild(buildEditFieldRow(f, editFields, editFieldsList));
        renderEditSchemaChips();
      });
      if (chips) editSchemaChips.appendChild(chips);
    }
    renderEditSchemaChips();
    valueWrap.appendChild(editSchemaChips);
  } else {
    simpleValueInput = el('textarea', { className: 'edit-input', rows: 3, style: 'font-family:var(--mono);font-size:12px;resize:vertical;width:100%' });
    simpleValueInput.value = currentValue;
    valueWrap.appendChild(simpleValueInput);
  }

  var descField = buildEditField('Description', meta.description || '', 'text');
  var notesField = buildEditField('Notes', meta.notes || '', 'text');
  var tagsField = buildEditField('Tags', (meta.tags || []).join(', '), 'text');
  var urlField = buildEditField('Source URL', meta.url || '', 'url');
  urlField.input.placeholder = 'https://dash.cloudflare.com/…';

  // Project dropdown
  var projLabel = el('div', { className: 'detail-label', text: 'Project', style: 'margin-bottom:4px' });
  var projSelect = el('select', { className: 'edit-select' });
  for (var i = 0; i < projects.length; i++) {
    var opt = el('option', { value: projects[i].id, text: projects[i].name });
    if (projects[i].id === meta.project) opt.selected = true;
    projSelect.appendChild(opt);
  }

  // Category
  var catField = buildEditField('Category', meta.category || '', 'text');

  // Sensitivity radio pills
  var sensLabel = el('div', { className: 'detail-label', text: 'Sensitivity', style: 'margin-bottom:4px;margin-top:10px' });
  var sensWrap = el('div', { className: 'edit-sens-pills' });
  var sensValue = meta.sensitivity;
  var sensLevels = ['critical', 'high', 'medium', 'low'];

  for (var si = 0; si < sensLevels.length; si++) {
    (function(level) {
      var pill = el('button', {
        className: 'sens-pill pill-' + level + (level === sensValue ? ' active' : ''),
        text: level,
        type: 'button',
      });
      pill.addEventListener('click', function() {
        sensValue = level;
        var allPills = sensWrap.querySelectorAll('.sens-pill');
        for (var j = 0; j < allPills.length; j++) allPills[j].classList.remove('active');
        pill.classList.add('active');
      });
      sensWrap.appendChild(pill);
    })(sensLevels[si]);
  }

  $panelBody.appendChild(nameField.wrap);
  $panelBody.appendChild(valueWrap);
  $panelBody.appendChild(projLabel);
  $panelBody.appendChild(projSelect);
  $panelBody.appendChild(catField.wrap);
  $panelBody.appendChild(descField.wrap);
  $panelBody.appendChild(urlField.wrap);
  $panelBody.appendChild(tagsField.wrap);
  $panelBody.appendChild(notesField.wrap);
  $panelBody.appendChild(sensLabel);
  $panelBody.appendChild(sensWrap);

  // Save / Cancel
  $panelBody.appendChild(el('hr', { className: 'detail-divider' }));

  var saveBtn = el('button', { className: 'btn btn-primary btn-sm', text: 'Save Changes' });
  var cancelBtn = el('button', { className: 'btn btn-sm', text: 'Cancel' });

  cancelBtn.addEventListener('click', function() {
    openDetail(meta.name, meta.sensitivity);
  });

  saveBtn.addEventListener('click', async function() {
    var updates = {};
    var newName = nameField.input.value.trim().toUpperCase();
    if (newName && newName !== meta.name) updates.name = newName;
    if (projSelect.value !== meta.project) updates.project = projSelect.value;
    if (catField.input.value.trim() !== (meta.category || '')) updates.category = catField.input.value.trim();
    if (descField.input.value.trim() !== (meta.description || '')) updates.description = descField.input.value.trim();
    if (notesField.input.value.trim() !== (meta.notes || '')) updates.notes = notesField.input.value.trim();
    if (urlField.input.value.trim() !== (meta.url || '')) updates.url = urlField.input.value.trim();
    if (sensValue !== meta.sensitivity) updates.sensitivity = sensValue;

    var newTags = tagsField.input.value.split(',').map(function(t) { return t.trim(); }).filter(Boolean);
    var oldTags = (meta.tags || []).join(',');
    if (newTags.join(',') !== oldTags) updates.tags = newTags;

    // Value changes
    if (isStructured && editFieldsList) {
      var newFields = editFields.filter(function(f) { return f.label.trim() || f.value.trim(); });
      var newVal = JSON.stringify({ _fields: newFields });
      if (newVal !== currentValue) updates.value = newVal;
    } else if (simpleValueInput) {
      var sv = simpleValueInput.value;
      if (sv !== currentValue) updates.value = sv;
    }

    if (Object.keys(updates).length === 0) {
      toast('No changes to save');
      openDetail(meta.name, meta.sensitivity);
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving…';

    try {
      await api('/credentials/' + encodeURIComponent(meta.name), {
        method: 'PATCH',
        body: JSON.stringify(updates),
      });
      toast('Updated ' + (updates.name || meta.name));
      await loadCredentials();
      loadStats();
      openDetail(updates.name || meta.name, updates.sensitivity || meta.sensitivity);
    } catch (err) {
      toast('Save failed: ' + err.message, 'error');
      saveBtn.disabled = false;
      saveBtn.textContent = 'Save Changes';
    }
  });

  $panelBody.appendChild(el('div', { className: 'detail-actions' }, [saveBtn, cancelBtn]));
}

function buildEditFieldRow(fieldObj, fieldsArr, listContainer) {
  var row = el('div', { className: 'field-row', style: 'display:flex;gap:6px;align-items:center;margin-bottom:6px' });
  var labelInput = el('input', { type: 'text', className: 'edit-input', style: 'width:110px;flex-shrink:0', placeholder: 'Label', value: fieldObj.label });
  var valInput = el('input', { type: 'text', className: 'edit-input', style: 'flex:1', placeholder: 'Value', value: fieldObj.value });
  labelInput.addEventListener('input', function() { fieldObj.label = labelInput.value; });
  valInput.addEventListener('input', function() { fieldObj.value = valInput.value; });
  var rmBtn = el('button', { type: 'button', className: 'btn-icon', style: 'flex-shrink:0;color:var(--danger)', title: 'Remove field' });
  rmBtn.appendChild(svgIcon('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', '12'));
  rmBtn.addEventListener('click', function() {
    var idx = fieldsArr.indexOf(fieldObj);
    if (idx > -1) fieldsArr.splice(idx, 1);
    row.remove();
  });
  row.appendChild(labelInput);
  row.appendChild(valInput);
  row.appendChild(rmBtn);
  return row;
}

function buildEditField(label, value, type) {
  var wrap = el('div', { style: 'margin-bottom:10px' });
  var labelEl = el('div', { className: 'detail-label', text: label, style: 'margin-bottom:4px' });
  var input = el('input', { type: type || 'text', className: 'edit-input', value: value });
  wrap.appendChild(labelEl);
  wrap.appendChild(input);
  return { wrap: wrap, input: input };
}

// ─── Detail Panel ──────────────────────────────────────────────────────────
async function openDetail(name, sensitivity, dOpts) {
  clearTotpTimer(); // stop any ticker from a previously open credential

  // Track whether this panel came from search results (drives the Back
  // affordance). Re-opening the SAME credential (rotate/edit refresh)
  // preserves the origin; navigating to a different one resets it.
  if (dOpts && typeof dOpts.fromSearch === 'boolean') {
    detailFromSearch = dOpts.fromSearch;
  } else if (name !== lastDetailName) {
    detailFromSearch = false;
  }
  lastDetailName = name;
  var $panelBack = document.getElementById('panel-back');
  if ($panelBack) $panelBack.style.display = detailFromSearch ? '' : 'none';

  $panelTitle.textContent = name;
  openDetailPanel(sensitivity || 'low');
  $panelBody.textContent = '';

  // Loading state
  $panelBody.appendChild(el('div', {
    style: 'padding:20px;color:var(--text-muted);font-size:13px;',
    text: 'Loading…',
  }));

  try {
    var meta = await api('/credentials/' + encodeURIComponent(name));
    $panelBody.textContent = '';

    // Ref badge
    var refBadge = el('span', { className: 'badge ref-badge', text: '#' + String(meta.ref || 0).padStart(3, '0') });
    var projB = el('span', { className: 'badge ' + projClass(meta.project), text: meta.project });
    var catB  = el('span', { className: 'badge badge-project', text: meta.category, style: 'background:var(--bg-elevated);color:var(--text-sec);border-color:var(--border)' });
    var sensB = el('span', { className: 'sens-badge ' + meta.sensitivity, text: meta.sensitivity });
    $panelBody.appendChild(el('div', {
      style: 'display:flex;gap:6px;flex-wrap:wrap;margin-bottom:18px;align-items:center;',
    }, [refBadge, projB, catB, sensB]));

    // Sensitivity rules hint
    var ruleText = SENS_RULES[meta.sensitivity] || '';
    if (ruleText) {
      var ruleHint = el('div', { className: 'sens-rule-hint sens-rule-' + meta.sensitivity, text: ruleText });
      $panelBody.appendChild(ruleHint);
    }

    // Fields
    var fields = [
      ['Format',       meta.format || '—'],
      ['Created',      formatDate(meta.created)],
      ['Modified',     formatDate(meta.modified)],
      ['Last Rotated', meta.rotated ? formatDate(meta.rotated) : 'Never'],
    ];
    if (meta.description) fields.unshift(['Description', meta.description]);
    if (meta.notes)       fields.push(['Notes', meta.notes]);

    for (var fi = 0; fi < fields.length; fi++) {
      $panelBody.appendChild(el('div', { className: 'detail-row' }, [
        el('div', { className: 'detail-label', text: fields[fi][0] }),
        el('div', { className: 'detail-value', text: String(fields[fi][1]) }),
      ]));
    }

    // Source URL (render as clickable link when present)
    if (meta.url) {
      var urlLink = el('a', {
        className: 'detail-value detail-url',
        text: meta.url,
        href: meta.url,
        target: '_blank',
        rel: 'noopener noreferrer',
      });
      $panelBody.appendChild(el('div', { className: 'detail-row' }, [
        el('div', { className: 'detail-label', text: 'Source URL' }),
        urlLink,
      ]));
    }

    // Tags
    if (meta.tags && meta.tags.length > 0) {
      var tagRow = el('div', { className: 'tag-list' });
      for (var ti = 0; ti < meta.tags.length; ti++) {
        tagRow.appendChild(el('span', { className: 'tag', text: meta.tags[ti] }));
      }
      $panelBody.appendChild(el('div', { className: 'detail-row' }, [
        el('div', { className: 'detail-label', text: 'Tags' }),
        tagRow,
      ]));
    }

    // Divider
    $panelBody.appendChild(el('hr', { className: 'detail-divider' }));

    // ── Fetch value + render (structured or simple) ──
    try {
      var valData = await api('/credentials/' + encodeURIComponent(name) + '/value');
      var rawVal = valData.value;

      if (looksLikeTotp(meta)) {
        renderTotpValue($panelBody, rawVal);
      } else if (isStructuredValue(rawVal) && meta.category === 'wallet') {
        renderWalletValue($panelBody, JSON.parse(rawVal)._fields);
      } else if (isStructuredValue(rawVal)) {
        renderStructuredValue($panelBody, rawVal, name);
      } else {
        renderSimpleValue($panelBody, rawVal, name);
      }
    } catch (valErr) {
      $panelBody.appendChild(el('div', {
        style: 'color:var(--danger);font-size:12px;padding:8px 0;',
        text: 'Could not decrypt value: ' + valErr.message,
      }));
    }

    // Actions
    $panelBody.appendChild(el('hr', { className: 'detail-divider' }));

    var editBtn = el('button', { className: 'btn btn-sm' });
    editBtn.appendChild(svgIcon('<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>', '12'));
    editBtn.appendChild(document.createTextNode(' Edit'));
    editBtn.addEventListener('click', function() { openEditPanel(meta); });

    // Inline flows (rotate form / history list) render into this container so
    // they appear between the action row and the bottom of the panel.
    var flowBox = el('div', { className: 'detail-flow' });

    var rotateBtn = el('button', { className: 'btn btn-sm rotate-btn', title: 'Replace the value — old value stays in changelog for 7 days' });
    rotateBtn.appendChild(svgIcon('<polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>', '12'));
    rotateBtn.appendChild(document.createTextNode(' Rotate'));
    rotateBtn.addEventListener('click', function() { openRotateFlow(name, flowBox); });

    var historyBtn = el('button', { className: 'btn btn-sm history-btn', title: 'Version trail from the encrypted changelog' });
    historyBtn.appendChild(svgIcon('<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>', '12'));
    historyBtn.appendChild(document.createTextNode(' History'));
    historyBtn.addEventListener('click', function() { toggleHistoryFlow(name, flowBox); });

    var deleteBtn = el('button', { className: 'btn btn-danger btn-sm', text: 'Delete' });
    deleteBtn.addEventListener('click', function() { requestDelete(name); });

    $panelBody.appendChild(el('div', { className: 'detail-actions' }, [editBtn, rotateBtn, historyBtn, deleteBtn]));
    $panelBody.appendChild(flowBox);

  } catch (err) {
    $panelBody.textContent = '';
    $panelBody.appendChild(el('div', { style: 'padding:20px;color:var(--danger)', text: 'Failed to load: ' + err.message }));
  }
}

// ─── Rotate flow (inline in detail panel) ──────────────────────────────────
function openRotateFlow(name, container) {
  container.textContent = '';
  var input = el('textarea', { className: 'rotate-input', rows: '2', placeholder: 'New value for ' + name });

  var genBtn = el('button', { className: 'btn btn-sm', type: 'button', text: 'Generate' });
  genBtn.addEventListener('click', async function() {
    try {
      var g = await api('/generate?length=32');
      input.value = g.value;
      input.focus();
    } catch (err) { toast('Generate failed: ' + err.message, 'error'); }
  });

  var confirmBtn = el('button', { className: 'btn btn-primary btn-sm', type: 'button', text: 'Rotate' });
  confirmBtn.addEventListener('click', async function() {
    var v = input.value.trim();
    if (!v) { toast('Enter or generate a new value first', 'error'); return; }
    confirmBtn.disabled = true;
    try {
      await api('/credentials/' + encodeURIComponent(name) + '/rotate', {
        method: 'POST', body: JSON.stringify({ value: v }),
      });
      toast('Rotated ' + name + ' — old value recoverable for 7 days');
      openDetail(name);          // refresh panel with new state
      loadCredentials();
    } catch (err) {
      confirmBtn.disabled = false;
      toast('Rotate failed: ' + err.message, 'error');
    }
  });

  var cancelBtn = el('button', { className: 'btn btn-sm', type: 'button', text: 'Cancel' });
  cancelBtn.addEventListener('click', function() { container.textContent = ''; });

  container.appendChild(el('div', { className: 'rotate-flow' }, [
    el('div', { className: 'detail-label', text: 'Rotate — old value stays undoable for 7 days' }),
    input,
    el('div', { className: 'rotate-actions' }, [genBtn, confirmBtn, cancelBtn]),
  ]));
  input.focus();
}

// ─── History flow (inline in detail panel) ─────────────────────────────────
async function toggleHistoryFlow(name, container) {
  // Toggle off if already showing history
  if (container.querySelector('.history-flow')) { container.textContent = ''; return; }
  container.textContent = '';
  container.appendChild(el('div', { className: 'history-flow', text: 'Loading history…' }));
  try {
    var rows = await api('/credentials/' + encodeURIComponent(name) + '/history');
    container.textContent = '';
    var box = el('div', { className: 'history-flow' });
    box.appendChild(el('div', { className: 'detail-label', text: 'History (changelog retains 7 days)' }));
    if (!rows.length) {
      box.appendChild(el('div', { className: 'history-empty', text: 'No recorded changes in the last 7 days.' }));
    }
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      box.appendChild(el('div', { className: 'history-row' }, [
        el('span', { className: 'history-action history-' + r.action, text: r.action }),
        el('span', { className: 'history-ts', text: formatDate(r.timestamp) }),
        el('span', { className: 'history-actor', text: r.actor || '' }),
      ]));
    }
    box.appendChild(el('div', {
      className: 'history-hint',
      text: rows.length ? 'Restore a point via History → Changelog (undo), or CLI: credmgr undo <id>' : '',
    }));
    container.appendChild(box);
  } catch (err) {
    container.textContent = '';
    toast('History failed: ' + err.message, 'error');
  }
}

// Close (X), Back, backdrop click, and Esc all return to the search results
// when the panel was opened from search, so picking the next candidate from
// a search never means retyping the query. Backdrop click used to bypass
// this and close everything outright — clicking outside the panel is the
// same "never mind, not this one" gesture as X, so it must behave the same.
document.getElementById('panel-close').addEventListener('click', function() {
  if (detailFromSearch) returnToSearchResults(); else closeDetailPanel();
});
document.getElementById('panel-back').addEventListener('click', returnToSearchResults);
$detailBackdrop.addEventListener('click', function() {
  if (detailFromSearch) returnToSearchResults(); else closeDetailPanel();
});

// ─── Add Modal ─────────────────────────────────────────────────────────────
document.getElementById('add-btn').addEventListener('click', function() {
  setAddType('simple');
  document.getElementById('add-strength').style.display = 'none';
  openModal($addModal);
  setTimeout(function() { document.getElementById('add-name').focus(); }, 50);
});
document.getElementById('add-cancel').addEventListener('click', function() { closeModal($addModal); });
document.getElementById('add-modal-close').addEventListener('click', function() { closeModal($addModal); });

// Close modal on backdrop click
$addModal.addEventListener('click', function(e) {
  if (e.target === $addModal) closeModal($addModal);
});
$changelogModal.addEventListener('click', function(e) {
  if (e.target === $changelogModal) closeModal($changelogModal);
});

// ─── Type Preset Switching ────────────────────────────────────────────────
var typeBtns = document.querySelectorAll('.type-btn');
for (var ti = 0; ti < typeBtns.length; ti++) {
  (function(btn) {
    btn.addEventListener('click', function() { setAddType(btn.getAttribute('data-type')); });
  })(typeBtns[ti]);
}

function setAddType(type) {
  currentAddType = type;
  for (var i = 0; i < typeBtns.length; i++) {
    typeBtns[i].classList.toggle('active', typeBtns[i].getAttribute('data-type') === type);
  }
  if (type === 'simple') {
    $simpleSection.style.display = '';
    $fieldsSection.style.display = 'none';
  } else {
    $simpleSection.style.display = 'none';
    $fieldsSection.style.display = '';
    if (PRESETS[type]) {
      addFields = PRESETS[type].map(function(f) { return { label: f.label, value: '' }; });
    } else {
      addFields = [{ label: '', value: '' }];
    }
    renderAddFields();
  }
}

// ─── Schema column chips ───────────────────────────────────────────────────
// One-click "+ column" buttons for every canonical field the item type
// defines but the form doesn't have yet (wallet → derivationPath,
// accountIndex, xpub…). Powered by GET /api/schemas.
function schemaChipRow(schemaKey, fieldsArr, onAdd) {
  var schema = typeSchemas[schemaKey];
  if (!schema || !schema.fields) return null;
  var have = {};
  fieldsArr.forEach(function(f) {
    if (f && f.label) have[String(f.label).replace(/_\d+$/, '').toLowerCase()] = true;
  });
  var remaining = schema.fields.filter(function(l) { return !have[l.toLowerCase()]; });
  if (!remaining.length) return null;
  var row = el('div', { className: 'schema-chip-row' }, [
    el('span', { className: 'schema-chip-label', text: 'Add column:' }),
  ]);
  remaining.forEach(function(label) {
    var chip = el('button', { type: 'button', className: 'schema-chip', text: '+ ' + label });
    chip.addEventListener('click', function() { onAdd(label); });
    row.appendChild(chip);
  });
  return row;
}

var $addSchemaChips = el('div');
$fieldsList.parentNode.insertBefore($addSchemaChips, $fieldsList.nextSibling);

function renderAddFields() {
  $fieldsList.textContent = '';
  for (var i = 0; i < addFields.length; i++) {
    $fieldsList.appendChild(buildFieldRow(i));
  }
  // Offer the type's remaining canonical columns as one-click chips
  $addSchemaChips.textContent = '';
  var schemaKey = PRESET_SCHEMA_KEY[currentAddType];
  if (schemaKey) {
    var chips = schemaChipRow(schemaKey, addFields, function(label) {
      addFields.push({ label: label, value: '' });
      renderAddFields();
    });
    if (chips) $addSchemaChips.appendChild(chips);
  }
}

function buildFieldRow(idx) {
  var field = addFields[idx];

  var labelInput = el('input', {
    className: 'field-label-input',
    value: field.label,
    placeholder: 'Field name',
  });
  labelInput.addEventListener('input', function() { addFields[idx].label = this.value; });

  var valueInput = el('input', {
    className: 'field-value-input',
    type: 'text',
    value: field.value,
    placeholder: 'Value',
  });
  valueInput.addEventListener('input', function() { addFields[idx].value = this.value; });

  var removeBtn = el('button', { className: 'field-remove', type: 'button' });
  removeBtn.appendChild(svgIcon('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', '12'));
  removeBtn.addEventListener('click', function() {
    addFields.splice(idx, 1);
    if (addFields.length === 0) addFields.push({ label: '', value: '' });
    renderAddFields();
  });

  return el('div', { className: 'field-row' }, [labelInput, valueInput, removeBtn]);
}

document.getElementById('add-field-btn').addEventListener('click', function() {
  addFields.push({ label: '', value: '' });
  renderAddFields();
  // Focus the new label input
  var inputs = $fieldsList.querySelectorAll('.field-label-input');
  if (inputs.length > 0) inputs[inputs.length - 1].focus();
});

// Value visibility toggle (simple mode)
var $textarea   = document.getElementById('add-value');
var $eyeIcon    = document.getElementById('eye-icon');
var valueHidden = false;

document.getElementById('value-toggle').addEventListener('click', function() {
  valueHidden = !valueHidden;
  if (valueHidden) {
    $textarea.style.webkitTextSecurity = 'disc';
    $textarea.style.color = 'transparent';
    $textarea.style.textShadow = '0 0 8px var(--text)';
    $eyeIcon.innerHTML = '<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/><line x1="1" y1="1" x2="23" y2="23"/>';
  } else {
    $textarea.style.webkitTextSecurity = '';
    $textarea.style.color = '';
    $textarea.style.textShadow = '';
    $eyeIcon.innerHTML = '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>';
  }
});

// ─── Form Submit ──────────────────────────────────────────────────────────
document.getElementById('add-form').addEventListener('submit', async function(e) {
  e.preventDefault();

  // Build value based on type
  var value;
  if (currentAddType === 'simple') {
    value = document.getElementById('add-value').value;
    if (!value) { toast('Value is required', 'error'); return; }
  } else {
    // Collect fields — filter out empty rows
    var fieldData = addFields.filter(function(f) { return f.label.trim() && f.value.trim(); });
    if (fieldData.length === 0) { toast('At least one field must have a label and value', 'error'); return; }
    value = JSON.stringify({ _fields: fieldData.map(function(f) { return { label: f.label.trim(), value: f.value }; }) });
  }

  var body = {
    name:        document.getElementById('add-name').value.trim().toUpperCase(),
    value:       value,
    project:     document.getElementById('add-project').value,
    category:    document.getElementById('add-category').value.trim() || undefined,
    description: document.getElementById('add-description').value.trim() || undefined,
    tags:        document.getElementById('add-tags').value.split(',')
                   .map(function(t) { return t.trim(); }).filter(Boolean),
  };

  if (!body.name) { toast('Name is required', 'error'); return; }

  var btn = e.target.querySelector('[type="submit"]');
  btn.disabled = true;
  btn.textContent = 'Saving…';

  try {
    await api('/credentials', { method: 'POST', body: JSON.stringify(body) });
    toast('Added ' + body.name);
    closeModal($addModal);
    document.getElementById('add-form').reset();
    document.getElementById('add-strength').style.display = 'none';
    addFields = [];
    currentAddType = 'simple';
    await loadCredentials();
    loadStats();
  } catch (err) {
    toast('Add failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Save Credential';
  }
});

// ─── Changelog ─────────────────────────────────────────────────────────────
async function loadChangelog() {
  var changes = await api('/changelog');
  $changelogBody.textContent = '';
  if (changes.length === 0) {
    $changelogBody.appendChild(el('div', { className: 'empty-state', text: 'No changes in the last 7 days.' }));
  } else {
    for (var i = 0; i < changes.length; i++) {
      $changelogBody.appendChild(renderChangeItem(changes[i]));
    }
  }
  return changes.length;
}

document.getElementById('changelog-btn').addEventListener('click', async function() {
  try {
    await loadChangelog();
    openModal($changelogModal);
  } catch (err) {
    toast('Failed to load changelog: ' + err.message, 'error');
  }
});

// Empty the recovery archive NOW — no 7-day wait. Irreversible, so it goes
// through the native-safe confirm modal (window.confirm is dead in the shell).
document.getElementById('changelog-purge').addEventListener('click', async function() {
  var ok = await appConfirm(
    'Permanently delete EVERY archived change now?\n\n' +
    'Deleted credentials and old values in the archive can no longer be restored. ' +
    'This cannot be reversed.',
    { title: 'Empty archive', okLabel: 'Delete everything', danger: true }
  );
  if (!ok) return;
  try {
    var r = await api('/changelog/purge', { method: 'POST', body: JSON.stringify({}) });
    toast('Archive emptied — ' + r.purged + ' entr' + (r.purged === 1 ? 'y' : 'ies') + ' permanently deleted');
    await loadChangelog();
  } catch (err) {
    toast('Purge failed: ' + err.message, 'error');
  }
});

function renderChangeItem(c) {
  var actionKey = c.action.startsWith('undo') ? 'undo' : c.action;
  var badge = el('span', { className: 'change-action-badge badge-' + actionKey, text: c.action });

  var nameNode = el('div', { className: 'change-name', text: c.credentialName });
  var metaNode = el('div', { className: 'change-meta', text: formatDate(c.timestamp) + ' · ' + (c.actor || 'cli') });
  var idNode   = el('div', { className: 'change-id',   text: 'ID: ' + c.changeId });

  var actionsRow = el('div', { className: 'change-actions', style: 'display:flex;gap:6px;margin-top:8px;flex-wrap:wrap' });

  var canUndo = c.action === 'modify' || c.action === 'rotate' || c.action === 'delete' || c.action === 'metadata-update';
  var canKeepBoth = c.action === 'modify' || c.action === 'rotate';

  if (canUndo) {
    var undoBtn = el('button', { className: 'btn btn-sm', text: 'Undo (replace)' });
    undoBtn.addEventListener('click', async function() {
      try {
        var result = await api('/changelog/' + encodeURIComponent(c.changeId) + '/undo', {
          method: 'POST',
          body: JSON.stringify({ mode: 'replace' }),
        });
        toast(result.message, result.success ? 'success' : 'error');
        await loadCredentials();
        loadStats();
      } catch (err) {
        toast('Undo failed: ' + err.message, 'error');
      }
    });
    actionsRow.appendChild(undoBtn);
  }

  if (canKeepBoth) {
    var keepBothBtn = el('button', {
      className: 'btn btn-sm',
      text: 'Keep both',
      title: 'Restore previous value as a NEW credential named "' + c.credentialName + ' old", keep current intact',
    });
    keepBothBtn.addEventListener('click', async function() {
      var ok = await appConfirm(
        'Restore the previous value as a new credential named "' + c.credentialName + ' old"?\n\n' +
        'The current "' + c.credentialName + '" will stay unchanged.',
        { title: 'Keep both', okLabel: 'Restore as copy' }
      );
      if (!ok) return;
      try {
        var result = await api('/changelog/' + encodeURIComponent(c.changeId) + '/undo', {
          method: 'POST',
          body: JSON.stringify({ mode: 'keep-both' }),
        });
        toast(result.message, result.success ? 'success' : 'error');
        await loadCredentials();
        loadStats();
      } catch (err) {
        toast('Keep-both failed: ' + err.message, 'error');
      }
    });
    actionsRow.appendChild(keepBothBtn);
  }

  // Permanent-delete button — removes this changelog entry from disk so the
  // change can never be undone. Confirm twice because it's irreversible.
  var deleteBtn = el('button', {
    className: 'btn btn-sm btn-danger',
    text: 'Delete',
    title: 'Permanently delete this history entry. This cannot be reversed.',
  });
  deleteBtn.addEventListener('click', async function() {
    var ok = await appConfirm(
      'Permanently delete this history entry?\n\n' +
      'Action: ' + c.action + '\n' +
      'Credential: ' + c.credentialName + '\n\n' +
      'After deletion, this change can no longer be undone. This cannot be reversed.',
      { title: 'Delete archive entry', okLabel: 'Delete permanently', danger: true }
    );
    if (!ok) return;
    try {
      var result = await api('/changelog/' + encodeURIComponent(c.changeId), { method: 'DELETE' });
      toast(result.message || 'Entry deleted', result.success ? 'success' : 'error');
      await loadChangelog(); // refresh the modal in place
    } catch (err) {
      toast('Delete failed: ' + err.message, 'error');
    }
  });
  actionsRow.appendChild(deleteBtn);

  // For 'add' actions, show why undo is disabled
  if (c.action === 'add') {
    var addNote = el('div', {
      className: 'change-note',
      text: 'Adds are permanent. Use the credential\'s Delete button to remove it.',
      style: 'font-size:11px;color:var(--text-muted);margin-top:6px;font-style:italic',
    });
    var info = el('div', { className: 'change-info' }, [nameNode, metaNode, idNode, addNote, actionsRow]);
    return el('div', { className: 'change-item' }, [badge, info]);
  }

  var info = el('div', { className: 'change-info' }, [nameNode, metaNode, idNode, actionsRow]);
  return el('div', { className: 'change-item' }, [badge, info]);
}

document.getElementById('changelog-close').addEventListener('click', function() { closeModal($changelogModal); });

// ─── Verify ────────────────────────────────────────────────────────────────
document.getElementById('verify-btn').addEventListener('click', async function() {
  var btn = this;
  btn.textContent = 'Verifying…';
  try {
    var result = await api('/verify');
    if (result.ok) {
      toast('Vault integrity OK — ' + result.credentialCount + ' credentials verified');
    } else {
      toast('Integrity errors: ' + result.errors.join('; '), 'error');
    }
  } catch (err) {
    toast('Verify failed: ' + err.message, 'error');
  } finally {
    btn.textContent = 'Verify';
  }
});

// ─── Expiring Banner ──────────────────────────────────────────────────────
// ─── Health & Automation Hub ────────────────────────────────────────────────
// The hero of the redesign: pulls integrity, doctor-fixable issues, dedupe
// suggestions, expiring credentials, and recent activity into one glance so
// the vault feels like it's watching itself. Re-run after anything that
// could change these signals (doctor fix, merge, delete, rotate).
var $hubRing      = document.getElementById('hub-ring');
var $hubRingIcon  = document.getElementById('hub-ring-icon');
var $hubRingArc   = document.getElementById('hub-ring-arc');
var $hubTitle     = document.getElementById('hub-status-title');
var $hubSub       = document.getElementById('hub-status-sub');
var $hubRows      = document.getElementById('hub-rows');
var $hubActivity  = document.getElementById('hub-activity-list');
var HUB_RING_CIRCUMFERENCE = 150.8; // 2π × r(24), matches the SVG in index.html

var ICON_CHECK   = '<polyline points="20 6 9 17 4 12"/>';
var ICON_ALERT   = '<path d="M12 9v4M12 17h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"/>';
var ICON_MERGE   = '<path d="M9 18h6M10 22h4M12 2v2M12 6a6 6 0 0 1 6 6c0 2.5-1.5 4.5-3 5.5H9C7.5 18.5 6 16.5 6 12a6 6 0 0 1 6-6Z"/>';

async function refreshHub() {
  // ── Status ring: integrity + checksum ──
  var okEncryption = false, okChecksum = false, total = null;
  try {
    var v = await api('/verify');
    okEncryption = v.ok !== false;
    okChecksum = v.checksum === 'ok' || v.ok === true;
    total = v.credentialCount != null ? v.credentialCount : null;
  } catch (e) { okEncryption = false; }
  if (total == null) { try { total = (await api('/stats')).total; } catch (e2) {} }

  var healthy = okEncryption && okChecksum;
  $hubRing.className = 'hub-ring' + (healthy ? '' : ' err');
  $hubRingArc.style.strokeDashoffset = healthy ? '6' : String(HUB_RING_CIRCUMFERENCE * 0.4);
  $hubRingIcon.textContent = '';
  $hubRingIcon.appendChild(svgIcon(healthy ? ICON_CHECK : ICON_ALERT, '20'));
  $hubTitle.textContent = healthy ? 'Your vault is encrypted and verified' : 'Vault needs attention';
  $hubSub.textContent = (total != null ? total + ' secrets' : 'Vault') +
    (projects.length ? ' across ' + projects.length + ' projects' : '') +
    (healthy ? ' · checksum verified just now' : ' · run Doctor to diagnose');

  // ── Rows: doctor, suggestions, expiring — built in priority order ──
  $hubRows.textContent = '';
  var anyRow = false;

  try {
    var diag = await api('/doctor', { method: 'POST', body: JSON.stringify({ fix: false }) });
    var fixCount = diag.heal ? diag.heal.fixCount : 0;
    if (fixCount > 0) {
      anyRow = true;
      var detail = (diag.heal.fixes || []).slice(0, 3).map(function(f) { return f.type; }).join(', ');
      var row = el('div', { className: 'hub-row tone-warning' }, [
        svgIcon(ICON_ALERT, '16'),
        el('div', { className: 'hub-row-text' }, [el('strong', { text: fixCount + ' issue' + (fixCount === 1 ? '' : 's') + ' found' }), ' — ' + (detail || 'store inconsistencies')]),
      ]);
      var fixBtn = el('button', { className: 'hub-row-btn primary', text: 'Fix all' });
      fixBtn.addEventListener('click', async function() {
        fixBtn.disabled = true; fixBtn.textContent = 'Fixing…';
        try {
          await api('/doctor', { method: 'POST', body: JSON.stringify({ fix: true }) });
          toast('Doctor applied ' + fixCount + ' fix(es)');
          await loadCredentials();
          refreshHub();
        } catch (err) { toast('Doctor failed: ' + err.message, 'error'); fixBtn.disabled = false; fixBtn.textContent = 'Fix all'; }
      });
      row.appendChild(el('div', { className: 'hub-row-actions' }, [fixBtn]));
      $hubRows.appendChild(row);
    }
  } catch (e) { /* doctor is non-critical for the hub */ }

  if (activeSuggestions.length > 0) {
    anyRow = true;
    var dupeCount = activeSuggestions.filter(function(s) { return s.type === 'exact-duplicate'; }).length;
    var mergeCount = activeSuggestions.filter(function(s) { return s.type === 'merge-candidates'; }).length;
    var parts = [];
    if (dupeCount) parts.push(dupeCount + ' exact duplicate' + (dupeCount > 1 ? 's' : ''));
    if (mergeCount) parts.push(mergeCount + ' credential' + (mergeCount > 1 ? 's' : '') + ' look' + (mergeCount === 1 ? 's' : '') + ' like one service');
    var sRow = el('div', { className: 'hub-row tone-neutral' }, [
      svgIcon(ICON_MERGE, '16'),
      el('div', { className: 'hub-row-text', text: parts.join(' · ') }),
    ]);
    var autoAllBtn = el('button', { className: 'hub-row-btn primary', text: 'Auto-merge safe', title: 'Merge every unambiguous group in one go' });
    autoAllBtn.addEventListener('click', function() { clickById('suggestions-auto-all'); });
    var reviewBtn = el('button', { className: 'hub-row-btn outline', text: 'Review' });
    reviewBtn.addEventListener('click', function() { renderSuggestionCards(); openModal($suggestionsModal); });
    var dismissBtn = el('button', { className: 'hub-row-btn ghost', text: 'Dismiss' });
    dismissBtn.addEventListener('click', async function() {
      dismissBtn.disabled = true;
      await Promise.all(activeSuggestions.map(function(s) { return dismissSuggestionPersist(s); }));
      activeSuggestions = [];
      refreshHub();
    });
    sRow.appendChild(el('div', { className: 'hub-row-actions' }, [autoAllBtn, reviewBtn, dismissBtn]));
    $hubRows.appendChild(sRow);
  }

  try {
    var expiring = await api('/expiring?days=14');
    if (expiring && expiring.length > 0) {
      anyRow = true;
      var chipsRow = el('div', { className: 'hub-expiry-row' });
      expiring.slice(0, 4).forEach(function(item) {
        var cls = item.expired ? 'expired' : 'soon';
        var label = item.expired ? 'expired' : ('expires in ' + item.daysLeft + 'd');
        var chip = el('span', { className: 'hub-expiry-chip ' + cls }, [
          el('strong', { text: item.name }), ' ' + label,
        ]);
        var rotateBtn = el('button', { text: 'Rotate' });
        rotateBtn.addEventListener('click', function() { openDetail(item.name, item.sensitivity); });
        chip.appendChild(rotateBtn);
        chipsRow.appendChild(chip);
      });
      if (expiring.length > 4) chipsRow.appendChild(el('span', { className: 'hub-row-text', text: '+' + (expiring.length - 4) + ' more' }));
      $hubRows.appendChild(chipsRow);
    }
  } catch (e) { /* expiring is non-critical for the hub */ }

  if (!anyRow) {
    $hubRows.appendChild(el('div', { className: 'hub-row tone-clean' }, [svgIcon(ICON_CHECK, '16'), el('div', { className: 'hub-row-text', text: 'No issues, duplicates, or expiring credentials — nothing to do here.' })]));
  }

  // ── Recent activity glance (top 4) ──
  $hubActivity.textContent = '';
  try {
    var logs = await api('/access-log?limit=4');
    if (!logs || logs.length === 0) {
      $hubActivity.appendChild(el('div', { className: 'hub-activity-empty', text: 'No activity yet' }));
    } else {
      logs.forEach(function(entry) {
        var cred = allCredentials.find(function(c) { return c.name === entry.name; });
        var sens = cred ? cred.sensitivity : 'low';
        var item = el('div', { className: 'hub-activity-item' }, [
          el('span', { className: 'hub-activity-dot', style: 'background:' + sensColor(sens) }),
          el('span', { className: 'hub-activity-name', text: entry.name }),
          el('span', { className: 'hub-activity-time', text: timeAgo(new Date(entry.ts || entry.timestamp).getTime()) }),
        ]);
        item.addEventListener('click', function() { openDetail(entry.name, sens); });
        $hubActivity.appendChild(item);
      });
    }
  } catch (e) {
    $hubActivity.appendChild(el('div', { className: 'hub-activity-empty', text: 'Failed to load activity' }));
  }
}

document.getElementById('hub-view-log-btn').addEventListener('click', function() { clickById('access-log-btn'); });

// Keep the hub fresh without needing a manual refresh — cheap, all-local calls.
setInterval(refreshHub, 60000);

// ─── Audit Modal ──────────────────────────────────────────────────────────
var $auditModal = document.getElementById('audit-modal');
var $auditBody = document.getElementById('audit-body');

document.getElementById('audit-btn').addEventListener('click', async function() {
  $auditBody.textContent = 'Running audit…';
  openModal($auditModal);
  try {
    var result = await api('/audit');
    $auditBody.textContent = '';

    var summary = el('div', { className: 'audit-summary' }, [
      el('div', { className: 'audit-stat' }, [
        el('span', { className: 'audit-stat-val', text: String(result.total) }),
        el('span', { className: 'audit-stat-label', text: 'credentials' }),
      ]),
      el('div', { className: 'audit-stat' }, [
        el('span', { className: 'audit-stat-val ' + (result.issueCount > 0 ? 'audit-warn' : 'audit-ok'), text: String(result.issueCount) }),
        el('span', { className: 'audit-stat-label', text: 'issues found' }),
      ]),
    ]);
    $auditBody.appendChild(summary);

    if (result.issues.length === 0) {
      $auditBody.appendChild(el('div', { className: 'audit-clean', text: 'All credentials passed health checks.' }));
      return;
    }

    // Group by type
    var groups = {};
    for (var i = 0; i < result.issues.length; i++) {
      var issue = result.issues[i];
      if (!groups[issue.type]) groups[issue.type] = { severity: issue.severity, items: [] };
      groups[issue.type].items.push(issue);
    }

    for (var type in groups) {
      if (!groups.hasOwnProperty(type)) continue;
      var group = groups[type];
      var header = el('div', { className: 'audit-group-header' }, [
        el('span', { className: 'audit-sev audit-sev-' + group.severity, text: group.severity.toUpperCase() }),
        el('span', { text: type.replace(/-/g, ' ') + ' (' + group.items.length + ')' }),
      ]);
      $auditBody.appendChild(header);

      for (var j = 0; j < Math.min(group.items.length, 15); j++) {
        var row = el('div', { className: 'audit-row' }, [
          el('span', { className: 'audit-row-name', text: group.items[j].name }),
          el('span', { className: 'audit-row-msg', text: group.items[j].message }),
        ]);
        $auditBody.appendChild(row);
      }
      if (group.items.length > 15) {
        $auditBody.appendChild(el('div', { className: 'audit-row audit-more', text: '… and ' + (group.items.length - 15) + ' more' }));
      }
    }
  } catch (err) {
    $auditBody.textContent = 'Audit failed: ' + err.message;
  }
});

document.getElementById('audit-close').addEventListener('click', function() { closeModal($auditModal); });

// ─── Access Log Modal ─────────────────────────────────────────────────────
var $accessLogModal = document.getElementById('access-log-modal');
var $accessLogBody = document.getElementById('access-log-body');

document.getElementById('access-log-btn').addEventListener('click', async function() {
  $accessLogBody.textContent = 'Loading…';
  openModal($accessLogModal);
  try {
    var log = await api('/access-log?limit=100');
    $accessLogBody.textContent = '';

    if (log.length === 0) {
      $accessLogBody.appendChild(el('div', { className: 'audit-clean', text: 'No access records yet. Credentials will be logged when accessed via CLI, API, or dashboard.' }));
      return;
    }

    var header = el('div', { className: 'access-log-header' }, [
      el('span', { className: 'al-col al-col-ts', text: 'Time' }),
      el('span', { className: 'al-col al-col-src', text: 'Source' }),
      el('span', { className: 'al-col al-col-name', text: 'Credential' }),
    ]);
    $accessLogBody.appendChild(header);

    for (var i = 0; i < log.length; i++) {
      var entry = log[i];
      var ts = entry.ts ? entry.ts.slice(0, 19).replace('T', ' ') : '—';
      var srcClass = 'al-src-' + (entry.source || 'cli');
      var row = el('div', { className: 'access-log-row' }, [
        el('span', { className: 'al-col al-col-ts', text: ts }),
        el('span', { className: 'al-col al-col-src ' + srcClass, text: entry.source || 'cli' }),
        el('span', { className: 'al-col al-col-name', text: entry.name }),
      ]);
      $accessLogBody.appendChild(row);
    }
  } catch (err) {
    $accessLogBody.textContent = 'Failed to load access log: ' + err.message;
  }
});

document.getElementById('access-log-close').addEventListener('click', function() { closeModal($accessLogModal); });

// ─── Merge Mode ───────────────────────────────────────────────────────────
var $mergeBtn        = document.getElementById('merge-btn');
var $mergeProceedBtn = document.getElementById('merge-proceed-btn');
var $mergeProceedCnt = document.getElementById('merge-proceed-count');
var $mergeModal      = document.getElementById('merge-modal');
var $mergeLeftList   = document.getElementById('merge-left-list');
var $mergeFieldsList = document.getElementById('merge-fields-list');
var $mergeCount      = document.getElementById('merge-count');

function toggleMergeMode() {
  mergeMode = !mergeMode;
  mergeSelected = {};
  $mergeBtn.classList.toggle('btn-active', mergeMode);
  $mergeBtn.innerHTML = '';
  if (mergeMode) {
    $mergeBtn.appendChild(svgIcon('<line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>', '13'));
    $mergeBtn.appendChild(document.createTextNode(' Cancel'));
  } else {
    $mergeBtn.appendChild(svgIcon('<path d="M8 6L21 6"/><path d="M8 12L21 12"/><path d="M8 18L21 18"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>', '13'));
    $mergeBtn.appendChild(document.createTextNode(' Merge'));
    $mergeProceedBtn.style.display = 'none';
  }
  loadCredentials();
  updateMergeCount();
}

function updateMergeCount() {
  var count = Object.keys(mergeSelected).length;
  $mergeCount.textContent = count;
  if (mergeMode && count >= 2) {
    $mergeProceedCnt.textContent = count;
    $mergeProceedBtn.style.display = '';
  } else {
    $mergeProceedBtn.style.display = 'none';
  }
}

$mergeBtn.addEventListener('click', function() {
  toggleMergeMode();
});

$mergeProceedBtn.addEventListener('click', function() {
  openMergeModal();
});

async function openMergeModal() {
  var names = Object.keys(mergeSelected);

  // Populate left panel — fetch values for each
  $mergeLeftList.textContent = '';
  mergeFields = [];
  $mergeFieldsList.textContent = '';

  openModal($mergeModal);

  for (var i = 0; i < names.length; i++) {
    var name = names[i];
    var card = el('div', { className: 'merge-source-card' });
    var cardHeader = el('div', { className: 'merge-source-header' }, [
      el('span', { className: 'merge-source-name', text: name }),
      makeCopyBtn(function(n) { return function() { return n; }; }(name)),
    ]);
    card.appendChild(cardHeader);

    try {
      var data = await api('/credentials/' + encodeURIComponent(name) + '/value');
      var val = data.value;

      if (isStructuredValue(val)) {
        var parsed = JSON.parse(val);
        var fields = parsed._fields;
        for (var fi = 0; fi < fields.length; fi++) {
          var frow = renderMergeSourceField(fields[fi].label, fields[fi].value);
          card.appendChild(frow);
          addMergeFieldUnique(fields[fi].label, fields[fi].value);
        }
      } else {
        // Simple value — show as single field, label = last part of name
        var parts = name.split(/[\s_\-./]+/).filter(Boolean);
        var label = parts.length > 1 ? parts.slice(-1)[0] : 'Value';
        label = label.charAt(0).toUpperCase() + label.slice(1).toLowerCase();
        var frow = renderMergeSourceField(label, val);
        card.appendChild(frow);
        // Pre-populate the merged credential's fields so nothing has to be
        // copy-pasted by hand — the user just reviews/renames labels.
        addMergeFieldUnique(label, val);
      }
    } catch (err) {
      card.appendChild(el('div', { className: 'merge-source-err', text: 'Could not decrypt: ' + err.message }));
    }

    $mergeLeftList.appendChild(card);
  }

  // Pre-populate right panel — suggest name from common prefix
  var prefix = findCommonPrefix(names);
  document.getElementById('merge-name').value = prefix || '';

  // Pre-populate project/category from first source
  var firstMeta = allCredentials.find(function(c) { return c.name === names[0]; });
  if (firstMeta) {
    document.getElementById('merge-project').value = firstMeta.project || 'global';
    document.getElementById('merge-category').value = firstMeta.category || '';
  }

  // Populate project dropdown
  var $mp = document.getElementById('merge-project');
  $mp.textContent = '';
  for (var pi = 0; pi < projects.length; pi++) {
    $mp.appendChild(el('option', { value: projects[pi].id, text: projects[pi].name }));
  }
  if (firstMeta) $mp.value = firstMeta.project;

  // Populate ref picker from source credentials
  var $mergeRef = document.getElementById('merge-ref');
  var $mergeRefOpts = document.getElementById('merge-ref-options');
  var $mergeRefError = document.getElementById('merge-ref-error');
  $mergeRefOpts.textContent = '';
  $mergeRef.value = '';
  $mergeRef.classList.remove('ref-error');
  $mergeRefError.style.display = 'none';

  // Find the "best" default ref — prefer the source with a USERNAME-type suffix
  var bestRef = '';
  var usernameSuffixes = ['USER', 'USERNAME', 'LOGIN', 'EMAIL', 'ACCOUNT'];
  for (var ri = 0; ri < names.length; ri++) {
    var srcMeta = allCredentials.find(function(c) { return c.name === names[ri]; });
    if (srcMeta && srcMeta.ref) {
      var refStr = String(srcMeta.ref);
      // Create a clickable option for each source ref
      (function(ref, cname) {
        var optBtn = el('button', { type: 'button', className: 'merge-ref-opt', text: '#' + refStr + ' (' + cname + ')' });
        optBtn.addEventListener('click', function() {
          $mergeRef.value = ref;
          $mergeRef.classList.remove('ref-error');
          $mergeRefError.style.display = 'none';
          // highlight active
          var allOpts = $mergeRefOpts.querySelectorAll('.merge-ref-opt');
          for (var x = 0; x < allOpts.length; x++) allOpts[x].classList.remove('active');
          optBtn.classList.add('active');
        });
        $mergeRefOpts.appendChild(optBtn);
      })(srcMeta.ref, names[ri]);

      // Default: first one with a username-ish suffix
      if (!bestRef) {
        var lastPart = names[ri].split('_').pop().toUpperCase();
        if (usernameSuffixes.indexOf(lastPart) !== -1) bestRef = refStr;
      }
    }
  }
  // If no username-type found, use first source ref
  if (!bestRef && names.length > 0) {
    var firstSrc = allCredentials.find(function(c) { return c.name === names[0]; });
    if (firstSrc && firstSrc.ref) bestRef = String(firstSrc.ref);
  }
  if (bestRef) {
    $mergeRef.value = bestRef;
    // highlight the matching option
    var opts = $mergeRefOpts.querySelectorAll('.merge-ref-opt');
    for (var oi = 0; oi < opts.length; oi++) {
      if (opts[oi].textContent.indexOf('#' + bestRef) === 0) opts[oi].classList.add('active');
    }
  }

  // Validate on input
  $mergeRef.addEventListener('input', function() {
    var v = parseInt($mergeRef.value, 10);
    if (v && (v < 1000 || v > 9999)) {
      $mergeRef.classList.add('ref-error');
      $mergeRefError.textContent = 'Must be 4 digits (1000-9999)';
      $mergeRefError.style.display = '';
    } else if (v && allCredentials.some(function(c) { return c.ref === v && names.indexOf(c.name) === -1; })) {
      $mergeRef.classList.add('ref-error');
      $mergeRefError.textContent = 'Duplicate ref!';
      $mergeRefError.style.display = '';
    } else {
      $mergeRef.classList.remove('ref-error');
      $mergeRefError.style.display = 'none';
    }
    // Clear active from option buttons
    var allOpts = $mergeRefOpts.querySelectorAll('.merge-ref-opt');
    for (var x = 0; x < allOpts.length; x++) allOpts[x].classList.remove('active');
  });
}

function renderMergeSourceField(label, value) {
  var masked = el('span', { className: 'merge-field-val masked', text: '••••••••' });
  var revealed = false;

  var eyeBtn = el('button', { className: 'btn-icon field-eye-btn', title: 'Reveal' });
  eyeBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
  eyeBtn.addEventListener('click', function() {
    if (!revealed) {
      masked.textContent = value; masked.classList.remove('masked'); revealed = true;
      eyeBtn.innerHTML = '';
      eyeBtn.appendChild(svgIcon('<path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/><line x1="1" y1="1" x2="23" y2="23"/>', '12'));
    } else {
      masked.textContent = '••••••••'; masked.classList.add('masked'); revealed = false;
      eyeBtn.innerHTML = '';
      eyeBtn.appendChild(svgIcon('<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>', '12'));
    }
  });

  var cpBtn = makeCopyBtn(function() { return value; });

  return el('div', { className: 'merge-field-row' }, [
    el('span', { className: 'merge-field-label', text: label }),
    masked,
    el('div', { className: 'field-display-actions' }, [eyeBtn, cpBtn]),
  ]);
}

function findCommonPrefix(names) {
  if (names.length === 0) return '';
  var parts = names.map(function(n) { return n.split('_'); });
  var minLen = Math.min.apply(null, parts.map(function(p) { return p.length; }));
  var common = [];
  for (var i = 0; i < minLen - 1; i++) {
    var seg = parts[0][i];
    var allMatch = parts.every(function(p) { return p[i] === seg; });
    if (allMatch) common.push(seg);
    else break;
  }
  return common.join('_');
}

// Add field to merge right panel
function addMergeField(label, value) {
  var idx = mergeFields.length;
  mergeFields.push({ label: label || '', value: value || '' });

  var labelInput = el('input', { type: 'text', className: 'field-label-input', placeholder: 'Field name', value: label || '' });
  var valueInput = el('input', { type: 'text', className: 'field-value-input', placeholder: 'Paste value', value: value || '' });
  var removeBtn = el('button', { className: 'field-remove', type: 'button', text: '×' });

  labelInput.addEventListener('input', function() { mergeFields[idx].label = labelInput.value; });
  valueInput.addEventListener('input', function() { mergeFields[idx].value = valueInput.value; });

  var row = el('div', { className: 'field-row' }, [labelInput, valueInput, removeBtn]);
  removeBtn.addEventListener('click', function() {
    mergeFields[idx] = null; // mark as removed
    row.remove();
  });

  $mergeFieldsList.appendChild(row);
}

// Add only if the exact label+value pair isn't already staged (sources that
// share a value contribute it once; same label with a different value is
// kept as a second row for the user to resolve).
function addMergeFieldUnique(label, value) {
  for (var i = 0; i < mergeFields.length; i++) {
    var f = mergeFields[i];
    if (f && f.label.toLowerCase() === String(label).toLowerCase() && f.value === value) return;
  }
  addMergeField(label, value);
}

document.getElementById('merge-add-field-btn').addEventListener('click', function() { addMergeField('', ''); });

// Save merge
document.getElementById('merge-save').addEventListener('click', async function() {
  var newName = document.getElementById('merge-name').value.trim();
  if (!newName) { toast('Name is required', 'error'); return; }

  var fields = mergeFields.filter(function(f) { return f && f.label && f.value; });
  if (fields.length === 0) { toast('Add at least one field', 'error'); return; }

  var sourceNames = Object.keys(mergeSelected);

  // Validate ref
  var mergeRefVal = document.getElementById('merge-ref').value.trim();
  var mergeRefNum = mergeRefVal ? parseInt(mergeRefVal, 10) : undefined;
  if (mergeRefNum && (mergeRefNum < 1000 || mergeRefNum > 9999)) {
    toast('Ref must be a 4-digit number (1000-9999)', 'error');
    return;
  }
  if (mergeRefNum && allCredentials.some(function(c) { return c.ref === mergeRefNum && sourceNames.indexOf(c.name) === -1; })) {
    toast('Ref #' + mergeRefNum + ' is already in use', 'error');
    document.getElementById('merge-ref').classList.add('ref-error');
    document.getElementById('merge-ref-error').textContent = 'Duplicate ref!';
    document.getElementById('merge-ref-error').style.display = '';
    return;
  }

  try {
    var mergeBody = {
      sourceNames: sourceNames,
      newName: newName,
      fields: fields,
      project: document.getElementById('merge-project').value,
      category: document.getElementById('merge-category').value || undefined,
      description: document.getElementById('merge-description').value || undefined,
    };
    if (mergeRefNum) mergeBody.ref = mergeRefNum;

    await api('/merge', {
      method: 'POST',
      body: JSON.stringify(mergeBody),
    });
    closeModal($mergeModal);
    mergeMode = false;
    mergeSelected = {};
    $mergeBtn.classList.remove('btn-active');
    $mergeBtn.innerHTML = '';
    $mergeBtn.appendChild(svgIcon('<path d="M8 6L21 6"/><path d="M8 12L21 12"/><path d="M8 18L21 18"/><path d="M3 6h.01"/><path d="M3 12h.01"/><path d="M3 18h.01"/>', '13'));
    $mergeBtn.appendChild(document.createTextNode(' Merge'));
    $mergeProceedBtn.style.display = 'none';
    toast('Merged ' + sourceNames.length + ' credentials into ' + newName);
    await loadCredentials();
    loadStats();
  } catch (err) {
    toast('Merge failed: ' + err.message, 'error');
  }
});

document.getElementById('merge-cancel').addEventListener('click', function() { closeModal($mergeModal); });
document.getElementById('merge-modal-close').addEventListener('click', function() { closeModal($mergeModal); });
$mergeModal.addEventListener('click', function(e) { if (e.target === $mergeModal) closeModal($mergeModal); });

// ─── Date helper ───────────────────────────────────────────────────────────
function formatDate(iso) {
  if (!iso) return '—';
  var d = new Date(iso);
  var opts = { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' };
  return d.toLocaleString('en-US', opts);
}

// ─── Feature: Dark/Light Theme Toggle ─────────────────────────────────────
var $themeToggle = document.getElementById('theme-toggle');
var $themeIconDark = document.getElementById('theme-icon-dark');
var $themeIconLight = document.getElementById('theme-icon-light');

function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('credmgr-theme', theme);
  var isDark = theme === 'dark';
  $themeIconDark.style.display  = isDark ? '' : 'none';
  $themeIconLight.style.display = isDark ? 'none' : '';
}

// Restore saved theme
(function() {
  var saved = localStorage.getItem('credmgr-theme') || 'dark';
  applyTheme(saved);
})();

$themeToggle.addEventListener('click', function() {
  var current = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(current === 'dark' ? 'light' : 'dark');
});

// ─── Feature: Vault Stats Modal ───────────────────────────────────────────
// Charts moved out of the always-visible strip into an on-demand modal — the
// Health & Automation Hub is the hero now; stats are one click away, not
// competing for attention on every load.
var $chartToggle = document.getElementById('chart-toggle');
var $statsModal  = document.getElementById('stats-modal');

function openStatsModal() {
  loadStats();
  openModal($statsModal);
}
function closeStatsModal() { closeModal($statsModal); }

$chartToggle.addEventListener('click', openStatsModal);
document.getElementById('stats-close').addEventListener('click', closeStatsModal);
$statsModal.addEventListener('click', function(e) { if (e.target === $statsModal) closeStatsModal(); });

// ─── Feature: Keyboard Shortcuts Modal ────────────────────────────────────
var $shortcutsModal = document.getElementById('shortcuts-modal');
var $shortcutsBtn = document.getElementById('shortcuts-btn');

$shortcutsBtn.addEventListener('click', function() { openModal($shortcutsModal); });
document.getElementById('shortcuts-close').addEventListener('click', function() { closeModal($shortcutsModal); });
$shortcutsModal.addEventListener('click', function(e) { if (e.target === $shortcutsModal) closeModal($shortcutsModal); });

// ─── Feature: Favorites / Pinned Credentials ─────────────────────────────
var favorites = JSON.parse(localStorage.getItem('credmgr-favorites') || '[]');

function isFavorite(name) { return favorites.indexOf(name) !== -1; }

function toggleFavorite(name) {
  var idx = favorites.indexOf(name);
  if (idx === -1) { favorites.push(name); } else { favorites.splice(idx, 1); }
  localStorage.setItem('credmgr-favorites', JSON.stringify(favorites));
  renderList(allCredentials);
}

function makeFavStar(name) {
  var star = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  star.setAttribute('viewBox', '0 0 24 24');
  star.setAttribute('width', '14');
  star.setAttribute('height', '14');
  star.setAttribute('class', 'fav-star' + (isFavorite(name) ? ' favorited' : ''));
  star.setAttribute('stroke', 'currentColor');
  star.setAttribute('stroke-width', '2');
  star.setAttribute('stroke-linecap', 'round');
  star.setAttribute('stroke-linejoin', 'round');
  star.setAttribute('fill', isFavorite(name) ? 'currentColor' : 'none');
  var path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
  path.setAttribute('d', 'M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z');
  star.appendChild(path);
  star.addEventListener('click', function(e) {
    e.stopPropagation();
    toggleFavorite(name);
  });
  return star;
}

// ─── Feature: Expiry Countdown Badges ─────────────────────────────────────
function makeExpiryBadge(expiresAt) {
  if (!expiresAt) return null;
  var now = Date.now();
  var exp = new Date(expiresAt).getTime();
  var daysLeft = Math.ceil((exp - now) / (1000 * 60 * 60 * 24));
  var badge = el('span', { className: 'expiry-badge' });
  if (daysLeft < 0) {
    badge.classList.add('expiry-expired');
    badge.textContent = 'expired';
  } else if (daysLeft <= 3) {
    badge.classList.add('expiry-red');
    badge.textContent = daysLeft + 'd';
  } else if (daysLeft <= 14) {
    badge.classList.add('expiry-yellow');
    badge.textContent = daysLeft + 'd';
  } else if (daysLeft <= 30) {
    badge.classList.add('expiry-green');
    badge.textContent = daysLeft + 'd';
  } else {
    return null; // Don't show badge for >30 days
  }
  return badge;
}

// ─── Feature: .env File Import ────────────────────────────────────────────
var $importOverlay = document.getElementById('import-overlay');
var dragCounter = 0;

document.addEventListener('dragenter', function(e) {
  e.preventDefault();
  dragCounter++;
  if (dragCounter === 1) $importOverlay.style.display = 'flex';
});

document.addEventListener('dragleave', function(e) {
  e.preventDefault();
  dragCounter--;
  if (dragCounter <= 0) { dragCounter = 0; $importOverlay.style.display = 'none'; }
});

document.addEventListener('dragover', function(e) { e.preventDefault(); });

document.addEventListener('drop', function(e) {
  e.preventDefault();
  dragCounter = 0;
  $importOverlay.style.display = 'none';

  var file = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
  if (!file) return;

  var reader = new FileReader();
  reader.onload = async function() {
    var text = reader.result;
    var lines = text.split('\n').filter(function(l) {
      var trimmed = l.trim();
      return trimmed && !trimmed.startsWith('#');
    });

    var entries = [];
    for (var i = 0; i < lines.length; i++) {
      var eq = lines[i].indexOf('=');
      if (eq === -1) continue;
      var key = lines[i].substring(0, eq).trim();
      var val = lines[i].substring(eq + 1).trim();
      // Strip surrounding quotes
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
        val = val.slice(1, -1);
      }
      if (key) entries.push({ name: key, value: val });
    }

    if (entries.length === 0) { toast('No valid KEY=VALUE lines found', 'error'); return; }

    // One batch request instead of a POST per line (v1.8, closes the v1.4
    // half-job): dry-run first for a dedupe/conflict preview, confirm, then
    // commit — same flow as the batch modal.
    try {
      var batchGroup = 'env-drop-' + (file.name || 'file').replace(/[^A-Za-z0-9._-]/g, '_');
      var preview = await api('/credentials/batch', {
        method: 'POST',
        body: JSON.stringify({ credentials: entries, batchGroup: batchGroup, dryRun: true }),
      });
      var lines2 = [
        'Import "' + (file.name || '.env') + '" (' + entries.length + ' entries)?', '',
        'Will add: ' + (preview.added || 0),
        'Identical (skipped): ' + (preview.skipped || 0),
        'Conflicts (existing, different value — skipped): ' + (preview.conflicts || 0),
      ];
      if (preview.errors) lines2.push('Errors: ' + preview.errors);
      var ok = await appConfirm(lines2.join('\n'), { title: 'Import .env', okLabel: 'Import' });
      if (!ok) { toast('Import cancelled'); return; }

      $importOverlay.style.display = 'flex';
      var result = await api('/credentials/batch', {
        method: 'POST',
        body: JSON.stringify({ credentials: entries, batchGroup: batchGroup }),
      });
      $importOverlay.style.display = 'none';

      var msg = 'Imported ' + (result.added || 0) + ' credential' + (result.added === 1 ? '' : 's');
      if (result.skipped) msg += ', ' + result.skipped + ' identical skipped';
      if (result.conflicts) msg += ', ' + result.conflicts + ' conflicts left untouched';
      toast(msg, result.errors ? 'error' : 'success');
      await loadCredentials();
      loadStats();
      loadSuggestions();
    } catch (err) {
      $importOverlay.style.display = 'none';
      toast('Import failed: ' + err.message, 'error');
    }
  };
  reader.readAsText(file);
});

// ─── Feature: Keyboard Navigation ─────────────────────────────────────────
var kbFocusIdx = -1;

function getCredItems() { return document.querySelectorAll('#cred-list .cred-item'); }

function setKbFocus(idx) {
  var items = getCredItems();
  if (items.length === 0) return;
  // Remove old focus
  var old = document.querySelector('.cred-item.kb-focus');
  if (old) old.classList.remove('kb-focus');

  if (idx < 0) idx = 0;
  if (idx >= items.length) idx = items.length - 1;
  kbFocusIdx = idx;

  items[kbFocusIdx].classList.add('kb-focus');
  items[kbFocusIdx].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}

// ─── Global keyboard shortcuts (single consolidated listener) ─────────────
document.addEventListener('keydown', function(e) {
  // Skip if typing in an input/textarea/select
  var tag = (e.target.tagName || '').toLowerCase();
  var isInput = tag === 'input' || tag === 'textarea' || tag === 'select';

  // ⌘K — open/close the command palette (always, even while typing elsewhere)
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    if ($paletteModal.classList.contains('open')) closePalette(); else openPalette();
    return;
  }

  // ⌘L — lock the vault (always)
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'l') {
    e.preventDefault();
    requestLock();
    return;
  }

  // Escape — close the topmost surface, in priority order
  if (e.key === 'Escape') {
    if ($paletteModal.classList.contains('open')) { closePalette(); return; }
    if ($shortcutsModal.classList.contains('open')) { closeModal($shortcutsModal); return; }
    if ($detailPanel.classList.contains('open')) {
      // Opened from search? Esc steps BACK to the results list first.
      if (detailFromSearch) { returnToSearchResults(); } else { closeDetailPanel(); }
      return;
    }
    // Close any other open modal
    var openModals = document.querySelectorAll('.modal-overlay.open');
    if (openModals.length > 0) { closeModal(openModals[openModals.length - 1]); return; }
    return;
  }

  if (isInput) return; // All shortcuts below skip when in an input

  // ? — shortcuts modal
  if (e.key === '?' || (e.shiftKey && e.key === '/')) {
    e.preventDefault();
    openModal($shortcutsModal);
    return;
  }

  // / — command palette (same as ⌘K, one hand)
  if (e.key === '/') {
    e.preventDefault();
    openPalette();
    return;
  }

  // T — toggle theme
  if (e.key === 't' || e.key === 'T') {
    var cur = document.documentElement.getAttribute('data-theme') || 'dark';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
    return;
  }

  // H — vault stats
  if (e.key === 'h' || e.key === 'H') {
    openStatsModal();
    return;
  }

  // N — new credential
  if (e.key === 'n' || e.key === 'N') {
    document.getElementById('add-btn').click();
    return;
  }

  // Panel-specific shortcuts (E, R, C, D, F)
  var panelOpen = $detailPanel.classList.contains('open');
  var currentName = panelOpen ? $panelTitle.textContent : null;

  // F — toggle favorite
  if (e.key === 'f' || e.key === 'F') {
    if (currentName) { toggleFavorite(currentName); return; }
    // If no panel, toggle focused item
    var items = getCredItems();
    if (kbFocusIdx >= 0 && kbFocusIdx < items.length) {
      var nameEl = items[kbFocusIdx].querySelector('.cred-name');
      if (nameEl) toggleFavorite(nameEl.textContent);
    }
    return;
  }

  if (panelOpen && currentName) {
    // E — edit
    if (e.key === 'e' || e.key === 'E') {
      var editBtn = $panelBody.querySelector('.detail-actions .btn-sm');
      if (editBtn) editBtn.click();
      return;
    }
    // R — reveal
    if (e.key === 'r' || e.key === 'R') {
      var revealBtn = $panelBody.querySelector('.reveal-all-btn') || $panelBody.querySelector('.reveal-btn');
      if (revealBtn) revealBtn.click();
      return;
    }
    // C — copy (button class is .btn-copy, created by makeCopyBtn)
    if (e.key === 'c' || e.key === 'C') {
      var copyBtn = $panelBody.querySelector('.btn-copy');
      if (copyBtn) copyBtn.click();
      return;
    }
    // D — delete
    if (e.key === 'd' || e.key === 'D') {
      var delBtn = $panelBody.querySelector('.btn-danger');
      if (delBtn) delBtn.click();
      return;
    }
  }

  // Arrow keys — navigate credentials list
  if (e.key === 'ArrowDown') {
    e.preventDefault();
    setKbFocus(kbFocusIdx + 1);
    return;
  }
  if (e.key === 'ArrowUp') {
    e.preventDefault();
    setKbFocus(kbFocusIdx - 1);
    return;
  }
  // Enter — open focused credential
  if (e.key === 'Enter') {
    var credItems = getCredItems();
    if (kbFocusIdx >= 0 && kbFocusIdx < credItems.length) {
      credItems[kbFocusIdx].click();
    }
    return;
  }
});

// ─── Feature: Settings Modal ──────────────────────────────────────────────
var $settingsModal = document.getElementById('settings-modal');
document.getElementById('settings-btn').addEventListener('click', function() {
  openModal($settingsModal);
  loadAgentTokenStatus();
  loadDismissedSuggestionsStatus();
  loadIntegrationsStatus();
  loadExportPasswordStatus();
  loadMachineLockStatus();
});

// ─── Feature: Machine lock (Settings) ─────────────────────────────────────
// Binds the vault's identity to this machine (see lib/machine-lock.js) so a
// copied store/ + .credmgr/ refuses to decrypt anywhere else. Off by
// default, and — deliberately — only reversible from the same machine that
// enabled it. A typed "LOCK" confirmation guards enable specifically because
// this is the one setting here that mutates the actual master key, not just
// a policy flag; the server still runs a real round-trip and auto-rolls-back
// on failure (see lib/server.js), so this can never leave the vault stuck.
var machineLockEnabled = false;
async function loadMachineLockStatus() {
  var $status = document.getElementById('machine-lock-status');
  try {
    var r = await api('/machine-lock');
    machineLockEnabled = !!r.enabled;
    $status.textContent = machineLockEnabled
      ? 'Enabled since ' + new Date(r.enabledAt).toLocaleString() + ' — locked to this machine'
      : 'Not enabled — a copied vault would decrypt on any machine that also has the master key';
    document.getElementById('enable-machine-lock-btn').style.display = machineLockEnabled ? 'none' : '';
    document.getElementById('disable-machine-lock-btn').style.display = machineLockEnabled ? '' : 'none';
  } catch (err) {
    $status.textContent = 'Could not load: ' + err.message;
  }
}
document.getElementById('enable-machine-lock-btn').addEventListener('click', async function() {
  var typed = await appPrompt(
    'This binds the master key to this machine\'s hardware/OS identity. A copied ' +
    'store/ + .credmgr/ will refuse to decrypt anywhere else — including with the raw ' +
    '`age` command, not just credmgr. It can only be undone from THIS machine.\n\n' +
    'Type LOCK to continue:',
    { title: 'Enable machine lock', placeholder: 'LOCK' }
  );
  if (typed !== 'LOCK') { if (typed !== null) toast('Not enabled — type LOCK exactly to confirm', 'error'); return; }
  var btn = this;
  btn.disabled = true;
  try {
    await api('/machine-lock/enable', { method: 'POST', body: JSON.stringify({}) });
    toast('Machine lock enabled — verified with a real round-trip through age');
    await loadMachineLockStatus();
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});
document.getElementById('disable-machine-lock-btn').addEventListener('click', async function() {
  var ok = await appConfirm(
    'Disable machine lock? The master key goes back to plaintext on disk — ' +
    'a copy of the vault would then decrypt on any machine again.',
    { title: 'Disable machine lock', okLabel: 'Disable', danger: true }
  );
  if (!ok) return;
  try {
    await api('/machine-lock/disable', { method: 'POST', body: JSON.stringify({}) });
    toast('Machine lock disabled');
    await loadMachineLockStatus();
  } catch (err) {
    toast('Failed: ' + err.message, 'error');
  }
});

// ─── Feature: AI Integrations (Claude/ChatGPT/other MCP clients) ──────────
// Registry lives server-side (lib/integrations.js); the actual enforcement
// happens in mcp/server.js at process launch, not here — this UI only
// manages the allowlist those launches get checked against.
async function loadIntegrationsStatus() {
  var $status = document.getElementById('integrations-status');
  var $list = document.getElementById('integrations-list');
  $list.textContent = '';
  try {
    var res = await api('/integrations');
    var list = res.integrations || [];
    if (!res.gated) {
      $status.textContent = 'Not used yet — credmgr mcp stays open to any MCP client (unchanged default) until you connect one below.';
      return;
    }
    if (list.length === 0) {
      $status.textContent = 'Every MCP client is refused — no integration is currently enabled. Connect one below.';
      return;
    }
    var enabledCount = list.filter(function(i) { return i.enabled; }).length;
    $status.textContent = enabledCount + ' of ' + list.length + ' enabled — every other MCP client is now refused.';
    list.forEach(function(i) {
      var label = el('span', { className: 'setting-label', text: i.name + (i.accountLabel ? ' — ' + i.accountLabel : '') });
      var lastUsed = i.lastUsedAt ? 'last used ' + new Date(i.lastUsedAt).toLocaleString() : 'never used yet';
      var desc = el('span', { className: 'setting-desc', text: lastUsed });
      var info = el('div', { className: 'setting-info' }, [label, desc]);

      var toggleInput = el('input', { type: 'checkbox' });
      toggleInput.checked = i.enabled;
      toggleInput.addEventListener('change', async function() {
        var next = toggleInput.checked;
        try {
          await api('/integrations/' + i.id + '/toggle', { method: 'POST', body: JSON.stringify({ enabled: next }) });
          toast(i.name + (next ? ' enabled' : ' disabled'));
          loadIntegrationsStatus();
        } catch (err) {
          toggleInput.checked = !next;
          toast('Failed: ' + err.message, 'error');
        }
      });
      var toggleLabel = el('label', { className: 'toggle-switch' }, [toggleInput, el('span', { className: 'toggle-slider' })]);

      var delBtn = el('button', { className: 'btn btn-sm', type: 'button', text: 'Disconnect' });
      delBtn.addEventListener('click', async function() {
        var ok = await appConfirm(
          'Disconnect ' + i.name + (i.accountLabel ? ' (' + i.accountLabel + ')' : '') + '? ' +
          'It will need to be reconnected — with a new config snippet — to work again.',
          { title: 'Disconnect integration', okLabel: 'Disconnect', danger: true }
        );
        if (!ok) return;
        try {
          await api('/integrations/' + i.id, { method: 'DELETE' });
          toast(i.name + ' disconnected');
          loadIntegrationsStatus();
        } catch (err) { toast('Failed: ' + err.message, 'error'); }
      });

      $list.appendChild(el('div', { className: 'setting-row setting-sub' }, [info, toggleLabel, delBtn]));
    });
  } catch (err) {
    $status.textContent = 'Could not load: ' + err.message;
  }
}

function integrationMcpConfigSnippet(id) {
  return JSON.stringify({ mcpServers: { credmgr: { command: 'credmgr', args: ['mcp', '--integration', id] } } }, null, 2);
}

// One click really does mean one click for the two named presets — the only
// input needed is an optional account label, purely for the operator's own
// bookkeeping (MCP's stdio transport gives no way to verify which AI account
// is really on the other end). "+ Connect other…" is the same flow with a
// free-text name for any additional MCP client (Cursor, Windsurf, etc.).
async function connectIntegration(presetName) {
  var name = presetName;
  if (!name) {
    name = await appPrompt('Integration name (e.g. "Cursor", "Windsurf"):', { title: 'Connect other MCP client' });
    if (!name) return;
  }
  var accountLabel = await appPrompt(
    'Which ' + name + ' account is this for? Optional — a label for your own reference, not verified.',
    { title: 'Connect ' + name, placeholder: 'e.g. work email or workspace name' }
  );
  if (accountLabel === null) return; // cancelled
  try {
    var created = await api('/integrations', { method: 'POST', body: JSON.stringify({ name: name, accountLabel: accountLabel || undefined }) });
    var snippet = integrationMcpConfigSnippet(created.id);
    var copied = false;
    try { await navigator.clipboard.writeText(snippet); copied = true; } catch (_) { /* clipboard may be unavailable */ }
    await appConfirm(
      name + ' is enabled.' + (copied
        ? ' The ready-to-paste MCP config has been copied to your clipboard — paste it into ' + name + '\'s MCP settings (mcpServers) and restart it.'
        : ' Copy this into ' + name + '\'s MCP settings (mcpServers) and restart it:\n\n' + snippet) +
      '\n\nFrom now on, every OTHER MCP client is refused unless it\'s connected the same way — this does not need re-approval again unless you disconnect it.',
      { title: name + ' connected', okLabel: 'Done' }
    );
    loadIntegrationsStatus();
  } catch (err) {
    toast('Could not connect: ' + err.message, 'error');
  }
}

document.getElementById('connect-claude-btn').addEventListener('click', function() { connectIntegration('Claude'); });
document.getElementById('connect-chatgpt-btn').addEventListener('click', function() { connectIntegration('ChatGPT'); });
document.getElementById('connect-other-btn').addEventListener('click', function() { connectIntegration(null); });

// ─── Feature: Dismissed-suggestion management (Settings) ──────────────────
async function loadDismissedSuggestionsStatus() {
  var $status = document.getElementById('dismissed-suggestions-status');
  var $btn = document.getElementById('restore-dismissed-btn');
  try {
    var list = await api('/suggestions/dismissed');
    $status.textContent = list.length + ' dismissed';
    $btn.disabled = list.length === 0;
  } catch (err) {
    $status.textContent = 'Could not load: ' + err.message;
  }
}
document.getElementById('restore-dismissed-btn').addEventListener('click', async function() {
  var btn = this;
  btn.disabled = true;
  try {
    var r = await api('/suggestions/restore-all', { method: 'POST', body: JSON.stringify({}) });
    toast('Restored ' + r.restored + ' dismissed suggestion' + (r.restored === 1 ? '' : 's'));
    await loadDismissedSuggestionsStatus();
    await loadSuggestions();
    refreshHub();
  } catch (err) {
    toast('Restore failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});
document.getElementById('settings-close').addEventListener('click', function() { closeModal($settingsModal); });
$settingsModal.addEventListener('click', function(e) { if (e.target === $settingsModal) closeModal($settingsModal); });

// ─── Feature: Agent / MCP access token ────────────────────────────────────
// Toggle maps directly onto the real security primitive: ON = a fresh token
// is issued (rotate), OFF = the token is revoked. lib/server.js's bearer-auth
// middleware already rejects every /api/* call once no valid token remains —
// this is a genuine kill switch, not a decorative flag.
// GitHub-PAT model (v1.8): the HTTP surface never returns the stored token.
// Status shows existence + last4; the full value appears exactly once, in the
// rotate response. freshAgentToken holds that one-time value only until the
// row is re-masked or the settings modal reloads.
var freshAgentToken = null;

async function loadAgentTokenStatus() {
  var $status = document.getElementById('agent-token-status');
  var $toggle = document.getElementById('setting-agent-access');
  var $row = document.getElementById('agent-token-row');
  freshAgentToken = null;
  try {
    var res = await api('/daemon-token');
    $toggle.checked = res.hasToken;
    $status.textContent = res.hasToken
      ? 'Token active (…' + (res.last4 || '????') + ') — value shown only at rotation'
      : 'No token — a daemon/MCP process would refuse to bind without one';
    $row.style.display = res.hasToken ? '' : 'none';
    setAgentTokenMasked(res.last4);
  } catch (err) {
    $status.textContent = 'Could not load token status: ' + err.message;
  }
}

function setAgentTokenMasked(last4) {
  var $val = document.getElementById('agent-token-value');
  var $copy = document.getElementById('agent-token-copy');
  $val.textContent = '••••••••••••••••••••••••' + (last4 ? last4 : '••••');
  $val.classList.add('blurred');
  $copy.style.display = 'none';
  freshAgentToken = null;
}

document.getElementById('setting-agent-access').addEventListener('change', async function(e) {
  var enabling = e.target.checked;
  try {
    if (enabling) {
      var res = await api('/daemon-token/rotate', { method: 'POST' });
      showRotatedToken(res.token);
      toast('Token issued — shown once below. Applies next daemon/MCP start');
    } else {
      await api('/daemon-token/revoke', { method: 'POST' });
      freshAgentToken = null;
      toast('Token revoked — applies next time a daemon/MCP process starts');
      await loadAgentTokenStatus();
    }
  } catch (err) {
    e.target.checked = !enabling; // revert the switch on failure
    toast('Failed: ' + err.message, 'error');
  }
});

// Show the one-time rotate response value in the row, unmasked, with Copy.
function showRotatedToken(token) {
  freshAgentToken = token;
  var $val = document.getElementById('agent-token-value');
  var $copy = document.getElementById('agent-token-copy');
  var $row = document.getElementById('agent-token-row');
  var $status = document.getElementById('agent-token-status');
  var $toggle = document.getElementById('setting-agent-access');
  $row.style.display = '';
  $toggle.checked = true;
  $val.textContent = token;
  $val.classList.remove('blurred');
  $copy.style.display = '';
  $status.textContent = 'New token — copy it NOW; it will not be shown again';
}

document.getElementById('agent-token-copy').addEventListener('click', async function() {
  if (!freshAgentToken) { toast('No token to copy — rotate to get a fresh one', 'error'); return; }
  try {
    await copySecretToClipboard(freshAgentToken);
    toast('Token copied — clipboard clears in 30s');
  } catch (e) { toast('Copy failed', 'error'); }
});

document.getElementById('agent-token-rotate').addEventListener('click', async function() {
  var ok = await appConfirm(
    'Rotate the agent token?\n\nThe current token stops working immediately. ' +
    'The new one is shown exactly once — every agent/MCP client must be updated with it.',
    { title: 'Rotate & show once', okLabel: 'Rotate' }
  );
  if (!ok) return;
  try {
    var res = await api('/daemon-token/rotate', { method: 'POST' });
    showRotatedToken(res.token);
  } catch (err) {
    toast('Rotate failed: ' + err.message, 'error');
  }
});

// ─── Feature: Generate secret in Add form ─────────────────────────────────
document.getElementById('add-generate-btn').addEventListener('click', async function() {
  try {
    var len = document.getElementById('add-generate-len').value;
    var type = document.getElementById('add-generate-type').value;
    var g = await api('/generate?length=' + encodeURIComponent(len) + '&type=' + encodeURIComponent(type));
    var ta = document.getElementById('add-value');
    ta.value = g.value;
    ta.dispatchEvent(new Event('input'));
    toast('Generated ' + len + '-char secret');
  } catch (err) {
    toast('Generate failed: ' + err.message, 'error');
  }
});

// Rough strength estimate: bits = length * log2(distinct charset in use).
// Good enough to warn on weak manual entries — not a substitute for a real
// zxcvbn-style dictionary check, which would need an external dep.
function estimateEntropyBits(value) {
  if (!value) return 0;
  var classes = 0;
  if (/[a-z]/.test(value)) classes += 26;
  if (/[A-Z]/.test(value)) classes += 26;
  if (/[0-9]/.test(value)) classes += 10;
  if (/[^a-zA-Z0-9]/.test(value)) classes += 32;
  if (!classes) classes = 1;
  return Math.round(value.length * (Math.log(classes) / Math.LN2));
}

function updateStrengthMeter() {
  var value = document.getElementById('add-value').value;
  var meter = document.getElementById('add-strength');
  if (!value) { meter.style.display = 'none'; return; }
  var bits = estimateEntropyBits(value);
  var label = bits >= 100 ? 'Very strong' : bits >= 60 ? 'Strong' : bits >= 40 ? 'Fair' : 'Weak';
  var tone  = bits >= 60 ? 'strong' : bits >= 40 ? 'fair' : 'weak';
  meter.className = 'strength-meter strength-' + tone;
  meter.textContent = label + ' · ' + bits + ' bits of entropy';
  meter.style.display = '';
}
document.getElementById('add-value').addEventListener('input', updateStrengthMeter);

// ─── Feature: Export password (Settings) ──────────────────────────────────
// Separate secret from the vault PIN — gates the whole-database export/
// backup surface specifically, with no bypass for an already-open PIN
// session or an agent's bearer token (see lib/lock.js). Checked once per
// export, not session-based, since export is infrequent and high-stakes.
var exportPasswordSet = false;
async function loadExportPasswordStatus() {
  try {
    var r = await api('/export-password');
    exportPasswordSet = !!r.set;
    renderExportPasswordSettings();
  } catch (e) { /* non-critical for page load */ }
}
function renderExportPasswordSettings() {
  document.getElementById('export-password-status').textContent = exportPasswordSet
    ? 'Set — whole-database export requires it'
    : 'Not set (recommended: set one) — export is open to the same access as everything else';
  document.getElementById('set-export-password-btn').textContent = exportPasswordSet ? 'Change' : 'Set';
  document.getElementById('remove-export-password-btn').style.display = exportPasswordSet ? '' : 'none';
}
document.getElementById('set-export-password-btn').addEventListener('click', async function() {
  var currentPassword = null;
  if (exportPasswordSet) {
    currentPassword = await appPrompt('Enter your CURRENT export password:', { title: 'Change export password', type: 'password', placeholder: '••••••••' });
    if (currentPassword === null) return;
  }
  var password = await appPrompt('Enter a new export password (8+ characters):', {
    title: exportPasswordSet ? 'Change export password' : 'Set export password', type: 'password', placeholder: '••••••••'
  });
  if (password === null) return;
  if (password.length < 8) { toast('Export password must be at least 8 characters', 'error'); return; }
  try {
    await api('/export-password', { method: 'POST', body: JSON.stringify({ password: password, currentPassword: currentPassword }) });
    exportPasswordSet = true;
    renderExportPasswordSettings();
    toast('Export password saved — required for whole-database export');
  } catch (err) { toast('Failed: ' + err.message, 'error'); }
});
document.getElementById('remove-export-password-btn').addEventListener('click', async function() {
  var currentPassword = await appPrompt('Enter your current export password to remove it:', { title: 'Remove export password', type: 'password', placeholder: '••••••••' });
  if (currentPassword === null) return;
  try {
    await api('/export-password', { method: 'POST', body: JSON.stringify({ remove: true, currentPassword: currentPassword }) });
    exportPasswordSet = false;
    renderExportPasswordSettings();
    toast('Export password removed');
  } catch (err) { toast('Failed: ' + err.message, 'error'); }
});

// ─── Feature: Export .env download (Settings) ─────────────────────────────
document.getElementById('export-env-btn').addEventListener('click', async function() {
  var proj = document.getElementById('export-project').value;
  if (!proj) { toast('Pick a project first', 'error'); return; }
  var headers = {};
  if (exportPasswordSet) {
    var pw = await appPrompt('Enter your export password to continue:', { title: 'Export password required', type: 'password', placeholder: '••••••••' });
    if (pw === null) return;
    headers['X-Credmgr-Export-Auth'] = pw;
  }
  try {
    // api() returns text for non-JSON responses (export is text/plain).
    var text = await api('/export/' + encodeURIComponent(proj), { headers: headers });
    var blob = new Blob([text], { type: 'text/plain' });
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = proj + '.env';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function() { URL.revokeObjectURL(a.href); }, 5000);
    toast('Exported ' + proj + '.env — keep it local, delete after use');
  } catch (err) {
    toast('Export failed: ' + err.message, 'error');
  }
});

// ─── Feature: Doctor (Settings) ───────────────────────────────────────────
async function runDoctor(fix) {
  var box = document.getElementById('doctor-results');
  box.style.display = '';
  box.textContent = fix ? 'Applying fixes…' : 'Diagnosing…';
  try {
    var r = await api('/doctor', { method: 'POST', body: JSON.stringify({ fix: !!fix }) });
    box.textContent = '';
    var integ = r.integrity;
    var heal = r.heal;

    var status = el('div', { className: 'doctor-status ' + (integ.ok ? 'ok' : 'fail') }, [
      el('span', { text: integ.ok ? '✓ Integrity PASS' : '✗ Integrity FAIL' }),
      el('span', { className: 'doctor-sub', text: 'checksum: ' + integ.checksum + ' · ' + integ.credentialCount + ' credentials' }),
    ]);
    box.appendChild(status);

    var issues = (integ.errors || []).concat(integ.warnings || []);
    for (var i = 0; i < issues.length; i++) {
      box.appendChild(el('div', { className: 'doctor-line', text: '• ' + issues[i] }));
    }

    if (heal.fixCount === 0) {
      box.appendChild(el('div', { className: 'doctor-line doctor-ok', text: heal.applied ? 'Nothing needed repair.' : 'Nothing to repair.' }));
    } else {
      for (var j = 0; j < heal.fixes.length; j++) {
        box.appendChild(el('div', { className: 'doctor-line', text: (heal.applied ? '✓ ' : '→ ') + '[' + heal.fixes[j].type + '] ' + heal.fixes[j].detail }));
      }
      if (!heal.applied) {
        var fixBtn = el('button', { className: 'btn btn-primary btn-sm', text: 'Apply ' + heal.fixCount + ' fix(es)', style: 'margin-top:8px' });
        fixBtn.addEventListener('click', function() { runDoctor(true); });
        box.appendChild(fixBtn);
      } else {
        toast('Doctor applied ' + heal.fixCount + ' fix(es)');
        loadCredentials();
      }
    }
  } catch (err) {
    box.textContent = 'Doctor failed: ' + err.message;
  }
}
document.getElementById('doctor-btn').addEventListener('click', function() { runDoctor(false); });

// ─── Feature: Encrypted backup (Settings) ─────────────────────────────────
document.getElementById('backup-btn').addEventListener('click', async function() {
  var btn = this;
  btn.disabled = true;
  try {
    var r = await api('/backup', { method: 'POST', body: JSON.stringify({}) });
    toast('Backup written: ' + r.path);
  } catch (err) {
    toast('Backup failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false;
  }
});

// ─── Feature: Server-Enforced Vault Lock (v1.8) ──────────────────────────
// The daemon holds the PIN (scrypt) and the unlock sessions; value-revealing
// endpoints 401 while locked. Everything here only REFLECTS that state —
// deleting this code or the lock screen div does not unlock anything.
var $lockScreen   = document.getElementById('lock-screen');
var $lockPinInput = document.getElementById('lock-pin-input');
var $lockPinBtn   = document.getElementById('lock-pin-submit');
var $lockError    = document.getElementById('lock-error');
var $autolockOpts = document.getElementById('autolock-options');
var $lockTimer    = document.getElementById('setting-lock-timer');
var $setPinBtn    = document.getElementById('set-pin-btn');
var $removePinBtn = document.getElementById('remove-pin-btn');
var $pinStatus    = document.getElementById('pin-status');
var lockIdleTimer = null;
var lockState     = { pinSet: false, ttlMinutes: 15 };

function showLockScreen() {
  if ($lockScreen.style.display === 'flex') return;
  $lockScreen.style.display = 'flex';
  $lockPinInput.value = '';
  $lockError.style.display = 'none';
  $lockPinInput.focus();
}

function hideLockScreen() {
  $lockScreen.style.display = 'none';
  resetIdleTimer();
}

async function refreshLockState() {
  try {
    var s = await api('/lock-status');
    lockState.pinSet = !!s.pinSet;
    lockState.ttlMinutes = s.ttlMinutes || 15;
    renderLockSettings();
    if (s.locked && s.pinSet) showLockScreen();
    return s;
  } catch (e) {
    return null;
  }
}

// Manual "Lock now" — header button, ⌘L, or the palette command. Revokes the
// server session; the lock screen follows as a consequence.
async function requestLock() {
  if (!lockState.pinSet) {
    toast('Set a PIN in Settings before locking', 'error');
    return;
  }
  try { await api('/lock', { method: 'POST', body: JSON.stringify({}) }); } catch (e) { /* still lock the UI */ }
  sessionStorage.removeItem('credmgr-session');
  showLockScreen();
}

async function verifyPin() {
  var entered = $lockPinInput.value;
  if (!entered) return;
  try {
    var r = await api('/unlock', { method: 'POST', body: JSON.stringify({ pin: entered }) });
    sessionStorage.setItem('credmgr-session', r.session);
    hideLockScreen();
    // Re-pull data the locked state may have blocked
    loadCredentials();
    loadStats();
  } catch (err) {
    $lockError.textContent = err.message || 'Incorrect PIN';
    $lockError.style.display = '';
    $lockPinInput.classList.add('shake');
    setTimeout(function() { $lockPinInput.classList.remove('shake'); }, 500);
    $lockPinInput.value = '';
    $lockPinInput.focus();
  }
}

$lockPinBtn.addEventListener('click', verifyPin);
$lockPinInput.addEventListener('keydown', function(e) {
  if (e.key === 'Enter') verifyPin();
});
var $lockNowBtn = document.getElementById('lock-now-btn');
if ($lockNowBtn) $lockNowBtn.addEventListener('click', requestLock);

// Idle timer — locks the UI (and revokes the session) after the same TTL the
// server uses. The server's sliding expiry is the real mechanism; this just
// keeps an abandoned screen from sitting open on unlocked values.
function resetIdleTimer() {
  if (lockIdleTimer) clearTimeout(lockIdleTimer);
  if (!lockState.pinSet) return;
  lockIdleTimer = setTimeout(function() { requestLock(); }, lockState.ttlMinutes * 60 * 1000);
}

['mousemove', 'mousedown', 'keydown', 'scroll', 'touchstart'].forEach(function(evt) {
  document.addEventListener(evt, function() {
    if ($lockScreen.style.display !== 'flex') resetIdleTimer();
  }, { passive: true });
});

function renderLockSettings() {
  $pinStatus.textContent = lockState.pinSet
    ? 'PIN is set — server-enforced'
    : 'Not set — value reveals are unprotected';
  $setPinBtn.textContent = lockState.pinSet ? 'Change PIN' : 'Set PIN';
  $removePinBtn.style.display = lockState.pinSet ? '' : 'none';
  $autolockOpts.style.display = lockState.pinSet ? '' : 'none';
  var opt = Array.prototype.find.call($lockTimer.options, function(o) { return Number(o.value) === lockState.ttlMinutes; });
  if (opt) $lockTimer.value = opt.value;
}

$lockTimer.addEventListener('change', async function() {
  try {
    await api('/pin', { method: 'POST', body: JSON.stringify({ lockTimeoutMinutes: parseInt($lockTimer.value, 10) }) });
    lockState.ttlMinutes = parseInt($lockTimer.value, 10);
    resetIdleTimer();
    toast('Auto-lock timeout updated');
  } catch (err) {
    toast('Failed to update timeout: ' + err.message, 'error');
  }
});

$setPinBtn.addEventListener('click', async function() {
  var currentPin = null;
  if (lockState.pinSet) {
    currentPin = await appPrompt('Enter your CURRENT PIN:', { title: 'Change PIN', type: 'password', placeholder: '••••' });
    if (currentPin === null) return;
  }
  var pin = await appPrompt('Enter a new PIN (4+ characters):', { title: lockState.pinSet ? 'Change PIN' : 'Set PIN', type: 'password', placeholder: '••••' });
  if (pin === null) return;
  if (pin.length < 4) { toast('PIN must be at least 4 characters', 'error'); return; }
  try {
    var r = await api('/pin', { method: 'POST', body: JSON.stringify({ pin: pin, currentPin: currentPin }) });
    if (r.session) sessionStorage.setItem('credmgr-session', r.session);
    lockState.pinSet = true;
    renderLockSettings();
    resetIdleTimer();
    toast('PIN saved — lock is now enforced by the daemon');
  } catch (err) {
    toast('Failed to set PIN: ' + err.message, 'error');
  }
});

$removePinBtn.addEventListener('click', async function() {
  var currentPin = await appPrompt('Enter your current PIN to remove the lock:', { title: 'Remove PIN', type: 'password', placeholder: '••••' });
  if (currentPin === null) return;
  try {
    await api('/pin', { method: 'POST', body: JSON.stringify({ remove: true, currentPin: currentPin }) });
    sessionStorage.removeItem('credmgr-session');
    lockState.pinSet = false;
    renderLockSettings();
    if (lockIdleTimer) clearTimeout(lockIdleTimer);
    toast('PIN removed — vault lock disabled');
  } catch (err) {
    toast('Failed to remove PIN: ' + err.message, 'error');
  }
});

// One-time migration from the retired client-side lock (localStorage SHA-256).
// The old hash can't be converted (different KDF), so we verify the re-entered
// PIN against it locally, then register the same PIN server-side.
async function migrateLegacyPin() {
  var legacy = null;
  try { legacy = JSON.parse(localStorage.getItem('credmgr-lock') || '{}'); } catch (e) { legacy = {}; }
  if (!legacy || !legacy.pinHash || lockState.pinSet) {
    if (legacy && legacy.pinHash && lockState.pinSet) localStorage.removeItem('credmgr-lock');
    return;
  }
  var pin = await appPrompt(
    'The vault lock is now enforced by the daemon (server-side).\n\n' +
    'Re-enter your existing PIN once to upgrade it — or Cancel to discard the old client-side lock.',
    { title: 'Lock upgrade', type: 'password', placeholder: '••••' }
  );
  if (pin) {
    var buf = new TextEncoder().encode(pin);
    var hash = await crypto.subtle.digest('SHA-256', buf);
    var hex = Array.from(new Uint8Array(hash)).map(function(b) { return b.toString(16).padStart(2, '0'); }).join('');
    if (hex === legacy.pinHash) {
      try {
        var r = await api('/pin', { method: 'POST', body: JSON.stringify({ pin: pin }) });
        if (r.session) sessionStorage.setItem('credmgr-session', r.session);
        lockState.pinSet = true;
        renderLockSettings();
        localStorage.removeItem('credmgr-lock');
        toast('PIN upgraded — lock is now enforced by the daemon');
        return;
      } catch (err) {
        toast('Upgrade failed: ' + err.message, 'error');
        return; // keep localStorage so the user can retry next load
      }
    }
    toast('PIN does not match the old lock — set a fresh PIN in Settings', 'error');
    return; // keep for another attempt next load
  }
  // Cancelled: the old lock was client-side theater — retire it honestly.
  localStorage.removeItem('credmgr-lock');
  toast('Old client-side lock discarded. Set a PIN in Settings for the enforced lock.');
}

// Boot the lock feature: reflect server state, then offer legacy migration.
(async function initLock() {
  await refreshLockState();
  migrateLegacyPin();
})();

// ─── Feature: Activity Sidebar ────────────────────────────────────────────
var $activitySidebar = document.getElementById('activity-sidebar');
var $activityToggle  = document.getElementById('activity-toggle');
var $activityList    = document.getElementById('activity-list');
var $sidebarTabs     = document.getElementById('sidebar-time-tabs');
var $sidebarSetting  = document.getElementById('setting-sidebar');
var activityWindow   = '3h';

function isSidebarEnabled() {
  return localStorage.getItem('credmgr-sidebar') === '1';
}

function setSidebarVisible(show) {
  $activitySidebar.style.display = show ? '' : 'none';
  $activityToggle.classList.toggle('active', show);
  $sidebarSetting.checked = show;
  localStorage.setItem('credmgr-sidebar', show ? '1' : '0');
  if (show) loadActivity();
}

// Restore state
(function() {
  if (isSidebarEnabled()) setSidebarVisible(true);
})();

$activityToggle.addEventListener('click', function() {
  setSidebarVisible(!isSidebarEnabled());
});

$sidebarSetting.addEventListener('change', function() {
  setSidebarVisible($sidebarSetting.checked);
});

// Time window tabs
$sidebarTabs.addEventListener('click', function(e) {
  var btn = e.target.closest('.stab');
  if (!btn) return;
  var tabs = $sidebarTabs.querySelectorAll('.stab');
  for (var i = 0; i < tabs.length; i++) tabs[i].classList.remove('active');
  btn.classList.add('active');
  activityWindow = btn.getAttribute('data-window');
  loadActivity();
});

function windowToMs(w) {
  switch (w) {
    case '3h':  return 3 * 60 * 60 * 1000;
    case '12h': return 12 * 60 * 60 * 1000;
    case '1d':  return 24 * 60 * 60 * 1000;
    case '1w':  return 7 * 24 * 60 * 60 * 1000;
    case '1m':  return 30 * 24 * 60 * 60 * 1000;
    default:    return 3 * 60 * 60 * 1000;
  }
}

async function loadActivity() {
  if (!isSidebarEnabled()) return;
  $activityList.textContent = '';
  $activityList.appendChild(el('div', { className: 'activity-empty', text: 'Loading…' }));

  try {
    var logs = await api('/access-log?limit=500');
    var cutoff = Date.now() - windowToMs(activityWindow);
    var counts = {};
    var lastAccess = {};

    for (var i = 0; i < logs.length; i++) {
      var ts = new Date(logs[i].ts || logs[i].timestamp).getTime();
      if (ts < cutoff) continue;
      var n = logs[i].name;
      counts[n] = (counts[n] || 0) + 1;
      if (!lastAccess[n] || ts > lastAccess[n]) lastAccess[n] = ts;
    }

    // Sort by count desc, then by most recent
    var sorted = Object.keys(counts).sort(function(a, b) {
      if (counts[b] !== counts[a]) return counts[b] - counts[a];
      return (lastAccess[b] || 0) - (lastAccess[a] || 0);
    });

    $activityList.textContent = '';

    if (sorted.length === 0) {
      $activityList.appendChild(el('div', { className: 'activity-empty', text: 'No activity in this window' }));
      return;
    }

    for (var j = 0; j < sorted.length; j++) {
      var name = sorted[j];
      var rank = j + 1;
      var ago = timeAgo(lastAccess[name]);

      var rankEl = el('span', { className: 'activity-rank' + (rank <= 3 ? ' rank-' + rank : ''), text: String(rank) });
      var infoEl = el('div', { className: 'activity-info' }, [
        el('div', { className: 'activity-name', text: name }),
        el('div', { className: 'activity-meta', text: 'last: ' + ago }),
      ]);
      var countEl = el('span', { className: 'activity-count', text: String(counts[name]) });

      var item = el('div', { className: 'activity-item' }, [rankEl, infoEl, countEl]);
      (function(credName) {
        item.addEventListener('click', function() {
          var cred = allCredentials.find(function(c) { return c.name === credName; });
          if (cred) openDetail(cred.name, cred.sensitivity);
        });
      })(name);
      $activityList.appendChild(item);
    }
  } catch (err) {
    $activityList.textContent = '';
    $activityList.appendChild(el('div', { className: 'activity-empty', text: 'Failed to load activity' }));
  }
}

function timeAgo(ts) {
  var diff = Date.now() - ts;
  var mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return mins + 'm ago';
  var hrs = Math.floor(mins / 60);
  if (hrs < 24) return hrs + 'h ago';
  var days = Math.floor(hrs / 24);
  return days + 'd ago';
}

// Auto-refresh activity sidebar every 30 seconds
setInterval(function() { if (isSidebarEnabled()) loadActivity(); }, 30000);

// ─── Feature: Smart Merge Suggestions ────────────────────────────────────
// Rendered as a row inside the Health Hub now (see refreshHub()) rather than
// a standalone banner — same data, one less thing competing for attention.
var $suggestionsModal    = document.getElementById('suggestions-modal');
var $suggestionsList     = document.getElementById('suggestions-list');
var activeSuggestions    = [];

// Dismissals are persisted server-side (index.json, keyed by each
// suggestion's own `.key`) — GET /suggestions already excludes them, so a
// rejected group stays gone across reloads, tabs, and sessions instead of
// reappearing every scan the moment sessionStorage is cleared.
async function loadSuggestions() {
  try {
    activeSuggestions = await api('/suggestions');
  } catch (e) {
    // Suggestions are non-critical — silently skip on error
  }
}

async function dismissSuggestionPersist(s) {
  try {
    await api('/suggestions/dismiss', { method: 'POST', body: JSON.stringify({ key: s.key }) });
  } catch (e) {
    toast('Could not save dismissal — it may reappear on the next scan', 'error');
  }
}

function renderSuggestionCards() {
  $suggestionsList.textContent = '';
  var visible = activeSuggestions;
  if (visible.length === 0) {
    $suggestionsList.appendChild(el('div', { className: 'suggestion-empty', text: 'No suggestions — your vault looks clean! 🎉' }));
    return;
  }

  for (var i = 0; i < visible.length; i++) {
    $suggestionsList.appendChild(buildSuggestionCard(visible[i]));
  }
}

function buildSuggestionCard(s) {
  var isDupe  = s.type === 'exact-duplicate';
  var sevClass = { high: 'sev-high', medium: 'sev-medium', low: 'sev-low' }[s.severity] || 'sev-low';
  var typeLabel =
    isDupe ? 'Exact Duplicate' :
    s.type === 'near-duplicate-value' ? 'Near-Duplicate Value' :
    s.type === 'near-name' ? 'Similar Names' :
    (s.walletLike ? 'Wallet Parts' : 'Merge Candidates');
  var typeClass = isDupe ? 'type-dupe' : 'type-merge';

  var sevDot    = el('span', { className: 'suggestion-sev-dot ' + sevClass });
  var typeBadge = el('span', { className: 'suggestion-type-badge ' + typeClass, text: typeLabel });
  var reason    = el('span', { className: 'suggestion-reason', text: s.reason });
  var cardHeader = el('div', { className: 'suggestion-card-header' }, [sevDot, typeBadge, reason]);

  // Per-item selection: every chip is a checkbox so wrongly-matched items
  // can be excluded before merging/deleting. For dupes the first name is
  // the fixed "keep" — only its duplicates are selectable.
  var fieldByName = {};
  (s.suggestedFields || []).forEach(function(f) { fieldByName[f.name] = f.label; });
  var checkboxes = {}; // name → input element
  var chips = [];
  for (var j = 0; j < s.names.length; j++) {
    var name = s.names[j];
    if (isDupe && j === 0) {
      chips.push(el('span', { className: 'suggestion-name-chip chip-keep', title: 'This one is kept', text: name + ' (keep)' }));
      continue;
    }
    var cb = el('input', { type: 'checkbox', className: 'suggestion-cb' });
    cb.checked = true;
    checkboxes[name] = cb;
    var chipChildren = [cb, el('span', { text: name })];
    if (!isDupe && fieldByName[name]) {
      chipChildren.push(el('span', { className: 'suggestion-field-tag', text: '→ ' + fieldByName[name] }));
    }
    var chip = el('label', { className: 'suggestion-name-chip chip-selectable' + (isDupe ? ' chip-remove' : ''), title: 'Uncheck if this item was matched incorrectly' }, chipChildren);
    chips.push(chip);
  }
  var namesRow = el('div', { className: 'suggestion-names' }, chips);
  var hint = el('div', { className: 'suggestion-hint', text: 'Uncheck anything that was matched incorrectly — it will be left untouched.' });

  function checkedNames() {
    return s.names.filter(function(n) { return checkboxes[n] ? checkboxes[n].checked : (isDupe && n === s.names[0]); })
      .filter(function(n) { return !(isDupe && n === s.names[0]); });
  }

  // Action buttons
  var dismissBtn = el('button', { className: 'btn-dismiss', type: 'button', text: 'Not a match' });
  var actionsRow;
  var card;

  function afterActionCleanup() {
    card.classList.add('dismissed');
    setTimeout(function() {
      card.remove();
      if ($suggestionsList.querySelectorAll('.suggestion-card:not(.dismissed)').length === 0) {
        renderSuggestionCards();
      }
    }, 300);
  }

  if (isDupe) {
    var deleteBtn = el('button', { className: 'btn-accept btn-danger-accent', type: 'button', text: 'Delete selected duplicates' });
    deleteBtn.addEventListener('click', function() { acceptDuplicateDeletion(s, card, checkedNames(), afterActionCleanup); });
    actionsRow = el('div', { className: 'suggestion-actions' }, [dismissBtn, deleteBtn]);
  } else if (s.type === 'near-duplicate-value' || s.type === 'near-name') {
    // Review-only types (v1.8): fuzzy matches are never auto-merged — the
    // human decides. Manual merge wizard is the only mutating action.
    var reviewBtn = el('button', { className: 'btn-dismiss', type: 'button', text: 'Merge manually…' });
    reviewBtn.addEventListener('click', function() {
      var names = checkedNames();
      if (names.length < 2) { toast('Select at least 2 items to merge', 'error'); return; }
      closeModal($suggestionsModal);
      openMergeModalForSuggestion(s, names);
    });
    actionsRow = el('div', { className: 'suggestion-actions' }, [dismissBtn, reviewBtn]);
  } else {
    var autoBtn   = el('button', { className: 'btn-accept', type: 'button', text: 'Auto-merge' });
    var manualBtn = el('button', { className: 'btn-dismiss', type: 'button', text: 'Merge manually…' });

    autoBtn.addEventListener('click', async function() {
      var names = checkedNames();
      if (names.length < 2) { toast('Select at least 2 items to merge', 'error'); return; }
      var targetName = s.suggestedName || findCommonPrefix(names) || names[0];
      var ok = await appConfirm(
        'Merge ' + names.length + ' credentials into one entry "' + targetName + '"?\n\n' +
        'Every value becomes a clearly labelled field (username, password, publicKey, privateKey, seedPhrase, …). ' +
        'The original items are archived and recoverable for 7 days.',
        { title: 'Auto-merge', okLabel: 'Merge ' + names.length + ' items' }
      );
      if (!ok) return;
      autoBtn.disabled = true; autoBtn.textContent = 'Merging…';
      try {
        var r = await api('/merge/auto', {
          method: 'POST',
          body: JSON.stringify({ sourceNames: names, newName: targetName, category: s.suggestedCategory }),
        });
        toast('Merged ' + names.length + ' → ' + r.merged.name + ' (#' + r.merged.ref + ', ' + r.fields.length + ' fields)');
        afterActionCleanup();
        await loadCredentials();
        loadStats();
        await loadSuggestions();
        refreshHub();
      } catch (err) {
        toast('Auto-merge failed: ' + err.message, 'error');
        autoBtn.disabled = false; autoBtn.textContent = 'Auto-merge';
      }
    });

    manualBtn.addEventListener('click', function() {
      var names = checkedNames();
      if (names.length < 2) { toast('Select at least 2 items to merge', 'error'); return; }
      closeModal($suggestionsModal);
      openMergeModalForSuggestion(s, names);
    });

    actionsRow = el('div', { className: 'suggestion-actions' }, [dismissBtn, manualBtn, autoBtn]);
  }

  card = el('div', { className: 'suggestion-card' }, [
    cardHeader,
    el('div', { className: 'suggestion-card-body' }, [namesRow, hint, actionsRow]),
  ]);

  // "Not a match" — dismiss without touching anything. Persisted server-side
  // first so a slow/failed save can't leave the UI claiming it's gone when
  // it isn't; the local array is trimmed in lockstep so a re-render before
  // the next full reload doesn't resurrect the card.
  dismissBtn.addEventListener('click', async function() {
    await dismissSuggestionPersist(s);
    activeSuggestions = activeSuggestions.filter(function(x) { return x.key !== s.key; });
    afterActionCleanup();
    refreshHub();
  });

  return card;
}

async function acceptDuplicateDeletion(s, card, selectedNames, onDone) {
  // Keep the first (lowest ref); delete the SELECTED duplicates only
  var toDelete = (selectedNames && selectedNames.length) ? selectedNames : (s.duplicates || s.names.slice(1));
  if (!toDelete || toDelete.length === 0) { toast('Nothing selected to delete', 'error'); return; }
  var ok = await appConfirm(
    'Delete ' + toDelete.length + ' duplicate' + (toDelete.length > 1 ? 's' : '') + '?\n\n' +
    toDelete.join('\n') + '\n\nKeeping: ' + s.keepName + '\nDeleted items are recoverable for 7 days.',
    { title: 'Delete duplicates', okLabel: 'Delete', danger: true }
  );
  if (!ok) return;
  try {
    card.style.opacity = '0.5';
    card.style.pointerEvents = 'none';
    for (var i = 0; i < toDelete.length; i++) {
      await api('/credentials/' + encodeURIComponent(toDelete[i]), { method: 'DELETE' });
    }
    toast('Deleted ' + toDelete.length + ' duplicate' + (toDelete.length > 1 ? 's' : ''));
    if (onDone) onDone();
    await loadCredentials();
    loadStats();
    await loadSuggestions();
  } catch (err) {
    card.style.opacity = '';
    card.style.pointerEvents = '';
    toast('Delete failed: ' + err.message, 'error');
  }
}

function openMergeModalForSuggestion(s, selectedNames) {
  // Pre-select the suggestion's (checked) credentials and open the wizard
  var names = (selectedNames && selectedNames.length) ? selectedNames : s.names;
  mergeMode = true;
  mergeSelected = {};
  for (var i = 0; i < names.length; i++) mergeSelected[names[i]] = true;
  $mergeBtn.classList.add('btn-active');
  renderList(allCredentials);
  updateMergeCount();
  // openMergeModal reads from global mergeSelected
  openMergeModal().then(function() {
    // Pre-fill suggested merged name after modal content is built
    var suggestedName = s.suggestedName || findCommonPrefix(names);
    if (suggestedName) {
      var nameInput = document.getElementById('merge-name');
      if (nameInput && !nameInput.value) nameInput.value = suggestedName;
    }
  });
  // Hide the suggestion while the user works the manual-merge wizard — this
  // is "handling it", not a rejection, so it's a local-only removal (not
  // persisted): if the merge is never completed it simply reappears on the
  // next refresh, instead of being recorded as a decision the user never made.
  activeSuggestions = activeSuggestions.filter(function(x) { return x.key !== s.key; });
  refreshHub();
}

// ─── Auto-merge all safe groups (batch mode) ───────────────────────────────
// Dry-run first so the confirm shows EXACTLY what will happen; ambiguous
// groups are never touched automatically.
document.getElementById('suggestions-auto-all').addEventListener('click', async function() {
  var btn = this;
  try {
    var plan = await api('/merge/auto-all', { method: 'POST', body: JSON.stringify({ dryRun: true }) });
    if (!plan.planned.length) {
      toast('No safe groups to auto-merge' + (plan.skipped.length ? ' — ' + plan.skipped.length + ' need manual review' : ''));
      return;
    }
    var msg = 'Auto-merge ' + plan.planned.length + ' group' + (plan.planned.length > 1 ? 's' : '') + '?\n\n' +
      plan.planned.slice(0, 8).map(function(p) { return '• ' + p.newName + ' (' + p.names.length + ' items)'; }).join('\n') +
      (plan.planned.length > 8 ? '\n…and ' + (plan.planned.length - 8) + ' more' : '') +
      (plan.skipped.length ? '\n\n' + plan.skipped.length + ' ambiguous group' + (plan.skipped.length > 1 ? 's' : '') + ' left for manual review.' : '') +
      '\n\nOriginals stay recoverable for 7 days.';
    var ok = await appConfirm(msg, { title: 'Auto-merge all safe', okLabel: 'Merge ' + plan.planned.length + ' group' + (plan.planned.length > 1 ? 's' : '') });
    if (!ok) return;
    btn.disabled = true; btn.textContent = 'Merging…';
    var r = await api('/merge/auto-all', { method: 'POST', body: JSON.stringify({}) });
    toast('Auto-merged ' + r.merged.length + ' group' + (r.merged.length === 1 ? '' : 's') +
      (r.errors.length ? ' · ' + r.errors.length + ' failed' : ''), r.errors.length ? 'error' : 'success');
    await loadCredentials();
    loadStats();
    await loadSuggestions();
    renderSuggestionCards();
    refreshHub();
  } catch (err) {
    toast('Auto-merge all failed: ' + err.message, 'error');
  } finally {
    btn.disabled = false; btn.textContent = 'Auto-merge all safe';
  }
});

document.getElementById('suggestions-modal-close').addEventListener('click', function() {
  closeModal($suggestionsModal);
});
$suggestionsModal.addEventListener('click', function(e) {
  if (e.target === $suggestionsModal) closeModal($suggestionsModal);
});

// ─── Feature: Bulk Operations (reassign + batch import) ───────────────────
var $batchModal = document.getElementById('batch-modal');

document.getElementById('reassign-btn').addEventListener('click', async function() {
  var from = document.getElementById('reassign-from').value;
  var to   = document.getElementById('reassign-to').value;
  if (!from || !to) { toast('Select both source and destination projects', 'error'); return; }
  if (from === to)  { toast('Source and destination must differ', 'error'); return; }
  var fromName = (projects.find(function(p){ return p.id === from; }) || {}).name || from;
  var toName   = (projects.find(function(p){ return p.id === to;   }) || {}).name || to;
  var ok = await appConfirm('Move ALL credentials from "' + fromName + '" to "' + toName + '"?',
    { title: 'Reassign project', okLabel: 'Move all' });
  if (!ok) return;
  try {
    var res = await api('/projects/' + encodeURIComponent(from) + '/reassign', {
      method: 'POST',
      body: JSON.stringify({ toProjectId: to }),
    });
    toast('Moved ' + (res.moved || 0) + ' credential' + (res.moved === 1 ? '' : 's'));
    await loadCredentials();
    loadStats();
  } catch (err) {
    toast('Reassign failed: ' + err.message, 'error');
  }
});

document.getElementById('remove-project-btn').addEventListener('click', async function() {
  var id = document.getElementById('remove-project-select').value;
  if (!id) { toast('Select a project first', 'error'); return; }
  var projName = (projects.find(function(p){ return p.id === id; }) || {}).name || id;
  var ok = await appConfirm(
    'Remove "' + projName + '" from the project list? This only works if no credentials ' +
    'reference it anymore, and cannot be undone from here (you would need to re-add it by ' +
    'tagging a credential with it again).',
    { title: 'Remove project', okLabel: 'Remove', danger: true }
  );
  if (!ok) return;
  try {
    await api('/projects/' + encodeURIComponent(id), { method: 'DELETE' });
    toast('"' + projName + '" removed — no longer selectable for tagging');
    await loadProjects();
  } catch (err) {
    toast('Could not remove: ' + err.message, 'error');
  }
});

var batchMode = 'simple';
function setBatchMode(mode) {
  batchMode = mode;
  var tabs = document.querySelectorAll('[data-batch-mode]');
  for (var i = 0; i < tabs.length; i++) {
    tabs[i].classList.toggle('active', tabs[i].getAttribute('data-batch-mode') === mode);
  }
  document.getElementById('batch-hint-simple').style.display  = mode === 'simple'  ? '' : 'none';
  document.getElementById('batch-hint-wallets').style.display = mode === 'wallets' ? '' : 'none';
  var ta = document.getElementById('batch-textarea');
  if (mode === 'wallets') {
    ta.placeholder = '[\n  {"name":"WALLET_MAIN","chain":"ethereum","address":"0x…","privateKey":"0x…","seedPhrase":"word1 word2 …"},\n  {"name":"WALLET_COLD","chain":"bitcoin","address":"bc1…","xpub":"xpub…","seedPhrase":"…"}\n]';
  } else {
    ta.placeholder = 'ACME_API_KEY=sk-...\nCF_ZONE_ID=abc123\n\nor\n[{"name":"X","value":"y","project":"global"}]';
  }
  scheduleBatchPreview();
}
(function wireBatchModeTabs() {
  var tabs = document.querySelectorAll('[data-batch-mode]');
  for (var i = 0; i < tabs.length; i++) {
    (function(tab) {
      tab.addEventListener('click', function() { setBatchMode(tab.getAttribute('data-batch-mode')); });
    })(tabs[i]);
  }
})();

function openBatchModal() {
  document.getElementById('batch-textarea').value = '';
  document.getElementById('batch-result').textContent = '';
  document.getElementById('batch-preview').style.display = 'none';
  setBatchMode('simple');
  openModal($batchModal);
}
document.getElementById('batch-import-btn').addEventListener('click', openBatchModal);
// Top-level header button — same handler so users don't have to dig through Settings
var $batchAddTopBtn = document.getElementById('batch-add-btn');
if ($batchAddTopBtn) $batchAddTopBtn.addEventListener('click', openBatchModal);
document.getElementById('batch-close').addEventListener('click',  function() { closeModal($batchModal); });
document.getElementById('batch-cancel').addEventListener('click', function() { closeModal($batchModal); });
$batchModal.addEventListener('click', function(e) { if (e.target === $batchModal) closeModal($batchModal); });

// Wallet-batch keys forwarded verbatim so each wallet lands as one
// structured entry (address + privateKey + seedPhrase as sub-credentials).
var BATCH_WALLET_KEYS = ['chain','walletType','address','publicKey','privateKey',
  'seedPhrase','seed','mnemonic','recoveryPhrase','derivationPath','xpub','zpub','purpose'];

// Shared by both the live dry-run preview and the real Import button —
// one parser, so the preview can never drift from what actually gets sent.
function parseBatchInput(text, mode, defaultProj) {
  var items = [];
  try {
    var parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) return { items: [], error: 'JSON must be an array of items' };
    items = parsed.map(function(it) {
      var out = {
        name: it.name,
        project: it.project || defaultProj || undefined,
        category: it.category,
        description: it.description,
        notes: it.notes,
        url: it.url,
        sensitivity: it.sensitivity,
        tags: it.tags,
      };
      // Pass through exactly one value-shape: fields[], wallet keys, or flat value.
      if (Array.isArray(it.fields)) out.fields = it.fields;
      for (var wi = 0; wi < BATCH_WALLET_KEYS.length; wi++) {
        if (it[BATCH_WALLET_KEYS[wi]] != null) out[BATCH_WALLET_KEYS[wi]] = it[BATCH_WALLET_KEYS[wi]];
      }
      if (it.value != null) out.value = it.value;
      return out;
    });
    return { items: items, error: null };
  } catch (e) {
    if (mode === 'wallets') {
      return { items: [], error: 'Wallet batch requires a JSON array. See the format hint above.' };
    }
    // Not JSON — parse KEY=value lines
    var lines = text.split(/\r?\n/);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i].trim();
      if (!line || line.charAt(0) === '#') continue;
      var m = line.match(/^([A-Za-z][A-Za-z0-9_]*)\s*=\s*(.+)$/);
      if (!m) continue;
      var val = m[2].trim();
      // Strip surrounding quotes
      if ((val.charAt(0) === '"' && val.charAt(val.length - 1) === '"') ||
          (val.charAt(0) === "'" && val.charAt(val.length - 1) === "'")) {
        val = val.slice(1, -1);
      }
      items.push({ name: m[1], value: val, project: defaultProj || undefined });
    }
    return { items: items, error: null };
  }
}

// ─── Live dry-run preview — "N will be added · M duplicates · K conflicts" ─
var batchPreviewTimeout = null;
function scheduleBatchPreview() {
  clearTimeout(batchPreviewTimeout);
  batchPreviewTimeout = setTimeout(runBatchPreview, 350);
}
async function runBatchPreview() {
  var $preview = document.getElementById('batch-preview');
  if (!$preview) return;
  var text = document.getElementById('batch-textarea').value.trim();
  var defaultProj = document.getElementById('batch-project').value || '';
  if (!text) { $preview.textContent = ''; $preview.style.display = 'none'; return; }

  var parsed = parseBatchInput(text, batchMode, defaultProj);
  if (parsed.error) { $preview.textContent = parsed.error; $preview.style.display = ''; return; }
  if (!parsed.items.length) { $preview.textContent = 'No valid items found.'; $preview.style.display = ''; return; }

  try {
    var res = await api('/credentials/batch', {
      method: 'POST',
      body: JSON.stringify({ credentials: parsed.items, defaultProject: defaultProj || undefined, dryRun: true }),
    });
    var parts = [];
    parts.push('<strong style="color:var(--accent)">' + (res.added || 0) + '</strong> will be added');
    if (res.skipped)   parts.push('<strong style="color:var(--warning)">' + res.skipped + '</strong> skipped as duplicates');
    if (res.conflicts) parts.push('<strong style="color:var(--danger)">' + res.conflicts + '</strong> conflict' + (res.conflicts === 1 ? '' : 's'));
    if (res.errors)    parts.push('<strong style="color:var(--danger)">' + res.errors + '</strong> invalid');
    $preview.innerHTML = parts.join(' &middot; '); // safe — only our own counts/labels, no user text
    $preview.style.display = '';
  } catch (err) {
    $preview.textContent = 'Preview failed: ' + err.message;
    $preview.style.display = '';
  }
}
document.getElementById('batch-textarea').addEventListener('input', scheduleBatchPreview);
document.getElementById('batch-project').addEventListener('change', scheduleBatchPreview);

document.getElementById('batch-submit').addEventListener('click', async function() {
  var text = document.getElementById('batch-textarea').value.trim();
  var defaultProj = document.getElementById('batch-project').value || '';
  var $result = document.getElementById('batch-result');
  if (!text) { $result.textContent = 'Nothing to import.'; return; }

  var parsed = parseBatchInput(text, batchMode, defaultProj);
  if (parsed.error) { $result.textContent = parsed.error.indexOf('Parse') === 0 ? parsed.error : 'Parse error: ' + parsed.error; return; }
  var items = parsed.items;
  if (!items.length) { $result.textContent = 'No valid items found.'; return; }

  $result.textContent = 'Importing ' + items.length + '…';
  try {
    var res = await api('/credentials/batch', {
      method: 'POST',
      body: JSON.stringify({ credentials: items, defaultProject: defaultProj || undefined }),
    });
    var added = res.added || 0;
    var parts = ['Added ' + added + ' of ' + items.length];
    if (res.skipped)   parts.push(res.skipped + ' skipped (identical)');
    if (res.conflicts) parts.push(res.conflicts + ' conflict(s) — resend with overwrite');
    var msg = parts.join(' · ');
    var failures = res.failures || [];
    if (failures.length) {
      msg += '\n' + failures.slice(0, 6).map(function(f) { return '• ' + (f.name || '?') + ': ' + f.error; }).join('\n');
    }
    $result.style.whiteSpace = 'pre-wrap';
    $result.textContent = msg;
    toast('Imported ' + added + ' credential' + (added === 1 ? '' : 's'));
    document.getElementById('batch-preview').style.display = 'none';
    await loadCredentials();
    loadStats();
  } catch (err) {
    $result.textContent = 'Import failed: ' + err.message;
  }
});

// ─── Boot ──────────────────────────────────────────────────────────────────
init();
