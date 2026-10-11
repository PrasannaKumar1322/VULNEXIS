(() => {
'use strict';

const savedTheme = localStorage.getItem('vulnexis-theme') || localStorage.getItem('qshield-theme') || 'executive';
document.documentElement.setAttribute('data-theme', savedTheme);

/* ======================= helpers ======================= */
const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtBytes = n => n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`;
const fmtDate = iso => { try { return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }); } catch { return iso; } };
const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

const SEV = ['critical', 'high', 'medium', 'low', 'info'];
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const SEV_HELP = {
  critical: 'Breaks under quantum attack or is already broken, and protects keys or data.',
  high: 'Quantum-vulnerable signatures or weak classical algorithms. Plan the fix.',
  medium: 'Weaker than current guidance. Fix during routine upgrades.',
  low: 'Acceptable today with a smaller safety margin.',
  info: 'Quantum-resistant or post-quantum. No action needed.'
};
const LEVEL_LABEL = { none: 'None found', low: 'Low', medium: 'Medium', high: 'High', critical: 'Critical' };
const STATUS_KEYS = ['vulnerable', 'classical', 'weakened', 'resistant', 'pqc'];
const STATUS_LABEL = { vulnerable: 'Quantum-vulnerable', classical: 'Unsafe today', weakened: 'Quantum-weakened', resistant: 'Quantum-resistant', pqc: 'Post-quantum' };
const STATUS_HELP = {
  vulnerable: "Public-key crypto that Shor's algorithm breaks",
  classical: 'Weak or exposed even without quantum computers',
  weakened: "Symmetric crypto with a reduced margin under Grover's algorithm",
  resistant: 'Safe against known quantum attacks',
  pqc: 'Post-quantum algorithms'
};
const IGNORED = ['.git', 'node_modules', '__pycache__', '.venv', 'venv', '.idea', '.vscode'];
const LIMITS = { files: 500, upload: 100 * 1048576 };

const state = {
  list: [], scan: null, totals: { scans: 0, files: 0 },
  filters: { sev: 'all', status: 'all', q: '', surface: 'all', timeframe: 'all' },
  pending: [], uploading: false, uploadError: '', skippedClient: 0
};

/* ======================= API ======================= */
async function api(path, opts) {
  const r = await fetch(path, opts);
  let body = null;
  try { body = await r.json(); } catch { /* not json */ }
  if (!r.ok) throw Object.assign(new Error((body && body.error) || `Request failed (${r.status})`), { body });
  return body;
}

async function refreshOverview() {
  const ov = await api('/api/overview');
  state.list = ov.scans;
  state.totals = { scans: ov.scan_count, files: ov.files_scanned_total };
  state.scan = ov.latest;
  syncPicker();
}

async function selectScan(id) {
  state.scan = await api(`/api/scans/${id}`);
  syncPicker();
}

function syncPicker() {
  const picker = $('#scanPicker'), sel = $('#scanSelect');
  picker.hidden = state.list.length === 0;
  sel.innerHTML = state.list.map(s => `<option value="${s.id}">${esc(s.label)} (${esc(fmtDate(s.created_at))})</option>`).join('');
  if (state.scan) sel.value = String(state.scan.id);
}

/* ======================= UI pieces ======================= */
let toastTimer;
function toast(msg, isErr) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'show' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = ''; }, 4200);
}

const sevBadge = s => `<span class="badge sev-${s}">${SEV_LABEL[s]}</span>`;
const statusBadge = (s, label) => `<span class="badge st-${s}">${esc(label || STATUS_LABEL[s])}</span>`;
const levelBadge = l => `<span class="badge lv-${l}">${LEVEL_LABEL[l]}</span>`;
const confBadge = c => {
  const label = c === 'confirmed' ? 'Confirmed' : (c === 'inferred' ? 'Inferred' : 'Text match');
  const cls = c === 'confirmed' ? 'st-pqc' : (c === 'inferred' ? 'st-weakened' : 'st-classical');
  return `<span class="badge ${cls}" title="Confidence level: ${label}">${label}</span>`;
};
const qClassBadge = c => {
  if (c === 'quantum-vulnerable') return `<span class="badge st-vulnerable">Quantum-vulnerable</span>`;
  if (c === 'quantum-resistant') return `<span class="badge st-resistant">Quantum-resistant</span>`;
  return `<span class="badge st-unclassified">Not yet confidently classified</span>`;
};
const exploitableBadge = (exp, label) => {
  if (exp) return `<span class="badge st-classical" style="--c:var(--critical)">Actively Exploitable Today</span>`;
  return `<span class="badge st-resistant" style="--c:var(--low)">${esc(label || 'Classically Secure')}</span>`;
};
const scoreBadge = (s, l) => {
  const band = l || (s >= 80 ? 'critical' : (s >= 60 ? 'high' : (s >= 30 ? 'medium' : 'low')));
  return `<span class="badge lv-${band}" title="Prioritisation score: ${s}/100 (${LEVEL_LABEL[band] || band})">Score: ${s !== undefined ? s : '-'}/100</span>`;
};

function pageHead(title, desc, actions = '') {
  return `<div class="page-head"><div><h2>${esc(title)}</h2><p>${esc(desc)}</p></div><div class="actions">${actions}</div></div>`;
}

function emptyState(title, text, cta = true) {
  return `<div class="empty">
    <svg viewBox="0 0 64 64" aria-hidden="true"><path d="M32 6 10 14v16c0 14 9 24 22 28 13-4 22-14 22-28V14L32 6Z"/><path d="M24 32h16M32 24v16" opacity=".6"/></svg>
    <h3>${esc(title)}</h3><p>${esc(text)}</p>
    ${cta ? '<a class="btn primary" href="#/upload">Upload files to scan</a>' : ''}
  </div>`;
}

const noScan = () => emptyState('No scan results yet', 'Upload source code, config files, certificates, keys or a .zip archive. VULNEXIS lists the cryptographic algorithms it finds and how exposed each one is to quantum attacks.');

function statCard(label, value, hint, tone, toneText) {
  return `<div class="stat" style="--tone:${tone};${toneText ? `--tone-text:${toneText};` : ''}">
    <div class="label">${esc(label)}</div><div class="value">${esc(value)}</div><div class="hint">${esc(hint)}</div></div>`;
}

function scanBanner(sc) {
  const s = sc.summary;
  return `<div class="banner"><strong>${esc(sc.label)}</strong>
    <span>Scanned ${esc(fmtDate(sc.created_at))}</span>
    <span>${plural(s.files_scanned, 'file')} (${fmtBytes(s.bytes_scanned)}) in ${sc.duration_ms} ms</span>
    ${s.files_skipped ? `<span>${plural(s.files_skipped, 'file')} not inspected</span>` : ''}
    ${levelBadge(s.risk_level)}</div>` +
    (sc.notes || []).map(n => `<div class="note">${esc(n)}</div>`).join('');
}

/* ---------- charts (plain SVG, no libraries) ---------- */
function ring(score, level) {
  const ticks = 60; let s = '';
  const on = Math.round(score / 100 * ticks);
  for (let i = 0; i < ticks; i++) {
    const a = (-90 + i * 360 / ticks) * Math.PI / 180;
    const x1 = 100 + 74 * Math.cos(a), y1 = 100 + 74 * Math.sin(a), x2 = 100 + 92 * Math.cos(a), y2 = 100 + 92 * Math.sin(a);
    s += `<line x1="${x1.toFixed(2)}" y1="${y1.toFixed(2)}" x2="${x2.toFixed(2)}" y2="${y2.toFixed(2)}" class="tick${i < on ? ' on' : ''}" style="--i:${i}"/>`;
  }
  return `<svg class="ring lv-${level}" viewBox="0 0 200 200" role="img" aria-label="Risk score ${score} out of 100, ${LEVEL_LABEL[level]}">${s}
    <text x="100" y="108" class="ring-num" text-anchor="middle">${score}</text>
    <text x="100" y="132" class="ring-sub" text-anchor="middle">${LEVEL_LABEL[level]}</text></svg>`;
}

function donut(counts) {
  const total = SEV.reduce((a, k) => a + (counts[k] || 0), 0);
  const r = 52, C = 2 * Math.PI * r; let off = 0, segs = '';
  SEV.forEach(k => {
    const n = counts[k] || 0; if (!n) return;
    const len = n / total * C;
    segs += `<circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--${k})" stroke-width="18" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-off).toFixed(2)}" transform="rotate(-90 70 70)"/>`;
    off += len;
  });
  const legend = SEV.map(k => `<li class="sev-${k}"><i></i>${SEV_LABEL[k]}<b>${counts[k] || 0}</b></li>`).join('');
  return `<div class="donut-wrap"><svg class="donut" viewBox="0 0 140 140" role="img" aria-label="${total} findings by severity">
    <circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--line-soft)" stroke-width="18"/>${segs}
    <text x="70" y="68" text-anchor="middle" font-size="26" font-weight="800">${total}</text>
    <text x="70" y="86" text-anchor="middle" font-size="11" fill="var(--muted)" style="fill:var(--muted)">findings</text></svg>
    <ul class="legend">${legend}</ul></div>`;
}

function stacked(counts) {
  const total = STATUS_KEYS.reduce((a, k) => a + (counts[k] || 0), 0) || 1;
  const segs = STATUS_KEYS.filter(k => counts[k]).map(k => `<span class="st-${k}" style="width:${counts[k] / total * 100}%" title="${STATUS_LABEL[k]}: ${counts[k]}"></span>`).join('');
  const legend = STATUS_KEYS.map(k => `<li class="st-${k}"><i></i><span>${STATUS_LABEL[k]}<br><small class="muted">${STATUS_HELP[k]}</small></span><b>${counts[k] || 0}</b></li>`).join('');
  return `<div class="stack" role="img" aria-label="Findings by quantum status">${segs}</div><ul class="legend">${legend}</ul>`;
}

function bars(rows, max, color) {
  return `<div class="bars">${rows.map(r => `<div class="bar-row"><span class="name" title="${esc(r.name)}">${esc(r.name)}</span>
    <div class="track"><span style="width:${Math.max(3, r.value / max * 100)}%;--c:${r.color || color || 'var(--accent)'}"></span></div>
    <span class="num">${r.label ?? r.value}</span></div>`).join('')}</div>`;
}

function lineChart(points) {
  const W = 560, H = 190, pl = 34, pr = 14, pt = 14, pb = 28;
  const x = i => pl + (points.length === 1 ? (W - pl - pr) / 2 : i * (W - pl - pr) / (points.length - 1));
  const y = v => pt + (100 - v) / 100 * (H - pt - pb);
  const grid = [0, 25, 50, 75, 100].map(v => `<line x1="${pl}" x2="${W - pr}" y1="${y(v)}" y2="${y(v)}" stroke="var(--line-soft)"/><text x="${pl - 8}" y="${y(v) + 4}" text-anchor="end">${v}</text>`).join('');
  const path = points.map((p, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(p.score).toFixed(1)}`).join(' ');
  const dots = points.map((p, i) => `<circle cx="${x(i).toFixed(1)}" cy="${y(p.score).toFixed(1)}" r="4.5" fill="var(--bg)" stroke="var(--accent)" stroke-width="2"><title>${esc(p.label)}: ${p.score}</title></circle>`).join('');
  const first = points[0], last = points[points.length - 1];
  return `<svg class="line-chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk score across ${points.length} scans">${grid}
    <path d="${path}" fill="none" stroke="var(--accent)" stroke-width="2.4" stroke-linejoin="round"/>${dots}
    <text x="${x(0)}" y="${H - 8}" text-anchor="${points.length > 1 ? 'start' : 'middle'}">${esc(first.short)}</text>
    ${points.length > 1 ? `<text x="${x(points.length - 1)}" y="${H - 8}" text-anchor="end">${esc(last.short)}</text>` : ''}</svg>`;
}

/* ======================= views ======================= */
const views = {};

views.overview = el => {
  const sc = state.scan;
  el.innerHTML = pageHead('Overview', 'A snapshot of cryptographic exposure in the selected scan.',
    sc ? `<a class="btn" href="/api/scans/${sc.id}/report.pdf" download>Download PDF report</a>` : '');
  if (!sc) { el.insertAdjacentHTML('beforeend', noScan()); return; }
  const s = sc.summary;
  const mPlan = sc.monday_morning_plan || {};
  const mSummary = mPlan.summary || {
    immediate_attention_count: (sc.findings || []).filter(f => (f.risk_score || 0) >= 80).length,
    this_week_count: (sc.findings || []).filter(f => (f.risk_score || 0) >= 60 && (f.risk_score || 0) < 80).length,
    planned_migration_count: (sc.findings || []).filter(f => (f.risk_score || 0) >= 30 && (f.risk_score || 0) < 60).length,
    monitor_and_maintain_count: (sc.findings || []).filter(f => (f.risk_score || 0) < 30).length,
  };

  el.insertAdjacentHTML('beforeend', scanBanner(sc) + `
    <div class="grid g-4">
      ${statCard('Files scanned', s.files_scanned, `${fmtBytes(s.bytes_scanned)} inspected. ${plural(state.totals.scans, 'scan')} and ${plural(state.totals.files, 'file')} in history.`, 'var(--accent)')}
      ${statCard('Algorithms detected', s.algorithms_detected, `${plural(s.occurrences_total, 'use')} across ${plural(s.findings_total, 'finding')}`, 'var(--low)')}
      ${statCard('Critical findings', s.critical_findings, `${s.severity_counts.high} high, ${s.severity_counts.medium} medium, ${s.severity_counts.low} low`, 'var(--critical)', s.critical_findings ? 'var(--critical)' : '')}
      ${statCard('Quantum-vulnerable assets', s.quantum_vulnerable_assets, "File and algorithm pairs that Shor's algorithm can break", 'var(--high)', s.quantum_vulnerable_assets ? 'var(--high)' : '')}
    </div>`);

  if (!s.findings_total) {
    el.insertAdjacentHTML('beforeend', `<div class="panel"><h3>No cryptographic algorithms detected</h3>
      <p class="sub">VULNEXIS checked ${plural(s.files_scanned, 'file')} and found no algorithm names, certificates or keys. It reads text files and certificates, so encrypted or compiled content is not inspected.</p></div>`);
    return;
  }

  // Monday Morning Action Plan Spotlight
  el.insertAdjacentHTML('beforeend', `
    <section class="panel" style="margin-bottom:16px;border-left:4px solid var(--accent)">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px;margin-bottom:12px">
        <div>
          <h3 style="margin:0 0 4px">Monday Morning Action Plan &bull; What to Fix First</h3>
          <p class="sub" style="margin:0">Prioritised remediation queue grouped by urgency with assigned roles, prerequisites, and validation tests.</p>
        </div>
        <a class="btn primary" href="#/fixfirst">Open Action Plan &rarr;</a>
      </div>
      <div class="grid g-4" style="margin-bottom:0">
        <div class="stat" style="--tone:var(--critical);--tone-text:var(--critical)">
          <div class="label">Immediate Attention</div>
          <div class="value">${mSummary.immediate_attention_count}</div>
          <div class="hint">Score 80–100 &bull; Next 24–48h</div>
        </div>
        <div class="stat" style="--tone:var(--high);--tone-text:var(--high)">
          <div class="label">This Week</div>
          <div class="value">${mSummary.this_week_count}</div>
          <div class="hint">Score 60–79 &bull; Current sprint</div>
        </div>
        <div class="stat" style="--tone:var(--medium)">
          <div class="label">Planned Migration</div>
          <div class="value">${mSummary.planned_migration_count}</div>
          <div class="hint">Score 30–59 &bull; Next release</div>
        </div>
        <div class="stat" style="--tone:var(--low)">
          <div class="label">Monitor &amp; Maintain</div>
          <div class="value">${mSummary.monitor_and_maintain_count}</div>
          <div class="hint">Score 0–29 &bull; Routine review</div>
        </div>
      </div>
    </section>`);

  const algoRows = sc.algorithms.slice(0, 8).map(a => ({ name: a.name, value: a.occurrences, color: `var(--${a.severity})` }));
  const maxA = Math.max(...algoRows.map(r => r.value));
  const fileRows = sc.files.slice(0, 6);
  el.insertAdjacentHTML('beforeend', `
    <div class="grid g-3">
      <section class="panel"><h3>Risk score</h3><p class="sub">Combined exposure for this scan.</p>
        <div class="ring-wrap">${ring(s.risk_score, s.risk_level)}</div></section>
      <section class="panel"><h3>Findings by severity</h3><p class="sub">Each finding is one algorithm in one file.</p>${donut(s.severity_counts)}</section>
      <section class="panel"><h3>Quantum exposure</h3><p class="sub">How findings hold up against quantum attacks.</p>${stacked(s.status_counts)}</section>
    </div>
    <div class="grid g-21">
      <section class="panel"><h3>Algorithms detected</h3><p class="sub">Number of uses, colored by severity.</p>${bars(algoRows, maxA)}</section>
      <section class="panel"><h3>Most exposed files</h3><p class="sub">Ranked by risk points.</p>
        <div class="table-wrap"><table><caption class="sr">Most exposed files</caption><thead><tr><th>File</th><th>Risk</th><th class="num">Findings</th></tr></thead><tbody>
        ${fileRows.map(f => `<tr><td><span class="path">${esc(f.name)}</span></td><td>${levelBadge(f.level)}</td><td class="num">${f.findings}</td></tr>`).join('')}
        </tbody></table></div>
        ${sc.files.length > fileRows.length ? `<p class="sub" style="margin:10px 0 0">Showing ${fileRows.length} of ${sc.files.length}. See the Risk score page for all files.</p>` : ''}</section>
    </div>`);
};

/* ---------- What to fix first (Monday Morning Action Plan) ---------- */
views.fixfirst = el => {
  const sc = state.scan;
  el.innerHTML = pageHead('What to fix first', 'Monday Morning Action Plan: Prioritised remediation queue with owner roles, prerequisites, validation tests, and concrete next actions.',
    sc ? `<a class="btn" href="/api/scans/${sc.id}/report.pdf" download>Download PDF report</a>` : '');
  if (!sc) { el.insertAdjacentHTML('beforeend', noScan()); return; }
  el.insertAdjacentHTML('beforeend', scanBanner(sc));
  if (!sc.findings || !sc.findings.length) {
    el.insertAdjacentHTML('beforeend', `<div class="panel"><h3>No cryptographic algorithms detected</h3><p class="sub">Nothing to prioritize in the ${plural(sc.summary.files_scanned, 'file')} scanned.</p></div>`);
    return;
  }

  const mPlan = sc.monday_morning_plan || {};
  const buckets = mPlan.buckets || [];
  const queue = sc.remediation_queue || [];
  const dedup = sc.deduplicated_issues || [];

  const totalFindings = sc.findings.length;
  const sourceCount = sc.findings.filter(f => (f.scan_surface || 'source_code') === 'source_code').length;
  const tlsCount = sc.findings.filter(f => f.scan_surface === 'live_tls').length;

  let currentSurface = state.filters.surface || 'all';

  const renderContent = () => {
    const summary = mPlan.summary || {
      immediate_attention_count: sc.findings.filter(f => (f.risk_score || 0) >= 80).length,
      this_week_count: sc.findings.filter(f => (f.risk_score || 0) >= 60 && (f.risk_score || 0) < 80).length,
      planned_migration_count: sc.findings.filter(f => (f.risk_score || 0) >= 30 && (f.risk_score || 0) < 60).length,
      monitor_and_maintain_count: sc.findings.filter(f => (f.risk_score || 0) < 30).length,
    };

    let html = `
      <div class="disclaimer-box" style="margin-bottom:16px">
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
        <span><strong>Triage Prioritisation Notice:</strong> Findings are sorted primarily by Risk Score (0–100), with ties broken by <em>Confidentiality Lifetime descending</em> (higher HNDL exposure) followed by <em>Asset Exposure descending</em> (internet-facing before internal). These rankings guide engineering execution and do not represent mathematical certainty of immediate compromise.</span>
      </div>

      <div class="grid g-4">
        ${statCard('Immediate attention', summary.immediate_attention_count, 'Score 80–100 &bull; Next 24–48 Hours', 'var(--critical)', summary.immediate_attention_count ? 'var(--critical)' : '')}
        ${statCard('This week', summary.this_week_count, 'Score 60–79 &bull; Current Sprint', 'var(--high)', summary.this_week_count ? 'var(--high)' : '')}
        ${statCard('Planned migration', summary.planned_migration_count, 'Score 30–59 &bull; Next Release Cycle', 'var(--medium)')}
        ${statCard('Monitor & maintain', summary.monitor_and_maintain_count, 'Score 0–29 &bull; Routine Review', 'var(--low)')}
      </div>

      <div class="toolbar" style="margin-bottom:20px">
        <span style="font-size:13px;font-weight:700;color:var(--muted)">Filter by scan surface:</span>
        <div class="chips" role="group" aria-label="Filter by surface">
          <button class="chip" data-surf="all" aria-pressed="${currentSurface === 'all'}">All surfaces (${totalFindings})</button>
          <button class="chip" data-surf="source_code" aria-pressed="${currentSurface === 'source_code'}">Source Code (${sourceCount})</button>
          <button class="chip" data-surf="live_tls" aria-pressed="${currentSurface === 'live_tls'}">Live TLS (${tlsCount})</button>
        </div>
      </div>`;

    // 2. Action Buckets
    html += `<h3 style="margin:24px 0 12px;font-size:18px">Actionable Remediation Buckets</h3>`;

    buckets.forEach(b => {
      const items = (b.items || []).filter(it => currentSurface === 'all' || (it.scan_surface || 'source_code') === currentSurface);
      const bColor = b.priority_level === 'critical' ? 'critical' : (b.priority_level === 'high' ? 'high' : (b.priority_level === 'medium' ? 'medium' : 'low'));
      const prereqs = Array.isArray(b.prerequisites) ? b.prerequisites : [b.prerequisites].filter(Boolean);
      const tests = Array.isArray(b.validation_tests) ? b.validation_tests : [b.validation_tests].filter(Boolean);

      html += `
        <div class="action-bucket bucket-${bColor}">
          <div class="bucket-head">
            <h4 class="bucket-title">
              <span class="badge lv-${bColor}">${esc(b.title)}</span>
              <span>${esc(b.timeframe)}</span>
              <span class="muted" style="font-size:13px">(${plural(items.length, 'finding')})</span>
            </h4>
            <span class="owner-tag">👤 Target Owner: ${esc(b.owner_role)}</span>
          </div>
          <div class="bucket-body">
            <div class="bucket-meta-grid">
              <div class="bucket-meta-card">
                <h6>Priority Rationale</h6>
                <p>${esc(b.rationale)}</p>
              </div>
              <div class="bucket-meta-card">
                <h6>Prerequisites</h6>
                <ul>${prereqs.map(p => `<li>${esc(p)}</li>`).join('')}</ul>
              </div>
              <div class="bucket-meta-card">
                <h6>Validation Tests</h6>
                <ul>${tests.map(t => `<li>${esc(t)}</li>`).join('')}</ul>
              </div>
              <div class="bucket-meta-card">
                <h6>Expected Outcome</h6>
                <p>${esc(b.expected_outcome)}</p>
              </div>
            </div>

            <div class="next-action-callout">
              <strong>👉 Concrete Next Action:</strong> ${esc(b.concrete_next_action)}
            </div>

            ${items.length ? `
              <div class="bucket-items-list">
                ${items.map(it => `
                  <div class="bucket-item-row">
                    <div class="bucket-item-details">
                      <div class="bucket-item-meta">
                        <strong class="mono" style="color:var(--accent)">${esc(it.priority_rank || ('#' + it.rank))}</strong>
                        <span class="badge ${it.scan_surface === 'live_tls' ? 'st-pqc' : 'st-weakened'}">${it.scan_surface === 'live_tls' ? 'Live TLS' : 'Source Code'}</span>
                        ${scoreBadge(it.risk_score, it.severity_level)}
                        ${it.is_provisional ? '<span class="badge st-unclassified" title="Provisional score calculated using default assumptions">Provisional</span>' : ''}
                        ${it.is_long_lived_sensitive_pki ? '<span class="badge st-vulnerable" title="Long-lived sensitive data on RSA/ECC (HNDL Threat)">⚠️ HNDL Target</span>' : ''}
                      </div>
                      <div style="margin-top:4px">
                        <strong>${esc(it.algorithm)}</strong> on <span class="path mono" style="font-size:12.5px">${esc(it.location || it.asset)}</span>
                      </div>
                      <div class="sub" style="font-size:12.5px;color:#c9d4ee;margin-top:2px">
                        <strong>Why it matters:</strong> ${esc(it.why_it_matters)}
                      </div>
                      <div style="font-size:12px;color:var(--muted);margin-top:2px">
                        <strong>Target:</strong> <span class="mono" style="color:#e2e8f0">${esc(it.recommended_migration)}</span> | <strong>Next Action:</strong> ${esc(it.concrete_next_action)}
                      </div>
                    </div>
                  </div>
                `).join('')}
              </div>
            ` : `<p class="muted" style="font-size:13px;margin:8px 0 0">No findings matching the surface filter in this bucket.</p>`}
          </div>
        </div>`;
    });

    // 3. Prioritised Remediation Queue Table with Tie-Breakers
    const filteredQueue = queue.filter(it => currentSurface === 'all' || (it.scan_surface || 'source_code') === currentSurface);
    html += `
      <section class="panel" style="margin-top:28px">
        <div style="display:flex;justify-content:space-between;align-items:flex-end;margin-bottom:12px;flex-wrap:wrap;gap:8px">
          <div>
            <h3 style="margin:0 0 4px">Prioritised Remediation Queue</h3>
            <p class="sub" style="margin:0">Ranked by Risk Score (descending), Tie-breaker 1: Confidentiality Lifetime (descending), Tie-breaker 2: Asset Exposure (descending).</p>
          </div>
          <span class="muted" style="font-size:13px">${plural(filteredQueue.length, 'item')}</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Rank</th>
                <th>Score</th>
                <th>Severity</th>
                <th>Timeframe</th>
                <th>Surface</th>
                <th>Asset / Location</th>
                <th>Algorithm</th>
                <th>Lifetime (TB1)</th>
                <th>Exposure (TB2)</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${filteredQueue.length ? filteredQueue.map(q => {
                const sLevel = q.severity_level || (q.risk_score >= 80 ? 'critical' : (q.risk_score >= 60 ? 'high' : (q.risk_score >= 30 ? 'medium' : 'low')));
                const tb1 = q.factor_scores && q.factor_scores.confidentiality_lifetime !== undefined ? `${q.factor_scores.confidentiality_lifetime} pts` : '-';
                const tb2 = q.factor_scores && q.factor_scores.asset_exposure !== undefined ? `${q.factor_scores.asset_exposure} pts` : '-';
                return `
                  <tr>
                    <td><strong class="mono" style="color:var(--accent)">${esc(q.priority_rank || ('#' + q.rank))}</strong></td>
                    <td>${scoreBadge(q.risk_score, sLevel)}</td>
                    <td>${sevBadge(sLevel)}</td>
                    <td><span style="font-size:12.5px;font-weight:600">${esc(q.remediation_timeframe || '-')}</span></td>
                    <td><span class="badge ${q.scan_surface === 'live_tls' ? 'st-pqc' : 'st-weakened'}">${q.scan_surface === 'live_tls' ? 'Live TLS' : 'Source Code'}</span></td>
                    <td><span class="path mono" style="font-size:12px">${esc(q.location || q.asset)}</span></td>
                    <td><strong>${esc(q.algorithm)}</strong></td>
                    <td class="mono" style="font-size:12px">${tb1}</td>
                    <td class="mono" style="font-size:12px">${tb2}</td>
                    <td>${q.is_provisional ? '<span class="badge st-unclassified" title="Provisional default assumption">Provisional</span>' : '<span class="badge st-resistant">Confirmed</span>'}</td>
                  </tr>`;
              }).join('') : `<tr><td colspan="10" class="muted" style="text-align:center;padding:24px">No items match the filter.</td></tr>`}
            </tbody>
          </table>
        </div>
      </section>`;

    // 4. Correlated & Deduplicated Issues
    if (dedup.length) {
      html += `
        <section class="panel" style="margin-top:20px">
          <div style="margin-bottom:12px">
            <h3 style="margin:0 0 4px">Correlated &amp; Deduplicated Assets</h3>
            <p class="sub" style="margin:0">Consolidated by asset and cryptographic primitive across scan surfaces to prevent alert fatigue.</p>
          </div>
          <div class="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Surface</th>
                  <th>Algorithm</th>
                  <th>Max Score</th>
                  <th>Severity</th>
                  <th>Findings</th>
                  <th>Uses</th>
                  <th>Recommended Target</th>
                </tr>
              </thead>
              <tbody>
                ${dedup.map(d => `
                  <tr>
                    <td><span class="path mono" style="font-size:12px">${esc(d.asset)}</span></td>
                    <td><span class="badge ${d.scan_surface === 'live_tls' ? 'st-pqc' : 'st-weakened'}">${d.scan_surface === 'live_tls' ? 'Live TLS' : 'Source Code'}</span></td>
                    <td><strong>${esc(d.algorithm)}</strong></td>
                    <td>${scoreBadge(d.max_risk_score, d.severity_level)}</td>
                    <td>${sevBadge(d.severity_level)}</td>
                    <td class="num">${d.findings_count}</td>
                    <td class="num">${d.total_occurrences}</td>
                    <td style="font-size:12.5px">${esc(d.recommended_migration)}</td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          </div>
        </section>`;
    }

    let dynContainer = $('#fixfirstDynamic', el);
    if (dynContainer) dynContainer.innerHTML = html;
    else el.insertAdjacentHTML('beforeend', `<div id="fixfirstDynamic">${html}</div>`);

    $$('.chip[data-surf]', el).forEach(btn => {
      btn.onclick = () => {
        currentSurface = btn.dataset.surf;
        state.filters.surface = currentSurface;
        renderContent();
      };
    });
  };

  renderContent();
};

/* ---------- Upload ---------- */
views.upload = el => {
  el.innerHTML = pageHead('Upload and scan', 'Send files to the VULNEXIS backend for analysis. Files are read in memory and never stored or run.') + `
    <div class="dropzone" id="dz" role="button" tabindex="0" aria-label="Drop files or folders here, or press Enter to choose files">
      <svg viewBox="0 0 48 48" aria-hidden="true"><path d="M24 32V8m0 0-9 9m9-9 9 9"/><path d="M8 30v8a2 2 0 0 0 2 2h28a2 2 0 0 0 2-2v-8"/></svg>
      <strong>Drag and drop files or a folder here</strong>
      <p>Source code, configuration, certificates (.pem, .crt, .cer, .der), public and private keys, scripts and .zip or .tar archives.</p>
      <div class="dz-actions">
        <button type="button" class="btn" id="pickFiles">Choose files</button>
        <button type="button" class="btn" id="pickFolder">Choose folder</button>
      </div>
    </div>
    <input type="file" id="fileInput" multiple hidden>
    <input type="file" id="folderInput" webkitdirectory hidden>
    <p class="limits">Limits: ${LIMITS.files} files per scan, 5 MB per file, 100 MB in total. Archives are opened in memory. Folders such as .git and node_modules are skipped.</p>
    <div class="queue" id="queue"></div>`;
  const dz = $('#dz');
  const fileInput = $('#fileInput'), folderInput = $('#folderInput');
  $('#pickFiles').onclick = e => { e.stopPropagation(); fileInput.click(); };
  $('#pickFolder').onclick = e => { e.stopPropagation(); folderInput.click(); };
  dz.onclick = () => fileInput.click();
  dz.onkeydown = e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } };
  fileInput.onchange = () => { addFiles([...fileInput.files].map(f => ({ file: f, path: f.webkitRelativePath || f.name }))); fileInput.value = ''; };
  folderInput.onchange = () => { addFiles([...folderInput.files].map(f => ({ file: f, path: f.webkitRelativePath || f.name }))); folderInput.value = ''; };
  ['dragenter', 'dragover'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.add('over'); }));
  ['dragleave', 'drop'].forEach(t => dz.addEventListener(t, e => { e.preventDefault(); dz.classList.remove('over'); }));
  dz.addEventListener('drop', async e => {
    const dt = e.dataTransfer;
    // Entries must be read synchronously, before any await.
    const entries = dt.items ? [...dt.items].map(i => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean) : [];
    let found = [];
    if (entries.length) { for (const en of entries) await walk(en, found, 0); }
    else found = [...dt.files].map(f => ({ file: f, path: f.name }));
    addFiles(found);
  });
  renderQueue();
};

async function walk(entry, out, depth) {
  if (entry.isFile) {
    const file = await new Promise((res, rej) => entry.file(res, rej));
    out.push({ file, path: entry.fullPath.replace(/^\//, '') });
  } else if (entry.isDirectory && depth < 25) {
    if (IGNORED.includes(entry.name)) { state.skippedClient++; return; }
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise((res, rej) => reader.readEntries(res, rej));
      for (const c of batch) await walk(c, out, depth + 1);
    } while (batch.length);
  }
}

function addFiles(list) {
  state.uploadError = '';
  const have = new Set(state.pending.map(p => p.path + ':' + p.file.size));
  let ignored = 0;
  for (const it of list) {
    const parts = it.path.split('/');
    if (parts.slice(0, -1).some(p => IGNORED.includes(p))) { ignored++; continue; }
    const key = it.path + ':' + it.file.size;
    if (!have.has(key)) { state.pending.push(it); have.add(key); }
  }
  if (ignored) state.skippedClient += ignored;
  renderQueue();
}

function renderQueue() {
  const q = $('#queue'); if (!q) return;
  const n = state.pending.length;
  if (!n && !state.uploading) {
    q.innerHTML = state.uploadError ? `<div class="error-box" role="alert">${esc(state.uploadError)}</div>` : '';
    return;
  }
  const total = state.pending.reduce((a, p) => a + p.file.size, 0);
  const over = n > LIMITS.files || total > LIMITS.upload;
  q.innerHTML = `
    <div class="queue-list" role="list">${state.pending.slice(0, 300).map((p, i) => `<div role="listitem"><span class="path" title="${esc(p.path)}">${esc(p.path)}</span><span class="size">${fmtBytes(p.file.size)}</span><button type="button" data-rm="${i}" aria-label="Remove ${esc(p.path)}" ${state.uploading ? 'disabled' : ''}>Remove</button></div>`).join('')}
    ${n > 300 ? `<div><span class="path muted">and ${n - 300} more</span></div>` : ''}</div>
    <p class="status-line">${plural(n, 'file')} ready, ${fmtBytes(total)} in total.${state.skippedClient ? ` ${plural(state.skippedClient, 'file')} in ignored folders left out.` : ''}
    ${over ? '<strong style="color:var(--critical)"> This is over the upload limit. Remove files or upload a .zip.</strong>' : ''}</p>
    <div class="scan-form">
      <label>Scan name (optional)<input type="text" id="scanName" maxlength="80" placeholder="For example: payment-service, main branch" ${state.uploading ? 'disabled' : ''}></label>
      <button class="btn" type="button" id="clearQueue" ${state.uploading ? 'disabled' : ''}>Clear list</button>
      <button class="btn primary" type="button" id="runScan" ${state.uploading || over ? 'disabled' : ''}>${state.uploading ? 'Scanning' : 'Run scan'}</button>
    </div>
    <details class="explain" style="margin-top:14px">
      <summary>Asset Environment Context (Optional for Prioritisation Scoring)</summary>
      <p style="margin-bottom:8px">When left as "Auto-detect", VULNEXIS will attempt to infer sensitivity, retention, and network exposure from file names and code patterns, or mark unknown factors without making unconfirmed assumptions.</p>
      <div class="context-fields" style="margin-top:10px">
        <label>Data Sensitivity
          <select id="scanSensitivity">
            <option value="">Auto-detect / Unknown</option>
            <option value="highly_sensitive">Highly Sensitive (Credentials, Keys, PII)</option>
            <option value="confidential">Confidential (Business / Customer Data)</option>
            <option value="internal">Internal (Operational Internal Data)</option>
            <option value="public">Public (Non-sensitive / Test Data)</option>
          </select>
        </label>
        <label>Confidentiality Lifetime
          <select id="scanLifetime">
            <option value="">Auto-detect / Unknown</option>
            <option value="10+_years">10+ Years (Long-term Archival, Root PKI)</option>
            <option value="5-9_years">5–9 Years (Medium-Long Retention)</option>
            <option value="1-4_years">1–4 Years (Standard Operational Data)</option>
            <option value="<1_year">&lt; 1 Year (Ephemeral Session Transit)</option>
          </select>
        </label>
        <label>Asset Exposure
          <select id="scanExposure">
            <option value="">Auto-detect / Unknown</option>
            <option value="internet_facing">Internet-Facing (Public Access)</option>
            <option value="partner_dmz">DMZ / Partner Facing</option>
            <option value="internal">Internal Network (Private VPC)</option>
            <option value="isolated">Isolated / Air-gapped Host</option>
          </select>
        </label>
      </div>
    </details>
    <div id="progressArea" ${state.uploading ? '' : 'hidden'}>
      <div class="progress" id="pbar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0"><span></span></div>
      <p class="status-line" id="pstatus">Uploading</p>
    </div>
    ${state.uploadError ? `<div class="error-box" role="alert">${esc(state.uploadError)}</div>` : ''}`;
  $$('[data-rm]', q).forEach(b => b.onclick = () => { state.pending.splice(+b.dataset.rm, 1); renderQueue(); });
  const clr = $('#clearQueue'); if (clr) clr.onclick = () => { state.pending = []; state.skippedClient = 0; state.uploadError = ''; renderQueue(); };
  const run = $('#runScan'); if (run) run.onclick = runScan;
}

function runScan() {
  if (state.uploading || !state.pending.length) return;
  const fd = new FormData();
  const name = ($('#scanName') || {}).value || '';
  fd.append('name', name);
  const sens = ($('#scanSensitivity') || {}).value;
  if (sens) fd.append('data_sensitivity', sens);
  const life = ($('#scanLifetime') || {}).value;
  if (life) fd.append('confidentiality_lifetime', life);
  const exp = ($('#scanExposure') || {}).value;
  if (exp) fd.append('asset_exposure', exp);
  state.pending.forEach(p => fd.append('files', p.file, p.path));
  state.uploading = true; state.uploadError = '';
  renderQueue();
  const nameVal = name; if ($('#scanName')) $('#scanName').value = nameVal;
  const bar = $('#pbar'), status = $('#pstatus');
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/scan');
  xhr.upload.onprogress = e => {
    if (!e.lengthComputable) return;
    const pct = Math.round(e.loaded / e.total * 100);
    bar.setAttribute('aria-valuenow', pct); $('span', bar).style.width = pct + '%';
    status.textContent = pct < 100 ? `Uploading ${pct}%` : 'Upload complete. Analyzing files on the server...';
    if (pct >= 100) bar.classList.add('indeterminate');
  };
  const fail = msg => { state.uploading = false; state.uploadError = msg; renderQueue(); };
  xhr.onerror = () => fail('Could not reach the VULNEXIS backend. Check that the Flask server is running and try again.');
  xhr.onload = async () => {
    let body = null; try { body = JSON.parse(xhr.responseText); } catch { /* ignore */ }
    if (xhr.status >= 200 && xhr.status < 300) {
      state.uploading = false; state.pending = []; state.skippedClient = 0;
      state.scan = body;
      await refreshOverview().catch(() => {});
      toast(`Scan complete: ${plural(body.summary.findings_total, 'finding')} in ${plural(body.summary.files_scanned, 'file')}.`);
      if (location.hash === '#/overview') render(); else location.hash = '#/overview';
    } else {
      let msg = (body && body.error) || `The scan failed (${xhr.status}).`;
      if (body && body.skipped && body.skipped.items && body.skipped.items.length) {
        msg += ' Skipped: ' + body.skipped.items.slice(0, 5).map(i => `${i.name} (${i.reason})`).join(', ') + '.';
      }
      fail(msg);
    }
  };
  xhr.send(fd);
}

/* ---------- Results ---------- */

/* ---------- Live TLS endpoint scan ---------- */
views.tls = el => {
  el.innerHTML = pageHead('TLS endpoint scan', 'Check the TLS protocol and cipher negotiated with a host you are authorised to assess.') + `
    <section class="panel">
      <form id="tlsForm" class="tls-form">
        <label for="tlsHost">Hostname or IP address</label>
        <input id="tlsHost" name="host" type="text" placeholder="example.com" required maxlength="253" autocomplete="url">
        <label for="tlsPort">Port</label>
        <input id="tlsPort" name="port" type="number" min="1" max="65535" value="443" required>
        <button class="btn primary" id="tlsSubmit" type="submit">Check TLS</button>
        <p class="sub">Connects to the supplied host and port from the Flask server. This check does not exploit or modify the target.</p>
      </form>
    </section>
    <div id="tlsResult" aria-live="polite"></div>`;
  $('#tlsForm').onsubmit = async e => {
    e.preventDefault();
    const host = $('#tlsHost').value.trim();
    const port = Number($('#tlsPort').value);
    const btn = $('#tlsSubmit'), out = $('#tlsResult');
    btn.disabled = true; btn.textContent = 'Checking...';
    out.innerHTML = '<section class="panel"><p class="sub">Connecting and negotiating TLS...</p></section>';
    try {
      const r = await api('/api/tls-scan', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({host, port}) });
      const findings = r.findings || [];
      
      const fmtIssuer = iss => {
        if (!iss || typeof iss !== 'object') return 'Not reported';
        const parts = [];
        if (iss.organizationName) parts.push(iss.organizationName);
        if (iss.commonName) parts.push(`CN=${iss.commonName}`);
        if (iss.countryName) parts.push(iss.countryName);
        return parts.length ? parts.join(', ') : 'Not reported';
      };

      const parseTlsDate = dStr => {
        if (!dStr) return { main: 'Unknown', sub: '', isExpired: false, badge: '' };
        try {
          const d = new Date(dStr);
          if (!isNaN(d.getTime())) {
            const isExpired = d < new Date();
            const main = d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
            const sub = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZoneName: 'short' });
            const badge = isExpired
              ? `<span class="badge st-classical" style="margin-top:6px;width:fit-content">Expired</span>`
              : `<span class="badge st-resistant" style="margin-top:6px;width:fit-content">Valid Certificate</span>`;
            return { main, sub, isExpired, badge };
          }
        } catch (e) {}
        return { main: dStr, sub: '', isExpired: false, badge: '' };
      };

      const parsedExpiry = parseTlsDate(r.certificate && r.certificate.not_after);
      const isModernTls = r.protocol === 'TLSv1.3';
      const isPqcKex = r.cipher && r.cipher.name && (r.cipher.name.includes('MLKEM') || r.cipher.name.includes('KYBER'));

      out.innerHTML = `
        <section class="panel">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:8px">
            <h3 style="margin:0;font-size:18px"><span class="mono" style="font-size:16px;font-weight:700;color:#fff">${esc(r.host)}:${r.port}</span></h3>
            <span class="badge st-resistant" style="--c:var(--low)">Negotiation Successful</span>
          </div>

          <div class="grid g-3">
            <div class="tls-stat" style="--tone:var(--accent)">
              <div class="label">Negotiated Protocol</div>
              <div class="value">
                <span class="val-protocol">${esc(r.protocol || 'Unknown')}</span>
                ${isModernTls ? '<span class="badge st-resistant" style="margin-top:6px;width:fit-content">Current Standard</span>' : '<span class="badge st-weakened" style="margin-top:6px;width:fit-content">Legacy Protocol</span>'}
              </div>
              <div class="hint">Protocol negotiated for this connection</div>
            </div>

            <div class="tls-stat" style="--tone:var(--low)">
              <div class="label">Negotiated Cipher</div>
              <div class="value">
                <span class="val-cipher" title="${esc(r.cipher ? r.cipher.name : 'Unknown')}">${esc(r.cipher ? r.cipher.name : 'Unknown')}</span>
                <span class="badge st-resistant" style="margin-top:6px;width:fit-content">${r.cipher ? `${r.cipher.bits}-bit Encryption` : 'Unknown Bits'}</span>
              </div>
              <div class="hint">${r.cipher && r.cipher.name && r.cipher.name.includes('GCM') ? 'Authenticated AEAD Mode' : 'Cipher for this connection'}</div>
            </div>

            <div class="tls-stat" style="--tone:var(--accent)">
              <div class="label">Certificate Expiry</div>
              <div class="value">
                <span class="val-date">${esc(parsedExpiry.main)}<small>${esc(parsedExpiry.sub)}</small></span>
                ${parsedExpiry.badge}
              </div>
              <div class="hint">${r.certificate.subject && r.certificate.subject.commonName ? `CN=${esc(r.certificate.subject.commonName)}` : 'Subject unreadable'}</div>
            </div>
          </div>

          <div class="tls-meta-card">
            <h4>Certificate & Trust Information</h4>
            <div class="tls-meta-grid">
              <div class="tls-meta-item">
                <strong>Subject (Common Name)</strong>
                <span>${r.certificate.subject && r.certificate.subject.commonName ? `CN = ${esc(r.certificate.subject.commonName)}` : 'Subject unreadable'}</span>
              </div>
              <div class="tls-meta-item">
                <strong>Certificate Issuer</strong>
                <span>${esc(fmtIssuer(r.certificate.issuer))}</span>
              </div>
              ${r.certificate.subject_alt_names && r.certificate.subject_alt_names.length ? `
              <div class="tls-meta-item" style="grid-column: 1 / -1">
                <strong>Subject Alternative Names (SANs)</strong>
                <div class="tls-sans">
                  ${r.certificate.subject_alt_names.slice(0, 16).map(s => `<span>${esc(s)}</span>`).join('')}
                  ${r.certificate.subject_alt_names.length > 16 ? `<span class="muted">+${r.certificate.subject_alt_names.length - 16} more</span>` : ''}
                </div>
              </div>` : ''}
            </div>
          </div>

          <h3 style="margin-top:24px">Findings (${findings.length})</h3>
          ${findings.length ? `<ul class="refs">${findings.map(f => `
            <li>
              <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px">
                ${f.risk_score !== undefined ? scoreBadge(f.risk_score, f.severity) : ''}
                ${sevBadge(f.severity)}
                <span class="badge ${f.is_provisional ? 'st-unclassified' : 'st-resistant'}">${f.is_provisional ? 'Provisional' : 'Confirmed'}</span>
                ${f.remediation_timeframe ? `<span style="font-size:12px;font-weight:700;color:var(--muted)">[Timeframe: ${esc(f.remediation_timeframe)}]</span>` : ''}
              </div>
              <strong>${esc(f.title)}</strong>
              <p class="sub">${esc(f.detail)}</p>
            </li>
          `).join('')}</ul>` : '<p class="sub" style="font-size:13px;color:#c9d4ee">No security flaws were detected from the checks implemented here. (This is a protocol inspection, not a complete network audit).</p>'}

          <div class="threat-box" style="margin-top:16px;border-left:3px solid var(--accent)">
            <h5><span>Quantum Threat Assessment for this Connection</span> <span class="badge ${isPqcKex ? 'st-pqc' : 'st-weakened'}">${isPqcKex ? 'Post-quantum KEX' : 'Classical KEX (HNDL Risk)'}</span></h5>
            <p style="margin:0;font-size:13px;color:#c9d4ee">${esc(r.quantum_note)}</p>
          </div>

          ${r.monday_morning_plan ? `
            <div style="margin-top:18px;display:flex;justify-content:space-between;align-items:center;padding:14px 18px;background:var(--panel-2);border-radius:8px;border:1px solid var(--line);flex-wrap:wrap;gap:10px">
              <div>
                <strong>Monday Morning Action Plan &bull; Endpoint Remediation</strong>
                <p class="sub" style="margin:2px 0 0">Prioritised migration steps, owner roles, and validation tests are mapped for this TLS target.</p>
              </div>
              <a class="btn primary small" href="#/fixfirst">Open Full Action Plan &rarr;</a>
            </div>
          ` : ''}
        </section>`;
    } catch (err) {
      out.innerHTML = `<section class="panel"><h3>TLS check failed</h3><p>${esc(err.message)}</p></section>`;
    } finally {
      btn.disabled = false; btn.textContent = 'Check TLS';
    }
  };
};

views.results = el => {
  const sc = state.scan;
  el.innerHTML = pageHead('Analysis results', 'Every cryptographic algorithm found, with where it was found and what to do about it.',
    sc ? `<a class="btn" href="/api/scans/${sc.id}/report.pdf" download>Download PDF report</a>` : '');
  if (!sc) { el.insertAdjacentHTML('beforeend', noScan()); return; }
  el.insertAdjacentHTML('beforeend', scanBanner(sc));
  if (!sc.findings.length) {
    el.insertAdjacentHTML('beforeend', `<div class="panel"><h3>No cryptographic algorithms detected</h3><p class="sub">Nothing to analyze in the ${plural(sc.summary.files_scanned, 'file')} scanned.</p></div>` + skippedBlock(sc));
    return;
  }
  const f = state.filters;
  const sevCounts = sc.summary.severity_counts;
  el.insertAdjacentHTML('beforeend', `
    <div class="disclaimer-box"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg><span><strong>Operational Prioritisation Notice:</strong> Risk scores (0–100) are triage prioritisation rankings calculated from quantum vulnerability, data impact, retention lifetime, network exposure, and parameter weaknesses. They are not measured mathematical probabilities of encryption failure today.</span></div>
    <div class="toolbar">
      <div class="chips" role="group" aria-label="Filter by severity">
        <button class="chip" data-sev="all" aria-pressed="${f.sev === 'all'}">All (${sc.findings.length})</button>
        ${SEV.filter(k => sevCounts[k]).map(k => `<button class="chip" data-sev="${k}" aria-pressed="${f.sev === k}">${SEV_LABEL[k]} (${sevCounts[k]})</button>`).join('')}
      </div>
      <select id="surfaceFilter" aria-label="Filter by scan surface">
        <option value="all" ${f.surface === 'all' ? 'selected' : ''}>All surfaces</option>
        <option value="source_code" ${f.surface === 'source_code' ? 'selected' : ''}>Source code</option>
        <option value="live_tls" ${f.surface === 'live_tls' ? 'selected' : ''}>Live TLS</option>
      </select>
      <select id="timeframeFilter" aria-label="Filter by remediation timeframe">
        <option value="all" ${f.timeframe === 'all' ? 'selected' : ''}>All timeframes</option>
        <option value="immediate" ${f.timeframe === 'immediate' ? 'selected' : ''}>Immediate attention (80–100)</option>
        <option value="this_week" ${f.timeframe === 'this_week' ? 'selected' : ''}>This week (60–79)</option>
        <option value="planned" ${f.timeframe === 'planned' ? 'selected' : ''}>Planned migration (30–59)</option>
        <option value="monitor" ${f.timeframe === 'monitor' ? 'selected' : ''}>Monitor & maintain (0–29)</option>
      </select>
      <select id="statusFilter" aria-label="Filter by quantum status">
        <option value="all">All quantum statuses</option>
        ${STATUS_KEYS.map(k => `<option value="${k}" ${f.status === k ? 'selected' : ''}>${STATUS_LABEL[k]}</option>`).join('')}
      </select>
      <div class="grow"><input type="search" id="q" placeholder="Search algorithm, asset or file" value="${esc(f.q)}" aria-label="Search findings"></div>
    </div>
    <div class="table-wrap"><table>
      <thead><tr><th><span class="sr">Details</span></th><th>Score</th><th>Severity</th><th>Timeframe</th><th>Surface</th><th>Algorithm</th><th>Quantum status</th><th>Asset / File</th><th class="num">Uses</th></tr></thead>
      <tbody id="rows"></tbody></table></div>
    <p class="sub" id="count" style="margin-top:10px"></p>` + skippedBlock(sc));
  const draw = () => {
    const q = f.q.trim().toLowerCase();
    const rows = sc.findings.filter(x => {
      const matchSev = (f.sev === 'all' || x.severity === f.sev);
      const matchStatus = (f.status === 'all' || x.quantum_status === f.status);
      const surf = x.scan_surface || 'source_code';
      const matchSurf = (f.surface === 'all' || surf === f.surface);
      const tf = (x.remediation_timeframe || x.timeframe || '').toLowerCase();
      let matchTf = true;
      if (f.timeframe === 'immediate') matchTf = tf.includes('immediate');
      else if (f.timeframe === 'this_week') matchTf = tf.includes('week');
      else if (f.timeframe === 'planned') matchTf = tf.includes('plan');
      else if (f.timeframe === 'monitor') matchTf = tf.includes('monitor');
      const matchQ = (!q || x.algorithm.toLowerCase().includes(q) || (x.file || x.asset || '').toLowerCase().includes(q) || (x.parsed || []).join(' ').toLowerCase().includes(q));
      return matchSev && matchStatus && matchSurf && matchTf && matchQ;
    });
    $('#rows').innerHTML = rows.length ? rows.map(x => findingRow(x)).join('') :
      `<tr><td colspan="9" class="muted" style="padding:28px;text-align:center">No findings match these filters.</td></tr>`;
    $('#count').textContent = `Showing ${rows.length} of ${sc.findings.length} findings.`;
  };
  draw();
  $$('.chip', el).forEach(b => b.onclick = () => { f.sev = b.dataset.sev; $$('.chip', el).forEach(c => c.setAttribute('aria-pressed', c === b)); draw(); });
  $('#surfaceFilter').onchange = e => { f.surface = e.target.value; draw(); };
  $('#timeframeFilter').onchange = e => { f.timeframe = e.target.value; draw(); };
  $('#statusFilter').onchange = e => { f.status = e.target.value; draw(); };
  $('#q').oninput = e => { f.q = e.target.value; draw(); };
  $('#rows').onclick = async e => {
    const rBtn = e.target.closest('.re-score-btn');
    if (rBtn) {
      const fid = Number(rBtn.dataset.fid);
      const sVal = $(`#ctx-sens-${fid}`).value;
      const lVal = $(`#ctx-life-${fid}`).value;
      const eVal = $(`#ctx-exp-${fid}`).value;
      rBtn.disabled = true; rBtn.textContent = 'Updating...';
      try {
        const res = await api(`/api/scans/${sc.id}/findings/${fid}/context`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            data_sensitivity: sVal,
            confidentiality_lifetime: lVal,
            asset_exposure: eVal
          })
        });
        toast('Risk score updated and findings re-ranked.');
        state.scan = res.scan;
        views.results(el);
      } catch (err) {
        toast(err.message, true);
        rBtn.disabled = false; rBtn.textContent = 'Recalculate Score';
      }
      return;
    }
    const b = e.target.closest('.expander'); if (!b) return;
    const open = b.getAttribute('aria-expanded') === 'true';
    b.setAttribute('aria-expanded', String(!open));
    const tr = b.closest('tr'), next = tr.nextElementSibling;
    if (open) { if (next && next.classList.contains('detail')) next.remove(); }
    else tr.insertAdjacentHTML('afterend', detailRow(sc.findings.find(x => x.id === +b.dataset.id)));
  };
};

function findingRow(x) {
  const conf = x.confidence_level ? confBadge(x.confidence_level) : '';
  const keySz = x.key_size_label ? `<small>Key size: ${esc(x.key_size_label)}</small>` : '';
  const modeLabel = x.mode ? `<small>Mode: ${esc(x.mode)}</small>` : '';
  const score = x.risk_score !== undefined ? scoreBadge(x.risk_score, x.risk_level) : '';
  const pkiHighlight = x.is_long_lived_sensitive_pki
    ? `<span class="badge st-vulnerable" style="margin-left:4px" title="${esc(x.highlight_callout || 'Long-lived sensitive data on RSA/ECC (HNDL Threat)')}">⚠️ HNDL Target</span>`
    : '';
  const provBadge = x.is_provisional
    ? `<span class="badge st-unclassified" style="margin-left:4px" title="Provisional score calculated from default assumptions">Provisional</span>`
    : '';
  const surfBadge = `<span class="badge ${x.scan_surface === 'live_tls' ? 'st-pqc' : 'st-weakened'}">${x.scan_surface === 'live_tls' ? 'Live TLS' : 'Source Code'}</span>`;

  return `<tr><td><button class="expander" data-id="${x.id}" aria-expanded="false" aria-label="Show details for ${esc(x.algorithm)} in ${esc(x.file || x.asset)}"><svg viewBox="0 0 16 16" aria-hidden="true"><path d="m3 6 5 5 5-5"/></svg></button></td>
    <td>${score}</td>
    <td>${sevBadge(x.severity)}</td>
    <td><span style="font-size:12px;font-weight:600">${esc(x.remediation_timeframe || x.timeframe || '-')}</span></td>
    <td>${surfBadge}</td>
    <td><strong>${esc(x.algorithm)}</strong> ${conf}${pkiHighlight}${provBadge}${x.parsed && x.parsed.length ? `<small>Parsed: ${esc(x.parsed.join(', '))}</small>` : ''}${keySz}${modeLabel}<small>${esc(x.category)}</small></td>
    <td>${statusBadge(x.quantum_status, x.quantum_label)}</td>
    <td><span class="path mono" style="font-size:12px">${esc(x.file || x.asset)}</span></td><td class="num">${x.count || 1}</td></tr>`;
}

function detailRow(x) {
  const cSec = x.current_security_concerns || {};
  const qSec = x.quantum_threat_analysis || {};
  const hndl = x.harvest_now_decrypt_later || {};
  const remed = x.remediation_guidance || {};
  const params = x.detected_parameters || {};

  // Classical block
  const classicalConcerns = (cSec.concerns && cSec.concerns.length)
    ? `<ul>${cSec.concerns.map(c => `<li>${esc(c)}</li>`).join('')}</ul>`
    : `<p>${esc((x.classical_security_assessment && x.classical_security_assessment.description) || 'Standard parameters currently meet acceptable classical criteria.')}</p>`;
  const classicalRef = cSec.standards_reference ? `<div class="ref-tag"><b>Reference:</b> ${esc(cSec.standards_reference)}</div>` : '';

  // Quantum CRQC block
  const qClass = x.quantum_classification || qSec.quantum_classification || 'not yet confidently classified';
  const qBreaks = (x.breaks_security_assumptions !== undefined ? x.breaks_security_assumptions : qSec.breaks_security_assumptions);
  const qBreaksBadge = qBreaks
    ? `<span class="badge st-vulnerable">Breaks Security Assumptions</span>`
    : `<span class="badge st-resistant">Security Assumptions Intact</span>`;
  const qAlgo = qSec.quantum_algorithm_applicable ? `<div class="ref-tag" style="margin-bottom:6px"><b>Applicable Quantum Algorithm:</b> ${esc(qSec.quantum_algorithm_applicable)}</div>` : '';
  const qWhy = esc(x.why_vulnerable || qSec.why_vulnerable || (x.quantum_risk_assessment && x.quantum_risk_assessment.description) || 'Quantum evaluation completed.');
  const qNotice = esc(x.theoretical_vs_active || qSec.theoretical_vs_active || 'Theoretical future quantum threat; no CRQC hardware exists today capable of breaking this system.');

  // HNDL block
  const hndlRisk = hndl.risk_level || 'none';
  const hndlBadge = hndl.applicable
    ? `<span class="badge ${hndlRisk === 'critical' ? 'st-vulnerable' : (hndlRisk === 'medium' ? 'st-classical' : 'st-weakened')}">HNDL Risk: ${esc(hndlRisk.toUpperCase())}</span>`
    : `<span class="badge st-resistant">HNDL: Not Applicable</span>`;
  const hndlExp = esc(x.hndl_explanation || hndl.explanation || 'Harvest-Now-Decrypt-Later does not apply to this algorithm type.');

  // PQC Migration Recommendation
  const mRec = x.migration_recommendation || {};
  let migrationCard = '';
  if (mRec && mRec.proposed_alternative) {
    const stepsHtml = (mRec.implementation_steps && mRec.implementation_steps.length)
      ? `<ol class="mig-steps">${mRec.implementation_steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>`
      : '';
    const testHtml = (mRec.testing_requirements && mRec.testing_requirements.length)
      ? `<ul class="mig-tests">${mRec.testing_requirements.map(t => `<li>${esc(t)}</li>`).join('')}</ul>`
      : '';

    // Tradeoff analysis (e.g. ML-DSA vs SLH-DSA)
    let tradeoffHtml = '';
    if (mRec.tradeoff_analysis && mRec.tradeoff_analysis.ml_dsa_vs_slh_dsa) {
      const dsa = mRec.tradeoff_analysis.ml_dsa_vs_slh_dsa;
      tradeoffHtml = `
        <div class="mig-tradeoff-box">
          <h6>⚖️ Signature Evaluation: ML-DSA (FIPS 204) vs SLH-DSA (FIPS 205)</h6>
          <div class="tradeoff-grid">
            <div class="tradeoff-col">
              <strong>ML-DSA (FIPS 204) — General / TLS</strong>
              <p><b>Best for:</b> ${esc(dsa.ml_dsa.best_for)}</p>
              <p><b>Advantages:</b> ${esc(dsa.ml_dsa.advantages)}</p>
              <p class="sub"><b>Caveats:</b> ${esc(dsa.ml_dsa.considerations)}</p>
            </div>
            <div class="tradeoff-col">
              <strong>SLH-DSA (FIPS 205) — Root Trust / Firmware</strong>
              <p><b>Best for:</b> ${esc(dsa.slh_dsa.best_for)}</p>
              <p><b>Advantages:</b> ${esc(dsa.slh_dsa.advantages)}</p>
              <p class="sub"><b>Caveats:</b> ${esc(dsa.slh_dsa.considerations)}</p>
            </div>
          </div>
        </div>`;
    }

    // Role distinctions (e.g. MD5 / SHA-1)
    let roleDistHtml = '';
    if (mRec.role_distinctions) {
      const rd = mRec.role_distinctions;
      roleDistHtml = `
        <div class="mig-tradeoff-box">
          <h6>🎯 Cryptographic Purpose & Role Requirements</h6>
          <ul class="sub" style="padding-left:18px;margin-top:4px">
            <li><strong>Digital Signatures:</strong> ${esc(rd.digital_signatures)}</li>
            <li><strong>Password Hashing:</strong> <span style="color:var(--critical)">${esc(rd.password_hashing)}</span></li>
            <li><strong>Key Derivation:</strong> ${esc(rd.key_derivation)}</li>
            <li><strong>Data Integrity:</strong> ${esc(rd.data_integrity_hmac)}</li>
          </ul>
        </div>`;
    }

    // AES-128 Assessment factors
    let aesAssessmentHtml = '';
    if (mRec.assessment_factors) {
      const af = mRec.assessment_factors;
      aesAssessmentHtml = `
        <div class="mig-tradeoff-box">
          <h6>🔍 AES-128 Security Assessment & Grover Margin</h6>
          <p class="sub">${esc(af.grover_security_margin)}</p>
          <p class="sub"><strong>Confidentiality Lifetime:</strong> ${esc(af.confidentiality_lifetime_evaluated)} | <strong>Sensitivity:</strong> ${esc(af.data_sensitivity_evaluated)}</p>
          <p class="sub"><strong>Upgrade Urgency:</strong> ${af.upgrade_recommended_now ? '<strong style="color:var(--high)">Recommended Now (Long-lived secret)</strong>' : '<span style="color:var(--low)">Standard Agility (Short-lived data)</span>'}</p>
        </div>`;
    }

    // Platform support (e.g. for TLS)
    let platformHtml = '';
    if (mRec.platform_support) {
      const ps = mRec.platform_support;
      platformHtml = `
        <div class="mig-tradeoff-box">
          <h6>🌐 Platform Ecosystem Support Verification</h6>
          <ul class="sub" style="padding-left:18px;margin-top:4px">
            <li><strong>OpenSSL:</strong> ${esc(ps.openssl)}</li>
            <li><strong>Go:</strong> ${esc(ps.golang)}</li>
            <li><strong>Java / Bouncy Castle:</strong> ${esc(ps.bouncy_castle)}</li>
            <li><strong>Edge / Envoy / Browsers:</strong> ${esc(ps.web_pki_envoy)}</li>
          </ul>
        </div>`;
    }

    // Standards list
    const stHtml = (mRec.standards_basis && mRec.standards_basis.length)
      ? `<div class="ref-tag" style="margin-top:8px"><b>Governing Standards:</b> ${esc(mRec.standards_basis.join('; '))}</div>` : '';

    migrationCard = `
      <div class="threat-box pqc-rec-box">
        <h5><span>PQC Migration Recommendation</span> <span class="badge st-pqc">${esc(mRec.proposed_alternative)}</span></h5>
        <div class="mig-header-meta">
          <span class="badge st-weakened">Role: ${esc(mRec.protocol_role || 'General')}</span>
          <span class="badge lv-${(mRec.priority || 'medium').toLowerCase()}">Priority: ${esc(mRec.priority || 'Medium')}</span>
        </div>
        <p style="margin-top:8px"><strong>Migration Rationale:</strong> ${esc(mRec.reason)}</p>
        ${tradeoffHtml}
        ${roleDistHtml}
        ${aesAssessmentHtml}
        ${platformHtml}
        <div class="mig-compat">
          <h6>⚡ Interoperability & Compatibility Considerations</h6>
          <p class="sub" style="white-space:pre-line">${esc(mRec.compatibility_considerations)}</p>
        </div>
        <div class="mig-workflow">
          <h6>📋 Actionable Implementation Steps</h6>
          ${stepsHtml}
        </div>
        <div class="mig-workflow">
          <h6>🧪 Testing & Validation Requirements</h6>
          ${testHtml}
        </div>
        ${stHtml}
      </div>`;
  } else {
    migrationCard = `
      <div class="threat-box">
        <h5><span>Remediation & Migration Guidance</span> <span class="badge st-pqc">${repl}</span></h5>
        <p>${strat}</p>
        ${stList}
      </div>`;
  }

  // Parameters list
  const paramItems = [];
  paramItems.push(`<div class="param-item"><div class="param-label">Algorithm</div><div class="param-val">${esc(x.detected_algorithm || x.algorithm)}</div></div>`);
  if (x.key_size_label || params.key_size) {
    paramItems.push(`<div class="param-item"><div class="param-label">Key Size</div><div class="param-val">${esc(x.key_size_label || params.key_size + '-bit')}</div></div>`);
  }
  if (x.mode || params.mode) {
    paramItems.push(`<div class="param-item"><div class="param-label">Cipher Mode</div><div class="param-val">${esc(x.mode || params.mode)}</div></div>`);
  }
  if (params.curve) {
    paramItems.push(`<div class="param-item"><div class="param-label">Curve</div><div class="param-val">${esc(params.curve)}</div></div>`);
  }
  if (params.hash_algorithm) {
    paramItems.push(`<div class="param-item"><div class="param-label">Hash Algorithm</div><div class="param-val">${esc(params.hash_algorithm)}</div></div>`);
  }
  paramItems.push(`<div class="param-item"><div class="param-label">Confidence</div><div class="param-val" style="display:flex;align-items:center;margin-top:2px">${confBadge(x.confidence_level)}</div></div>`);

  // Long-lived sensitive RSA/ECC alert
  const hndlAlert = x.is_long_lived_sensitive_pki ? `
    <div class="hndl-alert">
      <strong>⚠️ CRITICAL HNDL EXPOSURE: Long-Lived Sensitive Asset on RSA/ECC</strong>
      ${esc(x.highlight_callout || 'Long-lived sensitive data protected by quantum-vulnerable asymmetric cryptography (RSA/ECC). Adversaries can harvest encrypted traffic today and retroactively decrypt it once a CRQC is operational.')}
    </div>` : '';

  // 4-Factor Risk Prioritisation Card
  const factors = x.contributing_factors || [];
  const provAlert = x.is_provisional ? `
    <div class="provisional-warning">
      ⚠️ <strong>Provisional Prioritisation Score (${x.risk_score}/100):</strong> Data sensitivity, lifetime, or network exposure were not confirmed from source code and evaluated using neutral default assumptions (50/100). Select confirmed context below and click <em>Recalculate Score</em> to update.
    </div>` : '';

  const riskCard = `
    <div class="threat-box">
      <h5><span>Risk Prioritisation Score</span> ${scoreBadge(x.risk_score, x.risk_level)}</h5>
      <p style="margin-bottom:6px"><strong>Remediation Timeframe:</strong> <span class="badge lv-${x.risk_level || 'low'}">${esc(x.remediation_timeframe || x.timeframe || x.priority || 'Planned migration')}</span></p>
      <p style="font-size:12.5px;color:#c9d4ee;margin-bottom:10px">${esc(x.explanation || x.score_explanation || '')}</p>
      ${provAlert}

      <h6 style="margin:10px 0 4px;font-size:11px;text-transform:uppercase;color:var(--accent)">4-Factor Breakdown (0–100)</h6>
      <table class="factors-table">
        <thead><tr><th>Factor</th><th>Status</th><th>Value</th><th class="num">Weight</th><th class="num">Points</th></tr></thead>
        <tbody>
          ${factors.map(f => `
            <tr>
              <td><strong>${esc(f.name)}</strong></td>
              <td><span class="badge ${f.status === 'user_provided' ? 'st-pqc' : (f.status === 'inferred' ? 'st-weakened' : 'st-unclassified')}">${esc(f.status)}</span></td>
              <td class="mono" style="font-size:11px;max-width:140px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${esc(f.value || '')}">${esc(f.value || '-')}</td>
              <td class="num">${Math.round(f.weight * 100)}%</td>
              <td class="num"><strong>${f.weighted_score}</strong></td>
            </tr>
          `).join('')}
        </tbody>
      </table>

      <div class="context-editor">
        <h6>Provide / Override Business Context</h6>
        <div class="context-fields">
          <label>Data Sensitivity
            <select id="ctx-sens-${x.id}">
              <option value="highly_sensitive" ${['highly_sensitive', 'critical'].includes(x.user_context?.data_sensitivity) ? 'selected' : ''}>Highly Sensitive (Credentials, Keys, PII)</option>
              <option value="confidential" ${['confidential', 'high'].includes(x.user_context?.data_sensitivity) ? 'selected' : ''}>Confidential (Customer / Business Data)</option>
              <option value="internal" ${['internal', 'medium'].includes(x.user_context?.data_sensitivity) ? 'selected' : ''}>Internal (Operational Internal Data)</option>
              <option value="public" ${['public', 'low'].includes(x.user_context?.data_sensitivity) ? 'selected' : ''}>Public (Non-sensitive / Test Data)</option>
              <option value="unknown" ${x.user_context?.data_sensitivity === 'unknown' ? 'selected' : ''}>Unknown (Default: 50 pts)</option>
            </select>
          </label>
          <label>Retention Lifetime
            <select id="ctx-life-${x.id}">
              <option value="10+_years" ${x.user_context?.confidentiality_lifetime === '10+_years' ? 'selected' : ''}>10+ Years (Archival, Root PKI)</option>
              <option value="5-9_years" ${x.user_context?.confidentiality_lifetime === '5-9_years' ? 'selected' : ''}>5–9 Years (Medium-Long Retention)</option>
              <option value="1-4_years" ${x.user_context?.confidentiality_lifetime === '1-4_years' ? 'selected' : ''}>1–4 Years (Standard Operational)</option>
              <option value="<1_year" ${x.user_context?.confidentiality_lifetime === '<1_year' ? 'selected' : ''}>&lt; 1 Year (Ephemeral Transit)</option>
              <option value="unknown" ${x.user_context?.confidentiality_lifetime === 'unknown' ? 'selected' : ''}>Unknown (Default: 50 pts)</option>
            </select>
          </label>
          <label>Asset Exposure
            <select id="ctx-exp-${x.id}">
              <option value="internet_facing" ${['internet_facing', 'external_internet_facing'].includes(x.user_context?.asset_exposure) ? 'selected' : ''}>External / Public Internet</option>
              <option value="partner_dmz" ${x.user_context?.asset_exposure === 'partner_dmz' ? 'selected' : ''}>Partner / DMZ Facing</option>
              <option value="internal" ${['internal', 'internal_network'].includes(x.user_context?.asset_exposure) ? 'selected' : ''}>Internal Network (Private VPC)</option>
              <option value="isolated" ${['isolated', 'isolated_airgapped'].includes(x.user_context?.asset_exposure) ? 'selected' : ''}>Isolated / Air-gapped Host</option>
              <option value="unknown" ${x.user_context?.asset_exposure === 'unknown' ? 'selected' : ''}>Unknown (Default: 50 pts)</option>
            </select>
          </label>
        </div>
        <button class="btn small primary re-score-btn" data-fid="${x.id}" type="button">Recalculate Score</button>
      </div>
    </div>`;

  // Evidence & Hits
  const evidence = x.evidence ? `<div style="margin-bottom:12px"><h4>Cryptographic Evidence</h4><p class="code mono" style="font-size:12px;padding:6px 10px;border-radius:4px;word-break:break-all;background:var(--panel-2);border:1px solid var(--line)">${esc(x.evidence)}</p></div>` : '';
  const lims = (x.analysis_limitations && x.analysis_limitations.length) ? `<div style="margin-top:12px"><h4>Analysis limitations</h4><ul class="sub" style="padding-left:18px;margin-top:4px">${x.analysis_limitations.map(l => `<li>${esc(l)}</li>`).join('')}</ul></div>` : '';
  const hits = (x.occurrences || []).map(o => `<li><span class="ln">${o.line ? 'line ' + o.line : 'binary'}</span><span class="code">${esc(o.snippet)}</span></li>`).join('');

  return `<tr class="detail"><td colspan="9">
    ${hndlAlert}
    <div class="detail-grid">
      <div>
        ${riskCard}

        <div class="threat-box">
          <h5><span>Current Classical Threats</span> ${exploitableBadge(cSec.exploitable_today, cSec.status_label)}</h5>
          ${classicalConcerns}
          ${classicalRef}
        </div>

        <div class="threat-box">
          <h5><span>Future Quantum Threats (CRQC)</span> ${qClassBadge(qClass)}</h5>
          <div class="threat-meta">${qBreaksBadge}</div>
          ${qAlgo}
          <p><strong>Why vulnerable:</strong> ${qWhy}</p>
          <p class="ref-tag" style="border-top:1px solid var(--line-soft);padding-top:6px;margin-top:8px">${qNotice}</p>
        </div>

        <div class="threat-box">
          <h5><span>Harvest-Now-Decrypt-Later (HNDL)</span> ${hndlBadge}</h5>
          <p>${hndlExp}</p>
        </div>

        ${migrationCard}
      </div>

      <div>
        <h4>Detected Cryptographic Parameters</h4>
        <div class="param-grid">${paramItems.join('')}</div>

        ${evidence}

        <h4>Where it was found${x.count > x.occurrences.length ? ` (first ${x.occurrences.length} of ${x.count})` : ''}</h4>
        <ul class="hits" style="margin-top:8px">${hits}</ul>

        ${lims}
      </div>
    </div>
  </td></tr>`;
}

function skippedBlock(sc) {
  const sk = sc.skipped;
  if (!sk || !sk.total) return '';
  return `<details class="skipped"><summary>${plural(sk.total, 'file')} not inspected</summary><ul>${sk.items.map(i => `<li><span class="path mono">${esc(i.name)}</span>: ${esc(i.reason)}</li>`).join('')}</ul>
    ${sk.total > sk.items.length ? `<p class="muted">and ${sk.total - sk.items.length} more</p>` : ''}</details>`;
}

/* ---------- Risk ---------- */
views.risk = el => {
  const sc = state.scan;
  el.innerHTML = pageHead('Risk score', 'How exposed the scanned files are, from 0 (nothing found) to 100.',
    sc ? `<a class="btn" href="/api/scans/${sc.id}/report.pdf" download>Download PDF report</a>` : '');
  if (!sc) { el.insertAdjacentHTML('beforeend', noScan()); return; }
  const s = sc.summary, rd = s.pqc_readiness;
  el.insertAdjacentHTML('beforeend', scanBanner(sc) + `
    <div class="grid g-2">
      <section class="panel"><h3>Overall score</h3><p class="sub">${esc(sc.label)}</p>
        <div class="ring-wrap">${ring(s.risk_score, s.risk_level)}</div>
        <details class="explain"><summary>How the score is calculated</summary>
          <p><strong>Overall Scan Score:</strong> Each finding adds points by severity: critical 10, high 5, medium 2, low 1, info 0. Repeated use in the same file adds up to 50% more. The total points are turned into a 0 to 100 aggregate score via 100 × (1 − e<sup>−points/30</sup>).</p>
          <p style="margin-top:6px"><strong>Per-Finding Prioritisation Scoring:</strong> Each cryptographic finding is evaluated using 6 weighted factors: (1) Quantum Vulnerability (25%), (2) Data Sensitivity (20%), (3) Confidentiality Lifetime (15%), (4) Asset Exposure (15%), (5) Cryptographic Parameters (15%), and (6) Migration Path (10%).</p>
          <p style="margin-top:6px"><strong>Threshold Bands:</strong> Critical (75–100), High (50–74), Medium (25–49), Low (0–24).</p>
          <p style="margin-top:6px"><em>Notice: Finding scores are prioritisation rankings for remediation triage, not measured mathematical probabilities of encryption failure today.</em></p></details></section>
      <section class="panel"><h3>Severity levels</h3><p class="sub">Findings in this scan by severity.</p>
        <div class="sev-rows">${SEV.map(k => {
          const n = s.severity_counts[k] || 0, mx = Math.max(1, ...Object.values(s.severity_counts));
          return `<div class="sev-row">${sevBadge(k)}<div class="track" style="--c:var(--${k})"><span style="width:${n ? Math.max(4, n / mx * 100) : 0}%"></span></div><b style="text-align:right">${n}</b><small>${SEV_HELP[k]}</small></div>`;
        }).join('')}</div>
        <h3 style="margin-top:24px">Post-quantum readiness</h3>
        <div class="readiness">${rd.percent === null
          ? `<p class="sub">Not applicable. No quantum-vulnerable or post-quantum findings were detected.</p>`
          : `<div class="row"><span>${rd.pqc} post-quantum of ${rd.pqc + rd.vulnerable} public-key findings</span><b>${rd.percent}%</b></div>
             <div class="progress" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${rd.percent}" aria-label="Post-quantum readiness"><span style="width:${rd.percent}%;background:var(--pqc)"></span></div>`}</div>
      </section>
    </div>
    <section class="panel"><h3>Risk by file</h3><p class="sub">Files with findings, highest risk first.</p>${s.findings_total ? `
      <div class="table-wrap"><table><thead><tr><th>File</th><th>Risk level</th><th>Share of risk</th><th class="num">Score</th><th class="num">Findings</th></tr></thead><tbody>
      ${sc.files.map(f => { const mx = sc.files[0].points || 1; return `<tr><td><span class="path">${esc(f.name)}</span></td><td>${levelBadge(f.level)}</td>
        <td style="min-width:140px"><div class="track" style="--c:var(--${f.level === 'none' ? 'info' : f.level})"><span style="width:${Math.max(3, f.points / mx * 100)}%"></span></div></td>
        <td class="num">${f.score}</td><td class="num">${f.findings}</td></tr>`; }).join('')}
      </tbody></table></div>` : '<p class="muted">No findings, so no files to rank.</p>'}</section>`);
};

/* ---------- Plan ---------- */
const planKey = id => `vulnexis-plan-${id}`;
function loadChecks(id) { try { return JSON.parse(localStorage.getItem(planKey(id)) || localStorage.getItem(`qshield-plan-${id}`) || '[]'); } catch { return []; } }
function saveChecks(id, arr) { try { localStorage.setItem(planKey(id), JSON.stringify(arr)); } catch { /* storage unavailable */ } }

views.plan = el => {
  const sc = state.scan;
  el.innerHTML = pageHead('Post-quantum migration plan', 'Steps ordered by urgency, built from the algorithms found in this scan.',
    sc ? `<a class="btn" href="/api/scans/${sc.id}/report.pdf" download>Download PDF report</a>` : '');
  if (!sc) { el.insertAdjacentHTML('beforeend', noScan()); return; }
  const phases = sc.plan.phases;
  if (!phases.length) {
    el.insertAdjacentHTML('beforeend', scanBanner(sc) + `<div class="panel"><h3>No migration steps needed</h3><p class="sub">This scan found nothing that needs replacing. Scan again after code or configuration changes.</p></div>`);
    return;
  }
  const checks = new Set(loadChecks(sc.id));
  const all = phases.flatMap(p => p.actions.map(a => a.id));
  el.insertAdjacentHTML('beforeend', scanBanner(sc) + `
    <section class="panel" style="margin-bottom:16px"><div class="readiness"><div class="row"><span><strong id="planCount"></strong> steps marked done</span><b id="planPct"></b></div>
      <div class="progress" id="planBar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-label="Migration steps completed"><span></span></div>
      <p class="sub" style="margin:10px 0 0">Tick steps as your team completes them. Progress is saved in this browser for this scan.</p></div></section>
    <ul class="refs">${sc.plan.references.map(r => `<li>${esc(r)}</li>`).join('')}</ul>
    ${phases.map((p, i) => `<section class="phase"><header><h3>Phase ${i + 1}: ${esc(p.title)}</h3><span class="tag">${esc(p.priority)}</span></header><p class="intro">${esc(p.intro)}</p>
      ${p.actions.map(a => `<label class="action ${checks.has(a.id) ? 'done' : ''}"><input type="checkbox" data-aid="${esc(a.id)}" ${checks.has(a.id) ? 'checked' : ''}>
        <div><h4><span class="t">${esc(a.title)}</span>${a.severity ? sevBadge(a.severity) : ''}${a.action_priority ? `<span class="badge lv-${(a.action_priority).toLowerCase()}">${esc(a.action_priority)}</span>` : ''}</h4>
        <p>${esc(a.how)}</p>
        <div class="meta"><span class="repl">${esc(a.replace_with)}</span>
        ${a.file_count ? ` &nbsp;${plural(a.file_count, 'file')}, ${plural(a.uses, 'use')}: <span class="mono">${esc(a.files.slice(0, 3).join(', '))}${a.file_count > 3 ? ', ...' : ''}</span>` : ''}</div>
        ${(a.implementation_steps && a.implementation_steps.length) || a.compatibility_considerations ? `
          <details class="plan-details">
            <summary>View Actionable Steps & Testing Checklist</summary>
            ${a.compatibility_considerations ? `<p style="margin:6px 0;font-size:12px;color:#c9d0ff"><strong>Compatibility Considerations:</strong><br><span style="white-space:pre-line">${esc(a.compatibility_considerations)}</span></p>` : ''}
            ${a.implementation_steps && a.implementation_steps.length ? `<h6 style="margin:8px 0 4px;font-size:11px;text-transform:uppercase;color:#c9d0ff">Implementation Steps:</h6><ol class="mig-steps">${a.implementation_steps.map(s => `<li>${esc(s)}</li>`).join('')}</ol>` : ''}
            ${a.testing_requirements && a.testing_requirements.length ? `<h6 style="margin:8px 0 4px;font-size:11px;text-transform:uppercase;color:#c9d0ff">Testing & Validation Requirements:</h6><ul class="mig-tests">${a.testing_requirements.map(t => `<li>${esc(t)}</li>`).join('')}</ul>` : ''}
          </details>` : ''}
        </div></label>`).join('')}</section>`).join('')}`);
  const upd = () => {
    const done = all.filter(id => checks.has(id)).length, pct = Math.round(done / all.length * 100);
    $('#planCount').textContent = `${done} of ${all.length}`; $('#planPct').textContent = pct + '%';
    $('#planBar').setAttribute('aria-valuenow', pct); $('span', $('#planBar')).style.width = pct + '%';
  };
  upd();
  $$('input[data-aid]', el).forEach(cb => cb.onchange = () => {
    cb.checked ? checks.add(cb.dataset.aid) : checks.delete(cb.dataset.aid);
    cb.closest('.action').classList.toggle('done', cb.checked);
    saveChecks(sc.id, [...checks]); upd();
  });
};

/* ---------- History ---------- */
views.history = el => {
  const list = state.list;
  el.innerHTML = pageHead('History and reports', 'Every scan is saved by the backend. Open one to review it or download its PDF report.',
    list.length ? '<button class="btn danger" id="clearAll" type="button">Clear all history</button>' : '');
  if (!list.length) { el.insertAdjacentHTML('beforeend', emptyState('No scans in history', 'Completed scans appear here with a PDF report for each one.')); return; }
  const pts = [...list].reverse().map(s => ({ score: s.score, label: s.label, short: new Date(s.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) }));
  el.insertAdjacentHTML('beforeend', `
    ${pts.length > 1 ? `<section class="panel" style="margin-bottom:16px"><h3>Risk score over time</h3><p class="sub">Lower is better. Scan again after each migration step to see the trend.</p>${lineChart(pts)}</section>` : ''}
    <div class="table-wrap"><table><thead><tr><th>Scan</th><th>Date</th><th class="num">Files</th><th class="num">Findings</th><th class="num">Critical</th><th>Risk</th><th>Actions</th></tr></thead><tbody>
    ${list.map(s => `<tr><td><strong>${esc(s.label)}</strong><small>Scan ${s.id}</small></td><td>${esc(fmtDate(s.created_at))}</td>
      <td class="num">${s.files_scanned}</td><td class="num">${s.findings}</td><td class="num">${s.critical}</td>
      <td>${levelBadge(s.level)} <span class="muted">${s.score}</span></td>
      <td><div style="display:flex;gap:6px;flex-wrap:wrap"><button class="btn small" data-open="${s.id}" type="button">Open</button>
      <a class="btn small" href="/api/scans/${s.id}/report.pdf" download>PDF report</a>
      <button class="btn small danger" data-del="${s.id}" type="button" aria-label="Delete ${esc(s.label)}">Delete</button></div></td></tr>`).join('')}
    </tbody></table></div>`);
  $$('[data-open]', el).forEach(b => b.onclick = async () => { try { await selectScan(+b.dataset.open); if (location.hash === '#/overview') render(); else location.hash = '#/overview'; } catch (e) { toast(e.message, true); } });
  $$('[data-del]', el).forEach(b => b.onclick = async () => {
    if (!confirm('Delete this scan and its report?')) return;
    try {
      const id = +b.dataset.del; await api(`/api/scans/${id}`, { method: 'DELETE' });
      const keepId = state.scan && state.scan.id !== id ? state.scan.id : null;
      await refreshOverview(); if (keepId && state.list.some(s => s.id === keepId)) await selectScan(keepId);
      toast('Scan deleted.'); render();
    } catch (e) { toast(e.message, true); }
  });
  const ca = $('#clearAll');
  if (ca) ca.onclick = async () => {
    if (!confirm('Delete all saved scans and reports? This cannot be undone.')) return;
    try { await api('/api/scans', { method: 'DELETE' }); await refreshOverview(); toast('History cleared.'); render(); } catch (e) { toast(e.message, true); }
  };
};

/* ======================= router ======================= */
const TITLES = { overview: 'Overview', upload: 'Upload and scan', tls: 'TLS endpoint scan', results: 'Analysis results', fixfirst: 'What to fix first', risk: 'Risk score', plan: 'Migration plan', history: 'History and reports' };
function currentRoute() { const r = (location.hash.replace(/^#\/?/, '') || 'overview'); return views[r] ? r : 'overview'; }
function render() {
  const route = currentRoute();
  $$('#nav a').forEach(a => a.getAttribute('data-route') === route ? a.setAttribute('aria-current', 'page') : a.removeAttribute('aria-current'));
  $('#pageTitle').textContent = TITLES[route];
  document.title = `${TITLES[route]} | VULNEXIS`;
  document.body.classList.remove('nav-open'); $('#menuBtn').setAttribute('aria-expanded', 'false');
  views[route]($('#view'));
}

async function init() {
  $('#menuBtn').onclick = () => { const o = document.body.classList.toggle('nav-open'); $('#menuBtn').setAttribute('aria-expanded', String(o)); };
  $('#scrim').onclick = () => { document.body.classList.remove('nav-open'); $('#menuBtn').setAttribute('aria-expanded', 'false'); };
  
  const themeSel = $('#themeSelect');
  if (themeSel) {
    themeSel.value = savedTheme;
    themeSel.onchange = () => {
      const theme = themeSel.value;
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('vulnexis-theme', theme);
      const name = theme === 'executive' ? 'Executive Slate (Professional)' : (theme === 'cyberpunk' ? 'Cyber Red Team' : (theme === 'monochrome' ? 'Black & White Minimal' : 'Classic Dark'));
      toast(`Theme switched to ${name}`);
    };
  }

  $('#scanSelect').onchange = async e => { try { await selectScan(+e.target.value); render(); } catch (err) { toast(err.message, true); } };
  window.addEventListener('hashchange', () => { render(); $('#view').focus({ preventScroll: true }); window.scrollTo(0, 0); });
  $('#view').innerHTML = '<div class="skeleton"></div>';
  const pill = $('#backendPill');
  try {
    const h = await api('/api/health');
    pill.className = 'pill ok'; $('span', pill).textContent = 'Backend online';
    if (!h.pdf_reports) toast('PDF reports are unavailable. Install reportlab on the server.', true);
  } catch { pill.className = 'pill bad'; $('span', pill).textContent = 'Backend unreachable'; }
  try { await refreshOverview(); } catch (e) { toast(e.message, true); }
  render();
}
init();
})();
