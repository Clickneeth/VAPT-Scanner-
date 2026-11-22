'use strict';
/* VAPT Console front end. No framework, no inline handlers; every dynamic string goes through textContent. */

const $ = (s, r = document) => r.querySelector(s);
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k.startsWith('aria-') || k === 'role' || k === 'for') el.setAttribute(k, v === true ? 'true' : v);
    else if (k in el) { try { el[k] = v; } catch (_) { el.setAttribute(k, v); } }
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
const svg = (d) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', '1.8'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round'); s.setAttribute('aria-hidden', 'true'); const p = document.createElementNS('http://www.w3.org/2000/svg', 'path'); p.setAttribute('d', d); s.append(p); return s; };
const ICON = {
  home: 'M12 3l9 8-1.5 1.7-1.5-1.3V20H6v-8.6l-1.5 1.3L3 11zM10 20v-5h4v5',
  scope: 'M12 3l8 3v6c0 5-3.4 8-8 9-4.6-1-8-4-8-9V6zM9 12l2 2 4-4',
  assets: 'M3 6h18M3 12h18M3 18h18M7 3v18',
  scans: 'M4 12a8 8 0 1 0 8-8M4 4v5h5M12 8v4l3 2',
  findings: 'M12 3l9 16H3zM12 10v4M12 17h.01',
  audit: 'M6 3h9l4 4v14H6zM9 12h7M9 16h7M9 8h3',
};
const SEV = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
const SEVC = { CRITICAL: 'var(--crit)', HIGH: 'var(--high)', MEDIUM: 'var(--med)', LOW: 'var(--low)', INFO: 'var(--info)' };

const S = {
  meta: null, targets: [], assets: [], scans: [], findings: [], audit: [],
  view: 'home', sel: new Set(), profile: 'standard',
  af: { q: '', mode: 'all', target: 'all' }, ff: { q: '', sev: null, host: 'all' }, scanFilter: 'active',
  openScan: null, scanDetail: null, logOffset: 0, logText: '', tab: 'log', sig: '',
};

async function api(path, opts = {}) {
  const r = await fetch(path, {
    method: opts.method || 'GET',
    headers: { 'X-VAPT-UI': '1', ...(opts.body ? { 'Content-Type': 'application/json' } : {}) },
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let j = null; try { j = await r.json(); } catch (_) { /* not json */ }
  if (!r.ok) {
    const d = j && (j.detail || j.error);
    throw new Error(Array.isArray(d) ? d.map((x) => x.msg).join('; ') : (d || 'HTTP ' + r.status));
  }
  return j;
}

/* ---------- helpers ---------- */
function toast(msg, kind = '') {
  const t = h('div', { class: 'toast ' + kind }, msg);
  $('#toasts').append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 8000 : 4500);
}
function ago(ts) {
  if (!ts) return '';
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s / 60) + 'm ago';
  if (s < 86400) return Math.floor(s / 3600) + 'h ago';
  return Math.floor(s / 86400) + 'd ago';
}
function dur(a, b) {
  if (!a) return '';
  const s = Math.max(0, Math.round(((b ? new Date(b) : new Date()) - new Date(a)) / 1000));
  return s < 60 ? s + 's' : Math.floor(s / 60) + 'm ' + (s % 60) + 's';
}
const riskClass = (n) => (n >= 50 ? 'critical' : n >= 20 ? 'high' : n >= 6 ? 'medium' : n > 0 ? 'low' : 'clean');
function riskBar(score, has) {
  if (!has) return h('span', { class: 'faint' }, 'Not scanned');
  const c = riskClass(score);
  const fill = h('span'); fill.style.width = Math.max(score, 3) + '%';
  return h('span', { class: 'risk' }, h('span', { class: 'bar ' + c }, fill), h('b', {}, score));
}
const pill = (status, label) => h('span', { class: 'pill ' + status }, h('i'), label || status);
const sevBadge = (s) => h('span', { class: 'sev ' + s }, s);
function countsRow(c) {
  const parts = SEV.filter((k) => c && c[k]).map((k) => h('span', { class: 'sev ' + k }, c[k] + ' ' + k[0]));
  return h('span', { class: 'row' }, parts.length ? parts : h('span', { class: 'faint' }, 'clean'));
}
function modal(title, body, actions, opts = {}) {
  const root = $('#modal-root');
  const prev = document.activeElement;
  const close = () => { scrim.remove(); document.removeEventListener('keydown', onKey); if (prev && prev.focus) prev.focus(); };
  const onKey = (e) => { if (e.key === 'Escape') close(); };
  const box = h('div', { class: 'card modal', role: 'dialog', 'aria-modal': 'true', 'aria-label': title },
    h('h2', {}, title), body, h('div', { class: 'row spread' }, h('span'), h('div', { class: 'row' }, actions(close))));
  const scrim = h('div', { class: 'scrim', onclick: (e) => { if (e.target === scrim) close(); } }, box);
  root.append(scrim);
  document.addEventListener('keydown', onKey);
  const first = $('input,textarea,select,button.primary', box); if (first) first.focus();
  return close;
}
const tHost = (id) => (S.targets.find((t) => t.id === id) || {}).value || '?';
const total = (c) => Object.values(c || {}).reduce((a, b) => a + b, 0);

/* ---------- views ---------- */
const VIEWS = {
  home: { title: 'Scan', sub: 'Enter a target. We map its subdomains, then scan every live host.' },
  scope: { title: 'Manual setup', sub: 'Advanced: drop targets, map subdomains first, then choose exactly what to scan.' },
  assets: { title: 'Assets', sub: 'Pick what to test: single hosts, a selection, or everything that is alive.' },
  scans: { title: 'Scans', sub: 'Live progress, logs and results for every run.' },
  findings: { title: 'Findings', sub: 'Latest result for every asset, with what changed since the previous scan.' },
  audit: { title: 'Audit log', sub: 'Every authorisation and scan action, newest first.' },
};
let ctx = {};   // refs of the mounted view


/* ----- HOME: enter a target, scanning starts ----- */
function jobInfo(t) {
  const assets = S.assets.filter((a) => a.target_id === t.id), ids = new Set(assets.map((a) => a.id));
  const live = assets.filter((a) => a.alive && !a.excluded && !a.wildcard);
  const scans = S.scans.filter((s) => ids.has(s.asset_id));
  const active = scans.filter((s) => s.status === 'queued' || s.status === 'running');
  const fin = scans.filter((s) => !(s.status === 'queued' || s.status === 'running'));
  const counts = {}; assets.forEach((a) => Object.entries(a.last_counts || {}).forEach(([k, v]) => { counts[k] = (counts[k] || 0) + v; }));
  const part = active.reduce((n, s) => n + (s.status === 'running' ? s.module / 10 : 0), 0);
  return { assets, live, scans, active, fin, counts, pct: scans.length ? Math.round(((fin.length + part) / scans.length) * 100) : 0 };
}
function jobStage(t, j) {
  if (t.status === 'discovering' || t.status === 'new') return { key: 'discovering', label: 'Step 1 of 2: mapping subdomains and finding live hosts', ind: true };
  if (t.status === 'failed') return { key: 'failed', label: t.error || 'Discovery failed', ind: false };
  if (t.status === 'revoked') return { key: 'revoked', label: 'Stopped: authorisation revoked', ind: false };
  if (!j.scans.length) return j.live.length ? { key: 'queued', label: 'Starting scans…', ind: true } : { key: 'done', label: 'Mapped ' + j.assets.length + ' host' + (j.assets.length === 1 ? '' : 's') + ', but none answered on the web, so nothing was scanned.', ind: false };
  if (j.active.length) { const run = j.active.find((s) => s.status === 'running'); return { key: 'running', label: `Step 2 of 2: scanned ${j.fin.length} of ${j.scans.length} hosts` + (run ? ` · now ${run.host}, module ${run.module}/10` : ''), ind: false }; }
  return { key: 'done', label: `Finished: ${j.scans.length} host${j.scans.length === 1 ? '' : 's'} scanned`, ind: false };
}
function mountHome(root) {
  const input = h('input', { type: 'text', class: 'bigin', id: 'qs-target', placeholder: 'example.com  or  203.0.113.7', autocomplete: 'off', spellcheck: false, 'aria-label': 'Target domain or IP address' });
  const att = h('input', { type: 'checkbox', id: 'qs-att' });
  const go1 = h('button', { class: 'btn primary big', type: 'button', disabled: true }, 'Scan');
  const note = h('p', { class: 'err', role: 'alert' });
  const profBox = h('div', {});
  const sync = () => { go1.disabled = !(att.checked && input.value.trim()); };
  const renderProf = () => profBox.replaceChildren(h('div', { class: 'row' }, profileSeg(renderProf), h('span', { class: 'hint' }, S.meta ? S.meta.profiles[S.profile].blurb : '')));
  S.profile = S.profile === 'standard' ? 'quick' : S.profile; renderProf();
  input.addEventListener('input', sync); att.addEventListener('change', sync);
  const submit = async () => {
    if (go1.disabled) return;
    go1.disabled = true; note.textContent = '';
    try {
      const r = await api('/api/quickscan', { method: 'POST', body: { text: input.value, attested: att.checked, profile: S.profile } });
      if (r.started.length) { toast('Started: ' + r.started.map((x) => x.value).join(', '), 'ok'); input.value = ''; }
      if (r.duplicates.length) toast(r.duplicates.join(', ') + ' is already tracked. See it below, or use Assets to scan it again.');
      if (r.rejected.length) note.textContent = r.rejected.map((x) => x.raw + ': ' + x.error).join(' · ');
      await refresh(true);
    } catch (e) { note.textContent = e.message; }
    sync();
  };
  go1.addEventListener('click', submit);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') submit(); });
  const jobs = h('div', { class: 'jobs' });
  root.append(
    h('div', { class: 'hero card' },
      h('div', { class: 'hero-copy' }, h('h2', {}, 'What do you want to scan?'), h('p', { class: 'muted' }, 'Type a domain or an IP address and press Scan. We find its subdomains first, then test every live host.')),
      h('div', { class: 'hero-row' }, input, go1),
      note,
      h('label', { class: 'check', for: 'qs-att' }, att, h('span', {}, 'I own this target or have written permission to test it, including every subdomain found under it.')),
      profBox,
      h('ol', { class: 'steps' }, h('li', {}, h('b', {}, '1'), ' Map subdomains'), h('li', {}, h('b', {}, '2'), ' Probe which are alive'), h('li', {}, h('b', {}, '3'), ' Scan every live host'), h('li', {}, h('b', {}, '4'), ' Read the results')),
      h('p', { class: 'hint' }, 'Want to pick hosts yourself, or add extra IPs? Use ', h('button', { class: 'iplink', type: 'button', onclick: () => go('scope') }, 'manual setup'), '.')),
    h('h3', {}, 'Your scans'), jobs);
  ctx = { jobs, input };
  updateHome();
}
function updateHome() {
  const { jobs } = ctx;
  if (!jobs) return;
  const ts = S.targets.filter((t) => t.auto_scan);
  if (!ts.length) { jobs.replaceChildren(h('div', { class: 'card empty' }, h('h2', {}, 'Nothing scanned yet'), h('p', {}, 'Enter a target above and your scan appears here.'))); return; }
  jobs.replaceChildren(...ts.map((t) => {
    const j = jobInfo(t), st = jobStage(t, j);
    const fill = h('span'); fill.style.width = (st.key === 'done' ? 100 : st.key === 'discovering' ? 40 : j.pct) + '%';
    const running = j.active.length > 0 || t.status === 'discovering';
    return h('article', { class: 'card job' },
      h('div', { class: 'row spread' }, h('span', { class: 'val' }, t.value), pill(st.key === 'done' ? 'done' : st.key === 'failed' || st.key === 'revoked' ? 'failed' : 'running', st.key === 'done' ? 'finished' : st.key === 'failed' ? 'failed' : st.key === 'revoked' ? 'stopped' : 'scanning')),
      h('span', { class: 'bar ' + (st.ind ? 'indeterminate' : st.key === 'done' ? riskClass(Math.max(0, ...Object.entries(j.counts).map(([k, v]) => v * ({ CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1 }[k] || 0)))) : '') }, fill),
      h('p', { class: 'muted' }, st.label),
      st.key === 'done' || j.fin.length ? h('div', { class: 'row' }, countsRow(j.counts), j.live.length ? h('span', { class: 'hint' }, j.live.length + ' live host' + (j.live.length === 1 ? '' : 's') + ' · ' + j.assets.length + ' found') : null) : null,
      t.warning ? h('p', { class: 'warn' }, t.warning) : null,
      h('div', { class: 'row' },
        j.scans.length ? h('button', { class: 'btn small primary', type: 'button', onclick: () => { const r = j.active[0] || j.scans[0]; S.openScan = r.id; S.scanDetail = null; S.logOffset = 0; S.logText = ''; go('scans'); } }, running ? 'Watch live' : 'Open log') : null,
        j.fin.length ? h('button', { class: 'btn small', type: 'button', onclick: () => { S.ff.q = t.value; S.ff.sev = null; S.ff.host = 'all'; go('findings'); } }, 'See results') : null,
        j.live.length > 0 || t.status === 'ready' ? h('button', { class: 'btn small ghost', type: 'button', onclick: () => { S.af.target = String(t.id); go('assets'); } }, 'Hosts (' + j.assets.length + ')') : null,
        running ? h('button', { class: 'btn small danger', type: 'button', onclick: async () => { for (const s of j.active) { try { await api('/api/scans/' + s.id + '/cancel', { method: 'POST' }); } catch (e) { /* already finished */ } } if (t.status === 'discovering') { await api('/api/targets/' + t.id + '/revoke', { method: 'POST' }).catch(() => {}); } toast('Stopped ' + t.value, 'ok'); refresh(true); } }, 'Stop') : null));
  }));
}

/* ----- SCOPE ----- */
function mountScope(root) {
  const ta = h('textarea', { id: 'drop-text', rows: 5, spellcheck: false, 'aria-label': 'Targets', placeholder: 'example.com\napp.example.org\n203.0.113.7\n\nOne per line, or comma separated. Domains are mapped for subdomains; IPs are scanned as they are.' });
  const chips = h('div', { class: 'chips', 'aria-live': 'polite' });
  const info = h('span', {}, 'Drop a .txt or .csv here, or paste');
  const drop = h('div', { class: 'drop' }, ta, h('div', { class: 'drop-foot' }, info, chips));
  const att = h('input', { type: 'checkbox', id: 'att' });
  const basis = h('textarea', { id: 'basis', rows: 2, placeholder: 'e.g. Written permission from Acme Corp (ticket SEC-142), or HackerOne program "acme" in scope', style: '' });
  basis.removeAttribute('style'); basis.style.fontFamily = 'var(--sans)';
  const go = h('button', { class: 'btn primary', type: 'button', disabled: true }, 'Authorise and discover subdomains');
  const need = S.meta ? S.meta.limits.min_basis : 10;
  let valid = 0;
  const sync = () => { go.disabled = !(att.checked && basis.value.trim().length >= need && valid > 0); };
  let timer;
  const preview = () => {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (!ta.value.trim()) { chips.replaceChildren(); valid = 0; sync(); return; }
      try {
        const r = await api('/api/parse', { method: 'POST', body: { text: ta.value } });
        valid = r.items.filter((i) => !i.error).length;
        chips.replaceChildren(...r.items.slice(0, 60).map((i) => i.error
          ? h('span', { class: 'chip bad', title: i.error }, i.raw, h('small', {}, 'invalid'))
          : h('span', { class: 'chip ' + i.kind, title: i.warning || '' }, i.value, h('small', {}, i.kind))));
        sync();
      } catch (e) { /* preview is best effort */ }
    }, 250);
  };
  ta.addEventListener('input', preview);
  att.addEventListener('change', sync); basis.addEventListener('input', sync);
  ['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
  ['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('over')));
  drop.addEventListener('drop', async (e) => {
    const files = [...(e.dataTransfer?.files || [])];
    if (!files.length) return;
    e.preventDefault();
    for (const f of files.slice(0, 5)) {
      if (f.size > 200000) { toast(f.name + ' is larger than 200 KB, skipped', 'err'); continue; }
      ta.value += (ta.value && !ta.value.endsWith('\n') ? '\n' : '') + await f.text();
    }
    preview();
  });
  go.addEventListener('click', async () => {
    go.disabled = true;
    try {
      const r = await api('/api/targets', { method: 'POST', body: { text: ta.value, attested: att.checked, basis: basis.value } });
      if (r.added.length) toast(`Added ${r.added.length} target${r.added.length > 1 ? 's' : ''}. Discovery started.`, 'ok');
      if (r.duplicates.length) toast('Already tracked: ' + r.duplicates.join(', '));
      if (r.rejected.length) toast('Rejected: ' + r.rejected.map((x) => x.raw + ' (' + x.error + ')').join('; '), 'err');
      if (r.added.length) { ta.value = ''; chips.replaceChildren(); valid = 0; }
      await refresh(true);
    } catch (e) { toast(e.message, 'err'); }
    sync();
  });
  const authBox = h('div', { class: 'auth stack' },
    h('h3', {}, 'Authorisation'),
    h('label', { class: 'check', for: 'att' }, att, h('span', {}, 'I own these systems or have explicit written permission to test them, including every subdomain discovered under a domain.')),
    h('div', { class: 'field' }, h('label', { class: 'l', for: 'basis' }, 'Basis (stored in the audit log)'), basis,
      h('p', { class: 'hint' }, `At least ${need} characters. Name who permitted it or which program covers it.`)));
  const list = h('div', { class: 'targets' });
  root.append(
    h('div', { class: 'card pad stack' },
      h('div', {}, h('h2', {}, 'Drop your targets'), h('p', { class: 'muted' }, 'Step 1 is passive: subdomain discovery and a light liveness probe. Nothing is scanned until you choose, in Assets.')),
      drop, authBox, h('div', { class: 'row spread' }, h('p', { class: 'hint' }, 'Link-local, multicast and reserved IPs are refused. Credentials in URLs are dropped.'), go)),
    h('div', { class: 'row spread', style: '' }, h('h3', {}, 'Tracked targets')),
    list);
  ctx = { list };
  updateScope();
}
function updateScope() {
  const { list } = ctx;
  if (!list) return;
  if (!S.targets.length) { list.replaceChildren(h('div', { class: 'card empty' }, h('h2', {}, 'No targets yet'), h('p', {}, 'Paste a domain above to begin.'))); return; }
  list.replaceChildren(...S.targets.map((t) => {
    const as = S.assets.filter((a) => a.target_id === t.id);
    const alive = as.filter((a) => a.alive).length;
    const scanned = as.filter((a) => a.last_scan_id).length;
    return h('article', { class: 'card tcard' },
      h('div', { class: 'row spread' }, h('span', { class: 'val' }, t.value), pill(t.status)),
      h('div', { class: 'stats' },
        h('div', { class: 'stat' }, h('b', {}, as.length), h('span', {}, t.kind === 'domain' ? 'hosts found' : 'address')),
        h('div', { class: 'stat' }, h('b', {}, alive), h('span', {}, 'live web')),
        h('div', { class: 'stat' }, h('b', {}, scanned), h('span', {}, 'scanned'))),
      t.status === 'discovering' ? h('div', {}, h('span', { class: 'bar indeterminate' }, h('span')), h('p', { class: 'hint' }, 'Mapping subdomains and probing which are alive…')) : null,
      t.warning ? h('p', { class: 'warn' }, t.warning) : null,
      t.error ? h('p', { class: 'err' }, t.error) : null,
      h('p', { class: 'hint' }, 'Authorised ' + ago(t.authorised_at) + ': ' + t.basis),
      h('div', { class: 'row' },
        h('button', { class: 'btn small primary', type: 'button', disabled: t.status === 'revoked', onclick: () => { S.af.target = String(t.id); go('assets'); } }, 'Choose what to scan'),
        h('button', { class: 'btn small', type: 'button', disabled: t.status === 'discovering' || t.status === 'revoked', onclick: () => act('/api/targets/' + t.id + '/discover', 'Discovery restarted') }, 'Re-discover'),
        t.status !== 'revoked' ? h('button', { class: 'btn small danger', type: 'button', onclick: () => confirmRevoke(t) }, 'Revoke') : null,
        h('button', { class: 'btn small ghost', type: 'button', onclick: () => confirmDelete(t) }, 'Delete')));
  }));
}
async function act(path, okMsg, method = 'POST') {
  try { await api(path, { method }); if (okMsg) toast(okMsg, 'ok'); await refresh(true); } catch (e) { toast(e.message, 'err'); }
}
function confirmRevoke(t) {
  modal('Revoke authorisation?', h('p', {}, `Queued and running scans for ${t.value} stop immediately and nothing more can be scanned there. Existing results stay.`),
    (close) => [h('button', { class: 'btn', type: 'button', onclick: close }, 'Cancel'),
      h('button', { class: 'btn danger', type: 'button', onclick: () => { close(); act('/api/targets/' + t.id + '/revoke', 'Revoked ' + t.value); } }, 'Revoke')]);
}
function confirmDelete(t) {
  modal('Delete target and its data?', h('p', {}, `This removes ${t.value}, its hosts, scans, findings and saved logs from this machine. It cannot be undone.`),
    (close) => [h('button', { class: 'btn', type: 'button', onclick: close }, 'Keep'),
      h('button', { class: 'btn danger', type: 'button', onclick: () => { close(); act('/api/targets/' + t.id, 'Deleted ' + t.value, 'DELETE'); } }, 'Delete')]);
}

/* ----- ASSETS ----- */
function filteredAssets() {
  const f = S.af, q = f.q.trim().toLowerCase();
  return S.assets.filter((a) => {
    if (f.target !== 'all' && String(a.target_id) !== f.target) return false;
    if (q && !(a.host.includes(q) || a.title.toLowerCase().includes(q) || a.ips.join(' ').includes(q) || a.tech.join(' ').toLowerCase().includes(q))) return false;
    if (f.mode === 'excluded') return !!a.excluded;
    if (a.excluded) return false;
    if (f.mode === 'live') return a.alive;
    if (f.mode === 'unscanned') return !a.last_scan_id;
    if (f.mode === 'findings') return total(a.last_counts) > 0;
    return true;
  });
}
function mountAssets(root) {
  const search = h('input', { type: 'search', class: 'search', placeholder: 'Filter by host, IP, title, technology', 'aria-label': 'Filter assets', value: S.af.q });
  const tsel = h('select', { 'aria-label': 'Target', onchange: (e) => { S.af.target = e.target.value; updateAssets(); } });
  const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Filter' });
  const modes = [['all', 'All'], ['live', 'Live web'], ['unscanned', 'Unscanned'], ['findings', 'With findings'], ['excluded', 'Excluded']];
  const renderSeg = () => seg.replaceChildren(...modes.map(([k, l]) => h('button', { type: 'button', 'aria-pressed': String(S.af.mode === k), onclick: () => { S.af.mode = k; renderSeg(); updateAssets(); } }, l)));
  renderSeg();
  search.addEventListener('input', () => { S.af.q = search.value; updateAssets(); });
  const addBtn = h('button', { class: 'btn small', type: 'button', onclick: () => addAssetModal() }, '+ Add IP or host');
  const liveBtn = h('button', { class: 'btn small primary', type: 'button', onclick: () => { const live = filteredAssets().filter((a) => a.alive); S.sel = new Set(live.map((a) => a.id)); updateAssets(); confirmScan(); } }, 'Scan all live');
  const head = h('input', { type: 'checkbox', 'aria-label': 'Select all filtered', onchange: (e) => { const rows = filteredAssets().filter((a) => !a.excluded); if (e.target.checked) rows.forEach((a) => S.sel.add(a.id)); else rows.forEach((a) => S.sel.delete(a.id)); updateAssets(); } });
  const tbody = h('tbody');
  const meta = h('span', { class: 'hint' });
  const bar = h('div', { class: 'actionbar', role: 'region', 'aria-label': 'Scan selection' });
  const table = h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, head), h('th', {}, 'Host'), h('th', {}, 'Addresses'), h('th', {}, 'Web'), h('th', {}, 'Last scan'), h('th', {}, ''))), tbody);
  root.append(h('div', { class: 'card' }, h('div', { class: 'toolbar' }, search, tsel, seg, h('span', { class: 'row' }, addBtn, liveBtn)), h('div', { class: 'toolbar' }, meta), h('div', { class: 'tablewrap' }, table)), bar);
  ctx = { tbody, head, meta, bar, tsel };
  updateAssets();
}
function updateAssets() {
  const { tbody, head, meta, bar, tsel } = ctx;
  if (!tbody) return;
  const cur = S.af.target;
  tsel.replaceChildren(h('option', { value: 'all' }, 'All targets'), ...S.targets.map((t) => h('option', { value: String(t.id) }, t.value)));
  tsel.value = cur;
  const rows = filteredAssets();
  const selectable = rows.filter((a) => !a.excluded);
  const n = selectable.filter((a) => S.sel.has(a.id)).length;
  head.checked = selectable.length > 0 && n === selectable.length;
  head.indeterminate = n > 0 && n < selectable.length;
  meta.textContent = `${rows.length} shown · ${S.assets.filter((a) => a.alive).length} live of ${S.assets.length} total`;
  if (!rows.length) {
    tbody.replaceChildren(h('tr', {}, h('td', { colSpan: 6 }, h('div', { class: 'empty' }, h('h2', {}, S.assets.length ? 'Nothing matches' : 'No assets yet'), h('p', {}, S.assets.length ? 'Change the filter.' : 'Add a target in Scope, or add an IP or host here.')))));
  } else {
    tbody.replaceChildren(...rows.map((a) => {
      const cb = h('input', { type: 'checkbox', checked: S.sel.has(a.id), disabled: !!a.excluded, 'aria-label': 'Select ' + a.host, onchange: (e) => { e.target.checked ? S.sel.add(a.id) : S.sel.delete(a.id); updateAssets(); } });
      const code = a.status_code ? h('span', { class: 'code s' + String(a.status_code)[0] }, a.status_code) : null;
      const ips = a.ips.length ? h('span', { class: 'stack', style: '' }, a.ips.slice(0, 3).map((ip) => (a.kind === 'ip' ? h('span', { class: 'mono' }, ip) : h('button', { class: 'iplink', type: 'button', title: 'Add this IP as its own asset', onclick: () => addAssetModal(a.target_id, ip) }, ip))), a.ips.length > 3 ? h('span', { class: 'faint' }, '+' + (a.ips.length - 3) + ' more') : null) : h('span', { class: 'faint' }, 'no DNS');
      ips.removeAttribute('style');
      const running = S.scans.find((s) => s.asset_id === a.id && (s.status === 'queued' || s.status === 'running'));
      return h('tr', { class: (S.sel.has(a.id) ? 'sel ' : '') + (a.excluded ? 'dim' : '') },
        h('td', {}, cb),
        h('td', { class: 'host' }, a.host, ' ', h('span', { class: 'kind' }, a.kind), a.wildcard ? h('span', { class: 'sub', title: 'Wildcard DNS zone' }, 'Wildcard DNS: may not be a real host') : null, a.note ? h('span', { class: 'sub warn' }, a.note) : null),
        h('td', {}, ips),
        h('td', {}, a.alive ? h('div', {}, code, ' ', h('span', { class: 'muted' }, a.server), h('span', { class: 'sub' }, a.title), a.tech.length ? h('div', { class: 'tech' }, a.tech.slice(0, 4).map((t) => h('span', {}, t))) : null) : h('span', { class: 'faint' }, 'No web response')),
        h('td', {}, running ? pill(running.status, running.status === 'running' ? 'Scanning ' + running.module + '/10' : 'Queued') : h('div', {}, riskBar(a.last_risk || 0, !!a.last_scan_id), a.last_scan_id ? h('div', { class: 'row' }, countsRow(a.last_counts), h('button', { class: 'iplink', type: 'button', onclick: () => { S.openScan = a.last_scan_id; go('scans'); } }, ago(a.last_finished))) : null)),
        h('td', {}, h('div', { class: 'row' },
          h('button', { class: 'btn small', type: 'button', disabled: !!a.excluded || !!running, onclick: () => { S.sel = new Set([a.id]); confirmScan(); } }, 'Scan'),
          h('button', { class: 'btn small ghost', type: 'button', 'aria-label': (a.excluded ? 'Include ' : 'Exclude ') + a.host, title: a.excluded ? 'Include in scope' : 'Exclude from scope', onclick: () => act('/api/assets/' + a.id + '/exclude') }, a.excluded ? 'Include' : 'Exclude'))));
    }));
  }
  const count = [...S.sel].filter((id) => S.assets.some((a) => a.id === id)).length;
  bar.classList.toggle('show', count > 0);
  bar.replaceChildren(
    h('strong', {}, count + ' selected'),
    profileSeg(() => updateAssets()),
    h('span', { class: 'hint' }, S.meta ? S.meta.profiles[S.profile].blurb : ''),
    h('span', { style: '' }),
    h('button', { class: 'btn', type: 'button', onclick: () => { S.sel.clear(); updateAssets(); } }, 'Clear'),
    h('button', { class: 'btn primary', type: 'button', onclick: confirmScan }, 'Scan selected'));
  bar.lastChild.previousSibling.previousSibling.style.flex = '1';
}
function profileSeg(after) {
  const profs = S.meta ? Object.entries(S.meta.profiles) : [];
  return h('div', { class: 'seg', role: 'group', 'aria-label': 'Scan profile' }, profs.map(([k, p]) => h('button', { type: 'button', 'aria-pressed': String(S.profile === k), title: p.blurb, onclick: () => { S.profile = k; after(); } }, p.label)));
}
function confirmScan() {
  const ids = [...S.sel];
  if (!ids.length) return;
  const picked = S.assets.filter((a) => ids.includes(a.id));
  const cool = picked.filter((a) => a.cooldown > 0);
  const force = h('input', { type: 'checkbox', id: 'force' });
  const prof = S.meta.profiles[S.profile];
  const mins = Math.max(5, Math.round((prof.timeout_s / 60 / 3) * Math.ceil(picked.length / S.meta.limits.concurrency)));
  const body = h('div', { class: 'stack' },
    h('dl', { class: 'kv' }, h('dt', {}, 'Assets'), h('dd', {}, picked.length + (picked.length > 3 ? ` (${picked.slice(0, 3).map((a) => a.host).join(', ')}, …)` : ` (${picked.map((a) => a.host).join(', ')})`)),
      h('dt', {}, 'Profile'), h('dd', {}, prof.label + ': ' + prof.blurb),
      h('dt', {}, 'Runs'), h('dd', {}, `${S.meta.limits.concurrency} at a time. Rough total ${mins}+ min.`)),
    cool.length ? h('label', { class: 'check', for: 'force' }, force, h('span', {}, `${cool.length} scanned in the last ${Math.round(S.meta.limits.cooldown_s / 60)} min. Scan them again anyway.`)) : null,
    h('p', { class: 'hint' }, 'Active testing sends real traffic to these hosts. Only continue for targets you are authorised to test.'));
  modal('Start scanning?', body, (close) => [h('button', { class: 'btn', type: 'button', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', type: 'button', onclick: async () => {
      close();
      try {
        const r = await api('/api/scans', { method: 'POST', body: { asset_ids: ids, profile: S.profile, force: force.checked } });
        if (r.queued.length) toast(`${r.queued.length} scan${r.queued.length > 1 ? 's' : ''} queued`, 'ok');
        if (r.skipped.length) toast('Skipped: ' + r.skipped.slice(0, 4).map((x) => x.host + ' (' + x.reason + ')').join('; ') + (r.skipped.length > 4 ? '…' : ''), r.queued.length ? '' : 'err');
        S.sel.clear();
        if (r.queued.length) { S.openScan = r.queued[0]; S.scanDetail = null; S.logOffset = 0; S.logText = ''; go('scans'); }
        await refresh(true);
      } catch (e) { toast(e.message, 'err'); }
    } }, 'Start scan')]);
}
function addAssetModal(targetId, value) {
  const act0 = S.targets.filter((t) => t.status !== 'revoked');
  if (!act0.length) { toast('Add a target in Scope first', 'err'); return; }
  const sel = h('select', { id: 'na-t' }, act0.map((t) => h('option', { value: t.id }, t.value)));
  if (targetId) sel.value = String(targetId);
  const val = h('input', { type: 'text', id: 'na-v', placeholder: '203.0.113.7 or api.partner.com', value: value || '' });
  const att = h('input', { type: 'checkbox', id: 'na-a' });
  const basis = h('textarea', { id: 'na-b', rows: 2, placeholder: 'Why you may test this address (it can belong to someone else, e.g. a cloud provider).' });
  basis.style.fontFamily = 'var(--sans)';
  const body = h('div', { class: 'stack' },
    h('div', { class: 'field' }, h('label', { class: 'l', for: 'na-t' }, 'Attach to target'), sel),
    h('div', { class: 'field' }, h('label', { class: 'l', for: 'na-v' }, 'IP address or hostname'), val),
    h('div', { class: 'auth stack' }, h('label', { class: 'check', for: 'na-a' }, att, h('span', {}, 'I am authorised to test this exact address.')), basis));
  modal('Add an IP or host', body, (close) => [h('button', { class: 'btn', type: 'button', onclick: close }, 'Cancel'),
    h('button', { class: 'btn primary', type: 'button', onclick: async () => {
      try {
        const r = await api('/api/assets', { method: 'POST', body: { target_id: Number(sel.value), value: val.value, attested: att.checked, basis: basis.value } });
        close(); toast('Added ' + r.value + (r.warning ? '. ' + r.warning : ''), 'ok'); await refresh(true);
      } catch (e) { toast(e.message, 'err'); }
    } }, 'Add')]);
}

/* ----- SCANS ----- */
function mountScans(root) {
  const list = h('div'); const seg = h('div', { class: 'seg', role: 'group', 'aria-label': 'Scan filter' });
  const renderSeg = () => seg.replaceChildren(...[['active', 'Active'], ['all', 'All']].map(([k, l]) => h('button', { type: 'button', 'aria-pressed': String(S.scanFilter === k), onclick: () => { S.scanFilter = k; renderSeg(); updateScans(); } }, l)));
  renderSeg();
  const detail = h('div', { class: 'card' });
  root.append(h('div', { class: 'split' }, h('div', { class: 'card' }, h('div', { class: 'toolbar' }, seg), list), detail));
  ctx = { list, detail, term: null };
  updateScans();
}
function scanRow(s) {
  const pct = s.status === 'done' ? 100 : Math.round((s.module / 10) * 100);
  const fill = h('span'); fill.style.width = pct + '%';
  return h('div', { class: 'scanrow', role: 'option', tabIndex: 0, 'aria-selected': String(S.openScan === s.id), onclick: () => openScan(s.id), onkeydown: (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); openScan(s.id); } } },
    h('span', { class: 'h' }, s.host), pill(s.status),
    h('div', { class: 'm' }, h('span', {}, '#' + s.id + ' · ' + s.profile), s.status === 'running' ? h('span', { class: 'bar' }, fill) : null,
      s.status === 'running' ? h('span', {}, 'module ' + s.module + '/10') : null,
      h('span', {}, s.finished_at ? ago(s.finished_at) : dur(s.started_at)), s.status === 'done' || s.status === 'timeout' ? riskBar(s.risk, true) : null));
}
function openScan(id) { S.openScan = id; S.scanDetail = null; S.logOffset = 0; S.logText = ''; S.tab = 'log'; updateScans(); pollDetail(); }
function updateScans() {
  const { list, detail } = ctx;
  if (!list) return;
  const rows = S.scans.filter((s) => S.scanFilter === 'all' || s.status === 'running' || s.status === 'queued');
  list.setAttribute('role', 'listbox'); list.setAttribute('aria-label', 'Scans');
  list.replaceChildren(...(rows.length ? rows.map(scanRow) : [h('div', { class: 'empty' }, h('h2', {}, S.scans.length ? 'Nothing running' : 'No scans yet'), h('p', {}, 'Pick assets in the Assets tab and press Scan.'))]));
  renderDetail(detail);
}
function renderDetail(detail) {
  const d = S.scanDetail;
  if (!S.openScan || !d || d.scan.id !== S.openScan) {
    detail.replaceChildren(h('div', { class: 'empty' }, h('h2', {}, S.openScan ? 'Loading…' : 'Select a scan'), h('p', {}, 'Logs and findings appear here.')));
    return;
  }
  const s = d.scan, live = s.status === 'running' || s.status === 'queued';
  const tabBtn = (k, l) => h('button', { type: 'button', role: 'tab', 'aria-selected': String(S.tab === k), onclick: () => { S.tab = k; renderDetail(detail); } }, l);
  let content;
  if (S.tab === 'log') {
    const term = h('div', { class: 'terminal', tabIndex: 0, role: 'log', 'aria-label': 'Scan log' }, S.logText || (live ? 'Waiting for output…' : 'No log.'));
    content = term; ctx.term = term; requestAnimationFrame(() => { term.scrollTop = term.scrollHeight; });
  } else if (S.tab === 'findings') {
    content = d.findings.length ? h('div', { class: 'tablewrap' }, h('table', {}, h('tbody', {}, d.findings.map((f) => h('tr', {}, h('td', {}, sevBadge(f.severity)), h('td', {}, h('div', { class: 'find-title' }, f.title, f.status === 'new' ? h('span', { class: 'new' }, 'NEW') : null), h('div', { class: 'find-detail' }, f.detail))))))) : h('div', { class: 'empty' }, h('p', {}, live ? 'Findings appear when the scan finishes.' : 'No findings.'));
  } else {
    content = d.resolved.length ? h('div', { class: 'tablewrap' }, h('table', {}, h('tbody', {}, d.resolved.map((f) => h('tr', {}, h('td', {}, sevBadge(f.severity)), h('td', {}, h('div', { class: 'find-title' }, f.title), h('div', { class: 'find-detail' }, 'No longer reported: ' + f.detail))))))) : h('div', { class: 'empty' }, h('p', {}, 'Nothing resolved since the previous scan of this asset.'));
  }
  const newCount = d.findings.filter((f) => f.status === 'new').length;
  detail.replaceChildren(
    h('div', { class: 'pad stack' },
      h('div', { class: 'row spread' }, h('div', {}, h('h2', { class: 'mono' }, s.host), h('p', { class: 'muted' }, `Scan #${s.id} · ${s.profile} · ${dur(s.started_at, s.finished_at) || 'queued'}`)),
        h('div', { class: 'row' }, pill(s.status), live ? h('button', { class: 'btn small danger', type: 'button', onclick: () => act('/api/scans/' + s.id + '/cancel', 'Cancelling…') }, 'Cancel') : null,
          !live && (s.status === 'done' || s.status === 'timeout') ? h('a', { class: 'btn small', href: '/api/scans/' + s.id + '/report' }, 'Report (.md)') : null)),
      s.error ? h('p', { class: s.status === 'failed' ? 'err' : 'warn' }, s.error) : null,
      s.status === 'running' ? h('div', { class: 'bar' }, (() => { const f = h('span'); f.style.width = (s.module * 10) + '%'; return f; })()) : null),
    h('div', { class: 'tabs', role: 'tablist' }, tabBtn('log', 'Log'), tabBtn('findings', `Findings (${d.findings.length})${newCount ? ' · ' + newCount + ' new' : ''}`), tabBtn('changes', `Resolved (${d.resolved.length})`)),
    h('div', { class: 'pad' }, content));
}
async function pollDetail() {
  if (!S.openScan || S.view !== 'scans') return;
  try {
    const r = await api(`/api/scans/${S.openScan}?offset=${S.logOffset}`);
    if (r.scan.id !== S.openScan) return;
    S.logText = (S.logOffset === 0 ? '' : S.logText) + r.log;
    S.logOffset = r.next_offset; S.scanDetail = r;
    if (ctx.detail) {
      const term = ctx.term, atBottom = term ? term.scrollHeight - term.scrollTop - term.clientHeight < 40 : true;
      renderDetail(ctx.detail);
      if (ctx.term && atBottom) ctx.term.scrollTop = ctx.term.scrollHeight;
    }
  } catch (e) { /* transient */ }
}

/* ----- FINDINGS ----- */
function mountFindings(root) {
  const cards = h('div', { class: 'sevcards' }); const body = h('tbody');
  const q = h('input', { type: 'search', class: 'search', placeholder: 'Search findings', 'aria-label': 'Search findings', oninput: (e) => { S.ff.q = e.target.value; updateFindings(); } });
  const hsel = h('select', { 'aria-label': 'Host', onchange: (e) => { S.ff.host = e.target.value; updateFindings(); } });
  const exp = h('span', { class: 'row' }, h('a', { class: 'btn small', href: '/api/export?fmt=csv' }, 'Export CSV'), h('a', { class: 'btn small', href: '/api/export?fmt=json' }, 'Export JSON'));
  root.append(cards, h('div', { class: 'card' }, h('div', { class: 'toolbar' }, q, hsel, exp), h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'Severity'), h('th', {}, 'Finding'), h('th', {}, 'Host'), h('th', {}, 'Scan'))), body))));
  ctx = { cards, body, hsel };
  updateFindings();
}
function updateFindings() {
  const { cards, body, hsel } = ctx;
  if (!cards) return;
  const all = S.findings, cnt = Object.fromEntries(SEV.map((k) => [k, all.filter((f) => f.severity === k).length]));
  cards.replaceChildren(...SEV.map((k) => { const b = h('button', { class: 'sevcard', type: 'button', 'aria-pressed': String(S.ff.sev === k), onclick: () => { S.ff.sev = S.ff.sev === k ? null : k; updateFindings(); } }, h('b', {}, cnt[k]), h('span', {}, k)); b.style.setProperty('--c', SEVC[k]); return b; }));
  const hosts = [...new Set(all.map((f) => f.host))].sort();
  hsel.replaceChildren(h('option', { value: 'all' }, 'All hosts'), ...hosts.map((x) => h('option', { value: x }, x))); hsel.value = hosts.includes(S.ff.host) ? S.ff.host : 'all';
  const q = S.ff.q.trim().toLowerCase();
  const rows = all.filter((f) => (!S.ff.sev || f.severity === S.ff.sev) && (S.ff.host === 'all' || f.host === S.ff.host) && (!q || (f.title + f.detail + f.host).toLowerCase().includes(q)));
  body.replaceChildren(...(rows.length ? rows.map((f) => h('tr', {}, h('td', {}, sevBadge(f.severity)), h('td', {}, h('div', { class: 'find-title' }, f.title, f.status === 'new' ? h('span', { class: 'new' }, 'NEW') : null), h('div', { class: 'find-detail' }, f.detail)), h('td', { class: 'host' }, f.host), h('td', {}, h('button', { class: 'iplink', type: 'button', onclick: () => { S.openScan = f.scan_id; go('scans'); } }, '#' + f.scan_id)))) : [h('tr', {}, h('td', { colSpan: 4 }, h('div', { class: 'empty' }, h('h2', {}, all.length ? 'Nothing matches' : 'No findings yet'), h('p', {}, all.length ? 'Clear a filter.' : 'Results appear here after a scan finishes.'))))]));
}

/* ----- AUDIT ----- */
function mountAudit(root) {
  const body = h('tbody'); root.append(h('div', { class: 'card tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, h('th', {}, 'When'), h('th', {}, 'Action'), h('th', {}, 'Detail'))), body)));
  ctx = { body }; updateAudit();
}
function updateAudit() {
  const { body } = ctx; if (!body) return;
  body.replaceChildren(...(S.audit.length ? S.audit.map((a) => h('tr', {}, h('td', { class: 'mono' }, new Date(a.ts).toLocaleString()), h('td', {}, h('span', { class: 'kind' }, a.action)), h('td', {}, a.detail))) : [h('tr', {}, h('td', { colSpan: 3 }, h('div', { class: 'empty' }, 'Nothing logged yet.')))]));
}

/* ---------- shell ---------- */
const MOUNT = { home: mountHome, scope: mountScope, assets: mountAssets, scans: mountScans, findings: mountFindings, audit: mountAudit };
const UPDATE = { home: updateHome, scope: updateScope, assets: updateAssets, scans: updateScans, findings: updateFindings, audit: updateAudit };
function renderNav() {
  const counts = { home: S.targets.filter((t) => t.auto_scan && (t.status === 'discovering' || S.scans.some((x) => (x.status === 'running' || x.status === 'queued') && S.assets.some((a) => a.id === x.asset_id && a.target_id === t.id)))).length, scope: S.targets.length, assets: S.assets.length, scans: S.scans.filter((s) => s.status === 'running' || s.status === 'queued').length, findings: S.findings.length, audit: '' };
  $('#nav').replaceChildren(...Object.keys(VIEWS).map((k) => h('button', { type: 'button', 'aria-current': S.view === k ? 'page' : null, onclick: () => go(k) }, svg(ICON[k]), VIEWS[k].title, counts[k] !== '' && counts[k] !== 0 ? h('span', { class: 'n' }, counts[k]) : null)));
  const run = S.scans.filter((s) => s.status === 'running').length, q = S.scans.filter((s) => s.status === 'queued').length, disc = S.targets.filter((t) => t.status === 'discovering').length;
  const live = $('#live'); live.classList.toggle('on', run + q + disc > 0);
  live.lastChild.textContent = run + q + disc ? [disc ? disc + ' discovering' : '', run ? run + ' scanning' : '', q ? q + ' queued' : ''].filter(Boolean).join(' · ') : 'Idle';
}
function go(view) {
  S.view = view; location.hash = view;
  $('#title').textContent = VIEWS[view].title; $('#subtitle').textContent = VIEWS[view].sub; document.title = VIEWS[view].title + ' · VAPT Console';
  const root = $('#view'); root.replaceChildren(); ctx = {};
  MOUNT[view](root); renderNav();
  if (view === 'findings' || view === 'audit') refresh(true);
  if (view === 'scans') pollDetail();
}
async function refresh(force) {
  try {
    const st = await api('/api/state');
    const extra = S.view === 'findings' ? await api('/api/findings') : null;
    const aud = S.view === 'audit' ? await api('/api/audit') : null;
    if (extra) S.findings = extra.findings; if (aud) S.audit = aud.audit;
    const sig = JSON.stringify([st, S.findings.length, S.audit.length, extra && extra.findings.length]);
    S.targets = st.targets; S.assets = st.assets; S.scans = st.scans;
    if (S.view === 'scans') await pollDetail();
    if (sig !== S.sig || force) { S.sig = sig; renderNav(); if (UPDATE[S.view]) UPDATE[S.view](); }
  } catch (e) { /* server restarting */ }
}
function nextDelay() {
  return S.scans.some((s) => s.status === 'running' || s.status === 'queued') || S.targets.some((t) => t.status === 'discovering') ? 2000 : 6000;
}
async function loop() { await refresh(false); setTimeout(loop, nextDelay()); }

function initTheme() {
  let saved = null; try { saved = localStorage.getItem('vapt-theme'); } catch (_) { /* private mode */ }
  if (saved) document.documentElement.dataset.theme = saved;
  $('#theme').addEventListener('click', () => {
    const cur = document.documentElement.dataset.theme || (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark');
    const nxt = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.dataset.theme = nxt; try { localStorage.setItem('vapt-theme', nxt); } catch (_) { /* ignore */ }
  });
}
(async function boot() {
  initTheme();
  try { S.meta = await api('/api/meta'); } catch (e) { toast('Cannot reach the server: ' + e.message, 'err'); }
  if (S.meta) $('#tools').replaceChildren(...Object.entries(S.meta.tools).map(([t, ok]) => h('span', { class: 'tool ' + (ok ? 'ok' : 'missing'), title: ok ? 'installed' : 'not installed' }, t)));
  const st = await api('/api/state').catch(() => ({ targets: [], assets: [], scans: [] }));
  S.targets = st.targets; S.assets = st.assets; S.scans = st.scans;
  const v = location.hash.slice(1);
  go(VIEWS[v] ? v : 'home');
  addEventListener('hashchange', () => { const x = location.hash.slice(1); if (VIEWS[x] && x !== S.view) go(x); });
  setTimeout(loop, nextDelay());
})();
