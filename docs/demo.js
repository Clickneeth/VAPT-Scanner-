'use strict';
/* Demo backend for the GitHub Pages front page. It replaces fetch('/api/...') with a simulation that runs entirely in
   this browser tab. It makes NO network requests and scans NOTHING: every result is sample data. The real console
   (webui/run.sh) talks to the real scanner instead. */
(function () {
  const T0 = () => Date.now();
  const SAMPLE = [
    ['HIGH', 'Missing header: Content-Security-Policy', 'sample: this host does not set Content-Security-Policy'],
    ['HIGH', 'Missing header: Strict-Transport-Security', 'sample: this host does not set Strict-Transport-Security'],
    ['HIGH', 'Sensitive port open', 'sample: 22/tcp open ssh'],
    ['MEDIUM', 'Server version disclosed', 'sample: Server: Apache/2.4.7 (Ubuntu)'],
    ['MEDIUM', 'Nuclei: [ssh-weak-algo-supported] [medium]', 'sample: See nuclei.txt'],
    ['MEDIUM', 'Missing header: X-Frame-Options', 'sample: this host does not set X-Frame-Options'],
    ['LOW', 'Missing header: Referrer-Policy', 'sample: this host does not set Referrer-Policy'],
    ['LOW', 'Missing header: Permissions-Policy', 'sample: this host does not set Permissions-Policy'],
    ['INFO', 'Interesting endpoints crawled', 'sample: 14 endpoints'],
  ];
  const MODULES = ['RECONNAISSANCE', 'REACHABILITY CHECK', 'SECURITY HEADERS', 'PORT SCAN', 'DIRECTORY FUZZING',
    'TECH DETECTION', 'WEB CRAWL', 'VULNERABILITY SCAN', 'TLS / SSL AUDIT', 'WEB SERVER SCAN'];
  const PROFILES = {
    quick: { label: 'Quick', blurb: 'Headers, ports, tech, nuclei. About 5 to 10 minutes.', skip: [], timeout_s: 900 },
    standard: { label: 'Standard', blurb: 'Adds directory fuzzing, crawl and TLS audit. About 10 to 25 minutes.', skip: [], timeout_s: 1800 },
    deep: { label: 'Deep', blurb: 'Everything including nikto. Slowest, noisiest, up to 40 minutes.', skip: [], timeout_s: 2700 },
  };
  const DOMAIN = /^(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/;
  const IPV4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const SEC = 4;                                    // simulated seconds per module (kept short so the demo is quick)
  const targets = []; const cancelled = new Set(); const audit = [];
  let nextId = 1;

  const iso = (ms) => new Date(ms).toISOString();
  function host(raw) {
    let s = raw.trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, '').split('/')[0].split('?')[0].split('#')[0];
    s = s.slice(s.lastIndexOf('@') + 1);
    if (s.split(':').length === 2) s = s.split(':')[0];
    return s.replace(/\.$/, '');
  }
  function parse(text) {
    const seen = new Set(), out = [];
    for (const tok of (text || '').split(/[\s,;]+/)) {
      if (!tok || tok.startsWith('#')) continue;
      const v = host(tok); if (seen.has(v || tok)) continue; seen.add(v || tok);
      const m = v.match(IPV4);
      if (m) {
        const o = m.slice(1).map(Number);
        if (o.some((n) => n > 255) || o[0] === 0 || o[0] >= 224 || (o[0] === 169 && o[1] === 254)) out.push({ raw: tok.slice(0, 100), kind: '', value: '', warning: '', error: 'address class is never scanned (unspecified, multicast, link-local such as cloud metadata, reserved)' });
        else out.push({ raw: tok.slice(0, 100), kind: 'ip', value: v, warning: (o[0] === 10 || o[0] === 127 || (o[0] === 192 && o[1] === 168) || (o[0] === 172 && o[1] >= 16 && o[1] < 32)) ? 'private/loopback address: only your own lab or an authorised internal network' : '', error: '' });
      } else if (v.length <= 253 && DOMAIN.test(v)) out.push({ raw: tok.slice(0, 100), kind: 'domain', value: v, warning: '', error: '' });
      else out.push({ raw: tok.slice(0, 100), kind: '', value: '', warning: '', error: 'not a valid domain or IP address' });
    }
    return out;
  }

  /* Everything below is a pure function of "how long ago did this target start", so no timers are needed. */
  function hostsFor(t) {
    if (t.kind === 'ip') return [{ host: t.value, kind: 'ip', alive: true, ips: [t.value], code: 200, title: 'Sample web page', server: 'nginx', tech: ['Nginx'] }];
    const d = t.value;
    return [
      { host: d, kind: 'root', alive: true, ips: ['203.0.113.10', '203.0.113.11'], code: 200, title: 'Sample home page', server: 'cloudflare', tech: ['Cloudflare', 'React'] },
      { host: 'www.' + d, kind: 'subdomain', alive: true, ips: ['203.0.113.10'], code: 301, title: 'Moved', server: 'cloudflare', tech: ['Cloudflare'] },
      { host: 'api.' + d, kind: 'subdomain', alive: true, ips: ['203.0.113.20'], code: 401, title: 'Unauthorized', server: 'nginx/1.18', tech: ['Nginx', 'Express'] },
      { host: 'mail.' + d, kind: 'subdomain', alive: false, ips: ['203.0.113.30'], code: null, title: '', server: '', tech: [] },
    ];
  }
  function sim() {
    const state = { targets: [], assets: [], scans: [] }; let aid = 0;
    for (const t of targets) {
      const e = (T0() - t.t0) / 1000, discovering = e < 3;
      const tr = { id: t.id, kind: t.kind, value: t.value, status: t.revoked ? 'revoked' : discovering ? 'discovering' : 'ready', basis: 'Self-attested with the Quick Scan checkbox (demo)', authorised_at: iso(t.t0), created_at: iso(t.t0), discovered_at: discovering ? null : iso(t.t0 + 3000), error: '', warning: t.warning, auto_scan: t.profile };
      state.targets.push(tr);
      if (discovering) continue;
      const hs = hostsFor(t), live = hs.filter((x) => x.alive);
      hs.forEach((x, i) => {
        const id = t.id * 100 + i + 1; aid = id;
        const sc = scanFor(t, live, x);
        const done = sc && sc.status === 'done';
        const counts = done ? sc.counts : {};
        state.assets.push({ id, target_id: t.id, host: x.host, kind: x.kind, ips: x.ips, alive: x.alive, url: x.alive ? 'https://' + x.host : '', status_code: x.code, title: x.title, server: x.server, tech: x.tech, source: 'discovery', excluded: 0, wildcard: 0, note: '', created_at: iso(t.t0), last_scan_id: done ? sc.id : null, last_status: done ? 'done' : null, last_risk: done ? sc.risk : null, last_counts: counts, last_finished: done ? sc.finished_at : null, last_profile: done ? t.profile : null, cooldown: 0 });
        if (sc) state.scans.push(sc);
      });
    }
    state.scans.sort((a, b) => b.id - a.id);
    return state;
  }
  function scanFor(t, live, x) {
    const i = live.indexOf(x); if (i < 0) return null;
    const id = t.id * 100 + i + 1, start = t.t0 + 3000 + Math.floor(i / 2) * (MODULES.length * SEC * 1000 + 800);
    const e = (T0() - start) / 1000;
    const base = { id, asset_id: id, profile: t.profile, queued_at: iso(t.t0 + 3000), error: '', host: x.host, risk: 0, counts: {}, started_at: null, finished_at: null, module: 0 };
    if (cancelled.has(id)) return { ...base, status: 'cancelled', error: 'cancelled by you', started_at: iso(start), finished_at: iso(T0()), module: Math.max(0, Math.min(10, Math.floor(e / SEC))) };
    if (e < 0) return { ...base, status: 'queued' };
    const mod = Math.min(MODULES.length, Math.floor(e / SEC));
    if (mod < MODULES.length) return { ...base, status: 'running', started_at: iso(start), module: mod };
    const rows = findingsFor(i), counts = {}; rows.forEach((r) => { counts[r[0]] = (counts[r[0]] || 0) + 1; });
    const w = { CRITICAL: 10, HIGH: 5, MEDIUM: 2, LOW: 1, INFO: 0 };
    return { ...base, status: 'done', started_at: iso(start), finished_at: iso(start + MODULES.length * SEC * 1000), module: 10, counts, risk: Math.min(100, Object.entries(counts).reduce((n, [k, v]) => n + w[k] * v, 0)) };
  }
  const findingsFor = (i) => SAMPLE.filter((_, k) => (k + i) % 3 !== 2 || k < 3);
  function log(sc) {
    const lines = [`[*] Target  : https://${sc.host}`, '[*] DEMO: simulated output, nothing is being scanned', ''];
    for (let m = 0; m <= Math.min(sc.module, 9); m++) lines.push(` MODULE ${m + 1} — ${MODULES[m]}`, `[*] (simulated) ${MODULES[m].toLowerCase()} for ${sc.host}...`);
    if (sc.status === 'done') lines.push('', ' FINDINGS SUMMARY', '[+] Scan complete (simulated)');
    return lines.join('\n') + '\n';
  }

  const J = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { 'Content-Type': 'application/json' } });
  const NOPE = () => J({ detail: 'Disabled in the demo. Run the console on your own machine to use this.' }, 400);
  function route(method, path, params, body) {
    if (path === '/api/meta') return J({ profiles: PROFILES, tools: Object.fromEntries(['subfinder', 'httpx', 'nmap', 'ffuf', 'katana', 'nuclei', 'testssl.sh', 'nikto', 'whois', 'dig', 'curl'].map((k) => [k, true])), limits: { bulk: 200, concurrency: 2, cooldown_s: 300, min_basis: 10, targets_per_drop: 50 }, modules: 10 });
    if (path === '/api/state') return J(sim());
    if (path === '/api/parse') return J({ items: parse(body.text) });
    if (path === '/api/quickscan') {
      if (!body.attested) return J({ detail: 'Tick the box to confirm you are authorised to test this target.' }, 400);
      const items = parse(body.text);
      if (!items.length) return J({ detail: 'Enter a domain or IP address.' }, 400);
      const started = [], duplicates = [], rejected = [];
      for (const p of items) {
        if (p.error) { rejected.push({ raw: p.raw, error: p.error }); continue; }
        if (targets.some((t) => t.value === p.value)) { duplicates.push(p.value); continue; }
        const t = { id: nextId++, kind: p.kind, value: p.value, t0: T0(), profile: PROFILES[body.profile] ? body.profile : 'quick', warning: p.warning };
        targets.push(t); started.push({ id: t.id, value: t.value, kind: t.kind, warning: t.warning });
        audit.unshift({ ts: iso(T0()), action: 'target_authorised', detail: `${p.value} (${p.kind}); basis: Self-attested with the Quick Scan checkbox; DEMO, simulated` });
      }
      return J({ started, duplicates, rejected });
    }
    let m = path.match(/^\/api\/scans\/(\d+)$/);
    if (m && method === 'GET') {
      const st = sim(), sc = st.scans.find((s) => s.id === Number(m[1]));
      if (!sc) return J({ detail: 'unknown scan' }, 404);
      const text = log(sc), off = Number(params.get('offset') || 0), done = sc.status === 'done';
      const findings = done ? findingsFor((sc.id % 100) - 1).map((r) => ({ severity: r[0], title: r[1], detail: r[2], status: 'new' })) : [];
      return J({ scan: sc, log: text.slice(off), next_offset: text.length, findings, resolved: [] });
    }
    m = path.match(/^\/api\/scans\/(\d+)\/cancel$/);
    if (m) { cancelled.add(Number(m[1])); return J({ ok: true }); }
    if (path === '/api/findings') return J({ findings: allFindings() });
    if (path === '/api/audit') return J({ audit });
    return NOPE();
  }
  function allFindings() {
    const out = [];
    sim().scans.filter((s) => s.status === 'done').forEach((sc) => findingsFor((sc.id % 100) - 1).forEach((r) => out.push({ severity: r[0], title: r[1], detail: r[2], status: 'new', host: sc.host, asset_id: sc.asset_id, scan_id: sc.id, finished_at: sc.finished_at })));
    const order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
    return out.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  }

  const realFetch = window.fetch.bind(window);
  window.fetch = async (input, init = {}) => {
    const url = new URL(typeof input === 'string' ? input : input.url, location.href);
    if (!url.pathname.startsWith('/api/')) return realFetch(input, init);
    let body = {}; try { body = init.body ? JSON.parse(init.body) : {}; } catch (_) { /* ignore */ }
    await new Promise((r) => setTimeout(r, 60));
    return route((init.method || 'GET').toUpperCase(), url.pathname, url.searchParams, body);
  };

  /* exports: build the file in the browser instead of calling a server */
  document.addEventListener('click', (e) => {
    const a = e.target.closest && e.target.closest('a[href^="/api/"]'); if (!a) return;
    e.preventDefault();
    const u = new URL(a.getAttribute('href'), location.href);
    if (u.pathname === '/api/export') {
      const rows = allFindings();
      const fmt = u.searchParams.get('fmt');
      const text = fmt === 'json' ? JSON.stringify(rows, null, 2) : ['severity,host,finding,detail', ...rows.map((r) => [r.severity, r.host, r.title, r.detail].map((c) => '"' + String(c).replace(/"/g, '""') + '"').join(','))].join('\n');
      const b = document.createElement('a'); b.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' })); b.download = 'demo-findings.' + (fmt === 'json' ? 'json' : 'csv'); b.click();
    }
  });

  window.addEventListener('DOMContentLoaded', () => {
    const bar = document.createElement('div'); bar.className = 'demo-banner'; bar.setAttribute('role', 'note');
    const msg = document.createElement('span');
    msg.innerHTML = '<b>Live demo.</b> Results here are simulated and nothing is scanned. The real scanner runs on your own machine.';
    const code = document.createElement('code'); code.textContent = 'git clone https://github.com/Clickneeth/VAPT-Scanner-.git && webui/run.sh';
    const link = document.createElement('a'); link.href = 'https://github.com/Clickneeth/VAPT-Scanner-'; link.textContent = 'Get it on GitHub';
    bar.append(msg, code, link); document.body.prepend(bar);
  });
})();
