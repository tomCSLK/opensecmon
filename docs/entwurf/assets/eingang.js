/* Entwurf: Eingang (Triage) */
(function () {
  const A = App, $ = A.$, $$ = A.$$, esc = A.esc;
  const OPEN = ['neu', 'gesehen'];
  const VIEWS = [
    { id: 'offen', label: 'Offen', icon: 'inbox', status: OPEN },
    { id: 'kritisch', label: 'Kritisch + KEV', icon: 'star', status: OPEN, test: function (m) { return m.sev === 'crit' || !!m.kev; } },
    { id: 'neu', label: 'Neu seit gestern', icon: 'star', status: OPEN, test: function (m) { return (m.firstSeen || '') >= '2026-11-03'; } },
    { id: 'spaeter', label: 'Später', icon: 'clock', status: ['spaeter'] },
    { id: 'erledigt', label: 'Erledigt', icon: 'check-circle', status: ['erledigt'] },
    { id: 'ignoriert', label: 'Ignoriert', icon: 'eye-off', status: ['ignoriert'] }
  ];
  const GROUPS = [
    { key: 'sev', title: 'Schwere', vals: [['crit', 'Kritisch'], ['high', 'Hoch'], ['med', 'Mittel'], ['low', 'Niedrig']], get: function (m) { return [m.sev]; }, icon: true },
    { key: 'kev', title: 'Ausnutzung', vals: [['kev', 'Nur KEV']], get: function (m) { return m.kev ? ['kev'] : []; } },
    { key: 'type', title: 'Typ', vals: [['Software', 'Software'], ['Hardware', 'Hardware']], get: function (m) { return [m.type]; } },
    { key: 'host', title: 'Host / Gerät', vals: null, get: function (m) { return m.hosts; } },
    { key: 'vendor', title: 'Hersteller', vals: null, get: function (m) { return [m.vendor]; } },
    { key: 'src', title: 'Quelle', vals: [['BSI', 'BSI CERT-Bund'], ['USN', 'Ubuntu USN'], ['DSA', 'Debian DSA'], ['KEV', 'CISA KEV'], ['CVE', 'CVE-Liste'], ['NVD', 'NVD']], get: function (m) { return m.srcKinds; } }
  ];
  const S = { view: 'offen', f: {}, sel: null, checked: new Set(), empty: false, sort: 'prio' };
  GROUPS.forEach(function (g) { S.f[g.key] = new Set(); });

  function viewOf() { return VIEWS.find(function (v) { return v.id === S.view; }); }
  function baseItems() {
    if (S.empty) return [];
    const v = viewOf();
    return D.matches.filter(function (m) { return v.status.indexOf(m.state) >= 0 && (!v.test || v.test(m)); });
  }
  function passes(m, skip) {
    return GROUPS.every(function (g) {
      if (g.key === skip) return true;
      const set = S.f[g.key]; if (!set.size) return true;
      return g.get(m).some(function (x) { return set.has(x); });
    });
  }
  function items() {
    const list = baseItems().filter(function (m) { return passes(m); });
    if (S.sort === 'neu') list.sort(function (a, b) { return (b.firstSeen || '').localeCompare(a.firstSeen || ''); });
    else if (S.sort === 'host') list.sort(function (a, b) { return a.hosts[0].localeCompare(b.hosts[0]) || b.prio - a.prio; });
    else list.sort(function (a, b) { return b.prio - a.prio; });
    return list;
  }

  /* ---------- Filterspalte ---------- */
  function renderFilters() {
    const base = baseItems();
    let h = '<div class="fgroup"><h3>Ansichten</h3>' + VIEWS.map(function (v) {
      const n = S.empty ? 0 : D.matches.filter(function (m) { return v.status.indexOf(m.state) >= 0 && (!v.test || v.test(m)); }).length;
      return '<button type="button" class="frow view" data-view="' + v.id + '" aria-pressed="' + (S.view === v.id) + '">' + I(v.icon) + '<span>' + v.label + '</span><span class="n">' + n + '</span></button>';
    }).join('') + '</div>';
    GROUPS.forEach(function (g) {
      let vals = g.vals;
      if (!vals) {
        const all = new Set(); D.matches.forEach(function (m) { g.get(m).forEach(function (x) { all.add(x); }); });
        vals = Array.from(all).sort().map(function (x) { return [x, x]; });
      }
      const rows = vals.map(function (v) {
        const n = base.filter(function (m) { return passes(m, g.key) && g.get(m).indexOf(v[0]) >= 0; }).length;
        const on = S.f[g.key].has(v[0]);
        if (!n && !on) return '';
        return '<button type="button" class="frow" data-g="' + g.key + '" data-v="' + esc(v[0]) + '" aria-pressed="' + on + '"><span class="box" aria-hidden="true"></span>' +
          (g.icon ? '<span class="sev ' + v[0] + '">' + I(v[0], 'sm') + '</span>' : '') + '<span>' + esc(v[1]) + '</span><span class="n">' + n + '</span></button>';
      }).join('');
      if (!rows) return;
      h += '<div class="fgroup"><h3>' + g.title + (S.f[g.key].size ? '<button type="button" data-clear="' + g.key + '">zurücksetzen</button>' : '') + '</h3>' + rows + '</div>';
    });
    h += '<div class="fgroup"><button type="button" class="frow" data-draft-toast="Entwurf: aktuelle Filter als Ansicht speichern">' + I('plus') + '<span>Ansicht speichern</span></button></div>';
    $('#filters').innerHTML = '<div class="show-sm" style="display:flex;justify-content:space-between;align-items:center;padding:0 8px 8px"><h2>Filter</h2><button class="iconbtn" type="button" data-close-filters aria-label="Filter schließen">' + I('x') + '</button></div>' + h;
  }

  /* ---------- Liste ---------- */
  function renderList() {
    const list = items();
    const v = viewOf();
    const chips = [];
    GROUPS.forEach(function (g) {
      S.f[g.key].forEach(function (x) {
        const lab = (g.vals && (g.vals.find(function (y) { return y[0] === x; }) || [])[1]) || x;
        chips.push('<span class="chip">' + g.title + ': ' + esc(lab) + '<button type="button" data-unchip="' + g.key + '|' + esc(x) + '" aria-label="Filter ' + esc(lab) + ' entfernen">' + I('x', 'sm') + '</button></span>');
      });
    });
    $('#chips').innerHTML = chips.join('') + (chips.length ? '<button class="chip add" type="button" data-clear="*">Alle Filter entfernen</button>' : '');
    $('#chips').hidden = !chips.length;
    $('#listTitle').textContent = v.label;
    $('#listCount').textContent = list.length === 1 ? '1 Treffer' : list.length + ' Treffer';
    $('#bulkN').textContent = S.checked.size + ' ausgewählt';
    $('#listbar').classList.toggle('has-sel', S.checked.size > 0);
    $('#selAll').checked = list.length > 0 && list.every(function (m) { return S.checked.has(m.id); });
    $('#selAll').indeterminate = S.checked.size > 0 && !$('#selAll').checked;

    if (!list.length) {
      const allDone = S.empty || (S.view === 'offen' && !Object.values(S.f).some(function (s) { return s.size; }));
      $('#rows').innerHTML = allDone ?
        '<li class="empty">' + '<div>' + I('shield-check', 'xl') + '<h2>Alles erledigt</h2><p>Keine offenen Treffer für deine Assets.</p><p class="small muted">Letzte Prüfung heute 14:48 · nächste um 15:05 · 11 Quellen, 1 mit Fehler</p><p><a class="btn sm" href="lage.html">Zur Lage</a></p></div></li>' :
        '<li class="empty"><div>' + I('filter', 'xl') + '<h2>Nichts gefunden</h2><p>Kein Treffer passt zu diesen Filtern.</p><button class="btn sm" type="button" data-clear="*">Filter zurücksetzen</button></div></li>';
      $('#detail').innerHTML = '<div class="empty"><div><p class="muted">Kein Treffer ausgewählt.</p></div></div>';
      return;
    }
    $('#rows').innerHTML = list.map(function (m) {
      const unread = m.state === 'neu';
      const a0 = m.assets[0]; const asset = m.assets.length === 1 ? (a0.host === a0.name ? a0.name + ' · ' + a0.installed : a0.name + ' · ' + a0.host) : a0.name + ' · ' + m.hosts.join(', ');
      const icon = m.type === 'Hardware' ? 'router' : 'package';
      return '<li class="row' + (unread ? ' unread' : '') + ' state-' + m.state + '" role="option" id="r-' + m.id + '" data-id="' + m.id + '" aria-selected="' + (S.sel === m.id) + '" tabindex="-1">' +
        '<input type="checkbox" aria-label="' + m.id + ' auswählen" ' + (S.checked.has(m.id) ? 'checked' : '') + '>' +
        A.prioBadge(m) +
        '<div class="l1"><span class="id">' + esc(m.id) + '</span><span class="t">' + esc(m.title) + '</span></div>' +
        '<div class="meta">' + A.kevBadge(m) + (unread ? '<span class="newdot" title="Neu"></span><span class="sr-only">neu</span>' : '') +
        (m.state === 'spaeter' ? '<span class="rowstate">' + I('clock', 'sm') + 'bis ' + A.dmy(m.until).slice(0, 6) + '</span>' : '') +
        (m.state === 'erledigt' ? '<span class="rowstate">' + I('check', 'sm') + 'erledigt</span>' : '') +
        (m.state === 'ignoriert' ? '<span class="rowstate">' + I('eye-off', 'sm') + 'ignoriert</span>' : '') +
        '<span>' + A.ago(m.firstSeen) + '</span></div>' +
        '<div class="l2">' + I(icon, 'sm') + '<span class="asset">' + esc(asset) + '</span>' +
        (m.assets.length > 1 ? '<span class="tag">' + m.assets.length + ' Assets</span>' : '') +
        m.srcKinds.filter(function (k) { return k !== 'CVE' && k !== 'NVD' && k !== 'KEV'; }).map(function (k) { return '<span class="tag src">' + k + '</span>'; }).join('') + '</div>' +
        '</li>';
    }).join('');
    if (!S.sel || !list.some(function (m) { return m.id === S.sel; })) {
      if (window.innerWidth >= 1280) select(list[0].id, false); else { S.sel = null; $('#detail').innerHTML = ''; }
    } else renderDetail();
  }

  function cur() { return D.matches.find(function (m) { return m.id === S.sel; }); }
  function select(id, open) {
    S.sel = id;
    const m = cur();
    if (m && m.state === 'neu') { m.state = 'gesehen'; m._autoSeen = true; }
    $$('.row').forEach(function (r) { r.setAttribute('aria-selected', String(r.dataset.id === id)); });
    const row = $('#r-' + CSS.escape(id));
    if (row) { row.classList.remove('unread'); row.scrollIntoView({ block: 'nearest' }); }
    renderDetail();
    if (open && window.innerWidth < 1280) { document.body.classList.add('sheet-open'); }
    syncUrl();
  }
  function renderDetail() {
    const m = cur(); if (!m) return;
    $('#detail').innerHTML = A.detailHtml(m, { back: true, backLabel: 'Zur Liste' });
    $('#detail').scrollTop = 0;
  }
  function syncUrl() {
    try {
      const p = new URLSearchParams();
      if (S.view !== 'offen') p.set('ansicht', S.view);
      GROUPS.forEach(function (g) { if (S.f[g.key].size) p.set(g.key, Array.from(S.f[g.key]).join(',')); });
      if (S.sel) p.set('treffer', S.sel);
      history.replaceState(null, '', location.pathname + (p.toString() ? '?' + p.toString() : ''));
    } catch (e) { /* file:// kann das je nach Browser nicht */ }
  }
  function readUrl() {
    const p = new URLSearchParams(location.search);
    if (p.get('ansicht')) S.view = p.get('ansicht');
    GROUPS.forEach(function (g) { if (p.get(g.key)) p.get(g.key).split(',').forEach(function (x) { S.f[g.key].add(x); }); });
    if (p.get('treffer')) S.sel = p.get('treffer');
  }

  /* ---------- Aktionen ---------- */
  function targets() {
    if (S.checked.size) return D.matches.filter(function (m) { return S.checked.has(m.id); });
    const m = cur(); return m ? [m] : [];
  }
  function nextAfter(ids) {
    const list = items().map(function (m) { return m.id; });
    const i = list.indexOf(S.sel);
    for (let k = i + 1; k < list.length; k++) if (ids.indexOf(list[k]) < 0) return list[k];
    for (let k = i - 1; k >= 0; k--) if (ids.indexOf(list[k]) < 0) return list[k];
    return null;
  }
  function setState(ts, state, extra, msg) {
    const prev = ts.map(function (m) { return [m, m.state, m.until, m.reason]; });
    const ids = ts.map(function (m) { return m.id; });
    const nx = nextAfter(ids);
    ts.forEach(function (m) { m.state = state; Object.assign(m, extra || {}); });
    S.checked.clear();
    if (nx && viewOf().status.indexOf(state) < 0) S.sel = nx;
    document.body.classList.remove('sheet-open');
    rerender();
    A.toast(msg, function () { prev.forEach(function (p) { p[0].state = p[1]; p[0].until = p[2]; p[0].reason = p[3]; }); S.sel = ids[0]; rerender(); });
  }
  function rerender() { renderFilters(); renderList(); updateNavCount(); }
  function updateNavCount() {
    const n = D.matches.filter(function (m) { return OPEN.indexOf(m.state) >= 0; }).length;
    const c = $('.nav .count'); if (c) { c.textContent = n; c.hidden = !n; }
  }
  function act(a, anchor) {
    const ts = targets(); if (!ts.length) return;
    const lbl = ts.length > 1 ? ts.length + ' Treffer' : ts[0].id;
    if (a === 'done') setState(ts, 'erledigt', {}, lbl + ' als erledigt markiert');
    if (a === 'reopen') setState(ts, 'gesehen', { until: null, reason: null }, lbl + ' wieder geöffnet');
    if (a === 'open') A.toast('Entwurf: öffnet ' + ts[0].sources[0].id + ' in neuem Tab');
    if (a === 'ignore') {
      const m = ts[0];
      $('#ignAssets').innerHTML = ts.length > 1 ? '<p class="small muted">' + ts.length + ' Treffer ausgewählt.</p>' :
        m.assets.map(function (x, i) { return '<label class="check"><input type="checkbox" checked name="ia' + i + '"><span><b>' + esc(x.name) + '</b> · ' + esc(x.host) + '</span></label>'; }).join('');
      $('#ignTitle').textContent = 'Ignorieren: ' + lbl;
      A.openModal('ignoreModal');
    }
    if (a === 'later') {
      const pop = $('#laterPop');
      const r = (anchor || $('[data-act="later"]') || $('#rows')).getBoundingClientRect();
      pop.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 200)) + 'px';
      pop.style.top = (r.bottom + window.scrollY + 6) + 'px';
      pop.classList.add('open');
      pop.querySelector('button').focus();
    }
  }

  /* ---------- Ereignisse ---------- */
  function bind() {
    document.addEventListener('click', function (e) {
      const vb = e.target.closest('[data-view]'); if (vb) { S.view = vb.dataset.view; S.sel = null; S.checked.clear(); rerender(); syncUrl(); return; }
      const fr = e.target.closest('.frow[data-g]'); if (fr) { const s = S.f[fr.dataset.g]; s.has(fr.dataset.v) ? s.delete(fr.dataset.v) : s.add(fr.dataset.v); rerender(); syncUrl(); return; }
      const cl = e.target.closest('[data-clear]'); if (cl) { if (cl.dataset.clear === '*') GROUPS.forEach(function (g) { S.f[g.key].clear(); }); else S.f[cl.dataset.clear].clear(); rerender(); syncUrl(); return; }
      const uc = e.target.closest('[data-unchip]'); if (uc) { const p = uc.dataset.unchip.split('|'); S.f[p[0]].delete(p[1]); rerender(); syncUrl(); return; }
      if (e.target.closest('[data-close-filters]')) { document.body.classList.remove('filters-open'); return; }
      if (e.target.closest('#openFilters')) { document.body.classList.add('filters-open'); return; }
      const ab = e.target.closest('[data-act]'); if (ab) { e.preventDefault(); act(ab.dataset.act, ab); return; }
      const lb = e.target.closest('[data-later]'); if (lb) {
        $('#laterPop').classList.remove('open');
        const d = Number(lb.dataset.later); const until = new Date(Date.parse(D.NOW) + d * 864e5).toISOString().slice(0, 10);
        setState(targets(), 'spaeter', { until: until }, 'Zurückgestellt bis ' + A.dmy(until)); return;
      }
      const back = e.target.closest('[data-back]'); if (back) { e.preventDefault(); document.body.classList.remove('sheet-open'); const r = $('#r-' + CSS.escape(S.sel || '')); if (r) r.focus(); return; }
      const row = e.target.closest('.row');
      if (row) {
        if (e.target.matches('input[type="checkbox"]')) { e.target.checked ? S.checked.add(row.dataset.id) : S.checked.delete(row.dataset.id); renderList(); return; }
        select(row.dataset.id, true); return;
      }
    });
    $('#selAll').addEventListener('change', function (e) { const l = items(); if (e.target.checked) l.forEach(function (m) { S.checked.add(m.id); }); else S.checked.clear(); renderList(); });
    $('#bulkClear').addEventListener('click', function () { S.checked.clear(); renderList(); });
    $('#sort').addEventListener('change', function (e) { S.sort = e.target.value; renderList(); });
    $('#ignoreOk').addEventListener('click', function () {
      const r = $('#ignReason').value; A.closeModals(); setState(targets(), 'ignoriert', { reason: r }, 'Ignoriert: „' + r + '“');
    });
    document.addEventListener('keydown', function (e) {
      if (A.isTyping(e)) return;
      const list = items(); if (!list.length) return;
      const ids = list.map(function (m) { return m.id; }); const i = ids.indexOf(S.sel);
      if (e.key === 'j' || e.key === 'ArrowDown' && e.target.closest('.rows')) { e.preventDefault(); select(ids[Math.min(ids.length - 1, i + 1)], false); }
      else if (e.key === 'k' || e.key === 'ArrowUp' && e.target.closest('.rows')) { e.preventDefault(); select(ids[Math.max(0, i - 1)], false); }
      else if (e.key === 'Enter' && e.target.closest('.row')) { select(e.target.closest('.row').dataset.id, true); }
      else if (e.key === 'x' && S.sel) { S.checked.has(S.sel) ? S.checked.delete(S.sel) : S.checked.add(S.sel); renderList(); }
      else if (e.key === 'e') act('done');
      else if (e.key === 'i') { e.preventDefault(); act('ignore'); }
      else if (e.key === 's') { e.preventDefault(); act('later'); }
      else if (e.key === 'o') act('open');
      else if (e.key === 'Escape') { S.checked.clear(); document.body.classList.remove('sheet-open', 'filters-open'); renderList(); }
    });
    $('#emptyToggle').addEventListener('click', function (e) {
      S.empty = !S.empty; e.currentTarget.setAttribute('aria-pressed', String(S.empty)); S.sel = null; rerender();
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    A.shell('eingang', '<span class="opt">Zustand:</span><button type="button" id="emptyToggle" aria-pressed="false">Leerer Eingang</button><span class="opt" aria-hidden="true">·</span>');
    readUrl(); bind(); rerender();
    if (S.sel && window.innerWidth < 1280) document.body.classList.add('sheet-open');
  });
})();
