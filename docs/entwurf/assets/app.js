/* Entwurf opensecmon – gemeinsamer Rahmen. Nur für die Abnahme; die echte Anwendung rendert auf dem Server (askama + htmx). */
(function () {
  const $ = function (s, r) { return (r || document).querySelector(s); };
  const $$ = function (s, r) { return Array.from((r || document).querySelectorAll(s)); };
  const esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  const store = {
    get: function (k) { try { return localStorage.getItem('osm-entwurf-' + k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem('osm-entwurf-' + k, v); } catch (e) { /* egal */ } }
  };

  /* ---------- Thema ---------- */
  function applyTheme(t) {
    const html = document.documentElement;
    if (t === 'light' || t === 'dark') html.setAttribute('data-theme', t); else html.removeAttribute('data-theme');
    store.set('theme', t || 'system');
    $$('[data-theme-btn]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.themeBtn === (t || 'system'))); });
    const tb = $('#themeToggle');
    if (tb) tb.innerHTML = isDark() ? I('sun') : I('moon');
  }
  function isDark() {
    const t = document.documentElement.getAttribute('data-theme');
    if (t) return t === 'dark';
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }
  applyTheme(store.get('theme') || 'system');

  /* ---------- Hilfen ---------- */
  function dmy(iso) { if (!iso || iso === '–') return '–'; const p = iso.slice(0, 10).split('-'); return p[2] + '.' + p[1] + '.' + p[0] + (iso.length > 10 ? ' ' + iso.slice(11) : ''); }
  function daysBetween(a, b) { return Math.round((Date.parse(b.slice(0, 10)) - Date.parse(a.slice(0, 10))) / 864e5); }
  function ago(iso) {
    const d = daysBetween(iso, D.NOW);
    if (d <= 0) return 'heute ' + (iso.slice(11, 16) || '');
    if (d === 1) return 'gestern';
    if (d < 7) return 'vor ' + d + ' Tagen';
    return dmy(iso.slice(0, 10));
  }
  function num(x, dg) { return Number(x).toFixed(dg == null ? 1 : dg).replace('.', ','); }
  function pct(x, dg) { return num(x * 100, dg == null ? 1 : dg) + ' %'; }
  function prioBadge(m, big) {
    return '<span class="prio ' + m.sev + (big ? ' big' : '') + '" title="Priorität ' + m.prio + ' von 100 · ' + D.SEV_LABEL[m.sev] + '">' +
      I(m.sev) + '<span>' + m.prio + '</span>' + (big ? '<span class="lbl">' + D.SEV_LABEL[m.sev] + '</span>' : '<span class="sr-only">' + D.SEV_LABEL[m.sev] + '</span>') + '</span>';
  }
  function kevBadge(m) { return m.kev ? '<span class="kev" title="In der CISA-Liste aktiv ausgenutzter Schwachstellen">' + I('flame') + 'KEV</span>' : ''; }
  function confTag(c) { return c ? '<span class="tag conf-' + c + '" title="Vertrauen des Treffers">' + { hoch: 'Vertrauen hoch', mittel: 'Vertrauen mittel', niedrig: 'Vertrauen niedrig' }[c] + '</span>' : ''; }
  const STATE_LABEL = { neu: 'Neu', gesehen: 'Gesehen', spaeter: 'Später', erledigt: 'Erledigt', ignoriert: 'Ignoriert' };
  const STATE_ICON = { neu: 'inbox', gesehen: 'eye', spaeter: 'clock', erledigt: 'check-circle', ignoriert: 'eye-off' };

  /* ---------- Rahmen ---------- */
  const NAV = [
    ['eingang', 'eingang.html', 'inbox', 'Eingang'],
    ['lage', 'lage.html', 'activity', 'Lage'],
    ['assets', 'assets.html', 'server', 'Assets'],
    ['cves', 'cves.html', 'list', 'Alle CVEs'],
    ['quellen', 'quellen.html', 'rss', 'Quellen']
  ];
  const PAGES = [['index.html', 'Übersicht'], ['eingang.html', 'Eingang'], ['detail.html', 'Detail'], ['lage.html', 'Lage'], ['assets.html', 'Assets'], ['cves.html', 'Alle CVEs'], ['quellen.html', 'Quellen'], ['einstellungen.html', 'Einstellungen'], ['breiten.html', 'Breiten']];

  function openCount() { return D.matches.filter(function (m) { return m.state === 'neu' || m.state === 'gesehen'; }).length; }

  function shell(active, extraDraft) {
    const file = location.pathname.split('/').pop() || 'index.html';
    const draft =
      '<div class="draftbar" id="draftbar" role="region" aria-label="Entwurfsleiste">' +
      '<strong>ENTWURF</strong><span>Beispieldaten erfunden</span><span aria-hidden="true">·</span>' +
      '<span class="pages">' + PAGES.map(function (p) { return p[0] === file ? '<span><b>' + p[1] + '</b></span>' : '<a href="' + p[0] + '">' + p[1] + '</a>'; }).join(' ') + '</span>' +
      '<label class="sr-only" for="pgSel">Seite</label><select id="pgSel">' + PAGES.map(function (p) { return '<option value="' + p[0] + '"' + (p[0] === file ? ' selected' : '') + '>' + p[1] + '</option>'; }).join('') + '</select>' +
      '<span class="sp"></span>' + (extraDraft || '') +
      '<span class="opt">Thema:</span><button type="button" data-theme-btn="system">System</button><button type="button" data-theme-btn="light">Hell</button><button type="button" data-theme-btn="dark">Dunkel</button>' +
      '</div>';
    const n = openCount();
    const top =
      '<header class="topbar">' +
      '<a class="brand" href="eingang.html" aria-label="opensecmon, zum Eingang">' + I('mark', 'mark') + '<span class="name">opensecmon</span></a>' +
      '<nav class="nav" aria-label="Hauptnavigation">' +
      NAV.map(function (x) {
        return '<a href="' + x[1] + '"' + (x[0] === active ? ' aria-current="page"' : '') + '>' + I(x[2]) + x[3] +
          (x[0] === 'eingang' && n ? '<span class="count" aria-label="' + n + ' offen">' + n + '</span>' : '') + '</a>';
      }).join('') + '</nav>' +
      '<form class="search" role="search" action="cves.html">' + I('search') +
      '<label class="sr-only" for="gsearch">Suche</label><input id="gsearch" name="q" type="search" placeholder="CVE, Advisory, Produkt suchen" autocomplete="off"><kbd>/</kbd></form>' +
      '<a class="status-chip" href="quellen.html" title="Zustand der Quellen">' + '<span class="dot" style="background:var(--err)"></span><span class="txt">Letzte Prüfung 14:48 · 1 Quelle mit Fehler</span><span class="sr-only">Quellen</span></a>' +
      '<button class="iconbtn" id="themeToggle" type="button" aria-label="Hell/Dunkel umschalten"></button>' +
      '<details class="menu"><summary class="iconbtn" aria-label="Benutzermenü">' + I('user') + '</summary><div class="menu-pop" role="menu">' +
      '<div class="who">Angemeldet als <b>admin</b></div>' +
      '<a href="einstellungen.html" role="menuitem">' + I('settings') + 'Einstellungen</a>' +
      '<a href="einstellungen.html#protokoll" role="menuitem">' + I('history') + 'Protokoll</a>' +
      '<button type="button" role="menuitem" data-help>' + I('keyboard') + 'Tastenkürzel <kbd style="margin-left:auto">?</kbd></button>' +
      '<hr><a href="#" role="menuitem" data-draft-toast="Abgemeldet (Entwurf)">' + I('logout') + 'Abmelden</a></div></details>' +
      '</header>';
    const bottom = '<nav class="bottomnav" aria-label="Hauptnavigation">' + NAV.map(function (x) {
      return '<a href="' + x[1] + '"' + (x[0] === active ? ' aria-current="page"' : '') + '>' + I(x[2], 'lg') + '<span>' + (x[0] === 'cves' ? 'CVEs' : x[3]) + '</span></a>';
    }).join('') + '</nav>';
    const overlays =
      '<div class="scrim" id="scrim"></div>' +
      '<div class="toast" id="toast" role="status" aria-live="polite"><span id="toastMsg"></span><button type="button" id="toastUndo">Rückgängig</button></div>' +
      '<div class="modal" id="helpModal" role="dialog" aria-modal="true" aria-labelledby="helpTitle"><header><h2 id="helpTitle">Tastenkürzel</h2><button class="iconbtn" type="button" data-close aria-label="Schließen">' + I('x') + '</button></header>' +
      '<div class="mbody"><div class="keys">' +
      '<span><kbd>j</kbd> <kbd>k</kbd></span><span>Nächster / vorheriger Treffer</span>' +
      '<span><kbd>x</kbd></span><span>Treffer für Sammelaktion markieren</span>' +
      '<span><kbd>e</kbd></span><span>Erledigt</span>' +
      '<span><kbd>i</kbd></span><span>Ignorieren …</span>' +
      '<span><kbd>s</kbd></span><span>Später …</span>' +
      '<span><kbd>o</kbd></span><span>Quelle öffnen</span>' +
      '<span><kbd>/</kbd></span><span>Suche</span>' +
      '<span><kbd>Esc</kbd></span><span>Schließen, Auswahl aufheben</span>' +
      '<span><kbd>?</kbd></span><span>Diese Hilfe</span>' +
      '</div></div><footer><button class="btn" type="button" data-close>Schließen</button></footer></div>';

    document.body.insertAdjacentHTML('afterbegin', draft + top);
    document.body.insertAdjacentHTML('beforeend', bottom + overlays);
    const dh = $('#draftbar').offsetHeight;
    document.documentElement.style.setProperty('--draftbar-h', dh + 'px');
    window.addEventListener('resize', function () { document.documentElement.style.setProperty('--draftbar-h', $('#draftbar').offsetHeight + 'px'); });

    applyTheme(store.get('theme') || 'system');
    $('#pgSel').addEventListener('change', function (e) { location.href = e.target.value; });
    $$('[data-theme-btn]').forEach(function (b) { b.addEventListener('click', function () { applyTheme(b.dataset.themeBtn); }); });
    $('#themeToggle').addEventListener('click', function () { applyTheme(isDark() ? 'light' : 'dark'); });
    if (window.matchMedia) window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () { applyTheme(store.get('theme') || 'system'); });

    document.addEventListener('click', function (e) {
      const h = e.target.closest('[data-help]'); if (h) { e.preventDefault(); closeMenus(); openModal('helpModal'); }
      const c = e.target.closest('[data-close]'); if (c) { e.preventDefault(); closeModals(); }
      const t = e.target.closest('[data-draft-toast]'); if (t) { e.preventDefault(); toast(t.dataset.draftToast); }
      if (!e.target.closest('.menu')) closeMenus();
      if (!e.target.closest('.pop') && !e.target.closest('[data-pop]')) $$('.pop.open').forEach(function (p) { p.classList.remove('open'); });
    });
    $('#scrim').addEventListener('click', function () { closeModals(); document.body.classList.remove('sheet-open', 'filters-open'); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { closeModals(); closeMenus(); $$('.pop.open').forEach(function (p) { p.classList.remove('open'); }); }
      if (isTyping(e)) return;
      if (e.key === '/') { e.preventDefault(); $('#gsearch').focus(); }
      if (e.key === '?') { e.preventDefault(); openModal('helpModal'); }
    });
  }
  function isTyping(e) {
    const t = e.target;
    return (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) || !!$('.modal.open') || e.ctrlKey || e.metaKey || e.altKey;
  }
  function closeMenus() { $$('details.menu[open]').forEach(function (d) { d.removeAttribute('open'); }); }
  let lastFocus = null;
  function openModal(id) {
    lastFocus = document.activeElement;
    $('#' + id).classList.add('open'); $('#scrim').classList.add('open');
    const f = $('#' + id).querySelector('select, input, textarea, button:not([data-close])') || $('#' + id).querySelector('button');
    if (f) f.focus();
  }
  function closeModals() {
    const any = $('.modal.open');
    $$('.modal.open').forEach(function (m) { m.classList.remove('open'); });
    $('#scrim') && $('#scrim').classList.remove('open');
    if (any && lastFocus) lastFocus.focus();
  }
  let toastTimer = null, undoFn = null;
  function toast(msg, undo) {
    $('#toastMsg').textContent = msg; undoFn = undo || null;
    $('#toastUndo').style.display = undo ? '' : 'none';
    $('#toast').classList.add('open');
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { $('#toast').classList.remove('open'); }, 5000);
    $('#toastUndo').onclick = function () { if (undoFn) undoFn(); $('#toast').classList.remove('open'); };
  }

  /* ---------- CVSS ---------- */
  const CV = {
    AV: ['Angriffsweg', { N: 'Netzwerk', A: 'Lokales Netz', L: 'Lokal', P: 'Physisch' }, 'N'],
    AC: ['Komplexität', { L: 'Niedrig', H: 'Hoch' }, 'L'],
    PR: ['Rechte nötig', { N: 'Keine', L: 'Niedrig', H: 'Hoch' }, 'N'],
    UI: ['Mitwirkung', { N: 'Keine', R: 'Erforderlich' }, 'N'],
    S: ['Bereich', { U: 'Unverändert', C: 'Geändert' }, 'C'],
    C: ['Vertraulichkeit', { H: 'Hoch', L: 'Niedrig', N: 'Keine' }, 'H'],
    I: ['Integrität', { H: 'Hoch', L: 'Niedrig', N: 'Keine' }, 'H'],
    A: ['Verfügbarkeit', { H: 'Hoch', L: 'Niedrig', N: 'Keine' }, 'H']
  };
  function vectorHtml(v) {
    const parts = v.split('/').slice(1);
    return '<div class="vector">' + parts.map(function (p) {
      const kv = p.split(':'); const d = CV[kv[0]]; if (!d) return '';
      return '<div><span>' + d[0] + '</span><span class="' + (kv[1] === d[2] ? 'bad' : '') + '">' + d[1][kv[1]] + '</span></div>';
    }).join('') + '</div>';
  }

  /* ---------- Detail-Komponente (Eingang, Detailseite, Alle CVEs) ---------- */
  function detailHtml(m, opt) {
    opt = opt || {};
    const st = m.state;
    const ids = m.cves.length > 1 || m.id.indexOf('CVE-') !== 0 ? m.cves.join(', ') : '';
    let actions = '';
    if (opt.actions !== false && m.assets.length) {
      if (st === 'erledigt' || st === 'ignoriert') {
        actions = '<div class="btngroup"><span class="state ' + (st === 'erledigt' ? 'ok' : 'off') + '">' + I(STATE_ICON[st]) + STATE_LABEL[st] + (m.reason ? ': „' + esc(m.reason) + '“' : '') + '</span><button class="btn sm" type="button" data-act="reopen">Wieder öffnen</button></div>';
      } else {
        actions = '<div class="btngroup">' +
          '<button class="btn primary" type="button" data-act="done">' + I('check') + 'Erledigt <kbd>e</kbd></button>' +
          '<button class="btn" type="button" data-act="ignore">' + I('eye-off') + 'Ignorieren <kbd>i</kbd></button>' +
          '<button class="btn" type="button" data-act="later" data-pop>' + I('clock') + 'Später <kbd>s</kbd></button>' +
          '<button class="btn ghost" type="button" data-act="open" aria-label="Quelle öffnen" title="Quelle öffnen">' + I('external') + '<kbd>o</kbd></button>' +
          '</div>' + (st === 'spaeter' ? '<p class="small muted" style="margin:8px 0 0">' + I('clock', 'sm') + ' Zurückgestellt bis ' + dmy(m.until) + '</p>' : '');
      }
    }
    const kev = m.kev ? '<div class="notice kevn" style="margin-bottom:12px">' + I('flame') + '<div><b>Wird aktiv ausgenutzt</b> (CISA KEV seit ' + dmy(m.kev.since) + ').<br>' +
      (m.kev.due <= D.NOW ? '<span class="sev crit">Frist für US-Behörden abgelaufen (' + dmy(m.kev.due) + ').</span>' : 'Frist für US-Behörden: ' + dmy(m.kev.due) + '.') +
      ' Bekannte Nutzung durch Ransomware: ' + m.kev.ransomware + '.</div></div>' : '';

    const aff = m.assets.length ?
      '<ul class="affected">' +
      m.assets.map(function (a) {
        return '<li><div class="a1"><b>' + esc(a.name) + '</b>' + (a.host !== a.name ? '<span class="tag">' + I(a.host.indexOf(' ') > 0 ? 'router' : 'server', 'sm') + esc(a.host) + '</span>' : '') + '</div>' +
          '<div class="a2"><span class="lab">installiert</span><span class="ver-old">' + esc(a.installed) + '</span>' + I('chev-right', 'sm') + '<span class="lab">behoben in</span><span class="ver-fix">' + esc(a.fixed) + '</span></div>' +
          '<div class="a3">' + esc(a.reason) + '</div>' + (a.note ? '<div class="small" style="color:var(--warn)">' + I('alert', 'sm') + ' ' + esc(a.note) + '</div>' : '') + '</li>';
      }).join('') + '</ul><p class="small" style="margin:8px 0 0">' + confTag(m.conf) + ' <span class="muted">' + confWhy(m.conf) + '</span></p>'
      : '<p class="muted">Keine eigenen Assets betroffen.</p><button class="btn sm" type="button" data-draft-toast="Entwurf: öffnet „Asset anlegen“ mit Hersteller ' + esc(m.vendor) + '">' + I('plus') + 'Produkt als Asset anlegen</button>';

    const pp = m.prioParts;
    const formula = '<details class="formula"><summary>So entsteht die Priorität ' + m.prio + '</summary><table style="margin-top:8px">' +
      '<tr><td>CVSS ' + num(m.cvss) + ' × 7</td><td>' + num(pp.cvss) + '</td></tr>' +
      '<tr><td>EPSS-Perzentil ' + num(m.epssP * 100) + ' % × 20</td><td>' + num(pp.epss) + '</td></tr>' +
      (m.conf ? '<tr><td>Vertrauen ' + m.conf + '</td><td>+' + pp.conf + '</td></tr>' : '<tr><td>Kein eigener Treffer</td><td>+0</td></tr>') +
      (pp.kevFloor ? '<tr><td>Summe ' + num(pp.raw) + ', KEV hebt auf mindestens</td><td>90</td></tr>' : '') +
      '<tr class="sum"><td>Priorität (0–100)</td><td>' + m.prio + '</td></tr></table>' +
      '<p class="small muted" style="margin:8px 0 0">Formel und Gewichte unter Einstellungen → Priorität.</p></details>';

    const srcs = '<ul class="srcs">' + m.sources.map(function (s) {
      return '<li>' + I('file') + '<div><div><span class="tag">' + s.kind + '</span> <span class="nm mono">' + esc(s.id) + '</span></div><div class="d">' + esc(s.t) + ' · ' + dmy(s.d) + '</div></div>' +
        '<a class="iconbtn" href="#" data-draft-toast="Entwurf: öffnet die Quelle in neuem Tab" aria-label="Quelle ' + esc(s.id) + ' öffnen">' + I('external') + '</a></li>';
    }).join('') + '</ul>';

    const tl = m.timeline && m.timeline.length ? '<div class="dsec"><h3>Verlauf</h3><ul class="timeline">' + m.timeline.map(function (t) { return '<li><time>' + dmy(t[0]) + '</time><span>' + esc(t[1]) + '</span></li>'; }).join('') + '</ul></div>' : '';

    return '<div class="dhead">' +
      (opt.back ? '<a class="btn ghost back" href="' + (opt.backHref || '#') + '" data-back>' + I('chev-left') + (opt.backLabel || 'Zurück') + '</a>' : '') +
      '<div class="badges">' + prioBadge(m, true) + kevBadge(m) + (m.assets.length && st ? '<span class="state ' + (st === 'neu' ? '' : 'off') + '">' + I(STATE_ICON[st], 'sm') + STATE_LABEL[st] + '</span>' : '') +
      '<span class="ids">' + esc(m.id) + (ids ? ' · ' + esc(ids) : '') + '</span></div>' +
      '<h1>' + esc(m.title) + '</h1>' + actions + '</div>' +
      '<div class="dbody">' +
      '<div class="dsec"><h3>Betrifft</h3>' + aff + '</div>' +
      '<div class="dsec"><h3>Bewertung</h3>' + kev +
      '<div class="scores">' +
      '<div class="score"><div class="k">CVSS 3.1</div><div class="v sev ' + D.cvssBand(m.cvss) + '">' + num(m.cvss) + '</div><div class="s">' + D.SEV_LABEL[D.cvssBand(m.cvss)] + '</div></div>' +
      '<div class="score"><div class="k">EPSS (30 Tage)</div><div class="v">' + pct(m.epss) + '</div><div class="bar" role="img" aria-label="Perzentil ' + num(m.epssP * 100) + '"><i style="width:' + (m.epssP * 100) + '%"></i></div><div class="s">Perzentil ' + num(m.epssP * 100) + '</div></div>' +
      '<div class="score"><div class="k">Priorität</div><div class="v sev ' + m.sev + '">' + m.prio + '</div><div class="s">' + D.SEV_LABEL[m.sev] + '</div></div>' +
      '</div>' + vectorHtml(m.vector) + '<p class="vector-raw" style="margin-top:8px">' + esc(m.vector) + '</p>' + formula + '</div>' +
      '<div class="dsec"><h3>Beschreibung</h3><p class="desc">' + esc(m.desc) + '</p><p class="small muted">Veröffentlicht ' + dmy(m.published) + (m.firstSeen ? ' · hier zuerst gesehen ' + dmy(m.firstSeen) : '') + '</p></div>' +
      '<div class="dsec"><h3>Quellen (' + m.sources.length + ')</h3>' + srcs + '</div>' + tl +
      '</div>';
  }
  function confWhy(c) {
    return { hoch: 'Paketstatus der Distribution oder CPE mit Versionsbereich passt genau.', mittel: 'Hersteller und Produkt aus dem CSAF-Produktbaum, Version aus dem Inventar.', niedrig: 'Nur über ein Stichwort der Watchlist gefunden, bitte prüfen.' }[c] || '';
  }

  window.App = {
    $: $, $$: $$, esc: esc, store: store, shell: shell, toast: toast, openModal: openModal, closeModals: closeModals, isTyping: isTyping,
    dmy: dmy, ago: ago, num: num, pct: pct, prioBadge: prioBadge, kevBadge: kevBadge, confTag: confTag, detailHtml: detailHtml,
    STATE_LABEL: STATE_LABEL, STATE_ICON: STATE_ICON, isDark: isDark
  };
})();
