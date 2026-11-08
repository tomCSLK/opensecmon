/* Entwurf: Detail, Lage, Assets, Alle CVEs, Quellen, Einstellungen, Übersicht, Breiten */
(function () {
  const A = App, $ = A.$, $$ = A.$$, esc = A.esc;
  const OPEN = ['neu', 'gesehen'];
  const SEVS = ['crit', 'high', 'med', 'low'];
  const openM = function () { return D.matches.filter(function (m) { return OPEN.indexOf(m.state) >= 0; }); };

  /* ---------- Detailseite (Link aus der Mail) ---------- */
  function detail() {
    A.shell('eingang');
    const id = new URLSearchParams(location.search).get('id') || D.matches[0].id;
    const m = D.all.find(function (x) { return x.id === id; }) || D.matches[0];
    $('#main').innerHTML = '<article class="detailpage">' + A.detailHtml(m, { back: true, backHref: 'eingang.html?treffer=' + encodeURIComponent(m.id), backLabel: 'Eingang' }) + '</article>';
    document.addEventListener('click', function (e) {
      const b = e.target.closest('[data-act]'); if (!b) return;
      e.preventDefault();
      const t = { done: 'Als erledigt markiert', ignore: 'Entwurf: öffnet den Dialog „Ignorieren“', later: 'Entwurf: öffnet die Auswahl „Später“', open: 'Entwurf: öffnet die Quelle', reopen: 'Wieder geöffnet' }[b.dataset.act];
      A.toast(t);
    });
  }

  /* ---------- Lage ---------- */
  function lage() {
    A.shell('lage');
    const o = openM();
    const crit = o.filter(function (m) { return m.sev === 'crit'; }).length;
    const kev = o.filter(function (m) { return m.kev; }).length;
    const neu = D.matches.filter(function (m) { return (m.firstSeen || '') >= '2026-11-03'; }).length;
    const srcOk = D.sources.filter(function (s) { return s.state === 'ok'; }).length;
    const srcOn = D.sources.filter(function (s) { return s.on; }).length;
    let h = '<div class="pagehead"><div><h1>Lage</h1><p>Stand heute 14:48 · ' + o.length + ' offene Treffer auf ' + new Set([].concat.apply([], o.map(function (m) { return m.hosts; }))).size + ' Hosts und Geräten</p></div>' +
      '<a class="btn" href="eingang.html">' + I('inbox') + 'Zum Eingang</a></div>';
    h += '<div class="tiles">' +
      tile('eingang.html?sev=crit', 'crit', 'crit', 'Offen kritisch', crit, 'davon ' + o.filter(function (m) { return m.sev === 'crit' && m.state === 'neu'; }).length + ' neu') +
      tile('eingang.html?kev=kev', '', 'flame', 'Aktiv ausgenutzt (KEV)', kev, '1 Frist heute abgelaufen') +
      tile('eingang.html?ansicht=neu', '', 'inbox', 'Neu seit gestern', neu, 'seit 03.11. 00:00') +
      tile('quellen.html', '', 'rss', 'Quellen in Ordnung', srcOk + ' von ' + srcOn, '1 Fehler, 1 Warnung') +
      '</div>';
    h += '<div class="grid2"><section class="card"><header><h2>Offene Treffer, letzte 30 Tage</h2><span class="muted small">nach Schwere</span></header><div class="cbody chart" id="chart"></div></section>' +
      '<section class="card"><header><h2>Am stärksten betroffen</h2><a class="small" href="assets.html">Assets</a></header><div class="cbody" id="hosts"></div></section></div>';
    h += '<div class="grid2"><section class="card"><header><h2>Am längsten offen</h2></header><div class="tblwrap"><table class="tbl" id="oldest"></table></div></section>' +
      '<section class="card"><header><h2>Quellen</h2><a class="small" href="quellen.html">Details</a></header><div class="cbody" id="srcmini"></div></section></div>';
    $('#main').innerHTML = h;
    chart();
    // Hosts
    const byHost = {};
    o.forEach(function (m) { m.hosts.forEach(function (x) { byHost[x] = byHost[x] || { crit: 0, high: 0, med: 0, low: 0, n: 0 }; byHost[x][m.sev]++; byHost[x].n++; }); });
    const hs = Object.keys(byHost).sort(function (a, b) { return byHost[b].n - byHost[a].n; });
    const max = Math.max.apply(null, hs.map(function (x) { return byHost[x].n; }));
    $('#hosts').innerHTML = hs.map(function (x) {
      const v = byHost[x];
      return '<div class="hbar"><a href="eingang.html?host=' + encodeURIComponent(x) + '">' + esc(x) + '</a><span class="b" role="img" aria-label="' + SEVS.map(function (s) { return v[s] + ' ' + D.SEV_LABEL[s]; }).join(', ') + '" style="width:' + (v.n / max * 100) + '%">' +
        SEVS.map(function (s) { return v[s] ? '<i style="flex:' + v[s] + ';background:var(--' + s + ')"></i>' : ''; }).join('') + '</span><span class="n">' + v.n + '</span></div>';
    }).join('');
    // Älteste
    const old = o.slice().sort(function (a, b) { return a.firstSeen.localeCompare(b.firstSeen); }).slice(0, 5);
    $('#oldest').innerHTML = '<thead><tr><th>Prio</th><th>Kennung</th><th>Asset</th><th class="num">Offen seit</th></tr></thead><tbody>' + old.map(function (m) {
      const d = Math.round((Date.parse(D.NOW) - Date.parse(m.firstSeen.slice(0, 10))) / 864e5);
      return '<tr class="click" data-href="eingang.html?treffer=' + m.id + '"><td>' + A.prioBadge(m) + '</td><td class="mono small"><a href="eingang.html?treffer=' + m.id + '">' + m.id + '</a></td><td>' + esc(m.assets[0].name) + ' <span class="muted small">' + esc(m.hosts.join(', ')) + '</span></td><td class="num">' + d + ' Tage</td></tr>';
    }).join('') + '</tbody>';
    $('#srcmini').innerHTML = D.sources.filter(function (s) { return s.on; }).map(function (s) {
      return '<div class="hbar" style="grid-template-columns:minmax(0,1fr) auto">' + '<span>' + esc(s.name) + '</span>' + srcState(s, true) + '</div>';
    }).join('');
    document.addEventListener('click', function (e) { const r = e.target.closest('tr[data-href]'); if (r && !e.target.closest('a')) location.href = r.dataset.href; });
  }
  function tile(href, cls, icon, k, v, s) {
    return '<a class="tile ' + cls + '" href="' + href + '"><div class="k">' + I(icon) + k + '</div><div class="v">' + v + '</div><div class="s">' + s + '</div></a>';
  }
  function chart() {
    const W = 720, H = 230, pl = 28, pb = 24, pt = 8, pr = 8;
    const t = D.trend, n = t.length;
    const tot = t.map(function (d) { return d.crit + d.high + d.med + d.low; });
    const max = Math.ceil(Math.max.apply(null, tot) / 5) * 5;
    const bw = (W - pl - pr) / n;
    const y = function (v) { return pt + (H - pt - pb) * (1 - v / max); };
    let g = '<g class="grid">';
    for (let v = 0; v <= max; v += 5) g += '<line x1="' + pl + '" x2="' + (W - pr) + '" y1="' + y(v) + '" y2="' + y(v) + '"/>';
    g += '</g><g class="axis">';
    for (let v = 0; v <= max; v += 5) g += '<text x="' + (pl - 6) + '" y="' + (y(v) + 4) + '" text-anchor="end">' + v + '</text>';
    t.forEach(function (d, i) { if ((i % 7 === 0 && n - 1 - i >= 4) || i === n - 1) g += '<text x="' + (pl + i * bw + bw / 2) + '" y="' + (H - 6) + '" text-anchor="middle">' + A.dmy(d.d).slice(0, 6) + '</text>'; });
    g += '</g>';
    let bars = '';
    t.forEach(function (d, i) {
      let acc = 0; const x = pl + i * bw + 2;
      bars += '<g><title>' + A.dmy(d.d) + ': ' + tot[i] + ' offen (' + SEVS.map(function (s) { return d[s] + ' ' + D.SEV_LABEL[s].toLowerCase(); }).join(', ') + ')</title>';
      SEVS.forEach(function (s) {
        if (!d[s]) return;
        const y0 = y(acc), y1 = y(acc + d[s]);
        bars += '<rect x="' + x + '" y="' + y1 + '" width="' + (bw - 4) + '" height="' + (y0 - y1 - 1) + '" fill="var(--' + s + ')" rx="1"/>';
        acc += d[s];
      });
      bars += '</g>';
    });
    $('#chart').innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Offene Treffer je Tag, gestapelt nach Schwere. Heute ' + tot[n - 1] + '.">' + g + bars + '</svg>' +
      '<div class="legend">' + SEVS.map(function (s) { return '<span><span class="sev ' + s + '">' + I(s, 'sm') + '</span>' + D.SEV_LABEL[s] + '</span>'; }).join('') + '<span class="muted">Balken zeigen den Wert beim Überfahren</span></div>';
  }
  function srcState(s, short) {
    const m = { ok: ['ok', 'check-circle', 'In Ordnung'], warn: ['warn', 'alert', 'Warnung'], err: ['err', 'x-circle', 'Fehler'], off: ['off', 'pause-circle', 'Aus'] }[s.state];
    return '<span class="state ' + m[0] + '">' + I(m[1], 'sm') + m[2] + (short && s.state !== 'off' ? ' <span class="muted" style="font-weight:400">' + s.last + '</span>' : '') + '</span>';
  }

  /* ---------- Assets ---------- */
  function assets() {
    A.shell('assets');
    const tabs = [['assets', 'server', 'Assets', '42'], ['watchlist', 'tag', 'Watchlist', '4'], ['hosts', 'terminal', 'Hosts (SSH)', '3'], ['import', 'network', 'Import aus opennetmon', ''], ['csv', 'upload', 'CSV-Import', '']];
    let h = '<div class="pagehead"><div><h1>Assets</h1><p>Deine Soft- und Hardware. Nur dazu passende Meldungen landen im Eingang.</p></div></div>' +
      '<div class="split"><nav class="subnav" aria-label="Bereiche">' + tabs.map(function (t) { return '<a href="#' + t[0] + '" data-tab="' + t[0] + '">' + I(t[1]) + t[2] + (t[3] ? '<span class="n">' + t[3] + '</span>' : '') + '</a>'; }).join('') + '</nav><div>' +
      '<section class="panel" id="p-assets">' + assetsPanel() + '</section>' +
      '<section class="panel" id="p-watchlist">' + watchPanel() + '</section>' +
      '<section class="panel" id="p-hosts">' + hostsPanel() + '</section>' +
      '<section class="panel" id="p-import">' + importPanel() + '</section>' +
      '<section class="panel" id="p-csv">' + csvPanel() + '</section>' +
      '</div></div>';
    $('#main').innerHTML = h + addAssetModal();
    function show() {
      const t = (location.hash || '#assets').slice(1);
      $$('.panel').forEach(function (p) { p.hidden = p.id !== 'p-' + t; });
      $$('.subnav a').forEach(function (a) { a.toggleAttribute('aria-current', a.dataset.tab === t); if (a.dataset.tab === t) a.setAttribute('aria-current', 'page'); });
    }
    window.addEventListener('hashchange', show); show();
    document.addEventListener('click', function (e) {
      const tw = e.target.closest('button.tw');
      if (tw) { const open = tw.getAttribute('aria-expanded') === 'true'; tw.setAttribute('aria-expanded', String(!open)); $$('tr[data-grp="' + tw.dataset.grp + '"]').forEach(function (r) { r.hidden = open; }); }
      if (e.target.closest('#addAsset')) A.openModal('assetModal');
      const st = e.target.closest('[data-step]'); if (st) { wizStep(Number(st.dataset.step)); }
      const cp = e.target.closest('[data-copy]'); if (cp) A.toast('In die Zwischenablage kopiert');
      const sg = e.target.closest('.suggest li'); if (sg) { pickVendor(sg.dataset.v); }
      const im = e.target.closest('[data-imp]'); if (im) { const r = im.closest('tr'); r.querySelector('.impstate').innerHTML = im.dataset.imp === 'ok' ? '<span class="state ok">' + I('check', 'sm') + 'übernommen</span>' : '<span class="state off">übersprungen</span>'; }
    });
    const v = $('#aVendor'); if (v) { v.addEventListener('input', suggest); v.addEventListener('focus', suggest); }
    const ver = $('#aVersion'); if (ver) ver.addEventListener('input', preview);
    wizStep(2);
  }
  function assetsPanel() {
    const groups = [
      { id: 'server01', icon: 'server', name: 'server01', sub: 'Ubuntu 26.04 LTS', via: 'SSH, vor 2 h', n: '1 243 Pakete + 2 von Hand', open: true, rows: [
        ['openssh-server', '1:10.0p1-5ubuntu1', 'SSH (dpkg)', 'pkg:deb/ubuntu/openssh-server', 'CVE-2026-41872'],
        ['linux-image-7.0.0-41-generic', '7.0.0-41.42', 'SSH (dpkg)', 'pkg:deb/ubuntu/linux-image-7.0.0-41-generic', 'CVE-2026-40355'],
        ['libc6', '2.42-0ubuntu3', 'SSH (dpkg)', 'pkg:deb/ubuntu/libc6', 'CVE-2026-42210'],
        ['libcurl4t64', '8.16.0-2ubuntu1', 'SSH (dpkg)', 'pkg:deb/ubuntu/libcurl4t64', 'CVE-2026-37720'],
        ['libssl3t64', '3.5.3-1ubuntu2', 'SSH (dpkg)', 'pkg:deb/ubuntu/libssl3t64', 'CVE-2026-35190'],
        ['Traefik', '3.7.1', 'von Hand', 'cpe:2.3:a:traefik:traefik:3.7.1', 'CVE-2026-41003'],
        ['Fieldnet Controller', '6.2.0', 'von Hand', 'cpe:2.3:a:kestrel:fieldnet_controller:6.2.0', '']
      ] },
      { id: 'pi01', icon: 'server', name: 'pi01', sub: 'Debian 13 (Raspberry Pi OS)', via: 'SSH, vor 2 h', n: '812 Pakete', open: false, rows: [['openssh-server', '1:10.0p1-7', 'SSH (dpkg)', 'pkg:deb/debian/openssh-server', 'CVE-2026-41872'], ['libc6', '2.41-12', 'SSH (dpkg)', 'pkg:deb/debian/libc6', 'CVE-2026-42210'], ['libcurl4t64', '8.14.1-2', 'SSH (dpkg)', 'pkg:deb/debian/libcurl4t64', 'CVE-2026-37720']] },
      { id: 'nas01', icon: 'server', name: 'nas01', sub: 'Debian 13', via: 'SSH, vor 2 h', n: '967 Pakete', open: false, rows: [['openssh-server', '1:10.0p1-7', 'SSH (dpkg)', 'pkg:deb/debian/openssh-server', 'CVE-2026-41872'], ['samba', '2:4.22.4+dfsg-1', 'SSH (dpkg)', 'pkg:deb/debian/samba', 'CVE-2026-39960'], ['speicherpanel', '8.6.1-1', 'SSH (dpkg)', 'pkg:deb/debian/speicherpanel', 'CVE-2026-31877']] },
      { id: 'app01', icon: 'server', name: 'app01', sub: 'Ubuntu 24.04', via: 'von Hand', n: '2 Assets', open: false, rows: [['Hausautomat Core', '2026.10.2', 'von Hand', 'cpe:2.3:a:home-assistant:home-assistant:2026.10.2', 'CVE-2026-36512'], ['Hausautomat OS', '16.2', 'von Hand', 'cpe:2.3:o:home-assistant:home_assistant_os:16.2', '']] },
      { id: 'net', icon: 'router', name: 'Netzwerkgeräte', sub: '3 Geräte', via: 'opennetmon, von Hand', n: '3 Geräte', open: true, rows: [
        ['Nordlicht NR-750', 'NordOS 4.2.0', 'opennetmon', 'cpe:2.3:o:nordlicht:nordos:4.2.0', 'CVE-2026-39011'],
        ['Kestrel KG-200', '2.2.6', 'opennetmon', 'cpe:2.3:h:kestrel:kg-200', 'CVE-2026-38877'],
        ['Wellen 5G-Modem M5', '11.0.2', 'von Hand', '–', 'WID-SEC-2026-2304']
      ] }
    ];
    let rows = '';
    groups.forEach(function (g) {
      const n = D.matches.filter(function (m) { return OPEN.indexOf(m.state) >= 0 && (m.hosts.indexOf(g.name) >= 0 || (g.id === 'net' && m.type === 'Hardware')); });
      const worst = n.slice().sort(function (a, b) { return b.prio - a.prio; })[0];
      rows += '<tr class="group"><td colspan="2"><div class="grow"><button class="tw" type="button" data-grp="' + g.id + '" aria-expanded="' + g.open + '" aria-label="' + g.name + ' auf- oder zuklappen">' + I('chev-down') + '</button>' + I(g.icon) + '<b>' + g.name + '</b><span class="muted small">' + g.sub + '</span></div></td>' +
        '<td class="small muted">' + g.via + '</td><td class="small muted hide-sm">' + g.n + '</td><td>' + (n.length ? '<span class="openn sev ' + worst.sev + '">' + I(worst.sev, 'sm') + n.length + ' offen</span>' : '<span class="state ok">' + I('check', 'sm') + 'keine</span>') + '</td></tr>';
      g.rows.forEach(function (r) {
        const m = D.matches.find(function (x) { return x.id === r[4]; });
        rows += '<tr class="sub" data-grp="' + g.id + '"' + (g.open ? '' : ' hidden') + '><td>' + esc(r[0]) + '</td><td class="mono small">' + esc(r[1]) + '</td><td class="small">' + r[2] + '</td><td class="mono small muted hide-sm" style="max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r[3]) + '</td><td>' +
          (m && OPEN.indexOf(m.state) >= 0 ? '<a href="eingang.html?treffer=' + m.id + '">' + A.prioBadge(m) + '</a>' : '<span class="muted small">–</span>') + '</td></tr>';
      });
      if (g.id === 'server01') rows += '<tr class="sub" data-grp="server01"><td colspan="5"><a href="#" data-draft-toast="Entwurf: zeigt alle 1 243 Pakete mit Suche">Alle 1 243 Pakete anzeigen</a> <span class="muted small">· nur Pakete mit offenen Treffern sind aufgeführt</span></td></tr>';
    });
    return '<div class="card"><div class="toolbar"><label class="sr-only" for="aSearch">Assets durchsuchen</label><input id="aSearch" type="search" placeholder="Asset, Paket, Version suchen">' +
      '<select aria-label="Typ"><option>Alle Typen</option><option>Software</option><option>Hardware</option></select>' +
      '<select aria-label="Herkunft"><option>Jede Herkunft</option><option>SSH (dpkg)</option><option>opennetmon</option><option>von Hand</option><option>CSV</option></select>' +
      '<label class="check small"><input type="checkbox"> nur mit offenen Treffern</label><span class="sp"></span>' +
      '<button class="btn primary" type="button" id="addAsset">' + I('plus') + 'Asset anlegen</button></div>' +
      '<div class="tblwrap"><table class="tbl"><thead><tr><th>Asset</th><th>Version</th><th>Herkunft</th><th class="hide-sm">Kennung (CPE / PURL)</th><th>Offene Treffer</th></tr></thead><tbody>' + rows + '</tbody></table></div></div>';
  }
  const VENDORS = [['Nordlicht', 'NR-750, NR-690, Repeater R3', 'BSI CSAF'], ['Traefik Labs', 'Traefik', 'CPE'], ['Kestrel', 'KG-200, Fieldnet Controller, KS-108P', 'BSI CSAF, CPE'], ['Synology', 'DiskStation Manager (DSM)', 'CSAF'], ['Hausautomat', 'Hausautomat Core, Hausautomat OS', 'CPE'], ['Wellen', '5G-Modem M5, HarmonyOS', 'Wellen CSAF'], ['Grafana Labs', 'Grafana', 'CPE']];
  function addAssetModal() {
    return '<div class="modal" id="assetModal" role="dialog" aria-modal="true" aria-labelledby="amTitle" style="width:min(560px, calc(100vw - 32px))"><header><h2 id="amTitle">Asset anlegen</h2><button class="iconbtn" type="button" data-close aria-label="Schließen">' + I('x') + '</button></header><div class="mbody">' +
      '<div class="field"><span class="label">Typ</span><div class="btngroup"><label class="check"><input type="radio" name="aty" checked> Software</label><label class="check"><input type="radio" name="aty"> Hardware / Firmware</label></div></div>' +
      '<div class="field combo"><label for="aVendor">Hersteller</label><input id="aVendor" type="text" value="tra" autocomplete="off" aria-autocomplete="list" aria-controls="aSug"><ul class="suggest" id="aSug" role="listbox" hidden></ul><span class="help">Vorschläge aus CPE-Wörterbuch und CSAF-Produktbäumen</span></div>' +
      '<div class="field-row"><div class="field"><label for="aProduct">Produkt</label><select id="aProduct"><option>– erst Hersteller wählen –</option></select></div>' +
      '<div class="field"><label for="aVersion">Version</label><input id="aVersion" type="text" placeholder="z. B. 3.7.1"></div></div>' +
      '<div class="field"><label for="aHost">Host / Gerät</label><select id="aHost"><option>server01</option><option>pi01</option><option>nas01</option><option>app01</option><option>– eigenes Gerät –</option></select></div>' +
      '<div class="field"><label for="aCpe">Kennung</label><input id="aCpe" type="text" class="mono" value="" placeholder="wird aus Hersteller, Produkt und Version gebildet"><span class="help">CPE 2.3 oder PURL. Nur ändern, wenn du weißt, was du tust.</span></div>' +
      '<div class="notice info" id="aPrev">' + I('info') + '<span>Wähle Hersteller und Produkt für eine Vorschau der Treffer.</span></div>' +
      '</div><footer><button class="btn" type="button" data-close>Abbrechen</button><button class="btn primary" type="button" data-close data-draft-toast="Asset angelegt (Entwurf)">Anlegen</button></footer></div>';
  }
  function suggest() {
    const q = $('#aVendor').value.trim().toLowerCase();
    const list = VENDORS.filter(function (v) { return !q || v[0].toLowerCase().indexOf(q) >= 0 || v[1].toLowerCase().indexOf(q) >= 0; });
    const ul = $('#aSug');
    ul.innerHTML = list.map(function (v, i) {
      const n = esc(v[0]).replace(new RegExp('(' + q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'i'), '<mark>$1</mark>');
      return '<li role="option" data-v="' + esc(v[0]) + '" aria-selected="' + (i === 0) + '"><span>' + n + '</span><span class="muted">' + esc(v[2]) + '</span></li>';
    }).join('');
    ul.hidden = !list.length;
  }
  function pickVendor(v) {
    $('#aVendor').value = v; $('#aSug').hidden = true;
    const prods = (VENDORS.find(function (x) { return x[0] === v; }) || ['', ''])[1].split(', ');
    $('#aProduct').innerHTML = prods.map(function (p) { return '<option>' + esc(p) + '</option>'; }).join('');
    $('#aVersion').value = v === 'Traefik Labs' ? '3.7.1' : '';
    preview();
  }
  function preview() {
    const v = $('#aVendor').value, p = $('#aProduct').value, ver = $('#aVersion').value;
    $('#aCpe').value = v ? 'cpe:2.3:a:' + v.split(' ')[0].toLowerCase() + ':' + p.toLowerCase().replace(/[^a-z0-9]+/g, '_') + ':' + (ver || '*') : '';
    const hits = D.all.filter(function (m) { return m.vendor === v; });
    $('#aPrev').className = 'notice ' + (hits.length ? 'warn' : 'info');
    $('#aPrev').innerHTML = hits.length ? I('alert') + '<span>Würde aktuell <b>' + hits.length + ' Meldung' + (hits.length > 1 ? 'en' : '') + '</b> treffen: ' + hits.map(function (m) { return '<span class="mono">' + m.id + '</span> (' + m.prio + ')'; }).join(', ') + '</span>' : I('check-circle') + '<span>Aktuell keine bekannte Meldung für diese Version.</span>';
  }
  function watchPanel() {
    const kw = [['Wellen 5G-Modem', 1], ['Nordlicht Repeater', 0], ['Sensor-Gateway', 0], ['Wechselrichter', 0]];
    return '<div class="card"><header><h2>Watchlist</h2></header><div class="cbody">' +
      '<p class="muted">Stichwörter für Geräte und Programme ohne saubere Kennung. Treffer daraus haben das Vertrauen <span class="tag conf-niedrig">niedrig</span> und sollten geprüft werden.</p>' +
      '<div class="kwlist">' + kw.map(function (k) { return '<span class="chip">' + esc(k[0]) + ' <span class="muted small">' + k[1] + ' Treffer</span><button type="button" aria-label="' + esc(k[0]) + ' entfernen">' + I('x', 'sm') + '</button></span>'; }).join('') + '</div>' +
      '<div class="field" style="max-width:480px"><label for="kwNew">Stichwort hinzufügen</label><div style="display:flex;gap:8px"><input id="kwNew" type="text" placeholder="z. B. Zyxel NAS326" style="flex:1"><button class="btn" type="button" data-draft-toast="Stichwort hinzugefügt (Entwurf)">Hinzufügen</button></div><span class="help">Gesucht wird in Titel und Produktangaben der Advisories, ohne Groß-/Kleinschreibung.</span></div>' +
      '</div></div>';
  }
  function hostsPanel() {
    const rows = D.hosts.filter(function (x) { return x.via === 'SSH'; }).map(function (x) {
      return '<tr><td><b>' + x.name + '</b></td><td class="mono small">' + x.name + '.lan:22</td><td class="small">' + x.os + '</td><td class="num">' + x.pkgs.toLocaleString('de-DE') + '</td><td class="small">' + x.last + '</td><td><span class="state ok">' + I('check-circle', 'sm') + 'ok</span></td><td class="small"><button class="btn sm ghost" type="button" data-draft-toast="Entwurf: Abfrage gestartet">' + I('refresh', 'sm') + 'Jetzt abfragen</button></td></tr>';
    }).join('');
    return '<div class="card"><header><h2>Hosts (SSH)</h2><button class="btn sm" type="button" data-step="1">' + I('plus', 'sm') + 'Host hinzufügen</button></header>' +
      '<div class="tblwrap"><table class="tbl"><thead><tr><th>Name</th><th>Adresse</th><th>System</th><th class="num">Pakete</th><th>Letzte Abfrage</th><th>Zustand</th><th></th></tr></thead><tbody>' + rows + '</tbody></table></div>' +
      '<div class="cbody small muted">Abfrage alle 6 h über einen eigenen Schlüssel. Der Schlüssel darf auf dem Host nur einen Befehl ausführen (Paketliste und Systemangaben lesen).</div></div>' +
      '<section class="card wiz" aria-labelledby="wizTitle"><header><h2 id="wizTitle">Host hinzufügen</h2></header><div class="cbody">' +
      '<ol class="steps" id="steps"><li>Verbindung</li><li>Schlüssel hinterlegen</li><li>Host-Schlüssel bestätigen</li><li>Testen</li></ol>' +
      '<div data-pane="1"><div class="field-row"><div class="field"><label for="wName">Name</label><input id="wName" type="text" value="backup01"></div><div class="field"><label for="wAddr">Adresse</label><input id="wAddr" type="text" value="backup01.lan"></div></div>' +
      '<div class="field-row"><div class="field"><label for="wPort">Port</label><input id="wPort" type="number" value="22"></div><div class="field"><label for="wUser">Benutzer auf dem Host</label><input id="wUser" type="text" value="opensecmon"><span class="help">Ein eigener Benutzer ohne Rechte reicht.</span></div></div></div>' +
      '<div data-pane="2"><p>1. Lege auf <b>backup01</b> einen Benutzer <code>opensecmon</code> an und speichere dieses Skript als <code>/usr/local/bin/opensecmon-inventory</code> (ausführbar, gehört root):</p>' +
      '<div class="codebox">#!/bin/sh\n# opensecmon-inventory: gibt nur Systemangaben und Paketliste aus\ncat /etc/os-release\necho "---"\nexec dpkg-query -W -f=\'${Package}\\t${Version}\\t${Architecture}\\t${db:Status-Abbrev}\\n\'<button class="iconbtn" type="button" data-copy aria-label="Skript kopieren">' + I('copy') + '</button></div>' +
      '<p style="margin-top:12px">2. Trage diese Zeile in <code>~opensecmon/.ssh/authorized_keys</code> ein. <code>restrict</code> verbietet Weiterleitungen und Terminal, <code>command=</code> erlaubt nur das Skript:</p>' +
      '<div class="codebox">restrict,command="/usr/local/bin/opensecmon-inventory" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIK3vQ9Lw2xN8pE5mZr7tY1cH0fJ6uS4aB9dG2kV8oPqR opensecmon@server01<button class="iconbtn" type="button" data-copy aria-label="Zeile kopieren">' + I('copy') + '</button></div></div>' +
      '<div data-pane="3"><p>Beim ersten Verbinden meldet <b>backup01.lan</b> diesen Host-Schlüssel:</p><p><span class="fp">ED25519 SHA256:7Yc0pZ2m1r9QfK4xVb8LwT3nH6sJ5eA0dU2gR1iO9kE</span></p>' +
      '<p class="small muted">Vergleiche ihn auf dem Host mit <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code>. Erst nach deiner Bestätigung wird er gespeichert. Ändert er sich später, bricht die Abfrage ab und du bekommst eine Meldung.</p>' +
      '<label class="check"><input type="checkbox"> Der Fingerabdruck stimmt mit dem auf dem Host überein</label></div>' +
      '<div data-pane="4"><div class="notice info">' + I('check-circle') + '<span>Verbindung ok. <b>Debian 13 (trixie)</b>, 1 058 Pakete gelesen. 2 Pakete haben offene Meldungen, sie erscheinen gleich im Eingang.</span></div></div>' +
      '<div class="wizfoot"><button class="btn" type="button" id="wizBack">' + I('chev-left') + 'Zurück</button><button class="btn primary" type="button" id="wizNext">Weiter' + I('chev-right') + '</button></div>' +
      '</div></section>';
  }
  let wiz = 2;
  function wizStep(n) {
    wiz = Math.max(1, Math.min(4, n));
    $$('#steps li').forEach(function (li, i) { li.classList.toggle('done', i + 1 < wiz); if (i + 1 === wiz) li.setAttribute('aria-current', 'step'); else li.removeAttribute('aria-current'); });
    $$('[data-pane]').forEach(function (p) { p.hidden = Number(p.dataset.pane) !== wiz; });
    const b = $('#wizBack'), nx = $('#wizNext');
    if (!b) return;
    b.disabled = wiz === 1;
    nx.innerHTML = wiz === 3 ? 'Bestätigen und testen' + I('chev-right') : wiz === 4 ? 'Fertig' : 'Weiter' + I('chev-right');
    b.onclick = function () { wizStep(wiz - 1); };
    nx.onclick = function () { if (wiz === 4) A.toast('Host backup01 angelegt (Entwurf)'); else wizStep(wiz + 1); };
  }
  function importPanel() {
    const rows = [
      ['Router', 'NR-750 (UI) 4.2.0', 'Nordlicht · NR-750 · NordOS 4.2.0', 'Regel „Nordlicht NR“', 'ok'],
      ['KG-200', 'KG-200 v2.0', 'Kestrel · KG-200 · Version unbekannt', 'Regel „Kestrel Fieldnet“, Firmware fehlt in sysDescr', 'warn'],
      ['Switch Büro', 'SwitchLine 8-Port Gigabit L2+ Managed Switch with PoE+', 'Kestrel · KS-108P · ?', 'Regel „Kestrel SwitchLine“', 'warn'],
      ['Sensor-Gateway', 'Linux 4.4.198', '–', 'nicht erkannt', 'err'],
      ['pi01', 'Linux pi01 6.12.47+rpt-rpi-v8 aarch64', 'wird per SSH erfasst', 'Host bereits unter „Hosts (SSH)“', 'off']
    ];
    return '<div class="notice warn" style="margin-bottom:16px">' + I('info') + '<span>Dieser Import braucht eine kleine Erweiterung in opennetmon (Herstellerangaben speichern, lesender Endpunkt mit Token, Phase 6c). Bis dahin gibt es den CSV-Import.</span></div>' +
      '<div class="card"><header><h2>Geräte aus opennetmon</h2><span class="small muted">20 Geräte · zuletzt abgeglichen heute 14:00</span></header><div class="tblwrap"><table class="tbl"><thead><tr><th>Gerät in opennetmon</th><th class="hide-sm">sysDescr</th><th>Vorschlag</th><th>Erkannt durch</th><th></th></tr></thead><tbody>' +
      rows.map(function (r) {
        const st = { ok: '<span class="state ok">' + I('check-circle', 'sm') + 'sicher</span>', warn: '<span class="state warn">' + I('alert', 'sm') + 'bitte prüfen</span>', err: '<span class="state err">' + I('x-circle', 'sm') + 'unbekannt</span>', off: '<span class="state off">übersprungen</span>' }[r[4]];
        return '<tr><td><b>' + esc(r[0]) + '</b></td><td class="mono small muted hide-sm" style="max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="' + esc(r[1]) + '">' + esc(r[1]) + '</td><td>' + esc(r[2]) + '<div class="small">' + st + '</div></td><td class="small muted">' + esc(r[3]) + '</td><td class="impstate nowrap">' +
          (r[4] === 'off' ? '' : '<button class="btn sm" type="button" data-imp="ok"' + (r[4] === 'err' ? ' disabled' : '') + '>Übernehmen</button> <button class="btn sm ghost" type="button" data-draft-toast="Entwurf: Zuordnung bearbeiten">Ändern</button>') + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }
  function csvPanel() {
    return '<div class="card"><header><h2>CSV-Import</h2></header><div class="cbody"><div class="dropzone">' + I('upload', 'xl') + '<div><b>CSV-Datei hierher ziehen</b> oder <a href="#" data-draft-toast="Entwurf: Dateiauswahl">auswählen</a></div><div class="small muted">UTF-8, Trennzeichen Komma oder Semikolon, höchstens 5 000 Zeilen</div></div>' +
      '<h3 style="margin:16px 0 8px">Spalten</h3><div class="codebox">typ;hersteller;produkt;version;host;cpe\nhardware;Nordlicht;NR-750;4.2.0;;\nsoftware;Traefik Labs;Traefik;3.7.1;server01;cpe:2.3:a:traefik:traefik:3.7.1</div>' +
      '<p class="small muted" style="margin-top:8px">Vor dem Übernehmen zeigt eine Vorschau, welche Zeilen neu sind, welche vorhandene Assets ändern und welche Fehler haben.</p></div></div>';
  }

  /* ---------- Alle CVEs ---------- */
  function cves() {
    A.shell('cves');
    const q = new URLSearchParams(location.search).get('q') || '';
    const st = { q: q, kev: false, mine: false, epss: false, page: 1, sel: null, sort: 'pub' };
    $('#main').innerHTML = '<div class="cvelayout"><div class="main">' +
      '<div class="toolbar"><h1 style="font-size:var(--fs-lg);margin-right:8px">Alle CVEs</h1><label class="sr-only" for="cq">Volltext</label><input id="cq" type="search" placeholder="Volltext: Titel, Produkt, Kennung" value="' + esc(q) + '">' +
      '<span class="sp"></span><button class="btn sm" type="button" data-draft-toast="Entwurf: CSV mit den aktuellen Filtern">' + I('download', 'sm') + 'CSV</button></div>' +
      '<div class="chips" id="cchips"></div>' +
      '<div class="tblwrap"><table class="tbl" id="ctbl"></table></div>' +
      '<div class="pager" id="cpager"></div></div>' +
      '<section class="pane detail" id="detail" aria-label="Details"></section></div>';
    function list() {
      let l = D.all.filter(function (m) {
        if (st.kev && !m.kev) return false;
        if (st.mine && !m.assets.length) return false;
        if (st.epss && m.epss < 0.1) return false;
        if (st.q) { const s = (m.id + ' ' + m.cves.join(' ') + ' ' + m.title + ' ' + m.vendor + ' ' + m.product).toLowerCase(); if (s.indexOf(st.q.toLowerCase()) < 0) return false; }
        return true;
      });
      if (st.sort === 'prio') l.sort(function (a, b) { return b.prio - a.prio; });
      if (st.sort === 'cvss') l.sort(function (a, b) { return b.cvss - a.cvss; });
      if (st.sort === 'epss') l.sort(function (a, b) { return b.epss - a.epss; });
      return l;
    }
    function render() {
      const l = list();
      $('#cchips').innerHTML =
        '<span class="chip">Zeitraum: 30 Tage<button type="button" aria-label="Zeitraum entfernen" data-draft-toast="Entwurf: Zeitraum wählbar">' + I('x', 'sm') + '</button></span>' +
        chip('mine', 'Nur eigene Treffer') + chip('kev', 'Nur KEV') + chip('epss', 'EPSS ≥ 10 %') +
        '<button class="chip add" type="button" data-draft-toast="Entwurf: weitere Filter (Quelle, Schwere, Hersteller)">+ Filter</button>' +
        '<span class="muted small" style="margin-left:auto;align-self:center">' + l.length + ' von 294 113 CVEs</span>';
      const th = function (k, lab, cls) { return '<th' + (cls ? ' class="' + cls + '"' : '') + (st.sort === k ? ' aria-sort="descending"' : '') + '><button type="button" data-sort="' + k + '">' + lab + (st.sort === k ? I('arrow-down', 'sm') : '') + '</button></th>'; };
      $('#ctbl').innerHTML = '<thead><tr>' + th('prio', 'Prio') + '<th>Kennung</th><th>Titel</th>' + th('cvss', 'CVSS', 'num') + th('epss', 'EPSS', 'num hide-sm') + '<th>KEV</th><th class="hide-sm">Eigene</th>' + th('pub', 'Veröffentlicht', 'num hide-sm') + '</tr></thead><tbody>' +
        l.map(function (m) {
          return '<tr class="click" data-id="' + m.id + '" aria-selected="' + (st.sel === m.id) + '" tabindex="0"><td>' + A.prioBadge(m) + '</td><td class="mono small nowrap">' + m.id + '</td><td class="t" title="' + esc(m.title) + '">' + esc(m.title) + '</td><td class="num"><span class="sev ' + D.cvssBand(m.cvss) + '">' + A.num(m.cvss) + '</span></td><td class="num hide-sm">' + A.pct(m.epss) + '</td><td>' + A.kevBadge(m) + '</td><td class="hide-sm">' + (m.assets.length ? '<span class="mine">' + I('server', 'sm') + m.assets.length + '</span>' : '') + '</td><td class="num hide-sm">' + A.dmy(m.published) + '</td></tr>';
        }).join('') + '</tbody>';
      $('#cpager').innerHTML = '<span>Seite 1 von 1 · 50 je Seite</span><span class="pages"><span aria-current="page">1</span></span>';
      if (!st.sel && l.length && window.innerWidth >= 1280) sel(l[0].id, false);
    }
    function chip(k, lab) { return st[k] ? '<span class="chip">' + lab + '<button type="button" data-tog="' + k + '" aria-label="' + lab + ' entfernen">' + I('x', 'sm') + '</button></span>' : '<button class="chip off" type="button" data-tog="' + k + '">' + lab + '</button>'; }
    function sel(id, open) {
      st.sel = id;
      $$('#ctbl tbody tr').forEach(function (r) { r.setAttribute('aria-selected', String(r.dataset.id === id)); });
      const m = D.all.find(function (x) { return x.id === id; });
      $('#detail').innerHTML = A.detailHtml(m, { back: true, backLabel: 'Zur Liste', actions: true });
      if (open && window.innerWidth < 1280) document.body.classList.add('sheet-open');
    }
    document.addEventListener('click', function (e) {
      const t = e.target.closest('[data-tog]'); if (t) { st[t.dataset.tog] = !st[t.dataset.tog]; st.sel = null; render(); return; }
      const s = e.target.closest('[data-sort]'); if (s) { st.sort = s.dataset.sort; render(); return; }
      const b = e.target.closest('[data-back]'); if (b) { e.preventDefault(); document.body.classList.remove('sheet-open'); return; }
      const a = e.target.closest('[data-act]'); if (a) { e.preventDefault(); A.toast('Entwurf: dieselben Aktionen wie im Eingang'); return; }
      const r = e.target.closest('#ctbl tbody tr'); if (r) sel(r.dataset.id, true);
    });
    document.addEventListener('keydown', function (e) { const r = e.target.closest && e.target.closest('#ctbl tbody tr'); if (r && e.key === 'Enter') sel(r.dataset.id, true); });
    $('#cq').addEventListener('input', function (e) { st.q = e.target.value; st.sel = null; render(); });
    render();
  }

  /* ---------- Quellen ---------- */
  function quellen() {
    A.shell('quellen');
    $('#main').innerHTML = '<div class="pagehead"><div><h1>Quellen</h1><p>Abrufe laufen nur bei Änderungen (ETag, Prüfsummen, Änderungslisten). Intervalle mit Zufallsversatz.</p></div>' +
      '<button class="btn" type="button" data-draft-toast="Entwurf: alle eingeschalteten Quellen werden abgerufen">' + I('refresh') + 'Alle jetzt abrufen</button></div>' +
      '<div class="card"><div class="tblwrap"><table class="tbl" id="stbl"><thead><tr><th>Zustand</th><th>Quelle</th><th class="num">Letzter Lauf</th><th class="num hide-sm">Dauer</th><th class="num">Neu</th><th class="num hide-sm">Geändert</th><th class="hide-sm">Nächster Lauf</th><th class="hide-sm">Intervall</th><th>Ein</th><th></th></tr></thead><tbody>' +
      D.sources.map(function (s) {
        return '<tr data-s="' + s.id + '"><td>' + srcState(s) + '</td><td><b>' + esc(s.name) + '</b></td><td class="num">' + s.last + '</td><td class="num hide-sm">' + s.dur + '</td><td class="num">' + s.nw + '</td><td class="num hide-sm">' + s.ch.toLocaleString('de-DE') + '</td><td class="small hide-sm">' + s.next + '</td><td class="small hide-sm">' + s.iv + '</td>' +
          '<td><label class="switch"><input type="checkbox" ' + (s.on ? 'checked' : '') + ' aria-label="' + esc(s.name) + ' ein"></label></td>' +
          '<td class="nowrap"><button class="btn sm ghost" type="button" data-draft-toast="Entwurf: ' + esc(s.name) + ' wird abgerufen"' + (s.on ? '' : ' disabled') + '>' + I('refresh', 'sm') + '<span class="hide-sm">Abrufen</span></button><button class="iconbtn" type="button" data-more="' + s.id + '" aria-expanded="' + (s.state === 'err' || s.state === 'warn') + '" aria-label="Details ' + esc(s.name) + '">' + I('chev-down') + '</button></td></tr>' +
          '<tr class="more" data-more-of="' + s.id + '"' + (s.state === 'err' || s.state === 'warn' ? '' : ' hidden') + '><td></td><td colspan="9" style="padding:8px 12px 14px;height:auto"><div class="small">' +
          (s.state === 'err' ? '<div class="notice warn" style="margin-bottom:8px">' + I('x-circle') + '<span>' + esc(s.detail) + '</span></div>' : '<p>' + esc(s.detail) + '</p>') +
          '<p class="muted">' + I('info', 'sm') + ' ' + esc(s.lic) + '</p>' +
          '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><label for="iv-' + s.id + '">Intervall</label><select id="iv-' + s.id + '"><option>1 h</option><option' + (s.iv === '2 h' ? ' selected' : '') + '>2 h</option><option' + (s.iv === '6 h' ? ' selected' : '') + '>6 h</option><option' + (s.iv === 'täglich' ? ' selected' : '') + '>täglich</option></select>' +
          (s.id === 'vendor' ? '<a class="btn sm" href="#" data-draft-toast="Entwurf: Anbieter aus dem BSI-Lister wählen, eigene URL ergänzen">Anbieter verwalten</a>' : '') + '<a class="btn sm ghost" href="#" data-draft-toast="Entwurf: Protokoll der letzten Läufe">Letzte Läufe</a></div>' +
          '</div></td></tr>';
      }).join('') + '</tbody></table></div></div>' +
      '<section class="card" style="margin-top:16px"><header><h2>Hinweise zu den Daten</h2></header><div class="cbody small"><p>This product uses data from the NVD but is not endorsed or certified by the NVD.</p><p>CVE® ist eine Marke von The MITRE Corporation. EPSS-Daten: FIRST.org. KEV: CISA (CC0). Ubuntu Security Notices: Canonical Ltd., CC BY-SA 4.0. BSI CERT-Bund: Bundesamt für Sicherheit in der Informationstechnik.</p><p class="muted">Endgültige Texte nach der Lizenzprüfung (offener Punkt in PLAN.md).</p></div></section>';
    document.addEventListener('click', function (e) {
      const b = e.target.closest('[data-more]'); if (!b) return;
      const open = b.getAttribute('aria-expanded') === 'true'; b.setAttribute('aria-expanded', String(!open));
      $('tr[data-more-of="' + b.dataset.more + '"]').hidden = open;
    });
  }

  /* ---------- Einstellungen ---------- */
  function einstellungen() {
    A.shell('');
    const tabs = [['meldungen', 'mail', 'Sofort-Mail'], ['bericht', 'calendar', 'Tagesbericht'], ['mailserver', 'server', 'Mailserver'], ['prio', 'activity', 'Priorität'], ['aufbewahrung', 'history', 'Aufbewahrung'], ['konto', 'user', 'Konto'], ['protokoll', 'list', 'Protokoll']];
    const card = function (id, title, body, foot) { return '<section class="panel card" id="p-' + id + '"><header><h2>' + title + '</h2></header><div class="cbody">' + body + '</div>' + (foot === false ? '' : '<div class="cfoot"><button class="btn" type="button" data-draft-toast="Entwurf: verworfen">Verwerfen</button><button class="btn primary" type="button" data-draft-toast="Gespeichert (Entwurf)">Speichern</button></div>') + '</section>'; };
    const mail = '<div class="field"><label for="mTo">Empfänger</label><input id="mTo" type="email" value="admin@example.org"><span class="help">Mehrere Adressen mit Komma trennen.</span></div>' +
      '<div class="field"><span class="label">Sofort melden, wenn ein neuer Treffer eine dieser Bedingungen erfüllt</span>' +
      '<label class="check"><input type="checkbox" checked> Er steht in CISA KEV (wird aktiv ausgenutzt)</label>' +
      '<label class="check"><input type="checkbox" checked> Priorität mindestens <input type="number" value="85" min="0" max="100" style="width:72px;margin:0 6px" aria-label="Priorität mindestens"> (kritisch)</label>' +
      '<label class="check"><input type="checkbox"> CVSS mindestens <input type="number" value="8.0" step="0.1" style="width:72px;margin:0 6px" aria-label="CVSS mindestens"></label>' +
      '<label class="check"><input type="checkbox"> EPSS mindestens <input type="number" value="10" style="width:72px;margin:0 6px" aria-label="EPSS mindestens in Prozent"> %</label></div>' +
      '<div class="field"><label for="mConf">Mindestens nötiges Vertrauen</label><select id="mConf"><option>mittel</option><option>hoch</option><option>niedrig</option></select><span class="help">Stichwort-Treffer (niedrig) kommen sonst nur in den Tagesbericht.</span></div>' +
      '<div class="field"><span class="label">Zusammenfassen</span><label class="check"><input type="checkbox" checked> Treffer innerhalb von 10 Minuten in einer Mail bündeln</label><label class="check"><input type="checkbox" checked> Dieselbe CVE nur einmal melden, auch wenn weitere Hosts dazukommen</label></div>' +
      '<button class="btn" type="button" data-draft-toast="Testmail gesendet (Entwurf)">' + I('mail') + 'Testmail senden</button>';
    const rep = '<div class="field-row"><div class="field"><span class="label">Tagesbericht</span><label class="switch"><input type="checkbox" checked> an</label></div><div class="field"><label for="rTime">Uhrzeit</label><input id="rTime" type="time" value="07:00"></div></div>' +
      '<div class="field"><span class="label">Inhalt</span><label class="check"><input type="checkbox" checked> Neue Treffer seit dem letzten Bericht</label><label class="check"><input type="checkbox" checked> Alle offenen kritischen Treffer und KEV</label><label class="check"><input type="checkbox" checked> Quellen mit Fehlern</label><label class="check"><input type="checkbox"> Zurückgestellte Treffer, die heute wieder fällig werden</label><label class="check"><input type="checkbox" checked> Nicht senden, wenn es nichts zu melden gibt</label></div>' +
      '<h3 style="margin:8px 0">Vorschau</h3><div class="mailprev"><div class="mh"><b>opensecmon: 3 neue Treffer, 3 kritisch offen</b><br>An admin@example.org · Mi 05.11.2026 07:00</div><div class="mb">' +
      '<p><b>Neu seit gestern 07:00</b></p><table>' + D.matches.filter(function (m) { return m.firstSeen >= '2026-11-03 07'; }).map(function (m) { return '<tr><td>' + A.prioBadge(m) + '</td><td class="mono">' + m.id + '</td><td>' + esc(m.title) + '</td></tr>'; }).join('') + '</table>' +
      '<p><b>Quellen mit Fehlern:</b> Debian Security Tracker (HTTP 503 seit 12:21)</p><p class="muted">Jede Kennung verlinkt direkt auf den Treffer im Eingang.</p></div></div>' +
      '<div style="margin-top:12px"><button class="btn" type="button" data-draft-toast="Bericht jetzt gesendet (Entwurf)">' + I('mail') + 'Jetzt senden</button></div>';
    const smtp = '<div class="field-row"><div class="field"><label for="sHost">Server</label><input id="sHost" type="text" value="smtp.example.org"></div><div class="field"><label for="sPort">Port</label><input id="sPort" type="number" value="587"></div></div>' +
      '<div class="field-row"><div class="field"><label for="sTls">Verschlüsselung</label><select id="sTls"><option>STARTTLS</option><option>TLS</option><option>keine (nur lokal)</option></select></div><div class="field"><label for="sFrom">Absender</label><input id="sFrom" type="email" value="opensecmon@example.org"></div></div>' +
      '<div class="field-row"><div class="field"><label for="sUser">Benutzer</label><input id="sUser" type="text" value="opensecmon@example.org"></div><div class="field"><label for="sPw">Passwort</label><input id="sPw" type="password" value="••••••••••"><span class="help">Verschlüsselt gespeichert.</span></div></div>';
    const prio = '<p class="muted">Die Priorität ordnet den Eingang. Sie wird bei jeder Änderung für alle Treffer neu berechnet und auf jeder Detailseite offengelegt.</p>' +
      '<div class="field-row"><div class="field"><label for="wC">Gewicht CVSS (× Wert 0–10)</label><input id="wC" type="number" value="7"></div><div class="field"><label for="wE">Gewicht EPSS-Perzentil (× 0–1)</label><input id="wE" type="number" value="20"></div></div>' +
      '<div class="field-row"><div class="field"><label for="wV">Vertrauen hoch / mittel / niedrig</label><input id="wV" type="text" value="10 / 5 / 0"></div><div class="field"><label for="wK">KEV hebt auf mindestens</label><input id="wK" type="number" value="90"></div></div>' +
      '<div class="field"><span class="label">Stufen</span><div class="btngroup small"><span class="prio crit">' + I('crit') + '≥ 85</span><span class="prio high">' + I('high') + '≥ 65</span><span class="prio med">' + I('med') + '≥ 45</span><span class="prio low">' + I('low') + '&lt; 45</span></div></div>' +
      '<div class="formula"><b>Beispiel CVE-2026-40355</b> (Kernel): CVSS 7,8 × 7 = 54,6 · EPSS-Perzentil 82 % × 20 = 16,4 · Vertrauen hoch +10 → 81, in KEV → <b>90</b></div>';
    const ret = '<div class="field-row"><div class="field"><label for="kC">CVEs ohne eigenen Treffer behalten</label><select id="kC"><option>5 Jahre</option><option>alle</option><option>2 Jahre</option></select></div><div class="field"><label for="kD">Erledigte und ignorierte Treffer</label><select id="kD"><option>1 Jahr</option><option>immer</option></select></div></div>' +
      '<div class="field"><label for="kA">Protokoll</label><select id="kA"><option>2 Jahre</option><option>1 Jahr</option></select></div>' +
      '<div class="notice info">' + I('info') + '<span>Datenbank: 1,8 GB (CVE-Liste 1,3 GB, CSAF 0,4 GB). Letzte Sicherung heute 03:00 nach <code>/var/lib/opensecmon/backup/</code>.</span></div>';
    const acc = '<div class="field"><label for="uName">Benutzername</label><input id="uName" type="text" value="admin" disabled></div>' +
      '<div class="field-row"><div class="field"><label for="uPw1">Neues Passwort</label><input id="uPw1" type="password"></div><div class="field"><label for="uPw2">Wiederholen</label><input id="uPw2" type="password"></div></div>' +
      '<div class="field-row"><div class="field"><label for="uLang">Sprache</label><select id="uLang"><option>Deutsch</option><option>English</option></select></div><div class="field"><label for="uTheme">Darstellung</label><select id="uTheme"><option>wie System</option><option>hell</option><option>dunkel</option></select></div></div>' +
      '<div class="field"><span class="label">Angemeldete Sitzungen</span><div class="small">Dieser Browser · seit heute 14:30 <span class="muted">· Abmeldung nach 30 min ohne Aktivität</span></div></div>';
    const log = '<div class="tblwrap"><table class="tbl"><thead><tr><th>Zeit</th><th>Benutzer</th><th>Änderung</th></tr></thead><tbody>' + D.audit.map(function (a) { return '<tr><td class="mono small nowrap">' + A.dmy(a[0]) + '</td><td>' + a[1] + '</td><td>' + esc(a[2]) + '</td></tr>'; }).join('') + '</tbody></table></div>';
    $('#main').innerHTML = '<div class="pagehead"><div><h1>Einstellungen</h1></div></div><div class="split settings"><nav class="subnav" aria-label="Bereiche">' + tabs.map(function (t) { return '<a href="#' + t[0] + '" data-tab="' + t[0] + '">' + I(t[1]) + t[2] + '</a>'; }).join('') + '</nav><div>' +
      card('meldungen', 'Sofort-Mail bei neuen Treffern', mail) + card('bericht', 'Tagesbericht', rep) + card('mailserver', 'Mailserver', smtp) + card('prio', 'Priorität', prio) + card('aufbewahrung', 'Aufbewahrung', ret) + card('konto', 'Konto', acc) + card('protokoll', 'Protokoll', log, false) + '</div></div>';
    function show() {
      const t = (location.hash || '#meldungen').slice(1);
      $$('.panel').forEach(function (p) { p.hidden = p.id !== 'p-' + t; });
      $$('.subnav a').forEach(function (a) { if (a.dataset.tab === t) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current'); });
    }
    window.addEventListener('hashchange', show); show();
  }

  /* ---------- Übersicht ---------- */
  function index() {
    A.shell('');
    const pages = [
      ['eingang.html', 'Eingang', 'Hauptansicht: Filter, Trefferliste nach Priorität, Details mit Aktionen. Tastatur j/k/e/i/s/o/?. Oben in der Entwurfsleiste „Leerer Eingang“ für den Zustand ohne Treffer.'],
      ['detail.html?id=CVE-2026-41872', 'Detail', 'Ganze Seite für einen Treffer, so öffnet ein Link aus der Mail (vor allem am Handy).'],
      ['lage.html', 'Lage', 'Wenige Kacheln, Verlauf 30 Tage, betroffene Hosts, älteste offene Treffer, Quellen.'],
      ['assets.html', 'Assets', 'Nach Host gruppiert; Asset anlegen mit Vorschlägen und Vorschau; Watchlist; SSH-Assistent; Import aus opennetmon; CSV.'],
      ['assets.html#hosts', 'Host-Assistent', 'Vier Schritte: Verbindung, Schlüssel mit Zwangsbefehl, Host-Schlüssel bestätigen, Test.'],
      ['cves.html', 'Alle CVEs', 'Recherche über den ganzen Bestand mit Filterchips und derselben Detail-Komponente.'],
      ['quellen.html', 'Quellen', 'Zustand je Quelle, Fehler und Warnung aufgeklappt, Intervall, Quellenhinweise.'],
      ['einstellungen.html', 'Einstellungen', 'Sofort-Mail, Tagesbericht mit Vorschau, Mailserver, Priorität, Aufbewahrung, Konto, Protokoll.'],
      ['breiten.html', 'Breiten', 'Eine Seite gleichzeitig in 1440, 1024 und 390 px.']
    ];
    const toks = [['--bg', 'Hintergrund'], ['--surface', 'Fläche'], ['--text', 'Text'], ['--text-3', 'Text leise'], ['--accent', 'Akzent'], ['--crit', 'Kritisch'], ['--high', 'Hoch'], ['--med', 'Mittel'], ['--low', 'Niedrig'], ['--kev-bg', 'KEV'], ['--ok', 'In Ordnung']];
    $('#main').innerHTML = '<div class="pagehead"><div><h1>opensecmon – Entwürfe der Oberfläche</h1><p>Stand 04.11.2026 · nur zur Abnahme der Gestaltung · alle Daten erfunden · kein Anwendungscode</p></div></div>' +
      '<div class="grid2"><section class="card"><header><h2>Seiten</h2></header><div class="tblwrap"><table class="tbl"><tbody>' + pages.map(function (p) { return '<tr><td class="nowrap"><a href="' + p[0] + '"><b>' + p[1] + '</b></a></td><td class="small" style="height:auto;padding-top:8px;padding-bottom:8px">' + p[2] + '</td></tr>'; }).join('') + '</tbody></table></div></section>' +
      '<section class="card"><header><h2>Bitte prüfen</h2></header><div class="cbody small"><ol style="margin:0;padding-left:18px;display:grid;gap:6px">' +
      '<li>Passt der Eingang als Startseite? Reicht die Trefferzeile (Priorität, KEV, Kennung, Titel, Asset, Quelle)?</li>' +
      '<li>Ist die Prioritätsformel verständlich (Detail → „So entsteht die Priorität“)?</li>' +
      '<li>Akzentfarbe Blau, Schriften Fira Sans / Fira Code, Dichte der Zeilen</li>' +
      '<li>Hell und dunkel (Schalter oben rechts oder in der Entwurfsleiste)</li>' +
      '<li>Breiten: Fenster schmaler ziehen oder <a href="breiten.html">Breiten</a> öffnen</li>' +
      '<li>Fehlt eine Seite, ein Filter oder eine Aktion?</li></ol>' +
      '<p class="muted" style="margin-top:12px">Formen der Schwere: ' + SEVS.map(function (s) { return '<span class="sev ' + s + '">' + I(s, 'sm') + ' ' + D.SEV_LABEL[s] + '</span>'; }).join(' · ') + '. Farbe nie allein: Form, Zahl und Text gehören immer dazu.</p></div></section></div>' +
      '<section class="card"><header><h2>Farben (Tokens)</h2><span class="small muted">aus <code>assets/tokens.css</code>, Kontrast Text ≥ 4,5 : 1</span></header><div class="cbody"><div class="swatches">' + toks.map(function (t) { return '<div class="sw"><i style="background:var(' + t[0] + ')"></i><div>' + t[1] + '<br><code>' + t[0] + '</code></div></div>'; }).join('') + '</div>' +
      '<p class="small muted" style="margin-top:12px">Schriften: Fira Sans und Fira Code (SIL Open Font License 1.1), lokal in <code>fonts/</code>. Symbole nach Lucide (ISC). Kein CDN, keine Google-Fonts.</p></div></section>';
  }

  /* ---------- Breiten ---------- */
  function breiten() {
    A.shell('');
    const opts = [['eingang.html', 'Eingang'], ['detail.html', 'Detail'], ['lage.html', 'Lage'], ['assets.html', 'Assets'], ['cves.html', 'Alle CVEs'], ['quellen.html', 'Quellen'], ['einstellungen.html', 'Einstellungen']];
    const cur = new URLSearchParams(location.search).get('seite') || 'eingang.html';
    $('#main').innerHTML = '<div class="pagehead"><div><h1>Breiten</h1><p>Dieselbe Seite in 1440, 1024 und 390 px, verkleinert. In den Rahmen lässt sich klicken.</p></div>' +
      '<div><label for="bw" class="small">Seite </label><select id="bw">' + opts.map(function (o) { return '<option value="' + o[0] + '"' + (o[0] === cur ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') + '</select></div></div>' +
      '<div class="frames">' + [[1440, 900, 0.42], [1024, 768, 0.42], [390, 844, 0.6]].map(function (f) {
        return '<figure class="frame" style="margin:0"><div class="fw" style="width:' + Math.round(f[0] * f[2]) + 'px;height:' + Math.round(f[1] * f[2]) + 'px"><iframe src="' + cur + '" title="' + f[0] + ' px" style="width:' + f[0] + 'px;height:' + f[1] + 'px;transform:scale(' + f[2] + ')"></iframe></div><figcaption>' + f[0] + ' × ' + f[1] + ' px</figcaption></figure>';
      }).join('') + '</div>';
    $('#bw').addEventListener('change', function (e) { location.search = '?seite=' + encodeURIComponent(e.target.value); });
  }

  const R = { detail: detail, lage: lage, assets: assets, cves: cves, quellen: quellen, einstellungen: einstellungen, index: index, breiten: breiten };
  document.addEventListener('DOMContentLoaded', function () { R[document.body.dataset.page](); });
})();
