// "All CVEs" (templates/cves.html): a click on a row shows its detail beside the list (on narrow screens as a
// sheet) without reloading the page. The server renders everything; this script only fetches the same page
// with `sel=` and swaps the detail pane. Without it, the id links open the detail page of the CVE.
(function () {
  'use strict';
  var layout = document.getElementById('cvelayout');
  if (!layout) { return; }
  var body = document.body;
  var narrow = window.matchMedia('(max-width: 1279px)');
  if (layout.hasAttribute('data-sheet-open')) { body.classList.add('sheet-open'); }

  function selectedId(href) {
    try { return new URL(href, location.href).searchParams.get('sel') || ''; } catch (e) { return ''; }
  }
  function mark(id) {
    var rows = document.querySelectorAll('#ctbl tbody tr[data-href]');
    Array.prototype.forEach.call(rows, function (row) {
      if (selectedId(row.getAttribute('data-href')) === id) {
        row.setAttribute('aria-selected', 'true');
      } else {
        row.removeAttribute('aria-selected');
      }
    });
  }
  function show(href, push) {
    fetch(href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
      .then(function (reply) {
        if (!reply.ok || reply.redirected) { throw new Error('reload'); }
        return reply.text();
      })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var pane = doc.getElementById('detail');
        var current = document.getElementById('detail');
        if (!pane || !current) { throw new Error('reload'); }
        current.innerHTML = pane.innerHTML;
        if (window.opensecmonTimes) { window.opensecmonTimes(current); }
        current.scrollTop = 0;
        mark(selectedId(href));
        if (push) { history.pushState({ cves: true }, '', href); }
        body.classList.add('sheet-open');
      })
      .catch(function () { location.href = href; });
  }

  document.addEventListener('click', function (e) {
    if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) { return; }
    var close = e.target.closest('[data-sheet-close]');
    if (close) {
      if (narrow.matches) { e.preventDefault(); body.classList.remove('sheet-open'); }
      return;
    }
    var row = e.target.closest('#ctbl tbody tr[data-href]');
    if (!row) { return; }
    var link = e.target.closest('a');
    if (link && !link.hasAttribute('data-detail')) { return; }
    e.preventDefault();
    show(row.getAttribute('data-href'), true);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && body.classList.contains('sheet-open') && narrow.matches) {
      body.classList.remove('sheet-open');
    }
  });
  window.addEventListener('popstate', function () {
    if (selectedId(location.href)) {
      show(location.href, false);
    } else {
      body.classList.remove('sheet-open');
    }
  });
})();
