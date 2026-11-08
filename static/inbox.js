// Inbox (templates/inbox.html): a click on a row shows its detail without reloading the page (the server
// renders it; this script fetches the same page with `sel=` and swaps the detail pane), the check boxes fill
// the bulk bar, and keys: j/k select, Enter opens, x marks, e done, s later, i ignore, o source, r reopen,
// Esc closes. Without this script every link and form works on its own.
(function () {
  'use strict';
  var inbox = document.getElementById('inbox');
  if (!inbox) { return; }
  var body = document.body;
  var narrow = window.matchMedia('(max-width: 1279px)');
  var listbar = document.getElementById('listbar');
  var selAll = document.getElementById('selAll');
  var bulkN = document.getElementById('bulkN');
  if (inbox.hasAttribute('data-sheet-open')) { body.classList.add('sheet-open'); }
  if (selAll) { selAll.hidden = false; }
  Array.prototype.forEach.call(document.querySelectorAll('[data-noscript]'), function (el) { el.hidden = true; });

  function rows() { return Array.prototype.slice.call(document.querySelectorAll('#rows li.row')); }
  function boxes() { return Array.prototype.slice.call(document.querySelectorAll('#rows li.row input[type="checkbox"]')); }
  function current() { return document.querySelector('#rows li.row[aria-selected="true"]'); }

  function updateBulk() {
    var all = boxes();
    var n = all.filter(function (b) { return b.checked; }).length;
    if (listbar) { listbar.classList.toggle('has-sel', n > 0); }
    if (bulkN) { bulkN.textContent = n + ' ' + bulkN.getAttribute('data-text'); }
    if (selAll) {
      selAll.checked = n > 0 && n === all.length;
      selAll.indeterminate = n > 0 && n < all.length;
    }
  }

  function show(row, push, open) {
    var href = row.getAttribute('data-href');
    rows().forEach(function (r) { r.setAttribute('aria-selected', String(r === row)); });
    row.classList.remove('unread');
    row.scrollIntoView({ block: 'nearest' });
    fetch(href, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
      .then(function (reply) {
        if (!reply.ok || reply.redirected) { throw new Error('reload'); }
        return reply.text();
      })
      .then(function (html) {
        var doc = new DOMParser().parseFromString(html, 'text/html');
        var pane = doc.getElementById('detail');
        var detail = document.getElementById('detail');
        if (!pane || !detail) { throw new Error('reload'); }
        detail.replaceChildren.apply(detail, Array.prototype.map.call(pane.childNodes, function (n) {
          return document.importNode(n, true);
        }));
        if (window.opensecmonTimes) { window.opensecmonTimes(detail); }
        detail.scrollTop = 0;
        if (push) { history.pushState({ inbox: true }, '', href); }
        if (open) { body.classList.add('sheet-open'); }
      })
      .catch(function () { location.href = href; });
  }

  function closeMenus() {
    Array.prototype.forEach.call(document.querySelectorAll('details.act[open]'), function (d) { d.removeAttribute('open'); });
  }

  document.addEventListener('click', function (e) {
    if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) { return; }
    if (e.target.closest('[data-sheet-close]')) {
      if (narrow.matches) { e.preventDefault(); body.classList.remove('sheet-open'); }
      return;
    }
    if (e.target.closest('#openFilters')) { body.classList.add('filters-open'); return; }
    if (e.target.closest('[data-close-filters]')) { body.classList.remove('filters-open'); return; }
    if (e.target.closest('#bulkClear')) {
      boxes().forEach(function (b) { b.checked = false; });
      updateBulk();
      return;
    }
    Array.prototype.forEach.call(document.querySelectorAll('details.act[open]'), function (d) {
      if (!d.contains(e.target)) { d.removeAttribute('open'); }
    });
    var row = e.target.closest('#rows li.row');
    if (!row || e.target.matches('input[type="checkbox"]')) { return; }
    var link = e.target.closest('a');
    if (link && !link.hasAttribute('data-detail')) { return; }
    e.preventDefault();
    show(row, true, true);
  });
  document.addEventListener('change', function (e) {
    if (e.target === selAll) {
      boxes().forEach(function (b) { b.checked = selAll.checked; });
      updateBulk();
      return;
    }
    if (e.target.closest('#rows input[type="checkbox"]')) { updateBulk(); return; }
    var auto = e.target.closest('[data-autosubmit]');
    if (auto && auto.form) { auto.form.submit(); }
  });

  function typing(e) {
    var tag = (e.target.tagName || '').toLowerCase();
    return tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;
  }
  function openMenu(key) {
    var d = document.querySelector('#detail details.act[data-key="' + key + '"]');
    if (!d) { return; }
    closeMenus();
    d.setAttribute('open', '');
    var first = d.querySelector('select, button, textarea');
    if (first) { first.focus(); }
  }
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      closeMenus();
      body.classList.remove('filters-open');
      if (narrow.matches) { body.classList.remove('sheet-open'); }
      return;
    }
    if (typing(e) || e.ctrlKey || e.metaKey || e.altKey) { return; }
    var list = rows();
    var cur = current();
    var i = cur ? list.indexOf(cur) : -1;
    var target = null;
    switch (e.key) {
      case 'j': target = list[Math.min(list.length - 1, i + 1)]; break;
      case 'k': target = list[Math.max(0, i - 1)]; break;
      case 'Enter':
        if (cur && document.activeElement === document.body) { e.preventDefault(); show(cur, true, true); }
        return;
      case 'x':
        if (cur) {
          var box = cur.querySelector('input[type="checkbox"]');
          box.checked = !box.checked;
          updateBulk();
        }
        return;
      case 'e': case 'r': case 'o': {
        var b = document.querySelector('#detail [data-key="' + e.key + '"]');
        if (b) { e.preventDefault(); b.click(); }
        return;
      }
      case 's': case 'i':
        e.preventDefault();
        openMenu(e.key);
        return;
      default: return;
    }
    if (target && target !== cur) {
      e.preventDefault();
      show(target, true, false);
    }
  });
  window.addEventListener('popstate', function () {
    var sel = new URLSearchParams(location.search).get('sel');
    var row = rows().filter(function (r) {
      return new URL(r.getAttribute('data-href'), location.href).searchParams.get('sel') === sel;
    })[0];
    if (row) { show(row, false, narrow.matches); } else { body.classList.remove('sheet-open'); }
  });
  updateBulk();
}());
