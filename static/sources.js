// "Sources" (templates/sources.html): opens and closes the details rows, submits the on/off switch right
// away, and while a source runs refreshes the table every few seconds (the server marks the table with
// data-live while something runs). Without this script every form has its own button.
(function () {
  'use strict';
  var table = document.getElementById('srctable');
  if (!table) { return; }

  function openRows() {
    var ids = [];
    Array.prototype.forEach.call(document.querySelectorAll('[data-more][aria-expanded="true"]'), function (b) {
      ids.push(b.getAttribute('data-more'));
    });
    return ids;
  }
  function setOpen(button, open) {
    button.setAttribute('aria-expanded', String(open));
    var row = document.getElementById('more-' + button.getAttribute('data-more'));
    if (!row) { return; }
    if (open) { row.removeAttribute('data-closed'); } else { row.setAttribute('data-closed', ''); }
  }

  document.addEventListener('click', function (e) {
    var b = e.target.closest('[data-more]');
    if (b) { setOpen(b, b.getAttribute('aria-expanded') !== 'true'); }
  });
  document.addEventListener('change', function (e) {
    var input = e.target.closest('[data-autosubmit]');
    if (input && input.form) { input.form.submit(); }
  });

  function refresh() {
    var current = document.getElementById('srctable');
    if (!current || !current.hasAttribute('data-live')) { return; }
    var seconds = Number(current.getAttribute('data-live')) || 5;
    setTimeout(function () {
      var active = document.activeElement;
      if (active && active.closest && active.closest('#srctable') && /^(SELECT|INPUT)$/.test(active.tagName)) {
        refresh();
        return;
      }
      fetch(location.pathname, { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
        .then(function (reply) {
          if (!reply.ok || reply.redirected) { throw new Error('stop'); }
          return reply.text();
        })
        .then(function (html) {
          var doc = new DOMParser().parseFromString(html, 'text/html');
          var fresh = doc.getElementById('srctable');
          var now = document.getElementById('srctable');
          if (!fresh || !now) { return; }
          var open = openRows();
          now.innerHTML = fresh.innerHTML;
          if (fresh.hasAttribute('data-live')) {
            now.setAttribute('data-live', fresh.getAttribute('data-live'));
          } else {
            now.removeAttribute('data-live');
          }
          Array.prototype.forEach.call(now.querySelectorAll('[data-more]'), function (b) {
            if (open.indexOf(b.getAttribute('data-more')) >= 0) { setOpen(b, true); }
          });
          if (window.opensecmonTimes) { window.opensecmonTimes(now); }
          refresh();
        })
        .catch(function () { /* signed out or offline: stop refreshing */ });
    }, seconds * 1000);
  }
  refresh();
})();
