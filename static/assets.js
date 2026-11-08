// "Assets" (templates/assets.html, asset_form.html): folds the host groups of the list; in the form it shows
// only the fields of the chosen kind, offers suggestions while typing (/assets/suggest, JSON) and refreshes
// the preview of the matches (/assets/preview, an HTML fragment rendered and escaped by the server). Without
// this script every row and field is shown and the button "Preview" renders the page again.
(function () {
  'use strict';

  // ---- List: fold the groups ----
  Array.prototype.forEach.call(document.querySelectorAll('button.tw[data-grp]'), function (b) {
    b.hidden = false;
  });
  document.addEventListener('click', function (e) {
    var b = e.target.closest('button.tw[data-grp]');
    if (!b) { return; }
    var open = b.getAttribute('aria-expanded') === 'true';
    b.setAttribute('aria-expanded', String(!open));
    Array.prototype.forEach.call(document.querySelectorAll('tr.sub[data-grp="' + b.getAttribute('data-grp') + '"]'), function (r) {
      r.hidden = open;
    });
  });

  // ---- Form ----
  var form = document.querySelector('form[data-asset-form]');
  if (!form) { return; }

  function kind() {
    var checked = form.querySelector('input[name="kind"]:checked');
    return checked ? checked.value : 'software';
  }
  function showKind() {
    var k = kind();
    Array.prototype.forEach.call(form.querySelectorAll('fieldset.fields[data-for]'), function (fs) {
      fs.hidden = fs.getAttribute('data-for').split(' ').indexOf(k) < 0;
    });
  }
  showKind();

  // ---- Preview ----
  var prev = document.getElementById('aPrev');
  var prevButton = form.querySelector('[data-preview-button]');
  if (prevButton) { prevButton.hidden = true; }
  var timer = null;
  var asked = 0;
  function previewQuery() {
    var data = new FormData(form);
    var params = new URLSearchParams();
    data.forEach(function (value, key) {
      if (key !== 'csrf_token' && key !== 'action' && typeof value === 'string') { params.append(key, value); }
    });
    return params.toString();
  }
  function ready() {
    if (kind() === 'package') {
      return form.elements.package.value.trim() !== '' && form.elements.release.value.trim() !== '';
    }
    return form.elements.product_name.value.trim() !== '' || form.elements.cpe.value.trim() !== '';
  }
  function refresh() {
    if (!prev || !ready()) { return; }
    var mine = ++asked;
    fetch('/assets/preview?' + previewQuery(), { credentials: 'same-origin', headers: { 'Accept': 'text/html' } })
      .then(function (reply) {
        if (!reply.ok || reply.redirected) { throw new Error('preview'); }
        return reply.text();
      })
      .then(function (html) {
        if (mine !== asked) { return; }
        var doc = new DOMParser().parseFromString('<div>' + html + '</div>', 'text/html');
        var title = prev.querySelector('h2');
        prev.replaceChildren(title);
        Array.prototype.forEach.call(doc.body.firstChild.childNodes, function (n) {
          prev.appendChild(document.importNode(n, true));
        });
      })
      .catch(function () { if (prevButton) { prevButton.hidden = false; } });
  }
  function later() {
    clearTimeout(timer);
    timer = setTimeout(refresh, 400);
  }
  form.addEventListener('input', function (e) {
    if (e.target.name === 'note' || e.target.name === 'host') { return; }
    later();
  });
  form.addEventListener('change', function (e) {
    if (e.target.name === 'kind') { showKind(); }
    if (e.target.name !== 'note' && e.target.name !== 'host') { later(); }
  });

  // ---- Suggestions while typing ----
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function setup(input) {
    var list = document.getElementById(input.getAttribute('aria-controls'));
    if (!list) { return; }
    var field = input.getAttribute('data-suggest');
    var wait = null;
    var mine = 0;
    function close() {
      list.hidden = true;
      list.replaceChildren();
      input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant');
    }
    function pick(li) {
      input.value = li.getAttribute('data-v');
      close();
      input.dispatchEvent(new Event('input', { bubbles: true }));
      later();
    }
    function load() {
      var q = input.value.trim();
      var params = new URLSearchParams({ field: field, q: q });
      if (field === 'product') { params.set('vendor', form.elements.vendor_name.value.trim()); }
      if (field === 'package') {
        params.set('distro', form.elements.distro.value);
        params.set('release', form.elements.release.value.trim());
      }
      if (field === 'vendor' && q.length < 2) { close(); return; }
      if (field === 'package' && (q.length < 2 || !form.elements.release.value.trim())) { close(); return; }
      var ask = ++mine;
      fetch('/assets/suggest?' + params.toString(), { credentials: 'same-origin', headers: { 'Accept': 'application/json' } })
        .then(function (reply) {
          if (!reply.ok || reply.redirected) { throw new Error('suggest'); }
          return reply.json();
        })
        .then(function (items) {
          if (ask !== mine || document.activeElement !== input) { return; }
          if (!items.length) { close(); return; }
          var low = q.toLowerCase();
          list.innerHTML = items.map(function (it, i) {
            var name = esc(it.name);
            var at = low ? it.name.toLowerCase().indexOf(low) : -1;
            if (at >= 0) {
              name = esc(it.name.slice(0, at)) + '<mark>' + esc(it.name.slice(at, at + low.length)) + '</mark>' + esc(it.name.slice(at + low.length));
            }
            return '<li role="option" id="' + list.id + '-' + i + '" data-v="' + esc(it.name) + '" aria-selected="false"><span>' + name + '</span><span class="muted">' + esc(it.hint) + '</span></li>';
          }).join('');
          list.hidden = false;
          input.setAttribute('aria-expanded', 'true');
        })
        .catch(close);
    }
    input.addEventListener('input', function () {
      clearTimeout(wait);
      wait = setTimeout(load, 200);
    });
    input.addEventListener('focus', load);
    input.addEventListener('blur', function () { setTimeout(close, 150); });
    input.addEventListener('keydown', function (e) {
      if (list.hidden) { return; }
      var items = list.querySelectorAll('li');
      var current = list.querySelector('li[aria-selected="true"]');
      var index = Array.prototype.indexOf.call(items, current);
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        index = e.key === 'ArrowDown' ? Math.min(items.length - 1, index + 1) : Math.max(0, index - 1);
        Array.prototype.forEach.call(items, function (li, i) { li.setAttribute('aria-selected', String(i === index)); });
        input.setAttribute('aria-activedescendant', items[index].id);
        items[index].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Enter' && current) {
        e.preventDefault();
        pick(current);
      } else if (e.key === 'Escape') {
        e.preventDefault();
        close();
      }
    });
    list.addEventListener('mousedown', function (e) {
      var li = e.target.closest('li[data-v]');
      if (li) { e.preventDefault(); pick(li); }
    });
  }
  Array.prototype.forEach.call(form.querySelectorAll('input[data-suggest]'), setup);
}());
