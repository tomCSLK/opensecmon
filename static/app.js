// Small helpers of the page frame (templates/app.html); every page works without them.
// - The light/dark button stores the choice (theme.js applies it before the page paints).
// - "/" focuses the search, Escape closes an open menu, a click outside closes it as well.
(function () {
  'use strict';
  var T = window.opensecmonText;
  var html = document.documentElement;
  var KEY = 'opensecmon-theme';

  function isDark() {
    var chosen = html.getAttribute('data-theme');
    if (chosen) { return chosen === 'dark'; }
    return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
  }
  function label(button) {
    var text = isDark() ? T('theme-to-light') : T('theme-to-dark');
    button.setAttribute('aria-label', text);
    button.title = text;
  }
  var toggles = document.querySelectorAll('[data-theme-toggle]');
  Array.prototype.forEach.call(toggles, function (button) {
    label(button);
    button.addEventListener('click', function () {
      var next = isDark() ? 'light' : 'dark';
      html.setAttribute('data-theme', next);
      try { localStorage.setItem(KEY, next); } catch (e) { /* storage blocked: only this page */ }
      Array.prototype.forEach.call(toggles, label);
    });
  });

  var search = document.getElementById('gsearch');
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') {
      Array.prototype.forEach.call(document.querySelectorAll('details.menu[open], details.chipmenu[open]'), function (menu) {
        menu.removeAttribute('open');
        menu.querySelector('summary').focus();
      });
      return;
    }
    if (e.key !== '/' || !search || e.ctrlKey || e.metaKey || e.altKey) { return; }
    var tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) { return; }
    e.preventDefault();
    search.focus();
  });
  document.addEventListener('click', function (e) {
    Array.prototype.forEach.call(document.querySelectorAll('details.menu[open], details.chipmenu[open]'), function (menu) {
      if (!menu.contains(e.target)) { menu.removeAttribute('open'); }
    });
  });
})();
