// Translates English (or German) texts of a detail in the browser, on the device (Translator API, Chrome 138+).
// Nothing is sent to a server. The button (templates/translate_button.html) stays hidden unless the browser can
// translate from the language of the texts into the language of the page: CSS shows it under the class
// `can-translate-<from>` on <html>. Without the API the page stays as it is.
// The texts to translate carry `data-tr` and live in the same detail (#detail beside a list, or a page of its
// own); the translation goes right below each of them, the original stays. The inbox and the lists swap the
// detail without a reload, so clicks are handled for the whole document.
(function () {
  'use strict';
  var T = window.opensecmonText;
  var root = document.documentElement;
  var target = (root.getAttribute('lang') || '').toLowerCase();
  if (!('Translator' in self) || !target) { return; }
  // The languages of the interface; a text in one of them can be translated into the other.
  var SOURCES = ['en', 'de'];
  var translators = {};

  SOURCES.forEach(function (from) {
    if (from === target) { return; }
    try {
      self.Translator.availability({ sourceLanguage: from, targetLanguage: target }).then(function (state) {
        if (state && state !== 'unavailable') { root.classList.add('can-translate-' + from); }
      }, function () { /* not offered: leave the button hidden */ });
    } catch (e) { /* API present but not usable here */ }
  });

  // One translator per language pair for the whole page; creating it may download the model (needs the click).
  function translator(from, onProgress) {
    var key = from + '>' + target;
    if (!translators[key]) {
      translators[key] = self.Translator.create({
        sourceLanguage: from,
        targetLanguage: target,
        monitor: function (m) {
          m.addEventListener('downloadprogress', function (e) { onProgress(e.loaded); });
        }
      });
      translators[key].catch(function () { delete translators[key]; });
    }
    return translators[key];
  }

  // Line by line, so the line breaks of the original survive.
  function translateText(tr, text) {
    var lines = text.split('\n');
    var done = Promise.resolve();
    var out = [];
    lines.forEach(function (line, i) {
      done = done.then(function () {
        if (!line.trim()) { out[i] = line; return null; }
        return tr.translate(line).then(function (r) { out[i] = r; });
      });
    });
    return done.then(function () { return out.join('\n'); });
  }

  function run(line) {
    var btn = line.querySelector('.trbtn');
    var status = line.querySelector('.trstatus');
    var from = line.getAttribute('data-tr-from');
    var scope = line.closest('#detail, .detailpage') || document;
    var items = Array.prototype.filter.call(scope.querySelectorAll('[data-tr]'), function (el) {
      return !el.hasAttribute('data-tr-done') && (el.getAttribute('lang') || '').toLowerCase() === from;
    });
    if (!items.length) { line.remove(); return; }
    btn.disabled = true;
    status.textContent = T('translate-busy');
    translator(from, function (loaded) {
      status.textContent = T('translate-download', Math.round((loaded || 0) * 100));
    }).then(function (tr) {
      status.textContent = T('translate-busy');
      var chain = Promise.resolve();
      items.forEach(function (el) {
        chain = chain.then(function () {
          return translateText(tr, el.textContent.trim()).then(function (text) {
            var p = document.createElement('p');
            p.className = 'trout' + (el.classList.contains('prewrap') ? ' prewrap' : '');
            p.setAttribute('lang', target);
            p.textContent = text;
            el.setAttribute('data-tr-done', '');
            el.insertAdjacentElement('afterend', p);
          });
        });
      });
      return chain;
    }).then(function () {
      btn.remove();
      status.textContent = T('translate-done');
    }, function () {
      btn.disabled = false;
      status.textContent = T('translate-failed');
    });
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest ? e.target.closest('.trbtn') : null;
    if (!btn || btn.disabled) { return; }
    var line = btn.closest('.trline');
    if (line) { e.preventDefault(); run(line); }
  });
})();
