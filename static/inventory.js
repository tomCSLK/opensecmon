// Import of assets (templates/hosts.html, host_setup.html, csv_import.html):
// - boxes with [data-copy-box] get a button that copies their text;
// - buttons with [data-busy] show that a reading runs (it can take up to a minute) and cannot be pressed twice;
// - the CSV page reads a chosen or dropped file into the text field (the server only ever gets the text).
// Without this script the text can be selected by hand, and the CSV text can be pasted.
(function () {
  'use strict';
  var T = window.opensecmonText;
  var SVG = 'http://www.w3.org/2000/svg';

  function icon(name) {
    var svg = document.createElementNS(SVG, 'svg');
    svg.setAttribute('class', 'ico');
    svg.setAttribute('aria-hidden', 'true');
    svg.setAttribute('focusable', 'false');
    var use = document.createElementNS(SVG, 'use');
    use.setAttribute('href', '#i-' + name);
    svg.appendChild(use);
    return svg;
  }

  // ---- Copy ----
  Array.prototype.forEach.call(document.querySelectorAll('[data-copy-box]'), function (box) {
    if (!navigator.clipboard) { return; }
    var text = box.textContent;
    var b = document.createElement('button');
    b.type = 'button';
    b.className = 'iconbtn';
    b.setAttribute('aria-label', T('copy'));
    b.title = T('copy');
    b.appendChild(icon('copy'));
    b.addEventListener('click', function () {
      navigator.clipboard.writeText(text).then(function () {
        b.title = T('copied');
        b.setAttribute('aria-label', T('copied'));
        b.replaceChild(icon('check'), b.firstChild);
        window.setTimeout(function () {
          b.title = T('copy');
          b.setAttribute('aria-label', T('copy'));
          b.replaceChild(icon('copy'), b.firstChild);
        }, 1500);
      });
    });
    box.appendChild(b);
  });

  // ---- Busy ----
  document.addEventListener('submit', function (e) {
    var b = e.submitter;
    if (!b || !b.hasAttribute('data-busy')) { return; }
    if (b.getAttribute('aria-disabled') === 'true') { e.preventDefault(); return; }
    b.setAttribute('aria-disabled', 'true');
    b.classList.add('busy');
    var label = document.createElement('span');
    label.textContent = T('reading');
    while (b.firstChild) { b.removeChild(b.firstChild); }
    b.appendChild(icon('refresh'));
    b.appendChild(label);
  });

  // ---- CSV file ----
  var area = document.getElementById('csvText');
  var pick = document.getElementById('csvFile');
  var zone = document.querySelector('[data-dropzone]');
  if (!area || !pick || !zone) { return; }
  var status = document.getElementById('csvFileStatus');
  zone.hidden = false;
  function load(file) {
    if (!file) { return; }
    if (file.size > Number(zone.getAttribute('data-max'))) {
      status.textContent = T('csv-too-large');
      return;
    }
    var reader = new FileReader();
    reader.onload = function () {
      area.value = String(reader.result);
      status.textContent = T('csv-loaded').replace('%1', file.name);
    };
    reader.readAsText(file, 'utf-8');
  }
  pick.addEventListener('change', function () { load(pick.files[0]); });
  zone.addEventListener('dragover', function (e) { e.preventDefault(); zone.classList.add('over'); });
  zone.addEventListener('dragleave', function () { zone.classList.remove('over'); });
  zone.addEventListener('drop', function (e) {
    e.preventDefault();
    zone.classList.remove('over');
    if (e.dataTransfer && e.dataTransfer.files.length) { load(e.dataTransfer.files[0]); }
  });
}());
