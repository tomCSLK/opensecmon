// Shows the timestamps the server renders as <time class="ts" datetime="...Z"> in the browser's time zone,
// 24-hour clock, date order of the page's language. The UTC text from the server stays as tooltip (and as
// the fallback without JS).
(function () {
  'use strict';
  var T = window.opensecmonText;
  function two(n) { return (n < 10 ? '0' : '') + n; }
  function day(d) {
    return T('date').replace('DD', two(d.getDate())).replace('MM', two(d.getMonth() + 1)).replace('YYYY', d.getFullYear());
  }
  function local(d) {
    return day(d) + ' ' + two(d.getHours()) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds());
  }
  // class "short": only the time of day for today, otherwise date and time without seconds.
  function short(d) {
    var hm = two(d.getHours()) + ':' + two(d.getMinutes());
    return day(d) === day(new Date()) ? hm : day(d) + ' ' + hm;
  }
  function apply(root) {
    var times = root.querySelectorAll('time.ts:not([data-local])');
    for (var i = 0; i < times.length; i++) {
      var el = times[i];
      var d = new Date(el.getAttribute('datetime'));
      if (isNaN(d.getTime())) { continue; }
      el.title = el.textContent;
      el.textContent = el.classList.contains('short') ? short(d) : local(d);
      el.setAttribute('data-local', '');
    }
  }
  apply(document);
  // For parts of a page that a script replaced (static/sources.js).
  window.opensecmonTimes = apply;
})();
