(function () {
  'use strict';

  var form = document.getElementById('captcha');
  if (!form) return;

  var widgets = form.querySelectorAll('.widget');
  var primary = null;
  for (var i = 0; i < widgets.length; i++) {
    if (widgets[i].getAttribute('data-primary') === '1') primary = widgets[i];
  }
  if (!primary) primary = widgets[0];
  if (!primary) return;

  var kind = primary.getAttribute('data-kind');
  var data = {};
  try { data = JSON.parse(primary.querySelector('.challenge').textContent); } catch (e) {}

  function hex(buf) {
    var out = '', view = new Uint8Array(buf);
    for (var i = 0; i < view.length; i++) out += (view[i] < 16 ? '0' : '') + view[i].toString(16);
    return out;
  }

  function gpuClass() {
    try {
      var c = document.createElement('canvas');
      var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
      if (!gl) return 'none';
      var ext = gl.getExtension('WEBGL_debug_renderer_info');
      var r = ext ? String(gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)) : '';
      if (/swiftshader|llvmpipe|software|mesa offscreen/i.test(r)) return 'sw';
      return 'hw';
    } catch (e) { return 'none'; }
  }

  function canvasHash() {
    try {
      var c = document.createElement('canvas');
      c.width = 200; c.height = 40;
      var x = c.getContext('2d');
      x.textBaseline = 'top'; x.font = '16px Arial';
      x.fillStyle = '#f60'; x.fillRect(10, 5, 60, 20);
      x.fillStyle = '#069'; x.fillText('waf-captcha', 2, 15);
      return c.toDataURL();
    } catch (e) { return ''; }
  }

  function vector() {
    var n = navigator, s = screen, uad = n.userAgentData || {};
    return [
      n.webdriver ? 'wd' : '',
      (uad.brands || []).map(function (b) { return b.brand + b.version; }).join('|'),
      uad.platform || n.platform || '',
      uad.mobile ? 'm' : '',
      (n.languages || [n.language]).join(','),
      String(new Date().getTimezoneOffset()),
      (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || '',
      s.width + 'x' + s.height + '@' + (window.devicePixelRatio || 1) + '/' + s.colorDepth,
      String(n.maxTouchPoints || 0),
      String(n.hardwareConcurrency || 0),
      String(n.deviceMemory || 0),
      gpuClass(),
      form.getAttribute('data-canvas') === '1' ? canvasHash() : ''
    ].join('\n');
  }

  function fingerprint(done) {
    if (form.getAttribute('data-collect') !== '1' || !window.crypto || !crypto.subtle) return done('');
    var bytes = new TextEncoder().encode(vector());
    crypto.subtle.digest('SHA-256', bytes).then(function (h) {
      done(hex(h).slice(0, 32));
    }, function () { done(''); });
  }

  function wireManual(widget) {
    var input = widget.querySelector('input[type=text]');
    if (!input) return;
    form.addEventListener('submit', function () {
      form.querySelector('#provider').value = widget.getAttribute('data-kind');
      form.querySelector('#answer').value = input.value;
    });
  }

  var EXT = {
    turnstile: {
      src: 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit',
      ready: function () { return window.turnstile; },
      render: function (el, sitekey, done) {
        window.turnstile.render(el, { sitekey: sitekey, callback: done });
      }
    },
    recaptcha: {
      src: function (d) {
        return d.version === 'v3'
          ? 'https://www.google.com/recaptcha/api.js?render=' + encodeURIComponent(d.sitekey)
          : 'https://www.google.com/recaptcha/api.js?render=explicit';
      },
      ready: function () { return window.grecaptcha && window.grecaptcha.ready; },
      render: function (el, sitekey, done, d) {
        window.grecaptcha.ready(function () {
          if (d.version === 'v3') {
            window.grecaptcha.execute(sitekey, { action: 'waf' }).then(done);
          } else {
            window.grecaptcha.render(el, { sitekey: sitekey, callback: done });
          }
        });
      }
    },
    hcaptcha: {
      src: 'https://js.hcaptcha.com/1/api.js?render=explicit',
      ready: function () { return window.hcaptcha; },
      render: function (el, sitekey, done) {
        window.hcaptcha.render(el, { sitekey: sitekey, callback: done });
      }
    },
    smartcaptcha: {
      src: 'https://smartcaptcha.yandexcloud.net/captcha.js?render=onload&onload=__wafSmart',
      ready: function () { return window.smartCaptcha; },
      render: function (el, sitekey, done) {
        var id = window.smartCaptcha.render(el, { sitekey: sitekey, callback: done });
        void id;
      }
    }
  };

  function loadExternal(widget, kind, d) {
    var spec = EXT[kind];
    if (!spec) { showFallback(); return; }
    var el = widget.querySelector('.ext');
    var wait = widget.querySelector('.ext-wait');
    var timer = setTimeout(fail, 8000);
    var failed = false;

    function fail() {
      if (failed) return;
      failed = true;
      clearTimeout(timer);
      showFallback();
    }

    function done(token) {
      clearTimeout(timer);
      form.querySelector('#provider').value = kind;
      form.querySelector('#answer').value = token;
      fingerprint(function (fp) {
        form.querySelector('#fp').value = fp;
        form.submit();
      });
    }

    function render() {
      if (wait) wait.hidden = true;
      try { spec.render(el, d.sitekey, done, d); } catch (e) { fail(); }
    }

    window.__wafSmart = render;

    var s = document.createElement('script');
    s.src = typeof spec.src === 'function' ? spec.src(d) : spec.src;
    s.async = true;
    s.onerror = fail;
    s.onload = function () {
      if (kind === 'smartcaptcha') return;
      var tries = 0;
      (function poll() {
        if (spec.ready()) { render(); return; }
        if (++tries > 50) { fail(); return; }
        setTimeout(poll, 100);
      })();
    };
    document.head.appendChild(s);
  }

  function wireImage(widget) {
    var link = widget.querySelector('a[href=""]');
    if (link) link.addEventListener('click', function (e) {
      e.preventDefault();
      location.reload();
    });
    wireManual(widget);
  }

  function start(widget) {
    var k = widget.getAttribute('data-kind');
    var d = {};
    try { d = JSON.parse(widget.querySelector('.challenge').textContent); } catch (e) {}
    form.querySelector('#provider').value = k;

    if (k === 'image') {
      wireImage(widget);
      fingerprint(function (fp) { form.querySelector('#fp').value = fp; });
    } else {
      loadExternal(widget, k, d);
    }
  }

  function showFallback() {
    var list = [].slice.call(widgets);
    var i = list.indexOf(primary);
    if (i < 0 || i + 1 >= list.length) {
      var text = primary.querySelector('.ext-wait');
      if (text) text.textContent = 'The check is unavailable. Go back to the site and try again later.';
      return;
    }
    primary.hidden = true;
    primary = list[i + 1];
    primary.hidden = false;
    start(primary);
  }

  start(primary);
})();
