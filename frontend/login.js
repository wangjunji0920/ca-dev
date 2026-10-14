/* 登录页逻辑（从 login.html 的内联脚本抽出）。
   原因同上：CSP 不允许内联脚本。 */
(function () {
  'use strict';
  var $ = function (s) { return document.querySelector(s); };
  var form = $('#loginForm'), btn = $('#loginBtn'), errBox = $('#loginError');

  /* 诊断信息：出问题时让用户一眼看到到底缺什么，而不是静默卡住 */
  function diagText(extra) {
    var bits = [
      '地址 ' + location.origin,
      '安全上下文 ' + (window.isSecureContext ? '是' : '否'),
      'nacl ' + (window.nacl ? 'OK' : '缺失'),
      'CASecure ' + (window.CASecure ? 'OK' : '缺失')
    ];
    return (extra ? extra + '\n' : '') + bits.join(' · ');
  }
  function probeHealth() {
    return fetch('/api/health', { cache: 'no-store' })
      .then(function (r) { return 'HTTP ' + r.status; })
      .catch(function (e) { return '不可达(' + ((e && e.message) || e) + ')'; });
  }
  /* 自检：把关键环节的结果直接显示在页面上，用户不用会开 F12 也能反馈问题 */
  function selfCheck() {
    var lines = [diagText('')];
    var tasks = [
      ['GET /api/handshake', fetch('/api/handshake', { cache: 'no-store' })
        .then(function (r) { return r.text().then(function (t) {
          return 'HTTP ' + r.status + ' ' + t.slice(0, 80); }); })
        .catch(function (e) { return '失败: ' + ((e && e.message) || e); })],
      ['GET /api/health', fetch('/api/health', { cache: 'no-store' })
        .then(function (r) { return 'HTTP ' + r.status; })
        .catch(function (e) { return '失败: ' + ((e && e.message) || e); })],
      ['加密模块 crypto.js', Promise.resolve(
        hasChannel ? (window.nacl ? 'nacl + CASecure 均已加载' : 'CASecure 有但 nacl 缺失') : '未加载')],
      ['建立信道', hasChannel ? window.CASecure.handshake()
        .then(function () { return '成功，指纹 ' + ((window.CASecure.info() || {}).fingerprint || '?'); })
        .catch(function (e) { return '失败: ' + ((e && e.message) || e); }) : Promise.resolve('跳过')]
    ];
    showError('正在自检…');
    Promise.all(tasks.map(function (t) { return t[1]; })).then(function (vals) {
      for (var i = 0; i < tasks.length; i++) { lines.push(tasks[i][0] + ' → ' + vals[i]); }
      showError(lines.join('\n'));
    });
  }
  var scBtn = document.getElementById('selfCheckBtn');
  if (scBtn) scBtn.addEventListener('click', function (e) { e.preventDefault(); selfCheck(); });

  /* 页面脚本一旦报错就显示出来（例如被 CSP 拦掉、文件 404） */
  window.addEventListener('error', function (e) {
    if (errBox && errBox.hidden) {
      showError('页面脚本错误：' + ((e && (e.message || e.type)) || '未知') +
                '\n请按 F12 打开控制台查看详情');
    }
  });

  function showError(msg) {
    errBox.textContent = msg;
    errBox.hidden = false;
  }

  $('#themeToggle').addEventListener('click', function (e) {
    e.preventDefault();
    var dark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('ca_theme', dark ? 'dark' : 'light'); } catch (err) {}
  });

  /* ---------------- 加密信道 ---------------- */
  var hasChannel = !!(window.CASecure && typeof window.CASecure.rpc === 'function');

  function paintSecurity() {
    var dot = $('#secDot'), text = $('#secText'), fp = $('#secFingerprint'), reset = $('#secReset');
    if (!hasChannel) {
      dot.className = 'dot bad';
      text.textContent = '未加载加密模块（crypto.js），将使用明文会话';
      fp.textContent = '不可用';
      return Promise.resolve(false);
    }
    dot.className = 'dot';
    text.textContent = '正在建立加密信道…';
    /* 关键：不能无限期等待。曾经因为页面内联脚本被 CSP 拦掉，
       页面永远停在这句话上、点登录也没反应，用户完全无从判断。 */
    var timeout = new Promise(function (_ok, bad) {
      setTimeout(function () { bad(new Error('建立加密信道超时（8 秒）')); }, 8000);
    });
    return Promise.race([window.CASecure.handshake(), timeout]).then(function () {
      var f = (window.CASecure.info && window.CASecure.info().fingerprint) || '';
      dot.className = 'dot ok';
      text.textContent = '加密信道已建立';
      /* 传输安全：非本机 + 明文时服务端不会下发会话凭据（明文 cookie 可被嗅探后
         用于接管管理权限）→ 登录后进不了管理界面。提前说明，别让用户白试。 */
      try {
        var info = (window.CASecure.info && window.CASecure.info()) || {};
        var h = location.hostname;
        var isLocal = h === '127.0.0.1' || h === '::1' || h === 'localhost';
        if (info.tls === false && !isLocal) {
          dot.className = 'dot bad';
          text.textContent = '当前为非加密传输且非本机访问';
          showError('安全限制：你正通过明文 HTTP 从非本机地址访问。\n' +
            '服务端不会下发会话凭据（明文 cookie 可被嗅探后接管管理权限），' +
            '因此登录后无法进入管理界面。\n' +
            '请改用 SSH 隧道：ssh -L 9443:127.0.0.1:9443 <服务器>，' +
            '然后访问 http://127.0.0.1:9443/ ；或在服务器上启用 TLS（CA_TLS=on）。');
          return false;
        }
      } catch (e) {}
      fp.textContent = f ? (f.slice(0, 16) + '…' + f.slice(-8)) : '未知';
      fp.title = f;
      reset.hidden = false;
      return true;
    }).catch(function (err) {
      dot.className = 'dot bad';
      text.textContent = '加密信道建立失败';
      fp.textContent = '未建立';
      showError((err && err.message) || '无法建立加密信道');
      if (err && err.fingerprint) reset.hidden = false;
      /* 附上诊断：是否是 CSP 拦了脚本 / 接口不可达 / 模块没加载 */
      probeHealth().then(function (h) {
        showError(((err && err.message) || '无法建立加密信道') + '\n' +
                  diagText('后端健康检查 ' + h));
      });
      return false;
    });
  }

  $('#secReset').addEventListener('click', function () {
    if (!hasChannel) return;
    window.CASecure.resetPin();
    location.reload();
  });

  paintSecurity();

  /* 已登录则直接进入主应用 */
  function probeSession() {
    if (hasChannel) return window.CASecure.me().then(function (me) { return me && me.username; }).catch(function () { return null; });
    return fetch('/api/me', { credentials: 'same-origin', headers: { Accept: 'application/json' } })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (me) { return me && me.username; })
      .catch(function () { return null; });
  }
  probeSession().then(function (user) { if (user) location.replace('index.html'); });

  function doLogin(username, password) {
    if (hasChannel) {
      return window.CASecure.login(username, password).then(function () { return { ok: true }; })
        .catch(function (err) { return { ok: false, status: err && err.status, error: (err && err.message) || '登录失败' }; });
    }
    return fetch('/api/login', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ username: username, password: password })
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (data) {
        if (r.ok) return { ok: true };
        return { ok: false, status: r.status, error: data.error || ('登录失败（HTTP ' + r.status + '）') };
      });
    }).catch(function () { return { ok: false, error: '无法连接服务器，请确认后端服务已启动。' }; });
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    errBox.hidden = true;
    var username = $('#username').value.trim();
    var password = $('#password').value;
    if (!username) { showError('请输入用户名'); $('#username').focus(); return; }
    if (!password) { showError('请输入密码'); $('#password').focus(); return; }

    btn.disabled = true;
    btn.classList.add('is-loading');
    btn.textContent = '登录中…';

    var ready = hasChannel ? window.CASecure.handshake().catch(function () { return null; }) : Promise.resolve();
    /* 必须有超时：否则信道/网络一旦不返回，按钮会永远停在“登录中…”，
       用户只看到“点了没反应”，完全无从判断。 */
    var timeout = new Promise(function (_ok, bad) {
      setTimeout(function () { bad(new Error('登录请求超时（15 秒未收到响应）')); }, 15000);
    });
    Promise.race([ready.then(function () { return doLogin(username, password); }), timeout])
      .then(function (res) {
        if (res.ok) { location.replace('index.html'); return; }
        showError(res.error || '登录失败');
      })
      .catch(function (err) {
        showError(((err && err.message) || '登录失败'));
        probeHealth().then(function (h) { showError(((err && err.message) || '登录失败') +
          '\n' + diagText('后端健康检查 ' + h)); });
      })
      .finally(function () {
      btn.disabled = false;
      btn.classList.remove('is-loading');
      btn.textContent = '登录';
    });
  });
})();
