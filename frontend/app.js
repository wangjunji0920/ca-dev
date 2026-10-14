/* ==========================================================================
 * CA 证书管理系统 — 前端应用逻辑（纯原生 ES2020+，无构建步骤、无外部依赖）
 * ==========================================================================
 * 文件：frontend/app.js    配套：index.html / login.html / style.css / favicon.svg
 *                          + vendor/tweetnacl.min.js 与 crypto.js（应用层加密信道）
 *
 * ## 传输层：应用层加密信道（默认）与明文 REST（兼容）
 * 后端默认把明文 REST（/api/xxx）限制为本机回环访问（CA_LEGACY_API=loopback），
 * 浏览器必须通过 crypto.js 暴露的 window.CASecure 走加密信道：
 *     GET  /api/handshake → 服务端 X25519 公钥与指纹（TOFU 固定）
 *     POST /api/handshake → 协商信道密钥
 *     POST /api/rpc       → 所有业务请求/响应在 NaCl 密文内（含登录，无 Cookie token）
 * 本文件对上层统一封装为 api()/apiForm()/downloadApi()：
 *   · window.CASecure 存在 → 加密信道（文件以 base64 放入信封）
 *   · 否则                → 同源 Cookie 会话的明文 REST（便于本机调试 / CA_LEGACY_API=on）
 * 两条路径语义一致，页面代码无需感知差异。
 *
 * ## 运行方式
 * 把 frontend/ 目录作为静态根交给后端（或任意静态服务器）即可，例如：
 *   GET /            → frontend/index.html    （主应用，SPA）
 *   GET /login.html  → frontend/login.html
 *   GET /api/...     → 后端 API（前缀 /api，同源、Cookie 会话）
 * 默认假设前端与 API 同源；若前端被挂在子路径下，把 API_BASE 改成相应前缀即可。
 *
 * ## 结构
 *   · 常量/工具      —— $, $$, esc, 时间与状态格式化, toast, download
 *   · api()          —— 统一请求封装：自动 JSON、自动 FormData、自动 401 跳登录、
 *                       自动中文错误 Toast、超时保护
 *   · state          —— 全局状态（会话、缓存、筛选、分页、导入暂存…）
 *   · router()       —— hash 路由 → renderXxx()，每页一个渲染函数
 *   · 事件           —— 顶层事件委托（data-act / data-route），不为每行绑监听器
 *
 * ## 与后端的契约（前缀 /api，除 login 外均需会话）
 *   认证  : POST /api/login · POST /api/logout · GET /api/me
 *   其它  : GET /api/health
 *   概览  : GET /api/overview
 *   CA    : GET /api/ca · GET /api/ca/list · POST /api/ca/import(multipart)
 *           POST /api/ca/activate · GET /api/ca/{id}/download?format=pem|der
 *   证书  : GET /api/certs · POST /api/certs/issue · POST /api/certs/issue/csr(multipart)
 *           POST /api/certs/issue/batch · GET /api/certs/{id} · PATCH /api/certs/{id}
 *           DELETE /api/certs/{id}?hard= · POST /api/certs/{id}/revoke
 *           POST /api/certs/{id}/unrevoke · POST /api/certs/{id}/renew
 *           GET /api/certs/{id}/download?format=pem|der|key|chain|p12&password=
 *           POST /api/certs/import(multipart) · POST /api/certs/import/dir
 *           POST /api/certs/import/csv · GET /api/certs/export?format=csv|json
 *   CRL   : GET /api/crl · POST /api/crl/generate · GET /api/crl/download?format=
 *           POST /api/crl/import(multipart)
 *   体检  : POST /api/consistency/check · POST /api/consistency/repair
 *   审计  : GET /api/audit
 *   设置  : GET/PATCH /api/settings · GET/POST /api/backup
 *           GET /api/backup/download · POST /api/backup/restore(multipart)
 *   模板  : GET /api/templates
 *   规则集: GET/POST /api/rulesets · GET /api/rulesets/meta · POST /api/rulesets/validate
 *           POST /api/rulesets/default · GET/PATCH/DELETE /api/rulesets/{id}
 *           POST /api/rulesets/{id}/duplicate · POST /api/rulesets/{id}/reset
 *   发布  : GET /api/publish/status · GET/POST /api/publish/targets
 *           PATCH/DELETE /api/publish/targets/{id} · POST /api/publish/targets/{id}/test
 *           POST /api/publish/now · POST /api/publish/auto · GET /api/publish/log
 *   自动化: GET /api/automation/meta · GET/POST /api/automation/tasks
 *           PATCH/DELETE /api/automation/tasks/{id} · POST /api/automation/tasks/{id}/run
 *           POST /api/automation/presets · GET /api/automation/log
 *   strong : GET /api/strongswan/status · GET /api/strongswan/snippet
 *           GET /api/strongswan/sync-script · GET /api/certs/{id}/vpn-bundle
 *   错误  : 非 2xx + {"error":"中文错误信息"}；401 → {"error":"unauthorized"} 跳登录
 *
 * ## 契约未覆盖、前端自行决定的假设（详见交付说明）
 *   1) 未认证时 index.html 会先探测 GET /api/me，401 即跳 login.html。
 *   2) GET /api/overview.ca 为 null，或 ca.has_key === false → 全站显示醒目提示；
 *      由于契约未给出 ca_ready 在 overview 中的位置，额外使用 GET /api/health.ca_ready
 *      作为兜底判断（health 失败不影响页面）。
 *   3) 证书详情页的「扩展」中 BasicConstraints / SKI / AKI / CRL 分发点在 Cert 对象里
 *      没有对应字段，因此只展示已有字段（key_usage/eku/sans/…），并在 UI 上标注
 *      「未由接口返回」；不做任何猜测性渲染。
 *   4) 批量签发走 POST /api/certs/issue/batch {rows, dry_run}：dry_run=true 作为
 *      「预检」；CSV→JSON 的列映射在前端完成（详见 batchRowsFromCsv）。
 *   5) PDF/详情中的“签发者”筛选、排序字段名按 cns/not_after/serial_hex 等直接传给
 *      GET /api/certs 的 sort 参数，后端若使用不同字段名只需改 SORT_MAP。
 *   6) 导入目录方式的「预检」使用 dry_run=true 调用 POST /api/certs/import/dir，
 *      再把预检结果用于确认提示；确认时以 dry_run=false 再次调用（非幂等提示）。
 *   7) 删除证书按钮仅在 archived 状态显示，避免误删有效证书。
 *   8) CSV 解析为简易实现（支持双引号包裹与 "" 转义），不支持自定义分隔符。
 * ========================================================================== */
(function () {
  'use strict';

  /* ====================================================================== */
  /* 1. 常量与基础工具                                                       */
  /* ====================================================================== */

  var API_BASE = '';            // 与 /api 同源；部署在子路径时可改为 '/ca'
  var PAGE_SIZES = [20, 50, 100];
  var AUTO_REFRESH_MS = 5 * 60 * 1000;

  var STATUS_TEXT = { valid: '有效', revoked: '已吊销', expired: '已过期', archived: '已归档' };
  var STATUS_CLASS = { valid: 'badge-valid', revoked: 'badge-revoked', expired: 'badge-expired', archived: 'badge-archived' };

  var REVOKE_REASONS = [
    'unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged',
    'superseded', 'cessationOfOperation', 'certificateHold', 'privilegeWithdrawn'
  ];
  var REVOKE_REASON_TEXT = {
    unspecified: 'unspecified（未指定）',
    keyCompromise: 'keyCompromise（密钥泄露）',
    cACompromise: 'cACompromise（CA 泄露）',
    affiliationChanged: 'affiliationChanged（隶属关系变更）',
    superseded: 'superseded（已被取代）',
    cessationOfOperation: 'cessationOfOperation（停止使用）',
    certificateHold: 'certificateHold（证书挂起）',
    privilegeWithdrawn: 'privilegeWithdrawn（权限撤销）'
  };

  var KU_ALL = [
    ['digitalSignature', '数字签名'],
    ['nonRepudiation', '不可否认'],
    ['keyEncipherment', '密钥加密'],
    ['dataEncipherment', '数据加密'],
    ['keyAgreement', '密钥协商'],
    ['keyCertSign', '签发证书'],
    ['cRLSign', '签发 CRL'],
    ['encipherOnly', '仅加密'],
    ['decipherOnly', '仅解密']
  ];
  var EKU_ALL = [
    ['serverAuth', 'TLS 服务器认证'],
    ['clientAuth', 'TLS 客户端认证'],
    ['codeSigning', '代码签名'],
    ['emailProtection', '邮件保护'],
    ['timeStamping', '时间戳'],
    ['ocspSigning', 'OCSP 签名'],
    ['ipsecIKE', 'IPSec IKE'],
    ['msSmartcardLogin', '智能卡登录']
  ];
  var KU_TEXT = {}; KU_ALL.forEach(function (p) { KU_TEXT[p[0]] = p[1]; });
  var EKU_TEXT = {}; EKU_ALL.forEach(function (p) { EKU_TEXT[p[0]] = p[1]; });
  var SAN_TYPES = ['DNS', 'IP', 'Email', 'UPN', 'URI'];
  var KEY_SIZE_OPTIONS = {
    rsa: [['2048', 'RSA 2048'], ['3072', 'RSA 3072'], ['4096', 'RSA 4096']],
    ec: [['256', 'EC P-256'], ['384', 'EC P-384']]
  };
  var FALLBACK_TEMPLATES = [
    { id: 'server', name: 'TLS 服务器证书', description: '用于 Web/API 服务端 TLS', key_usage: ['digitalSignature', 'keyEncipherment'], eku: ['serverAuth'], validity_days: 397, builtin: true },
    { id: 'client', name: 'TLS 客户端证书', description: '用于双向 TLS 客户端身份', key_usage: ['digitalSignature'], eku: ['clientAuth'], validity_days: 397, builtin: true },
    { id: 'ca', name: '中间 CA', description: '用于签发下级证书', key_usage: ['keyCertSign', 'cRLSign', 'digitalSignature'], eku: [], validity_days: 1825, builtin: true },
    { id: 'user', name: '用户证书', description: '个人身份 / 登录', key_usage: ['digitalSignature', 'keyEncipherment'], eku: ['clientAuth', 'emailProtection'], validity_days: 365, builtin: true }
  ];

  /* ---- DOM 小工具 ---- */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function el(id) { return document.getElementById(id); }
  function setText(id, text) { var n = el(id); if (n) n.textContent = (text == null ? '' : String(text)); }
  function setHTML(id, html) { var n = el(id); if (n) n.innerHTML = html; }
  function show(id, visible) { var n = el(id); if (n) n.hidden = !visible; }
  function val(id) { var n = el(id); return n ? n.value : ''; }
  function checked(id) { var n = el(id); return !!(n && n.checked); }
  function trim(s) { return (s == null ? '' : String(s)).trim(); }
  function esc(s) {
    return (s == null ? '' : String(s))
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  /* ---- 时间格式化 ---- */
  function parseDate(v) {
    if (!v) return null;
    if (v instanceof Date) return isNaN(v.getTime()) ? null : v;
    var s = String(v);
    var d = new Date(s);
    if (!isNaN(d.getTime())) return d;
    // 兼容 "2026-01-01 00:00:00" 这类无时区写法，按本地时间处理
    d = new Date(s.replace(' ', 'T'));
    return isNaN(d.getTime()) ? null : d;
  }
  function pad2(n) { return (n < 10 ? '0' : '') + n; }
  function fmtDateTime(v) {
    var d = parseDate(v); if (!d) return '—';
    return d.getFullYear() + '-' + pad2(d.getMonth() + 1) + '-' + pad2(d.getDate()) +
      ' ' + pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
  }
  function fmtDate(v) { var s = fmtDateTime(v); return s === '—' ? s : s.slice(0, 10); }
  function fmtRelative(v) {
    var d = parseDate(v); if (!d) return '—';
    var diff = Date.now() - d.getTime();
    var abs = Math.abs(diff), fut = diff < 0;
    var text;
    if (abs < 60e3) text = '刚刚';
    else if (abs < 3600e3) text = Math.round(abs / 60e3) + ' 分钟';
    else if (abs < 86400e3) text = Math.round(abs / 3600e3) + ' 小时';
    else if (abs < 30 * 86400e3) text = Math.round(abs / 86400e3) + ' 天';
    else return fmtDateTime(d);
    return fut ? text + '后' : text + '前';
  }
  function isoPlusDays(days, from) {
    var d = from ? new Date(from.getTime()) : new Date();
    d.setDate(d.getDate() + Number(days || 0));
    return d.toISOString();
  }
  function daysRemaining(cert) {
    if (!cert) return null;
    if (typeof cert.days_remaining === 'number' && isFinite(cert.days_remaining)) return cert.days_remaining;
    var d = parseDate(cert.not_after);
    if (!d) return null;
    return Math.floor((d.getTime() - Date.now()) / 86400000);
  }
  function daysCell(cert) {
    var n = daysRemaining(cert);
    if (n == null) return '<span class="faint">—</span>';
    var cls = n < 0 ? 'days days-danger' : (n <= 30 ? 'days days-warn' : 'days');
    var label = n < 0 ? '已过期 ' + Math.abs(n) + ' 天' : '剩余 ' + n + ' 天';
    return '<span class="' + cls + '">' + esc(label) + '</span>';
  }

  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    if (n < 1024 * 1024 * 1024) return (n / 1048576).toFixed(1) + ' MB';
    return (n / 1073741824).toFixed(2) + ' GB';
  }
  function truncateMid(s, head, tail) {
    s = String(s == null ? '' : s);
    head = head || 20; tail = tail || 10;
    if (s.length <= head + tail + 3) return s;
    return s.slice(0, head) + '…' + s.slice(-tail);
  }
  function badge(text, cls, title) {
    return '<span class="badge ' + (cls || '') + '"' + (title ? ' title="' + esc(title) + '"' : '') + '>' + esc(text) + '</span>';
  }
  function statusBadge(status) {
    var s = status || 'valid';
    return badge(STATUS_TEXT[s] || s, STATUS_CLASS[s] || '');
  }
  function tagsHTML(tags) {
    if (!tags || !tags.length) return '<span class="faint">—</span>';
    return tags.map(function (t) { return '<span class="tag">' + esc(t) + '</span>'; }).join('');
  }
  function sansHTML(sans) {
    if (!sans || !sans.length) return '<span class="faint">—</span>';
    return sans.map(function (s) {
      return '<span class="tag mono">' + esc((s.type || 'DNS') + ':' + (s.value || '')) + '</span>';
    }).join(' ');
  }
  function joinText(arr) {
    if (!arr || !arr.length) return '—';
    return arr.join(', ');
  }
  function jsonPretty(v) {
    if (v == null) return '';
    if (typeof v === 'string') {
      try { return JSON.stringify(JSON.parse(v), null, 2); } catch (e) { return v; }
    }
    try { return JSON.stringify(v, null, 2); } catch (e) { return String(v); }
  }
  function emptyState(title, desc, actionHTML) {
    return '<div class="empty"><div class="empty-title">' + esc(title) + '</div>' +
      (desc ? '<div class="small">' + esc(desc) + '</div>' : '') +
      (actionHTML ? '<div style="margin-top:10px">' + actionHTML + '</div>' : '') + '</div>';
  }
  function skeletonTable(cols, rows) {
    var out = '<table class="tbl"><thead><tr>';
    for (var i = 0; i < cols; i++) out += '<th>&nbsp;</th>';
    out += '</tr></thead><tbody>';
    for (var r = 0; r < (rows || 5); r++) {
      out += '<tr><td colspan="' + cols + '"><div class="skeleton sk-row"></div></td></tr>';
    }
    return out + '</tbody></table>';
  }
  function tableHTML(headers, rows, opts) {
    opts = opts || {};
    var out = '<table class="tbl' + (opts.cls ? ' ' + opts.cls : '') + '"><thead><tr>';
    headers.forEach(function (h) {
      if (typeof h === 'string') out += '<th>' + esc(h) + '</th>';
      else out += '<th class="' + (h.cls || '') + '">' + esc(h.text) + '</th>';
    });
    out += '</tr></thead><tbody>';
    if (!rows.length) {
      out += '<tr><td colspan="' + headers.length + '">' +
        emptyState(opts.emptyTitle || '暂无数据', opts.emptyDesc || '', opts.emptyAction || '') + '</td></tr>';
    } else {
      rows.forEach(function (r) {
        out += '<tr' + (r.attrs || '') + '>' + r.cells.map(function (c) {
          return '<td class="' + (c.cls || '') + '">' + c.html + '</td>';
        }).join('') + '</tr>';
      });
    }
    return out + '</tbody></table>';
  }

  /* ---- URL / 下载 ---- */
  function apiUrl(path, params) {
    var url = /^https?:\/\//i.test(path) ? path : API_BASE + path;
    if (params) {
      var qs = Object.keys(params).filter(function (k) {
        var v = params[k];
        return v !== '' && v !== null && v !== undefined;
      }).map(function (k) {
        return encodeURIComponent(k) + '=' + encodeURIComponent(params[k]);
      }).join('&');
      if (qs) url += (url.indexOf('?') >= 0 ? '&' : '?') + qs;
    }
    return url;
  }
  function triggerDownload(url, fallbackName) {
    var a = document.createElement('a');
    a.href = url;
    a.download = fallbackName || '';
    a.rel = 'noopener';
    a.style.display = 'none';
    document.body.appendChild(a);
    a.click();
    setTimeout(function () { a.remove(); }, 0);
  }
  function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);
    triggerDownload(url, filename);
    setTimeout(function () { URL.revokeObjectURL(url); }, 30000);
  }
  function downloadText(text, filename) {
    downloadBlob(new Blob([text], { type: 'application/octet-stream' }), filename);
  }

  /* ---- Toast ---- */
  function toast(message, type, ms) {
    var host = el('toasts');
    if (!host) { window.alert(message); return; }
    var box = document.createElement('div');
    box.className = 'toast toast-' + (type || 'info');
    var body = document.createElement('div');
    body.className = 'toast-body';
    body.textContent = message;
    var btn = document.createElement('button');
    btn.className = 'toast-x';
    btn.type = 'button';
    btn.setAttribute('aria-label', '关闭');
    btn.textContent = '✕';
    box.appendChild(body);
    box.appendChild(btn);
    host.appendChild(box);
    var timer = setTimeout(remove, ms || (type === 'error' ? 7000 : 4000));
    function remove() { clearTimeout(timer); if (box.parentNode) box.parentNode.removeChild(box); }
    btn.addEventListener('click', remove);
  }
  var toastOk = function (m) { toast(m, 'success'); };
  var toastErr = function (m) { toast(m, 'error'); };
  var toastWarn = function (m) { toast(m, 'warn', 6000); };

  /* ---- 全局遮罩 / 按钮 loading ---- */
  var overlayCount = 0;
  function showLoading(text) {
    overlayCount++;
    setText('loadingText', text || '处理中…');
    show('loading', true);
  }
  function hideLoading() {
    overlayCount = Math.max(0, overlayCount - 1);
    if (!overlayCount) show('loading', false);
  }
  function withLoading(text, task) {
    showLoading(text);
    var p;
    try { p = Promise.resolve(task()); }
    catch (e) { hideLoading(); return Promise.reject(e); }
    return p.finally(function () { hideLoading(); });
  }
  function withButton(btn, task) {
    if (!btn) return Promise.resolve(task());
    if (btn.dataset.loading === '1') return Promise.resolve(null);
    btn.dataset.loading = '1';
    var prevDisabled = btn.disabled;
    btn.disabled = true;
    btn.classList.add('is-loading');
    var p;
    try { p = Promise.resolve(task()); }
    catch (e) { p = Promise.reject(e); }
    return p.finally(function () {
      btn.dataset.loading = '';
      btn.classList.remove('is-loading');
      btn.disabled = prevDisabled;
    });
  }

  /* ====================================================================== */
  /* 2. API 封装                                                            */
  /* ====================================================================== */

  function api(path, opts) {
    opts = opts || {};
    var init = {
      method: opts.method || 'GET',
      credentials: 'same-origin',
      headers: { Accept: 'application/json' },
      cache: 'no-store'
    };
    if (opts.signal) init.signal = opts.signal;
    if (opts.isForm) {
      init.body = opts.body;                       // FormData：让浏览器自动设置 boundary
    } else if (opts.body !== undefined && opts.body !== null) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(opts.body);
    }
    /* 优先走应用层加密信道（crypto.js 暴露 window.CASecure） */
    if (channelAvailable()) return rpcApi(path, opts);
    var timeoutMs = opts.timeout || 90000;
    var ctrl = ('AbortController' in window) ? new AbortController() : null;
    var timedOut = false;
    var timer = null;
    if (ctrl) {
      if (!init.signal) init.signal = ctrl.signal;
      timer = setTimeout(function () { timedOut = true; ctrl.abort(); }, timeoutMs);
    }
    return fetch(apiUrl(path, opts.params), init).then(function (res) {
      if (timer) clearTimeout(timer);
      if (res.status === 401) {
        handleUnauthorized();
        var e401 = new Error('登录已失效，请重新登录');
        e401.status = 401; e401.silent = true;
        throw e401;
      }
      var ctype = res.headers.get('content-type') || '';
      var isJson = ctype.indexOf('json') >= 0;
      var parse = isJson
        ? res.json().catch(function () { return null; })
        : res.text().then(function (t) { return { error: t }; }).catch(function () { return null; });
      return parse.then(function (data) {
        if (res.ok) return data;
        var msg = (data && (data.error || data.message)) || ('请求失败（HTTP ' + res.status + '）');
        var err = new Error(msg);
        err.status = res.status;
        err.data = data;
        if (data && data.fields) err.fields = data.fields;
        throw err;
      });
    }).catch(function (err) {
      if (timer) clearTimeout(timer);
      if (err && err.name === 'AbortError') {
        var e = new Error(timedOut ? '请求超时，请稍后重试或检查后端服务' : '请求已取消');
        e.aborted = true;
        if (timedOut) toastErr(e.message);
        throw e;
      }
      if (!err || !err.status) {
        if (!(err && err.silent)) toastErr('网络错误：无法连接服务器（' + (err && err.message ? err.message : '未知错误') + '）');
        throw err;
      }
      if (!err.silent) toastErr(err.message);
      throw err;
    });
  }
  var apiGet = function (p, params, o) { return api(p, Object.assign({ params: params }, o || {})); };
  var apiPost = function (p, body, o) { return api(p, Object.assign({ method: 'POST', body: body }, o || {})); };
  var apiPatch = function (p, body, o) { return api(p, Object.assign({ method: 'PATCH', body: body }, o || {})); };
  var apiDel = function (p, params, o) { return api(p, Object.assign({ method: 'DELETE', params: params }, o || {})); };
  var apiForm = function (p, form, o) { return api(p, Object.assign({ method: 'POST', body: form, isForm: true, timeout: 300000 }, o || {})); };

  /* ====================================================================== */
  /* 2b. 应用层加密信道适配（frontend/crypto.js → window.CASecure）          */
  /* ====================================================================== */
  /*
   * 后端默认把明文 REST（/api/xxx）限制为本机回环访问，浏览器必须走
   * /api/handshake + /api/rpc 的 NaCl 加密信道（见 backend/secure_channel.py）。
   * 若页面未加载 vendor/tweetnacl.min.js 与 crypto.js（或后端开启了
   * CA_LEGACY_API=on 的兼容模式），则自动退化为同源 Cookie 会话的明文 REST。
   * 两条路径对上层保持完全相同的语义：
   *   · 成功 → 解析后的 JSON
   *   · 失败 → 抛出 Error(message 为服务端中文错误, .status, .data)
   */

  function channelAvailable() {
    return !!(window.CASecure && typeof window.CASecure.rpc === 'function');
  }

  /* 把 FormData 拆成 { body:{标量}, files:[{field,name,type,blob}] } */
  function splitFormData(fd) {
    var body = {}, files = [];
    fd.forEach(function (value, key) {
      if (typeof File !== 'undefined' && value instanceof File) {
        files.push({ field: key, name: value.name, type: value.type || 'application/octet-stream', blob: value });
      } else if (typeof Blob !== 'undefined' && value instanceof Blob) {
        files.push({ field: key, name: key, type: value.type || 'application/octet-stream', blob: value });
      } else {
        body[key] = value;
      }
    });
    return { body: body, files: files };
  }

  /* 把后台返回的原始响应体转成前端期望的形状（去掉 __file__ 包装） */
  function unwrapEnvelope(data, fmts) {
    if (data && typeof data === 'object' && data.__file__) {
      var f = data.__file__;
      if (f && (fmts || ['pem']).indexOf(String(f.format || '').toLowerCase()) >= 0) return f.text;
      return data;
    }
    return data;
  }

  function rpcApi(path, opts) {
    var method = (opts.method || 'GET').toUpperCase();
    var query = opts.params || {};
    var body = null, files = null;
    if (opts.isForm && opts.body) {
      var split = splitFormData(opts.body);
      body = split.body;
      files = split.files;
    } else if (opts.body !== undefined && opts.body !== null) {
      body = opts.body;
    }
    return window.CASecure.rpc(method, path, body, { query: query, files: files })
      .then(function (out) {
        return unwrapEnvelope(out && out.data, opts.textFormats);
      }).catch(function (err) {
        err = err || new Error('请求失败');
        if (!err.silent) toastErr(err.message || '请求失败');
        throw err;
      });
  }

  /* 探测当前会话：加密信道 / Cookie 会话 / 未登录 */
  function fetchMe() {
    return apiGet('/api/me').catch(function (err) {
      if (err && err.status === 401) { handleUnauthorized(); err.silent = true; }
      throw err;
    });
  }

  var redirecting = false;
  function handleUnauthorized() {
    if (redirecting) return;
    redirecting = true;
    try { sessionStorage.setItem('ca_login_msg', '登录已失效，请重新登录'); } catch (e) {}
    location.replace('login.html');
  }

  /* 以登录页为基准跳回 login.html（index.html 与 login.html 同目录） */
  function goLogin() { handleUnauthorized(); }

  /* 带会话的下载：
     · 加密信道 → CASecure.fetchFile() 取回 Blob 后本地落地
     · 明文 REST → fetch+blob（401 可感知），失败退化为直接跳转 */
  function downloadApi(path, params, filename) {
    if (channelAvailable()) {
      return window.CASecure.fetchFile(path, { query: params || {} }).then(function (blob) {
        window.CASecure.saveBlob(blob, filename || 'download');
      }).catch(function (err) {
        toastErr(err && err.message ? err.message : '下载失败');
        throw err;
      });
    }
    var url = apiUrl(path, params);
    return fetch(url, { credentials: 'same-origin', cache: 'no-store' }).then(function (res) {
      if (res.status === 401) { handleUnauthorized(); throw new Error('unauthorized'); }
      if (!res.ok) {
        return res.text().then(function (t) {
          var msg = '';
          try { msg = (JSON.parse(t) || {}).error || ''; } catch (e) { msg = ''; }
          throw new Error(msg || ('下载失败（HTTP ' + res.status + '）'));
        });
      }
      return res.blob().then(function (b) {
        var name = filename || guessFilename(res.headers.get('content-disposition')) || 'download';
        downloadBlob(b, name);
      });
    }).catch(function (err) {
      if (err && err.message === 'unauthorized') return;
      toastErr(err && err.message ? err.message : '下载失败');
      throw err;
    });
  }
  function guessFilename(cd) {
    if (!cd) return '';
    var m = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cd);
    if (!m) return '';
    try { return decodeURIComponent(m[1].replace(/"/g, '')); } catch (e) { return m[1]; }
  }
  function fileDownloadName(prefix, cert, ext) {
    var cn = (cert && (cert.cn || cert.serial_hex)) || 'cert';
    return (prefix ? prefix + '-' : '') + String(cn).replace(/[\\/:*?"<>|\s]+/g, '_') + '.' + ext;
  }

  /* ====================================================================== */
  /* 3. 全局状态                                                            */
  /* ====================================================================== */

  var state = {
    me: null,
    health: null,
    ca: null,              // 当前 CA 缓存（概览 / CA 页）
    templates: [],         // 用途模板
    settings: null,
    route: '#/dashboard',

    certs: {
      items: [], total: 0, page: 1, page_size: 20,
      q: '', status: '', profile: '', tag: '', expires: '', issuer: '',
      sort: 'created_at', order: 'desc',
      facets: { status: {}, profile: {}, tags: [] },
      loading: false
    },
    detail: { id: null, cert: null, audit: [], loading: false },
    revoke: { selectedId: null, cert: null, loading: false },
    crl: { crl: null, revoked: [], loading: false, pendingImport: null },
    batch: { preview: null, rows: null, result: null },
    imp: { tab: 'files', preview: null, previewKind: null, files: null, dirPath: '', csv: null, result: null },
    consistency: { checked_at: null, summary: null, issues: [], selected: {}, running: false },
    audit: { items: [], total: 0, page: 1, page_size: 20, action: '', q: '' },
    caList: [],
    backups: [],
    issueMode: 'generate',
    serverCaps: { templates: true, dirImport: true },

    /* 规则集（证书怎么签，全部是可编辑数据） */
    /* CSR 证书请求池 */
    csrs: {
      items: [], total: 0, page: 1, page_size: 20, status: '', q: '',
      stats: {}, preview: null, rulesets: []
    },
    rulesets: {
      items: [], default_slug: '', platform_notes: {}, meta: null,
      used: {}, notesSlug: '', editing: null, editorNotes: null, editorUsedBy: 0
    },
    /* CRL 自动发布 */
    publish: {
      status: null, targets: [], detected: null, suggested: [], staging_dir: '',
      ss: null, cdp: '', editingTarget: null, targetFormOpen: false,
      log: { items: [], total: 0, page: 1, page_size: 20 }
    },
    /* 通用自动化 */
    automation: {
      meta: null, tasks: [], editing: null, formOpen: false,
      log: { items: [], total: 0, page: 1, page_size: 20, task_id: '' }
    },
    /* strongSwan（设置页状态卡 / 证书详情片段） */
    ssStatus: null,
    ssSnippet: ''
  };

  /* ====================================================================== */
  /* 4. 确认对话框 / 抽屉                                                   */
  /* ====================================================================== */

  function confirmAction(cfg) {
    return new Promise(function (resolve) {
      var modal = el('modal');
      setText('modalTitle', cfg.title || '确认操作');
      var body = '';
      if (cfg.warning) body += '<div class="callout callout-danger">' + esc(cfg.warning) + '</div>';
      if (cfg.message) body += '<p>' + esc(cfg.message) + '</p>';
      if (cfg.impact && cfg.impact.length) {
        body += '<div class="impact"><dl>' + cfg.impact.map(function (row) {
          return '<dt>' + esc(row[0]) + '</dt><dd class="mono">' + esc(row[1]) + '</dd>';
        }).join('') + '</dl></div>';
      }
      if (cfg.html) body += cfg.html;
      if (cfg.extraField) {
        body += '<div class="field" style="margin-top:10px"><label for="modalExtra">' +
          esc(cfg.extraField.label) + '</label><input id="modalExtra" class="input ' +
          (cfg.extraField.mono ? 'mono' : '') + '" type="' + (cfg.extraField.type || 'text') +
          '" placeholder="' + esc(cfg.extraField.placeholder || '') + '"></div>';
      }
      setHTML('modalBody', body);

      var foot = '';
      if (cfg.confirmWord) {
        foot += '<div class="field" style="flex:1 1 220px;text-align:left">' +
          '<label for="modalConfirmWord">请输入 <span class="mono">' + esc(cfg.confirmWord) +
          '</span> 以确认</label><input id="modalConfirmWord" class="input mono" autocomplete="off"></div>';
      }
      foot += '<button class="btn" type="button" data-modal-close>取消</button>';
      foot += '<button class="btn ' + (cfg.danger ? 'btn-danger' : 'btn-primary') + '" id="modalOk" type="button">' +
        esc(cfg.okText || '确认') + '</button>';
      setHTML('modalFoot', foot);
      modal.hidden = false;

      function cleanup() {
        modal.hidden = true;
        $$('#modal [data-modal-close]').forEach(function (b) { b.removeEventListener('click', onCancel); });
        document.removeEventListener('keydown', onKey);
        if (okBtn) okBtn.removeEventListener('click', onOk);
      }
      function onCancel() { cleanup(); resolve(null); }
      function onOk() {
        var out = { extra: el('modalExtra') ? el('modalExtra').value : '' };
        if (cfg.confirmWord) {
          var typed = el('modalConfirmWord') ? trim(el('modalConfirmWord').value) : '';
          if (typed !== cfg.confirmWord) { toastErr('确认词不正确，请输入 ' + cfg.confirmWord); return; }
        }
        cleanup(); resolve(out);
      }
      function onKey(e) { if (e.key === 'Escape') onCancel(); }
      var okBtn = el('modalOk');
      $$('#modal [data-modal-close]').forEach(function (b) { b.addEventListener('click', onCancel); });
      okBtn.addEventListener('click', onOk);
      document.addEventListener('keydown', onKey);
      var focusTarget = el('modalConfirmWord') || el('modalExtra') || okBtn;
      if (focusTarget) focusTarget.focus();
    });
  }

  function closeDrawer() { el('drawer').hidden = true; }

  /* ====================================================================== */
  /* 5. 路由                                                                */
  /* ====================================================================== */

  var ROUTES = {
    '#/dashboard': { view: 'dashboard', title: '概览', render: renderDashboard },
    '#/certs': { view: 'certs', title: '证书列表', render: renderCerts },
    '#/cert': { view: 'cert-detail', title: '证书详情', render: renderCertDetail },
    '#/issue': { view: 'issue', title: '签发证书', render: renderIssue },
    '#/batch': { view: 'batch', title: '批量签发', render: renderBatch },
    '#/csrs': { view: 'csrs', title: 'CSR 证书请求', render: renderCsrs },
    '#/revocation': { view: 'revocation', title: '吊销与 CRL', render: renderRevocation },
    '#/rulesets': { view: 'rulesets', title: '规则集', render: renderRulesets },
    '#/publish': { view: 'publish', title: 'CRL 自动发布', render: renderPublish },
    '#/automation': { view: 'automation', title: '自动化', render: renderAutomation },
    '#/import': { view: 'import', title: '导入数据', render: renderImport },
    '#/consistency': { view: 'consistency', title: '一致性体检', render: renderConsistency },
    '#/audit': { view: 'audit', title: '审计日志', render: renderAudit },
    '#/ca': { view: 'ca', title: 'CA 管理', render: renderCa },
    '#/settings': { view: 'settings', title: '设置', render: renderSettings }
  };

  function parseHash() {
    var hash = location.hash || '#/dashboard';
    var qIdx = hash.indexOf('?');
    var path = qIdx >= 0 ? hash.slice(0, qIdx) : hash;
    var query = {};
    if (qIdx >= 0) {
      hash.slice(qIdx + 1).split('&').forEach(function (kv) {
        if (!kv) return;
        var i = kv.indexOf('=');
        var k = i < 0 ? kv : kv.slice(0, i);
        var v = i < 0 ? '' : kv.slice(i + 1);
        try { query[decodeURIComponent(k)] = decodeURIComponent(v); } catch (e) { query[k] = v; }
      });
    }
    if (path === '#/certs' && hash.indexOf('#/cert/') === 0) path = '#/cert';
    if (hash.indexOf('#/cert/') === 0) {
      query.id = hash.slice('#/cert/'.length).split('?')[0];
      path = '#/cert';
    }
    if (!ROUTES[path]) {
      // 支持 #/issue?profile=xxx 等
      path = ROUTES[path] ? path : '#/notfound';
    }
    return { path: path, query: query, hash: hash };
  }

  function navigate(hash) {
    if (location.hash === hash) route();
    else location.hash = hash;
  }

  function route() {
    var r = parseHash();
    state.route = r.path;
    var def = ROUTES[r.path];
    var viewName = def ? def.view : 'notfound';

    $$('#viewRoot .view').forEach(function (sec) {
      sec.hidden = sec.getAttribute('data-view') !== viewName;
    });
    setText('pageTitle', def ? def.title : '页面不存在');
    $$('#sidebarNav .nav-item').forEach(function (a) {
      var target = a.getAttribute('data-route');
      var active = target === r.path || (r.path === '#/cert' && target === '#/certs');
      a.classList.toggle('active', !!active);
    });
    setHTML('topbarActions', '');
    closeDrawer();
    closeSidebar();
    if (!def) return;
    if (r.path !== '#/certs') { /* 保留列表筛选，便于返回 */ }
    withLoading('加载中…', function () { return def.render(r.query); }).catch(function (err) {
      if (err && (err.aborted || err.silent)) return;
      var wrap = $('#viewRoot .view[data-view="' + viewName + '"]');
      if (wrap) {
        var p = document.createElement('div');
        p.className = 'alert alert-error';
        p.textContent = '加载失败：' + (err && err.message ? err.message : '未知错误');
        wrap.insertBefore(p, wrap.firstChild);
      }
    });
  }

  window.addEventListener('hashchange', route);

  /* ====================================================================== */
  /* 6. 概览                                                                */
  /* ====================================================================== */

  function statCard(label, value, cls, sub) {
    return '<div class="stat"><div class="stat-label">' + esc(label) + '</div>' +
      '<div class="stat-value ' + (cls || '') + '">' + esc(value) + '</div>' +
      (sub ? '<div class="stat-sub">' + esc(sub) + '</div>' : '') + '</div>';
  }

  function renderDashboard() {
    var statHost = el('dashStats');
    statHost.innerHTML = '';
    for (var i = 0; i < 6; i++) statHost.innerHTML += '<div class="stat"><div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div></div>';
    setHTML('dashRecent', skeletonTable(4, 5));
    setHTML('dashExpiring', skeletonTable(3, 5));
    setHTML('dashProfiles', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');

    return Promise.all([
      apiGet('/api/overview'),
      apiGet('/api/health').catch(function () { return null; })
    ]).then(function (res) {
      var ov = res[0] || {};
      state.health = res[1] || null;
      state.ca = ov.ca || null;
      applyCaState(state.ca, state.health);
      renderOverviewStats(ov);
      renderOverviewCa(ov);
      renderOverviewProfiles(ov.by_profile || []);
      renderOverviewRecent(ov.recent || []);
      renderOverviewExpiring(ov.expiring || []);
      setText('brandOrg', (state.settings && state.settings.org_name) || (state.ca && state.ca.cn) || '未配置机构');
    });
  }

  function renderOverviewStats(ov) {
    setHTML('dashStats',
      statCard('证书总数', ov.total == null ? '—' : ov.total, '') +
      statCard('有效', ov.valid == null ? '—' : ov.valid, 'ok') +
      statCard('已吊销', ov.revoked == null ? '—' : ov.revoked, 'danger') +
      statCard('已过期', ov.expired == null ? '—' : ov.expired, 'warn') +
      statCard('30 天内到期', ov.expiring_30d == null ? '—' : ov.expiring_30d, 'warn', '建议提前续期') +
      statCard('90 天内到期', ov.expiring_90d == null ? '—' : ov.expiring_90d, '', '含 30 天内')
    );
  }

  function renderOverviewCa(ov) {
    var ca = ov.ca;
    if (!ca) {
      setHTML('dashCaBody',
        '<div class="callout callout-warn"><strong>尚未导入 CA 证书。</strong>' +
        '导入 CA（证书 + 私钥）后才能签发证书、生成 CRL。系统当前仅能执行少量只读操作。</div>' +
        '<div class="row" style="margin-top:12px"><a class="btn btn-primary" href="#/ca">前往 CA 管理导入 CA</a></div>');
      return;
    }
    var keyTip = ca.has_key
      ? badge('已导入私钥', 'badge-valid')
      : badge('未导入私钥', 'badge-warning', '无法签发证书与生成 CRL');
    setHTML('dashCaBody',
      '<dl class="kv">' +
      '<dt>主题</dt><dd>' + esc(ca.subject || '—') + '</dd>' +
      '<dt>通用名 CN</dt><dd>' + esc(ca.cn || '—') + '</dd>' +
      '<dt>序列号</dt><dd class="mono">' + esc(ca.serial_hex || '—') + '</dd>' +
      '<dt>指纹 SHA-256</dt><dd class="mono">' + esc(ca.fingerprint_sha256 || '—') + '</dd>' +
      '<dt>有效期</dt><dd>' + esc(fmtDate(ca.not_before)) + ' → ' + esc(fmtDate(ca.not_after)) + '</dd>' +
      '<dt>密钥算法</dt><dd>' + esc((ca.key_type || '—') + ' ' + (ca.key_size || '')) + '</dd>' +
      '<dt>私钥状态</dt><dd>' + keyTip + '</dd>' +
      '</dl>' +
      (ca.has_key ? '' : '<div class="callout callout-danger small" style="margin-top:10px">' +
        '<strong>未导入 CA 私钥：无法签发证书与生成 CRL。</strong>请前往「CA 管理」导入私钥。</div>') +
      '<div class="row" style="margin-top:12px">' +
      '<a class="btn" href="#/ca">CA 管理</a>' +
      '<a class="btn" href="#/issue">签发证书</a>' +
      '</div>');
  }

  function renderOverviewProfiles(list) {
    if (!list.length) {
      setHTML('dashProfiles', emptyState('暂无数据', '还没有任何证书，先从「签发证书」开始。'));
      return;
    }
    var total = list.reduce(function (a, b) { return a + (Number(b.count) || 0); }, 0) || 1;
    setHTML('dashProfiles', list.map(function (p) {
      var count = Number(p.count) || 0;
      var pct = Math.round(count / total * 100);
      return '<div style="margin-bottom:10px">' +
        '<div class="row"><span class="grow">' + esc(p.profile || '未指定') + '</span>' +
        '<span class="mono">' + count + ' 张 · ' + pct + '%</span></div>' +
        '<div style="height:6px;background:var(--bg-hover);border-radius:3px;overflow:hidden;margin-top:4px">' +
        '<div style="height:100%;width:' + pct + '%;background:var(--primary)"></div></div></div>';
    }).join(''));
  }

  function renderOverviewRecent(list) {
    if (!list.length) {
      setHTML('dashRecent', emptyState('暂无操作记录', '所有关键操作都会记录在审计日志中。'));
      return;
    }
    setHTML('dashRecent', tableHTML(
      ['时间', '操作', { text: '对象', cls: 'grow' }, '操作人'],
      list.slice(0, 10).map(function (a) {
        return {
          cells: [
            { html: '<span class="nowrap">' + esc(fmtDateTime(a.ts)) + '</span>' },
            { html: '<span class="mono">' + esc(a.action || '—') + '</span>' },
            { html: esc(a.target_label || a.target_id || '—') },
            { html: esc(a.actor || '—') }
          ]
        };
      })
    ));
  }

  function renderOverviewExpiring(list) {
    if (!list.length) {
      setHTML('dashExpiring', emptyState('90 天内没有即将到期的证书', ''));
      return;
    }
    var sorted = list.slice().sort(function (a, b) {
      var da = daysRemaining(a), db = daysRemaining(b);
      return (da == null ? 1e9 : da) - (db == null ? 1e9 : db);
    });
    setHTML('dashExpiring', tableHTML(
      ['通用名 CN', '到期时间', '剩余'],
      sorted.slice(0, 10).map(function (c) {
        return {
          cells: [
            { html: '<a href="#/cert/' + esc(c.id) + '" class="mono">' + esc(c.cn || '—') + '</a> ' + statusBadge(c.status) },
            { html: '<span class="nowrap">' + esc(fmtDate(c.not_after)) + '</span>' },
            { html: daysCell(c) }
          ]
        };
      })
    ));
  }

  /* ====================================================================== */
  /* 7. 证书列表                                                            */
  /* ====================================================================== */

  var SORT_MAP = {}; // "created_at:desc" 直接传给后端 sort/order

  function certsQueryFromState() {
    var c = state.certs;
    var params = {
      q: c.q, status: c.status, profile: c.profile, tag: c.tag,
      sort: c.sort, order: c.order, page: c.page, page_size: c.page_size
    };
    if (c.issuer) params.issuer = c.issuer;
    if (c.expires === 'expired') params.expires_before = new Date().toISOString();
    else if (c.expires === '30d') params.expires_before = isoPlusDays(30);
    else if (c.expires === '90d') params.expires_before = isoPlusDays(90);
    else if (c.expires === '365d') params.expires_before = isoPlusDays(365);
    return params;
  }

  function syncCertFilterInputs() {
    var c = state.certs;
    if (el('certQ')) el('certQ').value = c.q;
    if (el('certStatus')) el('certStatus').value = c.status;
    if (el('certExpires')) el('certExpires').value = c.expires;
    if (el('certIssuer')) el('certIssuer').value = c.issuer;
    if (el('certPageSize')) el('certPageSize').value = String(c.page_size);
    if (el('certSort')) el('certSort').value = c.sort + ':' + c.order;
    fillSelect(el('certProfile'), [{ v: '', t: '全部用途' }].concat(
      Object.keys(c.facets.profile || {}).map(function (p) { return { v: p, t: p + '（' + c.facets.profile[p] + '）' }; })
    ), c.profile);
    fillSelect(el('certTag'), [{ v: '', t: '全部标签' }].concat(
      (c.facets.tags || []).map(function (t) { return { v: t, t: t }; })
    ), c.tag);
  }
  function fillSelect(sel, options, current) {
    if (!sel) return;
    sel.innerHTML = options.map(function (o) {
      return '<option value="' + esc(o.v) + '">' + esc(o.t) + '</option>';
    }).join('');
    sel.value = current == null ? '' : String(current);
    if (sel.selectedIndex < 0) sel.selectedIndex = 0;
  }

  function renderCerts(query) {
    query = query || {};
    var c = state.certs;
    // 支持从 URL 带入筛选（例如 #/certs?expires_before=...）
    ['q', 'status', 'profile', 'tag'].forEach(function (k) {
      if (query[k] != null && query[k] !== '') c[k] = query[k];
    });
    if (query.expires_before === '90d') c.expires = '90d';
    else if (query.expires_before === '30d') c.expires = '30d';
    syncCertFilterInputs();
    setHTML('certTableWrap', skeletonTable(9, 6));
    setHTML('certPager', '');
    return fetchCerts();
  }

  function fetchCerts() {
    var c = state.certs;
    c.loading = true;
    setHTML('certTableWrap', skeletonTable(9, 5));
    return apiGet('/api/certs', certsQueryFromState()).then(function (data) {
      c.loading = false;
      c.items = (data && data.items) || [];
      c.total = (data && data.total) || 0;
      c.page = (data && data.page) || c.page;
      c.page_size = (data && data.page_size) || c.page_size;
      if (data && data.facets) c.facets = data.facets;
      syncCertFilterInputs();
      renderCertsTable();
      renderCertsPager();
    }).catch(function (err) {
      c.loading = false;
      setHTML('certTableWrap', '<div class="empty"><div class="empty-title">加载失败</div><div class="small">' +
        esc(err && err.message ? err.message : '未知错误') + '</div></div>');
      throw err;
    });
  }

  function renderCertsTable() {
    var items = state.certs.items;
    if (!items.length) {
      setHTML('certTableWrap', emptyState('没有符合条件的证书',
        '可以调整筛选条件，或直接签发一张新证书。',
        '<a class="btn btn-primary" href="#/issue">签发新证书</a> <a class="btn" href="#/import">批量导入</a>'));
      return;
    }
    setHTML('certTableWrap', tableHTML(
      ['状态', '通用名 CN', '序列号', '用途', '签发时间', '到期时间 / 剩余', '所有者', '标签', '操作'],
      items.map(function (cert) {
        var actions = '<div class="actions">' +
          '<a class="btn" href="#/cert/' + esc(cert.id) + '">详情</a>' +
          '<button class="btn" type="button" data-act="cert-download" data-id="' + esc(cert.id) + '">下载</button>' +
          '<button class="btn" type="button" data-act="cert-renew" data-id="' + esc(cert.id) + '">续期</button>' +
          (cert.status === 'revoked'
            ? '<button class="btn" type="button" data-act="cert-unrevoke" data-id="' + esc(cert.id) + '">恢复</button>'
            : '<button class="btn btn-danger" type="button" data-act="cert-revoke" data-id="' + esc(cert.id) + '">吊销</button>') +
          '</div>';
        return {
          attrs: ' data-cert-row="' + esc(cert.id) + '"',
          cells: [
            { html: statusBadge(cert.status) },
            { html: '<a href="#/cert/' + esc(cert.id) + '">' + esc(cert.cn || '—') + '</a>' +
                (cert.has_key ? ' <span class="badge badge-dim" title="数据库中保存了私钥">含私钥</span>' : '') },
            { cls: 'mono', html: '<span title="' + esc(cert.serial_hex) + '">' + esc(truncateMid(cert.serial_hex || '—', 16, 8)) + '</span>' },
            { html: esc(cert.profile || '—') },
            { cls: 'nowrap', html: esc(fmtDate(cert.not_before)) },
            { html: '<span class="nowrap">' + esc(fmtDate(cert.not_after)) + '</span><br>' + daysCell(cert) },
            { html: esc(cert.owner || '—') },
            { html: tagsHTML(cert.tags) },
            { html: actions }
          ]
        };
      })
    ));
  }

  function renderCertsPager() {
    var c = state.certs;
    var totalPages = Math.max(1, Math.ceil(c.total / c.page_size));
    var from = c.total ? (c.page - 1) * c.page_size + 1 : 0;
    var to = Math.min(c.total, c.page * c.page_size);
    setHTML('certPager',
      '<span class="pager-info">共 ' + c.total + ' 条，当前 ' + from + '–' + to + '，第 ' + c.page + '/' + totalPages + ' 页</span>' +
      '<button class="btn" type="button" data-act="certs-page" data-page="1"' + (c.page <= 1 ? ' disabled' : '') + '>«</button>' +
      '<button class="btn" type="button" data-act="certs-page" data-page="' + (c.page - 1) + '"' + (c.page <= 1 ? ' disabled' : '') + '>上一页</button>' +
      '<button class="btn" type="button" data-act="certs-page" data-page="' + (c.page + 1) + '"' + (c.page >= totalPages ? ' disabled' : '') + '>下一页</button>' +
      '<button class="btn" type="button" data-act="certs-page" data-page="' + totalPages + '"' + (c.page >= totalPages ? ' disabled' : '') + '>»</button>');
  }

  function certsGoPage(p) {
    var c = state.certs;
    var totalPages = Math.max(1, Math.ceil(c.total / c.page_size));
    p = Math.min(Math.max(1, Number(p) || 1), totalPages);
    if (p === c.page) return;
    c.page = p;
    fetchCerts().catch(function () {});
  }

  function certById(id) {
    var found = null;
    state.certs.items.forEach(function (c) { if (String(c.id) === String(id)) found = c; });
    if (!found && state.detail.cert && String(state.detail.cert.id) === String(id)) found = state.detail.cert;
    if (!found && state.revoke.cert && String(state.revoke.cert.id) === String(id)) found = state.revoke.cert;
    if (!found) {
      (state.crl.revoked || []).forEach(function (c) { if (String(c.id) === String(id)) found = c; });
    }
    return found;
  }

  /* ====================================================================== */
  /* 8. 证书详情                                                            */
  /* ====================================================================== */

  function renderCertDetail(query) {
    var id = query && query.id;
    if (!id) { setHTML('detailBody', emptyState('缺少证书 ID', '请从证书列表进入详情。')); return Promise.resolve(); }
    state.detail.id = id;
    state.detail.cert = null;
    setHTML('detailBody', '<div class="card"><div class="card-body">' +
      '<div class="skeleton sk-line"></div><div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div></div></div>');
    setHTML('detailActions', '');
    return apiGet('/api/certs/' + encodeURIComponent(id)).then(function (data) {
      state.detail.cert = (data && data.cert) || null;
      state.detail.audit = (data && data.audit) || [];
      if (!state.detail.cert) throw new Error('证书不存在或已被删除');
      paintCertDetail();
    });
  }

  function paintCertDetail() {
    var cert = state.detail.cert;
    setHTML('detailActions',
      '<button class="btn" type="button" data-act="cert-download">下载 PEM</button>' +
      '<button class="btn" type="button" data-act="cert-vpn-bundle">strongSwan 部署包</button>' +
      '<button class="btn" type="button" data-act="cert-renew">续期</button>' +
      (cert.status === 'revoked'
        ? '<button class="btn" type="button" data-act="cert-unrevoke">恢复吊销</button>'
        : '<button class="btn btn-danger" type="button" data-act="cert-revoke">吊销</button>') +
      (cert.status === 'archived' ? '<button class="btn btn-danger" type="button" data-act="cert-delete">删除</button>' : '') +
      '<button class="btn btn-ghost" type="button" data-act="cert-refresh">刷新</button>');

    var d = daysRemaining(cert);
    var expiryNote = d == null ? '' :
      (d < 0 ? '<span class="days-danger">（已过期 ' + Math.abs(d) + ' 天）</span>' :
        (d <= 30 ? '<span class="days-warn">（剩余 ' + d + ' 天，建议尽快续期）</span>' : '（剩余 ' + d + ' 天）'));

    var html = '<div class="card"><div class="card-head">' +
      '<h2>' + esc(cert.cn || '(无 CN)') + '</h2>' + statusBadge(cert.status) +
      (cert.profile ? badge(cert.profile, 'badge-info') : '') +
      (cert.has_key ? badge('含私钥', 'badge-dim') : badge('无私钥', 'badge-dim')) +
      '</div><div class="card-body">';

    html += '<div class="section"><h3>标识信息</h3><dl class="kv">' +
      row('证书 ID', '<span class="mono">' + esc(cert.id) + '</span>') +
      row('序列号 (hex)', '<span class="mono">' + esc(cert.serial_hex || '—') + '</span>') +
      row('序列号 (dec)', '<span class="mono">' + esc(cert.serial_dec == null ? '—' : cert.serial_dec) + '</span>') +
      row('指纹 SHA-256', '<span class="mono">' + esc(cert.fingerprint_sha256 || '—') + '</span>') +
      row('签名算法', esc(cert.signature_algorithm || '—')) +
      row('密钥', esc((cert.key_type || '—') + ' ' + (cert.key_size || ''))) +
      '</dl></div>';

    html += '<div class="section"><h3>主体与签发者</h3><dl class="kv">' +
      row('主题', '<span class="mono">' + esc(cert.subject || '—') + '</span>') +
      row('通用名 CN', esc(cert.cn || '—')) +
      row('签发者', '<span class="mono">' + esc(cert.issuer || '—') + '</span>') +
      '</dl></div>';

    html += '<div class="section"><h3>有效期</h3><dl class="kv">' +
      row('生效时间', esc(fmtDateTime(cert.not_before))) +
      row('到期时间', esc(fmtDateTime(cert.not_after)) + ' ' + expiryNote) +
      row('创建时间', esc(fmtDateTime(cert.created_at))) +
      row('续期关系', (cert.replaces_id ? '续期自 <span class="mono">' + esc(cert.replaces_id) + '</span>' : '') +
        (cert.replaces_id && cert.replaced_by_id ? '<br>' : '') +
        (cert.replaced_by_id ? '已被 <a class="mono" href="#/cert/' + esc(cert.replaced_by_id) + '">' + esc(cert.replaced_by_id) + '</a> 取代' : '') || '—') +
      '</dl></div>';

    html += '<div class="section"><h3>扩展</h3><dl class="kv">' +
      row('KeyUsage', esc(joinText(cert.key_usage))) +
      row('ExtendedKeyUsage', esc(joinText(cert.eku))) +
      row('SAN 主体备用名', sansHTML(cert.sans)) +
      row('BasicConstraints', '<span class="faint">接口未返回此字段</span>') +
      row('SubjectKeyIdentifier', '<span class="faint">接口未返回此字段</span>') +
      row('AuthorityKeyIdentifier', '<span class="faint">接口未返回此字段</span>') +
      row('CRL 分发点', '<span class="faint">接口未返回此字段' +
        (state.settings && state.settings.crl_url ? '（系统配置为 ' + esc(state.settings.crl_url) + '）' : '') + '</span>') +
      '</dl></div>';

    if (cert.status === 'revoked') {
      html += '<div class="section"><h3>吊销信息</h3><dl class="kv">' +
        row('吊销时间', esc(fmtDateTime(cert.revoked_at))) +
        row('吊销原因', esc(REVOKE_REASON_TEXT[cert.revocation_reason] || cert.revocation_reason || '—')) +
        '</dl></div>';
    }

    html += '<div class="section"><h3>元数据</h3><div class="form-grid">' +
      '<div class="field"><label for="detOwner">所有者</label>' +
      '<input id="detOwner" class="input" value="' + esc(cert.owner || '') + '"></div>' +
      '<div class="field"><label for="detTags">标签（逗号分隔）</label>' +
      '<input id="detTags" class="input" value="' + esc((cert.tags || []).join(', ')) + '"></div>' +
      '<div class="field"><label for="detNotes">备注</label>' +
      '<textarea id="detNotes" class="input" rows="2">' + esc(cert.notes || '') + '</textarea></div>' +
      '<div class="row"><button class="btn btn-primary" type="button" data-act="cert-save-meta">保存元数据</button>' +
      '<span class="muted small">所有者 / 标签 / 备注可随时修改，不改变证书本身。</span></div>' +
      '</div></div>';

    html += '<div class="section"><h3>下载</h3><div class="dl-grid">' +
      '<button class="btn" type="button" data-act="cert-dl" data-format="pem">证书 PEM</button>' +
      '<button class="btn" type="button" data-act="cert-dl" data-format="der">证书 DER</button>' +
      '<button class="btn" type="button" data-act="cert-dl" data-format="key">私钥 PEM</button>' +
      '<button class="btn" type="button" data-act="cert-dl" data-format="chain">证书链</button>' +
      '<button class="btn" type="button" data-act="cert-dl-p12">PKCS#12 (.p12)</button>' +
      '</div>' +
      (cert.has_key ? '' : '<p class="muted small" style="margin:8px 0 0">该证书未在数据库中保存私钥，私钥格式无法下载。</p>') +
      '</div>';

    html += '<div class="section"><h3>strongSwan 部署</h3>' + ssDeployHTML(cert) + '</div>';

    html += '<div class="section"><h3>PEM 文本</h3>' +
      '<div class="copy-row"><span class="muted small">证书 PEM</span>' +
      '<button class="btn btn-sm" type="button" data-act="copy-pem" data-target="pemCert">复制</button>' +
      '<button class="btn btn-sm" type="button" data-act="load-pem" data-format="pem">载入</button></div>' +
      '<pre class="pem" id="pemCert">加载中…</pre>' +
      '</div>';

    html += '<div class="section"><h3>审计历史</h3>' +
      renderAuditTimeline(state.detail.audit) + '</div>';

    html += '</div></div>';
    setHTML('detailBody', html);
    loadPemText();
  }

  function row(k, vHTML) { return '<dt>' + esc(k) + '</dt><dd>' + vHTML + '</dd>'; }

  function loadPemText() {
    var cert = state.detail.cert;
    if (!cert) return;
    fetch(apiUrl('/api/certs/' + encodeURIComponent(cert.id) + '/download', { format: 'pem' }),
      { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { if (r.status === 401) { handleUnauthorized(); return ''; } return r.ok ? r.text() : ''; })
      .then(function (t) {
        var pre = el('pemCert');
        if (pre) pre.textContent = t || '（无法获取证书 PEM）';
      })
      .catch(function () { var pre = el('pemCert'); if (pre) pre.textContent = '（无法获取证书 PEM）'; });
  }

  function copyText(text, okMsg) {
    var done = function () { toastOk(okMsg || '已复制到剪贴板'); };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
    } else fallbackCopy(text, done);
  }
  function fallbackCopy(text, done) {
    var ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); done(); } catch (e) { toastErr('复制失败，请手动选择文本复制'); }
    ta.remove();
  }

  function certSaveMeta() {
    var cert = state.detail.cert;
    if (!cert) return;
    var body = {
      owner: val('detOwner'),
      tags: trim(val('detTags')) ? trim(val('detTags')).split(/[,，]/).map(trim).filter(Boolean) : [],
      notes: val('detNotes')
    };
    return withButton($('[data-act="cert-save-meta"]'), function () {
      return apiPatch('/api/certs/' + encodeURIComponent(cert.id), body).then(function (data) {
        state.detail.cert = data.cert || Object.assign({}, cert, body);
        toastOk('元数据已保存');
        paintCertDetail();
        if (state.route === '#/certs') fetchCerts().catch(function () {});
      });
    });
  }

  function certRenew(cert) {
    if (!cert) return;
    return confirmAction({
      title: '续期证书',
      message: '将为「' + (cert.cn || cert.id) + '」签发一张新证书，新证书会与原证书建立续期关系。是否继续？',
      impact: [
        ['原证书 CN', cert.cn || '—'],
        ['原证书序列号', cert.serial_hex || '—'],
        ['原证书到期', fmtDateTime(cert.not_after)]
      ],
      extraField: { label: '新证书有效期（天）', placeholder: '365', type: 'number' },
      okText: '确认续期'
    }).then(function (res) {
      if (!res) return;
      var days = parseInt(res.extra, 10);
      if (!days || days < 1 || days > 3650) { toastErr('有效期需为 1–3650 之间的整数'); return; }
      return apiPost('/api/certs/' + encodeURIComponent(cert.id) + '/renew', { validity_days: days })
        .then(function (data) {
          toastOk('续期成功');
          showSecretResult(data, '续期结果');
          if (state.detail.cert) renderCertDetail({ id: state.detail.id }).catch(function () {});
          if (state.route === '#/certs') fetchCerts().catch(function () {});
        });
    });
  }

  function certRevoke(cert) {
    if (!cert) return;
    // 确认框内的表单字段会随确认框一起销毁，因此用捕获监听在销毁前取回用户输入
    var picked = { reason: 'unspecified', notes: '' };
    function watchModal(e) {
      var t = e.target;
      if (!t || !t.id) return;
      if (t.id === 'revokeReasonSel') picked.reason = t.value;
      else if (t.id === 'revokeNoteInp') picked.notes = trim(t.value);
    }
    document.addEventListener('change', watchModal, true);
    document.addEventListener('input', watchModal, true);
    return confirmAction({
      title: '吊销证书',
      warning: '吊销操作不可轻易撤销（仅 certificateHold 状态可恢复）。吊销后该证书在证书校验中会被判定为不可信。',
      message: '确认吊销下列证书？',
      impact: [
        ['通用名 CN', cert.cn || '—'],
        ['序列号', cert.serial_hex || '—'],
        ['用途', cert.profile || '—'],
        ['有效期至', fmtDateTime(cert.not_after)]
      ],
      html: '<div class="field"><label for="revokeReasonSel">吊销原因</label>' +
        '<select id="revokeReasonSel" class="input">' + REVOKE_REASONS.map(function (r) {
          return '<option value="' + r + '">' + esc(REVOKE_REASON_TEXT[r]) + '</option>';
        }).join('') + '</select></div>' +
        '<div class="field" style="margin-top:8px"><label for="revokeNoteInp">吊销备注（可选）</label>' +
        '<input id="revokeNoteInp" class="input"></div>',
      okText: '确认吊销', danger: true
    }).then(function (res) {
      document.removeEventListener('change', watchModal, true);
      document.removeEventListener('input', watchModal, true);
      if (!res) return;
      return doRevoke(cert, picked.reason, picked.notes);
    });
  }

  function doRevoke(cert, reason, notes) {
    var body = { reason: reason, revocation_date: '', notes: notes };
    return apiPost('/api/certs/' + encodeURIComponent(cert.id) + '/revoke', body).then(function (data) {
      toastOk('证书已吊销' + (data && data.crl ? '，并已更新 CRL（编号 ' + data.crl.number + '）' : ''));
      refreshAfterCertChange(cert.id);
    });
  }

  function certUnrevoke(cert) {
    if (!cert) return;
    return confirmAction({
      title: '恢复吊销（解除挂起）',
      warning: '恢复吊销仅适用于因 certificateHold 挂起的证书。恢复后该证书重新被视为有效，请确认这确实是你想要的。',
      message: '确认为下列证书解除吊销状态？',
      impact: [
        ['通用名 CN', cert.cn || '—'],
        ['序列号', cert.serial_hex || '—'],
        ['吊销时间', fmtDateTime(cert.revoked_at)],
        ['吊销原因', REVOKE_REASON_TEXT[cert.revocation_reason] || cert.revocation_reason || '—']
      ],
      okText: '确认恢复', danger: true, confirmWord: 'RESTORE'
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/certs/' + encodeURIComponent(cert.id) + '/unrevoke', { confirm: true }).then(function (data) {
        toastOk('已恢复吊销状态' + (data && data.crl ? '，CRL 已更新' : '')
          + (data && data.publish ? '，strongSwan 已重载' : ''));
        refreshAfterCertChange(cert.id);
      });
    });
  }

  function certDelete(cert) {
    if (!cert) return;
    return confirmAction({
      title: '删除证书记录',
      warning: '删除后该证书记录从数据库中移除（默认软删除为归档）。若需彻底移除，请选择硬删除。',
      impact: [['通用名 CN', cert.cn || '—'], ['序列号', cert.serial_hex || '—']],
      extraField: { label: '输入 hard 执行硬删除（留空为软删除）', placeholder: 'hard' },
      okText: '确认删除', danger: true
    }).then(function (res) {
      if (!res) return;
      var hard = trim(res.extra).toLowerCase() === 'hard';
      return apiDel('/api/certs/' + encodeURIComponent(cert.id), { hard: hard ? 'true' : 'false' }).then(function () {
        toastOk(hard ? '证书已硬删除' : '证书已归档');
        navigate('#/certs');
        fetchCerts().catch(function () {});
      });
    });
  }

  function refreshAfterCertChange(id) {
    if (state.route === '#/certs') fetchCerts().catch(function () {});
    else if (state.route === '#/cert' && String(state.detail.id) === String(id)) {
      renderCertDetail({ id: id }).catch(function () {});
    } else if (state.route === '#/revocation') {
      loadCrl().catch(function () {});
    } else if (state.route === '#/dashboard') {
      renderDashboard().catch(function () {});
    }
  }

  function certDownload(cert, format, password) {
    if (!cert) return Promise.resolve();
    var extMap = { pem: 'pem', der: 'der', key: 'key', chain: 'pem', p12: 'p12' };
    var prefixMap = { pem: '', der: '', key: 'key', chain: 'chain', p12: 'bundle' };
    var params = { format: format };
    if (format === 'p12') params.password = password || '';
    if (format === 'key' && !cert.has_key) { toastErr('该证书没有可下载的私钥'); return Promise.resolve(); }
    return downloadApi('/api/certs/' + encodeURIComponent(cert.id) + '/download', params,
      fileDownloadName(prefixMap[format] || '', cert, extMap[format] || 'bin'));
  }

  function askP12Password(cert) {
    return confirmAction({
      title: '导出 PKCS#12',
      message: 'PKCS#12 会同时包含证书与私钥，请设置导出口令（口令不会保存在服务器）。',
      impact: [['通用名 CN', cert.cn || '—'], ['序列号', cert.serial_hex || '—']],
      extraField: { label: '导出口令', type: 'password', placeholder: '请设置 p12 口令' },
      okText: '导出'
    }).then(function (res) {
      if (!res) return;
      if (!res.extra) { toastErr('请设置导出口令'); return; }
      return certDownload(cert, 'p12', res.extra);
    });
  }

  function renderAuditTimeline(list) {
    if (!list || !list.length) return '<p class="muted small">暂无审计记录。</p>';
    return '<div class="table-wrap">' + tableHTML(
      ['时间', '操作', '操作人', '详情'],
      list.map(function (a) {
        return {
          cells: [
            { cls: 'nowrap', html: esc(fmtDateTime(a.ts)) },
            { cls: 'mono', html: esc(a.action || '—') },
            { html: esc(a.actor || '—') },
            { html: '<span class="small mono cell-wrap">' + esc(typeof a.detail === 'string' ? a.detail : jsonPretty(a.detail)) + '</span>' }
          ]
        };
      })
    ) + '</div>';
  }

  /* ---- 签发结果（含私钥）展示 ---- */
  function showSecretResult(data, title) {
    var cert = (data && data.cert) || null;
    var secret = (data && data.secret) || null;
    setHTML('issueResult', '');
    var html = '';
    if (cert) {
      html += '<div class="section"><h3>' + esc(title || '签发结果') + '</h3><dl class="kv">' +
        row('通用名 CN', esc(cert.cn || '—')) +
        row('证书 ID', '<a class="mono" href="#/cert/' + esc(cert.id) + '">' + esc(cert.id) + '</a>') +
        row('序列号 (hex)', '<span class="mono">' + esc(cert.serial_hex || '—') + '</span>') +
        row('指纹 SHA-256', '<span class="mono">' + esc(cert.fingerprint_sha256 || '—') + '</span>') +
        row('有效期', esc(fmtDateTime(cert.not_before)) + ' → ' + esc(fmtDateTime(cert.not_after))) +
        row('用途', esc(cert.profile || '—')) +
        '</dl></div>';
    }
    if (secret && secret.key_pem) {
      html += '<div class="callout callout-danger" style="margin-top:12px">' +
        '<strong>私钥仅此一次显示！</strong>请立即下载并妥善保存；关闭后无法再次获取明文私钥。</div>' +
        '<div class="copy-row" style="margin-top:10px">' +
        '<button class="btn btn-primary" type="button" data-act="secret-download" data-kind="cert">下载证书 PEM</button>' +
        '<button class="btn btn-primary" type="button" data-act="secret-download" data-kind="key">下载私钥 KEY</button>' +
        '<button class="btn" type="button" data-act="secret-download" data-kind="chain">下载证书链</button>' +
        (secret.pkcs12_b64 ? '<button class="btn" type="button" data-act="secret-download" data-kind="pkcs12">下载 PKCS#12</button>' : '') +
        '<span class="spacer"></span>' +
        '<button class="btn btn-ghost" type="button" data-act="secret-copy" data-kind="key">复制私钥</button>' +
        '<button class="btn btn-ghost" type="button" data-act="secret-copy" data-kind="cert">复制证书</button>' +
        '</div>';
    } else if (secret && secret.cert_pem) {
      html += '<div class="callout" style="margin-top:12px">本次签发使用上传的 CSR，服务器不持有私钥，因此不返回 key_pem。</div>' +
        '<div class="copy-row" style="margin-top:10px">' +
        '<button class="btn btn-primary" type="button" data-act="secret-download" data-kind="cert">下载证书 PEM</button>' +
        '<button class="btn" type="button" data-act="secret-download" data-kind="chain">下载证书链</button>' +
        '<button class="btn btn-ghost" type="button" data-act="secret-copy" data-kind="cert">复制证书</button>' +
        '</div>';
    }
    if (secret && secret.cert_pem) {
      html += '<div class="section"><h3>证书 PEM</h3><pre class="pem">' + esc(secret.cert_pem) + '</pre></div>';
    }
    if (secret && secret.key_pem) {
      html += '<div class="section"><h3>私钥 PEM（仅此一次）</h3><pre class="pem">' + esc(secret.key_pem) + '</pre></div>';
    }
    setHTML('issueResult', html || '<p class="muted">接口未返回详细信息。</p>');
    show('issueResultCard', true);
    el('issueResultCard').dataset.secret = JSON.stringify(secret || {});
    if (cert && cert.id) el('issueResultCard').dataset.certId = cert.id;
    el('issueResultCard').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function secretPayload() {
    var box = el('issueResultCard');
    if (!box || !box.dataset.secret) return {};
    try { return JSON.parse(box.dataset.secret); } catch (e) { return {}; }
  }

  function secretDownload(kind) {
    var s = secretPayload();
    var cert = { cn: (state.detail.cert && state.detail.cert.cn) || 'cert' };
    if (kind === 'cert' && s.cert_pem) downloadText(s.cert_pem, fileDownloadName('', cert, 'pem'));
    else if (kind === 'key' && s.key_pem) downloadText(s.key_pem, fileDownloadName('key', cert, 'key'));
    else if (kind === 'chain' && s.chain_pem) downloadText(s.chain_pem, fileDownloadName('chain', cert, 'pem'));
    else if (kind === 'pkcs12' && s.pkcs12_b64) {
      var bin = atob(s.pkcs12_b64);
      var bytes = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      downloadBlob(new Blob([bytes], { type: 'application/x-pkcs12' }), fileDownloadName('bundle', cert, 'p12'));
    } else toastErr('该格式不可用');
  }

  /* ====================================================================== */
  /* 9. 签发证书                                                            */
  /* ====================================================================== */

  function renderIssue() {
    if (!state.templates.length) {
      state.templates = FALLBACK_TEMPLATES.slice();
      loadTemplates().then(function () { fillProfileSelect(); }).catch(function () {});
    }
    fillProfileSelect();
    fillKeySizes();
    renderSanRows([{ type: 'DNS', value: '' }]);
    renderCheckboxGroup('issKeyUsage', KU_ALL, ['digitalSignature', 'keyEncipherment']);
    renderCheckboxGroup('issEku', EKU_ALL, ['serverAuth']);
    setIssueMode(state.issueMode || 'generate');
    applyCaState(state.ca, state.health);
    show('issueResultCard', false);
    renderIssuePreview();
    var pwd = state.settings && state.settings.default_validity_days;
    if (pwd && el('issValidity') && !el('issValidity').dataset.touched) {
      if (!val('issValidity') || val('issValidity') === '365') el('issValidity').value = String(pwd);
    }
    return Promise.resolve();
  }

  function loadTemplates() {
    return apiGet('/api/templates').then(function (data) {
      var items = (data && data.items) || [];
      if (items.length) state.templates = items;
      else state.serverCaps.templates = false;
    }).catch(function () { state.serverCaps.templates = false; });
  }

  function fillProfileSelect() {
    var sel = el('issProfile');
    if (!sel) return;
    var cur = sel.value;
    sel.innerHTML = state.templates.map(function (t) {
      return '<option value="' + esc(t.id) + '">' + esc(t.name || t.id) + (t.builtin ? '' : '（自定义）') + '</option>';
    }).join('') || '<option value="">（无可用模板）</option>';
    if (cur && state.templates.some(function (t) { return String(t.id) === cur; })) sel.value = cur;
  }

  function currentTemplate() {
    var id = val('issProfile');
    var found = null;
    state.templates.forEach(function (t) { if (String(t.id) === String(id)) found = t; });
    return found;
  }

  function applyTemplateToForm() {
    var t = currentTemplate();
    if (!t) { setText('issProfileHint', ''); return; }
    setText('issProfileHint', (t.description || '') +
      (t.validity_days ? '　默认有效期 ' + t.validity_days + ' 天' : ''));
    if (t.validity_days) el('issValidity').value = String(t.validity_days);
    renderCheckboxGroup('issKeyUsage', KU_ALL, t.key_usage || []);
    renderCheckboxGroup('issEku', EKU_ALL, t.eku || []);
    renderIssuePreview();
  }

  function fillKeySizes() {
    var type = val('issKeyType') || 'rsa';
    var opts = KEY_SIZE_OPTIONS[type] || KEY_SIZE_OPTIONS.rsa;
    fillSelect(el('issKeySize'), opts.map(function (o) { return { v: o[0], t: o[1] }; }), opts[0][0]);
  }

  function renderCheckboxGroup(hostId, pairs, selected) {
    selected = selected || [];
    setHTML(hostId, pairs.map(function (p) {
      var on = selected.indexOf(p[0]) >= 0 ? ' checked' : '';
      return '<label class="check"><input type="checkbox" value="' + esc(p[0]) + '"' + on + '>' +
        esc(p[1]) + ' <span class="faint mono">' + esc(p[0]) + '</span></label>';
    }).join(''));
  }
  function collectChecks(hostId) {
    return $$('#' + hostId + ' input[type=checkbox]').filter(function (i) { return i.checked; })
      .map(function (i) { return i.value; });
  }

  function renderSanRows(rows) {
    var host = el('issSanRows');
    if (!host) return;
    host.innerHTML = (rows || []).map(sanRowHTML).join('') ||
      '<p class="muted small">尚未添加 SAN。可以点击右上角「添加一行」。</p>';
  }
  function sanRowHTML(r) {
    r = r || { type: 'DNS', value: '' };
    var opts = SAN_TYPES.map(function (t) {
      return '<option value="' + t + '"' + (String(r.type).toUpperCase() === t.toUpperCase() ? ' selected' : '') + '>' + t + '</option>';
    }).join('');
    return '<div class="san-row">' +
      '<select class="input san-type" aria-label="SAN 类型">' + opts + '</select>' +
      '<input class="input san-value mono" placeholder="' + esc(sanPlaceholder(r.type)) + '" value="' + esc(r.value || '') + '">' +
      '<button class="btn btn-ghost" type="button" data-act="san-del" title="删除此行">✕</button>' +
      '</div>';
  }
  function sanPlaceholder(type) {
    var t = String(type || '').toUpperCase();
    if (t === 'IP') return '例如 10.0.0.12 或 2001:db8::1';
    if (t === 'EMAIL') return '例如 ops@example.com';
    if (t === 'UPN') return '例如 user@example.local';
    if (t === 'URI') return '例如 https://example.com/';
    return '例如 www.example.com 或 *.example.com';
  }
  function collectSans() {
    var out = [];
    $$('#issSanRows .san-row').forEach(function (rowEl) {
      var type = $('.san-type', rowEl).value;
      var v = trim($('.san-value', rowEl).value);
      if (v) out.push({ type: type, value: v });
    });
    return out;
  }

  function setIssueMode(mode) {
    state.issueMode = mode === 'csr' ? 'csr' : 'generate';
    $$('#issueModeTabs .tab').forEach(function (t) {
      t.classList.toggle('active', t.getAttribute('data-issue-mode') === state.issueMode);
    });
    show('csrCard', state.issueMode === 'csr');
    // CSR 模式下隐藏密钥相关选项（不返回 key_pem，密钥由申请方持有）
    show('keyCard', state.issueMode !== 'csr');
    show('wrapSerialMode', state.issueMode !== 'csr');
    setText('issSubmitHint', state.issueMode === 'csr'
      ? '当前为 CSR 模式：将使用上传 CSR 中的公钥与主题，服务器不返回私钥。'
      : '系统生成密钥：签发成功后请立即下载私钥（仅显示一次）。');
    renderIssuePreview();
  }

  function issueFormBody() {
    var sans = collectSans();
    var body = {
      profile: val('issProfile'),
      cn: trim(val('issCn')),
      o: trim(val('issO')),
      ou: trim(val('issOu')),
      c: trim(val('issC')),
      st: trim(val('issSt')),
      l: trim(val('issL')),
      sans: sans,
      validity_days: parseInt(val('issValidity'), 10) || 0,
      key_type: state.issueMode === 'csr' ? '' : (val('issKeyType') || 'rsa'),
      key_size: state.issueMode === 'csr' ? 0 : (parseInt(val('issKeySize'), 10) || 0),
      key_usage: collectChecks('issKeyUsage'),
      eku: collectChecks('issEku'),
      serial_mode: state.issueMode === 'csr' ? '' : (val('issSerialMode') || 'random'),
      owner: trim(val('issOwner')),
      tags: trim(val('issTags')) ? trim(val('issTags')).split(/[,，]/).map(trim).filter(Boolean) : [],
      notes: val('issNotes'),
      csr_pem: state.issueMode === 'csr' ? trim(val('issCsrText')) : ''
    };
    return body;
  }

  function validateIssueForm(body) {
    var errs = {};
    if (state.issueMode === 'csr' && !body.csr_pem) errs.issCn = '请先粘贴或上传 CSR 内容';
    if (state.issueMode !== 'csr' && !body.cn) errs.issCn = '请输入通用名 CN';
    if (!body.validity_days || body.validity_days < 1 || body.validity_days > 3650) errs.issValidity = '有效期需为 1–3650 之间的整数';
    if (body.c && !/^[A-Za-z]{2}$/.test(body.c)) errs.issC = '国家代码需为 2 位字母';
    setHTML('err-issCn', errs.issCn ? esc(errs.issCn) : '');
    setHTML('err-issValidity', errs.issValidity ? esc(errs.issValidity) : '');
    var ok = !errs.issCn && !errs.issValidity && !errs.issC;
    if (errs.issC) toastErr(errs.issC);
    return ok;
  }

  function renderIssuePreview() {
    var body = issueFormBody();
    var t = currentTemplate();
    var keyText = state.issueMode === 'csr' ? '使用 CSR 中的公钥' :
      ((body.key_type || 'rsa').toUpperCase() + ' ' + (body.key_size || ''));
    var validFrom = new Date();
    var validTo = body.validity_days ? new Date(Date.now() + body.validity_days * 86400000) : null;
    var raw = trim(val('issCsrText'));
    setHTML('issPreview',
      '<dl class="kv">' +
      row('用途模板', esc((t && (t.name + '（' + t.id + '）')) || body.profile || '—')) +
      row('通用名 CN', esc(body.cn || '—')) +
      row('主题', '<span class="mono">' + esc(subjectString(body)) + '</span>') +
      row('SAN', sansHTML(body.sans)) +
      row('有效期', esc(body.validity_days ? (body.validity_days + ' 天（约 ' + fmtDate(validFrom) + ' → ' + (validTo ? fmtDate(validTo) : '—') + '）') : '—')) +
      row('密钥', esc(keyText)) +
      row('序列号模式', esc(body.serial_mode || '—')) +
      row('KeyUsage', esc(body.key_usage.length ? body.key_usage.map(function (k) { return k + '（' + (KU_TEXT[k] || k) + '）'; }).join('、') : '—')) +
      row('EKU', esc(body.eku.length ? body.eku.map(function (k) { return k + '（' + (EKU_TEXT[k] || k) + '）'; }).join('、') : '—')) +
      row('所有者 / 标签', esc((body.owner || '—') + ' / ' + (body.tags.length ? body.tags.join('、') : '—'))) +
      row('备注', esc(body.notes || '—')) +
      (raw ? row('CSR 内容', '<span class="mono">已粘贴 ' + raw.length + ' 字符</span>') : '') +
      '</dl>');
  }

  function subjectString(b) {
    var parts = [];
    if (b.cn) parts.push('CN=' + b.cn);
    if (b.ou) parts.push('OU=' + b.ou);
    if (b.o) parts.push('O=' + b.o);
    if (b.l) parts.push('L=' + b.l);
    if (b.st) parts.push('ST=' + b.st);
    if (b.c) parts.push('C=' + b.c);
    return parts.join(', ') || '—';
  }

  function issueSubmit() {
    var body = issueFormBody();
    if (!validateIssueForm(body)) return Promise.resolve();
    var go = function () {
      var btn = el('issSubmit');
      return withButton(btn, function () {
        return withLoading('正在签发证书…', function () {
          var p;
          if (state.issueMode === 'csr') {
            var fd = new FormData();
            var file = el('issCsrFile') && el('issCsrFile').files[0];
            if (file) fd.append('csr_file', file);
            fd.append('csr_pem', body.csr_pem);
            ['profile', 'cn', 'o', 'ou', 'c', 'st', 'l', 'validity_days', 'owner', 'notes'].forEach(function (k) {
              if (body[k] !== '' && body[k] != null) fd.append(k, body[k]);
            });
            fd.append('tags', JSON.stringify(body.tags));
            fd.append('key_usage', JSON.stringify(body.key_usage));
            fd.append('eku', JSON.stringify(body.eku));
            fd.append('sans', JSON.stringify(body.sans));
            p = apiForm('/api/certs/issue/csr', fd);
          } else {
            p = apiPost('/api/certs/issue', body);
          }
          return p.then(function (data) {
            toastOk('证书签发成功');
            showSecretResult(data, '签发成功');
            if (state.route === '#/issue') { /* 留在当前页展示结果 */ }
          });
        });
      });
    };
    var summary = '<div class="impact"><dl>' +
      '<dt>通用名 CN</dt><dd>' + esc(body.cn || '（来自 CSR）') + '</dd>' +
      '<dt>主题</dt><dd>' + esc(subjectString(body)) + '</dd>' +
      '<dt>用途</dt><dd>' + esc(body.profile || '—') + '</dd>' +
      '<dt>有效期</dt><dd>' + esc(body.validity_days + ' 天') + '</dd>' +
      '<dt>密钥</dt><dd>' + esc(state.issueMode === 'csr' ? 'CSR 公钥' : ((body.key_type || '').toUpperCase() + ' ' + body.key_size)) + '</dd>' +
      '<dt>SAN</dt><dd>' + esc(body.sans.map(function (s) { return s.type + ':' + s.value; }).join('、') || '—') + '</dd>' +
      '</dl></div>';
    return confirmAction({
      title: '确认签发证书',
      message: '请确认即将签发的证书信息：',
      html: summary + (state.issueMode === 'csr' ? '' :
        '<div class="callout callout-warn small">系统将生成密钥对，私钥仅在签发成功后显示一次，请立即下载保存。</div>'),
      okText: '确认签发'
    }).then(function (res) { if (res) return go(); });
  }

  function parseCsrPem() {
    var text = trim(val('issCsrText'));
    if (!text) {
      var f = el('issCsrFile') && el('issCsrFile').files[0];
      if (f) {
        return f.text().then(function (t) {
          el('issCsrText').value = t;
          return parseCsrPem();
        }).catch(function () {
          return apiForm('/api/certs/issue/csr', (function () {
            var fd = new FormData(); fd.append('csr_file', f); fd.append('dry_run', 'true'); return fd;
          })()).catch(function () {});
        });
      }
      toastErr('请上传 CSR 文件或粘贴 CSR PEM');
      return Promise.resolve();
    }
    // 前端只做格式检查；主题与 SAN 交由后端解析（契约未提供解析接口时退化为提示）
    if (text.indexOf('BEGIN CERTIFICATE REQUEST') < 0 && text.indexOf('BEGIN NEW CERTIFICATE REQUEST') < 0) {
      setHTML('issCsrResult', 'CSR 内容看起来不是标准 PEM（缺少 BEGIN CERTIFICATE REQUEST 标记）。若为 DER 格式，请直接上传文件后签发。');
      show('issCsrResult', true);
      return Promise.resolve();
    }
    var b64 = text.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    setHTML('issCsrResult',
      '<strong>CSR 已就绪</strong>（PEM，Base64 长度 ' + b64.length + '）。' +
      '主题与 SAN 将在提交时由服务端解析并写入证书；此模式下不会返回私钥。' +
      '<br><span class="muted small">如需核对主题与 SAN，可先提交签发，成功后在证书详情中查看。</span>');
    show('issCsrResult', true);
    return Promise.resolve();
  }

  function resetIssueForm() {
    ['issCn', 'issO', 'issOu', 'issC', 'issSt', 'issL', 'issOwner', 'issTags', 'issNotes', 'issCsrText'].forEach(function (id) {
      if (el(id)) el(id).value = '';
    });
    if (el('issCsrFile')) el('issCsrFile').value = '';
    show('issueResultCard', false);
    applyTemplateToForm();
    renderSanRows([{ type: 'DNS', value: '' }]);
    renderIssuePreview();
    toastOk('表单已清空');
  }

  /* ====================================================================== */
  /* 10. 批量签发                                                           */
  /* ====================================================================== */

  var BATCH_HEADERS = ['cn', 'o', 'ou', 'c', 'san_dns', 'san_ip', 'email', 'upn', 'validity_days', 'profile'];

  function parseCSV(text) {
    var rows = [], row = [], field = '', inQuotes = false, i = 0;
    text = String(text || '').replace(/^\uFEFF/, '')      // Excel 导出的 CSV 常带 BOM
      .replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    while (i < text.length) {
      var ch = text[i];
      if (inQuotes) {
        if (ch === '"') {
          if (text[i + 1] === '"') { field += '"'; i += 2; continue; }
          inQuotes = false; i++; continue;
        }
        field += ch; i++; continue;
      }
      if (ch === '"') { inQuotes = true; i++; continue; }
      if (ch === ',') { row.push(field); field = ''; i++; continue; }
      if (ch === '\n') { row.push(field); rows.push(row); row = []; field = ''; i++; continue; }
      field += ch; i++;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    return rows.filter(function (r) { return r.some(function (c) { return trim(c) !== ''; }); });
  }

  function batchRowsFromCsv(text, hasHeader) {
    var raw = parseCSV(text);
    var header = null, startIdx = 0;
    if (hasHeader && raw.length) {
      header = raw[0].map(function (h) { return trim(h).toLowerCase(); });
      startIdx = 1;
      var hasCn = header.indexOf('cn') >= 0;
      if (!hasCn) { header = BATCH_HEADERS.slice(); startIdx = 0; }
    } else {
      header = BATCH_HEADERS.slice();
    }
    var rows = [], errors = [];
    for (var r = startIdx; r < raw.length; r++) {
      var line = raw[r];
      var obj = { __line: r + 1 };
      header.forEach(function (key, idx) { obj[key] = trim(line[idx] == null ? '' : line[idx]); });
      var rowErrors = [];
      if (!obj.cn) rowErrors.push('缺少 cn');
      if (obj.validity_days && !/^\d+$/.test(obj.validity_days)) rowErrors.push('validity_days 必须为整数');
      if (obj.c && !/^[A-Za-z]{2}$/.test(obj.c)) rowErrors.push('c 必须为 2 位字母');
      if (obj.profile && !state.templates.some(function (t) { return String(t.id) === obj.profile; }) && state.serverCaps.templates) {
        rowErrors.push('profile「' + obj.profile + '」不在模板列表中');
      }
      ['san_dns', 'san_ip', 'email', 'upn'].forEach(function (k) {
        if (!obj[k]) return;
        obj[k].split(/[;；]/).map(trim).filter(Boolean).forEach(function (v) {
          // 占位：稍后统一展开为 SAN
        });
      });
      obj.__errors = rowErrors;
      rows.push(obj);
    }
    return { rows: rows, errors: errors };
  }

  function batchRowToBody(row) {
    var sans = [];
    (row.san_dns || '').split(/[;；]/).map(trim).filter(Boolean).forEach(function (v) { sans.push({ type: 'DNS', value: v }); });
    (row.san_ip || '').split(/[;；]/).map(trim).filter(Boolean).forEach(function (v) { sans.push({ type: 'IP', value: v }); });
    (row.email || '').split(/[;；]/).map(trim).filter(Boolean).forEach(function (v) { sans.push({ type: 'Email', value: v }); });
    (row.upn || '').split(/[;；]/).map(trim).filter(Boolean).forEach(function (v) { sans.push({ type: 'UPN', value: v }); });
    return {
      profile: row.profile || '',
      cn: row.cn || '',
      o: row.o || '', ou: row.ou || '', c: row.c || '',
      sans: sans,
      validity_days: row.validity_days ? parseInt(row.validity_days, 10) : 0,
      owner: row.owner || '', tags: [], notes: row.notes || ''
    };
  }

  function renderBatch() {
    show('batchPreviewCard', false);
    show('batchResultCard', false);
    setText('batchHint', '先预检，确认每行解析结果后再签发。');
    el('batchSubmit').disabled = true;
    state.batch.preview = null;
    state.batch.rows = null;
    return Promise.resolve();
  }

  function batchReadCsv() {
    var text = val('batchCsv');
    var file = el('batchFile') && el('batchFile').files[0];
    if (text && trim(text)) return Promise.resolve(text);
    if (file) return file.text();
    return Promise.resolve('');
  }

  function batchPrecheck() {
    return batchReadCsv().then(function (text) {
      if (!trim(text)) { toastErr('请粘贴 CSV 内容或选择 CSV 文件'); return; }
      var parsed = batchRowsFromCsv(text, checked('batchDemo'));
      if (!parsed.rows.length) { toastErr('未解析到任何数据行'); return; }
      state.batch.rows = parsed.rows;
      var invalid = parsed.rows.filter(function (r) { return r.__errors.length; }).length;
      renderBatchPreview(parsed.rows);
      if (invalid) {
        toastWarn('预检完成：' + parsed.rows.length + ' 行，其中 ' + invalid + ' 行存在格式问题（仍会提交，由服务端复核）');
      } else {
        toastOk('预检完成：共 ' + parsed.rows.length + ' 行，格式检查通过');
      }
      el('batchSubmit').disabled = false;
      setText('batchHint', '已预检 ' + parsed.rows.length + ' 行，可点击「确认签发」。');
      show('batchPreviewCard', true);
    });
  }

  function renderBatchPreview(rows) {
    var bad = rows.filter(function (r) { return r.__errors.length; }).length;
    setText('batchPreviewStat', '共 ' + rows.length + ' 行，问题行 ' + bad);
    setHTML('batchPreview', tableHTML(
      ['行号', 'CN', 'O/OU', 'C', 'SAN', '有效期', '用途', '检查结果'],
      rows.map(function (r) {
        var sans = [r.san_dns, r.san_ip, r.email, r.upn].filter(Boolean).join(' / ');
        return {
          attrs: r.__errors.length ? ' class="row-error"' : '',
          cells: [
            { html: String(r.__line) },
            { cls: 'mono', html: esc(r.cn || '—') },
            { html: esc([r.o, r.ou].filter(Boolean).join(' / ') || '—') },
            { html: esc(r.c || '—') },
            { cls: 'mono small', html: esc(sans || '—') },
            { html: esc(r.validity_days || '（默认）') },
            { html: esc(r.profile || '（默认）') },
            { html: r.__errors.length ? '<span class="badge badge-error">' + esc(r.__errors.join('；')) + '</span>' : '<span class="badge badge-valid">通过</span>' }
          ]
        };
      })
    ));
  }

  function batchSubmit() {
    var rows = state.batch.rows;
    if (!rows || !rows.length) { toastErr('请先预检'); return Promise.resolve(); }
    var bad = rows.filter(function (r) { return r.__errors.length; }).length;
    return confirmAction({
      title: '确认批量签发',
      warning: bad ? '注意：有 ' + bad + ' 行存在格式问题，服务端可能返回失败。' : null,
      message: '将按预检结果签发 ' + rows.length + ' 张证书。该操作会写入数据库并记录审计日志。',
      impact: [['总行数', String(rows.length)], ['问题行', String(bad)]],
      okText: '确认签发', danger: bad > 0
    }).then(function (res) {
      if (!res) return;
      var payload = rows.map(batchRowToBody);
      return withButton(el('batchSubmit'), function () {
        return withLoading('正在批量签发（共 ' + payload.length + ' 行）…', function () {
          return apiPost('/api/certs/issue/batch', { rows: payload, dry_run: false }).then(function (data) {
            state.batch.result = data || {};
            renderBatchResult(state.batch.result);
            toastOk('批量签发完成：成功 ' + ((data && data.created && data.created.length) || 0) +
              ' 张，失败 ' + ((data && data.failed && data.failed.length) || 0) + ' 行');
          });
        });
      });
    });
  }

  function renderBatchResult(data) {
    var created = (data && data.created) || [];
    var failed = (data && data.failed) || [];
    setText('batchResultStat', '成功 ' + created.length + '，失败 ' + failed.length);
    var rows = created.map(function (c) {
      return {
        cells: [
          { html: '<span class="badge badge-valid">成功</span>' },
          { html: '<a class="mono" href="#/cert/' + esc(c.id) + '">' + esc(c.cn || '—') + '</a>' },
          { cls: 'mono small', html: esc(c.serial_hex || '—') },
          { html: esc(c.profile || '—') },
          { html: esc(fmtDate(c.not_after)) },
          { html: '—' }
        ]
      };
    }).concat(failed.map(function (f) {
      return {
        attrs: ' class="row-error"',
        cells: [
          { html: '<span class="badge badge-error">失败</span>' },
          { cls: 'mono', html: esc((f.row && f.row.cn) || '第 ' + (f.row && f.row.__line ? f.row.__line : '?') + ' 行') },
          { html: '—' }, { html: '—' }, { html: '—' },
          { html: esc(f.error || '未知错误') }
        ]
      };
    }));
    setHTML('batchResult', tableHTML(['结果', 'CN', '序列号', '用途', '到期时间', '错误信息'], rows, {
      emptyTitle: '没有结果', emptyDesc: '服务端未返回 created/failed 明细。'
    }));
    show('batchResultCard', true);
  }

  /* ====================================================================== */
  /* 11. 吊销与 CRL                                                         */
  /* ====================================================================== */

  function renderRevocation() {
    state.revoke.cert = null;
    state.revoke.selectedId = null;
    setHTML('revSearchResult', '<p class="muted small">输入关键词搜索证书，然后选择要吊销的证书。</p>');
    el('revSubmit').disabled = true;
    el('revUnrevoke').disabled = true;
    if (el('crlValidity')) {
      var d = state.settings && state.settings.crl_validity_days;
      el('crlValidity').value = String(d || 7);
    }
    applyCaState(state.ca, state.health);
    return Promise.all([
      loadCrl(),
      apiGet('/api/settings').then(function (s) { state.settings = s && s.settings ? s.settings : s; }).catch(function () {}),
      apiGet('/api/ca').then(function (d) { state.ca = d && d.ca ? d.ca : null; applyCaState(state.ca, state.health); }).catch(function () {})
    ]);
  }

  function loadCrl() {
    setHTML('crlInfo', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    return apiGet('/api/crl').then(function (data) {
      state.crl.crl = (data && data.crl) || null;
      state.crl.revoked = (data && data.revoked) || [];
      renderCrlInfo();
      renderCrlRevoked();
    });
  }

  function renderCrlInfo() {
    var crl = state.crl.crl;
    if (!crl) {
      setHTML('crlInfo', '<div class="callout callout-warn">当前还没有 CRL。导入 CA 私钥后可生成 CRL。</div>' +
        '<div class="row" style="margin-top:10px"><button class="btn btn-primary" type="button" data-act="crl-generate">立即生成 CRL</button></div>');
      return;
    }
    var certsAreReady = !!(state.ca && state.ca.has_key);
    setHTML('crlInfo',
      '<dl class="kv">' +
      row('CRL 编号', '<span class="mono">' + esc(crl.number == null ? '—' : crl.number) + '</span>') +
      row('本次更新', esc(fmtDateTime(crl.this_update))) +
      row('下次更新', esc(fmtDateTime(crl.next_update)) +
        (parseDate(crl.next_update) && parseDate(crl.next_update).getTime() < Date.now()
          ? ' <span class="badge badge-error">已过期，请重新生成</span>' : '')) +
      row('吊销条目数', esc(crl.entries == null ? '—' : crl.entries)) +
      row('SHA-256 指纹', '<span class="mono">' + esc(crl.sha256 || '—') + '</span>') +
      row('创建时间', esc(fmtDateTime(crl.created_at))) +
      row('文件状态', crl.has_file ? badge('已生成文件', 'badge-valid') : badge('无文件', 'badge-warning')) +
      '</dl>' +
      (certsAreReady ? '' : '<div class="callout callout-danger small" style="margin-top:10px">当前 CA 未导入私钥，无法生成新的 CRL。</div>') +
      '<div class="row" style="margin-top:10px">' +
      '<button class="btn" type="button" data-act="crl-dl" data-format="pem">下载 PEM</button>' +
      '<button class="btn" type="button" data-act="crl-dl" data-format="der">下载 DER</button>' +
      '</div>');
  }

  function renderCrlRevoked() {
    var list = state.crl.revoked || [];
    setText('crlRevokedCount', list.length + ' 条');
    setHTML('crlRevoked', tableHTML(
      ['CN', '序列号', '吊销时间', '原因'],
      list.map(function (c) {
        return {
          cells: [
            { html: '<a href="#/cert/' + esc(c.id) + '">' + esc(c.cn || '—') + '</a>' },
            { cls: 'mono small', html: esc(truncateMid(c.serial_hex || '', 16, 8)) },
            { cls: 'nowrap', html: esc(fmtDateTime(c.revoked_at)) },
            { html: esc(REVOKE_REASON_TEXT[c.revocation_reason] || c.revocation_reason || '—') }
          ]
        };
      }), { emptyTitle: '当前没有吊销条目', emptyDesc: '吊销证书后条目会出现在这里。' }
    ));
  }

  function revSearch() {
    var q = trim(val('revSearch'));
    if (!q) { toastErr('请输入搜索关键词'); return Promise.resolve(); }
    setHTML('revSearchResult', '<div class="skeleton sk-row"></div><div class="skeleton sk-row"></div>');
    return withButton(el('revSearchBtn'), function () {
      return apiGet('/api/certs', { q: q, page: 1, page_size: 20, sort: 'created_at', order: 'desc' }).then(function (data) {
        var items = (data && data.items) || [];
        if (!items.length) {
          setHTML('revSearchResult', emptyState('没有找到匹配的证书', '换个关键词试试，例如完整 CN 或序列号。'));
          return;
        }
        state.certs.items = items;
        setHTML('revSearchResult', tableHTML(
          ['选择', '状态', 'CN', '序列号', '到期时间'],
          items.map(function (c) {
            return {
              attrs: ' data-rev-row="' + esc(c.id) + '"',
              cells: [
                { html: '<button class="btn btn-sm" type="button" data-act="rev-select" data-id="' + esc(c.id) + '">选择</button>' },
                { html: statusBadge(c.status) },
                { html: '<span class="mono">' + esc(c.cn || '—') + '</span>' },
                { cls: 'mono small', html: esc(truncateMid(c.serial_hex || '', 16, 8)) },
                { cls: 'nowrap', html: esc(fmtDate(c.not_after)) }
              ]
            };
          })
        ));
      });
    });
  }

  function revSelect(id) {
    var cert = certById(id);
    state.revoke.cert = cert;
    state.revoke.selectedId = id;
    $$('#revSearchResult tr[data-rev-row]').forEach(function (tr) {
      tr.classList.toggle('row-selected', tr.getAttribute('data-rev-row') === String(id));
    });
    if (!cert) return;
    var canRevoke = cert.status !== 'revoked';
    var canUnrevoke = cert.status === 'revoked';
    el('revSubmit').disabled = !canRevoke;
    el('revUnrevoke').disabled = !canUnrevoke;
    toast('已选择：' + (cert.cn || id) + '（' + (STATUS_TEXT[cert.status] || cert.status) + '）', 'info', 2500);
  }

  function revSubmit() {
    var cert = state.revoke.cert;
    if (!cert) { toastErr('请先选择证书'); return Promise.resolve(); }
    var reason = val('revReason') || 'unspecified';
    var date = trim(val('revDate'));
    var notes = val('revNotes');
    if (date && !parseDate(date)) { toastErr('吊销时间格式不正确，请使用 ISO8601（如 2026-01-01T00:00:00+08:00）'); return Promise.resolve(); }
    return confirmAction({
      title: '确认吊销证书',
      warning: '吊销后该证书将立即失效，并被写入 CRL。除 certificateHold 外不可恢复。',
      message: '请确认吊销以下证书：',
      impact: [
        ['通用名 CN', cert.cn || '—'],
        ['序列号', cert.serial_hex || '—'],
        ['当前状态', STATUS_TEXT[cert.status] || cert.status],
        ['吊销原因', REVOKE_REASON_TEXT[reason] || reason],
        ['吊销时间', date || '（当前时间）'],
        ['备注', notes || '（无）']
      ],
      okText: '确认吊销', danger: true
    }).then(function (res) {
      if (!res) return;
      return withButton(el('revSubmit'), function () {
        return apiPost('/api/certs/' + encodeURIComponent(cert.id) + '/revoke', {
          reason: reason, revocation_date: date, notes: notes
        }).then(function (data) {
          toastOk('证书已吊销' + (data && data.crl ? '，已生成 CRL #' + data.crl.number : ''));
          state.revoke.cert = (data && data.cert) || cert;
          if (state.revoke.cert) state.revoke.cert.status = 'revoked';
          el('revSubmit').disabled = true;
          el('revUnrevoke').disabled = false;
          if (el('revReason')) el('revReason').value = 'unspecified';
          if (el('revDate')) el('revDate').value = '';
          if (el('revNotes')) el('revNotes').value = '';
          return loadCrl();
        });
      });
    });
  }

  function revUnrevoke() {
    var cert = state.revoke.cert;
    if (!cert) { toastErr('请先选择证书'); return Promise.resolve(); }
    return confirmAction({
      title: '恢复吊销（危险）',
      warning: '恢复后该证书重新被视为有效，可能被继续信任。此操作仅对 certificateHold 挂起的证书有意义。',
      message: '确认恢复以下证书的吊销状态？',
      impact: [
        ['通用名 CN', cert.cn || '—'],
        ['序列号', cert.serial_hex || '—'],
        ['吊销时间', fmtDateTime(cert.revoked_at)],
        ['吊销原因', REVOKE_REASON_TEXT[cert.revocation_reason] || cert.revocation_reason || '—']
      ],
      okText: '确认恢复', danger: true, confirmWord: 'RESTORE'
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/certs/' + encodeURIComponent(cert.id) + '/unrevoke', { confirm: true }).then(function (data) {
        toastOk('已恢复吊销状态' + (data && data.crl ? '，CRL #' + data.crl.number : '')
          + (data && data.publish ? '，已发布并重载 strongSwan' : '')
          + (data && data.publish_error ? '（发布失败：' + data.publish_error + '）' : ''));
        state.revoke.cert = (data && data.cert) || null;
        el('revUnrevoke').disabled = true;
        el('revSubmit').disabled = false;
        return loadCrl();
      });
    });
  }

  function crlGenerate() {
    var validity = parseInt(val('crlValidity'), 10) || 0;
    if (validity < 1 || validity > 3650) { toastErr('CRL 有效期需为 1–3650 之间的整数'); return Promise.resolve(); }
    var nextUpdate = parseInt(val('crlNextUpdate'), 10);
    var body = {
      validity_days: validity,
      next_update_days: (nextUpdate && nextUpdate > 0) ? nextUpdate : validity,
      digest: val('crlDigest') || 'sha256',
      force: checked('crlForce')
    };
    return confirmAction({
      title: '生成 CRL',
      message: '将发布新的 CRL（吊销列表），旧的 CRL 会被替换。是否继续？',
      impact: [
        ['本次有效期', validity + ' 天'],
        ['下次更新', body.next_update_days + ' 天'],
        ['摘要算法', body.digest],
        ['强制生成', body.force ? '是' : '否'],
        ['当前吊销条目', String((state.crl.revoked || []).length)]
      ],
      okText: '生成 CRL'
    }).then(function (res) {
      if (!res) return;
      return withButton(el('crlGenerate'), function () {
        return withLoading('正在生成 CRL…', function () {
          return apiPost('/api/crl/generate', body).then(function (data) {
            state.crl.crl = (data && data.crl) || state.crl.crl;
            toastOk('CRL 已生成' + (state.crl.crl ? '（编号 ' + state.crl.crl.number + '）' : ''));
            return loadCrl();
          });
        });
      });
    });
  }

  function crlDownload(format) {
    if (!state.crl.crl) { toastErr('当前没有可下载的 CRL，请先生成'); return Promise.resolve(); }
    return downloadApi('/api/crl/download', { format: format }, 'ca.' + (format === 'der' ? 'crl' : 'pem'));
  }

  function crlImport() {
    var file = el('crlImportFile') && el('crlImportFile').files[0];
    if (!file) { toastErr('请选择 CRL 文件'); return Promise.resolve(); }
    return file.text().then(function (text) {
      // 先展示影响面：在本地证书列表中查找可能被标记的证书（按 CRL 文本中的序列号粗匹配）
      var serials = extractSerialsFromCrlText(text);
      var willMark = [];
      if (serials.length) {
        willMark = (state.certs.items || []).filter(function (c) {
          return serials.indexOf(String(c.serial_hex || '').toUpperCase()) >= 0 && c.status !== 'revoked';
        });
      }
      var impactHTML = serials.length
        ? '<div class="impact"><div class="small muted">文件中共发现 ' + serials.length +
          ' 个序列号（前端粗解析），其中本地匹配到 ' + willMark.length + ' 张可能被标记为已吊销：</div>' +
          (willMark.length ? '<ul class="small">' + willMark.slice(0, 10).map(function (c) {
            return '<li class="mono">' + esc(c.cn || '') + ' · ' + esc(truncateMid(c.serial_hex || '', 16, 8)) + '</li>';
          }).join('') + (willMark.length > 10 ? '<li>…等 ' + willMark.length + ' 张</li>' : '') + '</ul>'
            : '<div class="small">本地未匹配到对应证书（可能不在当前列表页中，最终以服务端结果为准）。</div>') + '</div>'
        : '<div class="callout small">无法在前端解析 CRL 序列号（可能为 DER 格式），最终影响以服务端返回为准。</div>';

      return confirmAction({
        title: '导入 CRL 并同步吊销状态',
        warning: '导入后，本地数据库中与该 CRL 序列号匹配的证书会被标记为「已吊销」，并记录审计日志。',
        message: '确认导入文件「' + file.name + '」？',
        html: impactHTML,
        okText: '确认导入', danger: true
      }).then(function (res) {
        if (!res) return;
        var fd = new FormData();
        fd.append('file', file);
        return withButton(el('crlImportBtn'), function () {
          return withLoading('正在导入 CRL…', function () {
            return apiForm('/api/crl/import', fd).then(function (data) {
              var updated = (data && data.updated) || [];
              var unknown = (data && data.unknown) || [];
              setHTML('crlImportResult',
                '<div class="section"><h3>导入结果</h3>' +
                '<p>已同步标记：<strong>' + updated.length + '</strong> 张；未在库中找到：<strong>' + unknown.length + '</strong> 条。</p>' +
                (updated.length ? '<div class="table-wrap">' + tableHTML(['CN', '序列号'],
                  updated.map(function (c) {
                    return { cells: [{ html: esc(c.cn || '—') }, { cls: 'mono small', html: esc(truncateMid(c.serial_hex || '', 16, 8)) }] };
                  })) + '</div>' : '') +
                (unknown.length ? '<p class="muted small">未匹配序列号：' +
                  esc(unknown.slice(0, 20).map(function (u) { return u.serial || (u.subject || ''); }).join('、')) +
                  (unknown.length > 20 ? ' …' : '') + '</p>' : '') +
                '</div>');
              toastOk('CRL 导入完成');
              return loadCrl();
            });
          });
        });
      });
    });
  }

  function extractSerialsFromCrlText(text) {
    // 仅做粗解析：从 PEM/DER 文本中提取连续 16–40 位十六进制串，作为候选序列号
    var out = [];
    var re = /\b[0-9A-Fa-f]{16,40}\b/g, m;
    while ((m = re.exec(text)) !== null) out.push(m[0].toUpperCase());
    return out;
  }

  /* ====================================================================== */
  /* 12. 导入数据                                                           */
  /* ====================================================================== */

  function renderImport() {
    setImportTab(state.imp.tab || 'files');
    show('impResultCard', false);
    return Promise.resolve();
  }

  function setImportTab(tab) {
    state.imp.tab = tab;
    $$('#importTabs .tab').forEach(function (t) {
      t.classList.toggle('active', t.getAttribute('data-import-tab') === tab);
    });
    $$('.import-pane').forEach(function (p) {
      p.hidden = p.getAttribute('data-import-pane') !== tab;
    });
  }

  function renderImportResult(title, data, kind) {
    var preview = (data && data.preview) || (kind === 'preview' ? null : null);
    var imported = (data && data.imported) || [];
    var skipped = (data && data.skipped) || [];
    var errors = (data && data.errors) || [];
    setText('impResultStat', kind === 'preview'
      ? ('预检 ' + (preview ? preview.length : 0) + ' 项')
      : ('导入 ' + imported.length + ' / 跳过 ' + skipped.length + ' / 错误 ' + errors.length));
    var html = '<div class="section"><h3>' + esc(title) + '</h3>';
    html += '<p>导入 <span class="badge badge-valid">' + imported.length + '</span> ' +
      '跳过 <span class="badge">' + skipped.length + '</span> ' +
      '错误 <span class="badge badge-error">' + errors.length + '</span></p>';
    var rows = [];
    if (preview && preview.length) {
      rows = preview.map(function (it) {
        var dup = it.duplicate || it.in_db || it.already_exists;
        return {
          cells: [
            { html: '<span class="badge">待导入</span>' },
            { cls: 'mono', html: esc(it.cn || it.name || '—') },
            { cls: 'mono small', html: esc(truncateMid(it.serial_hex || '', 16, 8)) },
            { html: esc(it.issuer || '—') },
            { html: esc(fmtDate(it.not_after)) },
            { html: it.belongs_to_ca === false ? badge('不属于当前 CA', 'badge-warning') : badge('属于当前 CA', 'badge-valid') },
            { html: dup ? badge('重复', 'badge-warning') : badge('新增', 'badge-valid') }
          ]
        };
      });
    } else {
      // 无 preview 字段时把 imported/skipped/errors 合成明细表
      imported.forEach(function (c) {
        rows.push({
          cells: [
            { html: badge('已导入', 'badge-valid') },
            { cls: 'mono', html: esc(c.cn || '—') },
            { cls: 'mono small', html: esc(truncateMid(c.serial_hex || '', 16, 8)) },
            { html: esc(c.issuer || '—') }, { html: esc(fmtDate(c.not_after)) },
            { html: '—' }, { html: '—' }
          ]
        });
      });
      skipped.forEach(function (it) {
        rows.push({
          cells: [
            { html: badge('已跳过', 'badge-warning') },
            { cls: 'mono', html: esc(it.cn || it.name || '—') },
            { cls: 'mono small', html: esc(truncateMid(it.serial_hex || it.serial || '', 16, 8)) },
            { html: esc(it.issuer || '—') }, { html: '—' },
            { html: '—' },
            { html: esc(it.reason || it.error || '重复或已存在') }
          ]
        });
      });
      errors.forEach(function (e) {
        rows.push({
          attrs: ' class="row-error"',
          cells: [
            { html: badge('错误', 'badge-error') },
            { cls: 'mono', html: esc(e.name || '—') },
            { html: '—' }, { html: '—' }, { html: '—' }, { html: '—' },
            { html: esc(e.error || '未知错误') }
          ]
        });
      });
    }
    html += '<div class="table-wrap">' + tableHTML(
      ['状态', 'CN / 文件', '序列号', '签发者', '到期时间', 'CA 归属', '说明'],
      rows, { emptyTitle: '没有明细', emptyDesc: '服务端未返回 preview/imported/skipped/errors 数据。' }
    ) + '</div></div>';
    setHTML('impResult', html);
    show('impResultCard', true);
    el('impResultCard').scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  function collectTags(id) {
    var t = trim(val(id));
    return t ? t.split(/[,，]/).map(trim).filter(Boolean) : [];
  }

  function importFiles(dryRun) {
    var files = el('impFiles') && el('impFiles').files;
    if (!files || !files.length) { toastErr('请选择证书文件（可多选或选择 zip）'); return Promise.resolve(); }
    var fd = new FormData();
    for (var i = 0; i < files.length; i++) fd.append('files', files[i]);
    fd.append('dry_run', dryRun ? 'true' : 'false');
    fd.append('mark_revoked', checked('impMarkRevoked') ? 'true' : 'false');
    fd.append('revoke_reason', val('impRevokeReason') || 'unspecified');
    if (trim(val('impOwner'))) fd.append('owner', trim(val('impOwner')));
    var tags = collectTags('impTags');
    if (tags.length) fd.append('tags', JSON.stringify(tags));

    var btn = dryRun ? el('impFilesPrecheck') : el('impFilesImport');
    return withButton(btn, function () {
      return withLoading(dryRun ? '正在预检文件…' : '正在导入文件…', function () {
        return apiForm('/api/certs/import', fd).then(function (data) {
          if (dryRun) {
            renderImportResult('预检结果（未写入）', data, 'preview');
            var n = (data && data.preview && data.preview.length) || 0;
            toastOk('预检完成，共 ' + n + ' 项');
            el('impFilesImport').disabled = false;
          } else {
            renderImportResult('导入结果', data, 'import');
            toastOk('导入完成');
            el('impFilesImport').disabled = true;
          }
        });
      });
    });
  }

  function importDir(dryRun) {
    var path = trim(val('impDirPath'));
    if (!path) { toastErr('请填写服务器目录绝对路径'); return Promise.resolve(); }
    var payload = {
      path: path,
      dry_run: !!dryRun,
      mark_revoked: checked('impDirMarkRevoked'),
      owner: trim(val('impDirOwner'))
    };
    var btn = dryRun ? el('impDirPrecheck') : el('impDirImport');
    var run = function () {
      return withButton(btn, function () {
        return withLoading(dryRun ? '正在扫描目录…' : '正在从目录导入…', function () {
          return apiPost('/api/certs/import/dir', payload).then(function (data) {
            renderImportResult(dryRun ? '目录预检结果（未写入）' : '目录导入结果', data, dryRun ? 'preview' : 'import');
            toastOk(dryRun ? '目录预检完成' : '目录导入完成');
            if (dryRun) el('impDirImport').disabled = false;
          });
        });
      });
    };
    if (dryRun) return run();
    return confirmAction({
      title: '确认从目录导入',
      warning: '将从服务器目录读取证书并写入数据库，重复证书会被跳过。',
      impact: [['目录', path], ['标记为已吊销', checked('impDirMarkRevoked') ? '是' : '否']],
      okText: '确认导入'
    }).then(function (res) { if (res) return run(); });
  }

  function importCsv(dryRun) {
    var file = el('impCsvFile') && el('impCsvFile').files[0];
    var text = val('impCsvText');
    if (!file && !trim(text)) { toastErr('请选择 CSV 文件或粘贴 CSV 文本'); return Promise.resolve(); }
    var btn = dryRun ? el('impCsvPrecheck') : el('impCsvImport');
    return withButton(btn, function () {
      return withLoading(dryRun ? '正在预检 CSV…' : '正在导入 CSV…', function () {
        var p;
        if (file) {
          var fd = new FormData();
          fd.append('file', file);
          fd.append('dry_run', dryRun ? 'true' : 'false');
          p = apiForm('/api/certs/import/csv', fd);
        } else {
          p = apiPost('/api/certs/import/csv', { csv_text: text, dry_run: !!dryRun });
        }
        return p.then(function (data) {
          renderImportResult(dryRun ? 'CSV 预检结果（未写入）' : 'CSV 导入结果', data, dryRun ? 'preview' : 'import');
          toastOk(dryRun ? 'CSV 预检完成' : 'CSV 导入完成');
          if (dryRun) el('impCsvImport').disabled = false;
        });
      });
    });
  }

  /* ====================================================================== */
  /* 13. 一致性体检                                                         */
  /* ====================================================================== */

  function renderConsistency() {
    var last = null;
    try { last = localStorage.getItem('ca_last_consistency'); } catch (e) {}
    setText('consistencyLast', '上次体检：' + (last ? fmtDateTime(last) : '—'));
    setHTML('consSummary', '');
    setHTML('consIssues', '');
    el('consRepairAll').disabled = true;
    return Promise.resolve();
  }

  function consCheck() {
    state.consistency.selected = {};
    show('consProgress', true);
    return withButton(el('consCheckBtn'), function () {
      return apiPost('/api/consistency/check', {}).then(function (data) {
        state.consistency.checked_at = (data && data.checked_at) || new Date().toISOString();
        state.consistency.summary = (data && data.summary) || { error: 0, warning: 0, info: 0 };
        state.consistency.issues = (data && data.issues) || [];
        try { localStorage.setItem('ca_last_consistency', state.consistency.checked_at); } catch (e) {}
        setText('consistencyLast', '上次体检：' + fmtDateTime(state.consistency.checked_at));
        consPaint();
        toastOk('体检完成：错误 ' + (state.consistency.summary.error || 0) +
          '、警告 ' + (state.consistency.summary.warning || 0) +
          '、提示 ' + (state.consistency.summary.info || 0));
      }).finally(function () { show('consProgress', false); });
    });
  }

  var LEVEL_TEXT = { error: '错误', warning: '警告', info: '提示' };
  var LEVEL_CLASS = { error: 'badge-error', warning: 'badge-warning', info: 'badge-info' };

  function consPaint() {
    var s = state.consistency.summary || {};
    setHTML('consSummary',
      '<div class="stat"><div class="stat-label">错误</div><div class="stat-value danger">' + (s.error || 0) + '</div><div class="stat-sub">需要立即处理</div></div>' +
      '<div class="stat"><div class="stat-label">警告</div><div class="stat-value warn">' + (s.warning || 0) + '</div><div class="stat-sub">建议尽快处理</div></div>' +
      '<div class="stat"><div class="stat-label">提示</div><div class="stat-value">' + (s.info || 0) + '</div><div class="stat-sub">可优化项</div></div>');

    var issues = state.consistency.issues || [];
    var fixable = issues.filter(function (i) { return i.fixable; });
    el('consRepairAll').disabled = !fixable.length;
    el('consRepairAll').textContent = fixable.length ? ('一键修复全部可修复项（' + fixable.length + '）') : '一键修复全部可修复项';

    if (!issues.length) {
      setHTML('consIssues', '<div class="card"><div class="card-body">' +
        emptyState('未发现问题', '当前数据一致。') + '</div></div>');
      return;
    }
    ['error', 'warning', 'info'].forEach(function (level) { /* 占位，保持顺序稳定 */ });
    var groups = { error: [], warning: [], info: [] };
    issues.forEach(function (i) { (groups[i.level] || groups.info).push(i); });
    setHTML('consIssues', ['error', 'warning', 'info'].map(function (level) {
      var list = groups[level];
      if (!list.length) return '';
      return '<div class="card"><div class="card-head">' +
        '<h2>' + esc(LEVEL_TEXT[level]) + '</h2>' + badge(list.length + ' 项', LEVEL_CLASS[level]) +
        '</div><div class="card-body no-pad"><div class="table-wrap">' +
        tableHTML(['选择', '代码', '说明', '对象', '操作'], list.map(function (i) {
          return {
            cells: [
              { html: i.fixable ? '<input type="checkbox" data-act="cons-pick" data-code="' + esc(i.code) + '"' + (state.consistency.selected[i.code] ? ' checked' : '') + '>' : '<span class="faint">—</span>' },
              { cls: 'mono small', html: esc(i.code || '—') },
              { html: esc(i.message || '—') },
              { cls: 'mono small', html: esc(i.entity || '—') },
              { html: i.fixable ? '<button class="btn btn-sm" type="button" data-act="cons-fix" data-code="' + esc(i.code) + '">修复</button>' : '<span class="faint small">需人工处理</span>' }
            ]
          };
        })) + '</div></div></div>';
    }).join(''));
  }

  function consFix(code) {
    return confirmAction({
      title: '执行修复',
      message: '将对问题「' + code + '」执行自动修复。是否继续？',
      html: '<div class="callout small">修复会修改数据库中的对应记录，并记录审计日志。</div>',
      okText: '确认修复'
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/consistency/repair', { codes: [code] }).then(function (data) {
        var repaired = (data && data.repaired) || [];
        toastOk('修复完成' + (repaired.length ? '：' + repaired.length + ' 项' : ''));
        return consCheck();
      });
    });
  }

  function consFixAll() {
    var codes = Object.keys(state.consistency.selected).filter(function (k) { return state.consistency.selected[k]; });
    if (!codes.length) {
      codes = (state.consistency.issues || []).filter(function (i) { return i.fixable; }).map(function (i) { return i.code; });
    }
    codes = codes.filter(function (v, i, a) { return a.indexOf(v) === i; });
    if (!codes.length) { toastErr('没有可修复项'); return Promise.resolve(); }
    return confirmAction({
      title: '一键修复全部可修复项',
      warning: '将批量修改数据库中的对应记录。',
      message: '即将修复以下 ' + codes.length + ' 类问题：',
      html: '<div class="impact mono small">' + esc(codes.join('、')) + '</div>',
      okText: '确认修复'
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/consistency/repair', { codes: codes }).then(function (data) {
        var repaired = (data && data.repaired) || [];
        toastOk('修复完成' + (repaired.length ? '：' + repaired.length + ' 项' : ''));
        return consCheck();
      });
    });
  }

  /* ====================================================================== */
  /* 14. 审计日志                                                           */
  /* ====================================================================== */

  var AUDIT_ACTIONS = [
    'login', 'logout', 'ca_import', 'ca_activate', 'cert_issue', 'cert_issue_batch',
    'cert_renew', 'cert_revoke', 'cert_unrevoke', 'cert_import', 'cert_update',
    'cert_delete', 'crl_generate', 'crl_import', 'consistency_check', 'consistency_repair',
    'settings_update', 'backup_create', 'backup_restore'
  ];

  function renderAudit(query) {
    if (el('auditAction') && !el('auditAction').dataset.filled) {
      fillSelect(el('auditAction'), [{ v: '', t: '全部操作类型' }].concat(
        AUDIT_ACTIONS.map(function (a) { return { v: a, t: a }; })
      ), state.audit.action);
      el('auditAction').dataset.filled = '1';
    }
    if (query && query.q) state.audit.q = query.q;
    if (el('auditQ')) el('auditQ').value = state.audit.q;
    if (el('auditAction')) el('auditAction').value = state.audit.action;
    if (el('auditPageSize')) el('auditPageSize').value = String(state.audit.page_size);
    return fetchAudit();
  }

  function fetchAudit() {
    var a = state.audit;
    setHTML('auditTable', skeletonTable(5, 6));
    setHTML('auditPager', '');
    return apiGet('/api/audit', {
      page: a.page, page_size: a.page_size, action: a.action, q: a.q
    }).then(function (data) {
      a.items = (data && data.items) || [];
      a.total = (data && data.total) || 0;
      renderAuditTable();
      renderAuditPager();
    }).catch(function (err) {
      setHTML('auditTable', '<div class="empty"><div class="empty-title">加载失败</div><div class="small">' +
        esc(err && err.message ? err.message : '未知错误') + '</div></div>');
      throw err;
    });
  }

  function renderAuditTable() {
    var items = state.audit.items;
    setHTML('auditTable', tableHTML(
      ['时间', '操作', '对象', '操作人', '详情'],
      items.map(function (a) {
        var d = typeof a.detail === 'string' ? a.detail : jsonPretty(a.detail);
        return {
          attrs: ' data-audit-row="' + esc(a.id) + '"',
          cells: [
            { cls: 'nowrap', html: esc(fmtDateTime(a.ts)) + '<br><span class="faint small">' + esc(fmtRelative(a.ts)) + '</span>' },
            { cls: 'mono', html: esc(a.action || '—') },
            { html: esc(a.target_label || a.target_id || '—') + (a.target_type ? '<br><span class="faint small">' + esc(a.target_type) + '</span>' : '') },
            { html: esc(a.actor || '—') },
            {
              html: '<div class="row"><button class="btn btn-sm" type="button" data-act="audit-toggle" data-id="' + esc(a.id) + '">展开 JSON</button></div>' +
                '<pre class="pem" id="auditDetail-' + esc(a.id) + '" hidden style="margin-top:6px;max-height:200px">' + esc(d || '（无详情）') + '</pre>'
            }
          ]
        };
      }), { emptyTitle: '暂无审计日志', emptyDesc: '关键操作会自动记录在这里。' }
    ));
  }

  function renderAuditPager() {
    var a = state.audit;
    var totalPages = Math.max(1, Math.ceil(a.total / a.page_size));
    var from = a.total ? (a.page - 1) * a.page_size + 1 : 0;
    var to = Math.min(a.total, a.page * a.page_size);
    setHTML('auditPager',
      '<span class="pager-info">共 ' + a.total + ' 条，当前 ' + from + '–' + to + '，第 ' + a.page + '/' + totalPages + ' 页</span>' +
      '<button class="btn" type="button" data-act="audit-page" data-page="1"' + (a.page <= 1 ? ' disabled' : '') + '>«</button>' +
      '<button class="btn" type="button" data-act="audit-page" data-page="' + (a.page - 1) + '"' + (a.page <= 1 ? ' disabled' : '') + '>上一页</button>' +
      '<button class="btn" type="button" data-act="audit-page" data-page="' + (a.page + 1) + '"' + (a.page >= totalPages ? ' disabled' : '') + '>下一页</button>' +
      '<button class="btn" type="button" data-act="audit-page" data-page="' + totalPages + '"' + (a.page >= totalPages ? ' disabled' : '') + '>»</button>');
  }

  function auditGoPage(p) {
    var a = state.audit;
    var totalPages = Math.max(1, Math.ceil(a.total / a.page_size));
    p = Math.min(Math.max(1, Number(p) || 1), totalPages);
    if (p === a.page) return;
    a.page = p;
    fetchAudit().catch(function () {});
  }

  /* ====================================================================== */
  /* 15. CA 管理                                                            */
  /* ====================================================================== */

  function applyCaState(ca, health) {
    var noCa = !ca;
    var noKey = !!(ca && ca.has_key === false);
    if (noCa && health && health.ca_ready) { /* health 兜底：说明服务端认为 CA 就绪 */ noCa = false; noKey = false; }
    show('noCaBanner', noCa && state.route !== '#/ca');
    show('caWarnBanner', !noCa && noKey);
  }

  function renderCa() {
    setHTML('caCurrent', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    setHTML('caHistory', skeletonTable(6, 3));
    return Promise.all([
      apiGet('/api/ca').then(function (d) { state.ca = (d && d.ca) || null; }).catch(function () { state.ca = null; }),
      apiGet('/api/ca/list').then(function (d) { state.caList = (d && d.items) || []; }).catch(function () { state.caList = []; })
    ]).then(function () {
      renderCaCurrent();
      renderCaHistory();
      applyCaState(state.ca, state.health);
    });
  }

  function renderCaCurrent() {
    var ca = state.ca;
    if (!ca) {
      setHTML('caCurrent',
        '<div class="callout callout-danger"><strong>尚未导入 CA。</strong>' +
        '请使用右侧表单导入 CA 证书（与私钥）。没有 CA 时无法签发证书或生成 CRL。</div>');
      return;
    }
    setHTML('caCurrent',
      '<dl class="kv">' +
      row('主题', '<span class="mono">' + esc(ca.subject || '—') + '</span>') +
      row('通用名 CN', esc(ca.cn || '—')) +
      row('序列号', '<span class="mono">' + esc(ca.serial_hex || '—') + '</span>') +
      row('指纹 SHA-256', '<span class="mono">' + esc(ca.fingerprint_sha256 || '—') + '</span>') +
      row('有效期', esc(fmtDateTime(ca.not_before)) + ' → ' + esc(fmtDateTime(ca.not_after)) +
        (daysRemaining(ca) != null && daysRemaining(ca) < 0 ? ' <span class="badge badge-error">已过期</span>' : '')) +
      row('密钥算法', esc((ca.key_type || '—') + ' ' + (ca.key_size || ''))) +
      row('私钥状态', ca.has_key ? badge('已导入私钥', 'badge-valid') : badge('未导入私钥', 'badge-warning')) +
      row('是否当前 CA', ca.is_active ? badge('当前使用', 'badge-primary') : badge('历史 CA', 'badge-dim')) +
      row('导入时间', esc(fmtDateTime(ca.created_at))) +
      '</dl>' +
      (ca.has_key ? '' :
        '<div class="callout callout-danger" style="margin-top:10px">' +
        '<strong>未导入私钥：无法签发证书，也无法生成 CRL。</strong>' +
        '请在右侧「导入 CA」中一并上传私钥文件（如有口令请填写）。</div>') +
      '<div class="row" style="margin-top:12px">' +
      '<button class="btn" type="button" data-act="ca-dl" data-format="pem">下载 CA 证书 PEM</button>' +
      '<button class="btn" type="button" data-act="ca-dl" data-format="der">下载 CA 证书 DER</button>' +
      (ca.is_active ? '' : '<button class="btn btn-primary" type="button" data-act="ca-activate" data-id="' + esc(ca.id) + '">设为当前 CA</button>') +
      '</div>');
  }

  function renderCaHistory() {
    var list = state.caList || [];
    setHTML('caHistory', tableHTML(
      ['CN', '序列号', '指纹 SHA-256', '有效期', '私钥', '状态', '操作'],
      list.map(function (ca) {
        return {
          cells: [
            { cls: 'mono', html: esc(ca.cn || '—') },
            { cls: 'mono small', html: esc(truncateMid(ca.serial_hex || '', 16, 8)) },
            { cls: 'mono small', html: esc(truncateMid(ca.fingerprint_sha256 || '', 20, 10)) },
            { cls: 'nowrap', html: esc(fmtDate(ca.not_before)) + ' → ' + esc(fmtDate(ca.not_after)) },
            { html: ca.has_key ? badge('有', 'badge-valid') : badge('无', 'badge-warning') },
            { html: ca.is_active ? badge('当前使用', 'badge-primary') : badge('历史', 'badge-dim') },
            {
              html: '<div class="actions">' +
                '<button class="btn" type="button" data-act="ca-dl-id" data-id="' + esc(ca.id) + '" data-format="pem">下载</button>' +
                (ca.is_active ? '' : '<button class="btn" type="button" data-act="ca-activate" data-id="' + esc(ca.id) + '">设为当前</button>') +
                '</div>'
            }
          ]
        };
      }), { emptyTitle: '还没有历史 CA', emptyDesc: '导入 CA 后会出现在这里。' }
    ));
  }

  function caImport() {
    var certFile = el('caCertFile') && el('caCertFile').files[0];
    if (!certFile) { toastErr('请选择 CA 证书文件'); return Promise.resolve(); }
    var keyFile = el('caKeyFile') && el('caKeyFile').files[0];
    var chainFile = el('caChainFile') && el('caChainFile').files[0];
    var pwd = val('caKeyPassword');
    var impact = [
      ['CA 证书文件', certFile.name],
      ['私钥文件', keyFile ? keyFile.name : '（未提供，导入后无法签发/生成 CRL）'],
      ['证书链文件', chainFile ? chainFile.name : '（无）'],
      ['私钥口令', pwd ? '已填写' : '（未填写）']
    ];
    return confirmAction({
      title: '导入 CA 并设为当前 CA',
      warning: '导入后该 CA 将成为当前签发 CA。若已有历史 CA，原 CA 会被保留为历史记录。',
      message: '确认导入以下 CA 材料？',
      impact: impact,
      okText: '确认导入'
    }).then(function (res) {
      if (!res) return;
      var fd = new FormData();
      fd.append('cert', certFile);
      if (keyFile) fd.append('key', keyFile);
      if (chainFile) fd.append('chain', chainFile);
      if (pwd) fd.append('password', pwd);
      return withButton(el('caImportBtn'), function () {
        return withLoading('正在导入 CA…', function () {
          return apiForm('/api/ca/import', fd).then(function (data) {
            state.ca = (data && data.ca) || null;
            toastOk('CA 导入成功');
            el('caImportReset').click();
            return renderCa();
          });
        });
      });
    });
  }

  function caActivate(id) {
    var ca = null;
    (state.caList || []).forEach(function (c) { if (String(c.id) === String(id)) ca = c; });
    if (!ca && state.ca && String(state.ca.id) === String(id)) ca = state.ca;
    return confirmAction({
      title: '设为当前 CA',
      warning: '切换当前 CA 后，新签发的证书将由该 CA 签发；已有证书不受影响。',
      message: '确认将下列 CA 设为当前 CA？',
      impact: [
        ['通用名 CN', (ca && ca.cn) || '—'],
        ['序列号', (ca && ca.serial_hex) || '—'],
        ['私钥', ca && ca.has_key ? '已导入（可签发）' : '未导入私钥（切换后无法签发与生成 CRL）']
      ],
      okText: '确认切换'
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/ca/activate', { id: id }).then(function (data) {
        state.ca = (data && data.ca) || null;
        toastOk('已切换当前 CA');
        return renderCa();
      });
    });
  }

  function caDownload(id, format, cert) {
    return downloadApi('/api/ca/' + encodeURIComponent(id) + '/download', { format: format },
      'ca-' + String((cert && cert.cn) || id).replace(/[\\/:*?"<>|\s]+/g, '_') + '.' + (format === 'der' ? 'der' : 'pem'));
  }

  /* ====================================================================== */
  /* 16. 设置                                                               */
  /* ====================================================================== */

  function renderSettings() {
    setHTML('backupList', skeletonTable(4, 3));
    setHTML('ssStatusBody', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    setHTML('setDefaultRuleset', '<option value="">加载中…</option>');
    return Promise.all([
      apiGet('/api/settings').then(function (data) {
        state.settings = (data && data.settings) || data || {};
        var s = state.settings;
        if (el('setOrg')) el('setOrg').value = s.org_name || '';
        if (el('setValidity')) el('setValidity').value = s.default_validity_days == null ? '' : s.default_validity_days;
        if (el('setCrlValidity')) el('setCrlValidity').value = s.crl_validity_days == null ? '' : s.crl_validity_days;
        if (el('setCrlUrl')) el('setCrlUrl').value = s.crl_url || '';
        if (el('setVpnGateway')) el('setVpnGateway').value = s.vpn_gateway || '';
        setText('brandOrg', s.org_name || (state.ca && state.ca.cn) || '未配置机构');
      }),
      loadBackups(),
      loadRulesetOptions(),
      loadStrongswanStatus()
    ]);
  }

  function settingsSave() {
    var gateway = trim(val('setVpnGateway'));
    var defaultPick = el('setDefaultRuleset') ? val('setDefaultRuleset') : '';
    var body = {
      org_name: trim(val('setOrg')),
      default_validity_days: parseInt(val('setValidity'), 10) || 0,
      crl_validity_days: parseInt(val('setCrlValidity'), 10) || 0,
      crl_url: trim(val('setCrlUrl')),
      vpn_gateway: gateway
    };
    return withButton(el('setSaveBtn'), function () {
      return apiPatch('/api/settings', body).then(function (data) {
        var saved = (data && data.settings) || {};
        state.settings = Object.assign({}, state.settings, body, saved);
        /* 后端设置接口未声明 vpn_gateway 时，返回体里不会有该字段；
           这里保留本地值，供「生成配置片段 / 部署包」立即使用。 */
        if (saved.vpn_gateway === undefined) state.settings.vpn_gateway = gateway;
        toastOk('设置已保存');
        setText('brandOrg', state.settings.org_name || '未配置机构');
        var prevDefault = state.rulesets.default_slug || '';
        if (defaultPick !== prevDefault) {
          return apiPost('/api/rulesets/default', { slug: defaultPick }).then(function () {
            state.rulesets.default_slug = defaultPick;
            toastOk('默认规则集已更新');
          });
        }
      });
    });
  }

  /* 规则集下拉（设置页默认规则集 / 详情提示） */
  function loadRulesetOptions() {
    return apiGet('/api/rulesets').then(function (d) {
      d = d || {};
      if (d.items && d.items.length) state.rulesets.items = d.items;
      state.rulesets.default_slug = d.default_ruleset || state.rulesets.default_slug || '';
      var sel = el('setDefaultRuleset');
      if (!sel) return;
      sel.innerHTML = '<option value="">（未设置，使用第一个启用的规则集）</option>' +
        (d.items || []).map(function (rs) {
          return '<option value="' + esc(rs.slug) + '"' +
            (d.default_ruleset === rs.slug ? ' selected' : '') + '>' +
            esc(rs.name) + '（' + esc(rs.slug) + '）' + (rs.enabled ? '' : ' — 已停用') + '</option>';
        }).join('');
    }).catch(function () {
      setHTML('setDefaultRuleset', '<option value="">（无法加载规则集）</option>');
    });
  }

  function loadStrongswanStatus() {
    setHTML('ssStatusBody', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    return apiGet('/api/strongswan/status', null, { timeout: 30000 }).then(function (d) {
      state.ssStatus = d || {};
      paintStrongswanStatus();
    }).catch(function (err) {
      setHTML('ssStatusBody', '<div class="callout callout-warn small">无法获取 strongSwan 状态：' +
        esc((err && err.message) || '未知错误') + '</div>');
    });
  }

  function paintStrongswanStatus() {
    var d = state.ssStatus || {};
    var ss = d.strongswan || {};
    var caRow = d.ca || null;
    var html = '<dl class="kv">' +
      row('strongSwan', ss.swanctl ? badge('swanctl 可用', 'badge-valid')
        : (ss.ipsec ? badge('ipsec 可用', 'badge-warning') : badge('未检测到 swanctl / ipsec', 'badge-error'))) +
      row('重载命令', '<span class="mono">' + esc(ss.reload_cmd || '—') + '</span>') +
      row('CRL 健康', publishHealthBadge(d.crl_health)) +
      row('CRL 距到期', d.crl_due_in_hours == null ? '—' : esc(d.crl_due_in_hours + ' 小时')) +
      row('自动发布', d.auto_publish ? badge('已开启', 'badge-valid') : badge('已关闭', 'badge-warning')) +
      row('启用发布目标', esc(String(d.publish_targets == null ? '—' : d.publish_targets))) +
      row('VPN 证书数', esc(String(d.vpn_cert_count == null ? '—' : d.vpn_cert_count))) +
      row('CA 私钥', caRow && caRow.has_key ? badge('已导入', 'badge-valid') : badge('未导入', 'badge-error')) +
      row('公开 CRL 路径', '<span class="mono">' + esc(d.public_crl_path || '—') + '</span>') +
      row('CRL 分发点 URL', d.crl_url ? '<span class="mono">' + esc(d.crl_url) + '</span>'
        : '<span class="faint">未设置（Windows 吊销检查依赖它，建议在「基本设置」中填写）</span>') +
      '</dl>';
    if (d.vpn_certs && d.vpn_certs.length) {
      html += '<div class="muted small" style="margin-top:8px">最近 VPN 证书：' +
        d.vpn_certs.slice(0, 6).map(function (c) {
          return '<a class="mono" href="#/cert/' + esc(c.id) + '">' + esc(c.cn || c.id) + '</a>';
        }).join('、') + '</div>';
    }
    if (!ss.swanctl && !ss.ipsec) {
      html += '<div class="callout callout-warn small" style="margin-top:8px">本机未检测到 strongSwan 的 ' +
        '<span class="mono">swanctl</span> / <span class="mono">ipsec</span> 命令。发布目标仍可写入暂存目录，' +
        '再用「下载同步脚本」在网关机上落位。</div>';
    }
    setHTML('ssStatusBody', html);
  }

  function settingsChangePassword() {
    var oldPwd = val('setOldPwd'), p1 = val('setNewPwd'), p2 = val('setNewPwd2');
    setHTML('err-setNewPwd', ''); setHTML('err-setNewPwd2', '');
    var ok = true;
    if (!oldPwd) { toastErr('请输入旧密码'); ok = false; }
    if (!p1 || p1.length < 8) { setHTML('err-setNewPwd', '新密码至少 8 位'); ok = false; }
    if (p1 !== p2) { setHTML('err-setNewPwd2', '两次输入的新密码不一致'); ok = false; }
    if (!ok) return Promise.resolve();
    return confirmAction({
      title: '修改管理员密码',
      warning: '修改成功后当前会话可能失效，届时需要用新密码重新登录。',
      message: '确认修改管理员密码？',
      okText: '确认修改'
    }).then(function (res) {
      if (!res) return;
      return withButton(el('setPwdBtn'), function () {
        return apiPatch('/api/settings', { password: { old: oldPwd, new: p1 } }).then(function () {
          toastOk('密码已修改，请使用新密码重新登录');
          ['setOldPwd', 'setNewPwd', 'setNewPwd2'].forEach(function (id) { if (el(id)) el(id).value = ''; });
        });
      });
    });
  }

  function loadBackups() {
    return apiGet('/api/backup').then(function (data) {
      state.backups = (data && data.items) || [];
      renderBackups();
    }).catch(function () {
      setHTML('backupList', '<div class="empty"><div class="small">无法获取备份列表。</div></div>');
    });
  }

  function renderBackups() {
    setHTML('backupList', tableHTML(
      ['备份文件', '大小', '创建时间', '操作'],
      (state.backups || []).map(function (b) {
        return {
          cells: [
            { cls: 'mono', html: esc(b.name || '—') },
            { html: esc(fmtBytes(b.size)) },
            { cls: 'nowrap', html: esc(fmtDateTime(b.created)) },
            { html: '<button class="btn btn-sm" type="button" data-act="backup-dl" data-name="' + esc(b.name) + '">下载</button>' }
          ]
        };
      }), { emptyTitle: '暂无备份', emptyDesc: '点击「一键备份」创建第一个备份。' }
    ));
  }

  function backupCreate() {
    return withButton(el('backupCreate'), function () {
      return withLoading('正在创建备份…', function () {
        return apiPost('/api/backup', {}).then(function (data) {
          toastOk('备份已创建' + (data && data.name ? '：' + data.name : ''));
          return loadBackups();
        });
      });
    });
  }

  function restoreBackup() {
    var file = el('restoreFile') && el('restoreFile').files[0];
    if (!file) { toastErr('请选择备份文件'); return Promise.resolve(); }
    return confirmAction({
      title: '恢复备份（覆盖当前数据）',
      warning: '恢复会覆盖当前全部数据：证书、CA、吊销列表、审计日志与设置都将被备份文件中的内容替换。此操作不可撤销。',
      message: '确认使用「' + file.name + '」恢复数据？',
      impact: [
        ['备份文件', file.name],
        ['文件大小', fmtBytes(file.size)],
        ['影响', '当前所有数据被覆盖']
      ],
      confirmWord: 'RESTORE',
      okText: '确认恢复', danger: true
    }).then(function (res) {
      if (!res) return;
      var fd = new FormData();
      fd.append('file', file);
      fd.append('confirm', 'true');
      return withButton(el('restoreBtn'), function () {
        return withLoading('正在恢复备份，请勿关闭页面…', function () {
          return apiForm('/api/backup/restore', fd).then(function (data) {
            toastOk('恢复完成' + (data && data.restored ? '（已恢复：' + data.restored + '）' : '') + '，即将重新登录');
            setTimeout(function () { apiPost('/api/logout', {}).catch(function () {}).finally(function () { goLogin(); }); }, 1500);
          });
        });
      });
    });
  }

  /* ====================================================================== */
  /* 16b. 通用多字段表单对话框 / 分页条                                     */
  /* ====================================================================== */
  /*
   * confirmAction 只支持一个附加输入框；这里补一个多字段对话框，复用 #modal。
   * cfg = { title, message, html, note, okText, fields:[{id,type}], validate(values) }
   * 返回 Promise：确认 → 字段值对象；取消/ESC → null。
   */
  function formDialog(cfg) {
    return new Promise(function (resolve) {
      var modal = el('modal');
      if (!modal) { resolve(null); return; }
      setText('modalTitle', cfg.title || '填写参数');
      var body = '';
      if (cfg.message) body += '<p>' + esc(cfg.message) + '</p>';
      if (cfg.html) body += cfg.html;
      if (cfg.note) body += '<div class="callout small">' + cfg.note + '</div>';
      setHTML('modalBody', body);
      setHTML('modalFoot',
        '<button class="btn" type="button" data-modal-close>取消</button>' +
        '<button class="btn ' + (cfg.danger ? 'btn-danger' : 'btn-primary') + '" id="modalFormOk" type="button">' +
        esc(cfg.okText || '确认') + '</button>');
      modal.hidden = false;

      function cleanup() {
        modal.hidden = true;
        $$('#modal [data-modal-close]').forEach(function (b) { b.removeEventListener('click', onCancel); });
        document.removeEventListener('keydown', onKey);
        if (okBtn) okBtn.removeEventListener('click', onOk);
      }
      function onCancel() { cleanup(); resolve(null); }
      function collect() {
        var values = {};
        (cfg.fields || []).forEach(function (f) {
          var n = el(f.id);
          if (!n) { values[f.id] = ''; return; }
          values[f.id] = (f.type === 'checkbox') ? !!n.checked : n.value;
        });
        return values;
      }
      function onOk() {
        var values = collect();
        if (cfg.validate) {
          var msg = cfg.validate(values);
          if (msg) { toastErr(msg); return; }
        }
        cleanup();
        resolve(values);
      }
      function onKey(ev) { if (ev.key === 'Escape') onCancel(); }
      var okBtn = el('modalFormOk');
      $$('#modal [data-modal-close]').forEach(function (b) { b.addEventListener('click', onCancel); });
      if (okBtn) okBtn.addEventListener('click', onOk);
      document.addEventListener('keydown', onKey);
      var first = cfg.fields && cfg.fields.length ? el(cfg.fields[0].id) : null;
      if (first && first.focus) first.focus();
    });
  }

  /* 通用分页条：act 为 data-act 名称，点击后由 handleAction 处理 data-page */
  function pagerHTML(page, pageSize, total, act) {
    page = Math.max(1, parseInt(page, 10) || 1);
    pageSize = Math.max(1, parseInt(pageSize, 10) || 20);
    total = Math.max(0, parseInt(total, 10) || 0);
    var totalPages = Math.max(1, Math.ceil(total / pageSize));
    var from = total ? (page - 1) * pageSize + 1 : 0;
    var to = Math.min(total, page * pageSize);
    return '<span class="pager-info">共 ' + total + ' 条，当前 ' + from + '–' + to + '，第 ' + page + '/' + totalPages + ' 页</span>' +
      '<button class="btn" type="button" data-act="' + act + '" data-page="1"' + (page <= 1 ? ' disabled' : '') + '>«</button>' +
      '<button class="btn" type="button" data-act="' + act + '" data-page="' + (page - 1) + '"' + (page <= 1 ? ' disabled' : '') + '>上一页</button>' +
      '<button class="btn" type="button" data-act="' + act + '" data-page="' + (page + 1) + '"' + (page >= totalPages ? ' disabled' : '') + '>下一页</button>' +
      '<button class="btn" type="button" data-act="' + act + '" data-page="' + totalPages + '"' + (page >= totalPages ? ' disabled' : '') + '>»</button>';
  }
  function paginate(p, total, pageSize) {
    var totalPages = Math.max(1, Math.ceil((total || 0) / (pageSize || 20)));
    return Math.min(Math.max(1, parseInt(p, 10) || 1), totalPages);
  }
  function nl2br(s) { return esc(s == null ? '' : String(s)).replace(/\n/g, '<br>'); }
  function publishHealthBadge(health) {
    var map = {
      ok: ['健康', 'badge-valid'],
      warning: ['告警', 'badge-warning'],
      critical: ['严重', 'badge-error']
    };
    var m = map[String(health || '').toLowerCase()] || [health || '未知', 'badge-dim'];
    return badge(m[0], m[1]);
  }
  function pubContentLabel(content) {
    return { crl: 'CRL 吊销列表', ca_cert: 'CA 证书', ca_chain: 'CA 证书链' }[content] || content || '—';
  }


  /* ====================================================================== */
  /* 16c. 证书详情：strongSwan 配置片段与一键部署包                         */
  /* ====================================================================== */
  function ssDeployHTML(cert) {
    var s = state.settings || {};
    return '<p class="muted small">部署包（ZIP）包含：证书、私钥（如已保存）、CA 证书、CRL、' +
      '<span class="mono">swanctl</span> 配置片段、<span class="mono">install-strongswan.sh</span> 与 README。' +
      (cert.has_key ? '' : '<br><strong class="days-warn">该证书未保存私钥，部署包中不会包含私钥。</strong>') +
      '</p>' +
      '<div class="form-grid"><div class="field-row">' +
      '<div class="field"><label for="ssRole">角色</label><select id="ssRole" class="input">' +
      '<option value="client">客户端 (client)</option><option value="gateway">网关 (gateway)</option></select></div>' +
      '<div class="field"><label for="ssGateway">对端网关地址</label>' +
      '<input id="ssGateway" class="input mono" value="' + esc(s.vpn_gateway || '') + '" placeholder="vpn.example.com"></div>' +
      '<div class="field"><label for="ssIdentity">IKEv2 身份（可选）</label>' +
      '<input id="ssIdentity" class="input mono" placeholder="留空取证书 SAN"></div>' +
      '</div><div class="row">' +
      '<button class="btn btn-primary" type="button" data-act="cert-vpn-bundle">下载 strongSwan 部署包</button>' +
      '<button class="btn" type="button" data-act="ss-snippet">查看配置片段</button>' +
      '</div></div>' +
      '<div id="ssSnippetBox" hidden></div>';
  }

  function ssSnippetPanelHTML() {
    return '<div class="copy-row"><span class="muted small">strongSwan 配置片段（swanctl conf.d）</span>' +
      '<button class="btn btn-sm" type="button" data-act="ss-snippet-load">生成 / 刷新</button>' +
      '<button class="btn btn-sm" type="button" data-act="ss-snippet-copy">复制</button></div>' +
      '<pre class="pem" id="ssSnippetPre">点击「生成 / 刷新」拉取片段。</pre>';
  }

  function ssSnippetToggle() {
    var box = el('ssSnippetBox');
    if (!box) return Promise.resolve();
    if (!box.hidden) { box.hidden = true; return Promise.resolve(); }
    return ssSnippetLoad();
  }

  function ssSnippetLoad() {
    var box = el('ssSnippetBox');
    if (box) {
      if (!box.innerHTML) box.innerHTML = ssSnippetPanelHTML();
      box.hidden = false;
    }
    var certId = (state.detail && state.detail.id) || '';
    setHTML('ssSnippetPre', '生成中…');
    return apiGet('/api/strongswan/snippet', {
      cert_id: certId, role: val('ssRole'), gateway: val('ssGateway'), identity: val('ssIdentity')
    }).then(function (d) {
      state.ssSnippet = (d && d.snippet) || '';
      var pre = el('ssSnippetPre');
      if (pre) pre.textContent = state.ssSnippet || '（接口未返回片段）';
      if (state.ssSnippet) toastOk('配置片段已生成');
    }).catch(function (err) {
      var pre = el('ssSnippetPre');
      if (pre) pre.textContent = '生成失败：' + ((err && err.message) || '未知错误');
    });
  }

  function certVpnBundle(cert) {
    if (!cert) return Promise.resolve();
    var s = state.settings || {};
    var html = '<div class="form-grid">' +
      '<div class="field"><label for="vpnDlgRole">角色</label><select id="vpnDlgRole" class="input">' +
      '<option value="client">客户端 (client)</option><option value="gateway">网关 (gateway)</option></select></div>' +
      '<div class="field"><label for="vpnDlgGateway">对端网关地址</label>' +
      '<input id="vpnDlgGateway" class="input mono" value="' + esc(s.vpn_gateway || '') + '" placeholder="vpn.example.com"></div>' +
      '<div class="field"><label for="vpnDlgIdentity">IKEv2 身份（可选）</label>' +
      '<input id="vpnDlgIdentity" class="input mono" placeholder="留空取证书 SAN"></div>' +
      '<div class="field"><label for="vpnDlgPassword">PKCS#12 口令（可选，≥4 位）</label>' +
      '<input id="vpnDlgPassword" class="input" type="password" autocomplete="new-password" placeholder="留空则部署包不含 PKCS#12"></div>' +
      '</div>';
    if (!cert.has_key) {
      html += '<div class="callout callout-warn small">该证书未保存私钥，部署包中<strong>不会包含私钥</strong>，需要从原签发处获取。</div>';
    }
    html += '<div class="callout small">部署包内容：证书、私钥（如已保存）、CA 证书、CRL、swanctl 配置片段、install-strongswan.sh、README。</div>';
    return formDialog({
      title: '下载 strongSwan 部署包',
      message: '为「' + (cert.cn || cert.serial_hex || cert.id) + '」生成一键部署包。',
      html: html,
      okText: '生成并下载',
      fields: [{ id: 'vpnDlgRole' }, { id: 'vpnDlgGateway' }, { id: 'vpnDlgIdentity' }, { id: 'vpnDlgPassword' }],
      validate: function (v) {
        if (v.vpnDlgPassword && String(v.vpnDlgPassword).length < 4) return 'PKCS#12 口令至少 4 位';
        return '';
      }
    }).then(function (v) {
      if (!v) return;
      var cn = String(cert.cn || cert.id).replace(/[\\/:*?"<>|\s]+/g, '_');
      return downloadApi('/api/certs/' + encodeURIComponent(cert.id) + '/vpn-bundle', {
        role: v.vpnDlgRole, gateway: trim(v.vpnDlgGateway),
        identity: trim(v.vpnDlgIdentity), password: v.vpnDlgPassword
      }, 'strongswan-' + cn + '.zip');
    });
  }

  /* ====================================================================== */
  /* 17. 规则集（证书怎么签，全部是可编辑数据）                              */
  /* ====================================================================== */
  var RS_REQUIRED_FIELDS = [
    ['CN', 'CN 通用名'], ['O', 'O 组织'], ['OU', 'OU 部门'], ['C', 'C 国家'],
    ['ST', 'ST 省/州'], ['L', 'L 城市'], ['EMAILADDRESS', 'emailAddress 邮箱']
  ];
  var RS_KEY_TYPES = [['rsa', 'RSA'], ['ec', 'EC（ECDSA）'], ['ed25519', 'Ed25519']];
  var RS_EC_SIZES = [['256', 'P-256'], ['384', 'P-384'], ['521', 'P-521']];
  var RS_SERIAL_MODES = [['random', 'random 随机'], ['sequential', 'sequential 顺序']];
  var RS_CUSTOM_TYPES = [
    ['utf8', 'utf8 文本'], ['hex', 'hex 十六进制'], ['der-base64', 'der-base64'], ['int', 'int 整数']
  ];
  var RS_ERR_GROUP_HINT = [
    ['extensions', ['KeyUsage', 'EKU', '扩展', 'CRL 分发点', 'OCSP', 'path_length', 'OID']],
    ['key', ['RSA', 'EC', '密钥', '摘要', 'digest']],
    ['validity', ['有效期', '天数', 'notBefore', 'not_before']],
    ['san', ['SAN']],
    ['subject', ['CN', '主题']],
    ['serial', ['序列号']],
    ['export', ['导出', 'bundle', 'PKCS#12', '口令']],
    ['revocation', ['吊销']]
  ];

  function rsOpts(list, current) {
    return (list || []).map(function (o) {
      var id = (typeof o === 'string') ? o : o.id;
      var label = (typeof o === 'string') ? o : (o.label || o.id);
      return '<option value="' + esc(id) + '"' +
        (String(current) === String(id) ? ' selected' : '') + '>' + esc(label) + '</option>';
    }).join('');
  }
  function rsChecksHTML(name, opts, selected) {
    var sel = (selected || []).map(String);
    return '<div class="checks" data-checks="' + esc(name) + '">' + (opts || []).map(function (o) {
      var id = (typeof o === 'string') ? o : o.id;
      var label = (typeof o === 'string') ? o : (o.label || o.id);
      return '<label class="check"><input type="checkbox" value="' + esc(id) + '"' +
        (sel.indexOf(String(id)) >= 0 ? ' checked' : '') + '> ' + esc(label) + '</label>';
    }).join('') + '</div>';
  }
  function rsCollectChecks(name) {
    var host = $('[data-checks="' + name + '"]');
    if (!host) return [];
    return $$('[type="checkbox"]', host).filter(function (c) { return c.checked; })
      .map(function (c) { return c.value; });
  }
  function rsField(label, inner, hint) {
    return '<div class="field"><label>' + esc(label) + '</label>' + inner +
      (hint ? '<div class="hint">' + hint + '</div>' : '') + '</div>';
  }
  function rsNumInput(id, v, min, max) {
    return '<input id="' + id + '" class="input" type="number"' +
      (v === null || v === undefined || v === '' ? '' : ' value="' + esc(v) + '"') +
      (min === undefined ? '' : ' min="' + min + '"') +
      (max === undefined ? '' : ' max="' + max + '"') + '>';
  }
  function rsText(id, v, cls) {
    return '<input id="' + id + '" class="input' + (cls ? ' ' + cls : '') +
      '" value="' + esc(v == null ? '' : v) + '">';
  }
  function rsTextarea(id, v, rows) {
    return '<textarea id="' + id + '" class="input" rows="' + (rows || 2) + '">' +
      esc(v == null ? '' : v) + '</textarea>';
  }
  function rsCheckbox(id, label, on, hint) {
    return '<div class="field"><label class="check"><input type="checkbox" id="' + id + '"' +
      (on ? ' checked' : '') + '> ' + esc(label) + '</label>' +
      (hint ? '<div class="hint">' + hint + '</div>' : '') + '</div>';
  }
  function rsGroup(key, title, body) {
    return '<details class="rs-group" data-group="' + esc(key) + '" open><summary>' +
      esc(title) + '</summary><div class="rs-group-body form-grid">' + body + '</div></details>';
  }
  function rsNumOr(id, fallback) {
    var v = trim(val(id));
    if (v === '') return fallback;
    var n = parseInt(v, 10);
    return isNaN(n) ? fallback : n;
  }
  function rsById(id) {
    return (state.rulesets.items || []).filter(function (r) {
      return String(r.id) === String(id);
    })[0] || null;
  }
  function rsIsOid(s) { return String(s == null ? '' : s).indexOf('.') >= 0; }

  function rsCustomRowHTML(r) {
    r = r || {};
    return '<div class="rs-custom-row">' +
      '<input class="input mono rs-c-oid" placeholder="1.2.3.4" value="' + esc(r.oid || '') + '">' +
      '<select class="input rs-c-type">' + RS_CUSTOM_TYPES.map(function (t) {
        return '<option value="' + t[0] + '"' + ((r.type || 'utf8') === t[0] ? ' selected' : '') +
          '>' + esc(t[1]) + '</option>';
      }).join('') + '</select>' +
      '<input class="input rs-c-value" placeholder="值" value="' + esc(r.value == null ? '' : r.value) + '">' +
      '<label class="check"><input type="checkbox" class="rs-c-critical"' +
      (r.critical ? ' checked' : '') + '> critical</label>' +
      '<button class="btn btn-sm btn-danger" type="button" data-act="rs-del-custom">删除</button>' +
      '</div>';
  }
  function rsEkuRowHTML(v) {
    return '<div class="rs-eku-row"><input class="input mono rs-eku-oid" placeholder="1.3.6.1.5.5.7.3.17" value="' +
      esc(v || '') + '"><button class="btn btn-sm btn-danger" type="button" data-act="rs-del-eku">删除</button></div>';
  }
  function rsCollectCustom() {
    return $$('.rs-custom-row', el('rsCustomRows')).map(function (r) {
      var oid = $('.rs-c-oid', r);
      var type = $('.rs-c-type', r);
      var value = $('.rs-c-value', r);
      var crit = $('.rs-c-critical', r);
      return {
        oid: trim(oid ? oid.value : ''),
        type: type ? type.value : 'utf8',
        value: value ? value.value : '',
        critical: !!(crit && crit.checked)
      };
    }).filter(function (r) { return r.oid || r.value; });
  }
  function rsCollectEkuExtras() {
    return $$('.rs-eku-oid', el('rsEkuExtras')).map(function (i) { return trim(i.value); })
      .filter(function (v) { return !!v; });
  }

  function rsNotesHTML(notes) {
    notes = notes || {};
    var html = '<dl class="kv">' +
      row('平台', esc(notes.platform || '—'));
    if (notes.bundle_label) html += row('打包格式', esc(notes.bundle_label));
    if (notes.windows_import_hint) html += row('Windows 导入 / PKCS#12', nl2br(notes.windows_import_hint));
    if (notes.linux_install_hint) html += row('Linux / strongSwan 落位', nl2br(notes.linux_install_hint));
    if (notes.extra_notes) html += row('其它说明', nl2br(notes.extra_notes));
    html += '</dl>';
    return html;
  }

  function renderRulesets() {
    show('rsEditorView', false);
    show('rsListView', true);
    setHTML('rsTable', skeletonTable(8, 4));
    setHTML('rsPlatformNotes', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    return Promise.all([
      apiGet('/api/rulesets'),
      rsMeta().catch(function () { return null; })
    ]).then(function (res) {
      var d = res[0] || {};
      state.rulesets.items = d.items || [];
      state.rulesets.default_slug = d.default_ruleset || '';
      state.rulesets.platform_notes = d.platform_notes || {};
      state.rulesets.used = {};
      if (!state.rulesets.notesSlug && state.rulesets.items.length) {
        var pick = state.rulesets.items.filter(function (r) {
          return r.slug === state.rulesets.default_slug;
        })[0] || state.rulesets.items[0];
        state.rulesets.notesSlug = pick.slug;
      }
      /* 列表接口不含 used_by，逐个补一次（内置规则集数量很小） */
      return Promise.all(state.rulesets.items.map(function (rs) {
        return apiGet('/api/rulesets/' + encodeURIComponent(rs.id)).then(function (x) {
          state.rulesets.used[rs.id] = (x && typeof x.used_by === 'number') ? x.used_by : 0;
          if (x && x.platform_notes) state.rulesets.platform_notes[rs.slug] = x.platform_notes;
        }).catch(function () { state.rulesets.used[rs.id] = null; });
      })).then(function () { paintRulesets(); });
    });
  }

  function rsMeta() {
    if (state.rulesets.meta) return Promise.resolve(state.rulesets.meta);
    return apiGet('/api/rulesets/meta').then(function (m) {
      state.rulesets.meta = m || {};
      return state.rulesets.meta;
    });
  }

  function paintRulesets() {
    var items = state.rulesets.items || [];
    setHTML('rsDefault', '<option value="">（未设置）</option>' + items.map(function (rs) {
      return '<option value="' + esc(rs.slug) + '"' +
        (state.rulesets.default_slug === rs.slug ? ' selected' : '') + '>' +
        esc(rs.name) + '（' + esc(rs.slug) + '）' + (rs.enabled ? '' : ' — 已停用') + '</option>';
    }).join(''));

    var rows = items.map(function (rs) {
      var used = state.rulesets.used[rs.id];
      var usedText = (used == null) ? '<span class="faint">未知</span>'
        : (used ? '<strong>' + used + '</strong> 张证书' : '0 张');
      var isDefault = state.rulesets.default_slug === rs.slug;
      return {
        cells: [
          {
            html: '<button class="link-btn" type="button" data-act="rs-notes" data-slug="' + esc(rs.slug) + '">' +
              esc(rs.name) + '</button>' + (isDefault ? ' ' + badge('默认', 'badge-primary') : '')
          },
          { cls: 'mono small', html: esc(rs.slug) },
          { html: esc(rs.platform || 'any') },
          { html: esc(rs.purpose || '—') },
          { html: rs.enabled ? badge('启用', 'badge-valid') : badge('停用', 'badge-dim') },
          { html: rs.builtin ? badge('内置', 'badge-info') : badge('自建', 'badge-dim') },
          { html: usedText },
          {
            html: '<div class="actions">' +
              '<button class="btn btn-sm" type="button" data-act="rs-edit" data-id="' + esc(rs.id) + '">编辑</button>' +
              '<button class="btn btn-sm" type="button" data-act="rs-dup" data-id="' + esc(rs.id) + '">复制</button>' +
              (isDefault ? '' : '<button class="btn btn-sm" type="button" data-act="rs-default" data-slug="' + esc(rs.slug) + '">设为默认</button>') +
              (rs.builtin ? '<button class="btn btn-sm" type="button" data-act="rs-reset" data-id="' + esc(rs.id) + '">恢复出厂</button>' : '') +
              '<button class="btn btn-sm btn-danger" type="button" data-act="rs-del" data-id="' + esc(rs.id) + '">删除</button>' +
              '</div>'
          }
        ]
      };
    });
    setHTML('rsTable', tableHTML(
      ['名称', '标识 slug', '平台', '用途', '启用', '内置', '已用于', '操作'], rows,
      { emptyTitle: '还没有规则集', emptyDesc: '点击「新建规则集」创建第一份签发规则。' }));
    paintRsNotes();
  }

  function paintRsNotes() {
    var slug = state.rulesets.notesSlug;
    var host = el('rsPlatformNotes');
    if (!host) return;
    var notes = (state.rulesets.platform_notes || {})[slug];
    if (!notes) {
      host.innerHTML = emptyState('暂无平台提示', '点击表格中的规则集名称查看该平台的差异说明。');
      return;
    }
    var rs = (state.rulesets.items || []).filter(function (r) { return r.slug === slug; })[0] || {};
    host.innerHTML = '<div class="muted small" style="margin-bottom:6px">当前查看：<span class="mono">' +
      esc(slug) + '</span>' + (rs.name ? ' — ' + esc(rs.name) : '') + '</div>' + rsNotesHTML(notes);
  }

  function rsSetDefault(slug) {
    if (!slug) { toastErr('请先选择要设为默认的规则集'); return Promise.resolve(); }
    var rs = (state.rulesets.items || []).filter(function (r) { return r.slug === slug; })[0] || {};
    return withButton($('[data-act="rs-default-pick"]'), function () {
      return apiPost('/api/rulesets/default', { slug: slug }).then(function () {
        state.rulesets.default_slug = slug;
        toastOk('默认规则集已设为：' + (rs.name || slug));
        paintRulesets();
      });
    });
  }

  function rsOpenEditor(id) {
    show('rsListView', false);
    show('rsEditorView', true);
    setHTML('rsFormErrors', '');
    setHTML('rsForm', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    setText('rsEditorTitle', id ? '编辑规则集' : '新建规则集');
    return rsMeta().then(function () {
      if (!id) return { ruleset: rsNewFromMeta(), platform_notes: null, used_by: 0 };
      return apiGet('/api/rulesets/' + encodeURIComponent(id));
    }).then(function (d) {
      var rs = (d && d.ruleset) || {};
      if (!rs.spec) rs.spec = (state.rulesets.meta && state.rulesets.meta.default_spec) || {};
      state.rulesets.editing = rs;
      setText('rsEditorTitle', (rs.id ? '编辑：' : '新建：') + (rs.name || '未命名规则集'));
      renderRsEditor(rs, (d && d.platform_notes) || null, (d && d.used_by) || 0);
    }).catch(function (err) {
      setHTML('rsForm', emptyState('无法加载规则集', (err && err.message) || '未知错误',
        '<button class="btn" type="button" data-act="rs-close-editor">返回列表</button>'));
    });
  }

  function rsNewFromMeta() {
    var meta = state.rulesets.meta || {};
    var spec;
    try { spec = JSON.parse(JSON.stringify(meta.default_spec || {})); } catch (e) { spec = {}; }
    return {
      id: null, slug: '', name: '', description: '', platform: 'strongswan', purpose: '',
      enabled: true, builtin: false, spec: spec
    };
  }

  function renderRsEditor(rs, notes, usedBy) {
    setHTML('rsForm', rsFormHTML(rs, notes, usedBy));
    var spec = rs.spec || {};
    var chost = el('rsCustomRows');
    if (chost) {
      chost.innerHTML = '';
      ((spec.extensions || {}).custom || []).forEach(function (r) {
        chost.insertAdjacentHTML('beforeend', rsCustomRowHTML(r));
      });
    }
    var ehost = el('rsEkuExtras');
    if (ehost) {
      ehost.innerHTML = '';
      (((spec.extensions || {}).eku) || []).filter(rsIsOid).forEach(function (o) {
        ehost.insertAdjacentHTML('beforeend', rsEkuRowHTML(o));
      });
    }
  }

  function rsFormHTML(rs, notes, usedBy) {
    var spec = rs.spec || {};
    var meta = state.rulesets.meta || {};
    var sub = spec.subject || {}, san = spec.san || {}, key = spec.key || {},
      va = spec.validity || {}, ext = spec.extensions || {}, ser = spec.serial || {},
      rev = spec.revocation || {}, ex = spec.export || {};
    var html = '';

    if (notes) {
      html += '<div class="card"><div class="card-head"><h2>平台差异提示</h2>' +
        (usedBy ? '<span class="muted small">已用于 ' + esc(usedBy) + ' 张证书</span>' : '') +
        '</div><div class="card-body">' + rsNotesHTML(notes) + '</div></div>';
    }

    html += '<div class="card"><div class="card-head"><h2>基本信息</h2></div>' +
      '<div class="card-body form-grid">' +
      rsField('名称 *', rsText('rsName', rs.name || '')) +
      rsField('标识 slug' + (rs.id ? '' : '（留空按名称自动生成）'),
        '<input id="rsSlug" class="input mono" value="' + esc(rs.slug || '') + '"' +
        (rs.id ? ' disabled' : '') + ' placeholder="例如 strongswan-vpn-client">',
        rs.id ? '标识创建后不可修改（已签发证书按它归档用途）。'
          : '建议只用小写字母、数字与短横线。') +
      rsField('平台', '<select id="rsPlatform" class="input">' +
        rsOpts(meta.platforms || [], rs.platform || 'any') + '</select>') +
      rsField('用途 purpose', rsText('rsPurpose', rs.purpose || '', 'mono'),
        '例如 vpn-client / vpn-gateway / smartcard（签发页按用途筛选）。') +
      rsField('描述', rsTextarea('rsDescription', rs.description || '', 2)) +
      rsCheckbox('rsEnabled', '启用该规则集（停用后不在签发页出现）', rs.enabled !== false) +
      '</div></div>';

    var groups = '';
    groups += rsGroup('subject', '主题 subject',
      rsCheckbox('rsRequireCn', 'require_cn：必须填写 CN', sub.require_cn !== false) +
      rsField('required_fields：必填主题字段',
        rsChecksHTML('required_fields', RS_REQUIRED_FIELDS, sub.required_fields || ['CN'])) +
      rsCheckbox('rsCnFromIdentity', 'cn_from_identity：CN 取自身份', sub.cn_from_identity !== false) +
      rsField('max_cn_length：CN 最大长度', rsNumInput('rsMaxCn', sub.max_cn_length, 1, 512)) +
      rsField('max_field_length：其它主题字段最大长度', rsNumInput('rsMaxField', sub.max_field_length, 1, 1024)) +
      rsCheckbox('rsAllowEmptyOrg', 'allow_empty_organization：允许组织 O 为空', sub.allow_empty_organization !== false));

    groups += rsGroup('san', '身份 / SAN',
      rsCheckbox('rsSanRequired', 'required：至少需要一个 SAN', san.required) +
      rsField('allowed_types：允许的 SAN 类型',
        rsChecksHTML('san_types', meta.san_types || [], san.allowed_types)) +
      rsField('default_type：默认类型', '<select id="rsSanDefault" class="input">' +
        rsOpts(meta.san_types || [], san.default_type || 'dns') + '</select>') +
      rsCheckbox('rsSanAuto', 'auto_from_identity：按身份自动生成 SAN', san.auto_from_identity) +
      rsCheckbox('rsAddUpn', 'add_upn_for_email：邮箱身份额外补 UPN(otherName)', san.add_upn_for_email) +
      rsCheckbox('rsCopyCn', 'copy_cn_if_fqdn：CN 是 FQDN 时复制进 SAN', san.copy_cn_if_fqdn) +
      rsField('max_entries：SAN 最大条目数', rsNumInput('rsMaxEntries', san.max_entries, 1, 200)) +
      '<div class="callout small">strongSwan 用证书 SAN 匹配 IKEv2 身份（<span class="mono">local.id / eap_id</span>），' +
      'VPN 类规则集请确保「按身份自动生成 SAN」已打开，且允许类型覆盖实际使用的身份形式。</div>');

    groups += rsGroup('key', '密钥与摘要',
      rsField('type：默认密钥类型', '<select id="rsKeyType" class="input">' +
        rsOpts(RS_KEY_TYPES, key.type || 'rsa') + '</select>') +
      rsField('size：默认位数', rsNumInput('rsKeySize', key.size, 256, 16384)) +
      rsField('allowed_types：允许的密钥类型',
        rsChecksHTML('key_types', RS_KEY_TYPES, key.allowed_types)) +
      rsField('min_rsa_size：RSA 最小位数', rsNumInput('rsMinRsa', key.min_rsa_size, 1024, 16384)) +
      rsField('allowed_ec_sizes：允许的 EC 曲线',
        rsChecksHTML('ec_sizes', RS_EC_SIZES, (key.allowed_ec_sizes || []).map(String))) +
      rsField('digest：摘要算法', '<select id="rsDigest" class="input">' +
        rsOpts(meta.digests || [], key.digest || 'sha256') + '</select>'));

    groups += rsGroup('validity', '有效期',
      rsField('days：默认有效期（天）', rsNumInput('rsDays', va.days, 1, 36500)) +
      rsField('min_days：最小天数', rsNumInput('rsMinDays', va.min_days, 1, 36500)) +
      rsField('max_days：最大天数', rsNumInput('rsMaxDays', va.max_days, 1, 36500)) +
      rsField('not_before_skew_minutes：notBefore 回溯分钟', rsNumInput('rsSkew', va.not_before_skew_minutes, 0, 1440)));

    groups += rsGroup('extensions', '扩展（KeyUsage / EKU / 扩展项）',
      rsField('key_usage：KeyUsage', rsChecksHTML('key_usage', meta.key_usages || [], ext.key_usage)) +
      rsField('eku：ExtendedKeyUsage',
        rsChecksHTML('eku', meta.ekus || [], ext.eku) +
        '<div class="hint">已知 EKU 直接勾选；如还需要其它用途，可在下方手填 OID。</div>' +
        '<div id="rsEkuExtras" class="rs-eku-extras"></div>' +
        '<button class="btn btn-sm" type="button" data-act="rs-add-eku">＋ 添加自定义 EKU OID</button>') +
      rsCheckbox('rsCdp', 'crl_distribution_point：写入 CRL 分发点（CDP）', ext.crl_distribution_point) +
      rsField('crl_url：CRL 分发点 URL', rsText('rsCrlUrl', ext.crl_url, 'mono'),
        '必须以 http:// 或 https:// 开头；留空则用「设置 → CRL 分发点 URL」。') +
      rsField('ocsp_url：OCSP 地址', rsText('rsOcspUrl', ext.ocsp_url, 'mono')) +
      rsCheckbox('rsSki', 'subject_key_identifier：写 SKI', ext.subject_key_identifier !== false) +
      rsCheckbox('rsAki', 'authority_key_identifier：写 AKI', ext.authority_key_identifier !== false) +
      rsField('path_length：BasicConstraints 路径长度',
        rsNumInput('rsPathLen', ext.path_length == null ? '' : ext.path_length, 0, 32),
        '留空表示不限制。') +
      rsField('custom：自定义 OID 扩展',
        '<div id="rsCustomRows"></div>' +
        '<button class="btn btn-sm" type="button" data-act="rs-add-custom">＋ 添加自定义扩展</button>',
        '字段：oid、type（utf8 / hex / der-base64 / int）、value、critical。'));

    groups += rsGroup('serial', '序列号',
      rsField('mode：模式', '<select id="rsSerialMode" class="input">' +
        rsOpts(RS_SERIAL_MODES, ser.mode || 'random') + '</select>') +
      rsField('bits：随机序列号位数', rsNumInput('rsSerialBits', ser.bits, 64, 256)));

    groups += rsGroup('revocation', '吊销策略',
      rsCheckbox('rsAllowRevoke', 'allow_revoke：允许吊销该规则集签发的证书', rev.allow_revoke !== false) +
      rsField('default_reason：默认吊销原因', '<select id="rsDefReason" class="input">' +
        rsOpts(meta.reasons || [], rev.default_reason || 'unspecified') + '</select>') +
      rsCheckbox('rsAutoPublish', 'auto_publish_crl：吊销后自动重新生成并发布 CRL', rev.auto_publish_crl !== false));

    groups += rsGroup('export', '导出与平台提示',
      rsField('bundle：打包格式', '<select id="rsBundle" class="input">' +
        rsOpts(meta.bundles || [], ex.bundle || 'pem') + '</select>') +
      rsField('key_file_mode：私钥文件权限', rsText('rsKeyMode', ex.key_file_mode || '0600', 'mono')) +
      rsCheckbox('rsReqP12Pw', 'require_p12_password：PKCS#12 必须设置口令', ex.require_p12_password) +
      rsField('windows_import_hint：Windows 导入提示', rsTextarea('rsWinHint', ex.windows_import_hint, 3)) +
      rsField('linux_install_hint：Linux / strongSwan 安装提示', rsTextarea('rsLinuxHint', ex.linux_install_hint, 3)) +
      rsField('extra_notes：其它说明', rsTextarea('rsExtraNotes', ex.extra_notes, 2)));

    groups += rsGroup('advanced', '高级（严格模式 / 可覆盖字段）',
      rsCheckbox('rsStrict', 'strict：只允许覆盖 overridable 中列出的字段', !!spec.strict) +
      rsField('overridable：允许签发时覆盖的字段（每行一个）',
        rsTextarea('rsOverridable', (spec.overridable || []).join('\n'), 5),
        '例如 validity.days、key.size、san、extensions.eku。'));

    html += '<div class="rs-groups">' + groups + '</div>';
    return html;
  }

  function rsCollectSpec() {
    return {
      subject: {
        require_cn: checked('rsRequireCn'),
        required_fields: rsCollectChecks('required_fields'),
        cn_from_identity: checked('rsCnFromIdentity'),
        max_cn_length: rsNumOr('rsMaxCn', 64),
        max_field_length: rsNumOr('rsMaxField', 128),
        allow_empty_organization: checked('rsAllowEmptyOrg')
      },
      san: {
        required: checked('rsSanRequired'),
        allowed_types: rsCollectChecks('san_types'),
        auto_from_identity: checked('rsSanAuto'),
        add_upn_for_email: checked('rsAddUpn'),
        copy_cn_if_fqdn: checked('rsCopyCn'),
        max_entries: rsNumOr('rsMaxEntries', 20),
        default_type: val('rsSanDefault') || 'dns'
      },
      key: {
        type: val('rsKeyType') || 'rsa',
        size: rsNumOr('rsKeySize', 2048),
        allowed_types: rsCollectChecks('key_types'),
        min_rsa_size: rsNumOr('rsMinRsa', 2048),
        allowed_ec_sizes: rsCollectChecks('ec_sizes').map(function (s) { return parseInt(s, 10); })
          .filter(function (n) { return !isNaN(n); }),
        digest: val('rsDigest') || 'sha256'
      },
      validity: {
        days: rsNumOr('rsDays', 365),
        min_days: rsNumOr('rsMinDays', 1),
        max_days: rsNumOr('rsMaxDays', 3650),
        not_before_skew_minutes: rsNumOr('rsSkew', 5)
      },
      extensions: {
        key_usage: rsCollectChecks('key_usage'),
        eku: rsCollectChecks('eku').concat(rsCollectEkuExtras()),
        crl_distribution_point: checked('rsCdp'),
        crl_url: trim(val('rsCrlUrl')),
        ocsp_url: trim(val('rsOcspUrl')),
        subject_key_identifier: checked('rsSki'),
        authority_key_identifier: checked('rsAki'),
        path_length: (function () {
          var v = trim(val('rsPathLen'));
          if (v === '') return null;
          var n = parseInt(v, 10);
          return isNaN(n) ? null : n;
        })(),
        custom: rsCollectCustom()
      },
      serial: { mode: val('rsSerialMode') || 'random', bits: rsNumOr('rsSerialBits', 159) },
      revocation: {
        allow_revoke: checked('rsAllowRevoke'),
        default_reason: val('rsDefReason') || 'unspecified',
        auto_publish_crl: checked('rsAutoPublish')
      },
      export: {
        bundle: val('rsBundle') || 'pem',
        key_file_mode: trim(val('rsKeyMode')) || '0600',
        require_p12_password: checked('rsReqP12Pw'),
        windows_import_hint: val('rsWinHint'),
        linux_install_hint: val('rsLinuxHint'),
        extra_notes: val('rsExtraNotes')
      },
      strict: checked('rsStrict'),
      overridable: trim(val('rsOverridable'))
        ? trim(val('rsOverridable')).split('\n').map(trim).filter(Boolean) : []
    };
  }

  function rsShowErrors(list) {
    if (!list || !list.length) { setHTML('rsFormErrors', ''); return; }
    setHTML('rsFormErrors', '<div class="callout callout-danger"><strong>规则集校验未通过：</strong>' +
      '<ul class="rs-err-list">' + list.map(function (m) { return '<li>' + esc(m) + '</li>'; }).join('') +
      '</ul></div>');
    rsOpenErrorGroups(list.join(' '));
  }
  function rsOpenErrorGroups(msg) {
    $$('.rs-group', el('rsForm')).forEach(function (d) {
      var key = d.getAttribute('data-group');
      for (var i = 0; i < RS_ERR_GROUP_HINT.length; i++) {
        if (RS_ERR_GROUP_HINT[i][0] !== key) continue;
        var hit = RS_ERR_GROUP_HINT[i][1].some(function (h) { return msg.indexOf(h) >= 0; });
        if (hit) d.open = true;
      }
    });
  }

  function rsSaveForm() {
    var name = trim(val('rsName'));
    if (!name) { rsShowErrors(['请填写规则集名称']); toastErr('请填写规则集名称'); return Promise.resolve(); }
    var editing = state.rulesets.editing || {};
    var spec = rsCollectSpec();
    var body = {
      name: name, description: val('rsDescription'), platform: val('rsPlatform') || 'any',
      purpose: trim(val('rsPurpose')), enabled: checked('rsEnabled')
    };
    rsShowErrors([]);
    return withButton(el('rsSaveBtn'), function () {
      return apiPost('/api/rulesets/validate', { spec: spec }).then(function (d) {
        var normalized = (d && d.spec) || spec;
        if (editing.id) {
          return apiPatch('/api/rulesets/' + encodeURIComponent(editing.id),
            Object.assign({}, body, { spec: normalized }));
        }
        var create = Object.assign({}, body, { spec: normalized });
        if (trim(val('rsSlug'))) create.slug = trim(val('rsSlug'));
        return apiPost('/api/rulesets', create);
      }).then(function (d) {
        var rs = (d && d.ruleset) || {};
        toastOk('规则集已保存：' + (rs.name || name));
        return rsCloseEditor();
      }).catch(function (err) {
        rsShowErrors([(err && err.message) || '保存失败']);
      });
    });
  }

  function rsValidateForm() {
    var spec = rsCollectSpec();
    var btn = $('[data-act="rs-validate"]');
    if (btn) btn.classList.add('is-loading');
    return apiPost('/api/rulesets/validate', { spec: spec }).then(function () {
      rsShowErrors([]);
      toastOk('校验通过，配置合法');
    }).catch(function (err) {
      rsShowErrors([(err && err.message) || '校验失败']);
    }).finally(function () {
      if (btn) btn.classList.remove('is-loading');
    });
  }

  function rsCloseEditor() {
    show('rsEditorView', false);
    show('rsListView', true);
    state.rulesets.editing = null;
    return renderRulesets();
  }

  function rsDuplicate(id) {
    var rs = rsById(id);
    if (!rs) { toastErr('规则集不存在'); return Promise.resolve(); }
    return formDialog({
      title: '复制规则集',
      message: '将复制「' + rs.name + '」的全部配置（不影响原规则集）。',
      html: '<div class="field"><label for="rsDupName">新规则集名称</label>' +
        '<input id="rsDupName" class="input" value="' + esc((rs.name || '') + ' 副本') + '"></div>',
      fields: [{ id: 'rsDupName' }],
      okText: '复制',
      validate: function (v) { return trim(v.rsDupName) ? '' : '请填写新规则集名称'; }
    }).then(function (v) {
      if (!v) return;
      return apiPost('/api/rulesets/' + encodeURIComponent(id) + '/duplicate',
        { name: trim(v.rsDupName) }).then(function (d) {
          toastOk('已复制为：' + ((d && d.ruleset && d.ruleset.name) || v.rsDupName));
          return renderRulesets();
        });
    });
  }

  function rsReset(id) {
    var rs = rsById(id);
    if (!rs) { toastErr('规则集不存在'); return Promise.resolve(); }
    return confirmAction({
      title: '恢复出厂设置',
      danger: true,
      okText: '恢复出厂',
      warning: '将把内置规则集「' + rs.name + '」的签发策略恢复成出厂默认值，' +
        '你对它做过的所有修改都会丢失。此操作不可撤销。',
      message: '确认恢复出厂？',
      impact: [
        ['规则集', rs.name + '（' + rs.slug + '）'],
        ['影响', '仅该规则集的 spec 被重置'],
        ['已签发证书', copyImpact(rs.slug)]
      ]
    }).then(function (res) {
      if (!res) return;
      return apiPost('/api/rulesets/' + encodeURIComponent(id) + '/reset', {}).then(function () {
        toastOk('已恢复出厂：' + (rs.name || id));
        return renderRulesets();
      });
    });
  }
  function copyImpact(slug) {
    var used = null;
    (state.rulesets.items || []).forEach(function (r) {
      if (r.slug === slug) used = state.rulesets.used[r.id];
    });
    return (used == null ? '未知' : used + ' 张') + '（不受影响）';
  }

  function rsDelete(id) {
    var rs = rsById(id);
    if (!rs) { toastErr('规则集不存在'); return Promise.resolve(); }
    var used = state.rulesets.used[id];
    return confirmAction({
      title: '删除规则集',
      danger: true,
      okText: '确认删除',
      warning: '删除后无法恢复。' +
        (used ? '该规则集已被 ' + used + ' 张证书使用，后端会拒绝删除；可先停用。' : ''),
      message: '确认删除该规则集？',
      impact: [
        ['规则集', rs.name + '（' + rs.slug + '）'],
        ['已用于', used == null ? '未知' : used + ' 张证书'],
        ['内置', rs.builtin ? '是（可用「恢复出厂」重置，删除需谨慎）' : '否']
      ]
    }).then(function (res) {
      if (!res) return;
      return apiDel('/api/rulesets/' + encodeURIComponent(id)).then(function () {
        toastOk('规则集已删除');
        if (state.rulesets.notesSlug === rs.slug) state.rulesets.notesSlug = '';
        return renderRulesets();
      });
    });
  }

  /* ====================================================================== */
  /* 18. CRL 自动发布（strongSwan）                                         */
  /* ====================================================================== */
  function pubSkeleton() {
    var stats = '';
    for (var i = 0; i < 8; i++) {
      stats += '<div class="stat"><div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div></div>';
    }
    setHTML('pubStats', stats);
    setHTML('pubHealthBody', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    setHTML('pubTargets', skeletonTable(9, 3));
    setHTML('pubSuggested', '<div class="skeleton sk-line"></div><div class="skeleton sk-line short"></div>');
    setHTML('pubLog', skeletonTable(7, 5));
    setHTML('pubNowResult', '');
    setHTML('pubTargetTestResult', '');
  }

  function renderPublish() {
    pubSkeleton();
    show('pubTargetFormWrap', false);
    state.publish.editingTarget = null;
    return Promise.all([
      apiGet('/api/publish/status'),
      apiGet('/api/publish/targets'),
      apiGet('/api/publish/log', { page: state.publish.log.page, page_size: state.publish.log.page_size }),
      apiGet('/api/strongswan/status', null, { timeout: 30000 }).catch(function () { return null; })
    ]).then(function (res) {
      state.publish.status = res[0] || {};
      var t = res[1] || {};
      state.publish.targets = t.items || [];
      state.publish.detected = t.detected || null;
      state.publish.suggested = t.suggested || [];
      state.publish.staging_dir = t.staging_dir || '';
      state.publish.ss = res[3] || null;
      paintPublishLog(res[2] || {});
      paintPublish();
    });
  }

  function paintPublish() {
    var st = state.publish.status || {};
    var ss = st.strongswan || {};
    var ssFull = state.publish.ss || {};
    var caRow = ssFull.ca || state.ca || null;

    setHTML('pubStats',
      statCard('CRL 健康', st.health === 'ok' ? '正常' : (st.health === 'warning' ? '告警' : '严重'),
        st.health === 'ok' ? 'ok' : (st.health === 'critical' ? 'danger' : 'warn'),
        (st.problems || [])[0] || '') +
      statCard('CRL 编号', st.crl && st.crl.number != null ? '#' + st.crl.number : '—', '',
        st.crl ? ('条目 ' + (st.crl.entries == null ? '—' : st.crl.entries) +
          '（已吊销 ' + (st.revoked_count == null ? '—' : st.revoked_count) + '）') : '尚未生成') +
      statCard('本次更新', st.crl ? fmtDateTime(st.crl.this_update) : '—') +
      statCard('下次更新', st.crl ? fmtDateTime(st.crl.next_update) : '—') +
      statCard('距到期', st.due_in_hours == null ? '—' : (st.due_in_hours + ' 小时'),
        (st.due_in_hours != null && st.due_in_hours < 0) ? 'danger'
          : ((st.due_in_hours != null && st.due_in_hours < (st.lead_hours || 72)) ? 'warn' : ''),
        '自动续签阈值 ' + (st.lead_hours == null ? '—' : st.lead_hours + ' 小时')) +
      statCard('启用目标', st.enabled_targets == null ? '—' : st.enabled_targets, '') +
      statCard('已吊销证书', st.revoked_count == null ? '—' : st.revoked_count, '') +
      statCard('上次发布', st.last_publish ? (st.last_publish.ok ? '成功' : '失败') : '从未发布',
        st.last_publish ? (st.last_publish.ok ? 'ok' : 'danger') : 'warn',
        st.last_publish ? fmtDateTime(st.last_publish.ts) : ''));
    setHTML('pubHealthBadge', publishHealthBadge(st.health));

    var probs = st.problems || [];
    var noKey = !caRow || caRow.has_key === false ||
      probs.some(function (p) { return String(p).indexOf('私钥') >= 0; });
    var body = '';
    if (noKey) {
      body += '<div class="callout callout-danger"><strong>CA 私钥未导入：无法生成或续签 CRL。</strong>' +
        'strongSwan 会拿到缺失或过期的吊销列表（无法判断证书是否被吊销）。' +
        '请前往「CA 管理」导入带私钥的 CA。</div>';
    }
    body += '<dl class="kv">' +
      row('健康状态', publishHealthBadge(st.health)) +
      row('strongSwan 检测', ss.swanctl ? badge('swanctl 可用', 'badge-valid')
        : (ss.ipsec ? badge('ipsec 可用', 'badge-warning') : badge('未检测到 swanctl / ipsec', 'badge-error'))) +
      row('重载命令', '<span class="mono">' + esc(ss.reload_cmd || '—') + '</span>') +
      row('swanctl 目录', '<span class="mono">' +
        esc((state.publish.detected && state.publish.detected.dirs && state.publish.detected.dirs.swanctl) ||
          (ss.swanctl_dir ? '/etc/swanctl/x509crl' : '—')) + '</span>') +
      row('发布暂存目录', '<span class="mono">' + esc(state.publish.staging_dir || '—') + '</span>') +
      row('启用目标数', esc(String(st.enabled_targets == null ? '—' : st.enabled_targets))) +
      row('上次发布', st.last_publish
        ? (esc(st.last_publish.target_name || '—') + ' · ' + esc(fmtDateTime(st.last_publish.ts)) + ' · ' +
          (st.last_publish.ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error')) +
          '<div class="small muted">' + esc(st.last_publish.message || '') + '</div>')
        : '<span class="faint">从未发布</span>') +
      '</dl>';
    if (probs.length) {
      body += '<div class="callout callout-warn" style="margin-top:8px"><strong>需要关注：</strong>' +
        '<ul class="rs-err-list">' + probs.map(function (p) {
          return '<li>' + esc(p) + '</li>';
        }).join('') + '</ul></div>';
    }
    setHTML('pubHealthBody', body);

    if (el('pubAutoPublish')) el('pubAutoPublish').checked = !!st.auto_publish;
    if (el('pubLeadHours')) el('pubLeadHours').value = st.lead_hours == null ? 72 : st.lead_hours;
    if (el('pubIntervalMinutes')) el('pubIntervalMinutes').value = st.interval_minutes == null ? 60 : st.interval_minutes;
    if (el('pubAutoReload')) el('pubAutoReload').checked = st.auto_reload !== false;

    var cdpPath = (state.publish.ss && state.publish.ss.public_crl_path) ||
      (state.settings && state.settings.public_crl_url) || '/crl/current.crl';
    state.publish.cdp = 'http://' + location.host + cdpPath;
    if (el('pubCdp')) el('pubCdp').value = state.publish.cdp;

    var d = state.publish.detected || {};
    setText('pubDetected', (d.swanctl || d.ipsec)
      ? ('检测到 ' + (d.swanctl ? 'swanctl' : 'ipsec') +
        (d.dirs && d.dirs.swanctl ? '（' + d.dirs.swanctl + '）' : ''))
      : '未检测到 strongSwan（仍可写入暂存目录）');

    paintPublishTargets();
    paintPublishSuggested();
    if (state.publish.editingTarget) paintPublishTargetForm();
    else show('pubTargetFormWrap', false);
  }

  function paintPublishTargets() {
    var items = state.publish.targets || [];
    setHTML('pubTargets', tableHTML(
      ['名称', '路径', '文件名', '格式', '内容', 'reload 命令', '启用', '上次结果', '操作'],
      items.map(function (t) {
        var last = t.last_publish_at
          ? ((t.last_ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error')) +
            '<div class="small muted nowrap" title="' + esc(t.last_message || '') + '">' +
            esc(fmtDateTime(t.last_publish_at)) + '</div>')
          : '<span class="faint">从未</span>';
        return {
          cells: [
            { html: esc(t.name) + (t.kind === 'command' ? ' ' + badge('命令', 'badge-info') : '') },
            { cls: 'mono small', html: esc(t.path || '—') },
            { cls: 'mono small', html: esc(t.filename || '—') },
            { html: esc(String(t.format || '').toUpperCase()) },
            { html: esc(pubContentLabel(t.content)) },
            { cls: 'mono small', html: esc(t.reload_cmd || '—') },
            {
              html: '<label class="check"><input type="checkbox" data-toggle="pub-target" data-id="' +
                esc(t.id) + '"' + (t.enabled ? ' checked' : '') + '> ' +
                (t.enabled ? '启用' : '停用') + '</label>'
            },
            { html: last },
            {
              html: '<div class="actions">' +
                '<button class="btn btn-sm" type="button" data-act="pub-target-test" data-id="' + esc(t.id) + '">测试</button>' +
                '<button class="btn btn-sm" type="button" data-act="pub-target-edit" data-id="' + esc(t.id) + '">编辑</button>' +
                '<button class="btn btn-sm btn-danger" type="button" data-act="pub-target-del" data-id="' + esc(t.id) + '">删除</button>' +
                '</div>'
            }
          ]
        };
      }), { emptyTitle: '还没有发布目标', emptyDesc: '点击「添加目标」或从下方「建议目标」一键添加。' }));
  }

  function paintPublishSuggested() {
    var sg = state.publish.suggested || [];
    if (!sg.length) {
      setHTML('pubSuggested', emptyState('没有建议目标', '本机未检测到 strongSwan 的 swanctl / ipsec 目录。'));
      return;
    }
    var existing = {};
    (state.publish.targets || []).forEach(function (t) {
      existing[(t.path || '') + '|' + (t.filename || '')] = true;
    });
    setHTML('pubSuggested', '<div class="checks rs-suggest">' + sg.map(function (s, i) {
      var dup = !!existing[(s.path || '') + '|' + (s.filename || '')];
      return '<label class="check"><input type="checkbox" data-suggest="' + i + '"' + (dup ? '' : ' checked') + '> ' +
        '<span><span class="mono">' + esc((s.path || '') + '/' + (s.filename || '')) + '</span> · ' +
        esc(pubContentLabel(s.content)) + ' · ' + esc(String(s.format || '').toUpperCase()) +
        (s.reload_cmd ? ' · <span class="mono">' + esc(s.reload_cmd) + '</span>' : '') +
        (dup ? ' ' + badge('已存在', 'badge-dim') : '') + '</span></label>';
    }).join('') + '</div>');
  }

  function paintPublishTargetForm() {
    var t = state.publish.editingTarget || {};
    setText('pubTargetFormTitle', t.id ? ('编辑发布目标：' + (t.name || '')) : '添加发布目标');
    if (el('pubTName')) el('pubTName').value = t.name || '';
    if (el('pubTPath')) el('pubTPath').value = t.path || '';
    if (el('pubTFilename')) el('pubTFilename').value = t.filename || '';
    if (el('pubTFormat')) el('pubTFormat').value = (t.format || 'pem').toLowerCase();
    if (el('pubTContent')) el('pubTContent').value = t.content || 'crl';
    if (el('pubTReload')) el('pubTReload').value = t.reload_cmd || '';
    if (el('pubTMode')) el('pubTMode').value = t.mode || '0644';
    if (el('pubTOwner')) el('pubTOwner').value = t.owner || '';
    if (el('pubTEnabled')) el('pubTEnabled').checked = t.id ? !!t.enabled : true;
    show('pubTargetFormWrap', true);
  }

  function pubTargetNew() {
    state.publish.editingTarget = {};
    paintPublishTargetForm();
    if (el('pubTName')) el('pubTName').focus();
  }
  function pubTargetEdit(id) {
    var t = (state.publish.targets || []).filter(function (x) { return String(x.id) === String(id); })[0];
    if (!t) { toastErr('发布目标不存在'); return; }
    state.publish.editingTarget = t;
    paintPublishTargetForm();
    var wrap = el('pubTargetFormWrap');
    if (wrap && wrap.scrollIntoView) wrap.scrollIntoView({ block: 'nearest' });
  }
  function pubTargetCancel() {
    state.publish.editingTarget = null;
    show('pubTargetFormWrap', false);
  }

  function pubTargetSave() {
    var t = state.publish.editingTarget || {};
    var name = trim(val('pubTName'));
    var path = trim(val('pubTPath'));
    if (!name) { toastErr('请填写目标名称'); return Promise.resolve(); }
    if (!path) { toastErr('请填写目标目录或命令'); return Promise.resolve(); }
    var body = {
      name: name, path: path, filename: trim(val('pubTFilename')),
      format: val('pubTFormat') || 'pem', content: val('pubTContent') || 'crl',
      reload_cmd: trim(val('pubTReload')), mode: trim(val('pubTMode')) || '0644',
      owner: trim(val('pubTOwner')), enabled: checked('pubTEnabled')
    };
    return withButton($('[data-act="pub-target-save"]'), function () {
      var req = t.id
        ? apiPatch('/api/publish/targets/' + encodeURIComponent(t.id), body)
        : apiPost('/api/publish/targets', body);
      return req.then(function () {
        state.publish.editingTarget = null;
        show('pubTargetFormWrap', false);
        toastOk(t.id ? '发布目标已更新' : '发布目标已添加');
        return refreshPublishTargets();
      });
    });
  }

  function refreshPublishTargets() {
    return apiGet('/api/publish/targets').then(function (t) {
      t = t || {};
      state.publish.targets = t.items || [];
      state.publish.suggested = t.suggested || [];
      state.publish.detected = t.detected || null;
      state.publish.staging_dir = t.staging_dir || '';
      var d = state.publish.detected || {};
      setText('pubDetected', (d.swanctl || d.ipsec)
        ? ('检测到 ' + (d.swanctl ? 'swanctl' : 'ipsec'))
        : '未检测到 strongSwan（仍可写入暂存目录）');
      paintPublishTargets();
      paintPublishSuggested();
    });
  }

  function pubTestTarget(id) {
    return withButton($('[data-act="pub-target-test"][data-id="' + id + '"]'), function () {
      return apiPost('/api/publish/targets/' + encodeURIComponent(id) + '/test', {}).then(function (d) {
        var ok = !!(d && d.ok);
        setHTML('pubTargetTestResult', '<div class="callout ' + (ok ? '' : 'callout-warn') + ' small">' +
          '<strong>测试目标 #' + esc(id) + '：' + (ok ? '通过' : '未通过') + '</strong> ' +
          esc((d && d.message) || '') +
          (d && d.resolved_path ? '（解析路径：<span class="mono">' + esc(d.resolved_path) + '</span>）' : '') +
          '</div>');
        toast(ok ? '测试通过' : '测试未通过：' + ((d && d.message) || ''), ok ? 'success' : 'warn', 8000);
      });
    });
  }

  function pubTargetToggle(id, enabled) {
    return apiPatch('/api/publish/targets/' + encodeURIComponent(id), { enabled: !!enabled })
      .then(function () {
        toastOk(enabled ? '发布目标已启用' : '发布目标已停用');
        return refreshPublishTargets();
      }).catch(function () {
        return refreshPublishTargets();
      });
  }

  function pubDeleteTarget(id) {
    var t = (state.publish.targets || []).filter(function (x) { return String(x.id) === String(id); })[0] || {};
    return confirmAction({
      title: '删除发布目标',
      danger: true,
      okText: '确认删除',
      warning: '删除后该目标不再接收 CRL / CA 证书，已写入的文件不会被删除。',
      message: '确认删除该发布目标？',
      impact: [
        ['名称', t.name || '—'],
        ['路径', t.path || '—'],
        ['内容', pubContentLabel(t.content) + ' / ' + String(t.format || '').toUpperCase()]
      ]
    }).then(function (res) {
      if (!res) return;
      return apiDel('/api/publish/targets/' + encodeURIComponent(id)).then(function () {
        toastOk('发布目标已删除');
        return refreshPublishTargets();
      });
    });
  }

  function pubSuggestAdd() {
    var picks = $$('[data-suggest]', el('pubSuggested')).filter(function (c) { return c.checked; })
      .map(function (c) { return state.publish.suggested[parseInt(c.getAttribute('data-suggest'), 10)]; })
      .filter(Boolean);
    if (!picks.length) { toastErr('请先勾选要添加的建议目标'); return Promise.resolve(); }
    return withButton(el('pubSuggestAddBtn'), function () {
      var created = 0, failed = [];
      return picks.reduce(function (chain, s) {
        return chain.then(function () {
          return apiPost('/api/publish/targets', {
            name: s.name, path: s.path, filename: s.filename, format: s.format,
            content: s.content, reload_cmd: s.reload_cmd, mode: s.mode,
            owner: s.owner, enabled: !!s.enabled
          }).then(function () { created++; }, function (err) {
            failed.push((s.name || s.path) + '：' + ((err && err.message) || '失败'));
          });
        });
      }, Promise.resolve()).then(function () {
        toastOk('已添加 ' + created + ' 个发布目标' + (failed.length ? '，' + failed.length + ' 个失败' : ''));
        if (failed.length) toastWarn(failed.join('；'));
        return refreshPublishTargets();
      });
    });
  }

  function pubSetAuto() {
    var auto = checked('pubAutoPublish');
    var wasAuto = !!(state.publish.status && state.publish.status.auto_publish);
    var body = {
      auto_publish: auto,
      lead_hours: rsNumOr('pubLeadHours', 72),
      interval_minutes: rsNumOr('pubIntervalMinutes', 60),
      auto_reload: checked('pubAutoReload')
    };
    function save() {
      return withButton(el('pubAutoSave'), function () {
        return apiPost('/api/publish/auto', body).then(function (st) {
          state.publish.status = st || state.publish.status;
          toastOk('自动发布设置已保存');
          paintPublish();
        });
      });
    }
    if (wasAuto && !auto) {
      return confirmAction({
        title: '关闭 CRL 自动发布',
        danger: true,
        okText: '确认关闭',
        warning: '关闭后 CRL 不会在 nextUpdate 到期前自动重新生成与发布。' +
          '一旦 strongSwan 读到过期的 CRL，会判定吊销状态不可用。',
        message: '确认关闭自动发布？',
        impact: [
          ['自动发布', '开启 → 关闭'],
          ['提前小时数', String(body.lead_hours) + ' 小时'],
          ['检查间隔', String(body.interval_minutes) + ' 分钟']
        ]
      }).then(function (r) { if (r) return save(); });
    }
    return save();
  }

  function pubNow() {
    return withButton(el('pubNowBtn'), function () {
      setHTML('pubNowResult', '<div class="muted small">正在重新生成 CRL 并发布到所有启用目标…</div>');
      return apiPost('/api/publish/now', { reload: true }).then(function (d) {
        var results = (d && d.results) || [];
        var fails = results.filter(function (r) { return !r.ok; }).length;
        var html = '<div class="callout ' + (fails ? 'callout-danger' : '') + ' small" style="margin-top:10px">' +
          '<strong>' + (fails ? ('发布完成，但有 ' + fails + ' 个目标失败') : '发布完成：全部目标成功') + '</strong>' +
          (d && d.crl ? '（CRL #' + esc(d.crl.number) + '，条目 ' + esc(d.crl.entries == null ? '—' : d.crl.entries) + '）' : '') +
          '</div>';
        html += '<div class="table-wrap">' + tableHTML(
          ['目标', '路径', '内容', 'SHA-256', '结果', '消息'],
          results.map(function (r) {
            return {
              attrs: r.ok ? '' : ' class="row-fail"',
              cells: [
                { html: esc(r.target_name || '—') },
                { cls: 'mono small', html: esc(r.path || '—') },
                { html: esc(pubContentLabel(r.content)) },
                { cls: 'mono small', html: r.sha256 ? esc(truncateMid(r.sha256, 12, 8)) : '—' },
                { html: r.ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error') },
                {
                  html: esc(r.message || '') +
                    (r.reload_output ? '<details><summary class="small muted">reload 输出</summary><pre class="pem">' +
                      esc(r.reload_output) + '</pre></details>' : '')
                }
              ]
            };
          }), { emptyTitle: '没有启用的发布目标', emptyDesc: '请先添加并启用发布目标。' }) + '</div>';
        setHTML('pubNowResult', html);
        toast(fails ? ('发布完成，有 ' + fails + ' 个目标失败') : 'CRL 已重新生成并发布',
          fails ? 'warn' : 'success', fails ? 8000 : 4000);
        return Promise.all([
          apiGet('/api/publish/status').then(function (s) { state.publish.status = s || {}; }),
          apiGet('/api/publish/log', { page: 1, page_size: state.publish.log.page_size })
            .then(function (l) { paintPublishLog(l || {}); })
        ]).then(function () { return refreshPublishTargets(); }).then(function () { paintPublish(); });
      }).catch(function (err) {
        setHTML('pubNowResult', '<div class="callout callout-danger small" style="margin-top:10px">发布失败：' +
          esc((err && err.message) || '未知错误') + '</div>');
      });
    });
  }

  function fetchPublishLog(page) {
    state.publish.log.page = paginate(page, state.publish.log.total, state.publish.log.page_size);
    setHTML('pubLog', skeletonTable(7, 5));
    return apiGet('/api/publish/log', {
      page: state.publish.log.page, page_size: state.publish.log.page_size
    }).then(function (d) { paintPublishLog(d || {}); });
  }

  function paintPublishLog(d) {
    state.publish.log.items = d.items || [];
    state.publish.log.total = d.total || 0;
    if (d.page) state.publish.log.page = d.page;
    if (d.page_size) state.publish.log.page_size = d.page_size;
    setHTML('pubLog', tableHTML(
      ['时间', '目标', '路径', 'SHA-256', '结果', '消息', '触发方式'],
      (state.publish.log.items || []).map(function (r) {
        return {
          cells: [
            { cls: 'nowrap', html: esc(fmtDateTime(r.ts)) },
            { html: esc(r.target_name || '—') },
            { cls: 'mono small', html: esc(r.path || '—') },
            { cls: 'mono small', html: r.sha256 ? esc(truncateMid(r.sha256, 12, 8)) : '<span class="faint">—</span>' },
            { html: r.ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error') },
            {
              html: esc(r.message || '—') +
                (r.reload_output ? '<details><summary class="small muted">reload 输出</summary><pre class="pem">' +
                  esc(r.reload_output) + '</pre></details>' : '')
            },
            { html: esc(r.trigger || '—') }
          ]
        };
      }), { emptyTitle: '暂无发布记录', emptyDesc: '点击「立即重新生成并发布」后会写入记录。' }));
    setHTML('pubLogPager', pagerHTML(state.publish.log.page, state.publish.log.page_size,
      state.publish.log.total, 'pub-log-page'));
  }

  function pubRefreshAll() {
    return Promise.all([
      apiGet('/api/publish/status').then(function (s) { state.publish.status = s || {}; }),
      refreshPublishTargets(),
      apiGet('/api/publish/log', { page: state.publish.log.page, page_size: state.publish.log.page_size })
        .then(function (l) { paintPublishLog(l || {}); })
    ]).then(function () { paintPublish(); toastOk('发布状态已刷新'); });
  }

  /* ====================================================================== */
  /* 19. 自动化（可扩展：通知 / 归档 / 多网关分发…）                        */
  /* ====================================================================== */
  function renderAutomation() {
    show('autoFormWrap', false);
    setHTML('autoTable', skeletonTable(7, 4));
    setHTML('autoLog', skeletonTable(7, 5));
    setHTML('autoRunResult', '');
    return Promise.all([
      apiGet('/api/automation/meta'),
      apiGet('/api/automation/tasks')
    ]).then(function (res) {
      var meta = res[0] || {};
      state.automation.meta = meta;
      state.automation.tasks = (res[1] && res[1].items) || [];
      state.automation.editing = null;
      state.automation.formOpen = false;
      if (meta.note) setText('autoNote', meta.note);
      setText('autoStaging', meta.staging_dir ? ('暂存目录：' + meta.staging_dir) : '');
      fillAutoSelects();
      fillAutoLogTaskSelect();
      paintAutomationTasks();
      return fetchAutomationLog(1);
    });
  }

  function fillAutoSelects() {
    var meta = state.automation.meta || {};
    if (el('autoKind')) el('autoKind').innerHTML = rsOpts(meta.kinds || [], val('autoKind') || 'file');
    if (el('autoTrigger')) el('autoTrigger').innerHTML = rsOpts(meta.triggers || [], val('autoTrigger') || 'manual');
    if (el('autoContent')) el('autoContent').innerHTML = rsOpts(meta.contents || [], val('autoContent') || 'none');
  }

  function fillAutoLogTaskSelect() {
    var sel = el('autoLogTask');
    if (!sel) return;
    sel.innerHTML = '<option value="">全部任务</option>' + (state.automation.tasks || []).map(function (t) {
      return '<option value="' + esc(t.id) + '"' +
        (String(state.automation.log.task_id) === String(t.id) ? ' selected' : '') + '>' +
        esc(t.name) + '</option>';
    }).join('');
  }

  function autoTriggerText(t) {
    var meta = state.automation.meta || {};
    var found = (meta.triggers || []).filter(function (x) { return x.id === t; })[0];
    return found ? found.label : (t || '—');
  }
  function autoKindText(k) {
    var meta = state.automation.meta || {};
    var found = (meta.kinds || []).filter(function (x) { return x.id === k; })[0];
    return found ? found.label : (k || '—');
  }
  function autoContentText(c) {
    var meta = state.automation.meta || {};
    var found = (meta.contents || []).filter(function (x) { return x.id === c; })[0];
    return found ? found.label : (c || '—');
  }
  function autoTargetText(t) {
    var tgt = (t && t.target) || {};
    if (t.kind === 'file') return tgt.path ? (tgt.path + (tgt.filename ? '/' + tgt.filename : '')) : '—';
    if (t.kind === 'command') return tgt.cmd || '—';
    if (t.kind === 'webhook') return (tgt.method || 'POST') + ' ' + (tgt.url || '—');
    return '—';
  }

  function paintAutomationTasks() {
    var items = state.automation.tasks || [];
    setHTML('autoTable', tableHTML(
      ['名称', '动作', '触发器', '内容', '目标', '启用', '上次运行', '操作'],
      items.map(function (t) {
        var last = t.last_run
          ? ((t.last_ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error')) +
            '<div class="small muted nowrap" title="' + esc(t.last_message || '') + '">' +
            esc(fmtDateTime(t.last_run)) + '</div>')
          : '<span class="faint">从未运行</span>';
        return {
          cells: [
            { html: esc(t.name) + (t.note ? '<div class="small muted">' + esc(t.note) + '</div>' : '') },
            { html: esc(autoKindText(t.kind)) },
            { html: esc(autoTriggerText(t.trigger)) +
                (t.trigger === 'schedule' ? '<div class="small muted">每 ' + esc(t.interval_minutes) + ' 分钟</div>' : '') +
                (t.trigger === 'crl_expiry' ? '<div class="small muted">提前 ' + esc(t.lead_hours) + ' 小时</div>' : '') },
            { html: esc(autoContentText(t.content)) +
                (t.only_if_changed ? ' ' + badge('仅变化时', 'badge-dim') : '') },
            { cls: 'mono small', html: esc(autoTargetText(t)) },
            {
              html: '<label class="check"><input type="checkbox" data-toggle="au-task" data-id="' +
                esc(t.id) + '"' + (t.enabled ? ' checked' : '') + '> ' + (t.enabled ? '启用' : '停用') + '</label>'
            },
            { html: last },
            {
              html: '<div class="actions">' +
                '<button class="btn btn-sm" type="button" data-act="au-run" data-id="' + esc(t.id) + '">运行</button>' +
                '<button class="btn btn-sm" type="button" data-act="au-edit" data-id="' + esc(t.id) + '">编辑</button>' +
                '<button class="btn btn-sm btn-danger" type="button" data-act="au-del" data-id="' + esc(t.id) + '">删除</button>' +
                '</div>'
            }
          ]
        };
      }), { emptyTitle: '还没有自动化任务', emptyDesc: '点击「新建任务」或「安装预置示例」。' }));
  }

  function autoById(id) {
    return (state.automation.tasks || []).filter(function (t) {
      return String(t.id) === String(id);
    })[0] || null;
  }

  function autoFormOpen(id) {
    var t = id ? autoById(id) : null;
    state.automation.editing = t || { id: null };
    state.automation.formOpen = true;
    var tgt = (t && t.target) || {};
    setText('autoFormTitle', t ? ('编辑任务：' + t.name) : '新建自动化任务');
    if (el('autoName')) el('autoName').value = (t && t.name) || '';
    if (el('autoKind')) el('autoKind').value = (t && t.kind) || 'file';
    if (el('autoTrigger')) el('autoTrigger').value = (t && t.trigger) || 'manual';
    if (el('autoContent')) el('autoContent').value = (t && t.content) || 'none';
    if (el('autoFilePath')) el('autoFilePath').value = tgt.path || '';
    if (el('autoTargetFilename')) el('autoTargetFilename').value = tgt.filename || '';
    if (el('autoMode')) el('autoMode').value = tgt.mode || '0644';
    if (el('autoOwner')) el('autoOwner').value = tgt.owner || '';
    if (el('autoCmd')) el('autoCmd').value = tgt.cmd || '';
    if (el('autoUrl')) el('autoUrl').value = tgt.url || '';
    if (el('autoMethod')) el('autoMethod').value = (tgt.method || 'POST').toUpperCase();
    if (el('autoSecret')) el('autoSecret').value = tgt.secret || '';
    if (el('autoCertId')) el('autoCertId').value = tgt.cert_id || '';
    if (el('autoInterval')) el('autoInterval').value = (t && t.interval_minutes) || 60;
    if (el('autoLead')) el('autoLead').value = (t && t.lead_hours) || 72;
    if (el('autoEnabled')) el('autoEnabled').checked = t ? !!t.enabled : true;
    if (el('autoOnlyIfChanged')) el('autoOnlyIfChanged').checked = t ? !!t.only_if_changed : true;
    if (el('autoTaskNote')) el('autoTaskNote').value = (t && t.note) || '';
    show('autoFormWrap', true);
    autoPaintDynamic();
    if (el('autoName') && el('autoName').focus) el('autoName').focus();
  }

  function autoPaintDynamic() {
    var kind = val('autoKind') || 'file';
    var trigger = val('autoTrigger') || 'manual';
    var content = val('autoContent') || 'none';
    show('autoTargetFile', kind === 'file');
    show('autoTargetFileMode', kind === 'file');
    show('autoTargetCommand', kind === 'command');
    show('autoTargetWebhook', kind === 'webhook');
    show('autoIntervalField', trigger === 'schedule');
    show('autoLeadField', trigger === 'crl_expiry');
    show('autoCertIdField', content === 'cert_pem' || content === 'cert_key');
  }

  function autoCollect() {
    var kind = val('autoKind') || 'file';
    var trigger = val('autoTrigger') || 'manual';
    var content = val('autoContent') || 'none';
    var target = {};
    if (kind === 'file') {
      target.path = trim(val('autoFilePath'));
      if (trim(val('autoTargetFilename'))) target.filename = trim(val('autoTargetFilename'));
      target.mode = trim(val('autoMode')) || '0644';
      if (trim(val('autoOwner'))) target.owner = trim(val('autoOwner'));
    } else if (kind === 'command') {
      target.cmd = trim(val('autoCmd'));
    } else if (kind === 'webhook') {
      target.url = trim(val('autoUrl'));
      target.method = (val('autoMethod') || 'POST').toUpperCase();
      target.secret = val('autoSecret');
    }
    if (content === 'cert_pem' || content === 'cert_key') {
      var cid = trim(val('autoCertId'));
      if (cid) target.cert_id = /^\d+$/.test(cid) ? parseInt(cid, 10) : cid;
    }
    return {
      name: trim(val('autoName')),
      kind: kind,
      content: content,
      trigger: trigger,
      target: target,
      interval_minutes: rsNumOr('autoInterval', 60),
      lead_hours: rsNumOr('autoLead', 72),
      only_if_changed: checked('autoOnlyIfChanged'),
      enabled: checked('autoEnabled'),
      note: val('autoTaskNote')
    };
  }

  function autoSave() {
    var body = autoCollect();
    if (!body.name) { toastErr('请填写任务名称'); return Promise.resolve(); }
    var editing = state.automation.editing || {};
    return withButton($('[data-act="au-save"]'), function () {
      var req = editing.id
        ? apiPatch('/api/automation/tasks/' + encodeURIComponent(editing.id), body)
        : apiPost('/api/automation/tasks', body);
      return req.then(function () {
        toastOk(editing.id ? '任务已更新' : '任务已创建');
        state.automation.editing = null;
        state.automation.formOpen = false;
        show('autoFormWrap', false);
        return reloadAutomationTasks();
      });
    });
  }

  function autoCancel() {
    state.automation.editing = null;
    state.automation.formOpen = false;
    show('autoFormWrap', false);
  }

  function reloadAutomationTasks() {
    return apiGet('/api/automation/tasks').then(function (d) {
      state.automation.tasks = (d && d.items) || [];
      fillAutoLogTaskSelect();
      paintAutomationTasks();
    });
  }

  function autoRun(id) {
    var t = autoById(id);
    return withButton($('[data-act="au-run"][data-id="' + id + '"]'), function () {
      setHTML('autoRunResult', '<div class="callout small">正在运行「' + esc((t && t.name) || id) + '」…</div>');
      return apiPost('/api/automation/tasks/' + encodeURIComponent(id) + '/run', { force: true })
        .then(function (d) {
          var ok = !!(d && d.ok);
          var html = '<div class="card"><div class="card-head"><h2>运行结果：' + esc((t && t.name) || id) + '</h2>' +
            (ok ? badge(d && d.skipped ? '已跳过' : '成功', 'badge-valid') : badge('失败', 'badge-error')) +
            '<button class="btn btn-sm btn-ghost" type="button" data-act="au-run-close">收起</button></div>' +
            '<div class="card-body">' +
            '<dl class="kv">' +
            row('结果', ok ? '成功' : '失败') +
            row('消息', esc((d && d.message) || '—')) +
            row('SHA-256', d && d.sha256 ? '<span class="mono">' + esc(d.sha256) + '</span>' : '<span class="faint">—</span>') +
            row('跳过', d && d.skipped ? '是（内容未变化）' : '否') +
            '</dl>' +
            ((d && d.output) ? '<div class="copy-row"><span class="muted small">命令 / Webhook 输出</span></div>' +
              '<pre class="pem">' + esc(d.output) + '</pre>' : '') +
            '</div></div>';
          setHTML('autoRunResult', html);
          if (!ok) toastErr('运行失败：' + ((d && d.message) || '未知原因'));
          else toastOk(d && d.skipped ? '内容未变化，已跳过' : '运行成功');
          return Promise.all([
            reloadAutomationTasks(),
            fetchAutomationLog(1)
          ]);
        }).catch(function (err) {
          setHTML('autoRunResult', '<div class="callout callout-danger small">运行失败：' +
            esc((err && err.message) || '未知错误') + '</div>');
        });
    });
  }

  function autoToggle(id, enabled) {
    return apiPatch('/api/automation/tasks/' + encodeURIComponent(id), { enabled: !!enabled })
      .then(function () {
        toastOk(enabled ? '任务已启用' : '任务已停用');
        return reloadAutomationTasks();
      }).catch(function () { return reloadAutomationTasks(); });
  }

  function autoDelete(id) {
    var t = autoById(id);
    return confirmAction({
      title: '删除自动化任务',
      danger: true,
      okText: '确认删除',
      warning: '删除后无法恢复，该任务不再被任何触发器调用（历史运行记录保留）。',
      message: '确认删除该任务？',
      impact: [
        ['任务', (t && t.name) || '—'],
        ['动作', autoKindText(t && t.kind)],
        ['触发器', autoTriggerText(t && t.trigger) + ' · 内容：' + autoContentText(t && t.content)]
      ]
    }).then(function (res) {
      if (!res) return;
      return apiDel('/api/automation/tasks/' + encodeURIComponent(id)).then(function () {
        toastOk('任务已删除');
        return reloadAutomationTasks();
      });
    });
  }

  function autoPresets() {
    return withButton($('[data-act="au-presets"]'), function () {
      return apiPost('/api/automation/presets', {}).then(function (d) {
        var created = (d && d.created) || [];
        state.automation.tasks = (d && d.items) || state.automation.tasks;
        fillAutoLogTaskSelect();
        paintAutomationTasks();
        if (created.length) {
          setHTML('autoRunResult', '<div class="callout small"><strong>已安装 ' + created.length +
            ' 个预置示例（默认停用，按需启用）：</strong><ul class="rs-err-list">' +
            created.map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') + '</ul></div>');
          toastOk('已安装 ' + created.length + ' 个预置示例');
        } else {
          setHTML('autoRunResult', '<div class="callout small">没有新增预置示例（同名任务已存在）。</div>');
          toastWarn('没有新增预置示例（同名任务已存在）');
        }
      });
    });
  }

  function fetchAutomationLog(page) {
    var job = state.automation.log;
    job.task_id = (el('autoLogTask') ? val('autoLogTask') : job.task_id) || '';
    job.page = paginate(page, job.total, job.page_size);
    setHTML('autoLog', skeletonTable(7, 5));
    return apiGet('/api/automation/log', {
      page: job.page, page_size: job.page_size, task_id: job.task_id
    }).then(function (d) { paintAutomationLog(d || {}); });
  }

  function paintAutomationLog(d) {
    var job = state.automation.log;
    job.items = d.items || [];
    job.total = d.total || 0;
    if (d.page) job.page = d.page;
    if (d.page_size) job.page_size = d.page_size;
    setHTML('autoLog', tableHTML(
      ['时间', '任务', '触发', '结果', '消息', 'SHA-256', '输出'],
      (job.items || []).map(function (r) {
        return {
          cells: [
            { cls: 'nowrap', html: esc(fmtDateTime(r.ts)) },
            { html: esc(r.task_name || '—') },
            { html: esc(autoTriggerText(r.trigger) || r.trigger || '—') },
            {
              html: r.skipped ? badge('已跳过', 'badge-dim')
                : (r.ok ? badge('成功', 'badge-valid') : badge('失败', 'badge-error'))
            },
            { html: esc(r.message || '—') + '<div class="small faint">操作人：' + esc(r.actor || '—') + '</div>' },
            { cls: 'mono small', html: r.sha256 ? esc(truncateMid(r.sha256, 12, 8)) : '<span class="faint">—</span>' },
            {
              html: r.output
                ? '<details><summary class="small muted">查看输出</summary><pre class="pem">' + esc(r.output) + '</pre></details>'
                : '<span class="faint">—</span>'
            }
          ]
        };
      }), { emptyTitle: '暂无运行记录', emptyDesc: '任务运行后会写入历史记录。' }));
    setHTML('autoLogPager', pagerHTML(job.page, job.page_size, job.total, 'au-log-page'));
  }

  /* ====================================================================== */
  /* 17. 全局事件委托                                                       */
  /* ====================================================================== */

  function certIdFromEvent(e) {
    var node = e.target.closest ? e.target.closest('[data-id]') : null;
    if (node) return node.getAttribute('data-id');
    if (state.route === '#/cert') return state.detail.id;
    return null;
  }
  function certFromEvent(e) {
    var id = certIdFromEvent(e);
    return id ? certById(id) : (state.route === '#/cert' ? state.detail.cert : null);
  }

  function handleAction(e) {
    var node = e.target.closest ? e.target.closest('[data-act]') : null;
    if (!node) return;
    var act = node.getAttribute('data-act');
    var id = node.getAttribute('data-id');

    switch (act) {
      /* CSR 证书请求池 */
      case 'csr-refresh': csrLoad(true).catch(function () {}); return;
      case 'csr-page': state.csrs.page = paginate(node.getAttribute('data-page'),
        state.csrs.total, state.csrs.page_size); csrLoad().catch(function () {}); return;
      case 'csr-pick': if (el('csrFiles')) el('csrFiles').click(); return;
      case 'csr-dir': csrImportDir(); return;
      case 'csr-import-do':
        if (state.csrs.previewDir) csrImportDirCommit(); else csrImport(false);
        return;
      case 'csr-preview-cancel':
        state.csrs.preview = null; show('csrPreviewCard', false);
        if (el('csrFiles')) el('csrFiles').value = ''; return;
      case 'csr-issue': csrIssueDialog(parseInt(id, 10)); return;
      case 'csr-download': csrDownload(parseInt(id, 10), node.getAttribute('data-cn')); return;
      case 'csr-detail': csrDetail(parseInt(id, 10)); return;
      case 'csr-reject': csrReject(parseInt(id, 10)); return;
      case 'csr-delete': csrDelete(parseInt(id, 10)); return;
      /* 证书列表 */
      case 'certs-page': certsGoPage(node.getAttribute('data-page')); return;
      /* 详情 */
      case 'cert-refresh': renderCertDetail({ id: state.detail.id }).catch(function () {}); return;
      case 'cert-save-meta': certSaveMeta(); return;
      case 'cert-delete': certDelete(certFromEvent(e)); return;
      case 'cert-dl': {
        var c1 = certFromEvent(e);
        if (node.getAttribute('data-format') === 'p12') askP12Password(c1);
        else certDownload(c1, node.getAttribute('data-format'));
        return;
      }
      case 'cert-dl-p12': askP12Password(certFromEvent(e)); return;
      case 'copy-pem': {
        var pre = el(node.getAttribute('data-target'));
        copyText(pre ? pre.textContent : '', '证书 PEM 已复制');
        return;
      }
      case 'load-pem': loadPemText(); return;
      /* 列表行内操作 */
      case 'cert-download': {
        certDownload(certFromEvent(e), 'pem');
        return;
      }
      case 'cert-renew': certRenew(certFromEvent(e)); return;
      case 'cert-revoke': certRevoke(certFromEvent(e)); return;
      case 'cert-unrevoke': certUnrevoke(certFromEvent(e)); return;
      /* 签发结果 */
      case 'secret-download': secretDownload(node.getAttribute('data-kind')); return;
      case 'secret-copy': {
        var s = secretPayload();
        var kind = node.getAttribute('data-kind');
        var text = kind === 'key' ? s.key_pem : s.cert_pem;
        if (!text) { toastErr('内容不可用'); return; }
        copyText(text, kind === 'key' ? '私钥已复制' : '证书已复制');
        return;
      }
      /* 吊销 / CRL */
      case 'rev-select': revSelect(id); return;
      case 'crl-generate': crlGenerate(); return;
      case 'crl-dl': crlDownload(node.getAttribute('data-format')); return;
      /* 导入 */
      case 'imp-files-precheck': importFiles(true); return;
      case 'imp-files-import': importFiles(false); return;
      case 'imp-dir-precheck': importDir(true); return;
      case 'imp-dir-import': importDir(false); return;
      case 'imp-csv-precheck': importCsv(true); return;
      case 'imp-csv-import': importCsv(false); return;
      /* 体检 */
      case 'cons-check': consCheck(); return;
      case 'cons-fix': consFix(node.getAttribute('data-code')); return;
      case 'cons-fix-all': consFixAll(); return;
      /* 审计 */
      case 'audit-page': auditGoPage(node.getAttribute('data-page')); return;
      case 'audit-toggle': {
        var pre2 = el('auditDetail-' + id);
        if (pre2) { pre2.hidden = !pre2.hidden; node.textContent = pre2.hidden ? '展开 JSON' : '收起 JSON'; }
        return;
      }
      /* CA */
      case 'ca-dl': {
        var fmt = node.getAttribute('data-format');
        if (state.ca) caDownload(state.ca.id, fmt, state.ca);
        else toastErr('当前没有 CA');
        return;
      }
      case 'ca-dl-id': {
        var target = null;
        (state.caList || []).forEach(function (c) { if (String(c.id) === String(id)) target = c; });
        caDownload(id, node.getAttribute('data-format'), target);
        return;
      }
      case 'ca-activate': caActivate(id); return;
      case 'ca-import': caImport(); return;
      /* 设置 */
      case 'settings-save': settingsSave(); return;
      case 'settings-pwd': settingsChangePassword(); return;
      case 'backup-create': backupCreate(); return;
      case 'backup-dl': downloadApi('/api/backup/download', { name: node.getAttribute('data-name') }, node.getAttribute('data-name')); return;
      case 'restore': restoreBackup(); return;
      case 'theme-toggle': toggleTheme(); return;
      case 'logout': logout(); return;
      case 'sec-reset-pin': resetFingerprintPin(); return;
      case 'expand-ca-warn': navigate('#/ca'); return;

      /* ---- 规则集 ---- */
      case 'rs-refresh': renderRulesets().catch(function () {}); return;
      case 'rs-new': rsOpenEditor(null).catch(function () {}); return;
      case 'rs-edit': rsOpenEditor(id).catch(function () {}); return;
      case 'rs-close-editor': rsCloseEditor(); return;
      case 'rs-save': rsSaveForm(); return;
      case 'rs-validate': rsValidateForm(); return;
      case 'rs-notes':
        state.rulesets.notesSlug = node.getAttribute('data-slug');
        paintRulesets();
        return;
      case 'rs-default': rsSetDefault(node.getAttribute('data-slug')); return;
      case 'rs-default-pick': rsSetDefault(val('rsDefault')); return;
      case 'rs-dup': rsDuplicate(id); return;
      case 'rs-reset': rsReset(id); return;
      case 'rs-del': rsDelete(id); return;
      case 'rs-add-custom': {
        var rsHost = el('rsCustomRows');
        if (rsHost) rsHost.insertAdjacentHTML('beforeend', rsCustomRowHTML({}));
        return;
      }
      case 'rs-del-custom': {
        var rsRow = node.closest('.rs-custom-row');
        if (rsRow) rsRow.remove();
        return;
      }
      case 'rs-add-eku': {
        var ekuHost = el('rsEkuExtras');
        if (ekuHost) ekuHost.insertAdjacentHTML('beforeend', rsEkuRowHTML(''));
        return;
      }
      case 'rs-del-eku': {
        var ekuRow = node.closest('.rs-eku-row');
        if (ekuRow) ekuRow.remove();
        return;
      }

      /* ---- CRL 自动发布 ---- */
      case 'pub-refresh': pubRefreshAll().catch(function () {}); return;
      case 'pub-now': pubNow(); return;
      case 'pub-dl': {
        var cfmt = node.getAttribute('data-format') || 'pem';
        downloadApi('/api/crl/download', { format: cfmt }, 'crl.' + cfmt);
        return;
      }
      case 'pub-copy-cdp':
        copyText(state.publish.cdp || (el('pubCdp') ? el('pubCdp').value : ''), 'CRL 分发点地址已复制');
        return;
      case 'pub-auto-save': pubSetAuto(); return;
      case 'pub-target-new': pubTargetNew(); return;
      case 'pub-target-edit': pubTargetEdit(id); return;
      case 'pub-target-save': pubTargetSave(); return;
      case 'pub-target-cancel': pubTargetCancel(); return;
      case 'pub-target-del': pubDeleteTarget(id); return;
      case 'pub-target-test': pubTestTarget(id); return;
      case 'pub-suggest-add': pubSuggestAdd(); return;
      case 'pub-log-page': fetchPublishLog(node.getAttribute('data-page')).catch(function () {}); return;

      /* ---- 自动化 ---- */
      case 'au-new': autoFormOpen(null); return;
      case 'au-edit': autoFormOpen(id); return;
      case 'au-save': autoSave(); return;
      case 'au-cancel': autoCancel(); return;
      case 'au-del': autoDelete(id); return;
      case 'au-run': autoRun(id); return;
      case 'au-run-close': setHTML('autoRunResult', ''); return;
      case 'au-presets': autoPresets(); return;
      case 'au-refresh':
        renderAutomation().then(function () { toastOk('自动化任务已刷新'); }).catch(function () {});
        return;
      case 'au-log-refresh': fetchAutomationLog(1).catch(function () {}); return;
      case 'au-log-page': fetchAutomationLog(node.getAttribute('data-page')).catch(function () {}); return;

      /* ---- strongSwan / 部署包 ---- */
      case 'ss-refresh':
        loadStrongswanStatus().then(function () { toastOk('strongSwan 状态已刷新'); });
        return;
      case 'ss-sync-script':
        downloadApi('/api/strongswan/sync-script', {}, 'ca-strongswan-sync.sh');
        return;
      case 'cert-vpn-bundle': certVpnBundle(certFromEvent(e)); return;
      case 'ss-snippet': ssSnippetToggle(); return;
      case 'ss-snippet-load': ssSnippetLoad(); return;
      case 'ss-snippet-copy':
        if (!state.ssSnippet) { toastErr('还没有可复制的片段，请先生成'); return; }
        copyText(state.ssSnippet, 'strongSwan 配置片段已复制');
        return;

      default: return;
    }
  }

  /* 变更/输入事件 */
  function handleChange(e) {
    var t = e.target;
    if (!t) return;
    var toggle = (t.getAttribute ? t.getAttribute('data-toggle') : null);
    if (toggle === 'pub-target') { pubTargetToggle(t.getAttribute('data-id'), t.checked); return; }
    if (toggle === 'au-task') { autoToggle(t.getAttribute('data-id'), t.checked); return; }
    if (t.id === 'autoKind' || t.id === 'autoTrigger' || t.id === 'autoContent') { autoPaintDynamic(); return; }
    if (t.id === 'autoLogTask') {
      state.automation.log.task_id = t.value;
      fetchAutomationLog(1).catch(function () {});
      return;
    }
    if (t.id === 'issKeyType') { fillKeySizes(); renderIssuePreview(); return; }
    if (t.id === 'issProfile') { applyTemplateToForm(); return; }
    if (t.id === 'certStatus' || t.id === 'certProfile' || t.id === 'certTag' ||
        t.id === 'certExpires' || t.id === 'certPageSize' || t.id === 'certSort') {
      applyCertFiltersFromInputs(); return;
    }
    if (t.id === 'impMarkRevoked') {
      if (el('impRevokeReason')) el('impRevokeReason').disabled = !t.checked;
      return;
    }
    if (t.id === 'auditAction' || t.id === 'auditPageSize') {
      state.audit.action = val('auditAction');
      state.audit.page_size = parseInt(val('auditPageSize'), 10) || 20;
      state.audit.page = 1;
      fetchAudit().catch(function () {});
      return;
    }
    if (t.id === 'csrFiles') { csrImport(true); return; }
    if (t.id === 'csrStatus') {
      state.csrs.status = t.value; state.csrs.page = 1; csrLoad().catch(function () {}); return;
    }
    if (t.id === 'csrQ') {
      state.csrs.q = t.value.trim(); state.csrs.page = 1; csrLoad().catch(function () {}); return;
    }
    if (t.id === 'impFiles') { el('impFilesImport').disabled = true; return; }
    if (t.id === 'impDirPath') { el('impDirImport').disabled = true; return; }
    if (t.id === 'impCsvFile' || t.id === 'impCsvText') { el('impCsvImport').disabled = true; return; }
  }

  function applyCertFiltersFromInputs() {
    var c = state.certs;
    c.status = val('certStatus');
    c.profile = val('certProfile');
    c.tag = val('certTag');
    c.expires = val('certExpires');
    c.page_size = parseInt(val('certPageSize'), 10) || 20;
    var sortVal = val('certSort') || 'created_at:desc';
    var parts = sortVal.split(':');
    c.sort = parts[0]; c.order = parts[1] || 'desc';
    c.page = 1;
    fetchCerts().catch(function () {});
  }

  function handleKeydown(e) {
    if (e.key !== 'Enter') return;
    var t = e.target;
    if (!t) return;
    if (t.id === 'certQ' || t.id === 'certIssuer') {
      e.preventDefault();
      state.certs.q = val('certQ');
      state.certs.issuer = val('certIssuer');
      state.certs.page = 1;
      fetchCerts().catch(function () {});
    } else if (t.id === 'revSearch') {
      e.preventDefault();
      revSearch();
    } else if (t.id === 'auditQ') {
      e.preventDefault();
      state.audit.q = val('auditQ');
      state.audit.page = 1;
      fetchAudit().catch(function () {});
    } else if (t.id === 'issCn' || t.id === 'issValidity') {
      e.preventDefault();
      issueSubmit();
    } else if (t.tagName === 'TEXTAREA' && t.id !== 'issCsrText') {
      // 文本域回车不提交
    }
  }

  function handleInput(e) {
    var t = e.target;
    if (!t) return;
    if (['issCn', 'issO', 'issOu', 'issC', 'issSt', 'issL', 'issValidity', 'issProfile',
      'issKeyType', 'issKeySize', 'issSerialMode', 'issOwner', 'issTags', 'issNotes'].indexOf(t.id) >= 0) {
      if (t.id === 'issValidity') t.dataset.touched = '1';
      debouncedPreview();
    }
  }

  var previewTimer = null;
  function debouncedPreview() {
    clearTimeout(previewTimer);
    previewTimer = setTimeout(function () { renderIssuePreview(); }, 250);
  }

  /* 主题 / 退出 / 侧边栏 */
  function toggleTheme() {
    var dark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('ca_theme', dark ? 'dark' : 'light'); } catch (e) {}
    setText('btnTheme', dark ? '☀ 浅色模式' : '◐ 深色模式');
  }
  function syncThemeButton() {
    var dark = document.documentElement.classList.contains('dark');
    setText('btnTheme', dark ? '☀ 浅色模式' : '◐ 深色模式');
  }
  function logout() {
    return confirmAction({ title: '退出登录', message: '确认退出当前会话？', okText: '退出' }).then(function (res) {
      if (!res) return;
      apiPost('/api/logout', {}).catch(function () {}).finally(function () { goLogin(); });
    });
  }
  function openSidebar() { el('sidebar').classList.add('open'); el('sidebarMask').classList.add('show'); }
  function closeSidebar() { el('sidebar').classList.remove('open'); el('sidebarMask').classList.remove('show'); }

  /* ====================================================================== */
  /* 18. 启动                                                               */
  /* ====================================================================== */

  function bindGlobal() {
    document.addEventListener('click', function (e) {
      // 抽屉 / 模态框关闭
      if (e.target.closest && e.target.closest('[data-drawer-close]')) { closeDrawer(); return; }
      if (e.target.closest && e.target.closest('[data-modal-close]')) { /* 由 confirmAction 自行处理 */ return; }
      var actNode = e.target.closest ? e.target.closest('[data-act]') : null;
      if (actNode) {
        // 表格行内按钮不应触发行跳转
        handleAction(e);
        var dd = e.target.closest('.dropdown');
        if (dd) dd.classList.remove('open');
        return;
      }
      var expBtn = e.target.closest ? e.target.closest('[data-export]') : null;
      if (expBtn) {
        var fmt = expBtn.getAttribute('data-export');
        downloadApi('/api/certs/export', { format: fmt }, 'certs.' + fmt);
        var dd2 = expBtn.closest('.dropdown');
        if (dd2) dd2.classList.remove('open');
        return;
      }
      var ddBtn = e.target.closest ? e.target.closest('#certExportBtn') : null;
      if (ddBtn) {
        var ddWrap = ddBtn.closest('.dropdown');
        if (ddWrap) ddWrap.classList.toggle('open');
        return;
      }
      if (!(e.target.closest && e.target.closest('.dropdown'))) {
        $$('.dropdown.open').forEach(function (d) { d.classList.remove('open'); });
      }
    });

    document.addEventListener('change', handleChange);
    document.addEventListener('input', handleInput);
    document.addEventListener('keydown', handleKeydown);

    /* 导航链接点击（hash 路由自动处理，这里补移动端收起） */
    if (el('sidebarNav')) {
      el('sidebarNav').addEventListener('click', function (e) {
        if (e.target.closest('.nav-item')) closeSidebar();
      });
    }
    if (el('btnTheme')) el('btnTheme').addEventListener('click', toggleTheme);
    if (el('btnLogout')) el('btnLogout').addEventListener('click', logout);
    if (el('btnSidebar')) el('btnSidebar').addEventListener('click', openSidebar);
    if (el('sidebarMask')) el('sidebarMask').addEventListener('click', closeSidebar);

    /* 静态按钮（不在委托范围内的表单提交） */
    on('issAddSan', 'click', function () {
      var host = el('issSanRows');
      if (host && !host.querySelector('.san-row')) host.innerHTML = '';
      host.insertAdjacentHTML('beforeend', sanRowHTML({ type: 'DNS', value: '' }));
      var last = host.querySelector('.san-row:last-child .san-value');
      if (last) last.focus();
    });
    on('issSanRows', 'click', function (e) {
      var del = e.target.closest('[data-act="san-del"]');
      if (del) { del.closest('.san-row').remove(); renderIssuePreview(); }
    });
    on('issSanRows', 'input', debouncedPreview);
    on('issSanRows', 'change', debouncedPreview);
    on('issKeyUsage', 'change', renderIssuePreview);
    on('issEku', 'change', renderIssuePreview);
    on('issPreviewBtn', 'click', function () { renderIssuePreview(); toastOk('预览已刷新'); });
    on('issSubmit', 'click', issueSubmit);
    on('issResetForm', 'click', resetIssueForm);
    on('issCsrParse', 'click', parseCsrPem);
    on('issCsrFile', 'change', parseCsrPem);
    on('issResultClose', 'click', function () { show('issueResultCard', false); });
    on('issueModeTabs', 'click', function (e) {
      var tab = e.target.closest('[data-issue-mode]');
      if (tab) setIssueMode(tab.getAttribute('data-issue-mode'));
    });

    on('batchPrecheck', 'click', batchPrecheck);
    on('batchSubmit', 'click', batchSubmit);
    on('batchCsv', 'input', function () { el('batchSubmit').disabled = true; });

    on('certReset', 'click', function () {
      state.certs.q = ''; state.certs.status = ''; state.certs.profile = '';
      state.certs.tag = ''; state.certs.expires = ''; state.certs.issuer = '';
      state.certs.sort = 'created_at'; state.certs.order = 'desc';
      state.certs.page = 1; state.certs.page_size = 20;
      syncCertFilterInputs();
      fetchCerts().catch(function () {});
    });

    on('revSearchBtn', 'click', revSearch);
    on('revSubmit', 'click', revSubmit);
    on('revUnrevoke', 'click', revUnrevoke);
    on('crlGenerate', 'click', crlGenerate);
    on('crlRefresh', 'click', function () { loadCrl().then(function () { toastOk('CRL 信息已刷新'); }).catch(function () {}); });
    on('crlDownloadPem', 'click', function () { crlDownload('pem'); });
    on('crlDownloadDer', 'click', function () { crlDownload('der'); });
    on('crlImportBtn', 'click', crlImport);

    on('importTabs', 'click', function (e) {
      var tab = e.target.closest('[data-import-tab]');
      if (tab) setImportTab(tab.getAttribute('data-import-tab'));
    });
    on('impFilesPrecheck', 'click', function () { importFiles(true); });
    on('impFilesImport', 'click', function () { importFiles(false); });
    on('impDirPrecheck', 'click', function () { importDir(true); });
    on('impDirImport', 'click', function () { importDir(false); });
    on('impCsvPrecheck', 'click', function () { importCsv(true); });
    on('impCsvImport', 'click', function () { importCsv(false); });

    on('consCheckBtn', 'click', consCheck);
    on('consRepairAll', 'click', consFixAll);
    on('consIssues', 'change', function (e) {
      var cb = e.target.closest('[data-act="cons-pick"]');
      if (cb) state.consistency.selected[cb.getAttribute('data-code')] = cb.checked;
    });

    on('auditReset', 'click', function () {
      state.audit.action = ''; state.audit.q = ''; state.audit.page = 1;
      if (el('auditAction')) el('auditAction').value = '';
      if (el('auditQ')) el('auditQ').value = '';
      fetchAudit().catch(function () {});
    });

    on('caImportBtn', 'click', caImport);
    on('caImportReset', 'click', function () {
      ['caCertFile', 'caKeyFile', 'caChainFile', 'caKeyPassword'].forEach(function (id) {
        if (el(id)) el(id).value = '';
      });
      toastOk('已清空');
    });

    on('setSaveBtn', 'click', settingsSave);
    on('setPwdBtn', 'click', settingsChangePassword);
    on('backupRefresh', 'click', function () { loadBackups().then(function () { toastOk('备份列表已刷新'); }); });
    on('backupCreate', 'click', backupCreate);
    on('restoreBtn', 'click', restoreBackup);
  }

  function on(id, type, fn) {
    var node = el(id);
    if (!node) return;
    if (type === 'click') node.addEventListener('click', fn);
    else if (type === 'change') node.addEventListener('change', fn);
    else if (type === 'input') node.addEventListener('input', fn);
  }

  function healthPing() {
    return apiGet('/api/health', null, { timeout: 8000 }).then(function (h) {
      state.health = h || null;
      var dot = el('healthDot');
      if (dot) dot.className = 'dot ' + (h && h.status ? 'ok' : 'bad');
      if (h && h.version) {
        var t = el('sidebarUser');
        if (t) t.title = '服务版本 ' + h.version + '（' + fmtDateTime(h.time) + '）';
      }
      return h;
    }).catch(function () {
      var dot = el('healthDot');
      if (dot) dot.className = 'dot bad';
      return null;
    });
  }

  /* 加密信道状态展示：指纹用于与服务器启动日志带外核对（TOFU 固定） */
  function paintChannelState() {
    if (!channelAvailable()) return Promise.resolve();
    var box = el('secState');
    if (box) { box.hidden = false; box.title = '端到端加密信道：所有业务请求与口令都在本信道内传输'; }
    return window.CASecure.handshake().then(function () {
      var fp = (window.CASecure.info && window.CASecure.info().fingerprint) || window.CASecure.fingerprint || '';
      setText('secFingerprint', fp ? truncateMid(fp, 14, 8) : '未建立');
      var n = el('secFingerprint');
      if (n) n.title = '服务端加密信道指纹（完整值）\n' + (fp || '未建立') +
        '\n请与服务器启动日志中的指纹核对；不一致则可能存在中间人。';
      if (el('secFingerprint')) el('secFingerprint').className = 'mono small';
      return fp;
    }).catch(function (err) {
      setText('secFingerprint', '信道异常');
      showSecurityError(err);
      throw err;
    });
  }

  /* 指纹不匹配 / 握手失败时的醒目告警（带“以新指纹重置”出口，避免把用户锁死） */
  function showSecurityError(err) {
    var banner = el('secErrorBanner');
    if (!banner) { if (err && err.message) toastErr(err.message); return; }
    var fp = (err && err.fingerprint) || '';
    banner.hidden = false;
    setHTML('secErrorBody', esc((err && err.message) || '无法建立加密信道。') +
      (fp ? '<div class="mono small" style="margin-top:6px">本次服务端指纹：' + esc(fp) + '</div>' : ''));
    var actions = el('secErrorActions');
    if (actions) {
      actions.innerHTML = '<button class="btn btn-sm" type="button" data-act="sec-reset-pin">以新指纹继续（重置固定）</button>';
    }
  }

  function resetFingerprintPin() {
    return confirmAction({
      title: '重置加密信道指纹',
      warning: '仅在确认服务端确实重新生成过信道密钥时才这样做。若当前正在被中间人攻击，重置固定会让攻击者得逞。',
      message: '重置后会记录本次连接的服务端指纹，并重新建立加密信道。确认继续？',
      okText: '重置并重连'
    }).then(function (res) {
      if (!res) return;
      if (window.CASecure && window.CASecure.resetPin) window.CASecure.resetPin();
      location.reload();
    });
  }

  function boot() {
    var msg = null;
    try { msg = sessionStorage.getItem('ca_login_msg'); sessionStorage.removeItem('ca_login_msg'); } catch (e) {}
    if (msg) toastWarn(msg);

    el('app').hidden = false;
    syncThemeButton();
    bindGlobal();
    fetchMe().then(function (me) {
      state.me = me || {};
      setText('sidebarUser', (me && me.username) || '—');
      return Promise.all([
        paintChannelState().catch(function () { return null; }),
        healthPing(),
        apiGet('/api/settings').then(function (data) {
          state.settings = (data && data.settings) || data || {};
          setText('brandOrg', state.settings.org_name || '未配置机构');
        }).catch(function () {}),
        apiGet('/api/ca').then(function (data) {
          state.ca = (data && data.ca) || null;
          applyCaState(state.ca, state.health);
        }).catch(function () {}),
        loadTemplates().then(fillProfileSelect).catch(function () {})
      ]);
    }).then(function () {
      if (!location.hash) location.hash = '#/dashboard';
      route();
      setInterval(function () {
        if (document.hidden) return;
        healthPing();
      }, AUTO_REFRESH_MS);
    }).catch(function (err) {
      if (err && err.status === 401) return; // 已跳转登录
      toastErr('初始化失败：' + (err && err.message ? err.message : '未知错误'));
    });
  }

  /* ====================================================================== */
  /* CSR 证书请求池：批量导入 → 预检 → 审核 → 用规则集签发                  */
  /* ====================================================================== */

  function renderCsrs() {
    if (!state.csrs.rulesets.length) {
      return apiGet('/api/rulesets').then(function (d) {
        state.csrs.rulesets = ((d && d.items) || []).map(function (r) {
          return { id: r.id, slug: r.slug, name: r.name, used_by: r.used_by || 0 };
        });
      }).catch(function () { return null; }).then(function () { return csrLoad(); });
    }
    return csrLoad();
  }

  function csrLoad(notify) {
    var p = { page: String(state.csrs.page), page_size: String(state.csrs.page_size) };
    if (state.csrs.status) p.status = state.csrs.status;
    if (state.csrs.q) p.q = state.csrs.q;
    return apiGet('/api/csrs', p).then(function (d) {
      state.csrs.items = (d && d.items) || [];
      state.csrs.total = (d && d.total) || 0;
      state.csrs.stats = (d && d.stats) || {};
      state.csrs.page = paginate((d && d.page) || 1, state.csrs.total, state.csrs.page_size);
      csrPaint();
      if (notify) toastOk('已刷新（共 ' + state.csrs.total + ' 条）');
    });
  }

  function csrStatusBadge(st) {
    var m = {
      pending: ['待签发', 'badge-warning'],
      issued: ['已签发', 'badge-valid'],
      rejected: ['已拒绝', 'badge-error']
    };
    var v = m[st] || [st || '—', ''];
    return badge(v[0], v[1]);
  }

  function csrPaint() {
    var st = state.csrs.stats || {};
    setText('csrStats', '共 ' + state.csrs.total + ' 条 ｜ 待签发 ' + (st.pending || 0) +
      ' ｜ 已签发 ' + (st.issued || 0) + ' ｜ 已拒绝 ' + (st.rejected || 0));
    var rows = (state.csrs.items || []).map(function (it) {
      var sans = (it.sans || []).map(function (x) { return x.type + '=' + x.value; }).join('; ');
      var acts = '';
      if (it.status !== 'issued') {
        acts += '<button class="btn btn-primary btn-sm" type="button" data-act="csr-issue" data-id="' +
          it.id + '">签发</button> ';
      }
      acts += '<button class="btn btn-ghost btn-sm" type="button" data-act="csr-download" data-id="' +
        it.id + '">CSR</button> ';
      acts += '<button class="btn btn-ghost btn-sm" type="button" data-act="csr-detail" data-id="' +
        it.id + '">详情</button> ';
      if (it.status !== 'issued') {
        acts += '<button class="btn btn-ghost btn-sm" type="button" data-act="csr-reject" data-id="' +
          it.id + '">拒绝</button> ';
        acts += '<button class="btn btn-danger btn-sm" type="button" data-act="csr-delete" data-id="' +
          it.id + '">删除</button>';
      }
      return { cells: [
        { html: csrStatusBadge(it.status) },
        { html: esc(it.cn || '—') },
        { html: '<span class="mono small">' + esc(it.subject || '') + '</span>' },
        { html: esc((it.key_type || '') + ' ' + (it.key_size || '')) },
        { html: '<span class="small">' + esc(sans || '—') + '</span>' },
        { html: it.cert_id ? '<a href="#/cert/' + it.cert_id + '">证书 #' + it.cert_id + '</a>'
                           : '<span class="faint">—</span>' },
        { html: esc(it.owner || '—') },
        { html: '<span class="small">' + esc(fmtDateTime(it.created_at)) + '</span>' },
        { html: acts }
      ] };
    });
    setHTML('csrTable', tableHTML(
      ['状态', 'CN', '主题', '密钥', 'SAN', '已签发', '所有者', '提交时间', '操作'], rows,
      { emptyTitle: '请求池为空',
        emptyDesc: '点右上角「导入 CSR」批量导入证书请求（支持 .csr/.req/.p10/.pem 与 zip）' }));
    setHTML('csrPager', pagerHTML(state.csrs.page, state.csrs.page_size, state.csrs.total, 'csr-page'));
  }

  function csrRows(res) {
    var list = (res && res.preview) || [];
    return list.map(function (p) {
      return { cells: [
        { html: p.will_import ? badge('将导入', 'badge-valid')
                              : badge('跳过', 'badge-warning') },
        { html: esc(p.cn || '—') },
        { html: '<span class="mono small">' + esc(p.subject || '') + '</span>' },
        { html: esc((p.key_type || '') + ' ' + (p.key_size || '')) },
        { html: '<span class="small">' + esc((p.sans || []).map(function (x) {
            return x.type + '=' + x.value; }).join('; ') || '—') + '</span>' },
        { html: p.signature_valid ? badge('有效', 'badge-valid') : badge('校验失败', 'badge-error') },
        { html: esc(p.skip_reason || '—') }
      ] };
    });
  }

  function csrPaintPreview(res) {
    setHTML('csrPreview', tableHTML(
      ['结果', 'CN', '主题', '密钥', 'SAN', 'CSR 自签名', '说明'], csrRows(res),
      { emptyTitle: '没有可解析的 CSR' }));
    var errs = (res && res.errors) || [];
    if (errs.length) {
      setHTML('csrPreview', el('csrPreview').innerHTML +
        '<div class="callout small">无法解析 ' + errs.length + ' 个文件：' +
        esc(errs.slice(0, 5).map(function (e) { return e.name + '：' + e.error; }).join('；')) +
        (errs.length > 5 ? ' …' : '') + '</div>');
    }
    show('csrPreviewCard', true);
  }

  function csrFilesForm(dryRun, extra) {
    var files = el('csrFiles') && el('csrFiles').files;
    if (!files || !files.length) { toastWarn('请先选择 CSR 文件'); return null; }
    var fd = new FormData();
    for (var i = 0; i < files.length; i++) fd.append('files', files[i]);
    fd.append('dry_run', dryRun ? 'true' : 'false');
    Object.keys(extra || {}).forEach(function (k) { fd.append(k, extra[k]); });
    return fd;
  }

  function csrImport(dryRun) {
    var fd = csrFilesForm(dryRun);
    if (!fd) return Promise.resolve();
    var btn = dryRun ? el('csrPick') : el('csrImportDo');
    return withButton(btn, function () {
      return apiForm('/api/csrs/import', fd).then(function (res) {
        if (dryRun) {
          state.csrs.preview = res;
          csrPaintPreview(res);
          toastOk('预检完成：' + ((res.preview || []).length) + ' 条可导入');
          return null;
        }
        var n = (res.imported || []).length;
        toastOk('已导入 ' + n + ' 条（跳过 ' + ((res.skipped || []).length) + '，错误 ' +
          ((res.errors || []).length) + '）');
        state.csrs.preview = null;
        show('csrPreviewCard', false);
        if (el('csrFiles')) el('csrFiles').value = '';
        return csrLoad();
      });
    });
  }

  function csrImportDir() {
    return formDialog({
      title: '从服务器目录导入 CSR',
      message: '填写服务器上存放 CSR 的目录或文件路径（支持 .csr/.req/.p10/.pem 与 zip）。',
      html: '<div class="field"><label for="csrDirPath">路径</label>' +
        '<input id="csrDirPath" class="input mono" placeholder="/root/csr-batch"></div>',
      fields: [{ id: 'csrDirPath' }],
      okText: '预检', validate: function (v) { return v.csrDirPath ? '' : '请填写路径'; }
    }).then(function (v) {
      if (!v || !v.csrDirPath) return null;
      return apiPost('/api/csrs/import', { path: v.csrDirPath.trim(), dry_run: true })
        .then(function (res) {
          state.csrs.previewDir = v.csrDirPath.trim();
          csrPaintPreview(res);
          toastOk('预检完成：扫描 ' + (res.scanned_files || 0) + ' 个文件，' +
            ((res.preview || []).length) + ' 条可导入');
        });
    });
  }

  function csrImportDirCommit() {
    var dir = state.csrs.previewDir;
    return withButton(el('csrImportDo'), function () {
      return apiPost('/api/csrs/import', { path: dir, dry_run: false }).then(function (res) {
        toastOk('已导入 ' + ((res.imported || []).length) + ' 条（跳过 ' +
          ((res.skipped || []).length) + '）');
        state.csrs.previewDir = null;
        state.csrs.preview = null;
        show('csrPreviewCard', false);
        return csrLoad();
      });
    });
  }

  function csrIssueDialog(csrId) {
    var opts = state.csrs.rulesets.map(function (r) {
      var label = r.name + '（' + r.slug + '）';
      return '<option value="' + r.id + '"' + (r.slug === defaultRulesetSlug() ? ' selected' : '') +
        '>' + esc(label) + '</option>';
    }).join('');
    return formDialog({
      title: '用该 CSR 签发证书',
      message: 'CSR 的私钥由申请方保管，本系统不会获得私钥。',
      html: '<div class="field"><label for="csrIssRs">规则集</label>' +
        '<select id="csrIssRs" class="input">' + opts + '</select></div>' +
        '<div class="field"><label for="csrIssDays">有效期（天，留空用规则集默认）</label>' +
        '<input id="csrIssDays" class="input" type="number" min="1" placeholder="留空=规则集默认"></div>' +
        '<label class="check"><input id="csrIssForce" type="checkbox"> ' +
        '允许重复签发（该请求已签发过 / 已被拒绝时）</label>',
      fields: [{ id: 'csrIssRs' }, { id: 'csrIssDays' }, { id: 'csrIssForce', type: 'checkbox' }],
      okText: '确认签发',
      note: '签发结果里<strong>不会包含私钥</strong>（私钥一直在申请方手上）；' +
            '签好后可在证书列表里下载证书/PEM/DER 或 strongSwan 部署包。'
    }).then(function (v) {
      if (!v) return null;
      var body = { ruleset_id: parseInt(v.csrIssRs, 10), force: !!v.csrIssForce };
      if (v.csrIssDays) body.validity_days = parseInt(v.csrIssDays, 10);
      return withButton(el('csrPick'), function () {
        return apiPost('/api/csrs/' + csrId + '/issue', body).then(function (res) {
          var cert = res.cert || {};
          toastOk('已签发：' + (cert.cn || '') + '（序列号 ' + (cert.serial_hex || '').slice(0, 12) +
            '…，有效期至 ' + String(cert.not_after || '').slice(0, 10) + '）');
          return csrLoad().then(function () {
            if (cert.id) location.hash = '#/cert/' + cert.id;
          });
        });
      });
    });
  }

  function csrDownload(csrId) {
    return apiGet('/api/csrs/' + csrId).then(function (d) {
      var cn = (d.csr && d.csr.cn) || 'request';
      return downloadApi('/api/csrs/' + csrId + '/download', {}, cn + '.csr');
    });
  }

  function csrDetail(csrId) {
    return apiGet('/api/csrs/' + csrId).then(function (d) {
      var it = d.csr || {};
      var kv = function (k, v) {
        return '<dt>' + esc(k) + '</dt><dd>' + v + '</dd>';
      };
      var sans = (it.sans || []).map(function (x) { return x.type + '=' + x.value; }).join('; ');
      var html = '<dl>' +
        kv('CN', esc(it.cn || '—')) +
        kv('主题', '<span class="mono">' + esc(it.subject || '') + '</span>') +
        kv('密钥', esc((it.key_type || '') + ' ' + (it.key_size || ''))) +
        kv('SAN', esc(sans || '—')) +
        kv('CSR 自签名', it.signature_valid ? badge('通过', 'badge-valid')
                                            : badge('失败', 'badge-error')) +
        kv('状态', csrStatusBadge(it.status) +
           (it.cert_id ? ' <a href="#/cert/' + it.cert_id + '">证书 #' + it.cert_id + '</a>' : '')) +
        kv('公钥指纹', '<span class="mono small">' + esc(it.spki_fingerprint || '') + '</span>') +
        kv('提交时间', esc(fmtDateTime(it.created_at))) +
        '</dl><pre class="mono small" style="white-space:pre-wrap;max-height:240px;overflow:auto">' +
        esc(d.pem || '') + '</pre>';
      return formDialog({ title: 'CSR 详情', html: html, okText: '关闭' });
    });
  }

  function csrReject(csrId) {
    return confirmAction({
      title: '拒绝该证书请求',
      message: '拒绝后该 CSR 仍保留在池中（可复盘），但默认不能再签发。确定拒绝？',
      danger: true, okText: '确认拒绝'
    }).then(function (ok) {
      if (ok === false || ok === null || ok === undefined) return null;
      return apiPatch('/api/csrs/' + csrId, { status: 'rejected' }).then(function () {
        toastOk('已标记为拒绝');
        return csrLoad();
      });
    });
  }

  function csrDelete(csrId) {
    return confirmAction({
      title: '删除该证书请求',
      message: '仅未签发的请求可以删除；已签发的请求会保留以便追溯。确定删除？',
      danger: true, okText: '确认删除'
    }).then(function (ok) {
      if (ok === false || ok === null || ok === undefined) return null;
      return api('/api/csrs/' + csrId, { method: 'DELETE' }).then(function () {
        toastOk('已删除');
        return csrLoad();
      });
    });
  }

  function defaultRulesetSlug() {
    return (state.rulesets && state.rulesets.default_slug) || '';
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
