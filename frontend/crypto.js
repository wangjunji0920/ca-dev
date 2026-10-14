/*
 * CA 管理系统的前端加密信道（在明文 HTTP 之上自建端到端加密）。
 *
 * 密码学由 tweetnacl（vendored 到 frontend/vendor/tweetnacl.min.js）与后端 PyNaCl 完成，
 * 二者都是 libsodium 的成熟实现，本文件只做“协议编排”，不自己实现任何原语。
 *
 * 协议
 * ----
 *  1. GET  /api/handshake            -> { server_pub, fingerprint, kdf, ... }
 *  2. 客户端生成临时 X25519 密钥对；shared = crypto_box_beforenm(server_pub, client_sk)
 *     k_c2s = SHA512(shared || "CA-CHANNEL-c2s-v1")[0:32]
 *     k_s2c = SHA512(shared || "CA-CHANNEL-s2c-v1")[0:32]   （两个方向独立，避免 nonce 复用）
 *  3. POST /api/handshake {client_pub, box}   box = crypto_box(请求, 随机nonce, server_pub, client_sk)
 *     <- { ch, n, c }  c 用 k_s2c 解开，得到 { ch, fingerprint, ... }
 *  4. 之后所有业务请求走 POST /api/rpc：{ch, n, c}
 *     请求正文用 k_c2s + secretbox 加密，nonce = 计数器(8B 大端) || 随机(16B)，计数器严格递增（防重放）
 *     响应正文用 k_s2c 解开的 secretbox 信封
 *
 * 信任模型（对“HTTPS 证书也不完全可信”的正面回应）
 * ------------------------------------------------
 * 服务端长期公钥的指纹首次连接时固定（TOFU）并显示在界面上，可与服务端启动日志核对；
 * 之后指纹一旦变化会直接阻断并告警，避免被替换服务端密钥的中间人欺骗。
 *
 * 会话即信道：登录成功后服务端把用户名绑定到本信道，不再下发 cookie，
 * 因此明文 HTTP 上不存在可被窃取的会话令牌。
 */
(function (global) {
  'use strict';

  const nacl = global.nacl || (typeof require === 'function' ? require('./vendor/tweetnacl.min.js') : null);
  if (!nacl) {
    console.error('[CASecure] tweetnacl 未加载，无法建立加密信道');
    return;
  }

  const PIN_KEY = 'ca_channel_fingerprint';
  const LS = (() => {
    try { global.localStorage.setItem('__t', '1'); global.localStorage.removeItem('__t'); return global.localStorage; }
    catch (e) { const m = {}; return { getItem: (k) => m[k] || null, setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } }; }
  })();

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ------------------------------------------------------------ 编码工具
  function b64encode(u8) {
    let s = '';
    const chunk = 0x8000;
    for (let i = 0; i < u8.length; i += chunk) s += String.fromCharCode.apply(null, u8.subarray(i, i + chunk));
    return btoa(s);
  }
  function b64decode(str) {
    const bin = atob(str);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }
  function concat(a, b) {
    const out = new Uint8Array(a.length + b.length);
    out.set(a, 0); out.set(b, a.length);
    return out;
  }
  function counterNonce(n) {
    const u8 = new Uint8Array(24);
    let v = BigInt(n);
    for (let i = 7; i >= 0; i--) { u8[i] = Number(v & 255n); v >>= 8n; }
    u8.set(nacl.randomBytes(16), 8);
    return u8;
  }
  function deriveKey(shared, label) {
    return nacl.hash(concat(shared, enc.encode(label))).slice(0, 32);
  }

  // ------------------------------------------------------------ 状态
  const state = {
    csrf: '',                   // 会话 CSRF 令牌（登录响应与 /api/me 都会带回）
    channelId: null,
    keyC2s: null,
    keyS2c: null,
    outCounter: 0,
    inCounter: 0,
    fingerprint: null,
    established: false,
    queue: Promise.resolve(),   // 串行化：保证计数器严格递增、服务端不会判定乱序
    onFingerprint: null,
  };

  function pinMismatch(seen) {
    const pinned = LS.getItem(PIN_KEY);
    return pinned && pinned !== seen;
  }

  // ------------------------------------------------------------ 握手
  async function handshake(force) {
    if (state.established && !force) return info();
    const res = await fetch('/api/handshake', { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error('无法获取服务端加密参数（HTTP ' + res.status + '）');
    const info0 = await res.json();
    if (info0.v !== 1) throw new Error('协议版本不匹配，请升级系统');

    if (pinMismatch(info0.fingerprint)) {
      const err = new Error(
        '安全警告：服务端加密指纹与上次记录不一致！\n' +
        '上次: ' + LS.getItem(PIN_KEY) + '\n本次: ' + info0.fingerprint + '\n' +
        '可能原因：服务端重新生成了信道密钥，或正在被中间人攻击。\n' +
        '请先在服务器上运行 ca-admin fingerprint 核对。若确认无误，' +
        '在地址后加 ?resetfp=1 重新打开本页以更新指纹。');
      err.code = 'fingerprint_mismatch';
      err.fingerprint = info0.fingerprint;
      throw err;
    }

    const serverPub = b64decode(info0.server_pub);
    const client = nacl.box.keyPair();
    const shared = nacl.box.before(serverPub, client.secretKey);

    const hello = enc.encode(JSON.stringify({
      v: 1, ts: Math.floor(Date.now() / 1000),
      ua: (global.navigator && global.navigator.userAgent) || '',
    }));
    /* 关键：tweetnacl 的 box() 只返回密文，**不包含 nonce**（这点与 PyNaCl 的
       crypto_box_easy 不同：PyNaCl 的 EncryptedMessage 是 nonce||密文）。
       服务端用 PyNaCl 解密时按 nonce||密文 解析，所以这里必须自己把 nonce 拼在前面，
       否则服务端永远解不开握手包（表现为“握手包无法解密”）。 */
    const nonce = nacl.randomBytes(24);
    const cipher = nacl.box(hello, nonce, serverPub, client.secretKey);
    const boxed = new Uint8Array(nonce.length + cipher.length);
    boxed.set(nonce, 0);
    boxed.set(cipher, nonce.length);

    const res2 = await fetch('/api/handshake', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_pub: b64encode(client.publicKey), box: b64encode(boxed) }),
    });
    const data = await res2.json().catch(() => ({}));
    if (!res2.ok) throw new Error(data.error || ('握手失败（HTTP ' + res2.status + '）'));

    const keyS2c = deriveKey(shared, 'CA-CHANNEL-s2c-v1');
    const opened = nacl.secretbox.open(b64decode(data.c), b64decode(data.n), keyS2c);
    if (!opened) throw new Error('握手响应解密失败（服务端密钥可能已更换，请刷新页面）');
    const reply = JSON.parse(dec.decode(opened));
    if (reply.ch !== data.ch) throw new Error('握手响应校验失败');

    state.channelId = data.ch;
    state.keyC2s = deriveKey(shared, 'CA-CHANNEL-c2s-v1');
    state.keyS2c = keyS2c;
    state.outCounter = 0;
    state.inCounter = 0;
    state.fingerprint = reply.fingerprint || info0.fingerprint;
    state.tls = info0.tls === true;
    state.established = true;
    if (!LS.getItem(PIN_KEY)) LS.setItem(PIN_KEY, state.fingerprint);
    if (typeof state.onFingerprint === 'function') state.onFingerprint(state.fingerprint, info0);
    return info();
  }

  function info() {
    /* tls 必须暴露：login.js 用 info().tls 判断"非加密且非本机"并提前给出安全提示；
       曾经漏掉这个字段，导致远程明文的提示永远不触发（审查发现）。 */
    return { fingerprint: state.fingerprint, established: state.established,
             channel: state.channelId, tls: state.tls === true,
             origin: (typeof location !== 'undefined' ? location.origin : '') };
  }

  // ------------------------------------------------------------ RPC
  /* 每个"逻辑请求"生成一次 id：底层因信道重建而重试时，rid 不变，
     服务端据此去重，保证签发/吊销这类非幂等操作只执行一次。 */
  function tlog(tag, withStack) {
    if (typeof window !== 'undefined' && window.__CA_TRACE_RID) {
      var rec = tag;
      if (withStack) {
        rec += ' || ' + String((new Error()).stack || '').split('\n')
          .slice(1, 7).map(function (x) { return x.trim(); }).join(' <- ');
      }
      (window.__CA_RID_TRACE = window.__CA_RID_TRACE || []).push(rec);
    }
  }

  function newRequestId() {
    // 诊断用（默认关闭，零开销）：window.__CA_TRACE_RID = true 时记录生成调用栈
    if (typeof window !== 'undefined' && window.__CA_TRACE_RID) {
      (window.__CA_RID_TRACE = window.__CA_RID_TRACE || []).push((new Error()).stack || '');
    }
    return nacl.randomBytes(12).reduce(function (acc, b) {
      return acc + (b + 256).toString(16).slice(1);
    }, '');
  }

  function sealRequest(inner) {
    state.outCounter += 1;
    const nonce = counterNonce(state.outCounter);
    const ct = nacl.secretbox(enc.encode(JSON.stringify(inner)), nonce, state.keyC2s);
    return { ch: state.channelId, n: b64encode(nonce), c: b64encode(ct) };
  }

  function openResponse(data) {
    const opened = nacl.secretbox.open(b64decode(data.c), b64decode(data.n), state.keyS2c);
    if (!opened) throw new Error('响应解密失败（信道可能已失效，请刷新页面）');
    return JSON.parse(dec.decode(opened));
  }

  async function rawRpc(inner) {
    const res = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sealRequest(inner)),
    });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && data.rehandshake) {
      state.established = false;
      await handshake(true);
      const retry = await fetch('/api/rpc', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(sealRequest(inner)),
      });
      const data2 = await retry.json().catch(() => ({}));
      if (!retry.ok) throw new Error(data2.error || ('请求失败（HTTP ' + retry.status + '）'));
      return openResponse(data2);
    }
    if (!res.ok) throw new Error(data.error || ('请求失败（HTTP ' + res.status + '）'));
    return openResponse(data);
  }

  /** 串行执行，避免并发导致计数器乱序 */
  function enqueue(task) {
    const run = state.queue.then(task, task);
    state.queue = run.catch(() => {});
    return run;
  }

  /**
   * 业务调用。method: HTTP 方法；path: /api/...；body: 对象；query: 对象。
   * 成功返回 {status, data}；HTTP>=400 抛 Error（message 为服务端中文错误）。
   */
  function rpc(method, path, body, opts) {
    opts = opts || {};
    tlog('RPC-ENTER ' + path, true);
    return enqueue(async () => {
      tlog('TASK-RUN ' + path);
      await handshake();
      const inner = { rid: newRequestId(), m: (method || 'GET').toUpperCase(), p: path,
                      q: opts.query || {}, b: body === undefined ? null : body };
      if (state.csrf) inner.csrf = state.csrf;   // cookie 授权模式下写操作需要
      if (opts.files && opts.files.length) {
        inner.files = {};
        for (const f of opts.files) {
          const buf = new Uint8Array(await f.blob.arrayBuffer());
          (inner.files[f.field] = inner.files[f.field] || []).push({
            name: f.name, ct: f.type || 'application/octet-stream', data: b64encode(buf),
          });
        }
      }
      const out = await rawRpc(inner);
      if (out.b && out.b.csrf) state.csrf = out.b.csrf;   // 登录/me 会带回
      if (out.s >= 400) {
        const err = new Error((out.b && out.b.error) || ('请求失败（HTTP ' + out.s + '）'));
        err.status = out.s;
        err.body = out.b;
        throw err;
      }
      return { status: out.s, data: out.b };
    });
  }

  /** 下载：走加密信道取回文件，再在浏览器端落地 */
  async function download(path, opts) {
    opts = opts || {};
    const out = await rpc(opts.method || 'GET', path, opts.body, { query: opts.query });
    const payload = out.data && out.data.__file__ ? out.data.__file__ : null;
    return payload;
  }

  async function fetchFile(path, opts) {
    opts = opts || {};
    return enqueue(async () => {
      await handshake();
      const inner = { rid: newRequestId(), m: (opts.method || 'GET').toUpperCase(), p: path,
                      q: opts.query || {}, b: opts.body === undefined ? null : opts.body };
      const out = await rawRpc(inner);
      if (out.s >= 400) throw new Error((out.b && out.b.error) || '下载失败');
      if (!out.f) throw new Error('服务端未返回文件内容');
      const bytes = b64decode(out.f.data);
      return new Blob([bytes], { type: out.f.ct || 'application/octet-stream' });
    });
  }

  function saveBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename || 'download.bin';
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
  }

  async function downloadAndSave(path, filename, opts) {
    const blob = await fetchFile(path, opts);
    saveBlob(blob, filename);
    return true;
  }

  // ------------------------------------------------------------ 认证
  async function login(username, password) {
    const out = await rpc('POST', '/api/login', { username: username, password: password });
    return out.data;
  }
  async function logout() {
    try { await rpc('POST', '/api/logout', {}); } catch (e) { /* 忽略 */ }
    state.established = false;
  }
  async function me() {
    const out = await rpc('GET', '/api/me');
    return out.data;
  }

  function resetPin() {
    LS.removeItem(PIN_KEY);
    state.established = false;
    state.channelId = null;
  }

  // ------------------------------------------------------------ 页面辅助
  function fingerprintEl() { return document.querySelector('[data-ca-fingerprint]'); }

  function showFingerprint(fp) {
    const el = fingerprintEl();
    if (el) { el.textContent = fp || '未建立'; el.title = '服务端加密信道指纹（应与服务器启动日志一致）'; }
  }

  function renderSecurityBanner() {
    if (global.location.search.indexOf('resetfp=1') >= 0) resetPin();
    handshake().then(() => showFingerprint(state.fingerprint))
      .catch((err) => {
        const bar = document.createElement('div');
        bar.style.cssText = 'position:fixed;left:0;right:0;top:0;z-index:99999;background:#b91c1c;color:#fff;padding:10px 16px;font:13px/1.6 system-ui,sans-serif;white-space:pre-wrap';
        bar.textContent = err.message || String(err);
        if (document.body) document.body.appendChild(bar);
      });
  }

  global.CASecure = {
    handshake, rpc, login, logout, me, fetchFile, downloadAndSave, saveBlob,
    resetPin, renderSecurityBanner, showFingerprint, info,
    get fingerprint() { return state.fingerprint; },
    get established() { return state.established; },
    set onFingerprint(fn) { state.onFingerprint = fn; },
  };
})(typeof window !== 'undefined' ? window : globalThis);
