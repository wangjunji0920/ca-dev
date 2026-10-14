/*
 * 前端真实 DOM 端到端测试（jsdom + Node fetch + 真实后端）。
 *
 * 与后端 e2e 的区别：这里跑的是**交付的 app.js / crypto.js / index.html 原文件**，
 * 在一个真实 DOM 里加载，并通过真实 HTTP 命中真实后端（走应用层加密信道）。
 * 覆盖：登录页登录、主应用引导、逐个页面渲染、以及全程"零未捕获 JS 错误"。
 *
 * 依赖：jsdom（本项目不把它作为运行时依赖，只在 .tmp/fe-test 里安装）
 *   cd .tmp/fe-test && npm install --cache ../npm-cache jsdom
 *
 * 用法：
 *   node tests/frontend_e2e.js                    # 自己拉起临时后端（127.0.0.1 随机端口）
 *   node tests/frontend_e2e.js --base http://127.0.0.1:9443 --password xxx   # 打已运行的服务
 */
'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
const JSDOM_PATHS = [
  path.join(ROOT, '.tmp/fe-test/node_modules/jsdom'),
  path.join(ROOT, 'node_modules/jsdom'),
];

let JSDOM;
for (const p of JSDOM_PATHS) {
  try { JSDOM = require(p).JSDOM; break; } catch (e) { /* 继续找 */ }
}
if (!JSDOM) {
  console.log('跳过：未安装 jsdom。安装方式：cd .tmp/fe-test && npm install --cache ../npm-cache jsdom');
  process.exit(process.env.CA_TEST_REQUIRE_DOM === '1' ? 2 : 0);
}

const argv = process.argv.slice(2);
const argOf = (name) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : null;
};
let BASE = argOf('--base');
let PASSWORD = argOf('--password');
let PY = argOf('--python') || path.join(ROOT, '.venv/bin/python');

// 应用里未被 catch 的 promise 拒绝不要直接崩掉测试进程，记录下来便于定位
process.on('unhandledRejection', (reason) => {
  console.log('    [未处理的 Promise 拒绝] ' + (reason && reason.message ? reason.message : reason));
  if (reason && reason.stack) {
    console.log('      ' + reason.stack.split('\n').slice(1, 4).join('\n      '));
  }
});

const PASS = [];
const FAIL = [];
function check(name, cond, detail) {
  (cond ? PASS : FAIL).push(name);
  console.log(`  ${cond ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'} ${name}` +
    (cond || !detail ? '' : `  ${detail}`));
  return !!cond;
}
const section = (t) => console.log(`\n\x1b[1m== ${t} ==\x1b[0m`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, { timeout = 15000, interval = 120, label = 'condition' } = {}) {
  const t0 = Date.now();
  for (;;) {
    let v = false;
    try { v = await fn(); } catch (e) { v = false; }
    if (v) return v;
    if (Date.now() - t0 > timeout) throw new Error(`等待超时：${label}`);
    await sleep(interval);
  }
}

// ---------------------------------------------------------------- 启动后端
// 每次运行用独立数据目录：避免上一次被中断后残留的进程/锁互相干扰
const RUN_ID = String(process.pid) + '-' + Date.now().toString(36);
const DATA_DIR = path.join(ROOT, '.tmp/fe-e2e-data-' + RUN_ID);
let child = null;

const SEED_DIR = path.join(ROOT, '.tmp/fe-e2e-seed-' + RUN_ID);
const CSR_FILE = path.join(SEED_DIR, 'fe.csr');

function seedData() {
  // 在起服务之前，用后端自己的模块播种：一个测试 CA、一张证书、一个 CSR 文件
  fs.rmSync(SEED_DIR, { recursive: true, force: true });
  fs.mkdirSync(SEED_DIR, { recursive: true });
  const py = `
import datetime as dt, sys
sys.path.insert(0, ${JSON.stringify(ROOT)})
from backend import server, ca, x509util
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
server.bootstrap(verbose=False)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'FE Test CA'),
                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'FE Org')])
now = x509util.now()
cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + dt.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
            key_encipherment=False, content_commitment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .sign(key, hashes.SHA256()))
row = ca.import_ca(x509util.pem_cert(cert).encode(), x509util.pem_key(key).encode())
res = ca.issue_certificate(ca_row=row, vpn_identity='fe-demo.example.com', cn='fe-demo',
                           owner='前端测试')
ca.generate_crl(actor='seed', source='seed')          # 让 CRL 相关页面有数据
print(res['cert']['id'], res['cert']['cn'])
# 生成一个待导入的 CSR（模拟外部申请）
k2 = rsa.generate_private_key(public_exponent=65537, key_size=2048)
csr = (x509.CertificateSigningRequestBuilder()
       .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'fe-csr')]))
       .add_extension(x509.SubjectAlternativeName([x509.DNSName('fe-csr.example.com')]),
                      critical=False)
       .sign(k2, hashes.SHA256()))
open(${JSON.stringify(CSR_FILE)}, 'wb').write(csr.public_bytes(serialization.Encoding.PEM))
`;
  const out = require('child_process').execFileSync(PY, ['-c', py], {
    cwd: ROOT, env: Object.assign({}, process.env, { CA_DATA_DIR: DATA_DIR }),
    encoding: 'utf8',
  });
  return out.trim();
}

function startBackend() {
  const port = 19000 + Math.floor(Math.random() * 900);
  BASE = `http://127.0.0.1:${port}`;
  child = spawn(PY, ['-m', 'backend.server'], {
    cwd: ROOT,
    env: Object.assign({}, process.env, {
      CA_DATA_DIR: DATA_DIR, CA_HOST: '127.0.0.1', CA_PORT: String(port),
      CA_LEGACY_API: 'loopback', CA_DEBUG_RPC: process.env.CA_DEBUG_RPC || '0',
      CA_RELOAD_CMD: process.env.CA_RELOAD_CMD || 'true',
    }),
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const serverLog = [];
  child.stderr.on('data', (b) => { serverLog.push(String(b)); });
  child.__log = serverLog;
  return { port };
}

async function readPassword() {
  const f = path.join(DATA_DIR, 'initial_admin_password.txt');
  await waitFor(() => fs.existsSync(f), { label: '初始口令文件' });
  const m = fs.readFileSync(f, 'utf8').match(/初始口令:\s*(\S+)/);
  if (!m) throw new Error('无法读取初始口令');
  return m[1];
}

// ---------------------------------------------------------------- jsdom 工具
function makeDom(html, { url, onError }) {
  const errors = [];
  const dom = new JSDOM(html, {
    url,
    runScripts: 'dangerously',
    resources: 'usable',
    pretendToBeVisual: true,
    beforeParse(window) {
      // 注入 Node 的网络与二进制类型：jsdom 不实现 fetch，且它的 FormData/Blob 与 undici 不兼容
      const N = globalThis;
      window.fetch = (input, init) => {
        // 相对路径要按“源”解析（不是按当前页面路径），否则会拼成 /login.html/api/...
        let target = input;
        try {
          if (typeof input === 'string') target = new N.URL(input, url).href;
          else if (input && input.url) target = input;
        } catch (e) { /* 保持原样 */ }
        return N.fetch(target, init);
      };
      // 注意：TextEncoder/TextDecoder 必须保留 jsdom 自己的实现，
      // 否则 enc.encode() 返回的是 Node realm 的 Uint8Array，tweetnacl 会报
      // “unexpected type, use Uint8Array”（两个 realm 的 typed array 不能混用）。
      for (const k of ['FormData', 'Blob', 'File', 'Headers', 'Request', 'Response',
        'AbortController', 'URLSearchParams']) {
        if (N[k]) window[k] = N[k];
      }
      for (const k of ['TextEncoder', 'TextDecoder']) {
        if (!window[k] && N[k]) window[k] = N[k];
      }
      if (!window.crypto || !window.crypto.getRandomValues) {
        window.crypto = N.crypto;
      } else if (!window.crypto.subtle && N.crypto && N.crypto.subtle) {
        try { window.crypto.subtle = N.crypto.subtle; } catch (e) {}
      }
      window.URL.createObjectURL = () => 'blob:test';
      window.URL.revokeObjectURL = () => {};
      // jsdom 未实现部分布局/滚动 API（真实浏览器有），这里补成无操作，避免误报
      window.Element.prototype.scrollIntoView = function () {};
      window.Element.prototype.scrollTo = function () {};
      if (!window.matchMedia) {
        window.matchMedia = () => ({ matches: false, addListener() {}, removeListener() {},
                                     addEventListener() {}, removeEventListener() {} });
      }
      window.onerror = (msg, src, line, col, err) => {
        errors.push(`${msg} @${String(src).split('/').pop()}:${line}`);
        onError && onError(errors[errors.length - 1]);
        return false;
      };
      window.addEventListener('unhandledrejection', (ev) => {
        errors.push('unhandledrejection: ' + (ev.reason && ev.reason.message || ev.reason));
      });
      const origErr = window.console.error;
      window.console.error = function (...a) {
        errors.push('console.error: ' + a.map(String).join(' ').slice(0, 200));
        return origErr.apply(window.console, a);
      };
    },
  });
  return { dom, errors, window: dom.window };
}

async function closeDom(entry) {
  try { entry.window.close(); } catch (e) {}
}

// ---------------------------------------------------------------- 主流程
async function main() {
  section('准备');
  let seeded = null;
  if (!BASE) {
    // 顺序很重要：先删旧数据 → 播种 → 再启动服务。
    // 若先起服务再播种，两个进程会对同一个新库并发 bootstrap，
    // journal_mode=WAL 切换可能撞锁（也顺带暴露了产品侧那个问题，已修）。
    fs.rmSync(DATA_DIR, { recursive: true, force: true });
    fs.mkdirSync(DATA_DIR, { recursive: true });
    seeded = seedData();
    startBackend();
    check('已播种测试数据（CA + 证书 fe-demo + CSR 文件）', /^\d+ fe-demo$/.test(seeded), seeded);
    await waitFor(async () => {
      const r = await fetch(`${BASE}/api/handshake`).catch(() => null);
      return r && r.ok;
    }, { label: '后端就绪 ' + BASE });
    check('临时后端已启动', true, BASE);
  }
  if (!PASSWORD) PASSWORD = await readPassword();
  check('取到管理员口令', !!PASSWORD);

  // ---------- 登录页：直接走交付的 crypto.js 登录（真实加密信道） ----------
  section('登录页（login.html + crypto.js，真实加密信道）');
  const loginHtml = fs.readFileSync(path.join(ROOT, 'frontend/login.html'), 'utf8');
  const login = makeDom(loginHtml, { url: BASE + '/login.html' });
  await waitFor(() => login.window.CASecure && login.window.nacl, { label: 'login 脚本加载' });
  check('tweetnacl 与 CASecure 已加载到页面', !!(login.window.nacl && login.window.CASecure));
  const info = await login.window.CASecure.handshake();
  check('页面内握手成功并拿到服务端指纹', /^[0-9A-F-]{39}$/.test(info.fingerprint), info.fingerprint);
  // 审查发现：info() 曾不含 tls 字段 → login.js 的"非加密且非本机"提示永不触发
  check('★ CASecure.info() 暴露 tls 字段（远程明文提示依赖它）',
        typeof login.window.CASecure.info().tls === 'boolean',
        JSON.stringify(login.window.CASecure.info()));
  check('★ 明文实例下 tls === false（本机仍可登录，但是明文）',
        login.window.CASecure.info().tls === false,
        JSON.stringify(login.window.CASecure.info()));
  let loginErr = null;
  try {
    await login.window.CASecure.login('admin', 'wrong-password');
    loginErr = '未报错';
  } catch (e) { loginErr = e && e.message; }
  check('错误口令登录被拒', loginErr && loginErr !== '未报错', String(loginErr).slice(0, 60));
  const me = await login.window.CASecure.login('admin', PASSWORD);
  check('正确口令登录成功', me && me.username === 'admin', JSON.stringify(me));
  check('登录页无未捕获错误', login.errors.length === 0, login.errors.slice(0, 2).join(' | '));

  // 指纹钉住（防中间人）：pin 与当前服务端不一致时必须阻断
  login.window.localStorage.setItem('ca_channel_fingerprint', 'DEAD-BEEF-DEAD-BEEF-DEAD-BEEF-DEAD-BEEF');
  let pinErr = null;
  try { await login.window.CASecure.handshake(true); } catch (e) { pinErr = e; }
  check('指纹不一致时阻断连接（TOFU 防中间人）',
    pinErr && pinErr.code === 'fingerprint_mismatch', pinErr ? pinErr.code : '未阻断');
  check('阻断时提示包含新旧指纹与处理办法',
    pinErr && /resetfp=1/.test(pinErr.message), pinErr ? pinErr.message.slice(0, 60) : '');
  login.window.CASecure.resetPin();
  const afterReset = await login.window.CASecure.handshake(true);
  check('重置指纹固定后可重新连接',
    /^[0-9A-F-]{39}$/.test(afterReset.fingerprint), afterReset.fingerprint);
  check('重置后本地重新写入固定指纹',
    login.window.localStorage.getItem('ca_channel_fingerprint') === afterReset.fingerprint);
  await closeDom(login);

  // ---------- 主应用：用真实 index.html + app.js，注入“首个 /api/me 自动登录”钩子 ----------
  section('主应用（index.html + app.js，真实 DOM + 真实后端）');
  let indexHtml = fs.readFileSync(path.join(ROOT, 'frontend/index.html'), 'utf8');
  const hook = `
<script>
/* 测试专用钩子：app 引导时会请求 /api/me，此时先在该加密信道内完成登录 */
(function () {
  var orig = window.CASecure && window.CASecure.rpc;
  if (!orig) return;
  window.__loggedIn = false;
  window.__rpcLog = [];
  window.__rpcCalls = [];
  window.__CA_TRACE_RID = true;   // 打开 crypto.js 的 rid 生成追踪（诊断重复请求）
  window.CASecure.rpc = function (method, path, body, opts) {
    window.__rpcCalls.push({ path: path, stack: (new Error()).stack.split(String.fromCharCode(10))[3] || '' });
    var p0 = orig(method, path, body, opts);
    try {
      p0.then(function () { window.__rpcLog.push({ path: path, ok: true }); },
              function (e) { window.__rpcLog.push({ path: path, ok: false, err: String(e && e.message) }); });
    } catch (e) { window.__rpcLog.push({ path: path, ok: false, err: 'wrap:' + e.message }); }
    if (path === '/api/me' && !window.__loggedIn) {
      // 首个 /api/me：先在该信道内登录，再重放这一次探测请求
      return orig('POST', '/api/login', { username: 'admin', password: ${JSON.stringify(PASSWORD)} })
        .then(function () { window.__loggedIn = true; })
        .then(function () { return orig(method, path, body, opts); });
    }
    // 注意：必须返回上面那一次 orig() 的结果。
    // 早期版本在这里又调用了一次 orig()，导致**每个请求都被真实发送两遍**
    // （签发因此签出两张证书、CSR 导入报“公钥重复”），是测试脚手架的 bug，不是产品问题。
    return p0;
  };
})();
</script>
`;
  if (!indexHtml.includes('crypto.js')) throw new Error('index.html 未引用 crypto.js');
  indexHtml = indexHtml.replace('<script src="app.js"></script>', hook + '<script src="app.js"></script>');
  check('已注入测试钩子（不修改交付文件）',
    indexHtml.includes('__loggedIn') && fs.readFileSync(path.join(ROOT, 'frontend/index.html'), 'utf8').includes('<script src="app.js"></script>'));

  const app = makeDom(indexHtml, { url: BASE + '/index.html' });
  const { window } = app;
  const doc = window.document;
  const $ = (s) => doc.querySelector(s);
  const bodyText = () => (doc.body ? doc.body.textContent : '');

  await waitFor(() => {
    const t = bodyText();
    return t.includes('概览') || t.includes('加密信道');
  }, { timeout: 25000, label: '主应用引导' });
  check('主应用已引导（概览或安全提示出现）', true);
  await waitFor(() => window.__loggedIn === true, { timeout: 25000, label: '自动登录钩子生效' });
  check('加密信道内完成登录', window.__loggedIn === true);

  // 概览
  await waitFor(() => /\d/.test((($('#overview') || doc.body).textContent || '')), { timeout: 20000 })
    .catch(() => {});
  check('概览页渲染出统计内容', bodyText().length > 200, `长度 ${bodyText().length}`);

  // 逐页导航：切 hash -> 等渲染 -> 断言关键字与表格行
  const routes = [
    { hash: '#/certs', must: ['证书'], rows: true, name: '证书列表' },
    { hash: '#/issue', must: ['签发'], name: '签发证书' },
    { hash: '#/batch', must: ['批量'], name: '批量签发' },
    { hash: '#/csrs', must: ['CSR'], name: 'CSR 证书请求' },
    { hash: '#/revocation', must: ['吊销'], name: '吊销与 CRL' },
    { hash: '#/import', must: ['导入'], name: '导入数据' },
    { hash: '#/consistency', must: ['体检'], name: '一致性体检' },
    { hash: '#/audit', must: ['审计'], name: '审计日志' },
    { hash: '#/ca', must: ['CA'], name: 'CA 管理' },
    { hash: '#/settings', must: ['设置'], name: '设置' },
    { hash: '#/rulesets', must: ['规则集'], rows: true, name: '规则集' },
    { hash: '#/publish', must: ['CRL'], rows: true, name: 'CRL 自动发布' },
    { hash: '#/automation', must: ['自动化'], rows: true, name: '自动化' },
  ];
  const errorsBefore = app.errors.length;
  for (const r of routes) {
    window.location.hash = r.hash;
    await waitFor(() => {
      const visible = doc.querySelector('.view:not([hidden])');
      return visible && doc.body.textContent.length > 100;
    }, { timeout: 8000, label: r.hash + ' 视图切换' }).catch(() => {});
    await sleep(400);
    const text = bodyText();
    const hit = r.must.some((m) => text.includes(m));
    check(`页面 ${r.name}（${r.hash}）渲染`, hit, `未在页面文本中找到 ${r.must.join('/')}`);
    if (r.rows) {
      const rowCount = doc.querySelectorAll('table.tbl tbody tr').length;
      check(`页面 ${r.name} 表格有数据行`, rowCount > 0, `行数 ${rowCount}`);
    }
  }

  // 具体数据校验：规则集页应出现 strongSwan 规则集
  window.location.hash = '#/rulesets';
  await sleep(800);
  check('规则集页出现 strongSwan 默认规则集',
    bodyText().includes('strongswan-vpn-client') || bodyText().includes('strongSwan'),
    bodyText().slice(0, 120));
  // CSR 页：空态应给出导入引导
  window.location.hash = '#/csrs';
  await sleep(800);
  check('CSR 页渲染出请求池（含空态引导）',
    bodyText().includes('请求池') || bodyText().includes('导入 CSR'),
    bodyText().slice(0, 140));

  // ---------- 真实数据：列表里能看到播种的证书 ----------
  window.location.hash = '#/certs';
  await sleep(900);
  check('证书列表显示播种的证书 fe-demo', bodyText().includes('fe-demo'),
    bodyText().slice(0, 120));

  // ---------- 下载（信封里的 base64 文件） ----------
  const listResp = await window.CASecure.rpc('GET', '/api/certs', null,
    { query: { q: 'fe-demo' } });
  const feCert = listResp && listResp.data && listResp.data.items && listResp.data.items[0];
  check('通过加密信道查询到证书对象', !!(feCert && feCert.id), JSON.stringify(listResp).slice(0, 80));
  if (feCert) {
    const blob = await window.CASecure.fetchFile('/api/certs/' + feCert.id + '/download',
      { query: { format: 'pem' } });
    const text = await blob.text();
    check('下载证书 PEM（base64 信封）内容正确', text.includes('BEGIN CERTIFICATE'),
      text.slice(0, 60));
    const chain = await window.CASecure.fetchFile('/api/certs/' + feCert.id + '/download',
      { query: { format: 'chain' } });
    check('下载证书链可用', (await chain.text()).includes('BEGIN CERTIFICATE'));
    const crl = await window.CASecure.fetchFile('/api/crl/download', { query: { format: 'pem' } });
    check('下载 CRL 可用（种子已生成 CRL）', (await crl.text()).includes('BEGIN X509 CRL'));
  }

  // ---------- 上传（FormData -> files 信封） ----------
  const csrPem = fs.readFileSync(CSR_FILE, 'utf8');
  const up = await window.CASecure.rpc('POST', '/api/csrs/import',
    { dry_run: false, owner: '前端上传' },
    { files: [{ field: 'files', name: 'fe.csr', type: 'application/pkcs10',
                blob: new Blob([csrPem]) }] });
  check('通过加密信道上传 CSR 成功（files 信封）',
    !!(up && up.data && (up.data.imported || []).length === 1),
    JSON.stringify(up && up.data).slice(0, 120));
  window.location.hash = '#/csrs';
  await sleep(900);
  check('CSR 页面显示刚上传的请求 fe-csr', bodyText().includes('fe-csr'),
    bodyText().slice(0, 140));

  // ---------- 上传证书文件（走证书导入接口） ----------
  const importResp = await window.CASecure.rpc('POST', '/api/certs/import', { dry_run: true },
    { files: [{ field: 'files', name: 'fe.crt', type: 'application/x-pem-file',
                blob: new Blob([fs.readFileSync(path.join(ROOT, 'frontend/favicon.svg'), 'utf8')]) }] });
  check('非证书文件通过上传接口得到结构化错误（不崩）',
    !!(importResp && importResp.data && (importResp.data.errors || []).length >= 1),
    JSON.stringify(importResp && importResp.data).slice(0, 100));

  // ---------- 真实交互 A：用签发表单签一张证书 ----------
  section('真实交互：签发（表单）与吊销（搜索+二次确认）');
  window.location.hash = '#/issue';
  await waitFor(() => {
    const sel = doc.querySelector('#issProfile');
    return sel && sel.options && sel.options.length > 1;
  }, { timeout: 15000, label: '签发页规则集下拉填充' });
  const setField = (sel, v) => {
    const n = doc.querySelector(sel);
    if (!n) return false;
    n.value = v;
    n.dispatchEvent(new window.Event('input', { bubbles: true }));
    n.dispatchEvent(new window.Event('change', { bubbles: true }));
    return true;
  };
  check('签发页可选规则集（含 strongSwan）',
    Array.from(doc.querySelectorAll('#issProfile option')).some((o) => o.value === 'strongswan-vpn-client'));
  setField('#issProfile', 'strongswan-vpn-client');
  await sleep(250);
  setField('#issCn', 'ui-issued.example.com');
  // 有效期是必填（校验要求 1–3650），模板可能没预填
  const validEl = doc.querySelector('#issValidity');
  if (!validEl.value) setField('#issValidity', '365');
  await sleep(250);
  // 规则集要求 SAN：加一行 DNS，同时验证前端 SAN 行编辑可用
  const addSan = doc.querySelector('#issAddSan');
  if (addSan) {
    addSan.click();
    await sleep(200);
    const rows = doc.querySelectorAll('#issSanRows .san-row');
    if (rows.length) {
      const typeSel = rows[rows.length - 1].querySelector('.san-type');
      const valInp = rows[rows.length - 1].querySelector('.san-value');
      typeSel.value = 'DNS';
      typeSel.dispatchEvent(new window.Event('change', { bubbles: true }));
      valInp.value = 'ui-issued.example.com';
      valInp.dispatchEvent(new window.Event('input', { bubbles: true }));
    }
    check('签发页可添加 SAN 行并填写', doc.querySelectorAll('#issSanRows .san-row').length >= 1);
  }
  await sleep(250);
  const previewBtn = doc.querySelector('#issPreviewBtn');
  if (previewBtn) previewBtn.click();
  await sleep(250);
  doc.querySelector('#issSubmit').click();
  // 签发前有二次确认弹窗（摘要 + 私钥仅一次可见的警告）
  let confirmShown = false;
  try {
    await waitFor(() => {
      const m = doc.querySelector('#modal');
      return m && !m.hidden;
    }, { timeout: 10000, label: '签发确认弹窗' });
    confirmShown = true;
  } catch (e) { confirmShown = false; }
  check('签发前弹出确认框（含摘要与私钥提示）', confirmShown &&
    /ui-issued/.test((doc.querySelector('#modal') || {}).textContent || '') &&
    /私钥/.test((doc.querySelector('#modal') || {}).textContent || ''),
    ((doc.querySelector('#modal') || {}).textContent || '').slice(0, 100));
  if (confirmShown) doc.querySelector('#modalOk').click();
  let issueOk = false;
  try {
    await waitFor(() => {
      const card = doc.querySelector('#issueResultCard');
      return card && !card.hidden && /ui-issued/.test(card.textContent || '');
    }, { timeout: 25000, label: '签发结果出现' });
    issueOk = true;
  } catch (e) { issueOk = false; }
  if (!issueOk) {
    await sleep(1200);
    const t = doc.querySelector('#toasts');
    console.log('    [诊断] 提示条: ' + ((t && t.textContent) || '（无）').slice(0, 200));
    const card = doc.querySelector('#issueResultCard');
    console.log('    [诊断] 结果卡 hidden=' + (card ? card.hidden : '无元素'));
    console.log('    [诊断] #issueResult 文本: ' +
      ((doc.querySelector('#issueResult') || {}).textContent || '（无）').slice(0, 160));
    const sb = doc.querySelector('#issSubmit');
    console.log('    [诊断] #issSubmit disabled=' + (sb ? sb.disabled : '无元素') +
      ' | 文本=' + (sb ? sb.textContent.trim() : ''));
    console.log('    [诊断] 最近 RPC: ' + JSON.stringify((window.__rpcLog || []).slice(-6)));
  }
  check('通过真实表单签发证书成功', issueOk,
    '结果区未出现 ui-issued；内联错误=CN:' +
    ((doc.querySelector('#err-issCn') || {}).textContent || '空') +
    ' 有效期:' + ((doc.querySelector('#err-issValidity') || {}).textContent || '空') +
    ' 校验有效期值=' + ((doc.querySelector('#issValidity') || {}).value || '空'));
  if (issueOk) {
    check('结果区明确提示私钥仅此一次可见',
      /私钥/.test(doc.querySelector('#issueResultCard').textContent || ''));
    const afterIssue = await window.CASecure.rpc('GET', '/api/certs', null,
      { query: { q: 'ui-issued.example.com' } });
    const issued = afterIssue.data.items[0];
    check('后端确实生成了该证书且规则集为 strongSwan',
      !!issued && issued.profile === 'strongswan-vpn-client',
      JSON.stringify(issued && { cn: issued.cn, profile: issued.profile }));
    check('一次点击只产生一张证书（rid 去重生效，未重复执行）',
      afterIssue.data.total === 1, `total=${afterIssue.data.total}`);
    const issuedId = issued && issued.id;

    // ---------- 真实交互 B：吊销（搜索 → 选择 → 二次确认 → 执行） ----------
    window.location.hash = '#/revocation';
    await waitFor(() => !!doc.querySelector('#revSearchBtn'), { label: '吊销页就绪' });
    const rs = doc.querySelector('#revSearch');
    rs.value = 'ui-issued';
    rs.dispatchEvent(new window.Event('input', { bubbles: true }));
    doc.querySelector('#revSearchBtn').click();
    let found = false;
    try {
      await waitFor(() => /ui-issued/.test(
        (doc.querySelector('#revSearchResult') || {}).textContent || ''),
        { timeout: 15000, label: '吊销搜索结果' });
      found = true;
    } catch (e) { found = false; }
    check('吊销页能搜到刚签发的证书', found,
      ((doc.querySelector('#revSearchResult') || {}).textContent || '').slice(0, 80));
    if (found) {
      const pick = doc.querySelector('#revSearchResult [data-act="rev-select"]');
      check('搜索结果有「选择」按钮', !!pick);
      if (pick) {
        pick.click();
        await sleep(300);
        const skipReason = doc.querySelector('#revReason');
        if (skipReason) {
          skipReason.value = 'keyCompromise';
          skipReason.dispatchEvent(new window.Event('change', { bubbles: true }));
        }
        doc.querySelector('#revSubmit').click();
        let modalShown = false;
        try {
          await waitFor(() => {
            const m = doc.querySelector('#modal');
            return m && !m.hidden;
          }, { timeout: 10000, label: '吊销确认弹窗' });
          modalShown = true;
        } catch (e) { modalShown = false; }
        check('吊销前弹出二次确认（含影响面）', modalShown);
        if (modalShown) {
          doc.querySelector('#modalOk').click();
          await sleep(1500);
          const afterRevoke = await window.CASecure.rpc('GET',
            '/api/certs/' + issuedId);
          const revoked = afterRevoke.data.cert;
          check('吊销生效（刚签发那张：状态 revoked + 原因 keyCompromise）',
            revoked && revoked.status === 'revoked'
            && revoked.revocation_reason === 'keyCompromise',
            JSON.stringify(revoked && { id: revoked.id, st: revoked.status,
                                        why: revoked.revocation_reason }));
          const crl = await window.CASecure.rpc('GET', '/api/crl');
          check('吊销后 CRL 立即包含该证书（条目 ≥1）',
            crl.data && crl.data.crl && crl.data.crl.entries >= 1,
            JSON.stringify(crl.data && crl.data.crl).slice(0, 100));
        }
      }
    }
  }

  // ---------- 真实交互 C：设置 / 备份 / 一致性修复 / 批量签发 / 发布目标 / 规则集 ----------
  section('真实交互 C：设置、备份、一致性修复、批量签发、发布目标、规则集');

  // (1) 设置保存
  window.location.hash = '#/settings';
  await sleep(900);
  setField('#setVpnGateway', 'gw-ui.example.com');
  setField('#setCrlValidity', '14');
  doc.querySelector('#setSaveBtn').click();
  let saved = null;
  try {
    await waitFor(async () => {
      const r = await window.CASecure.rpc('GET', '/api/settings');
      const d = r.data.settings || r.data;
      return d.vpn_gateway === 'gw-ui.example.com' && String(d.crl_validity_days) === '14';
    }, { timeout: 15000, label: '设置保存生效' });
    saved = true;
  } catch (e) { saved = false; }
  check('设置页保存生效（VPN 网关 + CRL 有效期）', saved);

  // (2) 备份创建
  const beforeBackups = (await window.CASecure.rpc('GET', '/api/backup')).data.items.length;
  doc.querySelector('#backupCreate').click();
  let backupOk = false;
  try {
    await waitFor(async () => {
      const r = await window.CASecure.rpc('GET', '/api/backup');
      return r.data.items.length > beforeBackups;
    }, { timeout: 20000, label: '备份创建' });
    backupOk = true;
  } catch (e) { backupOk = false; }
  check('界面「立即备份」生成新归档', backupOk, `before=${beforeBackups}`);
  doc.querySelector('#backupRefresh').click();
  let listShown = false;
  try {
    await waitFor(() => /ca-backup-/.test(
      (doc.querySelector('#backupList') || {}).textContent || ''),
      { timeout: 15000, label: '备份列表渲染' });
    listShown = true;
  } catch (e) { listShown = false; }
  check('备份列表渲染出归档名（含下载按钮）', listShown
    && !!doc.querySelector('#backupList [data-act="backup-dl"]'),
    ((doc.querySelector('#backupList') || {}).textContent || '').slice(0, 60));

  // (3) 一致性体检 + 一键修复（先人为造一个可修复问题：孤儿文件）
  const certDir = path.join(DATA_DIR, 'certs');
  fs.mkdirSync(certDir, { recursive: true });
  const orphan = path.join(certDir, 'orphan-ui-test.crt');
  fs.writeFileSync(orphan, '-----BEGIN CERTIFICATE-----\nnot-a-real-cert\n-----END CERTIFICATE-----\n');
  // 注：一致性接口是 POST /api/consistency/check（前端注释里有契约清单）
  window.location.hash = '#/consistency';
  await sleep(800);
  doc.querySelector('#consCheckBtn').click();
  let sawIssue = false;
  try {
    await waitFor(() => /orphan|孤儿|多余|文件/.test((doc.querySelector('#consIssues') || {}).textContent || ''),
      { timeout: 15000, label: '体检发现问题' });
    sawIssue = true;
  } catch (e) { sawIssue = false; }
  check('一致性体检能报出问题（孤儿文件）', sawIssue,
    ((doc.querySelector('#consIssues') || {}).textContent || '').slice(0, 80));
  const repairBtn = doc.querySelector('#consRepairAll');
  check('有可修复项时「一键修复」可用', !!repairBtn && repairBtn.disabled === false,
    `disabled=${repairBtn ? repairBtn.disabled : '无按钮'}`);
  if (repairBtn && repairBtn.disabled === false) {
    repairBtn.click();
    let modal = false;
    try {
      await waitFor(() => !doc.querySelector('#modal').hidden, { timeout: 8000, label: '修复确认' });
      modal = true;
    } catch (e) { modal = false; }
    if (modal) doc.querySelector('#modalOk').click();
    await sleep(2500);
    const rep = await window.CASecure.rpc('POST', '/api/consistency/check', {});
    const errs = (rep.data.issues || []).filter((i) => i.level === 'error');
    check('一键修复后一致性体检无 error', errs.length === 0,
      JSON.stringify(errs.map((i) => i.code).slice(0, 3)));
  }

  // (4) 批量签发（CSV 无表头，列序固定）
  window.location.hash = '#/batch';
  await sleep(800);
  const csv = 'batch-ui-1.cli.example.com,,,,batch-ui-1.cli.example.com,,,,' + '30' + ',strongswan-vpn-client\n'
            + 'batch-ui-2.cli.example.com,,,,batch-ui-2.cli.example.com,,,,' + '30' + ',strongswan-vpn-client\n';
  setField('#batchCsv', csv);
  doc.querySelector('#batchPrecheck').click();
  let previewed = false;
  try {
    await waitFor(() => /2\s*行|共 2/.test((doc.querySelector('#batchPreviewStat') || {}).textContent
      || (doc.querySelector('#batchPreview') || {}).textContent || ''),
      { timeout: 15000, label: '批量预检' });
    previewed = true;
  } catch (e) { previewed = false; }
  check('批量签发预检解析出 2 行', previewed,
    ((doc.querySelector('#batchPreviewStat') || {}).textContent || '').slice(0, 60));
  doc.querySelector('#batchSubmit').click();
  let batchModal = false;
  try {
    await waitFor(() => !doc.querySelector('#modal').hidden, { timeout: 8000, label: '批量确认' });
    batchModal = true;
  } catch (e) { batchModal = false; }
  if (batchModal) doc.querySelector('#modalOk').click();
  let batchDone = false;
  try {
    await waitFor(async () => {
      const r = await window.CASecure.rpc('GET', '/api/certs', null,
        { query: { q: 'batch-ui-', page_size: '10' } });
      return (r.data.items || []).length === 2;
    }, { timeout: 30000, label: '批量签发结果' });
    batchDone = true;
  } catch (e) { batchDone = false; }
  check('批量签发通过界面签发出 2 张证书', batchDone);

  // (5) 发布目标：新增 → 编辑 → 删除（全走界面）
  window.location.hash = '#/publish';
  await sleep(900);
  const tgtDir = path.join(DATA_DIR, 'publish', 'ui-target');
  fs.mkdirSync(tgtDir, { recursive: true });
  doc.querySelector('[data-act="pub-target-new"]').click();
  await sleep(300);
  setField('#pubTName', 'UI 目标');
  setField('#pubTPath', tgtDir);
  setField('#pubTFilename', 'ui.crl.pem');
  setField('#pubTFormat', 'pem');
  setField('#pubTContent', 'crl');
  setField('#pubTReload', '');
  doc.querySelector('[data-act="pub-target-save"]').click();
  let tgtId = null;
  try {
    await waitFor(async () => {
      const r = await window.CASecure.rpc('GET', '/api/publish/targets');
      const t = (r.data.items || []).filter((x) => x.name === 'UI 目标')[0];
      if (t) { tgtId = t.id; return true; }
      return false;
    }, { timeout: 15000, label: '发布目标创建' });
  } catch (e) { /* 下面按 tgtId 判定 */ }
  check('界面可新增发布目标', !!tgtId, String(tgtId));
  if (tgtId) {
    // 立即发布一次，确认目标真的可写
    const pub = await window.CASecure.rpc('POST', '/api/publish/now', { reload: false });
    const mine = (pub.data.results || []).filter((r) => r.target_name === 'UI 目标')[0];
    check('新目标可正常发布（文件写出）', !!mine && mine.ok === true,
      JSON.stringify(mine).slice(0, 120));
    check('发布文件确实落盘', fs.existsSync(path.join(tgtDir, 'ui.crl.pem')));
    // 界面删除
    const row = Array.from(doc.querySelectorAll('[data-act="pub-target-del"]'))
      .filter((b) => (b.getAttribute('data-id') || '') === String(tgtId))[0];
    if (row) {
      row.click();
      await sleep(400);
      if (!doc.querySelector('#modal').hidden) doc.querySelector('#modalOk').click();
      let gone = false;
      try {
        await waitFor(async () => {
          const r = await window.CASecure.rpc('GET', '/api/publish/targets');
          return !(r.data.items || []).some((x) => String(x.id) === String(tgtId));
        }, { timeout: 15000, label: '发布目标删除' });
        gone = true;
      } catch (e) { gone = false; }
      check('界面可删除发布目标', gone);
    } else {
      await window.CASecure.rpc('DELETE', '/api/publish/targets/' + tgtId);
      check('界面可删除发布目标', false, '未找到行内删除按钮');
    }
  }

  // (6) 规则集编辑器：新建 → 保存 → 校验生效
  window.location.hash = '#/rulesets';
  await sleep(900);
  doc.querySelector('[data-act="rs-new"]').click();
  try {
    await waitFor(() => !!doc.querySelector('#rsName'), { timeout: 15000, label: '规则集编辑器' });
  } catch (e) { /* 下面按是否有 rsName 判定 */ }
  const rsReady = !!doc.querySelector('#rsName');
  check('规则集编辑器可打开（新建）', rsReady);
  if (rsReady) {
    setField('#rsName', 'UI 新建规则集');
    setField('#rsSlug', 'ui-created-rs');
    setField('#rsPlatform', 'any');
    if (doc.querySelector('#rsDays')) setField('#rsDays', '45');
    if (doc.querySelector('#rsDescription')) setField('#rsDescription', '界面创建');
    doc.querySelector('#rsSaveBtn').click();
    let rsSaved = null;
    try {
      await waitFor(async () => {
        const r = await window.CASecure.rpc('GET', '/api/rulesets');
        const t = (r.data.items || []).filter((x) => x.slug === 'ui-created-rs')[0];
        if (t) { rsSaved = t; return true; }
        return false;
      }, { timeout: 20000, label: '规则集保存' });
    } catch (e) { rsSaved = null; }
    check('界面新建规则集并保存成功', !!rsSaved, String(rsSaved));
    if (rsSaved) {
      const full = await window.CASecure.rpc('GET', '/api/rulesets/' + rsSaved.id);
      check('保存的规则集内容正确（有效期 45 天）',
        !!(full.data.ruleset && full.data.ruleset.spec
           && Number(full.data.ruleset.spec.validity.days) === 45),
        JSON.stringify(full.data.ruleset && full.data.ruleset.spec &&
                     full.data.ruleset.spec.validity).slice(0, 80));
      await window.CASecure.rpc('DELETE', '/api/rulesets/' + rsSaved.id);
    }
  }

  const newErrors = app.errors.slice(errorsBefore);
  check('遍历全部 13 个页面期间无未捕获 JS 错误', newErrors.length === 0,
    newErrors.slice(0, 3).join(' | '));
  check('前端指纹展示元素存在', !!$('#secFingerprint'));
  await closeDom(app);

  section('结果');
  const rlog = window.__rpcLog || [];
  const counts = {};
  rlog.forEach((e) => { counts[e.path] = (counts[e.path] || 0) + 1; });
  if (process.env.CA_TRACE_RID === '1') console.log('  [RPC 调用统计] ' + JSON.stringify(counts));
  const ccounts = {};
  (window.__rpcCalls || []).forEach((e) => { ccounts[e.path] = (ccounts[e.path] || 0) + 1; });
  if (process.env.CA_TRACE_RID === '1') console.log('  [调用时计数] ' + JSON.stringify(ccounts));
  const dupes = {};
  (window.__rpcCalls || []).forEach((e) => {
    const k = e.path;
    (dupes[k] = dupes[k] || []).push(e.stack.trim());
  });
  console.log('  [issue/import 调用栈] ' + JSON.stringify(
    Object.entries(dupes).filter(([k]) => /issue|import/.test(k))
      .map(([k, v]) => [k, v.length, v[0].slice(0, 90)])));
  const ridTrace = window.__CA_RID_TRACE || [];
  const tagCount = (t) => ridTrace.filter((x) => String(x).indexOf(t) === 0).length;
  const iss = ridTrace.filter((x) => /certs\/issue/.test(String(x)));
  check('每次调用只发送一次请求（无重复发送）',
    tagCount('RPC-ENTER') === tagCount('TASK-RUN')
    && iss.filter((x) => String(x).startsWith('RPC-ENTER')).length
       === iss.filter((x) => String(x).startsWith('TASK-RUN')).length,
    'ENTER=' + tagCount('RPC-ENTER') + ' TASK=' + tagCount('TASK-RUN'));
  if (process.env.CA_TRACE_RID === '1') {
    ridTrace.filter((x) => String(x).startsWith('RPC-ENTER /api/certs/issue'))
      .forEach((x, i) => console.log('    [issue 调用者 #' + (i + 1) + '] ' + String(x).slice(0, 300)));
  }
  console.log('  [打点] RPC-ENTER 总数=' + tagCount('RPC-ENTER')
    + ' TASK-RUN 总数=' + tagCount('TASK-RUN')
    + ' | issue: ENTER=' + iss.filter((x) => String(x).startsWith('RPC-ENTER')).length
    + ' TASK=' + iss.filter((x) => String(x).startsWith('TASK-RUN')).length);
  if (process.env.CA_TRACE_RID === '1') {
    ridTrace.forEach((st, i) => {
      console.log('   #' + (i + 1) + ' ' + st.split(String.fromCharCode(10)).slice(1, 5)
        .map((x) => x.trim()).join(' <- '));
    });
  }
  if (process.env.CA_TRACE_RID === '1') console.log('  [写操作明细] ' + JSON.stringify(
    rlog.filter((e) => /issue|revoke|import|targets|tasks|settings|rulesets/.test(e.path))));
  console.log(`\n  通过 ${PASS.length} 项，失败 ${FAIL.length} 项`);
  if (FAIL.length) console.log('  失败明细: ' + FAIL.join('、'));
  return FAIL.length ? 1 : 0;
}

let exitCode = 1;
main().then((code) => { exitCode = code; })
  .catch((err) => {
    console.error('\n前端 E2E 异常终止：', err && err.message ? err.message : err);
    if (err && err.stack) console.error(err.stack.split('\n').slice(0, 6).join('\n'));
    console.log(`\n  通过 ${PASS.length} 项，失败 ${FAIL.length + 1} 项`);
  })
  .finally(async () => {
    if (child) {
      if (process.env.CA_DEBUG_RPC === '1') {
        const rpcLines = child.__log.join('').split('\n').filter((l) => l.includes('[rpc]'));
        const dup = {};
        rpcLines.forEach((l) => { const m = l.match(/rid=(\S+)/); if (m) dup[m[1]] = (dup[m[1]] || 0) + 1; });
        console.log('  [服务端 RPC 记录] 共 ' + rpcLines.length + ' 条，重复 rid: ' +
          JSON.stringify(Object.entries(dup).filter(([, n]) => n > 1)));
        console.log('  [issue/import 相关] ' +
          JSON.stringify(rpcLines.filter((l) => /issue|import/.test(l)).slice(-8)));
      }
      child.kill('SIGTERM');
      await sleep(300);
      if (child.exitCode === null) child.kill('SIGKILL');
      console.log('已停止临时后端');
    }
    process.exit(exitCode);
  });
