/* 真实浏览器跳转流程回归（这条最容易漏，因为测试里很容易用"自动登录钩子"绕过）。

现场故障：登录页登录成功 → location.replace('index.html') 打开新页面 = **新加密信道**，
而旧实现登录只把身份绑定在"当页信道"上、不下发任何会话凭据 → 新页面立刻是未登录，
于是又被送回登录页。用户在浏览器里看到的就是"输入密码后根本不跳转"。
（此前的测试注入了"在 SPA 页面内自动登录"的钩子，恰好掩盖了它。）

本测试忠实模拟浏览器：同一个 cookie jar 跨页面 + **不打任何自动登录钩子**。 */
const path=require('path'), {spawn}=require('child_process'), fs=require('fs'), os=require('os');
const ROOT=path.resolve(__dirname,'..'), PY=path.join(ROOT,'.venv/bin/python');
let JSDOM;
try { ({JSDOM}=require(path.join(ROOT,'.tmp/fe-test/node_modules/jsdom'))); }
catch(e){ console.log('\n  未安装 jsdom，跳过（一次性安装： mkdir -p .tmp/fe-test && cd .tmp/fe-test && npm install --cache ../npm-cache jsdom）\n'); process.exit(process.env.CA_TEST_REQUIRE_DOM === '1' ? 2 : 0); }
const DATA=fs.mkdtempSync(path.join(os.tmpdir(),'nav-'));
const net=require('net');
const freePort=()=>new Promise(r=>{const x=net.createServer();x.listen(0,'127.0.0.1',()=>{const p=x.address().port;x.close(()=>r(p));});});
let PORT=0, BASE='';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
const jar={};
const cookieHeader=()=>Object.entries(jar).map(([k,v])=>k+'='+v).join('; ');
function makeFetch(){
  const N=globalThis;
  return async (input,init)=>{
    let url=input;
    try{ if(typeof input==='string') url=new N.URL(input,BASE+'/index.html').href;
         else if(input&&input.url) url=input.url; }catch(e){}
    const h=new N.Headers((init&&init.headers)||{});
    if(cookieHeader()) h.set('Cookie',cookieHeader());
    const res=await N.fetch(url,Object.assign({},init,{headers:h}));
    const sc=res.headers.getSetCookie?res.headers.getSetCookie():(res.headers.get('set-cookie')?[res.headers.get('set-cookie')]:[]);
    sc.forEach(c=>{const kv=c.split(';')[0];const i=kv.indexOf('=');const k=kv.slice(0,i).trim(),v=kv.slice(i+1).trim();
      if(v) jar[k]=v; else delete jar[k];});
    return res;
  };
}
const jfetch=makeFetch();
function makeDom(html,url){
  const N=globalThis;
  return new JSDOM(html,{url,runScripts:'dangerously',resources:'usable',pretendToBeVisual:true,
    beforeParse(w){
      w.fetch=jfetch;
      for(const k of ['FormData','Blob','File','Headers','Request','Response','AbortController','URLSearchParams'])
        if(N[k]) w[k]=N[k];
      for(const k of ['TextEncoder','TextDecoder']) if(!w[k]&&N[k]) w[k]=N[k];
      w.URL.createObjectURL=()=>'blob:x'; w.URL.revokeObjectURL=()=>{};
      w.Element.prototype.scrollIntoView=function(){}; w.Element.prototype.scrollTo=function(){};
      w.onerror=(m)=>console.log('   [jsdom error]',m);
    }});
}
(async()=>{
  PORT=await freePort(); BASE=`http://127.0.0.1:${PORT}`;
  const child=spawn(PY,['-m','backend.server'],{cwd:ROOT,
    env:{...process.env,CA_DATA_DIR:DATA,CA_HOST:'127.0.0.1',CA_PORT:String(PORT),CA_LEGACY_API:'loopback'},stdio:'ignore'});
  let pass=0, fail=0;
  const chk=(n,c,d='')=>{ c?(pass++,console.log('  ✓',n)):(fail++,console.log('  ✗',n,d)); };
  try{
    for(let i=0;i<80;i++){ try{ await jfetch(BASE+'/api/health'); break; }catch(e){ await sleep(250);} }
    const pw=fs.readFileSync(path.join(DATA,'initial_admin_password.txt'),'utf8').match(/初始口令:\s*(\S+)/)[1];
    // ① 登录页
    const L=makeDom(await (await jfetch(BASE+'/login.html')).text(), BASE+'/login.html');
    await sleep(1200);
    chk('登录页加载了加密模块', !!L.window.CASecure);
    await L.window.CASecure.login('admin',pw);
    chk('登录页登录成功', true);
    chk('登录响应下发了会话 cookie', !!jar['ca_session'], JSON.stringify(jar).slice(0,40));
    L.window.close();
    // ② 真实跳转（新页面=新信道，靠 cookie）
    const r=await jfetch(BASE+'/index.html');
    const html=await r.text();
    chk('带 cookie 请求 index.html 返回 SPA（不是登录页）', html.includes('id="app"'), `HTTP ${r.status}`);
    const A=makeDom(html, BASE+'/index.html');
    await sleep(5000);
    const doc=A.window.document, txt=(doc.body.textContent||'').replace(/\s+/g,' ');
    chk('SPA 未退回登录页', !doc.querySelector('#loginForm'));
    chk('#app 已显示', !!(doc.querySelector('#app') && !doc.querySelector('#app').hidden));
    chk('概览已渲染数据', /证书|概览|CRL/.test(txt), txt.slice(0,90));
    // ③ 新信道下的写操作（带 csrf）应当被接受
    const created=await A.window.CASecure.rpc('POST','/api/rulesets',
        {slug:'nav-check',name:'跳转验证'});
    chk('新信道里可用 cookie 会话执行写操作', !!(created && created.data && created.data.ruleset),
        JSON.stringify(created).slice(0,100));
    // ④ 登出必须同时清掉会话 cookie，否则"登出"只是解绑了本页信道
    await A.window.CASecure.rpc('POST','/api/logout', {});
    chk('登出后会话 cookie 被清除', !jar['ca_session'], JSON.stringify(jar));
    const after=await jfetch(BASE+'/index.html');
    const afterHtml=await after.text();
    chk('登出后再取 index.html 会回到登录页', afterHtml.includes('id="loginForm"'));
    A.window.close();
  }catch(e){ fail++; console.log('  ✗ 异常:', (e&&e.message)||e); }
  finally{ child.kill('SIGKILL'); }
  console.log(`\n  通过 ${pass} 项，失败 ${fail} 项`);
  process.exit(fail?1:0);
})();
