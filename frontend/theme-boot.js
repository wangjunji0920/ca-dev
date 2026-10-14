/* 首屏前应用深色模式，避免闪白。抽成外部文件是因为 CSP 的 script-src 'self'
   会阻止内联 <script>（真实浏览器直接不执行）——jsdom 不执行 CSP，所以测试发现不了。 */
try {
    if (localStorage.getItem('ca_theme') === 'dark') document.documentElement.classList.add('dark');
  } catch (e) {}
