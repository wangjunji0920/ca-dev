# CA 证书管理系统 1.0.1（面向 strongSwan swanctl）

完整安装包统一部署到 `/opt/ca-dev`。安装与升级见 [QUICKSTART](deploy/QUICKSTART.md)，
发布检查与当前验证范围见 [RELEASE](deploy/RELEASE.md)。

> **推荐部署方式（最安全）：只监听回环 + SSH 隧道 → [deploy/DEPLOY-LOOPBACK-SSH.md](deploy/DEPLOY-LOOPBACK-SSH.md)**
> （`sudo ./deploy/install.sh --systemd --loopback`，管理端口不暴露到网络，完整性由 SSH 保证）
>
一套自建 CA 的图形化管理与自动化系统：签发/吊销/续期证书、维护 CRL、把 CRL 与 CA 证书
**自动同步给 strongSwan**，并把「证书怎么签」做成可编辑的**规则集**，方便以后扩展到别的用途。

- 图形界面：中文本地化单页应用（无需构建、无外部资源，内网可用）
- 传输安全：**不用 HTTPS，而是在 HTTP 之上自建应用层加密信道**（NaCl / XSalsa20-Poly1305），
  口令与私钥不以明文上网
- 运行身份：**以 root 运行**，配 systemd 强沙箱（整机只读，仅数据目录 + `/etc/swanctl` + `/run` 可写）
- 数据一致性：SQLite 为唯一事实来源，证书/CRL 文件原子落盘，另有「一致性体检」一键修复
- 单一管理员：一个账号 + 口令，不引入复杂权限体系

---

## 1. 交付内容

| 路径 | 说明 |
| --- | --- |
| `backend/` | 后端（Python 3.10+ + `cryptography` + `pynacl`，HTTP 服务用标准库） |
| `frontend/` | 前端单页应用（原生 JS，含 `vendor/tweetnacl.min.js` 与 `crypto.js`） |
| `deploy/` | 安装脚本与 systemd 单元（root 版 / 非 root 版 / strongSwan 同步单元） |
| `tests/e2e_test.py` | 后端端到端测试（自建测试 CA，覆盖全部功能，**326 项断言**） |
| `tests/frontend_e2e.js` | **前端真实 DOM 测试**：jsdom 加载交付的 `index.html`/`app.js`/`crypto.js`，真实 HTTP 打真实后端。覆盖登录/指纹钉住/13 个页面、签发+吊销全流程、上传下载、以及**设置保存、备份、一键修复、批量签发、发布目标增删、规则集编辑器**（**73 项断言**） |
| `tests/verify_deploy.py` | 部署验收检查（对运行中的服务做只读体检，**33 项断言**） |
| `tests/publish_hygiene_e2e.py` | **发布目标卫生**：首次安装只创建一个 CRL 目标、不产生 `.crl.pem`/CA 证书等变体、发布后目录里只有配置的文件、删掉的目标不重建、`cli targets --prune-unused`（**12 项**） |
| `tests/reload_e2e.py` | **重载行为测试**：桩 `swanctl`/`systemctl` + 假 swanctl 目录，真实走子进程数重载次数（**21 项**） |
| `tests/package_e2e.py` | **交付包验收**：解包 → `install.sh` 初始化 → 起服务 → 跑验收；并断言包内不含私钥/口令/数据（包含真实解包、初始化和 HTTP 健康检查） |
| `tests/units_e2e.py` | **部署单元验收**：按 install.sh 的方式渲染 systemd 单元，逐项校验沙箱/可写路径/ExecStart/防重载策略（静态配置与回环访问检查） |
| `tests/cli_e2e.py` | **CLI 端到端**：22 个子命令逐个真跑（init/import-ca/issue/import/revoke/gencrl/publish/check/export/bundle/reload-cmd/automation/doctor/preflight/rulesets/csr-*/backup/passwd）（**46 项**） |
| `tests/api_fuzz_e2e.py` | **API 健壮性扫描**：88 条路由灌入空/错类型/畸形 JSON/不存在 ID，断言 **零 5xx**、4xx 全为结构化 JSON、无堆栈泄漏；含 401/CSRF/同源安全断言（**17 项**） |
| `tests/session_flow_e2e.js` | **真实浏览器跳转流程**：同一个 cookie jar 跨页面、**不打自动登录钩子**——登录→新页面仍保持登录、写操作可用、登出真正失效（**10 项**） |
| `tests/login_lockout_e2e.py` | **登录锁定**：回环宽阈值（避免隧道下把自己锁死）、`cli unlock` 跨进程解锁、握手失败不计入锁定（**13 项**） |
| `tests/csp_compat_e2e.py` | **CSP 兼容性**：交付 HTML 不得含内联脚本/内联事件处理器、引用资源必须存在、CSP 不得放开 unsafe-inline；`doctor` 也会检查（**21 项**） |
| `tests/concurrent_init_e2e.py` | **并发初始化**：5 个进程同时对全新库 bootstrap，必须全部成功且规则集/预设/账号不重复（**7 项**） |
| `tests/assetguard_e2e.py` | **前端完整性核对**：本地哈希/指纹、对着真实服务核对应一致、对着**被篡改的服务**必须报错并指出文件（**16 项**） |
| `tests/import_edge_e2e.py` | **导入与规模边界**：CRL 导入（未知签发者/空/畸形）、重复导入幂等、脏 CSV（BOM/CRLF/引号逗号/中文/坏行）、混合目录、300 张证书规模（静态配置与回环访问检查） |
| `tests/requirements_e2e.py` | **明确要求落地**：PATH 清空后全流程可用（无 openssl 依赖）、Win/Linux 规则集差异真生效、规则集每个字段可定制并核对证书内容、自动化触发器/动作真执行（**67 项**） |
| `tests/keytypes_e2e.py` | **密钥类型/格式**：RSA(PKCS#1/加密 PKCS#8)、EC(P-256/DER)、Ed25519 四种 CA 各跑完整闭环，并用 CA 公钥**验签 CRL**（**51 项**） |
| `tests/restore_safety_e2e.py` | **备份/恢复安全性**：截断归档、被篡改、路径穿越、缺 manifest、垃圾数据库、替换中途失败（故障注入）——每种都必须报错且**原有数据完好**（**34 项**） |
| `tests/crl_race_e2e.py` | **CRL 并发竞态回归**：故障注入放大竞态，断言最新 CRL 不漏签、编号不撞号、落盘文件一致（**6 项**） |
| `tests/upgrade_e2e.py` | **升级演练**：沙箱里跑“旧版本 → 新版本”，验证先备份、代码覆盖、**数据不丢**、重载命令对齐、定时器策略（**21 项**） |
| `tests/run_all.sh` | 一键跑完**二十四套**。**测试中的 systemd/strongSwan 写操作使用桩**：`systemctl`/`systemd-analyze`/`swanctl`/`ipsec` 在 PATH 最前面被替换为桩，结束时校验调用日志为空；`systemd-analyze verify` 默认关闭（需 `CA_RUN_SYSTEMD_ANALYZE=1`） |
| `run.sh` | 前台启动 |
| `data/` | 运行数据（数据库、CA 材料、证书、CRL、发布暂存、备份、日志） |

### 后端模块（每个模块职责单一，便于扩展）

| 模块 | 职责 |
| --- | --- |
| `config.py` | 路径、端口、运行身份（root 检测）、swanctl 目录 |
| `db.py` | SQLite 数据层：单连接 + 可重入锁 + 事务 + 轻量迁移 |
| `x509util.py` | 证书/密钥/CSR/CRL 解析与构造（**不调用 openssl 命令行**） |
| `ca.py` | CA 引擎：导入 CA、按规则集签发、吊销/恢复、生成 CRL、验签 |
| `rules.py` | **规则集**：把证书规则做成可编辑数据（内置 strongSwan / Windows / Linux 预设） |
| `inventory.py` | 批量导入（文件/目录/ZIP/PKCS#12/CSV）、导出、元数据编辑、续期 |
| `csrs.py` | **CSR 证书请求池**：批量收 CSR（可 zip）、审核、用规则集签发并关联证书 |
| `consistency.py` | 一致性体检与自动修复（文件缺失、指纹不符、CRL 与吊销不一致、权限过宽…） |
| `publish.py` | CRL/CA 内容发布（强 target：目录/命令），到期前自动续签 |
| `automation.py` | **通用自动化引擎**：触发器 + 内容 + 动作 + 条件（文件/命令/Webhook） |
| `strongswan.py` | strongSwan 集成：身份→SAN、swanctl 配置片段、一键部署包、同步脚本 |
| `security.py` | 口令（scrypt）、会话、CSRF、登录限速、安全响应头、TLS 可选 |
| `secure_channel.py` | **应用层加密信道**（握手、密钥派生、防重放、会话即信道） |
| `server.py` | HTTP 服务：路由、静态资源、公开 CRL 端点、启动引导 |
| `api.py` | REST 接口实现与路由表（明文入口与加密入口共用同一份逻辑） |
| `backup.py` | 备份与恢复（含路径穿越防护、恢复前自动备份） |
| `cli.py` | 命令行工具（运维与自动化） |

---


### CRL 发布目标：不适用会"跳过"，不会报红

服务以 systemd 沙箱运行（`ProtectSystem=strict`），只有 `ReadWritePaths` 里的目录可写：
`<数据目录>`、`/etc/swanctl`、`-/etc/ipsec.d`、`/run`（`-` 前缀表示目录不存在时忽略）。

* **目录不存在的目标**（例如 swanctl 布局机器上的 `/etc/ipsec.d/crls`）→ 记为该目标**跳过**并说明
  "本机不使用该布局"，不再显示为失败；其它目标不受影响。
* **目录存在但不可写**（沙箱未放开该路径）→ 失败信息会直接告诉你：
  把该目录加入服务的 `ReadWritePaths`（如 `ReadWritePaths=-/etc/ipsec.d`），或停用该目标。
* `cli doctor` 会用**实际写探针**逐个检查启用目标的可写性（root 下 `os.access` 不可靠），
  提前暴露问题，而不是等到发布时才一片红。
* 建议目标只在**确实存在 legacy 布局**（`/etc/ipsec.d` 存在）时才包含 `ipsec.d` 目标 ——
  装了 `ipsec` 命令不等于在用 `ipsec.d` 布局。


### 如何验证 CRL 内容（两种方式）

**方式 1：openssl（最直接）**

```bash
CRL=/etc/swanctl/x509crl/crl.der
CA=/etc/swanctl/x509ca/example-ca.crt.pem

# 整体可读内容：签发者 / CRL 编号 / 本次与下次更新 / 全部吊销条目（序列号、时间、原因）
openssl crl -inform DER -in "$CRL" -noout -text

# 只看关键几行
openssl crl -inform DER -in "$CRL" -noout -issuer -lastupdate -nextupdate -crlnumber

# 验证签名：证明确实是这个 CA 签发的、且没被改过（最关键的一步，通过时输出 verify OK）
openssl crl -inform DER -in "$CRL" -noout -CAfile "$CA"

# 验证某张证书是否真的被吊销（最直观的"生效"确认）
openssl crl -inform DER -in "$CRL" -outform PEM -out /tmp/crl.pem
openssl verify -CAfile "$CA" -CRLfile /tmp/crl.pem -crl_check client.cert.pem
#   输出 OK = 未吊销；输出 revoked = 已吊销

sha256sum "$CRL"      # 与界面「CRL 自动发布 → 发布日志」里的 SHA-256 对照
```

**方式 2：`cli crl-info`（一条命令，不依赖 openssl）**

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli crl-info                      # 默认取启用的发布目标
sudo ... crl-info --file /etc/swanctl/x509crl/crl.der                          # 指定文件
sudo ... crl-info --serial 5D42AFA5AD430801C0DEFBCCDB6D54E2B9920323            # 查某序列号是否吊销
sudo ... crl-info --json                                                       # 纯 JSON，可接监控
```

它做四件事：① 解析（签发者/编号/有效期/条目）② **用 CA 公钥验证 CRL 签名**（等价于
`openssl crl -CAfile`）③ 与数据库交叉核对（编号/条目，以及"库中已吊销但 CRL 缺失"这种
**吊销未生效**的情况）④ 与各发布目标比对（磁盘上的内容是否就是当前应发布的内容）。
全部通过退出码 0，任一不通过退出码 1，可直接用于监控脚本。

### 发布目标：默认只写一份 CRL（不产生多余文件）

**默认行为**（首次安装）：

* 在 strongSwan 目录里只创建一个目标：`<设置里的 crl_filename>`（默认 `crl.der`）→ 启用
* `x509ca/` **默认不写**（`publish_ca_cert` 默认关）——需要分发 CA 证书时在界面勾选
* legacy `ipsec.d` 目标只在 `/etc/ipsec.d` 确实存在时才建议
* 本地暂存目录（`data/publish/`）里另有副本，供非 root/同步脚本使用，**不进 strongSwan 目录**

**不会重建**：`ensure_default_targets()` 只在 `publish_targets` 表为空（首次安装）时创建；
升级、重启、发布都不会把你删掉的目标补回来。

**核对与清理**：

```bash
CA=/opt/ca-dev/.venv/bin/python
sudo $CA -m backend.cli targets                    # 列出目标：路径/文件名/是否启用/目录是否存在
sudo $CA -m backend.cli targets --prune-unused     # 停用"目录不存在"的遗留目标
sudo $CA -m backend.cli doctor | grep -E "同名 CA|CRL 文件唯一性"
```

同一 CA 在 strongSwan 目录里**只应有一份 CRL**：charon 按签发者索引且只保留编号最大的那份，
多份同名 CRL 会让"编号更大的旧文件"遮蔽新 CRL（现场踩过：吊销了但重连照样通过）。

### CRL 何时真正生效（重载时机与在线连接）

strongSwan/charon 的行为有三个要点，直接决定"吊销多久生效"：

1. **charon 不监视 CRL 文件**：文件更新后必须显式清缓存、重新加载凭据；
   默认重载命令还会重启服务。只写文件不会让运行中的服务立即采用新内容。
2. **只接受编号更大的 CRL**（日志：`crl #07 is not newer - existing crl #07 retained`），
   所以每次发布都必须递增 CRL 编号（系统已保证）。
3. **吊销只在认证时校验，已建立的 IKE_SA 不会自动断开**：新连接立即被拒；在线用户仍保持连通，
   直到重连/重认证。

因此本系统做了两件事：

* **吊销/导入 CRL 触发的发布豁免"最小重载间隔"**（`reload_min_interval_seconds`，默认 30 秒）。
  之前这个节流会把吊销后的重载也挡掉，导致"吊销了但不重启 strongSwan 不生效"（现场踩过）；
  现在吊销类触发一律立即执行配置的重载命令（默认先 `swanctl --flush-certs`，再加载凭据并重启），
  只有普通发布才受节流保护（防重载风暴）。
* `cli doctor` 新增 **CRL 加载状态**：比对"最新 CRL 的生成时间 vs 上次重载时间"，
  若 CRL 更新却没重载，会告警并给出修复命令。

默认重载命令包含 `systemctl restart strongswan`，会中断该服务的所有在线连接。
可选 `reload-cmd --preset flush` 只清缓存并重新加载凭据，但需在你的 strongSwan 版本上
实际验证吊销对新连接的效果；已建立连接何时重新认证取决于连接配置。

### 接管现场已有 CA（保持原 CA 不变）

现场往往**已经有一张在用的 CA**（客户端/网关证书都是它签的）。这时**不要新建 CA**，
而是让本系统"接管"它 —— 同一个证书、同一把私钥、同一批已签发证书，什么都不用重签：

```bash
CA=/opt/ca-dev/.venv/bin/python
sudo $CA -m backend.cli backup --name before-adopt          # 先备份
sudo cp -a /etc/swanctl /root/swanctl-backup-$(date +%F)    # 现场目录也备一份

# ① 看清现状：哪张是"原 CA"，现场 CRL 最大编号是多少
for f in /etc/swanctl/x509ca/*; do openssl x509 -in "$f" -noout -subject -fingerprint -sha256; done
for f in /etc/swanctl/x509crl/*; do openssl crl -in "$f" -noout -issuer -crlnumber 2>/dev/null; done

# ② 导入原 CA（cert + key）与其现有 CRL —— 原 CA 本体不变
sudo $CA -m backend.cli import-ca --cert /etc/swanctl/x509ca/<原CA>.pem --key <原CA私钥>
sudo $CA -m backend.cli import-crl --file /etc/swanctl/x509crl/<原CRL>

# ③ 跳号：让系统下一个 CRL 编号**高于现场已有的最大编号**
#    （strongSwan 只保留编号更大的 CRL，否则新吊销会被旧文件遮蔽）
sudo $CA -m backend.cli crl-number                # 先看现状
sudo $CA -m backend.cli crl-number --set <现场最大+1>

# ④ 清理：同名 CA / 多余 CRL 移走备份（不删），只留原 CA + 一份 CRL
sudo mkdir -p /root/ca-backup
sudo mv /etc/swanctl/x509ca/<多余的>.pem /etc/swanctl/x509crl/<多余的>.crl* /root/ca-backup/

# ⑤ 重新生成并发布，然后重载（一次性 restart 可彻底清掉 charon 里的旧 CRL 缓存）
sudo $CA -m backend.cli gencrl
sudo swanctl --flush-certs
sudo swanctl --load-creds
sudo systemctl restart strongswan

# ⑥ 验证
sudo swanctl --list-certs                                   # 应只剩 1 份，编号=你设的下限
sudo $CA -m backend.cli doctor | grep -E "同名 CA|CRL 文件唯一性|重载命令"
```

导入后，用本系统签发的每一张证书、每一次吊销都会写进**原 CA** 的 CRL，
客户端/网关完全不用换证书 —— "吊销 → CRL → 拒绝连接"的闭环就此接通。

### 传输完整性：纯 HTTP 下如何保证前端 JS 不被篡改

**先说结论**：在纯 HTTP 上，**无法用客户端手段保证**。因为负责加密的 `crypto.js`
本身就是通过这条 HTTP 通道下发的——主动中间人把它换掉，就能偷口令、伪造签发/吊销；
而任何"页面内自证清白"的检查，都能被那份换过的代码伪造。这是信任锚问题，不是实现缺陷。

分层说明**什么被保护、什么没有**：

| 攻击场景 | 是否防住 | 靠什么 |
| --- | --- | --- |
| 同网段被动嗅探抓包 | ✅ | 应用层加密（X25519 + XSalsa20-Poly1305），口令/私钥不以明文上网 |
| **首次访问时的主动中间人**（改 HTML/JS） | ❌ | 纯客户端无法解决 |
| 首次之后的中间人 | ⚠️ 部分 | TOFU 指纹钉住——但钉的是**信道密钥**；代码若被换过则无效，且 `?resetfp=1` 会重置 |
| 第三方脚本注入 | ✅ | 严格 CSP（`script-src 'self'`，无内联/无外链）+ `X-Frame-Options: DENY` 等 |
| 服务器上的前端文件被人改动 | ⚠️ 可检测 | `cli asset-hash` 指纹变化；`doctor` 会打印该指纹 |

**要真正拿到完整性，从下面选一个：**

**方式 A（推荐，最省事）：管理端口不要暴露到网络**

```bash
# 服务器：只监听回环（systemd 单元里设 Environment=CA_HOST=127.0.0.1）
# 你的电脑：建立 SSH 隧道
ssh -L 9443:127.0.0.1:9443 your-server
# 浏览器访问 http://127.0.0.1:9443/
```
字节走 SSH（自带认证与完整性校验），前端 JS 的完整性由 SSH 保证，不需要信任任何 TLS 证书。

**方式 B（必须走明文 HTTP 时）：带外核对前端字节**

```bash
# 1) 服务器上（经 SSH，可信）：打印真实指纹与每个文件的 SHA-256
cd /opt/ca-dev && .venv/bin/python -m backend.cli asset-hash
#    资源指纹（与登录页/服务器日志核对）: 6230-07A8-B509-6B76

# 2) 在**你自己的机器**上，用你从可信渠道拿到的同一份代码去核对线上实际返回的字节
python3 -m backend.cli asset-hash --check-url http://your-server:9443
#    ✅ 一致：服务器返回的前端字节与本地可信副本完全相同（未被篡改）
#    ❌ 不一致：会精确指出是哪个文件（例如 crypto.js）并给出两边哈希
```
一致就说明"你浏览器里跑的代码 = 服务器上的代码"。**必须在自己的机器上跑**：
在服务器本机跑 `--check-url` 只能验证回环，验证不了你那一段网络。
（未登录访问 `/index.html` 会被认证门禁替换成登录页，工具会识别为正常、不误报；
如需核对登录后的 SPA 外壳，加 `--cookie "ca_session=..."`。）

**方式 C：启用 TLS + 客户端钉住**（如果你愿意）：`CA_TLS=on` 用自签证书，
让浏览器/客户端固定其 SPKI。这样传输既有保密也有完整性，且不依赖公共 CA 是否可信。

**方式 D（补充检测，不能替代 A/B）**：首次核对通过后，把资源指纹记录下来，
之后定期 `cli asset-hash` 比对——能发现"服务器上的前端被别人改过"。

两个必须知道的细节：
* 登录页显示的**信道指纹**钉的是加密信道密钥，**不是代码**；`?resetfp=1` 只能在
  **带外确认**服务器确实更换过密钥之后使用（否则等于把 TOFU 关掉）。
* **明文 REST 默认仅回环**（`CA_LEGACY_API=loopback`）：供本机 CLI/验收使用；
  远程访问一律走应用层加密信道。


## 2. 安装与部署

**全新虚拟机请从 [deploy/QUICKSTART.md](deploy/QUICKSTART.md) 开始。** 文档按 Ubuntu 24.04 / Debian 12、`/opt/ca-dev`、charon-systemd + swanctl 编写，覆盖系统依赖、清华 pip 源、SSH 隧道、实际发布验收和故障处理；每框一条命令，不用环境变量。

完成文档中的系统准备、源码放置和权限设置后：

```bash
cd /opt/ca-dev
```

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua --dry-run
```

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

安装会检查 swanctl/VICI、可见地安装依赖、保留已有数据，再验证 ca-admin 稳定运行和 HTTP 健康响应。失败会返回非零并给出原因，不会因为单元已启用就宣称成功。

root 服务直接发布 CRL，默认关闭旧版额外同步 path/timer；只有显式选择非 root 系统服务时才启用 root 同步。安装不重启 strongSwan，但以后发布 CRL 的默认重载命令含全局重启，会中断 VPN 连接。

首次管理员口令位于 `data/initial_admin_password.txt`；首次登录请改密。虚拟机本机可打开 `http://127.0.0.1:9443/`，宿主机/手机按 [SSH 指南](deploy/DEPLOY-LOOPBACK-SSH.md) 建立隧道。不要直接打开公网 HTTP 管理地址。

已有部署请用 QUICKSTART 的升级/迁移章节，不能把新源码目录嵌套到旧目录，也不要搬运原 `.venv`。

---

## 3. 传输安全：为什么没有 HTTPS，以及怎么保证安全

应用层加密信道的设计如下（远程管理仍要求 SSH 隧道或可信 TLS）：

1. 服务端有一对长期 X25519 密钥，公钥与**指纹**公开（`GET /api/handshake`），指纹同时打印在启动日志里。
2. 浏览器生成临时 X25519 密钥对，与服务器做 `crypto_box_beforenm` 协商，再用
   `SHA512(shared || 标签)[:32]` 派生出**两个方向各自独立**的对称密钥。
3. 之后**所有请求与响应正文**都用 NaCL `secretbox`（XSalsa20-Poly1305，AEAD）加解密；
   每条消息的 nonce = `递增计数器(8B) || 随机(16B)`，服务端强制计数器严格递增 → **防重放**，
   密文被改一个字节就解密失败（服务端会立刻作废该信道）。
4. 登录在密文里完成，成功后把用户名绑定到该信道；在 TLS 或回环/SSH 可信传输下，
   还会下发会话 cookie 供跨页面使用。非回环明文连接不会下发 cookie。
5. 指纹固定只在前端代码未被篡改时能发现服务端密钥变化；HTTP 下发的检查代码
   本身可以被主动中间人替换，不能作为远程裸 HTTP 的完整性保证。

**诚实的局限**：这套方案保护加密信道中的正文免受被动窃听，但网页脚本仍经 HTTP 下发。
即使首次核对过指纹，后续访问的前端代码仍可被主动中间人替换。请只通过 SSH 隧道或
可信 TLS 访问管理界面；首次指纹核对不能代替传输保护。

### root 运行 + 沙箱（`deploy/ca-admin-root.service`）

以 root 运行是为了能直接写 `/etc/swanctl` 并执行包含 `swanctl --flush-certs` 的重载命令，让 CRL 自动化闭环最短。
同时用 systemd 把 root 关进笼子：

```ini
ProtectHome=yes                 # /home、/root、/run/user 完全不可访问（读不到其他用户目录）
InaccessiblePaths=-/etc/shadow -/etc/gshadow # 不存在时忽略；不使用通配符
ProtectSystem=strict            # 整机只读
ReadWritePaths=<数据目录> /etc/swanctl /run
CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER CAP_DAC_READ_SEARCH
NoNewPrivileges=yes, PrivateTmp=yes, RestrictNamespaces=yes, ProcSubset=pid ...
UMask=0077
```

安装脚本在以 root 执行时会把 `data/` 交给 `root:root` 并设为 `0700`，**其他用户不可读取数据内容**；
私钥、会话密钥、初始口令文件都是 `0600`。一致性体检会检查数据目录与敏感文件权限并给出修复。

其他应用层防护：

- 明文 REST 接口默认**只允许本机回环**（`CA_LEGACY_API=loopback`），方便运维与自动化；
  远程只能用界面（加密信道）。可设 `off` 完全关闭或 `on` 放开。
- 登录失败 5 次锁定并按指数退避；成功即清零；登录/失败/锁定/改密都进审计。
- 严格 CSP、`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy`；API 响应 `no-store`。
- 上传体积上限、静态资源白名单、路径穿越防护、备份归档解包防穿越、公开 CRL 端点严格路径白名单。
- 唯一会执行外部命令的地方是**你自己配置**的发布目标 `reload_cmd` 与自动化 `command` 任务。

---

## 4. 导入已有 CA 和吊销记录

首次部署时，根据实际情况完成下面的操作：

1. **导入 CA 证书和私钥**：
   - 界面：「CA 管理」→「导入 CA」→ 选证书 + 私钥（可填私钥口令）→ 导入
   - 或命令行：
     ```bash
     .venv/bin/python -m backend.cli import-ca \
         --cert ~/ca.cert.pem --key ~/ca.key.pem            # 私钥若加密，再加 --password '口令'
     ```
   导入成功后，可以签发证书、吊销证书和生成 CRL。

2. **导入或核对已有吊销记录**：
   ```bash
   # 单张吊销（会自动重新生成并发布 CRL）
   .venv/bin/python -m backend.cli revoke --serial <序列号> --reason keyCompromise
   # 或批量：把要吊销的证书放一个目录，导入时直接标记吊销
   .venv/bin/python -m backend.cli import --path <目录> --revoked --reason keyCompromise
   ```
   如果你手上已有 CRL 文件，用界面「吊销与 CRL → 导入 CRL 同步吊销状态」或
   `POST /api/crl/import` 一键同步即可（系统会按序列号匹配并标记吊销）。

---

## 5. 核心概念

### 5.1 规则集（Rule Set）—— 「证书怎么签」全部是可编辑数据

打开「规则集」页，内置 13 套预设，**排在最前的是 strongSwan**：

| 规则集 | 平台 | 用途 |
| --- | --- | --- |
| `strongswan-vpn-client` | strongswan | IKEv2/EAP-TLS 客户端，`clientAuth+ipsecIKE`，825 天（**默认**） |
| `strongswan-vpn-gateway` | strongswan | VPN 网关，`serverAuth+ipsecIKE` |
| `strongswan-vpn-client-ec` | strongswan | 同上但用 EC P-256 |
| `windows-smartcard-upn` / `windows-user-vpn` | windows | 智能卡/Windows IKEv2，导出 PKCS#12，自动补 UPN |
| `linux-vpn-client` | linux | PEM 分离文件、私钥 0600 |
| `server_tls` / `client_tls` / `code_signing` / `email_smime` / `custom` / … | any | 通用用途 |

每个规则集可编辑的字段（**全部可改，改完立即对之后签发的证书生效**）：

- `subject`：必填字段、CN 是否取自身份、长度限制
- `san`：是否必须、允许的 SAN 类型、从身份自动生成、邮箱自动补 UPN、CN 复制进 SAN、条数上限
- `key`：类型（rsa/ec/ed25519）、位数、最小 RSA、允许的 EC 曲线、**摘要算法**（sha256/384/512…）
- `validity`：默认天数与上下限、notBefore 回溯分钟
- `extensions`：KeyUsage、EKU（可选内置名或**直接写 OID**）、SKI/AKI、**CRL 分发点**、OCSP 地址、
  `path_length`、**自定义 OID 扩展**（utf8/hex/der-base64/int，可标 critical）
- `serial`：随机位数或顺序号
- `revocation`：是否允许吊销、默认原因、是否自动发布 CRL
- `export`：导出 PEM / PKCS#12 / 两者，私钥文件权限，Windows 导入提示、Linux 落位提示
- 高级：`strict`（只允许覆盖白名单字段）、`overridable`

操作：新建、编辑、复制、删除、设为默认、**恢复出厂**。签名页选中规则集后，可在允许范围内临时覆盖字段。

> 想给别的系统（802.1X、签名网关、内部 mTLS…）加用途？**新建一个规则集即可，不需要改代码。**

### 5.2 CRL 的「消费方式」—— 全部可改，不写死

本系统只负责**产出** CRL；CRL 怎么被消费由**数据**决定，随时可改：

**（A）消费设置**（`GET/PATCH /api/publish/settings`，存在数据库里，可改可重置）

| 设置 | 默认 | 说明 |
| --- | --- | --- |
| `swanctl_dir` | `/etc/swanctl` | strongSwan 配置根目录 |
| `swanctl_crl_dir` | `/etc/swanctl/x509crl` | CRL 落地目录（**按你的现场约定**） |
| `swanctl_ca_dir` | `/etc/swanctl/x509ca` | CA 证书落地目录 |
| `crl_filename` | `crl.der` | CRL 文件名；**留空则自动沿用目标目录里已有的本 CA 的 CRL 文件名** |
| `crl_format` | `der` | `der` 或 `pem` |
| `crl_reload_cmd` | `swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan` | 发布后清缓存并重新加载的命令；可按现场验证调整 |
| `publish_ca_cert` | `1` | 是否同时把 CA 证书发布过去 |
| `ca_cert_filename` | 空 | 留空则沿用现场文件名或自动生成 |

改完设置后调 `POST /api/publish/apply-settings`（界面按钮「按设置生成/更新发布目标」），
系统会**创建或更新**对应发布目标，**幂等、不会产生重复目标**。

**（B）发布目标**（「CRL 自动发布」页，每条都能单独改）

- 内容类型：`CRL`（PEM/DER）、`CA 证书`、`CA 证书链`
- 目标三选一：
  - 目录 + 文件名 + 权限 + 属主（`dir_file`）
  - 一条命令（`command`，内容路径通过 `CA_CONTENT_FILE` 等环境变量传入，可 scp/rsync/curl）
  - 任意扩展（见 5.3 自动化的 Webhook）
- 所以 CRL 不止能给 strongSwan 用：换目录、换文件名、换格式、推远端、发通知，都是**配置**。

- **到期前自动续签**：在 `nextUpdate` 到期前 `lead_hours`（默认 72）小时自动重新生成并发布，
  所以 strongSwan 永远拿不到过期 CRL（过期 CRL 会被 strongSwan 判为不可用而拒绝连接）
- **吊销即生效**：任何吊销都会立刻重新生成并发布 CRL

#### 重载 strongSwan：默认命令与「防重载风暴」

默认重载命令（设置页可改，每个目标也可单独改）：

```bash
swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan
```

为了避免 strongSwan 被反复 reload，默认开启三重保护：

1. **内容未变就不重载**（每个目标有 `only_if_changed`，默认开）：目标文件与待发布内容
   字节一致时，既不写文件也不重载，只在结果里标注「内容未变化，已跳过（不重载）」。
2. **同一轮只重载一次**：一轮发布里多个目标即便写同一个重载命令，也只执行一次
   （早期版本每个目标各重载一次，是"总是重载"的主因）。
3. **最小重载间隔**：`reload_min_interval_seconds`（默认 30 秒）。间隔内的发布会照常
   更新文件，但**跳过重载**并在结果/审计里给出原因；审计里另有 `crl.reload` 记录，
   可直接看出"谁在什么时候重载了什么"。

`deploy/ca-strongswan-sync.sh`（非 root 部署时的 root 同步单元）同样只在
**内容确实变化时**才执行配置的重载命令（默认包含 `swanctl --flush-certs`），否则直接退出不重载。
它按**内容/扩展名**识别文件（`head -c 64 | grep "BEGIN X509 CRL"`，DER 看扩展名），
所以 `crl.der`、`<ca>.crl`、`<ca>.crl.pem`、`<ca>.crt.pem` 等任意命名都能正确归位——
这一点很关键：早期版本只匹配 `*.crl`/`*.pem`，遇到现场的 `crl.der` 会**静默不同步**。

如果你的 strongSwan 单元名不是 `strongswan`（例如 Debian 上是 `strongswan-starter`），
或者想换掉默认命令，用 `CA_RELOAD_CMD` 覆盖（写进 systemd 单元的 `Environment=` 即可）：

```bash
CA_RELOAD_CMD="swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan-starter"
```

> 自动化测试就是靠这个变量把默认重载命令指向无害回显，再叠加 PATH 里的
> `systemctl`/`swanctl` 桩，因此**跑测试绝不会调用你机器上的真实 systemd**；
> `./tests/run_all.sh` 结束时还会校验"调用日志为空"。

**升级已有部署时**：老目标里存的是旧命令，不会自动跟随设置变化，执行一次即可对齐：

```bash
.venv/bin/python -m backend.cli reload-cmd           # 查看当前所有目标的重载命令
.venv/bin/python -m backend.cli reload-cmd --set "swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan"
# 或： POST /api/publish/reload-cmd {"cmd": "..."}  ；界面「CRL 自动发布」页也有对应按钮
```
- **避免重复 CRL**：`GET /api/publish/inspect?dir=<目录>` 会探查目录里已有的 CRL/证书，
  报告主题、指纹、本次/下次更新时间、是否属于当前 CA；若目录里存在**同一 CA 的另一份 CRL**，
  发布会给出提醒（同一 CA 两份 CRL 会被 strongSwan 报重复），此时把 `crl_filename`
  改成现场那个文件名即可。

### 5.3 自动化（通用扩展点）—— 触发器 + 内容 + 动作

「自动化」页是一个**通用引擎**，CRL/strongSwan 只是它的第一个预设：

- **触发器**：手动、`on_revoke`、`on_unrevoke`、`on_issue`、`on_renew`、`on_import`、
  `schedule`（定时）、`crl_expiry`（CRL 到期前）
- **内容**：CRL(DER/PEM)、CA 证书(DER/PEM)、CA 链、证书(PEM)、私钥(PEM)、`index.txt`、证书清单 CSV、无
- **动作**：写入文件（原子替换 + 权限/属主）、执行命令（内容路径通过 `CA_CONTENT_FILE` 等
  环境变量传入，可 scp/rsync/curl）、HTTP Webhook（可带 `X-CA-Signature` HMAC 签名）
- **条件**：`only_if_changed`（内容未变自动跳过，避免重复动作）、启用开关、失败留痕

内置示例（默认**停用**，不与发布目标重复）：吊销时发 Webhook、每天导出证书清单、
CRL 到期前推送到远端网关、签发后导出 CA 链。

> 要新增能力？给 `CONTENTS` / `KINDS` / `TRIGGERS` 加一个键并实现对应分支即可，已有任务逻辑不用动。

### 5.4 CSR 证书请求池（`#/csrs`）

私钥应由申请方自己保管，所以除了「直接签发」，系统还提供一条**先收 CSR、再签发**的路径：

1. **批量导入**：上传 `.csr/.req/.p10/.pem`（可多选或打包 zip），或填服务器目录路径；
2. **预检**：显示每个请求的 CN、密钥类型/长度、SAN、CSR 自签名是否有效、是否重复；
   确认后才写入请求池；
3. **审核签发**：对某条请求选规则集（+ 可选有效期、允许重复签发）→ 签发；
   扩展策略、CRL 分发点、序列号、审计、自动化触发与「直接签发」完全一致；
4. 签发后该请求标记为 `issued` 并关联证书（`cert_id`），默认**不能重复签发**（防重签）；
   也可标记 `rejected` 保留复盘；仅未签发的请求可删除。

一致性与安全：以**公钥指纹（SPKI）**唯一约束去重，同一请求不会重复入库；入库即校验 CSR 自签名；
`POST /api/certs/import/dir` 导入混合目录时会**自动分流**——证书进证书库、CSR 进请求池。

```bash
.venv/bin/python -m backend.cli csr-import --path /root/csr-batch --dry-run
.venv/bin/python -m backend.cli csr-list --status pending
.venv/bin/python -m backend.cli csr-issue --id 3 --ruleset strongswan-vpn-client --out /tmp/vpn3
```

### 5.5 数据一致性

- **SQLite 是唯一事实来源**；`index.txt` 与 CRL 文件都是从数据库**派生**的产物，不存在双写漂移。
- 签发/吊销/导入都是「事务 + 文件原子落盘（写临时文件再 rename）」；失败自动回滚并清理已写文件。
- 数据库层面用唯一索引（指纹、CA 内序列号）阻止重复；外键约束引用关系。
- 「一致性体检」检查：证书/私钥文件缺失、指纹与磁盘不符、签名验证失败、孤儿文件、
  CRL 与已吊销数不一致、CRL 过期、CRL 未发布、顺序序列号计数器落后、私钥/数据目录权限过宽……
  可修复项提供**一键修复**。

---

## 6. strongSwan 工作流（端到端）

### 6.1 签发客户端证书

1. 「签发证书」→ 选规则集 `strongSwan VPN 客户端（IKEv2 / EAP-TLS）`
2. 填 **VPN 身份**：`vpn1.example.com`（FQDN）或 `user@example.com`（邮箱）或 `10.9.9.9`（IP）
   - 系统会按规则集把身份写成正确的 SAN：dNSName / rfc822Name（并自动补 UPN） / iPAddress
   - **strongSwan 用 SAN 匹配 IKEv2 身份（`local.id` / `eap_id`），只看 CN 是不够的**
3. 有效期、密钥类型等按规则集默认（可改）
4. 签发后可下载：PEM/DER、私钥、证书链、PKCS#12，或直接下载 **strongSwan 一键部署包**

### 6.2 一键部署包（ZIP）

在证书详情里点「下载 strongSwan 部署包」，填 role（client/gateway）、网关地址、可选 PKCS#12 口令。
包里含：

```
<cn>.crt.pem          证书         → /etc/swanctl/x509/
<cn>.key.pem          私钥(0600)   → /etc/swanctl/private/
<ca>.crt.pem          CA 证书      → /etc/swanctl/x509ca/
<ca>.crl(.pem)        CRL          → /etc/swanctl/x509crl/
<cn>.conf             swanctl 连接片段 → /etc/swanctl/conf.d/
<cn>.p12              （可选）PKCS#12，便于 Windows 导入
install-strongswan.sh 一键安装脚本（root 执行）
README.txt            部署步骤 + CDP 地址 + 身份说明
```

目标机执行：

```bash
unzip strongswan-*.zip -d /tmp/vpn && cd /tmp/vpn
sudo ./install-strongswan.sh        # 拷文件 + swanctl --load-creds && --load-conns
sudo swanctl --list-sas             # 查看隧道
```

### 6.3 CRL 自动化闭环（关键）

> 默认 swanctl 目标是 `/etc/swanctl/x509crl/crl.der`（DER）。首次初始化会在满足条件时建立目标：
> 发布目标直指该文件、格式 DER、发布后执行含 `swanctl --flush-certs` 的配置命令。
> 这些都存在数据库里，后续想改目录/文件名/格式/重载命令，改设置或直接改目标即可，无需改代码。

```
吊销证书 / CRL 临近 nextUpdate
        ↓（服务在 nextUpdate 前 lead_hours 小时自动重新生成，或吊销后立即）
原子写入 /etc/swanctl/x509crl/crl.der   （写临时文件再 rename，charon 不会读到半截）
        ↓
swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan
        ↓
strongSwan 立刻用上新 CRL
```

证书可配置 **CRL 分发点（CDP）**。回环管理端口不供远端 VPN 客户端下载；如需在线获取 CRL，应另配客户端可达的分发地址，不能为此开放明文管理界面。
远端对端可以自己通过 HTTP 拉取（该端点公开、无需认证，因为 CRL 本身就是公开信息）。
`/crl/ca-<id>.crl`（DER）与 `/crl/current.crl.pem`（PEM）都提供，并带
`X-CRL-Number` / `X-CRL-Next-Update` 响应头便于观测。

如果服务改成非 root 运行，用 `deploy/ca-strongswan-sync.{service,path,timer}`（root）
监听暂存目录并自动同步 + 重载，效果等价。

### 6.4 Windows 与 Linux 的差异（规则集里可改）

| | Linux / strongSwan | Windows |
| --- | --- | --- |
| 交付格式 | PEM 分离文件（证书/私钥/CA/CRL），私钥 0600 | **PKCS#12（.p12/.pfx）**，双击导入或 `certutil -importPFX -p <口令> x.p12` |
| 身份 | SAN 里 FQDN / email / IP，与 `local.id`/`eap_id` 一致 | 除 FQDN 外通常还要 **UPN（otherName）**；规则集 `add_upn_for_email` 会自动补 |
| EKU | `clientAuth (+ipsecIKE)` | `clientAuth`；智能卡登录再加 `msSmartcardLogin` |
| CRL 获取 | 文件放 `x509crl/` 或按 CDP 拉取 | 不读文件型 CRL，**依赖 CDP/OCSP**，所以务必设置 CRL 分发点 URL |
| 导入方式 | 拷文件 + `swanctl --load-creds` | 证书管理器/`certutil`；部署包会显示导入命令 |

---

## 7. 导入与修改数据

### 界面

- **导入数据**：上传证书/私钥/PKCS#12/ZIP（**先预检再导入**，显示每条的 CN、序列号、签发者、
  是否属于当前 CA、是否重复、是否将标记吊销）；也支持「从服务器目录导入」和「CSV 元数据导入」。
- **证书详情**：改所有者、标签、备注；续期；吊销/恢复；下载各种格式。
- **批量签发**：粘贴或上传 CSV，先预检再签发，逐行报错。
- 导入时若吊销状态发生变化，系统会**立即重新生成并发布 CRL**。

### 命令行（适合脚本化）

```bash
.venv/bin/python -m backend.cli --help
.venv/bin/python -m backend.cli import-ca --cert ~/ca.cert.pem --key ~/ca.key.pem
.venv/bin/python -m backend.cli import --path ~/certs --revoked --reason keyCompromise
.venv/bin/python -m backend.cli issue --identity vpn1.example.com --out /tmp/vpn1
.venv/bin/python -m backend.cli revoke --serial 53D2... --reason keyCompromise
.venv/bin/python -m backend.cli publish
.venv/bin/python -m backend.cli bundle --id 3 --gateway vpn.example.com --out /tmp/vpn3.zip
.venv/bin/python -m backend.cli check --repair
.venv/bin/python -m backend.cli export --format csv --out /tmp/certs.csv
.venv/bin/python -m backend.cli passwd
.venv/bin/python -m backend.cli automation --list
```

**没有任何 openssl 命令行依赖**：所有密码学操作都用 `cryptography` 库完成，规则集也是纯数据。
唯一与 OpenSSL 有关的是可选的 `index.txt` 导出（仅在你要用外部工具互操作时才用到）。

---

## 8. 运维

| 事项 | 做法 |
| --- | --- |
| 启动/停止 | `sudo systemctl {status,restart,stop} ca-admin` |
| 日志 | `journalctl -u ca-admin -f`（前台运行时输出到 `data/server.log`） |
| 端口/监听 | `CA_HOST` / `CA_PORT`（默认 `127.0.0.1:9443`）；需要网络访问时须显式配置可信传输 |
| 备份 | 界面「设置 → 备份」，或 `backend.cli backup`；备份为 tar.gz（含数据库快照 + CA/证书/CRL + manifest 校验和） |
| 恢复 | 界面「设置 → 恢复」或 `backend.cli backup --restore <文件名>`；恢复前自动做一次安全备份，解包含路径穿越防护 |
| 体检 | 界面「一致性体检」或 `backend.cli check [--repair]` |
| 自检 | `.venv/bin/python -m backend.cli doctor`（部署前后都能跑；`--json` 便于自动化） |
| 验收 | `.venv/bin/python tests/verify_deploy.py http://127.0.0.1:9443 --pw-file data/initial_admin_password.txt` |
| 全量测试 | `./tests/run_all.sh`（24 套；通过/失败/跳过以当次输出为准） |
| 部署前自检 | `.venv/bin/python -m backend.cli preflight`（只读；Python/依赖/权限/端口/strongSwan/工具链） |
| 先看不改 | `sudo ./deploy/install.sh --systemd --loopback --dry-run`（只读检查，见 QUICKSTART） |
| 服务器上手 | 见 [`deploy/QUICKSTART.md`](deploy/QUICKSTART.md)（首次部署 / 升级 / 回滚 / 巡检 一页命令） |
| 前端 DOM 测试依赖 | 一次性安装：`mkdir -p .tmp/fe-test && cd .tmp/fe-test && npm install --cache ../npm-cache jsdom` |

### 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `CA_HOST` / `CA_PORT` | `127.0.0.1` / `9443` | 监听地址与端口 |
| `CA_DATA_DIR` | `./data` | 数据目录 |
| `CA_LEGACY_API` | `loopback` | 明文 REST 范围：`off` / `loopback` / `on` |
| `CA_MANAGE_STRONGSWAN` | root 时 `1` | 是否直接管理 `/etc/swanctl` |
| `CA_SWANCTL_DIR` | `/etc/swanctl` | strongSwan 目录（仅作为首次生成的默认值，之后以数据库设置为准） |
| `CA_CRL_FILENAME` / `CA_CRL_FORMAT` | `crl.der` / `der` | 同上，仅首次默认值 |
| `CA_TLS` | `off` | 设为 `on` 可额外启用 HTTPS（例如放在反向代理后） |
| `CA_ALLOWED_HOSTS` | 空 | 设置后校验 Host 头，防 DNS rebinding |
| `vpn_gateway`（设置页） | 空 | strongSwan 客户端连接的对端网关地址，用于生成 swanctl 片段/部署包 |
| `CA_TRUST_PROXY` | `0` | 位于反向代理后时设为 `1`，用 `X-Forwarded-For` 取真实 IP |
| `CA_CHANNEL_*` | — | 加密信道空闲/最大时长、并发上限、握手限速 |

---

## 9. 部署验收、升级与回滚

完整流程统一维护在 [deploy/QUICKSTART.md](deploy/QUICKSTART.md)，避免不同章节的命令相互冲突。
安装必须确认进程和 HTTP 健康检查，业务验收另需验证 CA、CRL 目标以及真实 VPN 客户端。
升级前保留代码与数据备份；恢复数据备份不等于回滚代码版本。

重复初始化不会重复创建规则集、自动化预置或管理员；也不会重置已有发布目标和自定义重载命令。

### 验证范围（诚实说明）

- **后端**：`tests/e2e_test.py` 覆盖加密信道、认证与锁定、CA 导入、签发/CSR/批量、
  吊销与恢复、CRL 生成与发布与自动化、导入（文件/目录/ZIP/PKCS#12/CSV/CRL）、一致性体检与修复、
  备份恢复与路径穿越防护、规则集 CRUD 与策略、strongSwan 片段与部署包、审计、设置、**前端请求体契约**、
  **重复初始化幂等**、**老库列迁移**、**多信道并发签发/吊销**。
- **前端（真实 DOM）**：`tests/frontend_e2e.js` 用 jsdom 在真实 DOM 中加载**交付原文件**，
  通过真实 HTTP 命中真实后端（走应用层加密信道），验证：登录页正确/错误口令、指纹钉住与
  `resetfp=1` 重置、主应用引导后逐个遍历 **13 个页面**渲染、表格出数据行、证书列表显示真实数据、
  **下载**（证书 PEM / 证书链 / CRL，base64 信封）、**上传**（CSR 走 files 信封入库后页面可见）、
  非法文件得到结构化错误，以及**全程零未捕获 JS 错误**。
  另外静态检查：`node --check`、导航 ↔ 视图 ↔ 路由一一对应、`data-act` 全部有处理器、无悬空 id。
- **仍未覆盖**：jsdom 不是真正的浏览器内核（无布局/无真实下载落盘/无 CSP 执行）。
  建议部署后按 QUICKSTART 验收并在浏览器里再走一遍（尤其规则集编辑、发布目标增删改、PKCS#12 下载）。

> 这套前端 DOM 测试第一次运行就抓出了 3 个会让界面**完全不可用**的缺陷（都在 `crypto.js`）：
> 握手包漏传 nonce（tweetnacl 与 PyNaCl 的语义差异，导致服务端永远解不开）、
> 以及 2 处把 `TextDecoder` 实例当函数调用（`dec(x)` 应为 `dec.decode(x)`）。
> 之前的后端测试全部通过也发现不了它们——因为 Python 测试客户端自己实现了协议，
> 而两个前端 agent 的自测都用桩替换了 `CASecure`。这就是"真实 DOM + 真后端"这层的价值。

## 10. 常见问题

**Q：页面显示指纹，我要核对吗？**
建议首次核对一次（与服务器启动日志或 `backend.cli fingerprint` 一致）。之后浏览器会固定；
若某天出现红色「指纹不一致」，先在服务器核对，确认无误后用 `?resetfp=1` 更新。

**Q：为什么提示「CA 私钥未导入」？**
因为部署时只导入了你的 CA **证书**。导入私钥后，签发、吊销、CRL 全部可用（见第 4 节）。

**Q：strongSwan 说 CRL 不可用 / 拒绝连接？**
检查「CRL 自动发布」页的健康度：`critical` 通常是 CRL 过期或没发布。系统会在 `nextUpdate`
前 `lead_hours` 小时自动续签；也可以点「立即重新生成并发布」。同时确认 strongSwan 侧
`revocation` 插件已启用、`/etc/swanctl/x509crl/` 里有文件（`swanctl --list-certs`）。

**Q：能否同时管多套 CA？**
可以，「CA 管理」可导入多个 CA 并切换当前生效的 CA；历史 CA 的证书仍可查询与导出。

**Q：想改数据目录到 `/var/lib/ca-admin`？**
改 `CA_DATA_DIR`（systemd 单元里的 `Environment=` 与 `ReadWritePaths=` 一起改）即可；
root 部署时安装脚本会自动把数据目录 `chown root:root` 并设为 `0700`。


> 全新实例（尚未导入 CA）跑 `doctor` 为 **0 个 error**，只给一条“尚未导入 CA”的待完成步骤，导入后自动消失。
