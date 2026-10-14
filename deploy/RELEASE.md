# 1.0.1 完整安装包与发布验收

安装目录 `/opt/ca-dev`，面向 swanctl/VICI，默认回环监听与 SSH 隧道访问。
安装流程见 [QUICKSTART.md](QUICKSTART.md)。源码、前端资源、安装/升级脚本与测试都在同一个包内。
本版内置 WorkingDirectory / PathChanged 引号修复，无需执行 sed 补丁。

## 修复与发布流程

- systemd 单路径字段使用无外层引号的绝对路径；其余字段保留各自正确的转义规则。
- 正式安装、升级先对候选 ca-admin 单元执行 systemd-analyze verify；解析失败不会覆盖原服务单元。
- 服务进程稳定且 HTTP 健康检查成功才算启动成功；升级 doctor 出现 error 时返回失败。
- 升级设置开机启动，保留已有账号、CA、证书、监听配置与自定义重载命令。
- 统一打包脚本支持 ZIP 与 tar.gz，并生成 SHA256SUMS；拒绝混入私钥、数据库、符号链接等。
- 发布检查不允许静默跳过缺少 jsdom 的前端测试。包验收同时检查命令退出码与业务断言。

## 本地验证与真实部署的边界

本次编修环境没有运行 systemd，也没有 swanctl；不能在此宣称已完成真实 VPN 服务验收。
本地业务回归与故障注入结果记录在 INSTALL-CHANGES.md。

`.github/workflows/release-check.yml` 是独立发布门禁：

1. Python 3.12、Node 22、jsdom 26.1.0 跑完整 24 组回归，前端依赖缺失即失败。
2. 用统一打包脚本生成源码 ZIP，后续步骤只验证这个包。
3. Ubuntu 22.04 / 24.04 各在真实 systemd VM 内安装 charon-systemd、swanctl 和该 ZIP。
4. 校验单元解析，真实启动 root 沙箱，签发并吊销测试证书，由运行中的服务向 `/etc/swanctl` 发布 CRL，并核对 charon 实际加载的 CRL 字节。
5. 重复安装、执行升级，检查数据/账号保留与服务可用性。
6. 两种 VM 都通过后才生成 `ca-dev-verified` 构建产物；`source-under-test` 仅为待验证包。

工作流尚未在当前对话中提交或执行。将源码放入 GitHub 仓库后，在 Actions 中查看 Release check 结果。
未通过真实部署门禁前，不应将该构建标成“已通过生产验收”。VPN 客户端能否连接及吊销后拒绝重连，还须结合现场隧道配置与吊销策略验证。

## 在开发机跑发布回归

先按安装指南准备 `.venv` 和依赖；以下命令在项目根目录执行，使用 Node 22。

```bash
npm install --prefix .tmp/fe-test --no-audit --no-fund jsdom@26.1.0
```

```bash
bash tests/run_all.sh --release
```

普通 `bash tests/run_all.sh` 允许前端依赖缺失时跳过；它不等价于发布门禁。

## 在一次性 VM 上跑真实集成验收

仅限新建的无业务 VM，按 QUICKSTART 完成 `/opt/ca-dev` 全新安装后运行。
它会创建测试 CA、签发/吊销证书、发布文件、重启 strongSwan、重跑安装与升级。
脚本会拒绝已有 CA、证书、swanctl 凭据或在线 VPN 会话的环境。

```bash
sudo /opt/ca-dev/.venv/bin/python /opt/ca-dev/tests/native_systemd_e2e.py --disposable-vm
```

该脚本没有加入普通回归入口；用完销毁测试 VM，不把测试 CA 迁入生产。
CRL 目录与加载/查询命令依据 [swanctl 目录](https://docs.strongswan.org/docs/5.9/swanctl/swanctlDir.html)、[load-creds](https://docs.strongswan.org/docs/5.9/swanctl/swanctlLoadCreds.html) 与 [list-certs](https://docs.strongswan.org/docs/5.9/swanctl/swanctlListCerts.html)。

## 生成和核对完整包

ZIP 自带顶层目录 `ca-dev-github-public/`；tar.gz 直接包含项目文件，解压到目标目录即可。

```bash
bash deploy/package.sh --out dist/ca-dev-github-public.zip
```

```bash
bash deploy/package.sh --out dist/ca-dev-1.0.1.tar.gz
```

新解包后，在项目根目录验证：

```bash
sha256sum -c SHA256SUMS
```

清单用于检测损坏或误改，不是发行者签名。修改代码后应重新打包。
