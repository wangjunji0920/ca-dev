# 安装流程修订记录 · 2026-10-14

## 适用场景

全新 Linux 虚拟机，代码在 `/opt/ca-dev`，使用 charon-systemd + swanctl。详细步骤见 [QUICKSTART.md](QUICKSTART.md)。本包只包含源码与文档。

## 本次变更

- 正式 systemd 安装在写文件前检查 Python 版本、root 权限、`/opt` 路径、systemd、`/etc/swanctl`、strongSwan 服务和 VICI 查询。VICI 查询有超时，不在安装时重启 strongSwan。
- 补齐 `.venv`/pip 检查。pip 缺失时尝试离线 ensurepip；环境损坏时提供保留数据的恢复方式。不静默升级 pip，依赖下载显示过程并设置网络超时/重试。
- 新增 `--pip-mirror tsinghua|pypi` 和 `--pip-index-url`；只写项目虚拟环境的配置，本次安装显式使用所选镜像。
- 保留 `ProtectHome=yes`、`ProtectSystem=strict` 等沙箱；移除家目录绑定和无效的 `.ssh` 通配路径。可选敏感路径使用可缺失标记。swanctl 的必需目录 `/etc/swanctl`缺失时在安装前报错。
- systemd 和同步脚本使用统一渲染器，正确处理空格、引号、百分号等，避免 sed 替换误解释路径。
- 服务重启后要求稳定主进程及真实 `/api/health` 响应均正常；auto-restart/226、超时或错误响应返回失败并输出日志。不再以 enabled 作为安装成功依据。
- root 模式直接发布 CRL，关闭额外同步 path/timer；非 root 模式显式指定账号，数据属主与服务用户一致，并启用 root 同步。
- 升级使用相同单元渲染和就绪检查，沿用原监听端口，向子命令传递实际数据目录，启动失败不宣称升级完成。非 root 服务不会被升级脚本静默改成 root。
- 同步脚本使用发布暂存目录对应的数据目录，避免外置数据目录时读错数据库。
- 部署验收中的实际一致性错误会导致非零退出；空库 `no_ca` 单独列为待配置。测试种子先发布 CRL 再验收。
- README、QUICKSTART 与 SSH 部署文档统一指向 `/opt/ca-dev`，覆盖清华源、系统包、全新安装、旧数据迁移、端口冲突和 `226/NAMESPACE`。部署命令一框一条，无环境变量。

默认 CRL 重载仍包含 `swanctl --flush-certs`、`swanctl --load-creds` 和 strongSwan 全局重启。全局重启会中断 VPN 连接；本次没有恢复已经移除的按身份关闭连接功能。

## 验证记录与边界

- 新增安装故障/就绪回归：17 个测试通过，包括真实创建的无 pip 虚拟环境、pip 失败保留数据、只读预览、参数校验、路径转义及 226/auto-restart 拒绝。
- 部署单元/回环访问检查：43 项通过；没有可用局域网地址，因此局域网地址探测跳过（另有 127.0.0.2 不可达检查）。
- 升级演练：43 项通过，包含数据保留、监听配置、备份失败停止和换入失败回滚。
- 全套测试共 24 个阶段：执行的 22 套通过；两套前端 DOM 测试因缺少 jsdom 跳过。systemd/strongSwan 写操作用桩，不等于真实服务验收。
- 完成上述回归后，进一步收紧部署验收对 CRL 错误的判定；最终交付包流程单独复测 20 项通过，包括真实解包、依赖已就绪情况下的初始化、HTTP 服务、部署就绪检查，以及损坏 CRL 必须验收失败。
- 首轮完整运行曾出现升级测试证书计数及 CRL 体检两项异常；随后独立复测、带相同命令桩复测和第二轮完整运行均通过。该首轮异常未确定原因，不能将复测通过解释为定位并修复了该异常；已有数据升级仍应保留备份。
- 当前执行环境不能启动真实 systemd/strongSwan；`systemd-analyze verify` 也因运行环境工作目录访问失败未完成。因此真实命名空间启动、VICI、实际 VPN 连接/吊销策略，须在目标虚拟机按 QUICKSTART 验收。未宣称完成真实 VM 验证。

本包经过文件清单检查，不包含运行数据、私钥、密码文件、虚拟环境、测试日志或备份。不要将测试运行后的整个工作目录直接上传 GitHub；请遵守 `.gitignore` 并检查暂存文件。

## 2026-10-14 追加修复：systemd 单路径字段引号

用户在真实虚拟机复现 `WorkingDirectory= path is not absolute: "/opt/ca-dev"`。根因是首版修订错误地将所有路径字段当作需要去引号的单词列表。修正三个服务模板的 WorkingDirectory 和同步 path 模板的 PathChanged；渲染器对这两个字段只做百分号转义，保留字面路径，其余单词/列表字段维持各自引号规则。

按 systemd 源码的 `config_parse_working_directory`、`config_parse_path_spec` 与 `config_parse_namespace_path_strv` 核对了差异：[Debian 发行的 systemd 源码](https://sources.debian.org/src/systemd/254.26-1~bpo12%2B1/src/core/load-fragment.c/)。新增三个回归测试，安装测试现为 20 项通过；部署单元与回环测试 43 项通过。本次未重跑与字段无关的完整业务测试。

当前环境缺少 systemd-analyze 硬编码使用的 `/tmp`，仍未完成原生 systemd 校验或真实服务启动。没有将静态模板断言冒充原生解析器验收；最终校验由目标机器上的安装脚本执行 `systemd-analyze verify`，随后验证进程与 HTTP 就绪。

## 1.0.1 完整包修订与验证

- 将版本统一为 1.0.1，新增 RELEASE.md 与 GitHub Actions 发布门禁；正式包面向 `/opt/ca-dev` + swanctl。
- 安装和升级先校验候选 ca-admin 单元，校验通过后才替换系统单元；升级 doctor 出错返回失败，并补齐开机启动设置。
- 使用统一 Python 标准库打包器生成 ZIP/tar.gz，包含逐文件 SHA256SUMS，保留 shell 入口执行权限；不带运行数据、虚拟环境或测试残留。
- 新增 `tests/run_all.sh --release`：缺少前端测试依赖时失败，不再以跳过替代发布验证。
- 新增独立的一次性 VM 集成测试：真实 systemd 解析（含历史引号错误反例）、服务沙箱启动、通过加密 API 签发/吊销、CRL 发布、charon 加载字节比对、重装与升级后数据保留。GitHub 工作流使用 Ubuntu 22.04 / 24.04；全部通过才输出 verified 产物。
- 本次重新执行 24 阶段回归：两组 DOM 因缺少 jsdom 跳过；包验收初次发现“空库验收失败却被测试容忍”的问题，其余已执行组通过。新增显式 `verify_deploy.py --allow-empty` 修复空库验收语义，保留默认需要 CA 的验收标准。
- 修复后独立复测：交付包 24 项通过（tar.gz/ZIP 内容和权限、清单哈希、真实解包安装、HTTP、空库/有 CA 验收、损坏 CRL 必须失败）；升级 43 项通过；全量运行中的安装 20 项、部署单元/回环 43 项通过。
- 严格发布入口在本地缺少 jsdom 时按预期退出 2；真实集成入口在非 `/opt/ca-dev` 环境按预期拒绝执行。这两项只验证阻止误通过的行为，不代表 DOM 或原生 systemd 测试已通过。
- 当前环境无可运行的 systemd/strongSwan VM；新增 GitHub 工作流尚未在线运行，也未执行 VPN 客户端连接测试。真实发布验证仍是待完成项；不能将本包表述为已通过真机验收的稳定发行版。
