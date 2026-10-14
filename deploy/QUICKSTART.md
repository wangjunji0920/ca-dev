# 全新虚拟机安装：/opt/ca-dev + swanctl

本指南面向 **Ubuntu 24.04 / Debian 12 的全新虚拟机**，使用发行版的 Python 3.10+、systemd、charon-systemd 和 swanctl。其他发行版需使用对应包名。项目专为 swanctl 管理 CA、签发证书和发布 CRL；安装项目不等于已经配置好可连接的 VPN。

正式安装目录统一为 `/opt/ca-dev`，数据为 `/opt/ca-dev/data`。请按顺序执行，**每个代码框只有一条命令，不需要环境变量**。首次安装使用本节；已有 CA 数据请先看下方“已有安装”。

1.0.1 完整包已包含 systemd 引号修复；发布门禁与真实集成测试见 [RELEASE.md](RELEASE.md)。

## 1. 准备系统和 swanctl

以下安装包命令只面向全新虚拟机。已有 VPN 服务器不要照此切换 strongSwan 的启动方式。

```bash
sudo apt update
```

```bash
sudo apt install -y python3 python3-venv ca-certificates unzip curl charon-systemd strongswan-swanctl
```

不要同时运行 strongswan-starter 和 charon-systemd。全新 swanctl 安装使用 `strongswan.service`；若你的发行版使用其他名字，先核实，再用安装参数 `--strongswan-service 实际单元名`。

```bash
python3 --version
```

```bash
sudo systemctl enable --now strongswan
```

```bash
sudo systemctl is-active strongswan
```

```bash
sudo swanctl --stats
```

应显示 `active` 和守护进程运行信息；如果出现 VICI 连接失败，先处理 strongSwan，暂不安装 CA 管理服务。

```bash
sudo journalctl -u strongswan -b -n 50 --no-pager
```

安装脚本还会检查 `/etc/swanctl`。不要为了绕过检查只创建空目录；目录、swanctl 命令和可用的 VICI 服务都应来自完整安装。

## 2. 把源码放入 /opt

先把下载的新版文件命名为 `ca-dev-github-public.zip`，在该文件所在目录执行。**如果 `/opt/ca-dev` 已存在，请转到“已有安装”，不要把新目录套到旧目录内。**

```bash
unzip ca-dev-github-public.zip
```

```bash
sudo mv ca-dev-github-public /opt/ca-dev
```

```bash
sudo chown -R root:root /opt/ca-dev
```

```bash
sudo chmod -R go-w /opt/ca-dev
```

```bash
sudo chmod 755 /opt/ca-dev
```

```bash
cd /opt/ca-dev
```

```bash
sudo chmod +x run.sh deploy/*.sh tests/run_all.sh
```

源码包不包含 `.venv` 或 `data`。不要把在下载目录创建的 `.venv` 搬过来：虚拟环境包含原路径，应该在最终目录重新创建。root 服务的代码、虚拟环境及其父目录不能由普通用户修改。

## 3. 检查并安装

预览会检查 Python、目录、systemd 和 swanctl/VICI，不创建数据或下载依赖。正式部署必须用 sudo，即使是预览。

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua --dry-run
```

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

`--pip-mirror tsinghua` 只配置这个项目的 `.venv/pip.conf`，并明确用于本次安装，不修改系统 pip；改回 PyPI 用 `--pip-mirror pypi`。不传镜像参数则沿用 pip 配置。下载过程可见，网络超时 15 秒、重试 1 次（不是整个安装限时 15 秒）。不再静默升级 pip。

安装缺少 pip 的虚拟环境时会先尝试 `ensurepip`；失败会说明处理方式。成功必须看到 **“安装成功：ca-admin 服务运行且健康检查通过”**。仅仅出现 enabled、注册了单元或生成了密码，不代表成功。

安装会保留现有数据库和账号，不重置管理员密码；不会执行 `swanctl --flush-certs` 或重启 strongSwan。root 服务直接向 swanctl 目录发布，默认关闭旧版额外的同步 path/timer，避免两条发布链同时工作。

## 4. 验收与访问

```bash
sudo systemctl is-active ca-admin
```

```bash
sudo ss -ltnp '( sport = :9443 )'
```

```bash
curl --fail http://127.0.0.1:9443/api/health
```

应看到 `active`、`127.0.0.1:9443` 及健康响应 `status: ok`；全新未导入 CA 时 `ca_ready: false` 正常。

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli doctor
```

“尚未导入 CA”是首次配置待办。部署成功不表示 VPN 或 CRL 已经完成业务验收。

```bash
sudo cat /opt/ca-dev/data/initial_admin_password.txt
```

账号为 `admin`。初始口令也可能出现在安装/启动日志中，不要公开粘贴未遮盖的日志。已有账号且口令已修改时，这个初始文件不代表当前密码。

在虚拟机自己的浏览器打开 `http://127.0.0.1:9443/`。如果在宿主机或手机上访问，需要 SSH 隧道；宿主机的 `127.0.0.1` 不会自动指向虚拟机。

全新虚拟机尚未配置 SSH 时，在虚拟机执行：

```bash
sudo apt install -y openssh-server
```

```bash
sudo systemctl enable --now ssh
```

在宿主机/手机终端执行以下命令，把 `user@vm-address` 换成实际 SSH 用户和虚拟机地址；NAT 环境需先让 SSH 可达。

```bash
ssh -N -o ExitOnForwardFailure=yes -L 9443:127.0.0.1:9443 user@vm-address
```

然后在宿主机/手机浏览器打开 `http://127.0.0.1:9443/`，核对信道指纹后登录并更改密码。访问期间保持隧道。不要把 `9443` 改成公网明文 HTTP 来绕过隧道。

## 5. 在测试虚拟机验证 swanctl 发布

下面会生成测试 CA 和证书，并对**这台虚拟机**的 swanctl 目录发布；仅用于没有真实 CA/VPN 业务的测试实例。`drill_seed.py` 不是生产初始化命令。

默认 CRL 重载命令仍为 `swanctl --flush-certs && swanctl --load-creds && systemctl restart strongswan`。最后一步会中断所有在线 VPN 连接。“按身份关闭连接”的独立功能已移除；全局重启仍存在。

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli reload-cmd --print
```

```bash
sudo /opt/ca-dev/.venv/bin/python tests/drill_seed.py
```

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli targets
```

应包含启用的 strongSwan CRL 目标，目录 `/etc/swanctl/x509crl`，文件 `crl.der`。如果先前在没有 strongSwan 时初始化过数据库，安装不会替你重置发布目标；请在“CRL 自动发布”页面添加或启用实际 swanctl 目标，并排除同一 CA 的重复 CRL。

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli revoke --cn drill-0 --reason keyCompromise
```

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli crl-info
```

```bash
sudo /opt/ca-dev/.venv/bin/python -m backend.cli check
```

```bash
sudo swanctl --list-certs --type x509_crl
```

核对签名有效、编号/吊销条目与数据库一致、启用的发布目标一致，且 strongSwan 实际加载了对应 CRL。`check` 的 error 应为 0。最后用真实 VPN 客户端分别验证未吊销证书能连接、已吊销证书重新连接被拒绝；这项不能由模拟测试替代，还需要正确的 VPN 配置和吊销检查策略。

## 6. 常见故障

### No module named pip / ensurepip

新版安装会先自动修复 pip。手工检查可执行：

```bash
sudo /opt/ca-dev/.venv/bin/python -m ensurepip --upgrade
```

如果 `ensurepip` 也缺失，先安装发行版的 venv 包：

```bash
sudo apt install -y python3-venv
```

若使用自定义 Python，需要其对应版本的 venv/ensurepip 支持。如果 `.venv` 已损坏，先停止服务，再把它改名保留；下面备份名若已存在，请另选一个名字，不能套目录。

```bash
sudo systemctl stop ca-admin
```

```bash
sudo mv -T /opt/ca-dev/.venv /opt/ca-dev/.venv-before-repair
```

```bash
sudo /opt/ca-dev/deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

只重建 `.venv`，不删除 `data`。

### 安装依赖很久没有完成

新版会直接显示 pip 原始输出。网络超时可使用清华源；证书错误先检查系统时间与 `ca-certificates`，不要关闭 HTTPS 证书校验。如果镜像尚未同步指定版本，可改用 `--pip-mirror pypi`。pip 失败时不会进入数据库初始化或 systemd 安装。

### WorkingDirectory= path is not absolute: "/opt/ca-dev"

这是 2026-10-14 首版安装修订包的模板错误：`WorkingDirectory` 是单个路径字段，systemd 不会像解析 `ExecStart` 那样去掉外层引号。当前包已修正；`PathChanged` 的同类问题也已修正。`Environment`、`ExecStart`、`ReadWritePaths` 的引号仍应保留。

已有 `/opt/ca-dev` 安装无需删除 data 或重建虚拟环境。逐条执行下面的定向修复，然后重跑安装；后者会重新生成并验证服务单元。

```bash
sudo sed -i 's/^WorkingDirectory="\(.*\)"$/WorkingDirectory=\1/' /opt/ca-dev/deploy/ca-admin-root.service /opt/ca-dev/deploy/ca-admin.service /opt/ca-dev/deploy/ca-admin-user.service
```

```bash
sudo sed -i 's/^PathChanged="\(.*\)"$/PathChanged=\1/' /opt/ca-dev/deploy/ca-strongswan-sync.path
```

```bash
sudo /opt/ca-dev/deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

### 226/NAMESPACE 或反复 auto-restart

Python 可能尚未开始运行。先看 systemd 指出的具体路径，不能只凭状态码确定原因：

```bash
sudo journalctl -u ca-admin -b -n 50 --no-pager
```

```bash
sudo systemctl cat ca-admin
```

```bash
ls -ld /opt/ca-dev /opt/ca-dev/data /etc/swanctl
```

新版只支持在 `/opt` 下部署正式服务，保留 `ProtectHome=yes` 和 `ProtectSystem=strict`，不再绑定被隐藏的家目录，也不使用 `/home/*/.ssh` 这类不受支持的伪通配路径。`/etc/swanctl` 是必需目录，在安装前检查。不要关闭整个沙箱，也不要反复重装 pip 来处理命名空间故障。

### Address already in use / 端口占用

```bash
sudo ss -ltnp '( sport = :9443 )'
```

不要同时运行 `./run.sh` 和 systemd 服务。也可以重新安装时追加 `--port 9444`，并同步修改访问地址与 SSH 转发端口。

## 7. 已有安装与从下载目录迁移

已经有真实 CA 数据时，先备份，不能按“全新安装”覆盖数据。升级包只包含代码，不包含你的 `.venv`、`data` 和数据库；本公开版沿用示例组织名，现网迁移前仍须核对文件名/发布目标。

如果服务曾在 Downloads 下失败，但还没有创建 CA，可保留旧目录，按前面的全新安装步骤在 `/opt/ca-dev` 建新实例。先停止失败服务：

```bash
sudo systemctl stop ca-admin
```

如果 Downloads 下已有需要保留的 CA，请先在**旧项目目录**执行备份：

```bash
sudo .venv/bin/python -m backend.cli backup --name before-opt-move
```

将备份复制到旧目录之外妥善保存。不要移动旧 `.venv` 或直接改数据库内的发布路径。先在 `/opt/ca-dev` 安装新版，再按项目 `backup --restore` 流程恢复备份；恢复后必须核对发布目标、账号和 `crl-info`。恢复真实 CA 会关联真实发布任务，应安排维护窗口。

已有 `/opt/ca-dev` 的 root 部署：先把新源码解压到另一个目录，例如 `/tmp/ca-dev-update/ca-dev-github-public`，然后从旧项目运行：

在下载 ZIP 所在目录执行（该临时目录应尚不存在；若已存在，另选一个目录名）：

```bash
unzip ca-dev-github-public.zip -d /tmp/ca-dev-update
```

```bash
cd /tmp/ca-dev-update/ca-dev-github-public
```

```bash
sha256sum -c SHA256SUMS
```

```bash
cd /opt/ca-dev
```

```bash
sudo ./deploy/upgrade.sh --dry-run --code /tmp/ca-dev-update/ca-dev-github-public --loopback
```

```bash
sudo ./deploy/upgrade.sh --code /tmp/ca-dev-update/ca-dev-github-public --loopback
```

旧脚本执行升级时不会自动获得新版脚本的启动验收逻辑。代码替换后再运行新版安装，修复单元并完成验收；保留升级前备份。

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

如果使用非默认端口、外置数据目录或自定义 strongSwan 单元，重跑安装必须继续传入原来的 `--port`、`--data-dir`、`--strongswan-service`。已有数据库中的自定义 CRL 重载命令会保留，需另行核对；参数仅用于检查服务和首次初始化的默认值。

## 8. 自动测试的边界

```bash
cd /opt/ca-dev
```

```bash
sudo ./tests/run_all.sh
```

测试使用临时数据和测试 CA，systemd/strongSwan 写操作使用桩；不会替代本指南的真实服务、VICI 和 VPN 客户端验收。前端 DOM 测试依赖 Node.js + jsdom，缺少时会跳过；“跳过”不等于已验证。新增加的安装测试覆盖缺 pip、损坏虚拟环境、无效参数、pip 失败保留数据、只读预览、单元转义及启动失败判定。

## 非 root 系统服务（高级）

推荐流程仍为 root + systemd 沙箱。如果选非 root 服务，事先创建专用账号，使用 `--systemd-unprivileged --user caadmin`；安装脚本本身仍须 sudo。源码须 root 所有且账号可读取；数据目录归服务账号且为 0700，root 同步服务负责写 `/etc/swanctl`。只有此模式启用同步 path，`--with-timer` 为可选兜底。升级脚本不会自动把非 root 服务变成 root，请单独维护。

## 官方参考

- [strongSwan 安装与 swanctl/VICI](https://docs.strongswan.org/docs/latest/install/install.html)
- [swanctl --flush-certs](https://docs.strongswan.org/docs/latest/swanctl/swanctlFlushCerts.html)
- [systemd 文件系统沙箱](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
- [Python ensurepip](https://docs.python.org/3/library/ensurepip.html)
- [pip 配置](https://pip.pypa.io/en/stable/topics/configuration/)
- [清华 PyPI 镜像](https://mirrors.tuna.tsinghua.edu.cn/help/pypi/)
