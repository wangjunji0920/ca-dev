# /opt + swanctl + SSH 隧道部署

安装、升级、pip 修复、systemd 排错及验收的唯一完整流程见 [QUICKSTART.md](QUICKSTART.md)。正式代码放在 `/opt/ca-dev`，不要在 Downloads 或其他家目录直接注册服务。

服务器完成 swanctl 前置配置后，在 `/opt/ca-dev` 执行：

```bash
sudo ./deploy/install.sh --systemd --loopback --pip-mirror tsinghua
```

```bash
sudo systemctl is-active ca-admin
```

```bash
sudo ss -ltnp '( sport = :9443 )'
```

应为 `active`，并只监听 `127.0.0.1:9443`。

宿主机/手机终端执行（替换 SSH 用户与地址）：

```bash
ssh -N -o ExitOnForwardFailure=yes -L 9443:127.0.0.1:9443 user@vm-address
```

浏览器打开 `http://127.0.0.1:9443/`。隧道存续期间才可访问；关闭隧道不会停止服务器上的 CA 管理服务或 CRL 自动化。首次指纹核对不能保护以后经公网明文 HTTP 下载的网页脚本；远程管理始终需要 SSH 或经过验证的 TLS。

本机 9443 被占用时，可只改本地转发端口：

```bash
ssh -N -o ExitOnForwardFailure=yes -L 9444:127.0.0.1:9443 user@vm-address
```

此时浏览器地址为 `http://127.0.0.1:9444/`，服务器仍监听 9443。
