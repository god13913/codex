# Codex + Mihomo：Windows 专属代理版

让 Codex CLI 和官方 ChatGPT Windows 桌面端使用一条独立代理，不改系统代理，也不让其他程序跟着走。

这是一个基于 [OpenAI Codex](https://github.com/openai/codex) 的非官方 Windows 分支。它会按需启动内置的 Mihomo，把 Codex 的服务请求交给你选定的节点；如果你还在使用官方 ChatGPT 桌面端，也可以让它共用同一条线路。

## 为什么做这个版本

我只想给 Codex 单独准备一条稳定线路，不想为了它一直开着全局代理或 TUN，也不希望浏览器、终端和其他软件被一起改路由。

这个分支解决的就是这一个问题。

## 它能做什么

- **Codex 专属代理**：模型请求、账户请求和登录刷新使用独立的 Mihomo 会话。
- **桌面端共用线路**：已登记的官方 `ChatGPT.exe` 可以和 Codex 使用同一个出口。
- **订阅与单节点导入**：支持兼容的 Mihomo / Clash 配置和受支持的单条分享链接，并保留有效缓存。
- **图形化配置**：可以新建、搜索、编辑、导入、导出和选择配置，也能查看当前 CLI 出口 IPv4。
- **尽量少动系统**：不修改系统代理、路由表、DNS 或 TUN；其他程序仍按原来的网络方式连接。
- **本地隔离**：Mihomo 的代理端口和控制端口只监听本机回环地址，并使用随机端口和独立认证信息。

桌面透明转发需要一次 Windows UAC 授权。取消授权不会影响 Codex CLI 的专属代理，只是桌面端不会被接入。

## 开始使用

### 用图形界面配置

1. 前往 [Releases](https://github.com/god13913/codex/releases) 下载最新的 `CodexProxySetup.exe`。
2. 打开配置工具；如果需要桌面端共用线路，选择电脑上已经安装的官方 `ChatGPT.exe`。
3. 导入订阅、配置文件或分享链接，选中要使用的出口并保存。
4. 启动 Codex。桌面转发首次启用时，Windows 会显示 UAC 提示。

配置工具不会替换或修改官方 ChatGPT 的安装文件。

### 只用命令行

如果订阅 URL 已经在剪贴板中，可以通过标准输入配置，避免把地址留在命令历史里：

```powershell
Get-Clipboard | .\codex.exe proxy configure --stdin
.\codex.exe proxy status
```

`proxy status` 只显示脱敏后的状态。需要立即更新缓存时，可以运行：

```powershell
.\codex.exe proxy refresh
```

桌面端接入、`CODEX_CLI_PATH` 和恢复方法见 [专属代理使用说明](docs/dedicated-proxy.md)。

## 使用前要知道

- 当前版本面向 **Windows x64**。
- 你需要自行准备可用的订阅、节点或分享链接。
- 只会接管你登记的官方 ChatGPT 桌面版，其他程序不会跟着走。
- 支持 UDP 的节点可以正常处理桌面版的 QUIC、语音等连接；节点不支持 UDP 时，这类连接会被拒绝，应用如果支持就会自行改用 TCP。系统里其他程序的 UDP 不会受到影响。
- 官方桌面版更新到新目录后，先完全退出桌面版，再重新打开即可。服务会在启动时自动寻找新的安装目录，不需要你再次手动指定，也不会一直在后台扫描。
- 不会修改 TLS 证书校验、系统代理或系统 DNS，也不会在服务器上创建公开代理。
- 这是非官方分支，账号、节点和桌面版本不同都可能影响实际效果。第一次使用时建议保留原来的 Codex 安装方式，方便随时切回。

## 更多资料

- [专属代理的工作方式与配置](docs/dedicated-proxy.md)
- [配置界面说明](web-preview/README.md)
- [Windows 构建与发布](docs/windows-release.md)
- [下载构建物与安装包](https://github.com/god13913/codex/releases)
- [OpenAI Codex 官方仓库](https://github.com/openai/codex)

## 许可证

Codex 源码沿用 [Apache-2.0](LICENSE)。随发行包提供的 Mihomo、ProxyBridge 和 WinDivert 保留各自的许可证与来源说明。

这个项目与 OpenAI、MetaCubeX 没有隶属或官方合作关系。

本 README 由 OpenAI Codex 编写。
