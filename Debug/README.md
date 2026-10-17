# Debug 测试目录

这里集中放置本项目专用的调试和回归测试脚本。目录只包含源码、测试脚本和测试项目，**不包含**构建日志、运行状态、用户配置、订阅、节点、令牌、对话记录或 `.workbuddy` 数据。

## 内容

- `PowerShell/`：桌面代理、父进程退出、ProxyBridge 传输和服务防火墙的 Windows PowerShell 5.1 测试。
- `Python/`：服务入口和本机回环代理测试。
- `ProxyBridgeTests/`：ProxyBridge 的域名、TCP、UDP 和内核策略测试源文件。
- `RuntimeModeChecks/`：配置器运行模式的 .NET 检查程序源码。

对应的产品源码仍在仓库原本的位置：

- Rust：`codex-rs/`
- C# 配置器：`configurator/`
- WebView2 前端：`web-preview/`
- ProxyBridge C 源码：`third_party/proxybridge/`

## 从新克隆的仓库开始

在仓库根目录执行。Windows 脚本使用 Windows PowerShell 5.1 兼容语法：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Debug\PowerShell\test-service-relay-firewall.ps1
python .\Debug\Python\test-dedicated-service-entrypoints.py --help
```

需要真实二进制的测试必须显式传入本地构建产物路径，例如：

```powershell
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Debug\PowerShell\test-dedicated-app-server.ps1 -CodexPath 'D:\path\to\codex.exe'
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File .\Debug\PowerShell\test-dedicated-proxy-parent-exit.ps1 -AdminPath 'D:\path\to\codex-proxy-admin.exe'
```

测试输出应写入仓库外的临时目录；不要把输出目录、`.log`、JSON 状态文件或用户配置复制回仓库。完整安装器构建需要先生成 `web-preview/dist`，再按 `docs/dedicated-proxy.md` 准备固定版本的 Rust、Mihomo、WinDivert 和 Windows SDK。

## 发布边界

Git 仓库只保存可审查的源码和测试输入。`CodexProxySetup.exe`、`runtime.zip`、`notices.zip` 等二进制发布物不提交到 Git 历史，而是作为 GitHub Release 资源上传；日志、对话和 `.workbuddy` 永远不上传。
