# Codex CLI 与原安装桌面共用专属代理

本版本保留原安装的官方 `ChatGPT.exe`、`app.asar` 和 `chrome.dll`。当官方桌面通过 `CODEX_CLI_PATH` 选择本包的 `codex.exe` 时，CLI 启动内嵌的 Mihomo，并自动通过 Windows UAC 启动同一 CLI 的隐藏管理员转发子进程。桌面窗口可以先打开；无需提前手动启动 Mihomo 或 Clash。

## 使用

将当前用户的 `CODEX_CLI_PATH` 设置成本目录下 `codex.exe` 的完整路径，然后重新登录 Windows。直接打开原来的官方桌面 EXE，并允许管理员提示。不要把 `CODEX_CLI_PATH` 指向桌面 EXE。

管理员子进程只识别所属用户、登记的官方桌面路径与实际父进程。它把桌面的 TCP 80/443 请求送到该 app-server 管理的同一个 Mihomo 端口。CLI 的模型、账户、登录刷新和服务请求仍使用现有专属 HTTP 客户端。桌面的 UDP 443 被阻断以让 QUIC 回退到 TCP；其他程序不匹配转发规则。任意用户 HTTP 工具、终端、系统代理、路由表、DNS 和 TUN 保持原来的策略。

不对整个 `codex.exe` 添加必须管理员运行的清单，因为普通权限的桌面需要通过标准输入输出启动 app-server。实际获得管理员权限的转发子进程仍是本包的 `codex.exe`，命令由 CLI 自动调用，不需要另外启动 GUI 或替换官方桌面入口。同一桌面进程会话最多请求一次 UAC；后端 app-server 重启时沿用已授权的转发进程，不会再次请求。完全关闭并重新打开桌面后会重新请求一次。取消后 CLI 服务代理仍可使用，但桌面透明转发不可用。

## 订阅与恢复

订阅配置和经过校验的单节点缓存保存在当前 `CODEX_HOME/dedicated-proxy`。启动时先使用同一订阅的有效缓存，再通过已启动的代理后台刷新；没有缓存时才等待下载。失败刷新保留有效缓存。默认每 15 分钟刷新，失败后 30 秒重试；返回相同节点时不重复加载配置。

订阅可以是恰好一个节点的 Mihomo YAML 或受支持的单条分享链接。配置文件由当前用户和 SYSTEM 的 ACL 保护；不要把订阅地址、节点或密码放进命令行。通过 `codex.exe proxy configure --stdin` 导入，通过 `proxy status` 查看脱敏状态，通过 `proxy refresh` 更新缓存。

Mihomo 的 HTTP 和控制端口均随机分配并只监听回环，使用不同的随机认证信息。管理员转发进程从私有运行目录读取当前 HTTP 端口及凭据，不通过命令行传递密码。透明 TCP 中继使用独立动态端口，只有已登记的重定向连接可以使用；不创建服务器上的公开代理。Mihomo 的 TLS/HTTP 嗅探用于恢复透明连接的目标域名；未修改 TLS 证书校验。

CLI 退出时关闭 Mihomo 并通知管理员转发进程停止；CLI 或桌面意外退出时，管理员子进程通过进程句柄检测退出并释放 WinDivert。未匹配的其他程序流量原样放行。管理员转发状态保存在 `dedicated-proxy/desktop-forwarding-status.json`，不记录目标地址或认证头。

官方桌面升级后，运行本目录的 `configure-desktop-forwarding.ps1 -DistributionDirectory 本目录` 更新官方 EXE 路径及哈希登记。该脚本不会修改桌面安装文件。

## 构建与交付

使用工作区 Rust 1.95.0、VS C++ 工具链和固定的 Mihomo 1.19.32、WinDivert 2.2.2 驱动。`scripts/build-dedicated-proxy.ps1 -Stage Release -FreshBuild -TargetDirectory 全新目录 -OutputDirectory 交付目录` 全量编译 Rust 二进制与本地 C 转发库。FreshBuild 拒绝非空目标目录、禁用增量及编译包装器；旧缓存可以保留用于回退，不会用于本次编译。

交付包含 Codex Apache-2.0、Mihomo GPL-3.0、ProxyBridge MIT 和 WinDivert LGPLv3 许可证，以及相应第三方源码。驱动使用已签名的官方发行文件，构建与运行前校验固定哈希；不会关闭 Windows 驱动签名强制。

## 验证范围

本次按要求不运行测试、不启动新桌面、不加载驱动、不进行模型或账户网络探测。构建后的检查只涵盖编译退出码、文件齐全、SHA-256、驱动签名和配置结构。真实账户恢复、模型调用及透明转发效果留给用户验收。
