# Codex CLI 与原安装桌面共用专属代理

本版本保留原安装的官方 `ChatGPT.exe`、`app.asar` 和 `chrome.dll`。安装器提供 Windows 常驻服务及不安装服务两种方式，两者共用 UDP 转发修复和禁止 UDP 隐式直连的规则。

## 安装器的两种启动方式

在 `CodexProxySetup.exe` 的“代理启动方式”中选择后，点击“保存并配置”：

1. **安装 Windows 后台服务（推荐）**：完全退出桌面，以配置时同一账户允许一次管理员提示。安装器从内嵌资源校验并提取服务到新的 Program Files 目录，等待转发、内核和防火墙就绪，再选择对应 CLI。系统启动时服务自动运行。
2. **不安装服务，由桌面启动转发**：运行时放在当前用户目录。完全重开桌面并允许转发组件的管理员提示；转发组件随桌面会话运行，不常驻 Windows 服务。若此前存在当前账户的服务，切换时需退出桌面并授权移除服务。

两种方式都为支持 UDP 的节点启用 UDP，均使用 `MATCH,CODEX` 后接 `MATCH,REJECT`，不关闭 QUIC。无服务模式的转发在桌面后端启动后才建立，因此不能保证早于桌面首次请求；UDP 修复并不依赖安装服务。某节点不支持 UDP 时会拒绝该流量，是否回落 TCP 由应用决定。

修改节点、端口、DNS 或官方桌面更新后，请重新保存配置。服务使用安装时所选节点的独立加密快照；重新保存会在新受保护目录准备快照，再切换服务，失败时尝试还原旧服务、CLI 和配置。保存或升级前须完全退出桌面。新版本校验、切换并确认服务就绪后，自动清理安装器标记且属于当前账户的旧运行时；成功后只保留当前模式的一份组件，不长期缓存每个版本。服务模式直接解压到受保护目录，不另留用户目录副本。更新过程仍需新旧两份的临时空间；旧文件被其他进程占用时提示保留，下次保存重试。清理拒绝目录链接和越界路径，不清理手动测试目录、未标记的历史目录或用户下载的安装包。停用代理会移除所属服务并清除 User/Process 的 CLI 覆盖，保留当前运行时文件。安装器不会自动结束或重启桌面，不修改系统代理和系统 DNS。

## 首次请求测试版：可选后台服务

`codex-proxy-service.exe` 是本项目的 Windows 服务，服务名为 `CodexDedicatedProxy`，以 LocalSystem 自动启动。转发规则覆盖未来启动的指定桌面和 CLI，并限定配置用户 SID。服务先安装转发规则，再启动并认证专用内核，最后向 Windows 报告 Running。启动期间到达的连接在本机等待，45 秒内未就绪则关闭，不释放为直连。服务自身未能启动、官方桌面更新路径或文件校验失败时，需要排查服务状态，不能把文件存在视为转发成功。

临时安装入口是本运行时目录内的 `manage-desktop-proxy-service.ps1`，由 Windows PowerShell 5.1 运行：

```powershell
# 完全退出桌面后，在管理员 PowerShell 中运行；不要以管理员身份运行桌面。
.\manage-desktop-proxy-service.ps1 -Action Install
# 查询或卸载。卸载会清除 CLI 覆盖并保留全部文件，完全重开桌面后生效。
.\manage-desktop-proxy-service.ps1 -Action Status
.\manage-desktop-proxy-service.ps1 -Action Uninstall
```

该脚本供手动诊断使用，安装器已集成相同服务的安装、切换和停用。本脚本默认将运行时复制到 Program Files 下，代码仅允许管理员和 SYSTEM 写入；服务的独立配置目录不允许普通用户读取。只复制当前选中节点，使用机器 DPAPI 加密，不复制 ChatGPT 登录或订阅历史。服务使用安装时的节点和设置快照；修改节点、密码或端口后需重新准备服务。旧目录不会覆盖或删除，再次测试应指定 Program Files 下的新安装目录。CLI 复用服务时同时核对 SCM、服务进程、内核身份和本机代理认证，不会仅凭端口开放就复用。

域名转发优先读取当前连接中可见的 TLS SNI 或 HTTP Host，保持应用字节不变；同时从已匹配 GPT/Codex 进程的 UDP/TCP DNS 回复学习缓存，核对事务、问题、CNAME、TTL。共享 IP 的多域名记录标记为歧义，不猜测域名。系统 DNS 服务、DoH 或应用缓存中无法观察到的解析不会凭空产生域名；没有可见域名时仍使用 IP。真正启用 ECH 时可见的可能只是外层路由名，并不代表解密了内层域名。

## 使用

将当前用户的 `CODEX_CLI_PATH` 设置成本目录下 `codex.exe` 的完整路径，完全退出后重新打开桌面。直接打开原来的官方桌面 EXE；未安装后台服务时允许转发进程的管理员提示。后台服务安装并就绪后由服务提前接管。不要把 `CODEX_CLI_PATH` 指向桌面 EXE。

管理员子进程只识别所属用户、登记的官方桌面路径与实际父进程。它把桌面与本包 CLI 的 TCP 80/443、进程自行发出的 TCP 53，以及出站 UDP 送入同一个专用 Mihomo。UDP 使用带认证的 SOCKS5 转发，覆盖 QUIC 443、语音 3478 和进程自行发出的 DNS 53。匹配的 UDP 转发失败时丢弃，允许应用自行回落 TCP，不释放为直连；节点不支持 UDP 时不能保证应用一定提供 TCP 回落。其他程序不匹配这些转发规则，Windows 系统 DNS 服务代发的查询保持现状。系统代理、DNS 设置、路由表和 TUN 不变。

不对整个 `codex.exe` 添加必须管理员运行的清单，因为普通权限的桌面需要通过标准输入输出启动 app-server。实际获得管理员权限的转发子进程仍是本包的 `codex.exe`，命令由 CLI 自动调用，不需要另外启动 GUI 或替换官方桌面入口。同一桌面进程会话最多请求一次 UAC；后端 app-server 重启时沿用已授权的转发进程，不会再次请求。完全关闭并重新打开桌面后会重新请求一次。桌面后端等待属于本次后端的转发就绪状态，超时或拒绝授权会报错停止，避免把尚未接管的状态报告为可用。独立 CLI 的显式服务代理无需管理员授权。

`codex cloud`、`codex exec-server --remote`、隐藏的 `codex responses-api-proxy` 和独立 `codex-responses-api-proxy.exe` 在服务客户端创建前取得代理生命周期。`codex app-server daemon` 与独立 `codex-app-server.exe` 同样保留原有接管能力。独立服务可以通过本机 SOCKS5 认证复用新版混合监听器；认证失败不回退到直连。桌面转发的内核默认由该桌面后端持有；安装并验证上述后台服务后可复用服务内核。独立服务占用相同端口时应使用单独端口。旧版仅 HTTP 监听器不支持这一复用认证，应与测试版使用不同端口。

## 订阅与恢复

订阅配置和经过校验的单节点缓存保存在当前 `CODEX_HOME/dedicated-proxy`。启动时先使用同一订阅的有效缓存，再通过已启动的代理后台刷新；没有缓存时才等待下载。失败刷新保留有效缓存。默认每 15 分钟刷新，失败后 30 秒重试；返回相同节点时不重复加载配置。

订阅可以是恰好一个节点的 Mihomo YAML 或受支持的单条分享链接。配置文件由当前用户和 SYSTEM 的 ACL 保护；不要把订阅地址、节点或密码放进命令行。通过 `codex.exe proxy configure --stdin` 导入，通过 `proxy status` 查看脱敏状态，通过 `proxy refresh` 更新缓存。

Mihomo 的 HTTP/SOCKS5 混合端口只监听回环，默认 35234，可在私有设置中覆盖；控制端口动态分配，两者使用各自认证信息。管理员转发进程从私有运行目录读取端口及凭据，不通过命令行传递密码。透明 TCP 中继使用独立动态端口，只有已登记的重定向连接可以使用。Mihomo 的 TLS/HTTP/QUIC 嗅探用于恢复透明连接的目标域名；未修改 TLS 证书校验。

专用代理策略会为支持 UDP 的节点尝试启用 UDP，并修正旧版本缓存中统一写入的 `udp: false`；HTTP 节点保持 TCP。内核规则必须同时包含 `MATCH,CODEX` 和末尾的 `MATCH,REJECT`：Mihomo 会跳过不支持 UDP 的匹配代理，没有后续规则时隐式直连，单独一个 MATCH 不能保证禁止直连。节点实际拒绝 UDP 时，请求会失败，应用可自行回落 TCP；不修改桌面的 QUIC、CSP 或 CORS 设置。

CLI 退出时关闭 Mihomo 并通知管理员转发进程停止；CLI 或桌面意外退出时，管理员子进程通过进程句柄检测退出并释放 WinDivert。未匹配的其他程序流量原样放行。管理员转发状态保存在 `dedicated-proxy/desktop-forwarding-status.json`，不记录目标地址或认证头。

官方桌面升级后，运行本目录的 `configure-desktop-forwarding.ps1 -DistributionDirectory 本目录` 更新官方 EXE 路径及哈希登记。该脚本不会修改桌面安装文件。

## 构建与交付

使用工作区 Rust 1.95.0、VS C++ 工具链和固定的 Mihomo 1.19.32、WinDivert 2.2.2 驱动。工作区入口 `runtime/build-dedicated-runtime-with-progress.ps1` 由 Windows PowerShell 5.1 执行。迭代使用 `-Stage Check`、`-Stage Test`；需要试运行时使用 `-Stage Dev -RuntimeOnly -OutputDirectory 新测试目录`，复用 D 盘固定编译缓存，保留旧产物。正式安装器使用默认 Release 流程；Dev 不生成或覆盖安装器。默认 DesktopOnly 已包含本项目的 `codex-proxy-service.exe` 后台转发服务。只有需要独立 `codex-app-server.exe` 或 `codex-responses-api-proxy.exe` 时才使用 `-FullRuntime`；这两个独立二进制不加入默认桌面安装包。

交付包含 Codex Apache-2.0、Mihomo GPL-3.0、ProxyBridge MIT 和 WinDivert LGPLv3 许可证，以及相应第三方源码。驱动使用已签名的官方发行文件，构建与运行前校验固定哈希；不会关闭 Windows 驱动签名强制。

## 验证范围

本机模拟服务测试验证认证、连接分段、TCP 半关闭、UDP 多连接隔离及失败丢弃。可选固定 Mihomo 测试只使用本机模拟上游，不加载驱动。编译、静态产物检查和本机协议测试不能代替重启后的桌面路径、真实 Chat/DIL 回复及 QUIC/语音验收。
