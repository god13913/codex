# Windows 定制版构建与发布

本分支包含 Rust 运行时、C# 配置器、WebView2 前端、ProxyBridge 原生组件和专用测试源码。`Debug/` 是唯一集中放置本项目调试/回归测试的目录；构建日志、运行状态、用户配置、订阅、节点、令牌、对话记录和 `.workbuddy` 数据不进入 Git。

## 目录和交付边界

- `codex-rs/`：Rust CLI、专用代理和服务源码。
- `configurator/`：C# Windows 配置器源码，项目文件为 `configurator/CodexProxySetup.csproj`。
- `web-preview/`：配置器内嵌的 WebView2 前端源码。
- `third_party/proxybridge/`：ProxyBridge C 源码和测试输入。
- `scripts/`：构建和桌面路径登记脚本。Windows PowerShell 脚本按 Windows PowerShell 5.1 兼容语法维护。
- `build-tools/PublicPackager/`：把已验证的运行时文件生成 `runtime.zip`、清单和许可证包。
- `build-tools/PublicAudit/`：检查安装器、内嵌资源、运行时哈希和私密指纹。
- `Debug/`：测试脚本和测试项目，详见 `Debug/README.md`。

Git 只保存可审查的源码和测试输入。`CodexProxySetup.exe`、`runtime.zip`、`notices.zip` 等大文件通过 GitHub Release 资源分发，不提交到 Git 历史。Release 资源中也不包含订阅、节点、登录状态、用户配置、对话、日志或 `.workbuddy` 数据。

## 构建前提

目标环境是 Windows x64。需要：

- Windows PowerShell 5.1（不要用 PowerShell 7 验证构建脚本兼容性）。
- Rust 1.95.0、Visual Studio C++ 工具链、Windows SDK、.NET 8 SDK 和 Node.js。
- 固定版本的 Mihomo 1.19.32、WinDivert 2.2.2 以及 `rg.exe`。脚本会校验固定 SHA-256；不要用未校验的替代文件。
- 工作区父目录中的 `.toolchain/` 和 `third-party/` 材料。构建脚本从仓库父目录寻找它们，因此建议保持如下布局：

```text
工作区/
├─ .toolchain/
├─ third-party/
└─ codex-publish/       # 本仓库
```

不要把 `.toolchain/`、私有配置或用户目录复制到仓库。缺少固定材料时应先补齐材料，不要把本机路径写进源码。

## 从新克隆开始

```powershell
git clone https://github.com/god13913/codex.git codex-publish
Set-Location .\codex-publish

# 前端依赖和构建产物
npm.cmd --prefix .\web-preview ci
npm.cmd --prefix .\web-preview run build

# 先做快速 Rust 检查；该命令使用 Windows PowerShell 5.1
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-dedicated-proxy.ps1 `
  -Stage Check -TargetDirectory ..\runtime\compile-target
```

`Check` 不生成安装器。日常迭代优先使用 `Check`、`Test` 或 `Dev`，保留 `TargetDirectory` 以复用 Cargo 缓存；不要为了普通改动删除缓存，也不要使用 `-FreshBuild`。

## 生成运行时和安装器

以下 `$repo`、`$core` 和 `$rg` 必须替换为本机实际路径；`$core` 是已通过固定哈希校验的 Mihomo，`$rg` 是外部提供的 `rg.exe`，不能指向仓库的输出目录。

```powershell
$repo = (Get-Location).Path
$target = Join-Path (Split-Path $repo -Parent) 'runtime\compile-target'
$runtime = Join-Path (Split-Path $repo -Parent) 'runtime\public-runtime'
$core = 'D:\trusted-materials\mihomo-1.19.32\mihomo.exe'
$rg = 'D:\trusted-materials\rg.exe'

# Release 会重新链接全部发布机器码，但会复用 $target 中的 Cargo 缓存。
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass `
  -File "$repo\scripts\build-dedicated-proxy.ps1" `
  -Stage Release -DesktopOnly -BuildJobs 4 `
  -CorePath $core -RgPath $rg `
  -TargetDirectory $target -OutputDirectory $runtime

# 生成 runtime.zip、runtime-manifest.json 和 notices.zip。
dotnet run --project "$repo\build-tools\PublicPackager\PublicPackager.csproj" `
  -c Release -- "$repo" "$runtime"

# 只改 C# 时无需重新编译 Rust；只需确保 Assets 中已有上一步生成的资源。
dotnet publish "$repo\configurator\CodexProxySetup.csproj" `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -o "$repo\runtime\installer-publish"
```

前端源码有改动时，先重新运行 `npm.cmd --prefix "$repo\web-preview" run build`；只改 C# 时不需要重复前端构建。安装器项目会把 `web-preview/dist/index.html`、`configurator/Assets/runtime.zip`、`runtime-manifest.json` 和 `notices.zip` 内嵌到单文件 EXE。

## 发布前审计

`PublicAudit` 要求审计目录中只能有待审计的一个 EXE。因此不要直接把含有其他文件的 `installer-publish` 目录作为审计目录：

```powershell
$audit = Join-Path (Split-Path $repo -Parent) 'runtime\audit-tmp'
New-Item -ItemType Directory -Path $audit -Force | Out-Null
Copy-Item "$repo\runtime\installer-publish\CodexProxySetup.exe" "$audit\CodexProxySetup.exe" -Force

dotnet run --project "$repo\build-tools\PublicAudit\PublicAudit.csproj" `
  -c Release -- "$repo" "$audit\CodexProxySetup.exe"
```

只有审计通过后，才把 EXE 复制为发布文件名：

```powershell
$release = Join-Path (Split-Path $repo -Parent) 'release'
New-Item -ItemType Directory -Path $release -Force | Out-Null
Copy-Item "$audit\CodexProxySetup.exe" "$release\CodexProxySetup.exe" -Force
Get-FileHash "$release\CodexProxySetup.exe" -Algorithm SHA256
```

审计通过只能证明安装器结构、内嵌资源、运行时哈希和公开包私密指纹符合要求；它不等于已验证真实桌面会话、账户请求或 QUIC 数据面。真实桌面验证应在用户授权的全新桌面重启后进行。

## C# 配置器的快速迭代

只修改 `configurator/` 下的 C# 文件时，不需要重新编译 Rust：

```powershell
dotnet publish .\configurator\CodexProxySetup.csproj `
  -c Release -r win-x64 --self-contained true `
  -p:PublishSingleFile=true -o .\runtime\installer-publish
```

如果配置器仍在运行并锁定旧 EXE，请先退出配置器，再替换 `release/CodexProxySetup.exe`。不需要按名称强制结束其他进程，也不要覆盖 GitHub 上的旧 Release 资源；新版本使用新的 tag。

## 测试

测试入口和说明集中在 `Debug/README.md`。不依赖真实二进制的测试可以直接运行；需要桌面或运行时 EXE 的测试必须显式传入本机路径。测试输出应放在仓库外的临时目录，不能把 `.log`、JSON 状态文件、订阅或用户配置复制回仓库。

正式 Release 至少应记录以下结果：前端构建成功、Rust Release 构建成功、`runtime.zip` 清单与文件哈希一致、`notices.zip` 可读、单文件 EXE 为有效 Windows PE、`PublicAudit` 通过且私密指纹命中为 0。
