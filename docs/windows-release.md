# Windows 定制版构建与发布

此分支从 OpenAI Codex 提交 `c1382380de69521303b416720a52f42d51af6248` 衍生。定制源码位于 `codex-rs/dedicated-proxy`、相关 Rust 模块、`scripts`、`configurator`、`web-preview` 和 `build-tools`。根目录 `LICENSE` 保留官方 Apache-2.0；`third_party/proxybridge/LICENSE` 与发行包中的 Mihomo、WinDivert 许可证分别适用于这些组件。

## 构建前提

- Windows x64、Rust 1.95.0、Visual Studio C++ 工具链、.NET 8 SDK 和 Node.js。
- 构建脚本在仓库的父目录寻找 `.toolchain` 与 `third-party` 固定版本材料；`-CorePath` 指向 SHA-256 与脚本内固定值相符的 Mihomo 1.19.32 可执行文件。
- `-TargetDirectory` 应是全新的空目录。不要把 `CODEX_HOME/dedicated-proxy` 中的订阅、节点、令牌或桌面注册文件加入仓库或发布包。

## 生成构建物

在 PowerShell 中，将 `$repo` 设置为仓库根目录，将 `$target` 设置为空构建目录，将 `$core` 设置为固定版本 Mihomo 路径：

```powershell
& "$repo/scripts/build-dedicated-proxy.ps1" -Stage Release -FreshBuild -CorePath $core -TargetDirectory $target -OutputDirectory "$repo/runtime/public-runtime"
npm --prefix "$repo/web-preview" ci
npm --prefix "$repo/web-preview" run build
dotnet run --project "$repo/build-tools/PublicPackager/PublicPackager.csproj" -- $repo "$target/release"
dotnet publish "$repo/configurator/CodexProxySetup.csproj" -c Release -r win-x64 -o "$repo/release"
dotnet run --project "$repo/build-tools/PublicAudit/PublicAudit.csproj" -- $repo "$repo/release/CodexProxySetup.exe"
```

`PublicPackager` 比对已编译二进制与待打包文件，生成仅含必需运行时组件的 `runtime.zip`、清单和许可证归档。`PublicAudit` 校验程序集、内嵌资源、运行时哈希，并扫描私有配置指纹。只有审计通过的安装包才应作为 Release 附件。发布附件应包含安装包、独立运行时 ZIP、许可证归档、运行时清单和对应的 SHA-256 文件；较大的二进制放在 GitHub Release，避免加入 Git 历史。

## 本次交付的验证边界

2026-10-11 的 Windows 构建记录显示编译成功，运行时目录的 25 条 SHA-256 清单全部匹配。重新生成的安装包通过 `PublicAudit`，扫描 1,132 个解包文件，私有指纹命中数为 0。该构建没有运行单元测试，也未验证账户登录、模型请求或桌面透明转发的实际网络流量。