# Codex 代理配置界面

此目录是 `CodexProxySetup.exe` 的 Material 3 界面源码。构建产出的单文件 `dist/index.html` 会作为资源嵌入安装程序；也可独立打开预览布局。

## 打开

运行 `npm install` 和 `npm run build` 后，双击 `dist/index.html` 即可在桌面浏览器打开。构建脚本把 JavaScript、样式与 Material Symbols Rounded 字体嵌入同一个 HTML 文件，不依赖本地 Web 服务。

## 预览中的实际功能

- 首次进入时选择 `ChatGPT.exe` 或填写以该文件名结尾的路径；浏览器记住选择。
- 新建、搜索、编辑、删除、导出 Clash 订阅和 VPS 节点配置。
- 获取允许跨域访问的 HTTPS 订阅，或导入 Clash YAML / JSON / 分享链接文件和剪贴板节点。
- 选择一个出口，保存或停用浏览器本地配置；数据使用 IndexedDB 持久化，无法使用时退回 localStorage。
- “当前 CLI 出口 IPv4”默认以 `********` 遮罩；EXE 只在检测到正在运行的 CLI 专属代理会话时，通过该代理查询 IPinfo。浏览器独立打开时不会拿浏览器出口冒充 CLI 出口。
- 配置工作区上缘可以上下拖动：向上收起配置来源与出口 IPv4 区域，向下重新展开；也支持方向键和双击展开，状态保存在浏览器中。
- 已保存配置列表的分隔条可拖到左边缘收起列表，再向右拖动展开；窄屏和停靠布局则改为上下拖动。收起后把手仍可操作，状态同样保存在浏览器中。
- 跟随系统浅色/深色模式；可手动切换。浏览器支持 `AccentColor` 时以它生成动态 Material 配色，否则使用指定的 Purple 方案。

独立浏览器预览使用 IndexedDB 或 localStorage，不能扫描本机软件、验证 Windows 数字签名或配置正式 CLI。嵌入 EXE 后，`ConfiguratorBridge` 接管订阅下载、文件选择、配置保存、停用代理和出口 IP 查询；界面配置写入当前用户的 `CODEX_HOME/dedicated-proxy/ui-state.json`（默认位于用户目录的 `.codex`），由 Windows DPAPI 加密。设置窗口的“许可证显示”展示 `configurator/Assets/notices.zip` 中的许可文本。
