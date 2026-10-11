using System.Net;
using System.Text;
using System.Text.Json;
using System.Runtime.InteropServices;

namespace CodexProxySetup;

internal sealed class MainForm : Form
{
    private readonly Color accent = Color.FromArgb(38, 100, 220);
    private readonly TextBox subscription = new() { UseSystemPasswordChar = true, Dock = DockStyle.Fill, PlaceholderText = "粘贴你自己的 HTTPS Clash 订阅链接" };
    private readonly ComboBox nodes = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly Label status = new() { AutoSize = true, ForeColor = Color.FromArgb(74, 85, 104), Text = "添加订阅或节点，然后选择一个节点保存。" };
    private readonly Label count = new() { AutoSize = true, Text = "尚未添加节点" };
    private readonly Label desktopLabel = new() { AutoSize = true, Text = "正在查找官方桌面…" };
    private readonly ComboBox protocol = new() { DropDownStyle = ComboBoxStyle.DropDownList, Dock = DockStyle.Fill };
    private readonly Dictionary<string, TextBox> fields = new();
    private readonly NumericUpDown port = new() { Minimum = 1, Maximum = 65535, Value = 443, Dock = DockStyle.Fill };
    private readonly List<Button> actions = new();
    private string? sourceUrl;
    private string? desktop;
    private bool busy;

    internal MainForm()
    {
        Text = "Codex 代理配置";
        Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        Font = new Font("Microsoft YaHei UI", 10F);
        BackColor = Color.FromArgb(245, 247, 251);
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(880, 730);
        MinimumSize = new Size(820, 740);
        AutoScaleMode = AutoScaleMode.Dpi;
        var root = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), RowCount = 6, ColumnCount = 1 };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 86));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 54));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 48));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 36));
        Controls.Add(root);
        var header = new Panel { Dock = DockStyle.Fill };
        header.Controls.Add(new Label { Text = "配置一次，直接打开官方桌面", Font = new Font(Font.FontFamily, 18F, FontStyle.Bold), AutoSize = true, Location = new Point(0, 2), ForeColor = Color.FromArgb(24, 35, 56) });
        header.Controls.Add(new Label { Text = "使用自己的订阅或节点 · 只选择一个出口 · 凭据按当前 Windows 用户加密保存", AutoSize = true, Location = new Point(1, 43), ForeColor = Color.FromArgb(91, 105, 126) });
        root.Controls.Add(header, 0, 0);
        var tabs = new TabControl { Dock = DockStyle.Fill, Padding = new Point(18, 8) };
        tabs.TabPages.Add(BuildSubscriptionTab());
        tabs.TabPages.Add(BuildManualTab());
        root.Controls.Add(tabs, 0, 1);
        var selection = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 3, Padding = new Padding(0, 10, 0, 0) };
        selection.RowStyles.Add(new RowStyle(SizeType.Absolute, 23));
        selection.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));
        selection.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));
        selection.Controls.Add(new Label { Text = "选择以后使用的节点", AutoSize = true }, 0, 0);
        selection.Controls.Add(nodes, 0, 1);
        selection.Controls.Add(count, 0, 2);
        root.Controls.Add(selection, 0, 2);
        var buttons = new FlowLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(0, 8, 0, 0), WrapContents = false };
        var save = Button("保存并一键配置", async () => await ApplyAsync(), 172);
        save.BackColor = accent; save.ForeColor = Color.White; save.FlatAppearance.BorderSize = 0;
        buttons.Controls.Add(save);
        buttons.Controls.Add(Button("打开官方桌面", async () => { await OpenDesktopAsync(); }, 148));
        buttons.Controls.Add(Button("选择桌面文件", async () => { ChooseDesktop(); await Task.CompletedTask; }, 148));
        buttons.Controls.Add(Button("停用专属代理", async () => { Disable(); await Task.CompletedTask; }, 148));
        root.Controls.Add(buttons, 0, 3);
        var messages = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 2, ColumnCount = 1 };
        messages.Controls.Add(status, 0, 0); messages.Controls.Add(desktopLabel, 0, 1);
        root.Controls.Add(messages, 0, 4);
        var footer = new FlowLayoutPanel { Dock = DockStyle.Fill };
        var licenses = new LinkLabel { Text = "许可与源码", AutoSize = true, Margin = new Padding(0, 5, 24, 0) };
        licenses.LinkClicked += (_, _) => ShowLicenses();
        footer.Controls.Add(licenses);
        footer.Controls.Add(new Label { Text = "桌面升级后请重新保存配置；转发时请允许管理员提示。", AutoSize = true, ForeColor = Color.FromArgb(91, 105, 126), Margin = new Padding(0, 5, 0, 0) });
        root.Controls.Add(footer, 0, 5);
        Shown += (_, _) => LoadExisting();
        FormClosing += (_, e) => { if (busy) { e.Cancel = true; SetStatus("操作进行中，请等待完成。", false); } };
    }

    private TabPage BuildSubscriptionTab()
    {
        var page = new TabPage("Clash 订阅") { BackColor = Color.White, Padding = new Padding(18) };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 6, ColumnCount = 1 };
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 31));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 35));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 31));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));
        layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 68));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.Controls.Add(new Label { Text = "订阅链接", AutoSize = true }, 0, 0);
        layout.Controls.Add(subscription, 0, 1);
        var show = new CheckBox { Text = "显示链接", AutoSize = true };
        show.CheckedChanged += (_, _) => subscription.UseSystemPasswordChar = !show.Checked;
        layout.Controls.Add(show, 0, 2);
        var controls = new FlowLayoutPanel { Dock = DockStyle.Fill, WrapContents = false };
        controls.Controls.Add(Button("获取 / 刷新节点", FetchAsync, 156));
        controls.Controls.Add(Button("导入 Clash 文件", ImportFileAsync, 148));
        controls.Controls.Add(Button("导入剪贴板节点", ImportClipboardAsync, 164));
        layout.Controls.Add(controls, 0, 3);
        layout.Controls.Add(new Label { Text = "订阅有多个节点时，请在下方选择一个。以后自动刷新会继续使用所选节点。\r\n选定节点消失时保留有效缓存，重新打开配置器可改选。文件和剪贴板导入作为固定节点保存。", AutoSize = true, MaximumSize = new Size(760, 0), ForeColor = Color.FromArgb(91, 105, 126) }, 0, 4);
        layout.Controls.Add(new Label { Text = "支持 Clash YAML，以及常见节点分享订阅。每个人都使用自己的链接和凭据。", AutoSize = true, ForeColor = Color.FromArgb(91, 105, 126) }, 0, 5);
        page.Controls.Add(layout);
        return page;
    }

    private TabPage BuildManualTab()
    {
        var page = new TabPage("手动配置 VPS / 节点") { BackColor = Color.White, Padding = new Padding(18) };
        var table = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 4, RowCount = 7 };
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 108));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 112));
        table.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        for (var i = 0; i < 6; i++) table.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));
        table.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        protocol.Items.AddRange(new object[] { "Trojan + TLS", "Trojan + WebSocket + TLS", "VLESS + WebSocket + TLS", "VLESS + Reality", "Shadowsocks", "VMess + WebSocket + TLS" });
        protocol.SelectedIndex = 0;
        AddField(table, "协议", protocol, 0, 0);
        AddField(table, "节点名称", Field("name", "自定义节点"), 2, 0);
        AddField(table, "服务器地址", Field("server"), 0, 1);
        AddField(table, "端口", port, 2, 1);
        AddField(table, "密码 / UUID", Field("credential", "", true), 0, 2);
        AddField(table, "TLS 域名", Field("sni"), 2, 2);
        AddField(table, "WS 路径", Field("path", "/"), 0, 3);
        AddField(table, "WS Host", Field("host"), 2, 3);
        AddField(table, "Reality 公钥", Field("publicKey"), 0, 4);
        AddField(table, "Short ID", Field("shortId"), 2, 4);
        AddField(table, "SS 加密方式", Field("cipher", "aes-128-gcm"), 0, 5);
        var show = new CheckBox { Text = "显示密码 / UUID", AutoSize = true };
        show.CheckedChanged += (_, _) => fields["credential"].UseSystemPasswordChar = !show.Checked;
        table.Controls.Add(show, 2, 5); table.SetColumnSpan(show, 2);
        var bottom = new FlowLayoutPanel { Dock = DockStyle.Fill };
        bottom.Controls.Add(Button("使用这个节点", async () => { AddManualNode(); await Task.CompletedTask; }, 160));
        bottom.Controls.Add(new Label { Text = "按协议填写对应项目；TLS 域名为空时使用服务器地址。", AutoSize = true, Margin = new Padding(12, 12, 0, 0), ForeColor = Color.FromArgb(91, 105, 126) });
        table.Controls.Add(bottom, 0, 6); table.SetColumnSpan(bottom, 4);
        protocol.SelectedIndexChanged += (_, _) => UpdateManualFields();
        UpdateManualFields();
        page.Controls.Add(table);
        return page;
    }

    private TextBox Field(string key, string value = "", bool secret = false)
    {
        var field = new TextBox { Text = value, UseSystemPasswordChar = secret, Dock = DockStyle.Fill };
        fields[key] = field; return field;
    }
    private static void AddField(TableLayoutPanel table, string label, Control control, int column, int row)
    {
        table.Controls.Add(new Label { Text = label, AutoSize = true, Anchor = AnchorStyles.Left }, column, row);
        table.Controls.Add(control, column + 1, row);
    }
    private Button Button(string text, Func<Task> action, int width)
    {
        var button = new Button { Text = text, Width = width, Height = 36, FlatStyle = FlatStyle.Flat, BackColor = Color.White, Margin = new Padding(0, 0, 10, 0), Cursor = Cursors.Hand };
        button.FlatAppearance.BorderColor = Color.FromArgb(210, 219, 232);
        button.Click += async (_, _) =>
        {
            if (busy) return;
            try { await action(); }
            catch (InvalidOperationException error) { SetStatus(error.Message, true); }
            catch { SetStatus("操作失败。请检查网络、文件访问权限和官方桌面是否已安装。", true); }
        };
        actions.Add(button); return button;
    }
    private void SetStatus(string text, bool error)
    { status.Text = text; status.ForeColor = error ? Color.FromArgb(176, 44, 44) : Color.FromArgb(47, 93, 72); }
    private void SetBusy(bool value)
    { busy = value; foreach (var action in actions) action.Enabled = !value; nodes.Enabled = !value; UseWaitCursor = value; }
    private void UpdateManualFields()
    {
        var ws = protocol.SelectedIndex is 1 or 2 or 5;
        fields["path"].Enabled = fields["host"].Enabled = ws;
        fields["publicKey"].Enabled = fields["shortId"].Enabled = protocol.SelectedIndex == 3;
        fields["cipher"].Enabled = protocol.SelectedIndex == 4;
        fields["sni"].Enabled = protocol.SelectedIndex != 4;
    }
    private NodeItem? Selected => nodes.SelectedItem as NodeItem;
    private void SetNodes(List<NodeItem> items, string? url, string? preferredId = null, string? preferredName = null)
    {
        sourceUrl = url; nodes.Items.Clear(); nodes.Items.AddRange(items.Cast<object>().ToArray());
        var selected = items.FindIndex(item => preferredId is not null && item.Id == preferredId);
        if (selected < 0 && preferredName is not null && items.Count(item => item.Name == preferredName) == 1)
            selected = items.FindIndex(item => item.Name == preferredName);
        if (selected >= 0) nodes.SelectedIndex = selected;
        else if (items.Count == 1) nodes.SelectedIndex = 0;
        else nodes.SelectedIndex = -1;
        count.Text = $"发现 {items.Count} 个可用节点" + (items.Count > 1 ? "；请手动选择一个" : "");
    }

    private async Task FetchAsync()
    {
        var input = subscription.Text.Trim();
        if (input.Length > 8192) throw new InvalidOperationException("订阅链接过长。");
        if (!Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0)
            throw new InvalidOperationException("请输入不含用户名密码的 HTTPS 订阅链接。");
        var preferred = string.Equals(sourceUrl, input, StringComparison.Ordinal) ? Selected : null;
        SetBusy(true); SetStatus("正在下载订阅…", false);
        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
            client.DefaultRequestHeaders.UserAgent.ParseAdd("mihomo/1.19.32 CodexProxySetup/1.0");
            using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
            if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"订阅服务器返回 HTTP {(int)response.StatusCode}。请检查链接或导入 Clash 文件。");
            if (response.Content.Headers.ContentLength > 4 * 1024 * 1024) throw new InvalidOperationException("订阅超过 4 MB。");
            await using var stream = await response.Content.ReadAsStreamAsync();
            using var data = new MemoryStream(); var buffer = new byte[32768];
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            int read;
            while ((read = await stream.ReadAsync(buffer, cancellation.Token)) != 0)
            { if (data.Length + read > 4 * 1024 * 1024) throw new InvalidOperationException("订阅超过 4 MB。"); await data.WriteAsync(buffer.AsMemory(0, read)); }
            var items = NodeCatalog.Parse(Encoding.UTF8.GetString(data.ToArray()));
            SetNodes(items, input, preferred?.Id, preferred?.Name);
            SetStatus(items.Count > 1 ? "订阅已读取，请选择一个节点后保存。" : "订阅已读取，可以保存配置。", false);
        }
        catch (HttpRequestException) { throw new InvalidOperationException("订阅下载失败。请检查网络，或导入已经下载的 Clash 文件。"); }
        catch (OperationCanceledException) { throw new InvalidOperationException("订阅下载超时，请稍后重试。"); }
        finally { SetBusy(false); }
    }

    private async Task ImportFileAsync()
    {
        using var dialog = new OpenFileDialog { Title = "选择自己的 Clash 配置或节点文件", Filter = "节点配置|*.yaml;*.yml;*.json;*.txt|所有文件|*.*" };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        if (new FileInfo(dialog.FileName).Length > 4 * 1024 * 1024) throw new InvalidOperationException("配置超过 4 MB。");
        SetNodes(NodeCatalog.Parse(await File.ReadAllTextAsync(dialog.FileName)), null);
        SetStatus("已导入文件。选择一个节点后作为固定节点保存。", false);
    }
    private Task ImportClipboardAsync()
    {
        if (!Clipboard.ContainsText()) throw new InvalidOperationException("剪贴板里没有节点配置。");
        SetNodes(NodeCatalog.Parse(Clipboard.GetText()), null);
        SetStatus("已导入剪贴板。选择一个节点后作为固定节点保存。", false);
        return Task.CompletedTask;
    }
    private void AddManualNode()
    {
        string Get(string key) => fields[key].Text.Trim();
        var selectedProtocol = protocol.SelectedIndex;
        var server = Get("server"); var sni = Get("sni") is { Length: > 0 } name ? name : server;
        var kind = selectedProtocol switch { 2 or 3 => "vless", 4 => "ss", 5 => "vmess", _ => "trojan" };
        var data = new Dictionary<string, object?>
        { ["name"] = Get("name"), ["type"] = kind, ["server"] = server, ["port"] = (int)port.Value,
            ["network"] = selectedProtocol is 1 or 2 or 5 ? "ws" : "tcp", ["udp"] = false };
        data[kind is "vless" or "vmess" ? "uuid" : "password"] = Get("credential");
        if (kind == "ss") data["cipher"] = Get("cipher");
        else { data["tls"] = true; data[kind is "vless" or "vmess" ? "servername" : "sni"] = sni; data["skip-cert-verify"] = false; }
        if (kind == "vmess") { data["alterId"] = 0; data["cipher"] = "auto"; }
        if (selectedProtocol is 1 or 2 or 5) data["ws-opts"] = new Dictionary<string, object?>
            { ["path"] = Get("path"), ["headers"] = new Dictionary<string, object?> { ["Host"] = Get("host") is { Length: > 0 } host ? host : sni } };
        if (selectedProtocol == 3)
        { data["reality-opts"] = new Dictionary<string, object?> { ["public-key"] = Get("publicKey"), ["short-id"] = Get("shortId") }; data["client-fingerprint"] = "chrome"; data["flow"] = "xtls-rprx-vision"; }
        NodeCatalog.Validate(data);
        SetNodes(new List<NodeItem> { new(data) }, null);
        SetStatus("手动节点已准备，可以保存配置。", false);
    }

    private async Task ApplyAsync()
    {
        if (sourceUrl is not null && !string.Equals(sourceUrl, subscription.Text.Trim(), StringComparison.Ordinal))
            throw new InvalidOperationException("订阅链接已修改，请先点击“获取 / 刷新节点”，再选择一个节点保存。");
        var selected = Selected ?? throw new InvalidOperationException("请先添加配置并选择一个节点。");
        desktop ??= DesktopLocator.Find();
        if (desktop is null) throw new InvalidOperationException("没有找到官方桌面，请安装官方 Codex 桌面或点击“选择桌面文件”。");
        DesktopLocator.Verify(desktop);
        SetBusy(true);
        try
        {
            var runtime = await RuntimeInstaller.InstallAsync(new Progress<string>(message => SetStatus(message, false)));
            RuntimeInstaller.RegisterDesktop(runtime, desktop);
            var previous = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
            using var old = PrivateStore.Read("configurator.json");
            if (old is not null && old.RootElement.TryGetProperty("previous_cli_path", out var backup)) previous = backup.ValueKind == JsonValueKind.Null ? null : backup.GetString();
            // Re-save earlier credential files as current-user DPAPI, preserving their content.
            foreach (var name in new[] { "subscription.json", "subscription-cache.json", "vps-profile.json", "node-profile.json" })
                PrivateStore.MigrateCredentialFile(name);
            var mode = sourceUrl is null ? "node" : "subscription";
            if (sourceUrl is not null)
            {
                PrivateStore.Write("subscription.json", new { Url = sourceUrl, SelectedNodeName = selected.Name.Length > 0 ? selected.Name : null, SelectedNodeId = selected.Id });
                PrivateStore.Write("subscription-cache.json", new { Subscription = sourceUrl, Node = selected.Data });
            }
            else PrivateStore.Write("node-profile.json", selected.Data);
            PrivateStore.Write("settings.json", new { Enabled = true, Mode = mode, UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), LastError = (string?)null }, false);
            PrivateStore.Write("configurator.json", new Dictionary<string, object?> { ["previous_cli_path"] = previous, ["runtime_directory"] = runtime, ["desktop_executable"] = desktop, ["selected_node_name"] = selected.Label });
            var cli = Path.Combine(runtime, "codex.exe");
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", cli, EnvironmentVariableTarget.User);
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", cli, EnvironmentVariableTarget.Process);
            if (Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User) != cli) throw new InvalidOperationException("无法保存 CLI 设置。");
            BroadcastEnvironment();
            SetStatus($"已保存并启用：{selected.Label}。完全退出后重新打开官方桌面即可。", false);
            desktopLabel.Text = "官方桌面已登记；订阅与节点凭据已加密保存。";
        }
        finally { SetBusy(false); }
    }

    private void LoadExisting()
    {
        try
        {
            desktop = DesktopLocator.Find();
            desktopLabel.Text = desktop is null ? "未找到官方桌面，可点击“选择桌面文件”。" : "已找到官方桌面。";
            using var settings = PrivateStore.Read("settings.json");
            if (settings is null) return;
            var mode = settings.RootElement.GetProperty("mode").GetString();
            if (mode == "subscription")
            {
                using var config = PrivateStore.Read("subscription.json");
                using var cache = PrivateStore.Read("subscription-cache.json");
                if (config is null || cache is null) return;
                var url = config.RootElement.GetProperty("url").GetString();
                var data = NodeCatalog.FromJson(cache.RootElement.GetProperty("node"));
                if (config.RootElement.TryGetProperty("selected_node_name", out var name) && name.ValueKind == JsonValueKind.String) data["name"] = name.GetString();
                else if (config.RootElement.TryGetProperty("selected_node_id", out _)) data["name"] = "";
                subscription.Text = url ?? "";
                SetNodes(new List<NodeItem> { new(data) }, url);
                count.Text = "已读取保存的节点；点击“获取 / 刷新节点”可重新选择。";
            }
            else if (mode == "node")
            {
                using var node = PrivateStore.Read("node-profile.json");
                if (node is not null) SetNodes(new List<NodeItem> { new(NodeCatalog.FromJson(node.RootElement)) }, null);
            }
            if (Selected is { } selected) SetStatus("已保存的节点：" + selected.Label, false);
        }
        catch { SetStatus("已有配置无法读取。可以输入自己的订阅或节点重新配置。", true); }
    }
    private void ChooseDesktop()
    {
        using var dialog = new OpenFileDialog { Title = "选择官方桌面 ChatGPT.exe", Filter = "官方桌面|ChatGPT.exe", CheckFileExists = true };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;
        DesktopLocator.Verify(dialog.FileName); desktop = dialog.FileName;
        desktopLabel.Text = "已选择有效签名的官方桌面。";
    }
    private Task OpenDesktopAsync()
    {
        desktop = DesktopLocator.Find() ?? desktop;
        if (desktop is null) throw new InvalidOperationException("请先安装或选择官方桌面。");
        DesktopLocator.Verify(desktop);
        using var meta = PrivateStore.Read("configurator.json");
        if (meta is not null && meta.RootElement.TryGetProperty("runtime_directory", out var runtime))
            RuntimeInstaller.RegisterDesktop(runtime.GetString()!, desktop);
        RuntimeInstaller.LaunchDesktop(desktop);
        SetStatus("已打开官方桌面。若桌面此前已运行，请完全退出后重开使配置生效。", false);
        return Task.CompletedTask;
    }
    private void Disable()
    {
        using var settings = PrivateStore.Read("settings.json");
        if (settings is null) { SetStatus("尚未配置专属代理。", false); return; }
        var mode = settings.RootElement.GetProperty("mode").GetString();
        PrivateStore.Write("settings.json", new { Enabled = false, Mode = mode, UpdatedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(), LastError = (string?)null }, false);
        using var metadata = PrivateStore.Read("configurator.json");
        if (metadata is not null)
        {
            var current = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
            var installed = Path.Combine(metadata.RootElement.GetProperty("runtime_directory").GetString()!, "codex.exe");
            if (string.Equals(current, installed, StringComparison.OrdinalIgnoreCase))
            {
                var prior = metadata.RootElement.GetProperty("previous_cli_path");
                var value = prior.ValueKind == JsonValueKind.String ? prior.GetString() : null;
                Environment.SetEnvironmentVariable("CODEX_CLI_PATH", value, EnvironmentVariableTarget.User);
                Environment.SetEnvironmentVariable("CODEX_CLI_PATH", value, EnvironmentVariableTarget.Process);
                BroadcastEnvironment();
            }
        }
        SetStatus("已停用，并恢复原 CLI 设置。完全退出后重新打开桌面生效。", false);
    }

    private void ShowLicenses()
    {
        try
        {
            using var form = new Form { Text = "许可与源码", Width = 800, Height = 620, StartPosition = FormStartPosition.CenterParent };
            var text = new TextBox { Multiline = true, ReadOnly = true, ScrollBars = ScrollBars.Both, Dock = DockStyle.Fill, Text = RuntimeInstaller.LicenseText(), Font = new Font("Consolas", 9F) };
            var export = new Button { Text = "导出许可与源码", Dock = DockStyle.Bottom, Height = 42 };
            export.Click += (_, _) =>
            {
                using var save = new SaveFileDialog { Filter = "ZIP 压缩包|*.zip", FileName = "ThirdPartyNotices.zip", OverwritePrompt = true };
                if (save.ShowDialog(form) != DialogResult.OK) return;
                try { RuntimeInstaller.ExportNotices(save.FileName); MessageBox.Show(form, "已导出。", "许可与源码"); }
                catch { MessageBox.Show(form, "无法导出，请选择一个不存在的新文件名。", "许可与源码"); }
            };
            form.Controls.Add(text); form.Controls.Add(export); form.ShowDialog(this);
        }
        catch { SetStatus("内置许可信息不可用，请使用正式发布文件。", true); }
    }
    private static void BroadcastEnvironment() => SendMessageTimeout(new IntPtr(0xFFFF), 0x001A, IntPtr.Zero, "Environment", 2, 5000, out _);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr value, string text, uint flags, uint timeout, out IntPtr result);
}
