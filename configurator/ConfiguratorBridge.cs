using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CodexProxySetup;

internal sealed class ConfiguratorBridge
{
    private readonly Form owner;
    private readonly SemaphoreSlim storeGate = new(1, 1);
    private readonly SemaphoreSlim operationGate = new(1, 1);

    internal ConfiguratorBridge(Form owner) => this.owner = owner;

    internal async Task<object?> DispatchAsync(string method, JsonElement payload) => method switch
    {
        "loadState" => await LoadStateAsync(),
        "saveSettings" => await UpdateUiAsync(ui => ui["settings"] = ParsePayload(payload)),
        "saveProfile" => await UpdateUiAsync(ui => SaveProfile(ui, payload)),
        "removeProfile" => await UpdateUiAsync(ui => RemoveProfile(ui, payload.GetString() ?? "")),
        "chooseDesktop" => ChooseDesktop(),
        "locateDesktop" => LocateDesktop(),
        "verifyDesktop" => VerifyDesktop(payload.GetString() ?? ""),
        "fetchNodes" => await FetchNodesAsync(payload.GetString() ?? ""),
        "importFile" => await ImportFileAsync(),
        "importClipboard" => ImportClipboard(),
        "exportProfile" => ExportProfile(payload),
        "applyProfile" => await RunExclusiveAsync(() => ApplyProfileAsync(payload)),
        "disableProxy" => await RunExclusiveAsync(DisableProxyAsync),
        "uninstallProxy" => await RunExclusiveAsync(UninstallProxyAsync),
        "getNodeExitIpv4" => await GetNodeExitIpv4Async(payload),
        _ => throw new InvalidOperationException("不支持的界面操作。")
    };

    private static JsonNode? ParsePayload(JsonElement payload) => JsonNode.Parse(payload.GetRawText());

    private async Task<object> RunExclusiveAsync(Func<Task<object>> action)
    {
        if (!await operationGate.WaitAsync(0)) throw new InvalidOperationException("上一项配置操作尚未完成。");
        try { return await action(); }
        finally { operationGate.Release(); }
    }

    private static JsonObject ReadUi()
    {
        using var saved = PrivateStore.Read("ui-state.json");
        return saved is null ? new JsonObject() : JsonNode.Parse(saved.RootElement.GetRawText()) as JsonObject ?? new JsonObject();
    }

    private async Task<object?> UpdateUiAsync(Action<JsonObject> update)
    {
        await storeGate.WaitAsync();
        try
        {
            var ui = ReadUi();
            update(ui);
            PrivateStore.Write("ui-state.json", ui);
            return true;
        }
        finally { storeGate.Release(); }
    }

    private async Task<object> LoadStateAsync()
    {
        await storeGate.WaitAsync();
        try
        {
            var ui = ReadUi();
            var settings = ui["settings"] as JsonObject ?? new JsonObject();
            var profiles = ui["profiles"] as JsonArray ?? new JsonArray();
            using var active = PrivateStore.Read("settings.json");
            var enabled = active?.RootElement.TryGetProperty("enabled", out var flag) == true && flag.ValueKind == JsonValueKind.True;
            if (profiles.Count == 0 && active is not null && MigrateExistingProfile(active.RootElement, profiles, settings))
            {
                if (ui["profiles"] is null) ui["profiles"] = profiles;
                if (ui["settings"] is null) ui["settings"] = settings;
                PrivateStore.Write("ui-state.json", ui);
            }
            var managedCli = IsManagedCliSelected();
            settings["enabled"] = enabled && managedCli;
            settings["cliPathMismatch"] = enabled && !managedCli;
            settings["installationMode"] = RuntimeModeInstaller.CurrentMode();
            return new { settings, profiles };
        }
        finally { storeGate.Release(); }
    }

    private static bool IsManagedCliSelected()
    {
        try
        {
            using var metadata = PrivateStore.Read("configurator.json");
            if (metadata is null) return false;
            var runtime = Get(metadata.RootElement, "runtime_directory");
            var selected = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
            if (runtime.Length == 0 || string.IsNullOrWhiteSpace(selected)) return false;
            var installed = Path.GetFullPath(Path.Combine(runtime, "codex.exe"));
            return File.Exists(installed) && string.Equals(installed, Path.GetFullPath(selected), StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception error) when (error is IOException or JsonException or InvalidOperationException or ArgumentException)
        {
            return false;
        }
    }

    private static bool MigrateExistingProfile(JsonElement active, JsonArray profiles, JsonObject settings)
    {
        var mode = active.TryGetProperty("mode", out var value) ? value.GetString() : null;
        try
        {
            string? url = null;
            Dictionary<string, object?>? node = null;
            if (mode == "subscription")
            {
                using var config = PrivateStore.Read("subscription.json");
                using var cache = PrivateStore.Read("subscription-cache.json");
                if (config is null || cache is null) return false;
                url = config.RootElement.GetProperty("url").GetString();
                node = NodeCatalog.FromJson(cache.RootElement.GetProperty("node"));
            }
            else if (mode == "node")
            {
                using var saved = PrivateStore.Read("node-profile.json");
                if (saved is null) return false;
                node = NodeCatalog.FromJson(saved.RootElement);
            }
            else if (mode == "vps")
            {
                using var saved = PrivateStore.Read("vps-profile.json");
                if (saved is null) return false;
                var vps = saved.RootElement;
                var host = vps.GetProperty("sni").GetString() ?? "";
                node = new Dictionary<string, object?>
                {
                    ["name"] = "VPS 节点", ["type"] = "vless",
                    ["server"] = vps.GetProperty("server").GetString(),
                    ["port"] = vps.GetProperty("port").GetInt32(),
                    ["uuid"] = vps.GetProperty("uuid").GetString(),
                    ["tls"] = true, ["servername"] = host, ["network"] = "ws",
                    ["client-fingerprint"] = "chrome", ["udp"] = true,
                    ["ws-opts"] = new Dictionary<string, object?>
                    {
                        ["path"] = vps.GetProperty("path").GetString(),
                        ["headers"] = new Dictionary<string, object?> { ["Host"] = host }
                    }
                };
            }
            if (node is null) return false;
            var item = new NodeItem(node);
            var id = Guid.NewGuid().ToString("N");
            var displayNode = new Dictionary<string, object?>(node) { ["id"] = item.Id };
            profiles.Add(JsonSerializer.SerializeToNode(new
            {
                id, kind = "clash", name = item.Label, url = url ?? "", source = url is null ? "file" : "subscription",
                nodes = new[] { displayNode }, selectedNodeId = item.Id,
                createdAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), updatedAt = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()
            }));
            settings["activeProfileId"] = id;
            return true;
        }
        catch { return false; }
    }

    private static void SaveProfile(JsonObject ui, JsonElement payload)
    {
        var id = payload.GetProperty("id").GetString();
        if (string.IsNullOrWhiteSpace(id)) throw new InvalidOperationException("配置标识无效。");
        var profiles = ui["profiles"] as JsonArray ?? new JsonArray();
        for (var i = profiles.Count - 1; i >= 0; i--)
            if (profiles[i]?["id"]?.GetValue<string>() == id) profiles.RemoveAt(i);
        profiles.Insert(0, ParsePayload(payload));
        if (ui["profiles"] is null) ui["profiles"] = profiles;
    }

    private static void RemoveProfile(JsonObject ui, string id)
    {
        var profiles = ui["profiles"] as JsonArray ?? new JsonArray();
        for (var i = profiles.Count - 1; i >= 0; i--)
            if (profiles[i]?["id"]?.GetValue<string>() == id) profiles.RemoveAt(i);
        if (ui["profiles"] is null) ui["profiles"] = profiles;
    }

    private string? ChooseDesktop()
    {
        using var dialog = new OpenFileDialog { Title = "选择官方桌面 ChatGPT.exe", Filter = "官方桌面|ChatGPT.exe", CheckFileExists = true };
        if (dialog.ShowDialog(owner) != DialogResult.OK) return null;
        DesktopLocator.Verify(dialog.FileName);
        return dialog.FileName;
    }

    private static string? LocateDesktop()
    {
        var desktop = DesktopLocator.Find();
        if (desktop is null) return null;
        DesktopLocator.Verify(desktop);
        return desktop;
    }

    private static bool VerifyDesktop(string path)
    {
        DesktopLocator.Verify(path);
        return true;
    }

    private static object NodesForUi(IEnumerable<NodeItem> nodes) => nodes.Select(item =>
    {
        var data = new Dictionary<string, object?>(item.Data) { ["id"] = item.Id };
        return data;
    }).ToList();

    private static async Task<object> FetchNodesAsync(string input)
    {
        if (input.Length > 8192 || !Uri.TryCreate(input, UriKind.Absolute, out var uri) || uri.Scheme != "https" || uri.UserInfo.Length != 0)
            throw new InvalidOperationException("请输入不含用户名密码的 HTTPS 订阅链接。");
        using var handler = new HttpClientHandler { AllowAutoRedirect = false, AutomaticDecompression = DecompressionMethods.All };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("mihomo/1.19.32 CodexProxySetup/1.0");
        using var response = await client.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"订阅服务器出错了（错误码 {(int)response.StatusCode}）。");
        if (response.Content.Headers.ContentLength > 4 * 1024 * 1024) throw new InvalidOperationException("订阅文件超过 4 MB。");
        await using var stream = await response.Content.ReadAsStreamAsync();
        using var data = new MemoryStream();
        var buffer = new byte[32768];
        using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        int read;
        while ((read = await stream.ReadAsync(buffer, cancellation.Token)) != 0)
        {
            if (data.Length + read > 4 * 1024 * 1024) throw new InvalidOperationException("订阅文件超过 4 MB。");
            await data.WriteAsync(buffer.AsMemory(0, read));
        }
        return NodesForUi(NodeCatalog.Parse(Encoding.UTF8.GetString(data.ToArray())));
    }

    private async Task<object?> ImportFileAsync()
    {
        using var dialog = new OpenFileDialog { Title = "选择 Clash 配置或节点文件", Filter = "节点配置|*.yaml;*.yml;*.json;*.txt|所有文件|*.*" };
        if (dialog.ShowDialog(owner) != DialogResult.OK) return null;
        if (new FileInfo(dialog.FileName).Length > 4 * 1024 * 1024) throw new InvalidOperationException("配置文件超过 4 MB。");
        return NodesForUi(NodeCatalog.Parse(await File.ReadAllTextAsync(dialog.FileName)));
    }

    private static object ImportClipboard()
    {
        if (!Clipboard.ContainsText()) throw new InvalidOperationException("剪贴板里没有节点配置。");
        return NodesForUi(NodeCatalog.Parse(Clipboard.GetText()));
    }

    private object? ExportProfile(JsonElement payload)
    {
        using var dialog = new SaveFileDialog { Title = "导出配置", Filter = "JSON 配置|*.json", FileName = "codex-proxy-profile.json", OverwritePrompt = true };
        if (dialog.ShowDialog(owner) != DialogResult.OK) return null;
        File.WriteAllText(dialog.FileName, JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return true;
    }

    private static string Get(JsonElement value, string name) => value.TryGetProperty(name, out var field) && field.ValueKind == JsonValueKind.String ? field.GetString() ?? "" : "";

    private static NodeItem SelectedNode(JsonElement profile, out string? subscriptionUrl)
    {
        subscriptionUrl = null;
        if (Get(profile, "kind") == "clash")
        {
            if (Get(profile, "source") == "subscription" && Get(profile, "fetchedUrl") is { Length: > 0 } fetched &&
                !string.Equals(fetched, Get(profile, "url").Trim(), StringComparison.Ordinal))
                throw new InvalidOperationException("订阅链接已修改，请先刷新节点。");
            var selected = Get(profile, "selectedNodeId");
            foreach (var raw in profile.GetProperty("nodes").EnumerateArray())
            {
                if (Get(raw, "id") != selected) continue;
                var data = NodeCatalog.FromJson(raw);
                data.Remove("id");
                NodeCatalog.Validate(data);
                subscriptionUrl = Get(profile, "source") == "subscription" ? Get(profile, "url") : null;
                return new NodeItem(data);
            }
            throw new InvalidOperationException("请选择一个以后使用的节点。");
        }
        if (Get(profile, "kind") != "vps") throw new InvalidOperationException("配置类型无效。");
        var protocol = Get(profile, "protocol");
        var server = Get(profile, "server");
        var name = Get(profile, "name");
        if (!int.TryParse(profile.GetProperty("port").ToString(), out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException("节点端口无效。");
        var kind = protocol switch { "vless-ws" or "vless-reality" => "vless", "vmess-ws" => "vmess", "ss" => "ss", _ => "trojan" };
        var ws = protocol is "trojan-ws" or "vless-ws" or "vmess-ws";
        var sni = Get(profile, "sni") is { Length: > 0 } customSni ? customSni : server;
        var dataManual = new Dictionary<string, object?>
        {
            ["name"] = name, ["type"] = kind, ["server"] = server, ["port"] = port,
            ["network"] = ws ? "ws" : "tcp", ["udp"] = true,
            [kind is "vless" or "vmess" ? "uuid" : "password"] = Get(profile, "credential")
        };
        if (kind == "ss") dataManual["cipher"] = Get(profile, "cipher");
        else
        {
            dataManual["tls"] = true;
            dataManual[kind is "vless" or "vmess" ? "servername" : "sni"] = sni;
            dataManual["skip-cert-verify"] = false;
        }
        if (kind == "vmess") { dataManual["alterId"] = 0; dataManual["cipher"] = "auto"; }
        if (ws) dataManual["ws-opts"] = new Dictionary<string, object?>
        {
            ["path"] = Get(profile, "path"),
            ["headers"] = new Dictionary<string, object?> { ["Host"] = Get(profile, "host") is { Length: > 0 } host ? host : sni }
        };
        if (protocol == "vless-reality")
        {
            dataManual["reality-opts"] = new Dictionary<string, object?> { ["public-key"] = Get(profile, "publicKey"), ["short-id"] = Get(profile, "shortId") };
            dataManual["client-fingerprint"] = "chrome";
            dataManual["flow"] = "xtls-rprx-vision";
        }
        NodeCatalog.Validate(dataManual);
        return new NodeItem(dataManual);
    }

    private static async Task<object> ApplyProfileAsync(JsonElement payload)
    {
        var profile = payload.GetProperty("profile");
        var desktop = Get(payload, "desktopPath");
        var selected = SelectedNode(profile, out var sourceUrl);
        var installationMode = Get(payload, "installationMode");
        if (installationMode.Length == 0) installationMode = RuntimeModeInstaller.CurrentMode();
        await ProxyConfiguration.ApplyAsync(selected, sourceUrl, desktop, installationMode, new Progress<string>(_ => { }));
        return (installationMode == RuntimeModeInstaller.Service
            ? "Windows 服务已就绪；请正常重新打开官方桌面。"
            : "已启用「不安装服务」模式。请完全退出并重开桌面，启动时允许管理员授权提示。") + ManagedRuntime.Notice;
    }

    private static async Task<object> DisableProxyAsync()
    {
        await RuntimeModeInstaller.DisableAsync();
        return true;
    }

    private static async Task<object> UninstallProxyAsync()
    {
        await RuntimeModeInstaller.UninstallAsync();
        return true;
    }

    private static async Task<object> GetNodeExitIpv4Async(JsonElement profile)
    {
        var node = SelectedNode(profile, out _);
        return await NodeExitProbe.GetIpv4Async(node);
    }

    private static void BroadcastEnvironment() => SendMessageTimeout(new IntPtr(0xFFFF), 0x001A, IntPtr.Zero, "Environment", 2, 5000, out _);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr value, string text, uint flags, uint timeout, out IntPtr result);
}
