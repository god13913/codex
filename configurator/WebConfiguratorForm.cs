using System.Reflection;
using System.Text.Json;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

namespace CodexProxySetup;

internal sealed class WebConfiguratorForm : Form
{
    private const string UiUrl = "https://codexproxy.local/index.html";
    private readonly WebView2 browser = new() { Dock = DockStyle.Fill };
    private readonly ConfiguratorBridge bridge;
    private bool showingFallback;

    internal WebConfiguratorForm()
    {
        Text = "Codex 代理配置";
        Icon = System.Drawing.Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1160, 820);
        MinimumSize = new Size(840, 620);
        AutoScaleMode = AutoScaleMode.Dpi;
        Controls.Add(browser);
        bridge = new ConfiguratorBridge(this);
        Shown += async (_, _) => await InitializeAsync();
    }

    private async Task InitializeAsync()
    {
        try
        {
            var userData = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "CodexProxy", "WebView2");
            PrivateStore.SecureDirectory(userData);
            var environment = await CoreWebView2Environment.CreateAsync(userDataFolder: userData);
            await browser.EnsureCoreWebView2Async(environment);
            browser.CoreWebView2.Settings.IsPasswordAutosaveEnabled = false;
            browser.CoreWebView2.Settings.IsGeneralAutofillEnabled = false;
            browser.CoreWebView2.Settings.AreDevToolsEnabled = false;
            browser.CoreWebView2.WebMessageReceived += OnWebMessageReceived;
            browser.CoreWebView2.NavigationStarting += (_, args) =>
            {
                if (!args.Uri.Equals(UiUrl, StringComparison.OrdinalIgnoreCase)) args.Cancel = true;
            };
            browser.CoreWebView2.NewWindowRequested += (_, args) => args.Handled = true;
            browser.CoreWebView2.AddWebResourceRequestedFilter(UiUrl, CoreWebView2WebResourceContext.Document);
            browser.CoreWebView2.WebResourceRequested += (_, args) =>
            {
                if (!args.Request.Uri.Equals(UiUrl, StringComparison.OrdinalIgnoreCase)) return;
                var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream("configurator-ui.html")
                    ?? throw new InvalidOperationException("内置配置界面不存在。");
                args.Response = environment.CreateWebResourceResponse(resource, 200, "OK",
                    "Content-Type: text/html; charset=utf-8\r\nCache-Control: no-store");
            };
            browser.CoreWebView2.NavigationCompleted += async (_, args) =>
            {
                if (!args.IsSuccess) { ShowFallback(); return; }
                try
                {
                    await Task.Delay(1500);
                    if (IsDisposed || showingFallback) return;
                    var rendered = await browser.CoreWebView2.ExecuteScriptAsync(
                        "document.querySelector('#app')?.childElementCount ?? 0");
                    if (rendered == "0") ShowFallback();
                }
                catch { ShowFallback(); }
            };
            browser.CoreWebView2.Navigate(UiUrl);
        }
        catch
        {
            ShowFallback();
        }
    }

    private void ShowFallback()
    {
        if (showingFallback || IsDisposed) return;
        showingFallback = true;
        Hide();
        using var fallback = new MainForm();
        fallback.ShowDialog(this);
        Close();
    }

    private async void OnWebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs args)
    {
        int id = 0;
        try
        {
            var message = args.WebMessageAsJson;
            if (message.Length > 8 * 1024 * 1024) throw new InvalidOperationException("请求数据过大。");
            using var document = JsonDocument.Parse(message);
            var root = document.RootElement;
            id = root.GetProperty("id").GetInt32();
            var method = root.GetProperty("method").GetString() ?? "";
            var payload = root.TryGetProperty("payload", out var value) ? value.Clone() : default;
            var result = await bridge.DispatchAsync(method, payload);
            browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new { id, result }));
        }
        catch (Exception error)
        {
            var message = error is InvalidOperationException ? error.Message : "操作失败，请检查网络或本机配置。";
            browser.CoreWebView2.PostWebMessageAsJson(JsonSerializer.Serialize(new { id, error = message }));
        }
    }
}
