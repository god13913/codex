namespace CodexProxySetup;

// Both native and WebView UIs use the same mode/credential transaction.
internal static class ProxyConfiguration
{
    internal static async Task ApplyAsync(NodeItem selected, string? sourceUrl, string desktop, string installationMode,
        IProgress<string> progress)
    {
        using var update = ManagedRuntime.AcquireUpdate();
        RuntimeModeInstaller.Normalize(installationMode);
        NodeCatalog.Validate(selected.Data); // Also normalize nodes loaded by the fallback UI from old caches.
        RuntimeModeInstaller.Preflight(installationMode);
        DesktopLocator.Verify(desktop);
        // Service mode extracts once into the protected destination in the
        // elevated helper, rather than leaving a duplicate in LocalAppData.
        var runtime = installationMode == RuntimeModeInstaller.Service ? "" : await RuntimeInstaller.InstallAsync(progress);
        if (runtime.Length != 0) RuntimeInstaller.RegisterDesktop(runtime, desktop);
        var saved = RuntimeModeInstaller.Snapshot();
        var oldUser = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
        var oldProcess = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.Process);
        try
        {
            foreach (var name in new[] { "subscription.json", "subscription-cache.json", "vps-profile.json", "node-profile.json" }) PrivateStore.MigrateCredentialFile(name);
            if (sourceUrl is not null)
            {
                PrivateStore.Write("subscription.json", new { Url = sourceUrl, SelectedNodeName = selected.Name.Length > 0 ? selected.Name : null, SelectedNodeId = selected.Id });
                PrivateStore.Write("subscription-cache.json", new { Subscription = sourceUrl, Node = selected.Data });
            }
            else PrivateStore.Write("node-profile.json", selected.Data);
            RuntimeModeInstaller.SetEnabled(true, sourceUrl is null ? "node" : "subscription");
            var meta = RuntimeModeInstaller.ReadObject("configurator.json");
            meta["selected_node_name"] = selected.Label;
            PrivateStore.Write("configurator.json", meta);
            progress.Report(installationMode == RuntimeModeInstaller.Service ? "正在安装并等待 Windows 服务转发就绪…" : "正在配置不安装服务模式…");
            await RuntimeModeInstaller.ApplyAsync(installationMode, desktop, runtime);
        }
        catch
        {
            RuntimeModeInstaller.Restore(saved);
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", oldUser, EnvironmentVariableTarget.User);
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", oldProcess, EnvironmentVariableTarget.Process);
            RuntimeInstaller.BroadcastEnvironment();
            throw;
        }
        finally { foreach (var bytes in saved.Values) if (bytes is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }
}
