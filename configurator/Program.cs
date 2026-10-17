using System.Runtime.InteropServices;
using System.Text.Json;

namespace CodexProxySetup;

internal static class Program
{
    [STAThread]
    private static void Main(string[] args)
    {
        if (args.Length > 0 && args[0] == "--configure-runtime")
        {
            try { Environment.ExitCode = RuntimeModeInstaller.RunElevatedAsync(args).GetAwaiter().GetResult(); }
            catch { Environment.ExitCode = 13; }
            return;
        }
        if (args.Length == 1 && args[0] == "--upgrade-runtime")
        {
            try { UpgradeRuntimeAsync().GetAwaiter().GetResult(); }
            catch { Environment.ExitCode = 1; }
            return;
        }
        if (args.Length != 0) { Environment.ExitCode = 2; return; }
        using var single = new Mutex(true, "Local\\CodexProxySetup-" +
            System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value, out var first);
        if (!first) { MessageBox.Show("配置器已经打开。", "Codex 代理配置"); return; }
        ApplicationConfiguration.Initialize();
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += (_, _) => MessageBox.Show(
            "操作未完成，请重新打开配置器。错误详情不会记录订阅或节点凭据。", "Codex 代理配置");
        Application.Run(new WebConfiguratorForm());
    }

    private static async Task UpgradeRuntimeAsync()
    {
        using var update = ManagedRuntime.AcquireUpdate();
        using var metadata = PrivateStore.Read("configurator.json")
            ?? throw new InvalidOperationException("尚未保存代理配置。");
        using var settings = PrivateStore.Read("settings.json")
            ?? throw new InvalidOperationException("尚未启用代理。");
        if (!settings.RootElement.GetProperty("enabled").GetBoolean())
            throw new InvalidOperationException("专属代理尚未启用。");
        var fields = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(
            metadata.RootElement.GetRawText(), PrivateStore.Json)
            ?? throw new InvalidOperationException("已有配置不完整。");
        var oldRuntime = fields["runtime_directory"].GetString()
            ?? throw new InvalidOperationException("已有运行目录无效。");
        var desktop = fields["desktop_executable"].GetString()
            ?? throw new InvalidOperationException("已有桌面路径无效。");
        var oldCli = Path.Combine(oldRuntime, "codex.exe");
        var selectedCli = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
        if (!string.Equals(Path.GetFullPath(oldCli), selectedCli is null ? null : Path.GetFullPath(selectedCli),
                StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("当前命令行与已保存的配置不一致，请重新保存一次。");

        var mode = RuntimeModeInstaller.CurrentMode();
        RuntimeModeInstaller.Preflight(mode);
        var runtime = mode == RuntimeModeInstaller.Service ? "" : await RuntimeInstaller.InstallAsync(new Progress<string>(_ => { }));
        if (runtime.Length != 0) RuntimeInstaller.RegisterDesktop(runtime, desktop);
        var saved = RuntimeModeInstaller.Snapshot();
        var oldProcess = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.Process);
        try { await RuntimeModeInstaller.ApplyAsync(mode, desktop, runtime); }
        catch
        {
            RuntimeModeInstaller.Restore(saved);
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", selectedCli, EnvironmentVariableTarget.User);
            Environment.SetEnvironmentVariable("CODEX_CLI_PATH", oldProcess, EnvironmentVariableTarget.Process);
            RuntimeInstaller.BroadcastEnvironment();
            throw;
        }
        finally { foreach (var bytes in saved.Values) if (bytes is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void BroadcastEnvironment() =>
        SendMessageTimeout(new IntPtr(0xFFFF), 0x001A, IntPtr.Zero, "Environment", 2, 5000, out _);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr value,
        string text, uint flags, uint timeout, out IntPtr result);
}
