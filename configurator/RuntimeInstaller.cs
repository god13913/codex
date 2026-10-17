using System.Diagnostics;
using System.IO.Compression;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexProxySetup;

internal static class RuntimeInstaller
{
    private sealed record Manifest(string BundleId, Dictionary<string, string> Files);
    private static Stream Resource(string name) => Assembly.GetExecutingAssembly().GetManifestResourceStream(name)
        ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");

    internal static async Task<string> InstallAsync(IProgress<string> progress)
    {
        using var manifestStream = Resource("runtime-manifest.json");
        var manifest = JsonSerializer.Deserialize<Manifest>(manifestStream, PrivateStore.Json)
            ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        if (manifest.BundleId.Length != 16 || manifest.BundleId.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        var root = ManagedRuntime.UserRoot;
        ManagedRuntime.AssertNoLinks(root);
        PrivateStore.SecureDirectory(root);
        var destination = Path.Combine(root, manifest.BundleId);
        if (System.IO.Directory.Exists(destination))
        {
            progress.Report("检查已安装的运行组件…");
            try { ManagedRuntime.AssertNoLinks(destination); await VerifyAsync(destination, manifest); ManagedRuntime.Mark(destination, RuntimeModeInstaller.Desktop); return destination; }
            catch (InvalidOperationException)
            {
                destination = Path.Combine(root, manifest.BundleId + "-" + Guid.NewGuid().ToString("N")[..8]);
                progress.Report("正在重新安装完整的运行组件…");
            }
        }
        var staging = Path.Combine(root, ".install-" + Guid.NewGuid().ToString("N"));
        PrivateStore.SecureDirectory(staging);
        ManagedRuntime.Mark(staging, RuntimeModeInstaller.Desktop);
        try
        {
        using var resource = Resource("runtime.zip");
        using var zip = new ZipArchive(resource, ZipArchiveMode.Read);
        var index = 0;
        foreach (var (name, expected) in manifest.Files)
        {
            if (Path.GetFileName(name) != name || name.Contains(':')) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            var entry = zip.GetEntry(name) ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            if (entry.Length > 600 * 1024 * 1024) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            progress.Report($"安装运行组件 {++index}/{manifest.Files.Count}…");
            var path = Path.Combine(staging, name);
            await using (var input = entry.Open())
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
                await input.CopyToAsync(output);
            if (!await HashMatchesAsync(path, expected)) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        }
        if (!manifest.Files.ContainsKey("codex.exe") || !manifest.Files.ContainsKey("codex-mihomo.exe") ||
            !manifest.Files.ContainsKey("WinDivert64.sys") || !manifest.Files.ContainsKey("ProxyBridge.dll"))
            throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        System.IO.Directory.Move(staging, destination);
        return destination;
        }
        catch { ManagedRuntime.Discard(staging, RuntimeModeInstaller.Desktop); throw; }
    }

    private static async Task VerifyAsync(string directory, Manifest manifest)
    {
        ManagedRuntime.AssertNoLinks(directory);
        foreach (var (name, hash) in manifest.Files)
        {
            if (Path.GetFileName(name) != name || name.Contains(':')) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            ManagedRuntime.AssertNoLinks(Path.Combine(directory, name));
            if (!await HashMatchesAsync(Path.Combine(directory, name), hash))
                throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        }
    }

    internal static async Task VerifyInstalledAsync(string directory)
    {
        using var stream = Resource("runtime-manifest.json");
        var manifest = JsonSerializer.Deserialize<Manifest>(stream, PrivateStore.Json)
            ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        await VerifyAsync(directory, manifest);
    }

    internal static async Task<string> InstallProtectedAsync()
    {
        using var stream = Resource("runtime-manifest.json");
        var manifest = JsonSerializer.Deserialize<Manifest>(stream, PrivateStore.Json)
            ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        if (manifest.BundleId.Length != 16 || manifest.BundleId.Any(c => !Uri.IsHexDigit(c)) ||
            !manifest.Files.ContainsKey("codex-proxy-service.exe")) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        var root = Path.Combine(ManagedRuntime.ServiceRoot,
            "CodexDedicatedProxy-Setup-" + manifest.BundleId + "-" + Guid.NewGuid().ToString("N")[..8]);
        RuntimeModeInstaller.Protect(root, true);
        ManagedRuntime.Mark(root, RuntimeModeInstaller.Service);
        var runtime = Path.Combine(root, "runtime");
        try
        {
        RuntimeModeInstaller.Protect(runtime, true);
        using var zipStream = Resource("runtime.zip");
        using var zip = new ZipArchive(zipStream, ZipArchiveMode.Read);
        foreach (var (name, hash) in manifest.Files)
        {
            if (Path.GetFileName(name) != name || name.Contains(':')) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            var entry = zip.GetEntry(name) ?? throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            if (entry.Length > 600 * 1024 * 1024) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
            var path = Path.Combine(runtime, name);
            await using (var input = entry.Open())
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
                await input.CopyToAsync(output);
            if (!await HashMatchesAsync(path, hash)) throw new InvalidOperationException("安装文件不完整或已损坏，请重新下载正式版配置器。");
        }
        return runtime;
        }
        catch { ManagedRuntime.Discard(runtime, RuntimeModeInstaller.Service); throw; }
    }

    private static async Task<bool> HashMatchesAsync(string path, string hash)
    {
        if (!File.Exists(path)) return false;
        await using var input = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(input)).Equals(hash, StringComparison.OrdinalIgnoreCase);
    }

    internal static void RegisterDesktop(string runtime, string desktop)
    {
        DesktopLocator.Verify(desktop);
        var registration = new
        {
            Schema = 1, DesktopPackageFamily = DesktopLocator.PackageFamily, DesktopExecutable = desktop,
            DesktopSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(desktop))),
            BridgeSha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(Path.Combine(runtime, "ProxyBridge.dll"))))
        };
        File.WriteAllBytes(Path.Combine(runtime, "desktop-forwarding.json"), JsonSerializer.SerializeToUtf8Bytes(registration, PrivateStore.Json));
    }

    /// <summary>
    /// Reverts the desktop to the official CLI by removing the <c>CODEX_CLI_PATH</c> override.
    /// </summary>
    /// <remarks>
    /// The official desktop selects its bundled CLI whenever <c>CODEX_CLI_PATH</c> is absent,
    /// so removal is the correct way back. Earlier revisions instead restored a remembered
    /// "previous_cli_path" value, which broke in three ways: the key is omitted from
    /// configurator.json when the previous value was null (DefaultIgnoreCondition =
    /// WhenWritingNull), so reading it threw KeyNotFoundException and cleared nothing; the
    /// equality guard skipped the whole step whenever the variable did not match the recorded
    /// runtime; and a remembered path can be stale after a runtime rebuild. Always clear, and
    /// never depend on stored metadata.
    /// </remarks>
    internal static void ClearCliOverride()
    {
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH", null, EnvironmentVariableTarget.User);
        if (Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User) is not null)
            throw new InvalidOperationException("无法恢复官方命令行设置，请重启电脑后再试。");
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH", null, EnvironmentVariableTarget.Process);
        if (Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.Process) is not null)
            throw new InvalidOperationException("无法恢复官方命令行设置，请重启电脑后再试。");
        BroadcastEnvironment();
    }

    internal static void BroadcastEnvironment() =>
        SendMessageTimeout(new IntPtr(0xFFFF), 0x001A, IntPtr.Zero, "Environment", 2, 5000, out _);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(IntPtr window, uint message, IntPtr value,
        string text, uint flags, uint timeout, out IntPtr result);

    internal static void LaunchDesktop(string path) => Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });

    internal static string LicenseText()
    {
        using var resource = Resource("notices.zip");
        using var zip = new ZipArchive(resource, ZipArchiveMode.Read);
        var text = new System.Text.StringBuilder("本程序包含 Codex、Mihomo、ProxyBridge、WinDivert、YamlDotNet 和 WebView2。\r\n相关许可和源码内置在这个 EXE 中，可导出查看。\r\n\r\n");
        foreach (var entry in zip.Entries.Where(e => e.FullName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)))
        {
            using var reader = new StreamReader(entry.Open());
            text.AppendLine(entry.Name).AppendLine(reader.ReadToEnd()).AppendLine();
        }
        return text.ToString();
    }

    internal static void ExportNotices(string destination)
    {
        using var input = Resource("notices.zip");
        using var output = new FileStream(destination, FileMode.Create, FileAccess.Write);
        input.CopyTo(output);
    }
}
