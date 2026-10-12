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
        ?? throw new InvalidOperationException("此配置器没有完整的内置运行组件，请使用正式发布文件。");

    internal static async Task<string> InstallAsync(IProgress<string> progress)
    {
        using var manifestStream = Resource("runtime-manifest.json");
        var manifest = JsonSerializer.Deserialize<Manifest>(manifestStream, PrivateStore.Json)
            ?? throw new InvalidOperationException("内置运行组件不完整。");
        if (manifest.BundleId.Length != 16 || manifest.BundleId.Any(c => !Uri.IsHexDigit(c)))
            throw new InvalidOperationException("内置版本标识不正确。");
        var root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CodexProxy", "Runtime");
        PrivateStore.SecureDirectory(root);
        var destination = Path.Combine(root, manifest.BundleId);
        if (System.IO.Directory.Exists(destination))
        {
            progress.Report("检查已安装的运行组件…");
            try { await VerifyAsync(destination, manifest); return destination; }
            catch (InvalidOperationException)
            {
                destination = Path.Combine(root, manifest.BundleId + "-" + Guid.NewGuid().ToString("N")[..8]);
                progress.Report("正在重新安装完整的运行组件…");
            }
        }
        var staging = Path.Combine(root, ".install-" + Guid.NewGuid().ToString("N"));
        PrivateStore.SecureDirectory(staging);
        using var resource = Resource("runtime.zip");
        using var zip = new ZipArchive(resource, ZipArchiveMode.Read);
        var index = 0;
        foreach (var (name, expected) in manifest.Files)
        {
            if (Path.GetFileName(name) != name || name.Contains(':')) throw new InvalidOperationException("内置文件名不正确。");
            var entry = zip.GetEntry(name) ?? throw new InvalidOperationException("内置运行组件缺失。");
            if (entry.Length > 600 * 1024 * 1024) throw new InvalidOperationException("内置组件大小不正确。");
            progress.Report($"安装运行组件 {++index}/{manifest.Files.Count}…");
            var path = Path.Combine(staging, name);
            await using (var input = entry.Open())
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 131072, true))
                await input.CopyToAsync(output);
            if (!await HashMatchesAsync(path, expected)) throw new InvalidOperationException("内置运行组件校验失败。");
        }
        if (!manifest.Files.ContainsKey("codex.exe") || !manifest.Files.ContainsKey("codex-mihomo.exe") ||
            !manifest.Files.ContainsKey("WinDivert64.sys") || !manifest.Files.ContainsKey("ProxyBridge.dll"))
            throw new InvalidOperationException("内置运行组件不完整。");
        System.IO.Directory.Move(staging, destination);
        return destination;
    }

    private static async Task VerifyAsync(string directory, Manifest manifest)
    {
        foreach (var (name, hash) in manifest.Files)
            if (!await HashMatchesAsync(Path.Combine(directory, name), hash))
                throw new InvalidOperationException("已安装组件不完整或被修改，请重新下载正式配置器。");
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
            Schema = 1, DesktopExecutable = desktop,
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
            throw new InvalidOperationException("无法清除 CLI 设置。");
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH", null, EnvironmentVariableTarget.Process);
        BroadcastEnvironment();
    }

    private static void BroadcastEnvironment() =>
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
