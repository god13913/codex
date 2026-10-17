using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Diagnostics;

namespace CodexProxySetup;

// Only generations explicitly created by this installer are disposable. Manual
// diagnostic runtimes and downloaded installers never acquire this marker.
internal static class ManagedRuntime
{
    private const string Marker = ".codex-proxy-setup.json";
    internal static string UserRoot => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CodexProxy", "Runtime");
    internal static string ServiceRoot => Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
    private static string Sid => WindowsIdentity.GetCurrent().User!.Value;
    internal static bool CleanupPending { get; set; }
    internal static string Notice => CleanupPending ? " 部分旧组件暂未清理，下次保存配置时会重试。" : "";

    internal static IDisposable AcquireUpdate()
    {
        var semaphore = new Semaphore(1, 1, "Local\\CodexProxySetupUpdate-" + Sid);
        if (semaphore.WaitOne(0)) return new UpdateLease(semaphore);
        semaphore.Dispose(); throw new InvalidOperationException("运行组件正在更新，请等待当前配置或升级完成。");
    }

    private sealed class UpdateLease(Semaphore semaphore) : IDisposable
    {
        public void Dispose() { semaphore.Release(); semaphore.Dispose(); }
    }

    internal static void Mark(string directory, string scope)
    {
        AssertNoLinks(directory);
        File.WriteAllBytes(Path.Combine(directory, Marker), JsonSerializer.SerializeToUtf8Bytes(new
        { Schema = 1, Product = "CodexProxySetup", OwnerSid = Sid, Scope = scope }, PrivateStore.Json));
    }

    // Reject the parent itself, siblings, links at any depth, foreign owners and
    // unmarked directories before considering recursive removal.
    private static bool OwnsRoot(string directory, string parent, string scope)
    {
        try
        {
            directory = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar);
            parent = Path.GetFullPath(parent).TrimEnd(Path.DirectorySeparatorChar);
            if (!string.Equals(Path.GetDirectoryName(directory), parent, StringComparison.OrdinalIgnoreCase)) return false;
            if (scope == RuntimeModeInstaller.Service && !Path.GetFileName(directory).StartsWith("CodexDedicatedProxy-Setup-", StringComparison.Ordinal)) return false;
            AssertNoLinks(directory);
            var marker = Path.Combine(directory, Marker);
            if (!File.Exists(marker) || new FileInfo(marker).Length > 4096) return false;
            AssertNoLinks(marker);
            using var document = JsonDocument.Parse(File.ReadAllBytes(marker)); var r = document.RootElement;
            if (r.GetProperty("schema").GetInt32() != 1 || r.GetProperty("product").GetString() != "CodexProxySetup" ||
                r.GetProperty("owner_sid").GetString() != Sid || r.GetProperty("scope").GetString() != scope) return false;
            if (scope == RuntimeModeInstaller.Service)
                foreach (var path in new[] { directory, marker })
                {
                    FileSystemSecurity acl = File.Exists(path) ? new FileInfo(path).GetAccessControl() : new DirectoryInfo(path).GetAccessControl();
                    if (acl.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544")) return false;
                    foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                        if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
                            (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0) return false;
                }
            return true;
        }
        catch { return false; } // Invalid ownership metadata is never a reason to delete.
    }

    private static bool CanDelete(string directory, string parent, string scope)
    {
        if (!OwnsRoot(directory, parent, scope)) return false;
        try
        {
            // Do not use AllDirectories: examine every directory before entering it.
            var pending = new Stack<string>(); pending.Push(directory);
            while (pending.TryPop(out var current))
                foreach (var entry in Directory.EnumerateFileSystemEntries(current))
                {
                    if ((File.GetAttributes(entry) & FileAttributes.ReparsePoint) != 0) return false;
                    if (Directory.Exists(entry)) pending.Push(entry);
                }
            return true;
        }
        catch { return false; }
    }

    internal static bool HasServiceGenerations()
    {
        try
        {
            // Root/marker are user-readable; the private service snapshot is
            // intentionally not. Detect leftovers without entering that snapshot.
            AssertNoLinks(ServiceRoot);
            return Directory.EnumerateDirectories(ServiceRoot, "CodexDedicatedProxy-Setup-*")
                .Any(path => OwnsRoot(path, ServiceRoot, RuntimeModeInstaller.Service));
        }
        catch { return false; }
    }

    internal static void AssertNoLinks(string path)
    {
        for (var p = new DirectoryInfo(Path.GetFullPath(path)); p is not null; p = p.Parent)
            if ((Directory.Exists(p.FullName) || File.Exists(p.FullName)) && (File.GetAttributes(p.FullName) & FileAttributes.ReparsePoint) != 0)
                throw new IOException("Runtime directory links are not allowed");
    }

    private static bool Remove(string directory, string parent, string scope)
    {
        if (!CanDelete(directory, parent, scope)) return false;
        try
        {
            var prefix = Path.GetFullPath(directory).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            foreach (var process in Process.GetProcesses())
                using (process)
                {
                    try { if (process.MainModule?.FileName.StartsWith(prefix, StringComparison.OrdinalIgnoreCase) == true) return false; }
                    catch (Exception e) when (e is System.ComponentModel.Win32Exception or InvalidOperationException or NotSupportedException) { }
                }
            var marker = Path.Combine(directory, Marker);
            // Keep the marker until the very end so a locked old file can be
            // retried on the next update instead of becoming an orphan.
            foreach (var file in Directory.EnumerateFiles(directory, "*", SearchOption.AllDirectories))
                if (!string.Equals(file, marker, StringComparison.OrdinalIgnoreCase)) File.Delete(file);
            foreach (var child in Directory.EnumerateDirectories(directory, "*", SearchOption.AllDirectories).OrderByDescending(p => p.Length)) Directory.Delete(child);
            File.Delete(marker); Directory.Delete(directory);
            return true;
        }
        catch { return false; }
    }

    internal static void Cleanup(string scope, string? keepRuntime)
    {
        var parent = scope == RuntimeModeInstaller.Service ? ServiceRoot : UserRoot;
        var keep = keepRuntime is null ? null : Path.GetFullPath(scope == RuntimeModeInstaller.Service ? Path.GetDirectoryName(keepRuntime)! : keepRuntime).TrimEnd(Path.DirectorySeparatorChar);
        CleanupWithin(parent, scope, keep);
    }

    internal static void RemoveEmptyUserRoot()
    {
        if (!Directory.Exists(UserRoot)) return;
        AssertNoLinks(UserRoot);
        if (Directory.EnumerateFileSystemEntries(UserRoot).Any()) return;
        Directory.Delete(UserRoot);
    }

    private static void CleanupWithin(string parent, string scope, string? keep)
    {
        try
        {
            if (!Directory.Exists(parent)) return;
            AssertNoLinks(parent);
            foreach (var directory in Directory.EnumerateDirectories(parent, scope == RuntimeModeInstaller.Service ? "CodexDedicatedProxy-Setup-*" : "*"))
                if (!string.Equals(directory, keep, StringComparison.OrdinalIgnoreCase) && OwnsRoot(directory, parent, scope) && !Remove(directory, parent, scope)) CleanupPending = true;
        }
        catch { CleanupPending = true; } // Cleanup cannot invalidate a committed update.
    }

    internal static void Discard(string runtime, string scope)
    {
        var directory = scope == RuntimeModeInstaller.Service ? Path.GetDirectoryName(runtime)! : runtime;
        var parent = scope == RuntimeModeInstaller.Service ? ServiceRoot : UserRoot;
        if (Directory.Exists(directory) && !Remove(directory, parent, scope)) CleanupPending = true;
    }
}
