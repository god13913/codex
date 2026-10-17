using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CodexProxySetup;

// The elevated entry point only runs embedded, hash-checked runtime code. No
// command, node, password, or executable supplied by the UI is elevated.
internal static class RuntimeModeInstaller
{
    internal const string Service = "service", Desktop = "desktop";
    private const string ServiceName = "CodexDedicatedProxy";
    private static string Sid => WindowsIdentity.GetCurrent().User!.Value;
    private sealed record Installed(string Binary, uint Start, uint State, uint Pid);

    internal static string Normalize(string mode) => mode is Service or Desktop ? mode
        : throw new InvalidOperationException("请选择 Windows 服务或不安装服务模式。");

    internal static string CurrentMode()
    {
        // SCM is authoritative, including installations made by the old manual script.
        if (Query() is not null) return Service;
        using var meta = PrivateStore.Read("configurator.json");
        var savedMode = meta?.RootElement.TryGetProperty("installation_mode", out var mode) == true ? mode.GetString() : null;
        var hadRuntime = meta?.RootElement.TryGetProperty("runtime_directory", out var runtime) == true && !string.IsNullOrWhiteSpace(runtime.GetString());
        return ModeWithoutService(savedMode, hadRuntime);
    }

    private static string ModeWithoutService(string? savedMode, bool hadRuntime) => savedMode is Service or Desktop ? savedMode
        : hadRuntime ? Desktop : Service; // Keep pre-selector installs in their existing no-service mode.

    internal static async Task ApplyAsync(string mode, string desktop, string runtime)
    {
        Normalize(mode);
        if (mode == Service || Query() is not null || ManagedRuntime.HasServiceGenerations())
        {
            AssertDesktopClosed();
            await ElevateAsync(mode, desktop, runtime);
        }
        else Commit(runtime, Desktop, desktop);
        // The elevated child's process environment does not propagate back to its parent.
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH",
            Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User), EnvironmentVariableTarget.Process);
        // Only after commit/readiness: old runtime generations remain available
        // throughout rollback. User-writable trees are cleaned unelevated.
        ManagedRuntime.Cleanup(Desktop, mode == Desktop ? runtime : null);
    }

    internal static void Preflight(string mode)
    {
        Normalize(mode);
        ManagedRuntime.CleanupPending = false;
        AssertDesktopClosed(); // Updates must not remove a runtime in use by the desktop.
    }

    internal static async Task DisableAsync()
    {
        using var update = ManagedRuntime.AcquireUpdate();
        if (Query() is not null)
        {
            AssertDesktopClosed();
            await ElevateAsync("disable", "", "");
        }
        else
        {
            // A missing or corrupt settings file must not prevent returning to
            // the official CLI. Service removal still has its own transaction.
            try { SetEnabled(false); }
            finally { RuntimeInstaller.ClearCliOverride(); }
            return;
        }
        RuntimeInstaller.ClearCliOverride();
    }

    internal static async Task UninstallAsync()
    {
        using var update = ManagedRuntime.AcquireUpdate();
        ManagedRuntime.CleanupPending = false;
        var hasService = Query() is not null || ManagedRuntime.HasServiceGenerations();
        AssertDesktopClosed();
        if (hasService)
        {
            await ElevateAsync("uninstall", "", "");
            if (ManagedRuntime.CleanupPending)
                throw new InvalidOperationException("服务已移除，但还有文件被占用。请完全退出桌面后再卸载一次。");
            if (Query() is not null)
                throw new InvalidOperationException("Windows 服务注册项仍然存在，请再次卸载。");
        }

        RuntimeInstaller.ClearCliOverride();
        ManagedRuntime.Cleanup(Desktop, null);
        if (ManagedRuntime.CleanupPending)
            throw new InvalidOperationException("服务已移除，但还有文件被占用。请完全退出桌面后再卸载一次。");
        ManagedRuntime.RemoveEmptyUserRoot();
        PrivateStore.DeleteDedicatedProxy();
    }

    private static async Task ElevateAsync(string mode, string desktop, string runtime)
    {
        var start = new ProcessStartInfo(Environment.ProcessPath!) { UseShellExecute = true, Verb = "runas", WindowStyle = ProcessWindowStyle.Hidden };
        foreach (var arg in new[] { "--configure-runtime", mode, PrivateStore.Home, desktop, runtime, Sid }) start.ArgumentList.Add(arg);
        try
        {
            using var child = Process.Start(start) ?? throw new InvalidOperationException("无法启动服务安装程序，请重试或重启电脑。");
            await child.WaitForExitAsync();
            if (child.ExitCode == 16) ManagedRuntime.CleanupPending = true;
            else if (child.ExitCode != 0) throw new InvalidOperationException(child.ExitCode switch
            {
                10 => "请在管理员授权提示中使用当前账户同意，不要切换到其他账户。",
                11 => "请完全退出 Codex 桌面后再切换或停用服务。",
                12 => "同名服务的路径、权限或所属账户不匹配，已停止修改。",
                14 => "服务尚未确认转发就绪；已尝试还原原服务和 CLI 设置。",
                15 => "安装未完成，且原服务未能自动恢复。请保留当前文件并检查 Windows 服务状态。",
                _ => "服务配置未完成；原配置已保留。请检查磁盘空间和管理员权限。"
            });
        }
        catch (Win32Exception e) when (e.NativeErrorCode == 1223)
        { throw new InvalidOperationException("已取消管理员授权，未切换运行模式。"); }
    }

    internal static async Task<int> RunElevatedAsync(string[] args)
    {
        if (args.Length != 6 || args[5] != Sid || !new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator)) return 10;
        var mode = args[1];
        if (mode != "disable" && mode != "uninstall") Normalize(mode);
        Environment.SetEnvironmentVariable("CODEX_HOME", Path.GetFullPath(args[2]));
        try { AssertDesktopClosed(); } catch { return 11; }
        Installed? before;
        try { before = Query(); if (before is not null) ValidateOwned(before); } catch { return 12; }
        var oldUser = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User);
        var oldProcess = Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.Process);
        var snapshots = Snapshot();
        var changed = false;
        var created = false;
        string? preparedRuntime = null;
        try
        {
            var runtime = args[4];
            if (mode == Service)
            {
                // Extract directly from this installer after securing the destination.
                runtime = await RuntimeInstaller.InstallProtectedAsync();
                preparedRuntime = runtime;
                RuntimeInstaller.RegisterDesktop(runtime, args[3]);
                var root = Path.GetDirectoryName(runtime)!;
                Protect(Path.Combine(root, "home"), false);
                Protect(Path.Combine(root, "home", "dedicated-proxy"), false);
                var prepare = new ProcessStartInfo(Path.Combine(runtime, "codex.exe"))
                { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
                prepare.ArgumentList.Add("proxy"); prepare.ArgumentList.Add("service-prepare");
                using var process = Process.Start(prepare)!;
                var stdout = process.StandardOutput.ReadToEndAsync();
                var stderr = process.StandardError.ReadToEndAsync();
                await process.WaitForExitAsync();
                var output = await stdout; await stderr; // Never persist credentials or native output.
                if (process.ExitCode != 0 || !output.Contains("\"service_prepared\":true", StringComparison.Ordinal))
                    throw new InvalidOperationException("service preparation failed");
            }
            else if (mode == Desktop)
            {
                // Do not execute an unelevated, user-writable runtime as administrator.
                await RuntimeInstaller.VerifyInstalledAsync(runtime);
                DesktopLocator.Verify(args[3]);
            }
            if (before is not null) { changed = true; Stop(); }
            if (mode == Service)
            {
                var binary = "\"" + Path.Combine(runtime, "codex-proxy-service.exe") + "\"";
                if (before is null) { Create(binary); created = true; changed = true; }
                else Configure(binary, 2);
                Start();
                await WaitReadyAsync(runtime);
                Commit(runtime, mode, args[3]);
                Sc("failure", ServiceName, "reset=", "86400", "actions=", "restart/5000/restart/15000/restart/30000");
                Sc("failureflag", ServiceName, "1");
            }
            else
            {
                if (mode == Desktop) Commit(runtime, mode, args[3]);
                else { SetEnabled(false); RuntimeInstaller.ClearCliOverride(); }
                // Delete last: no fallible commit follows removal.
                if (before is not null)
                {
                    Sc("delete", ServiceName);
                    WaitForServiceRemoval();
                }
            }
            // Cleanup failure must never roll back an otherwise healthy update.
            // Disable keeps files; a successful apply retains only its current
            // installer-owned runtime. Unmarked manual test installs are kept.
            if (mode == "uninstall") ManagedRuntime.Cleanup(Service, null);
            else if (mode != "disable") ManagedRuntime.Cleanup(Service, mode == Service ? runtime : null);
            return ManagedRuntime.CleanupPending ? 16 : 0;
        }
        catch
        {
            try
            {
                Restore(snapshots);
                SetCli(oldUser, oldProcess);
                if (created) { Stop(); Sc("delete", ServiceName); }
                else if (changed && before is not null)
                {
                    Stop(); Configure(before.Binary, before.Start);
                    if (before.State == 4) Start();
                }
                if (preparedRuntime is not null) ManagedRuntime.Discard(preparedRuntime, Service);
                return changed ? 14 : 13;
            }
            catch { return 15; }
        }
        finally { foreach (var bytes in snapshots.Values) if (bytes is not null) System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static Dictionary<string, byte[]?> Snapshot() => new[] { "settings.json", "subscription.json", "subscription-cache.json", "node-profile.json", "vps-profile.json", "configurator.json" }
        .ToDictionary(n => n, n => File.Exists(Path.Combine(PrivateStore.DirectoryPath, n)) ? File.ReadAllBytes(Path.Combine(PrivateStore.DirectoryPath, n)) : null);

    internal static void Restore(Dictionary<string, byte[]?> snapshot)
    {
        foreach (var (name, bytes) in snapshot)
        {
            var path = Path.Combine(PrivateStore.DirectoryPath, name);
            if (bytes is null) File.Delete(path);
            else PrivateStore.RestoreBytes(name, bytes);
        }
    }

    internal static JsonObject ReadObject(string name)
    {
        using var saved = PrivateStore.Read(name);
        return saved is null ? new JsonObject() : JsonNode.Parse(saved.RootElement.GetRawText())!.AsObject();
    }

    internal static void SetEnabled(bool enabled, string? nodeMode = null)
    {
        var settings = ReadObject("settings.json");
        settings["enabled"] = enabled;
        if (nodeMode is not null) settings["mode"] = nodeMode;
        settings["updated_at"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(); settings["last_error"] = null;
        PrivateStore.Write("settings.json", settings, false); // Preserve port, password and DNS options.
    }

    private static void Commit(string runtime, string mode, string desktop)
    {
        var meta = ReadObject("configurator.json");
        meta["runtime_directory"] = runtime; meta["installation_mode"] = mode; meta["desktop_executable"] = desktop;
        PrivateStore.Write("configurator.json", meta);
        SetCli(Path.Combine(runtime, "codex.exe"), Path.Combine(runtime, "codex.exe"));
    }

    private static void SetCli(string? user, string? process)
    {
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH", user, EnvironmentVariableTarget.User);
        Environment.SetEnvironmentVariable("CODEX_CLI_PATH", process, EnvironmentVariableTarget.Process);
        if (Environment.GetEnvironmentVariable("CODEX_CLI_PATH", EnvironmentVariableTarget.User) != user) throw new IOException("CLI selection failed");
        RuntimeInstaller.BroadcastEnvironment();
    }

    private static void AssertDesktopClosed()
    {
        var processes = Process.GetProcessesByName("ChatGPT");
        try { if (processes.Length != 0) throw new InvalidOperationException("请先完全退出 Codex 桌面，再安装、切换或停用后台服务。"); }
        finally { foreach (var p in processes) p.Dispose(); }
    }

    internal static void Protect(string path, bool readable)
    {
        AssertNoLinks(path);
        var directory = Directory.CreateDirectory(path);
        var acl = new DirectorySecurity(); acl.SetAccessRuleProtection(true, false);
        acl.SetOwner(new SecurityIdentifier("S-1-5-32-544"));
        foreach (var sid in new[] { "S-1-5-18", "S-1-5-32-544" })
            acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid), FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        if (readable) acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(Sid), FileSystemRights.ReadAndExecute,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(acl);
    }

    private static void AssertNoLinks(string path)
    {
        for (var p = new DirectoryInfo(path); p is not null; p = p.Parent)
            if ((Directory.Exists(p.FullName) || File.Exists(p.FullName)) && (File.GetAttributes(p.FullName) & FileAttributes.ReparsePoint) != 0) throw new IOException("Directory links are not allowed");
    }

    private static void ValidateOwned(Installed installed)
    {
        var binary = installed.Binary.Trim('"');
        if (!installed.Binary.Equals("\"" + binary + "\"", StringComparison.Ordinal) || Path.GetFileName(binary) != "codex-proxy-service.exe") throw new IOException();
        var root = Path.GetDirectoryName(Path.GetDirectoryName(binary))!;
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles).TrimEnd('\\');
        if (!root.StartsWith(programFiles + "\\", StringComparison.OrdinalIgnoreCase)) throw new IOException();
        AssertNoLinks(binary);
        using var config = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(root, "service.json")));
        if (config.RootElement.GetProperty("schema").GetInt32() != 1 || config.RootElement.GetProperty("owner_sid").GetString() != Sid) throw new IOException();
        // An ordinary user must never be able to replace code launched as SYSTEM.
        foreach (var p in new[] { root, Path.GetDirectoryName(binary)!, binary, Path.Combine(root, "service.json") })
        {
            FileSystemSecurity acl = File.Exists(p) ? new FileInfo(p).GetAccessControl() : new DirectoryInfo(p).GetAccessControl();
            if (acl.GetOwner(typeof(SecurityIdentifier))?.Value is not ("S-1-5-18" or "S-1-5-32-544")) throw new IOException();
            foreach (FileSystemAccessRule rule in acl.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                if (rule.AccessControlType == AccessControlType.Allow && rule.IdentityReference.Value is not ("S-1-5-18" or "S-1-5-32-544") &&
                    (rule.FileSystemRights & (FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0) throw new IOException();
        }
    }

    private static async Task WaitReadyAsync(string runtime)
    {
        for (var i = 0; i < 240; i++)
        {
            var service = Query();
            var path = Path.Combine(Path.GetDirectoryName(runtime)!, "ready.json");
            if (service?.State == 4 && File.Exists(path))
            {
                using var ready = JsonDocument.Parse(File.ReadAllBytes(path)); var r = ready.RootElement;
                if (r.GetProperty("forwarding_ready").GetBoolean() && r.GetProperty("firewall_ready").GetBoolean() &&
                    r.GetProperty("owner_sid").GetString() == Sid && r.GetProperty("service_pid").GetUInt32() == service.Pid &&
                    r.GetProperty("relay_port").GetInt32() > 0 && string.Equals(r.GetProperty("cli_executable").GetString(), Path.Combine(runtime, "codex.exe"), StringComparison.OrdinalIgnoreCase)) return;
            }
            if (service?.State == 1) throw new IOException("Service stopped before readiness");
            await Task.Delay(250);
        }
        throw new IOException("Service readiness timed out");
    }

    private static void Sc(params string[] args)
    {
        var start = new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "sc.exe"))
        { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (var a in args) start.ArgumentList.Add(a);
        using var p = Process.Start(start)!;
        var stdout = p.StandardOutput.ReadToEndAsync(); var stderr = p.StandardError.ReadToEndAsync();
        p.WaitForExit(); Task.WaitAll(stdout, stderr);
        if (p.ExitCode != 0) throw new IOException("Windows service operation failed: " + p.ExitCode);
    }
    private static void Create(string binary) => Sc("create", ServiceName, "binPath=", binary, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "Codex dedicated proxy");
    private static void Configure(string binary, uint start) => Sc("config", ServiceName, "binPath=", binary, "start=", start == 2 ? "auto" : start == 4 ? "disabled" : "demand");
    private static void Start() { Sc("start", ServiceName); WaitState(4); }
    private static void Stop() { if (Query()?.State is not (null or 1)) { if (Query()?.State != 3) Sc("stop", ServiceName); WaitState(1); } }
    private static void WaitState(uint state)
    {
        for (var i = 0; i < 240; i++) { if (Query()?.State == state) return; Thread.Sleep(250); }
        throw new IOException("Windows service state timed out");
    }

    private static void WaitForServiceRemoval()
    {
        for (var i = 0; i < 120; i++)
        {
            if (Query() is null) return;
            Thread.Sleep(250);
        }
        throw new IOException("Windows service registry entry was not removed in time");
    }

    private static Installed? Query()
    {
        var scm = OpenSCManager(null, null, 1); if (scm == IntPtr.Zero) throw new Win32Exception();
        try
        {
            var service = OpenService(scm, ServiceName, 5);
            if (service == IntPtr.Zero) { if (Marshal.GetLastWin32Error() == 1060) return null; throw new Win32Exception(); }
            try
            {
                QueryServiceConfig(service, IntPtr.Zero, 0, out var bytes);
                var buffer = Marshal.AllocHGlobal(checked((int)bytes));
                try
                {
                    if (!QueryServiceConfig(service, buffer, bytes, out _) || !QueryServiceStatusEx(service, 0, out var status, (uint)Marshal.SizeOf<ServiceStatus>(), out _)) throw new Win32Exception();
                    var config = Marshal.PtrToStructure<ServiceConfig>(buffer);
                    if (Marshal.PtrToStringUni(config.Account) != "LocalSystem") throw new IOException("Unexpected service account");
                    return new Installed(Marshal.PtrToStringUni(config.Binary)!, config.Start, status.State, status.Pid);
                }
                finally { Marshal.FreeHGlobal(buffer); }
            }
            finally { CloseServiceHandle(service); }
        }
        finally { CloseServiceHandle(scm); }
    }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceConfig { public uint Type, Start, Error; public IntPtr Binary, Group; public uint Tag; public IntPtr Dependencies, Account, Display; }
    [StructLayout(LayoutKind.Sequential)] private struct ServiceStatus { public uint Type, State, Controls, Win32Exit, ServiceExit, Checkpoint, WaitHint, Pid, Flags; }
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenSCManager(string? machine, string? database, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern IntPtr OpenService(IntPtr scm, string name, uint access);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)] private static extern bool QueryServiceConfig(IntPtr service, IntPtr config, uint size, out uint needed);
    [DllImport("advapi32.dll", SetLastError = true)] private static extern bool QueryServiceStatusEx(IntPtr service, int level, out ServiceStatus status, uint size, out uint needed);
    [DllImport("advapi32.dll")] private static extern bool CloseServiceHandle(IntPtr handle);
}
