using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CodexProxySetup;

internal static class DesktopLocator
{
    internal const string PackageFamily = "OpenAI.Codex_2p2nqsd0c76g0";

    internal static string? Find()
    {
        var candidates = new List<(Version Version, string Path)>();
        foreach (var path in RegisteredPackageExecutables()) AddCandidate(candidates, path);
        foreach (var path in RunningPackageExecutables()) AddCandidate(candidates, path);
        foreach (var root in WindowsAppsRoots())
        {
            try
            {
                foreach (var package in Directory.EnumerateDirectories(root, "OpenAI.Codex_*"))
                    AddCandidate(candidates, Path.Combine(package, "app", "ChatGPT.exe"));
            }
            catch (UnauthorizedAccessException) { }
            catch (DirectoryNotFoundException) { }
        }
        return candidates.OrderByDescending(candidate => candidate.Version).FirstOrDefault().Path;
    }

    private static IEnumerable<string> RegisteredPackageExecutables()
    {
        var executables = new List<string>();
        uint count = 0, length = 0;
        if (GetPackagesByPackageFamily(PackageFamily, ref count, IntPtr.Zero, ref length, IntPtr.Zero) != 122 || count == 0)
            return executables;
        var names = Marshal.AllocHGlobal(checked((int)count * IntPtr.Size));
        var buffer = Marshal.AllocHGlobal(checked((int)length * 2));
        try
        {
            if (GetPackagesByPackageFamily(PackageFamily, ref count, names, ref length, buffer) == 0)
            {
                for (var i = 0; i < count; i++)
                {
                    var fullName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(names, i * IntPtr.Size));
                    if (fullName is null) continue;
                    var root = PackagePath(fullName);
                    if (root is not null) executables.Add(Path.Combine(root, "app", "ChatGPT.exe"));
                }
            }
        }
        finally { Marshal.FreeHGlobal(names); Marshal.FreeHGlobal(buffer); }
        return executables;
    }

    private static string? PackagePath(string fullName)
    {
        uint size = 0;
        if (GetPackagePathByFullName(fullName, ref size, IntPtr.Zero) != 122 || size == 0) return null;
        var memory = Marshal.AllocHGlobal(checked((int)size * 2));
        try
        {
            return GetPackagePathByFullName(fullName, ref size, memory) == 0
                ? Marshal.PtrToStringUni(memory)
                : null;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    private static IEnumerable<string> RunningPackageExecutables()
    {
        var executables = new List<string>();
        foreach (var process in System.Diagnostics.Process.GetProcessesByName("ChatGPT"))
        {
            try
            {
                if (process.MainModule?.FileName is { } path) executables.Add(path);
            }
            catch (InvalidOperationException) { }
            catch (System.ComponentModel.Win32Exception) { }
            finally { process.Dispose(); }
        }
        return executables;
    }

    private static IEnumerable<string> WindowsAppsRoots()
    {
        var roots = new List<string>();
        foreach (var variable in new[] { "ProgramW6432", "ProgramFiles" })
        {
            var value = Environment.GetEnvironmentVariable(variable);
            if (!string.IsNullOrWhiteSpace(value))
            {
                var root = Path.Combine(value, "WindowsApps");
                if (!roots.Any(existing => existing.Equals(root, StringComparison.OrdinalIgnoreCase))) roots.Add(root);
            }
        }
        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
        if (!roots.Any(existing => existing.Equals(fallback, StringComparison.OrdinalIgnoreCase))) roots.Add(fallback);
        return roots;
    }

    private static void AddCandidate(List<(Version Version, string Path)> candidates, string? executable)
    {
        if (executable is null || !File.Exists(executable) ||
            !Path.GetFileName(executable).Equals("ChatGPT.exe", StringComparison.OrdinalIgnoreCase)) return;
        var appDirectory = Directory.GetParent(executable);
        var packageDirectory = appDirectory?.Parent;
        if (packageDirectory is null || !WindowsAppsRoots().Any(root => IsUnder(packageDirectory.FullName, root))) return;
        var parts = packageDirectory.Name.Split('_');
        if (parts.Length != 4 || !parts[0].Equals("OpenAI.Codex", StringComparison.OrdinalIgnoreCase) ||
            !parts[2].Equals("x64", StringComparison.OrdinalIgnoreCase) || parts[3] != "2p2nqsd0c76g0" ||
            !Version.TryParse(parts[1], out var version)) return;
        if (!candidates.Any(candidate => candidate.Path.Equals(executable, StringComparison.OrdinalIgnoreCase)))
            candidates.Add((version, executable));
    }

    private static bool IsUnder(string path, string root)
    {
        var normalizedPath = Path.GetFullPath(path).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        return normalizedPath.Equals(normalizedRoot, StringComparison.OrdinalIgnoreCase) ||
            normalizedPath.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }

    internal static void Verify(string path)
    {
        if (!File.Exists(path) || !Path.GetFileName(path).Equals("ChatGPT.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("请选择官方桌面的 ChatGPT.exe。");
        var fileInfo = new TrustFile { Size = (uint)Marshal.SizeOf<TrustFile>(), FilePath = path };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<TrustFile>());
        try
        {
            Marshal.StructureToPtr(fileInfo, pointer, false);
            var data = new TrustData { Size = (uint)Marshal.SizeOf<TrustData>(), UiChoice = 2, UnionChoice = 1, File = pointer, ProviderFlags = 0x1000 };
            var action = new Guid("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");
            if (WinVerifyTrust(new IntPtr(-1), ref action, ref data) != 0)
                throw new InvalidOperationException("这个桌面文件的签名无效。");
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            if (!certificate.Subject.Contains("OpenAI", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("这个桌面文件不是 OpenAI 发布的官方版本。");
        }
        finally { Marshal.DestroyStructure<TrustFile>(pointer); Marshal.FreeHGlobal(pointer); }
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackagesByPackageFamily(string family, ref uint count, IntPtr names, ref uint length, IntPtr buffer);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern int GetPackagePathByFullName(string fullName, ref uint length, IntPtr path);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct TrustFile { public uint Size; [MarshalAs(UnmanagedType.LPWStr)] public string FilePath; public IntPtr File, KnownSubject; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TrustData
    {
        public uint Size; public IntPtr PolicyCallback, SipClient;
        public uint UiChoice, RevocationChecks, UnionChoice; public IntPtr File;
        public uint StateAction; public IntPtr StateData, UrlReference;
        public uint ProviderFlags, UiContext; public IntPtr SignatureSettings;
    }
    [DllImport("wintrust.dll", ExactSpelling = true)]
    private static extern int WinVerifyTrust(IntPtr window, ref Guid action, ref TrustData data);
}
