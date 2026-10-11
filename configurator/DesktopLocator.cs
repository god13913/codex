using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CodexProxySetup;

internal static class DesktopLocator
{
    internal static string? Find()
    {
        uint count = 0, length = 0;
        if (GetPackagesByPackageFamily("OpenAI.Codex_2p2nqsd0c76g0", ref count, IntPtr.Zero, ref length, IntPtr.Zero) != 122 || count == 0) return null;
        var names = Marshal.AllocHGlobal(checked((int)count * IntPtr.Size));
        var buffer = Marshal.AllocHGlobal(checked((int)length * 2));
        var paths = new List<string>();
        try
        {
            if (GetPackagesByPackageFamily("OpenAI.Codex_2p2nqsd0c76g0", ref count, names, ref length, buffer) != 0) return null;
            for (var i = 0; i < count; i++)
            {
                var fullName = Marshal.PtrToStringUni(Marshal.ReadIntPtr(names, i * IntPtr.Size));
                if (fullName is null || !fullName.Contains("_x64_", StringComparison.Ordinal)) continue;
                uint size = 0;
                if (GetPackagePathByFullName(fullName, ref size, IntPtr.Zero) != 122) continue;
                var memory = Marshal.AllocHGlobal(checked((int)size * 2));
                try
                {
                    if (GetPackagePathByFullName(fullName, ref size, memory) == 0 && Marshal.PtrToStringUni(memory) is { } root)
                    {
                        var exe = Path.Combine(root, "app", "ChatGPT.exe");
                        if (File.Exists(exe)) paths.Add(exe);
                    }
                }
                finally { Marshal.FreeHGlobal(memory); }
            }
        }
        finally { Marshal.FreeHGlobal(names); Marshal.FreeHGlobal(buffer); }
        return paths.OrderByDescending(path =>
        {
            var name = new DirectoryInfo(Path.GetDirectoryName(Path.GetDirectoryName(path))!).Name;
            return Version.TryParse(name.Split('_').ElementAtOrDefault(1), out var version) ? version : new Version();
        }).FirstOrDefault();
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
                throw new InvalidOperationException("桌面文件的发布者签名无效。");
            using var certificate = new X509Certificate2(X509Certificate.CreateFromSignedFile(path));
            if (!certificate.Subject.Contains("OpenAI", StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("这个桌面文件的发布者不是 OpenAI。");
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
