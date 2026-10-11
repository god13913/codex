using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace CodexProxySetup;

internal static class PrivateStore
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true
    };

    internal static string Home => Environment.GetEnvironmentVariable("CODEX_HOME") is { Length: > 0 } home
        ? Path.GetFullPath(home) : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".codex");
    internal static string DirectoryPath => Path.Combine(Home, "dedicated-proxy");

    internal static void SecureDirectory(string path)
    {
        var directory = System.IO.Directory.CreateDirectory(path);
        var acl = new DirectorySecurity();
        acl.SetAccessRuleProtection(true, false);
        foreach (var sid in new[] { WindowsIdentity.GetCurrent().User!, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null) })
            acl.AddAccessRule(new FileSystemAccessRule(sid, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));
        directory.SetAccessControl(acl);
    }

    internal static void Write(string name, object value, bool encrypted = true)
    {
        SecureDirectory(DirectoryPath);
        var plain = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        byte[] bytes;
        try
        {
            bytes = encrypted ? JsonSerializer.SerializeToUtf8Bytes(new Envelope("codex-dpapi-v1", Convert.ToBase64String(Crypt(plain, true))), Json) : plain.ToArray();
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(plain); }
        try { WriteBytes(name, bytes); }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void WriteBytes(string name, byte[] bytes)
    {
        var limit = name switch
        {
            "subscription.json" or "vps-profile.json" => 16 * 1024,
            "node-profile.json" => 64 * 1024,
            "subscription-cache.json" => 4 * 1024 * 1024 + 4096,
            _ => 8 * 1024 * 1024
        };
        if (bytes.Length > limit) throw new InvalidOperationException("配置超过运行组件的大小限制，请使用较短的订阅链接或精简节点配置。");
        var path = Path.Combine(DirectoryPath, name);
        var temporary = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
        using (var file = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.WriteThrough))
        { file.Write(bytes); file.Flush(true); }
        File.Move(temporary, path, true);
    }

    internal static void MigrateCredentialFile(string name)
    {
        var path = Path.Combine(DirectoryPath, name);
        if (!File.Exists(path)) return;
        if (new FileInfo(path).Length > 8 * 1024 * 1024) throw new InvalidOperationException("已有配置文件过大。");
        var bytes = File.ReadAllBytes(path);
        try
        {
            try
            {
                using var value = JsonDocument.Parse(bytes);
                if (value.RootElement.TryGetProperty("format", out var format) && format.GetString() == "codex-dpapi-v1") return;
            }
            catch (JsonException) { }
            SecureDirectory(DirectoryPath);
            var encrypted = JsonSerializer.SerializeToUtf8Bytes(new Envelope("codex-dpapi-v1", Convert.ToBase64String(Crypt(bytes, true))), Json);
            WriteBytes(name, encrypted);
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static JsonDocument? Read(string name)
    {
        var path = Path.Combine(DirectoryPath, name);
        if (!File.Exists(path)) return null;
        if (new FileInfo(path).Length > 8 * 1024 * 1024) throw new InvalidOperationException("配置文件过大。");
        var bytes = File.ReadAllBytes(path);
        try
        {
            using var wrapper = JsonDocument.Parse(bytes);
            if (wrapper.RootElement.TryGetProperty("format", out var format) && format.GetString() == "codex-dpapi-v1")
            {
                var decrypted = Crypt(Convert.FromBase64String(wrapper.RootElement.GetProperty("data").GetString()!), false);
                try { return JsonDocument.Parse(System.Text.Encoding.UTF8.GetString(decrypted)); }
                finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(decrypted); }
            }
            return JsonDocument.Parse(System.Text.Encoding.UTF8.GetString(bytes));
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    internal static JsonDocument ReadProtectedFile(string path)
    {
        if (new FileInfo(path).Length > 64 * 1024) throw new InvalidOperationException("CLI 会话信息无效。");
        var bytes = File.ReadAllBytes(path);
        try
        {
            using var wrapper = JsonDocument.Parse(bytes);
            if (wrapper.RootElement.GetProperty("format").GetString() != "codex-dpapi-v1")
                throw new InvalidOperationException("CLI 会话信息无效。");
            var decrypted = Crypt(Convert.FromBase64String(wrapper.RootElement.GetProperty("data").GetString()!), false);
            try { return JsonDocument.Parse(decrypted); }
            finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(decrypted); }
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(bytes); }
    }

    private sealed record Envelope(string Format, string Data);
    [StructLayout(LayoutKind.Sequential)] private struct Blob { internal int Length; internal IntPtr Data; }
    [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern bool CryptProtectData(ref Blob input, string? description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("crypt32.dll", SetLastError = true, ExactSpelling = true)]
    private static extern bool CryptUnprotectData(ref Blob input, IntPtr description, IntPtr entropy, IntPtr reserved, IntPtr prompt, int flags, out Blob output);
    [DllImport("kernel32.dll", ExactSpelling = true)] private static extern IntPtr LocalFree(IntPtr memory);

    private static byte[] Crypt(byte[] bytes, bool encrypt)
    {
        var memory = Marshal.AllocHGlobal(bytes.Length);
        var input = new Blob { Length = bytes.Length, Data = memory };
        try
        {
            Marshal.Copy(bytes, 0, memory, bytes.Length);
            Blob output;
            var ok = encrypt ? CryptProtectData(ref input, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output)
                : CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 1, out output);
            if (!ok) throw new InvalidOperationException("无法访问当前 Windows 用户的加密配置。");
            try { var result = new byte[output.Length]; Marshal.Copy(output.Data, result, 0, result.Length); return result; }
            finally { LocalFree(output.Data); }
        }
        finally
        {
            for (var i = 0; i < bytes.Length; i++) Marshal.WriteByte(memory, i, 0);
            Marshal.FreeHGlobal(memory);
        }
    }
}
