using System.IO.Compression;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using CodexProxySetup;

var workspace = Path.GetFullPath(args[0]);
var assets = Path.Combine(workspace, "configurator", "Assets");
var markers = new HashSet<string>(StringComparer.Ordinal);
foreach (var name in new[] { "subscription.json", "subscription-cache.json", "vps-profile.json", "node-profile.json" })
{
    using var document = PrivateStore.Read(name);
    if (document is not null) Collect(document.RootElement);
}
// Also reject personal build paths in shipped code and materials.
markers.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
var patterns = markers.SelectMany(value => new[] { Encoding.UTF8.GetBytes(value), Encoding.Unicode.GetBytes(value) }).ToArray();
var inspected = 0;
var maxPattern = patterns.Length == 0 ? 1 : patterns.Max(value => value.Length);
Console.WriteLine($"Loaded {markers.Count} private fingerprints without printing their values.");

using (var manifest = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(assets, "runtime-manifest.json"))))
using (var archive = ZipFile.OpenRead(Path.Combine(assets, "runtime.zip")))
{
    var files = manifest.RootElement.GetProperty("files").EnumerateObject().ToDictionary(p => p.Name, p => p.Value.GetString()!);
    if (archive.Entries.Count != 10 || files.Count != 10) throw new InvalidDataException("Runtime file count mismatch");
    foreach (var entry in archive.Entries)
    {
        if (!files.TryGetValue(entry.FullName, out var expected) || Path.GetFileName(entry.FullName) != entry.FullName)
            throw new InvalidDataException("Unexpected runtime file");
        using (var input = entry.Open())
            if (Hash(input) != expected) throw new InvalidDataException("Runtime hash mismatch");
        using var scan = entry.Open(); Scan(scan);
    }
}
using (var archive = ZipFile.OpenRead(Path.Combine(assets, "notices.zip"))) InspectArchive(archive, 0);
Console.WriteLine($"Verified runtime hashes and inspected {inspected} decompressed files. Private fingerprint matches: 0.");

if (args.Length > 1)
{
    var executable = Path.GetFullPath(args[1]);
    using var input = File.OpenRead(executable);
    var signature = Convert.FromHexString("8B1202B96A612038727B930214D7A03213F5B9E6EFAE3318EE3B2DCE24B36AAE");
    var position = FindSignature(input, signature);
    if (position < 8) throw new InvalidDataException("Single-file bundle signature missing");
    using var reader = new BinaryReader(input, Encoding.UTF8, true);
    input.Position = position - 8;
    var bundleHeader = reader.ReadInt64();
    input.Position = bundleHeader;
    var major = reader.ReadUInt32(); var minor = reader.ReadUInt32(); var count = reader.ReadInt32();
    if (major != 6 || minor != 0 || count < 50 || count > 1000) throw new InvalidDataException("Unexpected .NET bundle format");
    reader.ReadString();
    for (var i = 0; i < 5; i++) reader.ReadInt64();
    var entries = new Dictionary<string, (long Offset, long Size)>();
    for (var i = 0; i < count; i++)
    {
        var offset = reader.ReadInt64(); var size = reader.ReadInt64(); var compressed = reader.ReadInt64();
        reader.ReadByte(); var name = reader.ReadString();
        if (compressed != 0 || offset < 0 || size < 0 || offset > input.Length - size ||
            Path.IsPathRooted(name) || name.Contains(':') || name.Split('/', '\\').Any(part => part is "" or "." or "..") ||
            name.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase) ||
            !(name.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
            throw new InvalidDataException("Unexpected bundled component");
        entries.Add(name, (offset, size));
    }
    foreach (var required in new[] { "CodexProxySetup.dll", "YamlDotNet.dll", "System.Windows.Forms.dll", "System.Private.CoreLib.dll", "CodexProxySetup.runtimeconfig.json" })
        if (!entries.ContainsKey(required)) throw new InvalidDataException("Required self-contained component missing: " + required);
    // Windows singlefilehost statically links the native runtime and host components.
    // Compare that host with the published prefix, masking only the bundle pointer.
    using (var host = File.OpenRead(Path.Combine(workspace, "configurator", "obj", "Release", "net8.0-windows", "win-x64", "singlefilehost.exe")))
    {
        if (host.Length > bundleHeader || position >= host.Length ||
            HashMasked(host, host.Length, position - 8) != HashMasked(input, host.Length, position - 8))
            throw new InvalidDataException("Self-contained native host mismatch");
    }
    var configEntry = entries["CodexProxySetup.runtimeconfig.json"];
    using (var segment = new SegmentStream(input, configEntry.Offset, configEntry.Size))
    using (var config = JsonDocument.Parse(segment))
    {
        var options = config.RootElement.GetProperty("runtimeOptions");
        if (options.TryGetProperty("frameworks", out _) || options.TryGetProperty("framework", out _) ||
            !options.TryGetProperty("includedFrameworks", out var frameworks) || frameworks.GetArrayLength() != 2)
            throw new InvalidDataException("Published application depends on an external .NET framework");
    }
    var assembly = entries["CodexProxySetup.dll"];
    using (var segment = new SegmentStream(input, assembly.Offset, assembly.Size))
    using (var built = File.OpenRead(Path.Combine(workspace, "configurator", "bin", "Release", "net8.0-windows", "win-x64", "CodexProxySetup.dll")))
        if (Hash(segment) != Hash(built)) throw new InvalidDataException("Published assembly differs from built assembly");
    var dllPath = Path.Combine(workspace, "configurator", "bin", "Release", "net8.0-windows", "win-x64", "CodexProxySetup.dll");
    using (var dll = File.OpenRead(dllPath))
    using (var pe = new PEReader(dll, PEStreamOptions.LeaveOpen))
    {
        var metadata = pe.GetMetadataReader();
        var rva = pe.PEHeaders.CorHeader!.ResourcesDirectory.RelativeVirtualAddress;
        var section = pe.PEHeaders.SectionHeaders.Single(s => rva >= s.VirtualAddress && rva < s.VirtualAddress + Math.Max(s.VirtualSize, s.SizeOfRawData));
        var resourceBase = (long)section.PointerToRawData + rva - section.VirtualAddress;
        var found = new HashSet<string>();
        foreach (var handle in metadata.ManifestResources)
        {
            var resource = metadata.GetManifestResource(handle); var name = metadata.GetString(resource.Name);
            if (!resource.Implementation.IsNil || !new[] { "runtime.zip", "runtime-manifest.json", "notices.zip", "configurator-ui.html" }.Contains(name))
                throw new InvalidDataException("Unexpected embedded resource");
            dll.Position = resourceBase + resource.Offset;
            using var resourceReader = new BinaryReader(dll, Encoding.UTF8, true);
            var size = resourceReader.ReadUInt32();
            using var segment = new SegmentStream(dll, dll.Position, size);
            var sourcePath = name == "configurator-ui.html"
                ? Path.Combine(workspace, "web-preview", "dist", "index.html")
                : Path.Combine(assets, name);
            using var source = File.OpenRead(sourcePath);
            if (Hash(segment) != Hash(source)) throw new InvalidDataException("Embedded resource differs from verified asset");
            found.Add(name);
        }
        if (found.Count != 4) throw new InvalidDataException("Embedded assets missing");
    }
    input.Position = 0; Scan(input);
    var only = Directory.GetFiles(Path.GetDirectoryName(executable)!, "*", SearchOption.AllDirectories);
    if (only.Length != 1 || only[0] != executable) throw new InvalidDataException("Publish directory contains loose files");
    var result = new { state = "verified", executable_bytes = input.Length, sha256 = HashFile(executable), bundle_components = count,
        runtime_components = 10, private_fingerprint_matches = 0, tests_run = false };
    File.WriteAllText(Path.Combine(workspace, "runtime", "public-final-audit.json"), JsonSerializer.Serialize(result));
    Console.WriteLine(JsonSerializer.Serialize(result));
}

void Collect(JsonElement value, string? key = null)
{
    if (value.ValueKind == JsonValueKind.Object)
        foreach (var property in value.EnumerateObject()) Collect(property.Value, property.Name);
    else if (value.ValueKind == JsonValueKind.Array)
        foreach (var child in value.EnumerateArray()) Collect(child, key);
    else if (value.ValueKind == JsonValueKind.String && key is not null &&
        new[] { "url", "subscription", "server", "password", "uuid", "username", "sni", "servername", "Host", "public_address", "address", "public-key", "path" }.Contains(key))
    {
        var text = value.GetString()!;
        if (text.Length >= 8 && text is not "localhost" and not "127.0.0.1") markers.Add(text);
        if (key is "url" or "subscription" && Uri.TryCreate(text, UriKind.Absolute, out var uri))
        {
            if (uri.Host.Length >= 8) markers.Add(uri.Host);
            foreach (var part in uri.AbsolutePath.Split('/')) if (part.Length >= 12) markers.Add(part);
        }
    }
}
void InspectArchive(ZipArchive archive, int depth)
{
    if (depth > 3) throw new InvalidDataException("Unexpected nested source archive depth");
    foreach (var entry in archive.Entries)
    {
        if (entry.FullName.EndsWith('/')) continue;
        using (var input = entry.Open()) Scan(input);
        if (entry.FullName.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
        {
            using var bytes = new MemoryStream(); using var input = entry.Open(); input.CopyTo(bytes); bytes.Position = 0;
            using var child = new ZipArchive(bytes, ZipArchiveMode.Read); InspectArchive(child, depth + 1);
        }
    }
}
void Scan(Stream input)
{
    var buffer = new byte[1024 * 1024 + maxPattern]; var carry = 0;
    int read;
    while ((read = input.Read(buffer, carry, buffer.Length - carry)) != 0)
    {
        var length = carry + read;
        foreach (var pattern in patterns)
            if (buffer.AsSpan(0, length).IndexOf(pattern) >= 0) throw new InvalidDataException("Private fingerprint found; values suppressed");
        carry = Math.Min(maxPattern - 1, length);
        buffer.AsSpan(length - carry, carry).CopyTo(buffer);
    }
    inspected++;
}
static string Hash(Stream input) => Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
static string HashFile(string path) { using var input = File.OpenRead(path); return Hash(input); }
static string HashMasked(Stream input, long length, long maskedOffset)
{
    input.Position = 0; long processed = 0; var buffer = new byte[131072];
    using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    while (processed < length)
    {
        var read = input.Read(buffer, 0, (int)Math.Min(buffer.Length, length - processed));
        if (read == 0) throw new EndOfStreamException();
        var start = Math.Max(processed, maskedOffset); var end = Math.Min(processed + read, maskedOffset + 8);
        if (end > start) Array.Clear(buffer, (int)(start - processed), (int)(end - start));
        hash.AppendData(buffer, 0, read); processed += read;
    }
    return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
}
static long FindSignature(Stream input, byte[] signature)
{
    var buffer = new byte[1024 * 1024 + signature.Length]; var carry = 0; long total = 0;
    int read;
    while ((read = input.Read(buffer, carry, buffer.Length - carry)) != 0)
    {
        var length = carry + read;
        var found = buffer.AsSpan(0, length).IndexOf(signature);
        if (found >= 0) return total - carry + found;
        total += read; carry = Math.Min(signature.Length - 1, length);
        buffer.AsSpan(length - carry, carry).CopyTo(buffer);
    }
    return -1;
}

sealed class SegmentStream(Stream source, long offset, long length) : Stream
{
    private long position;
    public override bool CanRead => true; public override bool CanSeek => false; public override bool CanWrite => false;
    public override long Length => length; public override long Position { get => position; set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int start, int count)
    { source.Position = offset + position; var read = source.Read(buffer, start, (int)Math.Min(count, length - position)); position += read; return read; }
    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
