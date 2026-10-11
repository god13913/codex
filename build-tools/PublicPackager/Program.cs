using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

if (args.Length != 2) throw new ArgumentException("Usage: PublicPackager <workspace> <compiled-release-directory>");
var workspace = Path.GetFullPath(args[0]);
var compiledRelease = Path.GetFullPath(args[1]);
var staged = Path.Combine(workspace, "runtime", "public-runtime");
var assets = Path.Combine(workspace, "configurator", "Assets");
Directory.CreateDirectory(assets);
using (var state = JsonDocument.Parse(File.ReadAllBytes(Path.Combine(staged, "build-result.json"))))
    if (!state.RootElement.GetProperty("success").GetBoolean() || state.RootElement.GetProperty("stage").GetString() != "Release")
        throw new InvalidOperationException("Release build is not complete");
var binaries = new[] { "codex", "codex-code-mode-host", "codex-windows-sandbox-setup", "codex-windows-sandbox-service", "codex-command-runner" };
var files = binaries.Select(name => name + ".exe").Concat(new[] { "codex-mihomo.exe", "ProxyBridge.dll", "WinDivert.dll", "WinDivert64.sys", "codex-dedicated-proxy.distribution" }).ToArray();
string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant(); }
foreach (var binary in binaries)
    if (Hash(Path.Combine(staged, binary + ".exe")) != Hash(Path.Combine(compiledRelease, binary + ".exe")))
        throw new InvalidOperationException("Copied compiled binary mismatch: " + binary);
if (Hash(Path.Combine(staged, "codex-mihomo.exe")) != "3c107d54ef1b895e4980b53f517d52f3c1137101fa2637347c9ce343fc50d7b2" ||
    Hash(Path.Combine(staged, "WinDivert.dll")) != "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2" ||
    Hash(Path.Combine(staged, "WinDivert64.sys")) != "8da085332782708d8767bcace5327a6ec7283c17cfb85e40b03cd2323a90ddc2")
    throw new InvalidOperationException("Pinned runtime asset mismatch");
var hashes = files.ToDictionary(name => name, name => Hash(Path.Combine(staged, name)));
var id = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", hashes.OrderBy(p => p.Key, StringComparer.Ordinal).Select(p => p.Key + ":" + p.Value))))).ToLowerInvariant()[..16];
File.WriteAllText(Path.Combine(assets, "runtime-manifest.json"), JsonSerializer.Serialize(new { bundle_id = id, files = hashes }));
Console.WriteLine("Verified compiled runtime; packaging " + files.Length + " required components.");
using (var zip = new ZipArchive(new FileStream(Path.Combine(assets, "runtime.zip"), FileMode.Create, FileAccess.ReadWrite), ZipArchiveMode.Create))
    foreach (var name in files) zip.CreateEntryFromFile(Path.Combine(staged, name), name, CompressionLevel.SmallestSize);
Console.WriteLine("Runtime archive created.");
var materials = new Dictionary<string, string>();
foreach (var name in new[] { "LICENSE-Codex.txt", "NOTICE-Codex.txt", "LICENSE-Mihomo.txt", "LICENSE-ProxyBridge.txt", "WinDivert-LGPL.txt", "mihomo-v1.19.32-source.zip", "ProxyBridge-source.zip", "WinDivert-v2.2.2-source.zip" })
    materials[name] = Path.Combine(staged, name);
materials["YamlDotNet-license.txt"] = Path.Combine(assets, "YamlDotNet-license.txt");
var nuget = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".nuget", "packages");
materials["DOTNET-LICENSE.txt"] = Path.Combine(nuget, "microsoft.netcore.app.runtime.win-x64", "8.0.25", "LICENSE.TXT");
materials["DOTNET-THIRD-PARTY-NOTICES.txt"] = Path.Combine(nuget, "microsoft.netcore.app.runtime.win-x64", "8.0.25", "THIRD-PARTY-NOTICES.TXT");
materials["WindowsDesktop-LICENSE.txt"] = Path.Combine(nuget, "microsoft.windowsdesktop.app.runtime.win-x64", "8.0.25", "LICENSE");
using (var zip = new ZipArchive(new FileStream(Path.Combine(assets, "notices.zip"), FileMode.Create, FileAccess.ReadWrite), ZipArchiveMode.Create))
    foreach (var (name, path) in materials) zip.CreateEntryFromFile(path, name, CompressionLevel.SmallestSize);
using (var zip = ZipFile.OpenRead(Path.Combine(assets, "runtime.zip")))
{
    if (zip.Entries.Count != files.Length || zip.Entries.Any(entry => !hashes.ContainsKey(entry.FullName))) throw new InvalidOperationException("Unexpected runtime package entry");
    foreach (var entry in zip.Entries)
    {
        using var input = entry.Open();
        var actual = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        if (actual != hashes[entry.FullName]) throw new InvalidOperationException("Runtime package hash mismatch");
    }
}
File.WriteAllText(Path.Combine(workspace, "runtime", "public-package-state.json"), JsonSerializer.Serialize(new
{
    state = "assets-ready", bundle_id = id, runtime_files = files.Length,
    credentials_included = false, desktop_registration_included = false,
    powershell_included = false, loose_documentation_included = false, tests_run = false
}));
Console.WriteLine("Verified runtime ZIP. No credentials, machine registration, scripts or build reports included.");
