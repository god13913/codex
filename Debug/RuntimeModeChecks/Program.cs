using System.Reflection;
using System.Text.Json;

var assembly = Assembly.Load("CodexProxySetup");
var installer = assembly.GetType("CodexProxySetup.RuntimeModeInstaller", true)!;
const BindingFlags flags = BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic;
object? Call(string method, params object?[] args) => installer.GetMethod(method, flags)!.Invoke(null, args);
int passed = 0;
void Check(bool ok, string name) { if (!ok) throw new Exception(name); Console.WriteLine("PASS " + name); passed++; }
Check((string)Call("Normalize", "service")! == "service" && (string)Call("Normalize", "desktop")! == "desktop", "both installation modes");
Check((string)Call("ModeWithoutService", null, false)! == "service" && (string)Call("ModeWithoutService", null, true)! == "desktop" &&
    (string)Call("ModeWithoutService", "service", true)! == "service" && (string)Call("ModeWithoutService", "desktop", true)! == "desktop", "fresh default and preserve legacy mode on upgrade");
try { Call("Normalize", "arbitrary"); throw new Exception("invalid mode accepted"); }
catch (TargetInvocationException e) when (e.InnerException is InvalidOperationException) { passed++; Console.WriteLine("PASS reject invalid mode"); }
var catalog = assembly.GetType("CodexProxySetup.NodeCatalog", true)!;
foreach (var type in new[] { "socks5", "trojan", "http" })
{
    var node = new Dictionary<string, object?> { ["type"] = type, ["server"] = "192.0.2.1", ["port"] = 9443, ["name"] = "fixture", ["password"] = "fixture-only", ["udp"] = false };
    catalog.GetMethod("Validate", flags)!.Invoke(null, new object[] { node });
    Check((bool)node["udp"]! == (type != "http"), "legacy UDP policy: " + type);
}
// Invalid identity is rejected before touching CODEX_HOME, files or SCM.
var beforeHome = Environment.GetEnvironmentVariable("CODEX_HOME");
var rejected = (Task<int>)Call("RunElevatedAsync", (object)new[] { "--configure-runtime", "service", "Z:\\must-not-exist", "", "", "S-1-0-0" })!;
Check(await rejected == 10 && Environment.GetEnvironmentVariable("CODEX_HOME") == beforeHome, "elevation identity gate before mutation");
// Query only: validates native struct layout against the actual SCM. Never stop,
// create, delete, start, or change a Windows service from this test executable.
var service = Call("Query");
if (service is not null)
{
    var binary = (string)service.GetType().GetProperty("Binary")!.GetValue(service)!;
    Check(binary.Contains("codex-proxy-service.exe", StringComparison.OrdinalIgnoreCase), "SCM config native layout");
    Call("ValidateOwned", service);
    Check(true, "current service protected path and owner validation");
}
var testHome = Path.Combine(Path.GetTempPath(), "codex-mode-check-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(Path.Combine(testHome, "dedicated-proxy"));
Environment.SetEnvironmentVariable("CODEX_HOME", testHome);
try
{
    var settingsPath = Path.Combine(testHome, "dedicated-proxy", "settings.json");
    File.WriteAllText(settingsPath, "{\"enabled\":false,\"mode\":\"node\",\"proxy_port\":45678,\"proxy_password\":\"fixture-only\",\"dns_nameservers\":[\"https://fixture.invalid/dns-query\"],\"dns_bootstrap\":[\"192.0.2.1\"]}");
    var original = File.ReadAllBytes(settingsPath);
    var saved = (Dictionary<string, byte[]?>)Call("Snapshot")!;
    Call("SetEnabled", true, "subscription");
    using (var doc = JsonDocument.Parse(File.ReadAllBytes(settingsPath)))
    {
        var s = doc.RootElement;
        Check(s.GetProperty("enabled").GetBoolean() && s.GetProperty("mode").GetString() == "subscription", "update enabled and node mode");
        Check(s.GetProperty("proxy_port").GetInt32() == 45678 && s.GetProperty("proxy_password").GetString() == "fixture-only" &&
            s.GetProperty("dns_nameservers")[0].GetString() == "https://fixture.invalid/dns-query" && s.GetProperty("dns_bootstrap")[0].GetString() == "192.0.2.1", "preserve endpoint credentials and DNS settings");
    }
    File.WriteAllText(Path.Combine(testHome, "dedicated-proxy", "configurator.json"), "{}");
    Call("Restore", saved);
    Check(File.ReadAllBytes(settingsPath).SequenceEqual(original) && !File.Exists(Path.Combine(testHome, "dedicated-proxy", "configurator.json")), "rollback exact bytes and remove newly created metadata");

    var managed = assembly.GetType("CodexProxySetup.ManagedRuntime", true)!;
    object? Manage(string method, params object?[] args) => managed.GetMethod(method, flags)!.Invoke(null, args);
    using ((IDisposable)Manage("AcquireUpdate")!)
    {
        try { Manage("AcquireUpdate"); throw new Exception("concurrent update accepted"); }
        catch (TargetInvocationException e) when (e.InnerException is InvalidOperationException) { Check(true, "reject concurrent configuration and upgrade before staging or cleanup"); }
    }
    using ((IDisposable)Manage("AcquireUpdate")!) Check(true, "update lease released for next operation");
    var generations = Path.Combine(testHome, "generations"); Directory.CreateDirectory(generations);
    var current = Path.Combine(generations, "current"); var stale = Path.Combine(generations, "stale");
    var locked = Path.Combine(generations, "locked"); var manual = Path.Combine(generations, "manual");
    foreach (var directory in new[] { current, stale, locked, manual }) { Directory.CreateDirectory(directory); File.WriteAllText(Path.Combine(directory, "fixture.txt"), "fixture-only"); }
    foreach (var directory in new[] { current, stale, locked }) Manage("Mark", directory, "desktop");
    Check((bool)Manage("OwnsRoot", stale, generations, "desktop")! && !(bool)Manage("OwnsRoot", manual, generations, "desktop")!, "detect owned remnants independently of recursive deletion eligibility");
    Check(!(bool)Manage("CanDelete", generations, generations, "desktop")! && !(bool)Manage("CanDelete", stale, testHome, "desktop")!, "cleanup rejects parent and paths outside the exact managed parent");
    Check(!(bool)Manage("CanDelete", manual, generations, "desktop")! && !(bool)Manage("CanDelete", stale, generations, "service")!, "cleanup preserves unmarked manual runtimes and wrong scope");
    var marker = Path.Combine(stale, ".codex-proxy-setup.json"); var markerText = File.ReadAllText(marker);
    File.WriteAllText(marker, markerText.Replace(System.Security.Principal.WindowsIdentity.GetCurrent().User!.Value, "S-1-0-0"));
    Check(!(bool)Manage("CanDelete", stale, generations, "desktop")!, "cleanup rejects another runtime owner");
    File.WriteAllText(marker, "{\"schema\":999999999999999999999}");
    Check(!(bool)Manage("CanDelete", stale, generations, "desktop")!, "malformed ownership metadata cannot abort a committed update");
    Manage("Mark", stale, "desktop");
    using (var held = new FileStream(Path.Combine(locked, "fixture.txt"), FileMode.Open, FileAccess.Read, FileShare.None))
    {
        Manage("CleanupWithin", generations, "desktop", current);
        Check(Directory.Exists(current) && File.Exists(Path.Combine(manual, "fixture.txt")) && !Directory.Exists(stale), "successful replacement keeps current and manual files and removes owned old generation");
        Check(File.Exists(Path.Combine(locked, ".codex-proxy-setup.json")) && (bool)managed.GetProperty("CleanupPending", flags)!.GetValue(null)!, "locked old files retain ownership marker and report retry pending");
    }
    Manage("CleanupWithin", generations, "desktop", current);
    Check(!Directory.Exists(locked) && Directory.Exists(current), "next update retries locked old generation without deleting current");

    // A directory junction requires no developer mode. Only create it with cmd;
    // removal below is a nonrecursive .NET unlink, never a shell recursive delete.
    var linked = Path.Combine(generations, "linked"); Directory.CreateDirectory(linked); Manage("Mark", linked, "desktop");
    var target = Path.Combine(testHome, "outside"); Directory.CreateDirectory(target); File.WriteAllText(Path.Combine(target, "sentinel.txt"), "must-survive");
    var junction = Path.Combine(linked, "junction");
    var command = new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "cmd.exe"))
    { UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true };
    foreach (var arg in new[] { "/d", "/c", "mklink", "/J", junction, target }) command.ArgumentList.Add(arg);
    using (var process = System.Diagnostics.Process.Start(command)!) { var stdout = process.StandardOutput.ReadToEndAsync(); var stderr = process.StandardError.ReadToEndAsync(); await process.WaitForExitAsync(); await stdout; await stderr; Check(process.ExitCode == 0, "create junction cleanup boundary fixture"); }
    try
    {
        Check(!(bool)Manage("CanDelete", linked, generations, "desktop")! && !(bool)Manage("Remove", linked, generations, "desktop")! && File.Exists(Path.Combine(target, "sentinel.txt")), "cleanup refuses descendant junction and preserves outside target");
    }
    finally { Directory.Delete(junction); }
}
finally
{
    Environment.SetEnvironmentVariable("CODEX_HOME", beforeHome);
    // Only this freshly created, absolute temporary directory is removed.
    Directory.Delete(testHome, true);
}
Console.WriteLine($"Runtime mode checks: {passed} passed; service mutations: 0");
