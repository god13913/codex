using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json;

namespace CodexProxySetup;

internal static class NodeExitProbe
{
    internal static async Task<string> GetIpv4Async(NodeItem selected)
    {
        var runtime = await RuntimeInstaller.InstallAsync(new Progress<string>(_ => { }));
        var probeRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "CodexProxy", "NodeProbes");
        PrivateStore.SecureDirectory(probeRoot);
        var directory = Path.Combine(probeRoot, Guid.NewGuid().ToString("N"));
        PrivateStore.SecureDirectory(directory);
        Process? process = null;
        try
        {
            using var reservation = new TcpListener(IPAddress.Loopback, 0);
            reservation.Start();
            var port = ((IPEndPoint)reservation.LocalEndpoint).Port;
            var password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
            var node = new Dictionary<string, object?>(selected.Data) { ["name"] = "CODEX" };
            var configuration = new Dictionary<string, object?>
            {
                ["port"] = port, ["socks-port"] = 0, ["mixed-port"] = 0,
                ["redir-port"] = 0, ["tproxy-port"] = 0,
                ["allow-lan"] = false, ["bind-address"] = "127.0.0.1",
                ["mode"] = "rule", ["log-level"] = "silent", ["find-process-mode"] = "off",
                ["authentication"] = new[] { $"probe:{password}" }, ["skip-auth-prefixes"] = Array.Empty<string>(),
                ["tun"] = new { enable = false }, ["dns"] = new { enable = false },
                ["profile"] = new Dictionary<string, bool> { ["store-selected"] = false, ["store-fake-ip"] = false },
                ["proxies"] = new[] { node }, ["rules"] = new[] { "MATCH,CODEX", "MATCH,REJECT" }
            };
            var configPath = Path.Combine(directory, "probe.yaml");
            await File.WriteAllBytesAsync(configPath, JsonSerializer.SerializeToUtf8Bytes(configuration));
            var start = new ProcessStartInfo(Path.Combine(runtime, "codex-mihomo.exe"))
            {
                UseShellExecute = false, CreateNoWindow = true, WindowStyle = ProcessWindowStyle.Hidden,
                WorkingDirectory = directory
            };
            start.ArgumentList.Add("-d");
            start.ArgumentList.Add(directory);
            start.ArgumentList.Add("-f");
            start.ArgumentList.Add(configPath);
            reservation.Stop();
            process = Process.Start(start) ?? throw new InvalidOperationException("节点检测组件未能启动。");
            await WaitForProxyAsync(process, port);

            using var handler = new HttpClientHandler
            {
                UseProxy = true,
                Proxy = new WebProxy($"http://127.0.0.1:{port}")
                {
                    BypassProxyOnLocal = false,
                    Credentials = new NetworkCredential("probe", password)
                },
                AllowAutoRedirect = false
            };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
            try
            {
                using var response = await client.GetAsync("https://v4.api.ipinfo.io/ip", HttpCompletionOption.ResponseContentRead);
                if (!response.IsSuccessStatusCode)
                    throw new InvalidOperationException($"节点出口查询返回 HTTP {(int)response.StatusCode}。");
                var address = (await response.Content.ReadAsStringAsync()).Trim();
                if (!IPAddress.TryParse(address, out var ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                    throw new InvalidOperationException("节点出口没有返回有效 IPv4。");
                return address;
            }
            catch (TaskCanceledException)
            {
                throw new InvalidOperationException("所选节点出口检测超时。");
            }
            catch (HttpRequestException)
            {
                throw new InvalidOperationException("所选节点无法连接检测服务器，请检查节点网络是否正常。");
            }
        }
        finally
        {
            if (process is not null)
            {
                try
                {
                    if (!process.HasExited) process.Kill(entireProcessTree: true);
                    process.WaitForExit(5000);
                }
                catch (InvalidOperationException) { }
                process.Dispose();
            }
            try { Directory.Delete(directory, recursive: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
    }

    private static async Task WaitForProxyAsync(Process process, int port)
    {
        for (var attempt = 0; attempt < 100; attempt++)
        {
            if (process.HasExited) throw new InvalidOperationException("所选节点无法启动检测代理。");
            using var socket = new TcpClient();
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
            try
            {
                await socket.ConnectAsync(IPAddress.Loopback, port, timeout.Token);
                return;
            }
            catch (SocketException) { }
            catch (OperationCanceledException) { }
            await Task.Delay(100);
        }
        throw new InvalidOperationException("节点检测代理启动超时。");
    }
}
