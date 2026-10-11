using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using YamlDotNet.Serialization;

namespace CodexProxySetup;

internal sealed class NodeItem
{
    internal Dictionary<string, object?> Data { get; }
    internal string Name => NodeCatalog.Text(Data, "name");
    internal string Kind => NodeCatalog.Text(Data, "type");
    internal string Network => NodeCatalog.Text(Data, "network") is { Length: > 0 } n ? n : "tcp";
    internal string Label => Name.Length > 0 ? Name : "未命名节点";
    internal string Id
    {
        get
        {
            var fields = new[] { "name", "type", "server", "port", "network", "uuid", "password", "username" };
            var values = fields.Select(f => f == "network" && !Data.ContainsKey(f) ? "tcp" : NodeCatalog.Text(Data, f)).ToList();
            values.Add(Data.TryGetValue("ws-opts", out var ws) && ws is Dictionary<string, object?> map ? NodeCatalog.Text(map, "path") : "");
            return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n", values)))).ToLowerInvariant();
        }
    }
    internal NodeItem(Dictionary<string, object?> data) { Data = data; }
    public override string ToString() => $"{Label}    ·    {Kind.ToUpperInvariant()}    ·    {Network}";
}

internal static class NodeCatalog
{
    private static readonly HashSet<string> Types = new(StringComparer.Ordinal)
        { "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "snell", "socks5", "http" };
    internal static string Text(Dictionary<string, object?> map, string key) =>
        map.TryGetValue(key, out var value) ? Convert.ToString(value, CultureInfo.InvariantCulture) ?? "" : "";

    internal static List<NodeItem> Parse(string text)
    {
        if (text.Length > 4 * 1024 * 1024) throw new InvalidOperationException("配置超过 4 MB，无法导入。");
        text = text.Trim().TrimStart('\uFEFF');
        if (!text.Contains("://", StringComparison.Ordinal) && !text.Contains("proxies:", StringComparison.Ordinal) && !text.StartsWith('{'))
        {
            try { var decoded = DecodeBase64(text); if (decoded.Contains("://") || decoded.Contains("proxies:")) text = decoded; }
            catch (FormatException) { }
        }
        var nodes = new List<Dictionary<string, object?>>();
        if (text.StartsWith('{') || text.Contains("proxies:", StringComparison.Ordinal) || text.Contains("type:", StringComparison.Ordinal))
        {
            try
            {
                var parsed = new DeserializerBuilder().WithDuplicateKeyChecking().WithAttemptingUnquotedStringTypeDeserialization().Build().Deserialize<object>(text);
                if (parsed is IDictionary<object, object> root && root.TryGetValue("proxies", out var rawList))
                {
                    if (Normalize(rawList) is List<object?> sequence) nodes.AddRange(sequence.OfType<Dictionary<string, object?>>());
                }
                else if (parsed is IDictionary<object, object> direct && direct.ContainsKey("type") && Normalize(direct) is Dictionary<string, object?> node) nodes.Add(node);
            }
            catch { throw new InvalidOperationException("无法解析 Clash YAML 或 JSON 配置。"); }
        }
        else
        {
            foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                try { nodes.Add(ParseLink(line)); } catch { }
            }
        }
        if (nodes.Count > 10000) throw new InvalidOperationException("节点数量超过 10000，无法导入。");
        var supported = new List<NodeItem>();
        foreach (var node in nodes)
        {
            try { Validate(node); supported.Add(new NodeItem(node)); } catch (InvalidOperationException) { }
        }
        if (supported.Count == 0) throw new InvalidOperationException("没有找到可用节点。请提供包含 proxies 的 Clash 配置或受支持的节点分享链接。");
        return supported;
    }

    internal static Dictionary<string, object?> FromJson(JsonElement value) =>
        (Dictionary<string, object?>)Normalize(new DeserializerBuilder().WithAttemptingUnquotedStringTypeDeserialization()
            .Build().Deserialize<object>(value.GetRawText()))!;

    internal static void Validate(Dictionary<string, object?> node)
    {
        if (Text(node, "name").Length > 1024 || JsonSerializer.SerializeToUtf8Bytes(node, PrivateStore.Json).Length > 32768)
            throw new InvalidOperationException("节点配置过大，无法保存。");
        var type = Text(node, "type");
        if (!Types.Contains(type)) throw new InvalidOperationException("不支持这个节点协议。");
        if (string.IsNullOrWhiteSpace(Text(node, "server")) || Text(node, "server").Any(char.IsControl))
            throw new InvalidOperationException("请填写有效服务器地址。");
        if (!int.TryParse(Text(node, "port"), out var port) || port is < 1 or > 65535)
            throw new InvalidOperationException("节点端口必须在 1 到 65535 之间。");
        if (type is "vless" or "vmess" or "tuic" && !Guid.TryParse(Text(node, "uuid"), out _))
            throw new InvalidOperationException("请填写有效 UUID。");
        if (type is "ss" or "ssr" or "trojan" or "hysteria2" or "tuic" && Text(node, "password").Length == 0)
            throw new InvalidOperationException("请填写节点密码。");
        if (type is "ss" or "ssr" && Text(node, "cipher").Length == 0)
            throw new InvalidOperationException("请填写加密方式。");
        if (new[] { "certificate", "private-key", "private-key-passphrase", "ca" }.Any(node.ContainsKey))
            throw new InvalidOperationException("这个节点依赖外部证书或密钥文件，请使用完整的独立节点配置。");
        if (node.TryGetValue("reality-opts", out var reality) && reality is Dictionary<string, object?> options)
        {
            try { if (DecodeBase64Bytes(Text(options, "public-key")).Length != 32) throw new FormatException(); }
            catch { throw new InvalidOperationException("Reality 公钥格式不正确。"); }
            var id = Text(options, "short-id");
            if (id.Length > 16 || id.Length % 2 != 0 || id.Any(c => !Uri.IsHexDigit(c)))
                throw new InvalidOperationException("Reality Short ID 格式不正确。");
        }
        foreach (var field in new[] { "dialer-proxy", "interface-name", "routing-mark" }) node.Remove(field);
        node["udp"] = false;
    }

    private static object? Normalize(object? value, int depth = 0)
    {
        if (depth > 32) throw new InvalidOperationException("节点配置嵌套过深。");
        return value switch
        {
            IDictionary<object, object> map => map.ToDictionary(p => Convert.ToString(p.Key, CultureInfo.InvariantCulture) ?? "", p => Normalize(p.Value, depth + 1)),
            IDictionary<string, object> map => map.ToDictionary(p => p.Key, p => Normalize(p.Value, depth + 1)),
            System.Collections.IEnumerable list when value is not string => list.Cast<object?>().Select(item => Normalize(item, depth + 1)).ToList(),
            _ => value
        };
    }

    internal static string DecodeBase64(string value) => Encoding.UTF8.GetString(DecodeBase64Bytes(value));
    private static byte[] DecodeBase64Bytes(string value)
    {
        var compact = string.Concat(value.Where(c => !char.IsWhiteSpace(c))).Replace('-', '+').Replace('_', '/');
        return Convert.FromBase64String(compact.PadRight((compact.Length + 3) / 4 * 4, '='));
    }

    private static Dictionary<string, object?> ParseLink(string link)
    {
        if (link.StartsWith("vmess://", StringComparison.Ordinal))
        {
            using var document = JsonDocument.Parse(DecodeBase64(link[8..]));
            var value = document.RootElement;
            string Get(string key) => value.TryGetProperty(key, out var item) ? item.ToString() : "";
            var node = new Dictionary<string, object?>
            {
                ["name"] = Get("ps"), ["type"] = "vmess", ["server"] = Get("add"), ["port"] = int.Parse(Get("port")),
                ["uuid"] = Get("id"), ["alterId"] = int.TryParse(Get("aid"), out var aid) ? aid : 0,
                ["cipher"] = Get("scy") is { Length: > 0 } cipher ? cipher : "auto",
                ["network"] = Get("net") is { Length: > 0 } network ? network : "tcp", ["tls"] = Get("tls") == "tls", ["servername"] = Get("sni")
            };
            if (Get("net") == "ws") node["ws-opts"] = new Dictionary<string, object?>
                { ["path"] = Get("path") is { Length: > 0 } path ? path : "/", ["headers"] = new Dictionary<string, object?> { ["Host"] = Get("host") } };
            return node;
        }
        var uri = new Uri(link);
        var scheme = uri.Scheme.ToLowerInvariant();
        var type = scheme == "hy2" ? "hysteria2" : scheme;
        if (type is not ("trojan" or "vless" or "ss" or "tuic" or "hysteria2")) throw new FormatException();
        var query = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries)
            .Select(part => part.Split('=', 2)).GroupBy(parts => Uri.UnescapeDataString(parts[0]))
            .ToDictionary(group => group.Key, group => Uri.UnescapeDataString(group.First().Length == 2 ? group.First()[1] : ""));
        string GetQuery(string key, string fallback = "") => query.GetValueOrDefault(key, fallback);
        var user = uri.UserInfo.Split(':', 2);
        var nodeData = new Dictionary<string, object?>
            { ["name"] = Uri.UnescapeDataString(uri.Fragment.TrimStart('#')), ["type"] = type, ["server"] = uri.IdnHost,
                ["port"] = uri.Port > 0 ? uri.Port : 443 };
        if (type == "ss")
        {
            var credential = user.Length == 2 ? Uri.UnescapeDataString(uri.UserInfo) : DecodeBase64(Uri.UnescapeDataString(user[0]));
            var pair = credential.Split(':', 2);
            nodeData["cipher"] = pair[0]; nodeData["password"] = pair[1]; return nodeData;
        }
        if (type is "vless" or "tuic") nodeData["uuid"] = Uri.UnescapeDataString(user[0]);
        if (type == "tuic") nodeData["password"] = user.Length == 2 ? Uri.UnescapeDataString(user[1]) : "";
        if (type is "trojan" or "hysteria2") nodeData["password"] = Uri.UnescapeDataString(user[0]);
        nodeData[type is "vless" ? "servername" : "sni"] = GetQuery("sni", uri.IdnHost);
        nodeData["network"] = GetQuery("type", "tcp"); nodeData["tls"] = true;
        foreach (var (source, target) in new[] { ("fp", "client-fingerprint"), ("flow", "flow"), ("obfs", "obfs"), ("obfs-password", "obfs-password") })
            if (query.ContainsKey(source)) nodeData[target] = query[source];
        if (query.ContainsKey("insecure") || query.ContainsKey("allowInsecure"))
            nodeData["skip-cert-verify"] = GetQuery("insecure", GetQuery("allowInsecure")) is "1" or "true";
        if (GetQuery("type", "tcp") == "ws") nodeData["ws-opts"] = new Dictionary<string, object?>
            { ["path"] = GetQuery("path", "/"), ["headers"] = new Dictionary<string, object?> { ["Host"] = GetQuery("host", GetQuery("sni", uri.IdnHost)) } };
        if (GetQuery("security") == "reality") nodeData["reality-opts"] = new Dictionary<string, object?>
            { ["public-key"] = GetQuery("pbk"), ["short-id"] = GetQuery("sid") };
        return nodeData;
    }
}
