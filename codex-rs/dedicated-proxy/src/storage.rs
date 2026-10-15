use anyhow::{Context, Result, bail};
use base64::Engine;
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_yaml::{Mapping, Value};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const MAX_SUBSCRIPTION_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Vps,
    Subscription,
    Node,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vps => "vps",
            Self::Subscription => "subscription",
            Self::Node => "node",
        }
    }
}

/// Default fixed proxy port. A fixed port lets sibling processes (for example a
/// standalone exec-server) reach the kernel that an already running app-server owns
/// instead of starting a second one.
pub const DEFAULT_PROXY_PORT: u16 = 35234;

/// Default fixed proxy password. It must be exactly 64 ASCII hex characters because
/// desktop forwarding request validation enforces that shape; a shorter value makes
/// every endpoint fail validation and the forwarding worker never starts.
pub const DEFAULT_PROXY_PASSWORD: &str =
    "a3f1c0dea3f1c0dea3f1c0dea3f1c0dea3f1c0dea3f1c0dea3f1c0dea3f1c0de";

/// Compile-time guard so the default password can never drift out of the 64-hex
/// shape that forwarding validation requires.
const _: () = {
    assert!(DEFAULT_PROXY_PASSWORD.len() == 64);
    let bytes = DEFAULT_PROXY_PASSWORD.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        assert!(bytes[i].is_ascii_hexdigit());
        i += 1;
    }
};

#[derive(Default, Serialize, Deserialize)]
pub struct Settings {
    pub enabled: bool,
    #[serde(default)]
    pub mode: Mode,
    pub updated_at: u64,
    pub last_error: Option<String>,
    /// Fixed local proxy port. `0` (or missing) means [`DEFAULT_PROXY_PORT`].
    #[serde(default)]
    pub proxy_port: u16,
    /// Fixed proxy password. Must be 64 ASCII hex characters; anything else falls
    /// back to [`DEFAULT_PROXY_PASSWORD`] so forwarding validation keeps working.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_password: Option<String>,
    /// DNS-over-HTTPS endpoints the private kernel resolves with. Missing means
    /// [`DEFAULT_DNS_NAMESERVERS`]; set it to `[]` to disable kernel-side resolution and
    /// let the OS resolver answer instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_nameservers: Option<Vec<String>>,
    /// Plain resolvers used only to reach `dns_nameservers`; missing means
    /// [`DEFAULT_DNS_BOOTSTRAP`]. Ignored when `dns_nameservers` is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_bootstrap: Option<Vec<String>>,
}

/// Returns `true` when `value` matches the shape desktop forwarding validation expects.
pub fn is_acceptable_password(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Resolves the effective port, falling back to the built-in default.
pub fn effective_proxy_port(settings: &Settings) -> u16 {
    if settings.proxy_port == 0 {
        DEFAULT_PROXY_PORT
    } else {
        settings.proxy_port
    }
}

/// Resolves the effective password, falling back to the built-in default.
pub fn effective_proxy_password(settings: &Settings) -> String {
    match settings.proxy_password.as_deref() {
        Some(value) if is_acceptable_password(value) => value.to_owned(),
        _ => DEFAULT_PROXY_PASSWORD.to_owned(),
    }
}

/// DoH endpoints the kernel resolves with, used whenever `settings.json` does not carry
/// `dns_nameservers`. Both are Tencent DNSPod endpoints: they answer from inside mainland
/// China (measured 0.5s and 2.0s) and return the real Cloudflare addresses for ChatGPT
/// hosts, where the local resolver answers with dead Facebook/Twitter addresses.
pub const DEFAULT_DNS_NAMESERVERS: &[&str] =
    &["https://doh.pub/dns-query", "https://1.12.12.12/dns-query"];

/// Plain resolvers used only to reach the DoH endpoints above, so the kernel can
/// bootstrap its own encrypted resolution without depending on the OS resolver.
/// `223.5.5.5` is Alibaba AliDNS, `119.29.29.29` is Tencent DNSPod.
pub const DEFAULT_DNS_BOOTSTRAP: &[&str] = &["223.5.5.5", "119.29.29.29"];

/// Upper bound for operator-supplied resolver lists.
const MAX_DNS_ENTRIES: usize = 8;

/// Trims, de-duplicates and caps an operator-supplied resolver list. An empty result
/// is legal and means "let the kernel fall back to the OS resolver".
fn sanitize_resolvers(values: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for value in values {
        let value = value.trim();
        if value.is_empty() || out.len() >= MAX_DNS_ENTRIES || out.iter().any(|v| v == value) {
            continue;
        }
        out.push(value.to_owned());
    }
    out
}

/// Resolves the DoH endpoints for the kernel. **On by default** (`None` -> see
/// [`DEFAULT_DNS_NAMESERVERS`]).
///
/// Why the kernel needs a resolver of its own: the sniffer turns a hijacked packet back
/// into a hostname, but the kernel still resolves that hostname locally before dialing the
/// node. Measured - pinning the ChatGPT hosts in the hosts file is what made cloud replies
/// load again, so the locally resolved address really is on the forwarding path, and a
/// poisoned OS resolver makes every tunnel stall until a retry re-resolves the name.
///
/// This is *not* Clash's remote resolution: Mihomo dials these DoH endpoints itself, from
/// this machine, so they must be reachable without a proxy. That is acceptable because the
/// answer only has to be *correct* - the node is what actually connects to it. Set
/// `dns_nameservers` to `[]` in settings.json to fall back to plain OS resolution.
pub fn effective_dns_nameservers(settings: &Settings) -> Vec<String> {
    match settings.dns_nameservers.as_ref() {
        Some(values) => sanitize_resolvers(values),
        None => DEFAULT_DNS_NAMESERVERS.iter().map(|v| (*v).to_owned()).collect(),
    }
}

/// Bootstrap resolvers used to reach [`effective_dns_nameservers`], and — as the kernel's
/// `default-nameserver` plus `proxy-server-nameserver` — to resolve the node's own host
/// name directly, never through the loopback resolver (that would deadlock on the tunnel).
///
/// Mihomo rejects a `default-nameserver` entry that is not a plain IP, and rejects an
/// empty `default-nameserver` outright; rejecting the whole configuration would take the
/// dedicated proxy down, so anything else is dropped and an empty result falls back to
/// [`DEFAULT_DNS_BOOTSTRAP`].
pub fn effective_dns_bootstrap(settings: &Settings) -> Vec<String> {
    let values = match settings.dns_bootstrap.as_ref() {
        Some(values) => sanitize_resolvers(values),
        None => DEFAULT_DNS_BOOTSTRAP.iter().map(|v| (*v).to_owned()).collect(),
    };
    let filtered: Vec<String> = values
        .into_iter()
        .filter(|value| value.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if filtered.is_empty() {
        DEFAULT_DNS_BOOTSTRAP.iter().map(|v| (*v).to_owned()).collect()
    } else {
        filtered
    }
}

/// Builds the fixed local endpoint other processes can reuse without starting a
/// second kernel. Returns `None` when the dedicated proxy is not enabled.
pub fn endpoint_for(settings: &Settings) -> Option<String> {
    if !settings.enabled {
        return None;
    }
    let port = effective_proxy_port(settings);
    let password = effective_proxy_password(settings);
    Some(if password.is_empty() {
        format!("http://127.0.0.1:{port}")
    } else {
        format!("http://codex:{password}@127.0.0.1:{port}")
    })
}

/// Credential-bearing configuration, encrypted for the current Windows user.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubscriptionConfig {
    #[serde(alias = "subscription")]
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selected_node_id: Option<String>,
}

// Deliberately no Debug implementation: every field is credential-bearing.
#[derive(Serialize, Deserialize)]
pub struct Cache {
    pub subscription: String,
    pub node: Mapping,
}

// Deliberately no Debug implementation: the UUID and hidden WebSocket path are credentials.
#[derive(Serialize, Deserialize)]
pub struct VpsProfile {
    pub server: String,
    pub port: u16,
    pub sni: String,
    pub path: String,
    pub uuid: String,
}

impl VpsProfile {
    pub fn node(&self) -> Result<Mapping> {
        self.validate()?;
        let mut node = Mapping::new();
        node.insert(Value::String("name".into()), Value::String("CODEX".into()));
        node.insert(Value::String("type".into()), Value::String("vless".into()));
        node.insert(
            Value::String("server".into()),
            Value::String(self.server.clone()),
        );
        node.insert(
            Value::String("port".into()),
            serde_yaml::to_value(self.port)?,
        );
        node.insert(
            Value::String("uuid".into()),
            Value::String(self.uuid.clone()),
        );
        node.insert(Value::String("tls".into()), Value::Bool(true));
        node.insert(
            Value::String("servername".into()),
            Value::String(self.sni.clone()),
        );
        node.insert(
            Value::String("client-fingerprint".into()),
            Value::String("chrome".into()),
        );
        node.insert(Value::String("network".into()), Value::String("ws".into()));
        node.insert(Value::String("udp".into()), Value::Bool(false));

        let mut headers = Mapping::new();
        headers.insert(
            Value::String("Host".into()),
            Value::String(self.sni.clone()),
        );
        let mut ws = Mapping::new();
        ws.insert(
            Value::String("path".into()),
            Value::String(self.path.clone()),
        );
        ws.insert(Value::String("headers".into()), Value::Mapping(headers));
        node.insert(Value::String("ws-opts".into()), Value::Mapping(ws));
        Ok(node)
    }

    fn validate(&self) -> Result<()> {
        self.server
            .parse::<std::net::Ipv4Addr>()
            .map_err(|_| anyhow::anyhow!("VPS server must be an IPv4 address"))?;
        if !(1..=65535).contains(&self.port) {
            bail!("invalid VPS port");
        }
        if self.sni.is_empty()
            || self.sni.len() > 253
            || self.sni.parse::<IpAddr>().is_ok()
            || self
                .sni
                .bytes()
                .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-')))
        {
            bail!("invalid VPS TLS server name");
        }
        if self.path.len() < 9
            || self.path.len() > 121
            || !self.path.starts_with('/')
            || self.path.contains("//")
            || !self.path[1..].bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'/' | b'-')
            })
        {
            bail!("invalid VPS WebSocket path");
        }
        uuid::Uuid::parse_str(&self.uuid).map_err(|_| anyhow::anyhow!("invalid VPS UUID"))?;
        Ok(())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn directory(home: &Path) -> PathBuf {
    home.join("dedicated-proxy")
}

fn subscription_config_path(home: &Path) -> PathBuf {
    directory(home).join("subscription.json")
}

fn subscription_cache_path(home: &Path) -> PathBuf {
    directory(home).join("subscription-cache.json")
}

pub fn settings(home: &Path) -> Result<Settings> {
    let path = directory(home).join("settings.json");
    if !path.exists() {
        return Ok(Settings::default());
    }
    let data = std::fs::read(path).context("cannot read proxy settings")?;
    serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("invalid proxy settings"))
}

pub fn save_settings(home: &Path, value: &Settings) -> Result<()> {
    write_private(home, "settings.json", &serde_json::to_vec_pretty(value)?)
}

pub fn subscription_config(home: &Path) -> Result<SubscriptionConfig> {
    let path = subscription_config_path(home);
    let metadata = std::fs::metadata(&path).context("no subscription config configured")?;
    if metadata.len() > 16 * 1024 {
        bail!("invalid subscription config size");
    }
    let data = read_private(&path)?;
    let config: SubscriptionConfig = serde_json::from_slice(&data)
        .map_err(|_| anyhow::anyhow!("invalid subscription config"))?;
    validate_uri(&config.url)?;
    Ok(config)
}

pub fn save_subscription_config(home: &Path, value: &SubscriptionConfig) -> Result<()> {
    validate_uri(&value.url)?;
    write_private(
        home,
        "subscription.json",
        &serde_json::to_vec_pretty(value)?,
    )
}

pub fn cache(home: &Path) -> Result<Cache> {
    let path = subscription_cache_path(home);
    let path = if path.is_file() {
        path
    } else {
        // Read the pre-config-file cache format during migration. Once the new
        // config file is written, this fallback naturally stops matching it.
        subscription_config_path(home)
    };
    let metadata = std::fs::metadata(&path).context("no subscription cache available")?;
    if metadata.len() > MAX_SUBSCRIPTION_BYTES as u64 + 4096 {
        bail!("invalid proxy cache size");
    }
    let data = read_private(&path)?;
    let mut cached: Cache =
        serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("invalid proxy cache"))?;
    validate_uri(&cached.subscription)?;
    // Revalidate local cache data before passing it to the kernel.
    cached.node = sanitize_node(cached.node)?;
    Ok(cached)
}

pub fn save_cache(home: &Path, value: &Cache) -> Result<()> {
    write_private(
        home,
        "subscription-cache.json",
        &serde_json::to_vec_pretty(value)?,
    )
}

pub fn vps_profile(home: &Path) -> Result<VpsProfile> {
    let path = directory(home).join("vps-profile.json");
    let metadata = std::fs::metadata(&path).context("no VPS profile configured")?;
    if metadata.len() > 16 * 1024 {
        bail!("invalid VPS profile size");
    }
    let data = read_private(&path)?;
    let profile: VpsProfile =
        serde_json::from_slice(&data).map_err(|_| anyhow::anyhow!("invalid VPS profile"))?;
    profile.validate()?;
    Ok(profile)
}

pub fn save_vps_profile(home: &Path, profile: &VpsProfile) -> Result<()> {
    profile.validate()?;
    write_private(
        home,
        "vps-profile.json",
        &serde_json::to_vec_pretty(profile)?,
    )
}

fn write_private(home: &Path, name: &str, data: &[u8]) -> Result<()> {
    let dir = directory(home);
    crate::windows::private_directory(&dir)?;
    let mut file =
        tempfile::NamedTempFile::new_in(&dir).context("cannot create private proxy state")?;
    let protected = if name == "settings.json" { data.to_vec() } else { protect(data)? };
    file.write_all(&protected)
        .context("cannot write private proxy state")?;
    file.as_file()
        .sync_all()
        .context("cannot sync private proxy state")?;
    file.persist(dir.join(name))
        .map_err(|_| anyhow::anyhow!("cannot commit private proxy state"))?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct ProtectedEnvelope {
    format: String,
    data: String,
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).context("cannot read private proxy configuration")?;
    unprotect(&bytes)
}

pub(super) fn unprotect(bytes: &[u8]) -> Result<Vec<u8>> {
    if let Ok(envelope) = serde_json::from_slice::<ProtectedEnvelope>(bytes) {
        if envelope.format != "codex-dpapi-v1" { bail!("unsupported protected proxy configuration"); }
        let encrypted = base64::engine::general_purpose::STANDARD.decode(envelope.data)
            .map_err(|_| anyhow::anyhow!("invalid protected proxy configuration"))?;
        return crypt(&encrypted, false);
    }
    // Read existing private JSON without changing the active installation.
    Ok(bytes.to_vec())
}

pub(super) fn protect(bytes: &[u8]) -> Result<Vec<u8>> {
    #[cfg(windows)]
    { serde_json::to_vec(&ProtectedEnvelope { format: "codex-dpapi-v1".into(),
        data: base64::engine::general_purpose::STANDARD.encode(crypt(bytes, true)?) }).map_err(Into::into) }
    #[cfg(not(windows))]
    { Ok(bytes.to_vec()) }
}

fn crypt(bytes: &[u8], encrypt: bool) -> Result<Vec<u8>> {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Security::Cryptography::{CRYPT_INTEGER_BLOB, CryptProtectData,
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN};
        let input = CRYPT_INTEGER_BLOB { cbData: bytes.len().try_into()?, pbData: bytes.as_ptr().cast_mut() };
        let mut output: CRYPT_INTEGER_BLOB = unsafe { std::mem::zeroed() };
        let result = unsafe { if encrypt {
            CryptProtectData(&input, std::ptr::null(), std::ptr::null(), std::ptr::null(),
                std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        } else {
            CryptUnprotectData(&input, std::ptr::null_mut(), std::ptr::null(), std::ptr::null(),
                std::ptr::null(), CRYPTPROTECT_UI_FORBIDDEN, &mut output)
        }};
        if result == 0 { bail!("cannot access proxy credentials for this Windows user"); }
        let value = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe { windows_sys::Win32::Foundation::LocalFree(output.pbData.cast()); }
        Ok(value)
    }
    #[cfg(not(windows))]
    { let _ = (bytes, encrypt); bail!("protected proxy configuration requires Windows"); }
}

pub fn node_profile(home: &Path) -> Result<Mapping> {
    let path = directory(home).join("node-profile.json");
    if std::fs::metadata(&path)?.len() > 64 * 1024 { bail!("invalid node profile size"); }
    let node: Mapping = serde_json::from_slice(&read_private(&path)?)
        .map_err(|_| anyhow::anyhow!("invalid node profile"))?;
    sanitize_node(node)
}

fn validate_uri(input: &str) -> Result<()> {
    let uri =
        reqwest::Url::parse(input).map_err(|_| anyhow::anyhow!("invalid subscription URL"))?;
    if uri.scheme() != "https"
        || uri.host_str().is_none()
        || !uri.username().is_empty()
        || uri.password().is_some()
    {
        bail!("subscription must be an HTTPS URL without URL userinfo");
    }
    Ok(())
}

pub async fn download(input: &str, proxy: Option<&str>) -> Result<Cache> {
    download_selected(&SubscriptionConfig { url: input.to_owned(), selected_node_name: None,
        selected_node_id: None }, proxy).await
}

pub async fn download_selected(config: &SubscriptionConfig, proxy: Option<&str>) -> Result<Cache> {
    let input = &config.url;
    validate_uri(input)?;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("mihomo/1.19.32 CodexDedicatedProxy");
    if let Some(proxy) = proxy {
        builder = builder
            .no_proxy()
            .proxy(reqwest::Proxy::all(proxy).map_err(|_| anyhow::anyhow!("invalid local proxy"))?);
    }
    let client = builder
        .build()
        .map_err(|_| anyhow::anyhow!("cannot build subscription client"))?;
    let response = client
        .get(input)
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("subscription connection failed"))?;
    if !response.status().is_success() {
        bail!("subscription HTTP status {}", response.status().as_u16());
    }
    if response
        .content_length()
        .is_some_and(|size| size > MAX_SUBSCRIPTION_BYTES as u64)
    {
        bail!("subscription exceeds size limit");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("subscription download failed"))?;
        if bytes.len() + chunk.len() > MAX_SUBSCRIPTION_BYTES {
            bail!("subscription exceeds size limit");
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(Cache {
        subscription: input.to_owned(),
        node: parse_selected_subscription(&bytes, Some(config))?,
    })
}

pub fn parse_subscription(bytes: &[u8]) -> Result<Mapping> {
    parse_selected_subscription(bytes, None)
}

fn parse_selected_subscription(bytes: &[u8], config: Option<&SubscriptionConfig>) -> Result<Mapping> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| anyhow::anyhow!("subscription is not valid UTF-8"))?
        .trim_start_matches('\u{feff}')
        .trim();
    parse_subscription_text(text, true, config)
}

fn parse_subscription_text(text: &str, allow_base64: bool, config: Option<&SubscriptionConfig>) -> Result<Mapping> {
    if let Ok(root) = serde_yaml::from_str::<Value>(text) {
        if let Some(proxies) = root.get("proxies") {
            let proxies = proxies
                .as_sequence()
                .context("subscription proxies must be a list")?;
            let nodes: Vec<Mapping> = proxies.iter().filter_map(Value::as_mapping).cloned().collect();
            return select_node(nodes, config);
        }
    }

    if allow_base64 {
        if let Some(decoded) = decode_base64_payload(text) {
            return parse_subscription_text(&decoded, false, config);
        }
    }

    let entries: Vec<_> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    let nodes: Vec<Mapping> = entries.into_iter().filter_map(|entry| parse_share_link(entry).ok()).collect();
    select_node(nodes, config)
}

fn node_identity(node: &Mapping) -> String {
    let fields = ["name", "type", "server", "port", "network", "uuid", "password", "username"];
    let values: Vec<String> = fields.into_iter().map(|field| {
        if field == "network" && !node.contains_key(Value::String(field.into())) { return "tcp".into(); }
        match node.get(Value::String(field.into())) {
            Some(Value::String(value)) => value.clone(),
            Some(Value::Number(value)) => value.to_string(),
            _ => String::new(),
        }
    }).collect();
    let ws = node.get(Value::String("ws-opts".into())).and_then(Value::as_mapping)
        .and_then(|opts| opts.get(Value::String("path".into()))).and_then(Value::as_str).unwrap_or("");
    format!("{:x}", Sha256::digest(format!("{}\n{ws}", values.join("\n")).as_bytes()))
}

fn select_node(nodes: Vec<Mapping>, config: Option<&SubscriptionConfig>) -> Result<Mapping> {
    if let Some(config) = config {
        if let Some(id) = &config.selected_node_id {
            let found: Vec<_> = nodes.iter().filter(|node| node_identity(node) == *id).collect();
            if found.len() == 1 { return sanitize_node(found[0].clone()); }
        }
        if let Some(name) = &config.selected_node_name {
            let found: Vec<_> = nodes.iter().filter(|node|
                node.get(Value::String("name".into())).and_then(Value::as_str) == Some(name.as_str())).collect();
            if found.len() == 1 { return sanitize_node(found[0].clone()); }
        }
        if config.selected_node_id.is_some() || config.selected_node_name.is_some() {
            bail!("selected node is absent or ambiguous; choose a node again in the configurator");
        }
    }
    if nodes.len() != 1 { bail!("subscription must contain exactly one proxy node unless a node is selected; found {}", nodes.len()); }
    sanitize_node(nodes.into_iter().next().context("subscription contains no supported nodes")?)
}

fn decode_base64_payload(text: &str) -> Option<String> {
    let compact: String = text
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    if compact.len() < 4
        || !compact.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'=' | b'-' | b'_')
        })
    {
        return None;
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(compact.as_bytes()))
        .ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    if decoded.contains("://") || decoded.contains("proxies:") || decoded.trim_start().starts_with('{') {
        Some(decoded)
    } else {
        None
    }
}

fn parse_share_link(input: &str) -> Result<Mapping> {
    if let Some(payload) = input.strip_prefix("vmess://") {
        let text = decode_base64_payload(payload).context("invalid VMess share link")?;
        let value: serde_json::Value = serde_json::from_str(&text)
            .map_err(|_| anyhow::anyhow!("invalid VMess share link"))?;
        let text = |field: &str| value.get(field).and_then(serde_json::Value::as_str).unwrap_or("");
        let port = value.get("port").and_then(serde_json::Value::as_u64)
            .or_else(|| text("port").parse().ok()).context("invalid VMess port")?;
        let mut node: Mapping = serde_yaml::to_value(serde_json::json!({
            "name": text("ps"), "type": "vmess", "server": text("add"), "port": port,
            "uuid": text("id"), "alterId": value.get("aid").and_then(serde_json::Value::as_u64)
                .or_else(|| text("aid").parse().ok()).unwrap_or(0),
            "cipher": if text("scy").is_empty() { "auto" } else { text("scy") },
            "network": if text("net").is_empty() { "tcp" } else { text("net") },
            "tls": text("tls") == "tls", "servername": text("sni")
        }))?.as_mapping().context("invalid VMess node")?.clone();
        if text("net") == "ws" {
            node.insert(Value::String("ws-opts".into()), serde_yaml::to_value(serde_json::json!({
                "path": if text("path").is_empty() { "/" } else { text("path") },
                "headers": {"Host": text("host")}
            }))?);
        }
        return Ok(node);
    }
    let url =
        reqwest::Url::parse(input).map_err(|_| anyhow::anyhow!("invalid subscription node"))?;
    if url.scheme().eq_ignore_ascii_case("trojan") { return parse_trojan_link(&url); }
    let scheme = url.scheme().to_ascii_lowercase();
    let kind = match scheme.as_str() {
        "vless" => "vless", "ss" => "ss", "tuic" => "tuic",
        "hysteria2" | "hy2" => "hysteria2", _ => bail!("unsupported subscription node protocol"),
    };
    let mut node: Mapping = serde_yaml::to_value(serde_json::json!({
        "name": percent_decode(url.fragment().unwrap_or(""))?, "type": kind,
        "server": url.host_str().context("share link has no server")?, "port": url.port().unwrap_or(443)
    }))?.as_mapping().context("invalid share node")?.clone();
    let mut set = |key: &str, value: String| { node.insert(Value::String(key.into()), Value::String(value)); };
    if kind == "ss" {
        let credential = if let Some(password) = url.password() {
            format!("{}:{}", percent_decode(url.username())?, percent_decode(password)?)
        } else {
            let user = percent_decode(url.username())?;
            let decoded = base64::engine::general_purpose::STANDARD.decode(&user)
                .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(user.trim_end_matches('=')))
                .map_err(|_| anyhow::anyhow!("invalid Shadowsocks credential"))?;
            String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("invalid Shadowsocks credential"))?
        };
        let (cipher, password) = credential.split_once(':').context("invalid Shadowsocks credential")?;
        set("cipher", cipher.into()); set("password", password.into());
        return Ok(node);
    }
    if kind == "vless" || kind == "tuic" { set("uuid", percent_decode(url.username())?); }
    if kind == "tuic" { set("password", percent_decode(url.password().unwrap_or(""))?); }
    if kind == "hysteria2" { set("password", percent_decode(url.username())?); }
    set(if kind == "vless" { "servername" } else { "sni" },
        query_value(&url, "sni").unwrap_or_else(|| url.host_str().unwrap_or("").to_owned()));
    let network = query_value(&url, "type").unwrap_or_else(|| "tcp".into());
    set("network", network.clone());
    if let Some(value) = query_value(&url, "fp") { set("client-fingerprint", value); }
    if let Some(value) = query_value(&url, "flow") { set("flow", value); }
    if let Some(value) = query_value(&url, "obfs") { set("obfs", value); }
    if let Some(value) = query_value(&url, "obfs-password") { set("obfs-password", value); }
    node.insert(Value::String("tls".into()), Value::Bool(true));
    if let Some(value) = query_value(&url, "insecure").or_else(|| query_value(&url, "allowInsecure")) {
        node.insert(Value::String("skip-cert-verify".into()), Value::Bool(matches!(value.as_str(), "1" | "true")));
    }
    if network == "ws" {
        node.insert(Value::String("ws-opts".into()), serde_yaml::to_value(serde_json::json!({
            "path": query_value(&url, "path").unwrap_or_else(|| "/".into()),
            "headers": {"Host": query_value(&url, "host").unwrap_or_default()}
        }))?);
    }
    if query_value(&url, "security").as_deref() == Some("reality") {
        node.insert(Value::String("reality-opts".into()), serde_yaml::to_value(serde_json::json!({
            "public-key": query_value(&url, "pbk").unwrap_or_default(),
            "short-id": query_value(&url, "sid").unwrap_or_default()
        }))?);
    }
    Ok(node)
}

fn query_value(url: &reqwest::Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.into_owned())
}

fn percent_decode(value: &str) -> Result<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                bail!("invalid subscription node credential");
            }
            let high = (bytes[index + 1] as char).to_digit(16);
            let low = (bytes[index + 2] as char).to_digit(16);
            match (high, low) {
                (Some(high), Some(low)) => decoded.push((high * 16 + low) as u8),
                _ => bail!("invalid subscription node credential"),
            }
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| anyhow::anyhow!("invalid subscription node credential"))
}

fn parse_trojan_link(url: &reqwest::Url) -> Result<Mapping> {
    let password = percent_decode(url.username())?;
    if password.is_empty() || url.password().is_some() {
        bail!("subscription Trojan node has no valid password");
    }
    let server = url
        .host_str()
        .filter(|server| !server.is_empty())
        .context("subscription Trojan node has no server")?;
    let port = url.port().unwrap_or(443);
    let security = query_value(url, "security").unwrap_or_else(|| "tls".into());
    if !security.eq_ignore_ascii_case("tls") {
        bail!("subscription Trojan node must use TLS");
    }
    let network = query_value(url, "type").unwrap_or_else(|| "tcp".into());
    let network = network.to_ascii_lowercase();
    if !matches!(network.as_str(), "tcp" | "ws") {
        bail!("unsupported subscription Trojan transport");
    }

    let mut node = Mapping::new();
    node.insert(Value::String("type".into()), Value::String("trojan".into()));
    node.insert(
        Value::String("server".into()),
        Value::String(server.to_owned()),
    );
    node.insert(Value::String("port".into()), serde_yaml::to_value(port)?);
    node.insert(Value::String("password".into()), Value::String(password));
    node.insert(Value::String("tls".into()), Value::Bool(true));
    node.insert(
        Value::String("sni".into()),
        Value::String(query_value(url, "sni").unwrap_or_else(|| server.to_owned())),
    );

    if let Some(fingerprint) = query_value(url, "fp") {
        node.insert(
            Value::String("client-fingerprint".into()),
            Value::String(fingerprint),
        );
    }
    if let Some(alpn) = query_value(url, "alpn") {
        let values: Vec<_> = alpn
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        if values.is_empty() {
            bail!("invalid subscription ALPN");
        }
        node.insert(Value::String("alpn".into()), serde_yaml::to_value(values)?);
    }
    if let Some(value) =
        query_value(url, "allowInsecure").or_else(|| query_value(url, "allow_insecure"))
    {
        let skip_cert_verify = match value.to_ascii_lowercase().as_str() {
            "1" | "true" => true,
            "0" | "false" => false,
            _ => bail!("invalid subscription TLS verification setting"),
        };
        node.insert(
            Value::String("skip-cert-verify".into()),
            Value::Bool(skip_cert_verify),
        );
    }

    node.insert(
        Value::String("network".into()),
        Value::String(network.clone()),
    );
    if network == "ws" {
        let path = query_value(url, "path").context("subscription WebSocket path is missing")?;
        let host = query_value(url, "host")
            .unwrap_or_else(|| query_value(url, "sni").unwrap_or_else(|| server.to_owned()));
        let mut headers = Mapping::new();
        headers.insert(Value::String("Host".into()), Value::String(host));
        let mut ws = Mapping::new();
        ws.insert(Value::String("path".into()), Value::String(path));
        ws.insert(Value::String("headers".into()), Value::Mapping(headers));
        node.insert(Value::String("ws-opts".into()), Value::Mapping(ws));
    }
    sanitize_node(node)
}

fn string<'a>(node: &'a Mapping, name: &str) -> Result<&'a str> {
    node.get(Value::String(name.into()))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing or invalid node field: {name}"))
}

fn sanitize_node(mut node: Mapping) -> Result<Mapping> {
    let kind = string(&node, "type")?.to_owned();
    if !matches!(kind.as_str(), "ss" | "ssr" | "vmess" | "vless" | "trojan" |
        "hysteria" | "hysteria2" | "tuic" | "snell" | "socks5" | "http") {
        bail!("unsupported node protocol");
    }
    string(&node, "server")?;
    if !node.get(Value::String("port".into())).and_then(Value::as_u64)
        .is_some_and(|port| (1..=65535).contains(&port)) { bail!("invalid node port"); }
    if matches!(kind.as_str(), "vless" | "vmess" | "tuic") {
        uuid::Uuid::parse_str(string(&node, "uuid")?)
            .map_err(|_| anyhow::anyhow!("invalid node UUID"))?;
    }
    if matches!(kind.as_str(), "ss" | "ssr" | "trojan" | "hysteria2" | "tuic") {
        string(&node, "password")?;
    }
    if matches!(kind.as_str(), "ss" | "ssr") { string(&node, "cipher")?; }
    if let Some(reality) = node.get(Value::String("reality-opts".into())).and_then(Value::as_mapping) {
        let key = string(reality, "public-key")?;
        let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(key.trim_end_matches('='))
            .map_err(|_| anyhow::anyhow!("invalid Reality public key"))?;
        if key_bytes.len() != 32 { bail!("invalid Reality public key length"); }
        if let Some(value) = reality.get(Value::String("short-id".into())) {
            let id = value.as_str().context("invalid Reality short ID")?;
            if id.len() > 16 || id.len() % 2 != 0 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
                bail!("invalid Reality short ID");
            }
        }
    }
    for field in ["certificate", "private-key", "private-key-passphrase", "ca"] {
        if node.contains_key(Value::String(field.into())) {
            bail!("node references a local certificate or key; use a self-contained node");
        }
    }
    // Import only this node. Subscription groups, rules, providers and local routing
    // overrides are never installed in the dedicated service proxy.
    for field in ["dialer-proxy", "interface-name", "routing-mark"] {
        node.remove(Value::String(field.into()));
    }
    node.insert(Value::String("name".into()), Value::String("CODEX".into()));
    node.insert(Value::String("udp".into()), Value::Bool(false));
    Ok(node)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    const NODE: &str = "proxies:\n- name: private\n  type: vless\n  server: example.com\n  port: 443\n  uuid: 00000000-0000-0000-0000-000000000001\n  network: tcp\n  tls: true\n  servername: example.com\n  reality-opts:\n    public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n    short-id: ''\n  dialer-proxy: malicious\n  udp: true\n";
    #[test]
    fn imports_only_safe_node_fields() {
        let node = parse_subscription(
            format!("{NODE}tun:\n  enable: true\nrules: [MATCH,DIRECT]\n").as_bytes(),
        )
        .unwrap();
        assert_eq!(
            node.get(Value::String("name".into())).unwrap().as_str(),
            Some("CODEX")
        );
        assert!(!node.contains_key(Value::String("dialer-proxy".into())));
        assert_eq!(
            node.get(Value::String("udp".into())).unwrap().as_bool(),
            Some(false)
        );
    }
    #[test]
    fn imports_one_plain_trojan_share_link() {
        let node = parse_subscription(
            b"trojan://password@example.com:443?security=tls&type=ws&sni=example.com&host=example.com&path=%2Fcodex&fp=chrome#single",
        )
        .unwrap();
        assert_eq!(
            node.get(Value::String("type".into())).unwrap().as_str(),
            Some("trojan")
        );
        assert_eq!(
            node.get(Value::String("network".into())).unwrap().as_str(),
            Some("ws")
        );
        assert_eq!(
            node.get(Value::String("udp".into())).unwrap().as_bool(),
            Some(false)
        );
    }
    #[test]
    fn imports_one_base64_trojan_share_link() {
        let link = "trojan://password@example.com:443?security=tls&type=ws&sni=example.com&host=example.com&path=%2Fcodex&fp=chrome#single";
        let encoded = base64::engine::general_purpose::STANDARD.encode(link);
        let node = parse_subscription(encoded.as_bytes()).unwrap();
        assert_eq!(
            node.get(Value::String("type".into())).unwrap().as_str(),
            Some("trojan")
        );
    }
    #[test]
    fn rejects_multiple_share_links() {
        let links = b"trojan://password@example.com:443?security=tls\n\
trojan://password@example.com:443?security=tls\n";
        assert!(
            parse_subscription(links)
                .unwrap_err()
                .to_string()
                .contains("found 2")
        );
    }
    #[test]
    fn rejects_multiple_candidates_and_redacts_parser_errors() {
        let duplicate = format!("{NODE}{}", NODE.trim_start_matches("proxies:\n"));
        assert!(
            parse_subscription(duplicate.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("found 2")
        );
        let error = parse_subscription(b"proxies: [SECRET_INVALID")
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SECRET"));
    }
    #[test]
    fn rejects_malformed_reality_fields() {
        assert!(
            parse_subscription(NODE.replace("short-id: ''", "short-id: invalid").as_bytes())
                .is_err()
        );
        assert!(parse_subscription(NODE.replace("port: 443", "port: 0").as_bytes()).is_err());
        assert!(parse_subscription(NODE.replace("tls: true", "tls: false").as_bytes()).is_ok());
    }
    #[test]
    fn builds_and_sanitizes_vps_websocket_node() {
        let profile = VpsProfile {
            server: "192.0.2.1".into(),
            port: 443,
            sni: "example.com".into(),
            path: "/codex-test".into(),
            uuid: "00000000-0000-0000-0000-000000000001".into(),
        };
        let node = sanitize_node(profile.node().unwrap()).unwrap();
        assert_eq!(
            node.get(Value::String("network".into())).unwrap().as_str(),
            Some("ws")
        );
        assert_eq!(
            node.get(Value::String("ws-opts".into()))
                .unwrap()
                .get(Value::String("path".into()))
                .unwrap()
                .as_str(),
            Some("/codex-test")
        );
        assert!(!node.contains_key(Value::String("dialer-proxy".into())));
    }
}
