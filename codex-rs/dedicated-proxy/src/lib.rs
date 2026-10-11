//! Private subscription transport for Codex service requests. No global proxy environment changes.
#[cfg(windows)]
mod desktop;
mod storage;
mod windows;

use anyhow::{Context, Result, bail};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::{IsTerminal, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const CORE_VERSION: &str = "1.19.32";
const CORE_SHA256: &str = "3C107D54EF1B895E4980B53F517D52F3C1137101FA2637347C9CE343FC50D7B2";
static ACTIVE: Mutex<Option<Weak<Runtime>>> = Mutex::new(None);
static START: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub struct ProxyGuard(Arc<Runtime>);
struct Runtime {
    home: PathBuf,
    proxy_url: String,
    controller: String,
    controller_secret: String,
    proxy_port: u16,
    password: String,
    child: Mutex<Child>,
    #[cfg(windows)]
    bridge: Mutex<Option<desktop::BridgeLease>>,
    _job: windows::Job,
    _directory: tempfile::TempDir,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Ok(bridge) = self.bridge.get_mut() {
            if let Some(bridge) = bridge {
                bridge.stop();
            }
        }
        if let Ok(child) = self.child.get_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub fn active_proxy_url() -> Option<String> {
    ACTIVE
        .lock()
        .ok()?
        .as_ref()?
        .upgrade()
        .map(|runtime| runtime.proxy_url.clone())
}

pub fn enabled(home: &Path) -> Result<bool> {
    Ok(storage::settings(home)?.enabled)
}

pub fn custom_distribution() -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| {
            p.parent()
                .map(|p| p.join("codex-dedicated-proxy.distribution"))
        })
        .is_some_and(|p| p.is_file())
}

fn random_secret() -> String {
    rand::random::<[u8; 32]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn core_path() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("cannot locate Codex executable")?;
    let directory = exe.parent().context("cannot locate Codex distribution")?;
    let candidate = directory.join(if cfg!(windows) {
        "codex-mihomo.exe"
    } else {
        "codex-mihomo"
    });
    if !candidate.is_file() {
        bail!("dedicated Mihomo core is missing from the Codex directory");
    }
    let bytes = std::fs::read(&candidate).context("cannot read dedicated Mihomo core")?;
    let hash = format!("{:X}", Sha256::digest(bytes));
    if hash != CORE_SHA256 {
        bail!("dedicated Mihomo core checksum does not match the pinned distribution");
    }
    Ok(candidate)
}

fn private_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|_| anyhow::anyhow!("cannot create private kernel control client"))
}

fn configuration(runtime: &Runtime, node: &serde_yaml::Mapping) -> Result<String> {
    let node = serde_json::to_value(node)
        .map_err(|_| anyhow::anyhow!("cannot serialize validated node"))?;
    // JSON is accepted by Mihomo's YAML loader. Use its own serializer so dependency-level
    // serde_json/arbitrary_precision cannot turn numeric ports into private YAML mappings.
    serde_json::to_string(&json!({
        "port": runtime.proxy_port, "socks-port": 0, "mixed-port": 0,
        "redir-port": 0, "tproxy-port": 0, "allow-lan": false, "bind-address": "127.0.0.1",
        "mode": "rule", "log-level": "silent", "find-process-mode": "off",
        "authentication": if runtime.password.is_empty() { Vec::<String>::new() } else { vec![format!("codex:{}", runtime.password)] },
        "skip-auth-prefixes": [],
        "external-controller": runtime.controller, "secret": runtime.controller_secret,
        "tun": {"enable": false}, "dns": {"enable": false},
        "sniffer": {"enable": true, "parse-pure-ip": true,
            "sniff": {"TLS": {"ports": [443], "override-destination": true},
                "HTTP": {"ports": [80], "override-destination": true}}},
        "profile": {"store-selected": false, "store-fake-ip": false},
        "proxies": [node], "rules": ["MATCH,CODEX"]
    }))
    .map_err(|_| anyhow::anyhow!("cannot serialize private kernel configuration"))
}

async fn apply_node(runtime: &Runtime, node: &serde_yaml::Mapping) -> Result<()> {
    let payload = configuration(runtime, node)?;
    let response = private_client()?
        .put(format!("http://{}/configs?force=true", runtime.controller))
        .bearer_auth(&runtime.controller_secret)
        .json(&json!({"payload": payload}))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("Mihomo configuration connection failed"))?;
    if !response.status().is_success() {
        bail!(
            "Mihomo rejected the private configuration (HTTP {})",
            response.status().as_u16()
        );
    }
    // Do not read or expose the kernel's payload-bearing error response.
    Ok(())
}

pub async fn start_if_enabled(home: &Path) -> Result<Option<ProxyGuard>> {
    let _start = START.lock().await;
    let mut settings = storage::settings(home)?;
    if !settings.enabled {
        return Ok(None);
    }
    if let Some(existing) = ACTIVE
        .lock()
        .map_err(|_| anyhow::anyhow!("proxy runtime lock failed"))?
        .as_ref()
        .and_then(Weak::upgrade)
    {
        if existing.home != home {
            bail!("a dedicated proxy for another CODEX_HOME is already active");
        }
        return Ok(Some(ProxyGuard(existing)));
    }
    let initial_node = match settings.mode {
        storage::Mode::Subscription => {
            let config = storage::subscription_config(home)?;
            let fallback = storage::cache(home)
                .ok()
                .filter(|cache| cache.subscription == config.url);
            match fallback {
                Some(cache) => cache.node,
                None => match storage::download_selected(&config, None).await {
                    Ok(cache) => {
                        // The plain JSON file is the source of truth; the cache only
                        // keeps the last validated node for a temporary outage.
                        storage::save_subscription_config(home, &config)?;
                        storage::save_cache(home, &cache)?;
                        settings.updated_at = storage::now();
                        settings.last_error = None;
                        storage::save_settings(home, &settings)?;
                        cache.node
                    }
                    Err(error) => {
                        settings.last_error = Some(format!("subscription refresh failed: {error}"));
                        storage::save_settings(home, &settings)?;
                        return Err(error.context(
                            "subscription unavailable and no matching cached node exists",
                        ));
                    }
                },
            }
        }
        storage::Mode::Vps => storage::vps_profile(home)?.node()?,
        storage::Mode::Node => storage::node_profile(home)?,
    };
    let core = core_path()?;
    let root = storage::directory(home);
    windows::private_directory(&root)?;
    let runtime_dir = tempfile::Builder::new()
        .prefix("runtime-")
        .tempdir_in(&root)
        .context("cannot create private kernel runtime")?;
    windows::private_directory(runtime_dir.path())?;
    // Reserve both ports simultaneously, then release immediately before starting the kernel.
    let proxy_listener =
        TcpListener::bind("127.0.0.1:0").context("cannot reserve private proxy port")?;
    let control_listener =
        TcpListener::bind("127.0.0.1:0").context("cannot reserve private control port")?;
    let proxy_port = proxy_listener.local_addr()?.port();
    let controller = control_listener.local_addr()?.to_string();
    let secret = random_secret();
    let password = random_secret();
    let bootstrap = serde_json::to_string(&json!({
        "port": 0, "socks-port": 0, "mixed-port": 0, "allow-lan": false,
        "bind-address": "127.0.0.1", "log-level": "silent", "mode": "rule", "find-process-mode": "off",
        "external-controller": controller, "secret": secret,
        "tun": {"enable": false}, "dns": {"enable": false},
        "profile": {"store-selected": false, "store-fake-ip": false}, "rules": ["MATCH,REJECT"]
    }))?;
    let bootstrap_path = runtime_dir.path().join("bootstrap.yaml");
    std::fs::write(&bootstrap_path, bootstrap).context("cannot write private kernel bootstrap")?;
    let mut command = Command::new(core);
    windows::hidden(&mut command);
    command
        .arg("-d")
        .arg(runtime_dir.path())
        .arg("-f")
        .arg(&bootstrap_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    drop(proxy_listener);
    drop(control_listener);
    let mut child = command
        .spawn()
        .context("cannot start dedicated Mihomo core")?;
    let job = match windows::Job::contain(&child) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    let runtime = Arc::new(Runtime {
        home: home.to_owned(),
        proxy_url: if password.is_empty() {
            format!("http://127.0.0.1:{proxy_port}")
        } else {
            format!("http://codex:{password}@127.0.0.1:{proxy_port}")
        },
        controller,
        controller_secret: secret,
        proxy_port,
        password,
        child: Mutex::new(child),
        #[cfg(windows)]
        bridge: Mutex::new(None),
        _job: job,
        _directory: runtime_dir,
    });
    let client = private_client()?;
    let mut ready = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while tokio::time::Instant::now() < deadline {
        if runtime
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel process lock failed"))?
            .try_wait()?
            .is_some()
        {
            bail!("dedicated Mihomo core exited during startup");
        }
        if let Ok(response) = client
            .get(format!("http://{}/version", runtime.controller))
            .bearer_auth(&runtime.controller_secret)
            .send()
            .await
        {
            if response.status().is_success() {
                let value: serde_json::Value = response
                    .json()
                    .await
                    .map_err(|_| anyhow::anyhow!("invalid kernel version response"))?;
                if value
                    .get("version")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| v.trim_start_matches('v') == CORE_VERSION)
                {
                    ready = true;
                    break;
                }
                bail!("unsupported dedicated Mihomo version");
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    if !ready {
        bail!("dedicated Mihomo startup timed out");
    }
    apply_node(&runtime, &initial_node).await?;
    if runtime.password.is_empty() {
        // Desktop HTTP proxies do not support credentials embedded in the URL.
        // Check only the local listener; do not generate an upstream probe.
        std::net::TcpStream::connect_timeout(
            &std::net::SocketAddr::from(([127, 0, 0, 1], proxy_port)),
            Duration::from_secs(1),
        )
        .context("dedicated desktop proxy listener did not start")?;
    } else {
        let listener_probe = client
            .get(format!("http://127.0.0.1:{proxy_port}/"))
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("dedicated Mihomo proxy listener did not start"))?;
        if listener_probe.status() != reqwest::StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            bail!("dedicated Mihomo proxy authentication check failed");
        }
    }
    *ACTIVE
        .lock()
        .map_err(|_| anyhow::anyhow!("proxy runtime lock failed"))? =
        Some(Arc::downgrade(&runtime));
    #[cfg(windows)]
    match desktop::attach(&runtime) {
        Ok(bridge) => {
            *runtime
                .bridge
                .lock()
                .map_err(|_| anyhow::anyhow!("desktop bridge lock failed"))? = bridge;
        }
        Err(error) => {
            settings.last_error = Some(format!("desktop forwarding unavailable: {error}"));
            storage::save_settings(home, &settings)?;
        }
    }
    if settings.mode == storage::Mode::Subscription {
        refresh_in_background(Arc::downgrade(&runtime));
    }
    Ok(Some(ProxyGuard(runtime)))
}

fn refresh_in_background(runtime: Weak<Runtime>) {
    tokio::spawn(async move {
        loop {
            let Some(active) = runtime.upgrade() else {
                return;
            };
            let home = active.home.clone();
            let proxy = active.proxy_url.clone();
            drop(active);
            let result = async {
                let config = storage::subscription_config(&home)?;
                let cache = storage::download_selected(&config, Some(&proxy)).await?;
                let current = storage::subscription_config(&home)?;
                let mut settings = storage::settings(&home)?;
                if current != config || settings.mode != storage::Mode::Subscription || !settings.enabled {
                    return Ok::<(), anyhow::Error>(());
                }
                if let Some(active) = runtime.upgrade() {
                    // Avoid disrupting streams when a refresh returns the same node.
                    if storage::cache(&home)
                        .ok()
                        .is_none_or(|old| old.node != cache.node)
                    {
                        apply_node(&active, &cache.node).await?;
                    }
                    storage::save_cache(&home, &cache)?;
                    settings.updated_at = storage::now();
                    settings.last_error = None;
                    storage::save_settings(&home, &settings)?;
                }
                Ok(())
            }
            .await;
            let delay = if let Err(error) = result {
                if let Ok(mut settings) = storage::settings(&home) {
                    settings.last_error = Some(error.to_string());
                    let _ = storage::save_settings(&home, &settings);
                }
                Duration::from_secs(30)
            } else {
                Duration::from_secs(15 * 60)
            };
            tokio::time::sleep(delay).await;
        }
    });
}

pub fn run_desktop_bridge(request: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        desktop::run(request)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        bail!("desktop forwarding requires Windows");
    }
}

pub fn run_desktop_bridge_session(request: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        desktop::run_session(request)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        bail!("desktop forwarding requires Windows");
    }
}

pub fn run_desktop_bridge_worker(request: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        desktop::run_worker(request)
    }
    #[cfg(not(windows))]
    {
        let _ = request;
        bail!("desktop forwarding requires Windows");
    }
}

impl ProxyGuard {
    /// Local process metadata only; useful for proving parent-exit cleanup without exposing credentials.
    pub fn local_process(&self) -> Result<(u32, u16, u16)> {
        let pid = self
            .0
            .child
            .lock()
            .map_err(|_| anyhow::anyhow!("kernel process lock failed"))?
            .id();
        let port = self
            .0
            .controller
            .rsplit(':')
            .next()
            .and_then(|value| value.parse().ok())
            .context("invalid local control port")?;
        Ok((pid, self.0.proxy_port, port))
    }
    /// Aggregate only: never return destinations, node parameters, or authentication headers.
    pub async fn connection_count(&self) -> Result<usize> {
        let response = private_client()?
            .get(format!("http://{}/connections", self.0.controller))
            .bearer_auth(&self.0.controller_secret)
            .send()
            .await
            .map_err(|_| anyhow::anyhow!("kernel diagnostics unavailable"))?;
        let body: serde_json::Value = response
            .json()
            .await
            .map_err(|_| anyhow::anyhow!("invalid kernel diagnostic response"))?;
        Ok(body
            .get("connections")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len))
    }
}

pub async fn manage(home: &Path, action: &str, from_stdin: bool) -> Result<serde_json::Value> {
    let mut settings = storage::settings(home)?;
    match action {
        "configure" | "import" => {
            let input = if from_stdin || !std::io::stdin().is_terminal() {
                let mut input = String::new();
                std::io::stdin()
                    .take(8193)
                    .read_to_string(&mut input)
                    .context("cannot read subscription input")?;
                if input.len() > 8192 {
                    bail!("subscription URL input too long");
                }
                input
            } else {
                rpassword::prompt_password("Subscription URL (hidden): ")
                    .context("cannot read subscription input")?
            };
            let config = storage::SubscriptionConfig {
                url: input.trim().to_owned(),
                selected_node_name: None,
                selected_node_id: None,
            };
            let cache = match storage::download(&config.url, None).await {
                Ok(cache) => cache,
                Err(error) => {
                    settings.last_error = Some(error.to_string());
                    storage::save_settings(home, &settings)?;
                    return Err(error);
                }
            };
            storage::save_subscription_config(home, &config)?;
            storage::save_cache(home, &cache)?;
            settings.enabled = true;
            settings.mode = storage::Mode::Subscription;
            settings.updated_at = storage::now();
            settings.last_error = None;
            storage::save_settings(home, &settings)?;
        }
        "refresh" => {
            if settings.mode != storage::Mode::Subscription {
                bail!("the active VPS profile does not require subscription refresh");
            }
            let config = storage::subscription_config(home)?;
            match storage::download_selected(&config, None).await {
                Ok(cache) => {
                    storage::save_subscription_config(home, &config)?;
                    storage::save_cache(home, &cache)?;
                    settings.updated_at = storage::now();
                    settings.last_error = None;
                }
                Err(error) => {
                    settings.last_error = Some(error.to_string());
                    storage::save_settings(home, &settings)?;
                    return Err(error);
                }
            }
            storage::save_settings(home, &settings)?;
        }
        "vps-import" => {
            let input = if from_stdin || !std::io::stdin().is_terminal() {
                let mut input = String::new();
                std::io::stdin()
                    .take(8193)
                    .read_to_string(&mut input)
                    .context("cannot read VPS profile input")?;
                if input.len() > 8192 {
                    bail!("VPS profile input too long");
                }
                input
            } else {
                rpassword::prompt_password("VPS profile JSON (hidden): ")
                    .context("cannot read VPS profile input")?
            };
            let profile: storage::VpsProfile = serde_json::from_str(input.trim())
                .map_err(|_| anyhow::anyhow!("invalid VPS profile JSON"))?;
            storage::save_vps_profile(home, &profile)?;
            settings.enabled = true;
            settings.mode = storage::Mode::Vps;
            settings.updated_at = storage::now();
            settings.last_error = None;
            storage::save_settings(home, &settings)?;
        }
        "enable" => {
            match settings.mode {
                storage::Mode::Subscription => {
                    storage::subscription_config(home)?;
                }
                storage::Mode::Vps => {
                    storage::vps_profile(home)?;
                }
                storage::Mode::Node => { storage::node_profile(home)?; }
            }
            settings.enabled = true;
            storage::save_settings(home, &settings)?;
        }
        "disable" => {
            settings.enabled = false;
            storage::save_settings(home, &settings)?;
        }
        "status" => {}
        _ => bail!("unknown proxy command"),
    }
    let subscription_present = storage::directory(home).join("subscription.json").exists();
    let subscription_error = if subscription_present {
        storage::subscription_config(home)
            .err()
            .map(|error| error.to_string())
    } else {
        None
    };
    let cache_path = storage::directory(home).join("subscription-cache.json");
    let legacy_cache_present =
        !cache_path.exists() && subscription_present && storage::cache(home).is_ok();
    let cache_present = cache_path.exists() || legacy_cache_present;
    let cache_error = if cache_present {
        storage::cache(home).err().map(|error| error.to_string())
    } else {
        None
    };
    let vps_present = storage::directory(home).join("vps-profile.json").exists();
    let vps_error = if vps_present {
        storage::vps_profile(home)
            .err()
            .map(|error| error.to_string())
    } else {
        None
    };
    let desktop_forwarding =
        std::fs::read(storage::directory(home).join("desktop-forwarding-status.json"))
            .ok()
            .filter(|bytes| bytes.len() < 32 * 1024)
            .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .map(|mut value| {
                #[cfg(windows)]
                desktop::refresh_status(&mut value);
                value
            });
    Ok(
        json!({"enabled": settings.enabled, "mode": settings.mode.as_str(), "subscription_config_present": subscription_present, "subscription_config_valid": subscription_present && subscription_error.is_none(), "subscription_config_error": subscription_error, "cache_present": cache_present, "cache_valid": cache_present && cache_error.is_none(), "cache_error": cache_error, "vps_profile_present": vps_present, "vps_profile_valid": vps_present && vps_error.is_none(), "vps_profile_error": vps_error, "updated_at": settings.updated_at, "last_error": settings.last_error, "kernel_version": CORE_VERSION, "desktop_forwarding": desktop_forwarding}),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires the pinned core next to the test executable"]
    async fn real_kernel_lifecycle_authentication_and_failure() {
        let home = tempfile::tempdir().unwrap();
        let fixture = "proxies:\n- type: vless\n  server: example.invalid\n  port: 443\n  uuid: 00000000-0000-0000-0000-000000000001\n  tls: true\n  servername: example.invalid\n  reality-opts:\n    public-key: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n    short-id: ''\n";
        let cache = storage::Cache {
            subscription: "https://example.invalid/subscription".into(),
            node: storage::parse_subscription(fixture.as_bytes()).unwrap(),
        };
        storage::save_subscription_config(
            home.path(),
            &storage::SubscriptionConfig {
                url: cache.subscription.clone(),
                selected_node_name: None,
                selected_node_id: None,
            },
        )
        .unwrap();
        storage::save_cache(home.path(), &cache).unwrap();
        storage::save_settings(
            home.path(),
            &storage::Settings {
                enabled: true,
                mode: storage::Mode::Subscription,
                updated_at: storage::now(),
                last_error: None,
            },
        )
        .unwrap();
        let guard = start_if_enabled(home.path()).await.unwrap().unwrap();
        let port = guard.0.proxy_port;
        let control = guard.0.controller.clone();
        let startup =
            std::fs::read_to_string(guard.0._directory.path().join("bootstrap.yaml")).unwrap();
        assert!(!startup.contains("example.invalid"));
        assert!(!startup.contains("00000000-0000"));
        let second = start_if_enabled(home.path()).await.unwrap().unwrap();
        assert!(Arc::ptr_eq(&guard.0, &second.0));
        drop(second);
        drop(guard);
        assert!(active_proxy_url().is_none());
        assert!(TcpListener::bind(format!("127.0.0.1:{port}")).is_ok());
        assert!(TcpListener::bind(&control).is_ok());
        let guard = start_if_enabled(home.path()).await.unwrap().unwrap();
        let port = guard.0.proxy_port;
        let control = guard.0.controller.clone();
        guard.0.child.lock().unwrap().kill().unwrap();
        guard.0.child.lock().unwrap().wait().unwrap();
        assert!(guard.connection_count().await.is_err());
        drop(guard);
        assert!(active_proxy_url().is_none());
        assert!(TcpListener::bind(format!("127.0.0.1:{port}")).is_ok());
        assert!(TcpListener::bind(control).is_ok());
    }
    #[test]
    fn corrupt_plain_cache_is_rejected_without_echoing_content() {
        let home = tempfile::tempdir().unwrap();
        let dir = storage::directory(home.path());
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("subscription.json"), "SECRET_NOT_JSON").unwrap();
        let error = storage::cache(home.path()).err().unwrap().to_string();
        assert!(!error.contains("SECRET"));
    }
}
