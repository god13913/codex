//! Opt-in SCM service. Assets and machine-encrypted configuration must be installed
//! into administrator-owned directories; no user-provided command is run as SYSTEM.
use super::{current_sid, distribution, image, process_parents, read_json, same_path, started, wide};
use crate::storage;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use std::time::Duration;
use windows_sys::Win32::System::Services::*;

const NAME: &str = "CodexDedicatedProxy";
static STOP: AtomicBool = AtomicBool::new(false);
static HANDLE: AtomicPtr<std::ffi::c_void> = AtomicPtr::new(std::ptr::null_mut());

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Config { schema: u32, owner_sid: String }

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    schema: u32, forwarding_ready: bool, firewall_ready: bool, relay_port: u16,
    service_pid: u32, service_started: u64,
    kernel_pid: u32, kernel_started: u64, owner_sid: String, proxy_port: u16,
    cli_executable: PathBuf,
}
fn root() -> Result<PathBuf> {
    let directory = std::env::current_exe()?.parent().context("missing service directory")?.to_path_buf();
    // The install script creates this sibling directory with SYSTEM/Admin write ACLs.
    Ok(directory.parent().context("missing service root")?.to_path_buf())
}
fn config_path() -> Result<PathBuf> { Ok(root()?.join("service.json")) }

/// Called interactively by the installing administrator, never by the service.
/// Transfer only the selected node, not subscription history or user login data.
pub(crate) fn prepare(home: &Path) -> Result<()> {
    if unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } == 0 || current_sid()? == "S-1-5-18" {
        bail!("service preparation requires the configuring user's administrator token");
    }
    let mut settings = storage::settings(home)?;
    if !settings.enabled { bail!("dedicated proxy must be configured before service installation"); }
    let node = match settings.mode {
        storage::Mode::Vps => storage::vps_profile(home)?.node()?,
        storage::Mode::Node => storage::node_profile(home)?,
        storage::Mode::Subscription => {
            let subscription = storage::subscription_config(home)?;
            let cached = storage::cache(home)?;
            if cached.subscription != subscription.url { bail!("refresh the selected subscription before service installation"); }
            cached.node
        }
    };
    let directory = root()?.join("home").join("dedicated-proxy");
    if !directory.is_dir() { bail!("protected service directories have not been installed"); }
    settings.mode = storage::Mode::Node;
    settings.last_error = None;
    let mut plain = serde_json::to_vec(&node)?;
    let encrypted = storage::protect_machine(&plain);
    plain.fill(0);
    std::fs::write(directory.join("node-profile.json"), encrypted?)?;
    // This directory is not readable by ordinary users (unlike ready.json).
    std::fs::write(directory.join("settings.json"), serde_json::to_vec(&settings)?)?;
    std::fs::write(config_path()?, serde_json::to_vec(&Config { schema: 1, owner_sid: current_sid()? })?)?;
    Ok(())
}

fn report(state: u32, code: u32) {
    let value = SERVICE_STATUS { dwServiceType: SERVICE_WIN32_OWN_PROCESS, dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_RUNNING { SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN } else { 0 },
        dwWin32ExitCode: code, dwServiceSpecificExitCode: 0,
        dwCheckPoint: if state == SERVICE_START_PENDING { 1 } else { 0 }, dwWaitHint: 60000 };
    unsafe { SetServiceStatus(HANDLE.load(Ordering::SeqCst), &value); }
}
unsafe extern "system" fn control(code: u32, _: u32, _: *mut std::ffi::c_void, _: *mut std::ffi::c_void) -> u32 {
    if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
        STOP.store(true, Ordering::SeqCst);
        report(SERVICE_STOP_PENDING, 0);
    } else if code == SERVICE_CONTROL_INTERROGATE {
        // SCM retains the current status; do not claim RUNNING during startup.
    }
    0
}
fn publish(ready: &Ready) -> Result<()> {
    use std::io::Write;
    let directory = root()?;
    let mut file = tempfile::NamedTempFile::new_in(&directory)?;
    file.write_all(&serde_json::to_vec(ready)?)?;
    file.persist(directory.join("ready.json")).map_err(|_| anyhow::anyhow!("cannot publish service readiness"))?;
    Ok(())
}
async fn serve() -> Result<()> {
    if current_sid()? != "S-1-5-18" { bail!("persistent forwarding must be started by SCM as LocalSystem"); }
    let config: Config = read_json(&config_path()?)?;
    if config.schema != 1 || !config.owner_sid.starts_with("S-1-") || config.owner_sid == "S-1-5-18" {
        bail!("invalid service owner");
    }
    // A medium-integrity desktop cannot query a default SYSTEM process DACL.
    // Keep client-side PID/image/creation-time checks and grant only the right
    // those checks need, before publishing any readiness to the desktop.
    super::identity_acl::allow_identity_queries(std::process::id(), &config.owner_sid)?;
    let (assets, _) = distribution()?;
    let home = root()?.join("home");
    let settings = storage::settings(&home)?;
    if !settings.enabled { bail!("service proxy is disabled"); }
    // The filter matches future processes; it is installed before kernel startup
    // and before SCM publishes RUNNING. No desktop/backend ancestry is required.
    let forwarding = super::start_forwarding(storage::effective_proxy_port(&settings),
        &storage::effective_proxy_password(&settings), &config.owner_sid, false)?;
    let relay_port = forwarding.tcp_relay_port()?;
    // Reflected SYNs are inbound traffic. A listening socket alone does not
    // establish readiness when Windows Firewall defaults to blocking inbound.
    // This guard installs/verifies the current port, and removes only its rule.
    let _firewall = super::relay_firewall::RelayFirewall::install(relay_port)?;
    let mut ready = Ready { schema: 1, forwarding_ready: false, firewall_ready: true, relay_port,
        service_pid: std::process::id(), service_started: started(std::process::id())?,
        kernel_pid: 0, kernel_started: 0, owner_sid: config.owner_sid,
        proxy_port: storage::effective_proxy_port(&settings), cli_executable: assets.join("codex.exe") };
    publish(&ready)?;
    let runtime = crate::start_if_enabled(&home).await?.context("service proxy disabled")?;
    crate::authenticate_service_endpoint(ready.proxy_port, &storage::effective_proxy_password(&settings)).await?;
    forwarding.ready();
    let (pid, _, _) = runtime.local_process()?;
    super::identity_acl::allow_identity_queries(pid, &ready.owner_sid)?;
    let kernel = crate::windows::ParentProcess::open(pid)?;
    ready.kernel_pid = pid; ready.kernel_started = started(pid)?; ready.forwarding_ready = true;
    publish(&ready)?;
    report(SERVICE_RUNNING, 0);
    while !STOP.load(Ordering::SeqCst) && kernel.running()? {
        // The multi-source desktop package scan already ran when
        // start_forwarding installed the service rules. Keep the service
        // alive without rescanning while it owns the kernel.
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    ready.forwarding_ready = false;
    let _ = publish(&ready);
    if !STOP.load(Ordering::SeqCst) { bail!("service kernel exited"); }
    Ok(())
}
unsafe extern "system" fn service_main(_: u32, _: *mut *mut u16) {
    let name = wide(NAME);
    let handle = unsafe { RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), std::ptr::null_mut()) };
    if handle.is_null() { return; }
    HANDLE.store(handle, Ordering::SeqCst); STOP.store(false, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0);
    let result = tokio::runtime::Builder::new_current_thread().enable_all().build()
        .map_err(anyhow::Error::from).and_then(|runtime| runtime.block_on(serve()));
    // No credentials or configuration values are written to the Windows event log.
    if result.is_err() {
        if let Ok(directory) = root() { let _ = std::fs::remove_file(directory.join("ready.json")); }
    }
    report(SERVICE_STOPPED, if result.is_ok() { 0 } else { 1066 });
}
pub(crate) fn run() -> Result<()> {
    let name = wide(NAME);
    let entries = [SERVICE_TABLE_ENTRYW { lpServiceName: name.as_ptr().cast_mut(), lpServiceProc: Some(service_main) },
        SERVICE_TABLE_ENTRYW { lpServiceName: std::ptr::null_mut(), lpServiceProc: None }];
    if unsafe { StartServiceCtrlDispatcherW(entries.as_ptr()) } == 0 { bail!("start this binary using Windows Service Control Manager"); }
    Ok(())
}

/// A running, identity-checked SCM service may replace a desktop-owned kernel.
/// A local listening port or stale status file alone is never sufficient proof.
fn service_state() -> Result<Option<SERVICE_STATUS_PROCESS>> {
    let name = wide(NAME);
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() { bail!("cannot inspect persistent service status"); }
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG) };
    let open_error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
    unsafe { CloseServiceHandle(manager); }
    if service.is_null() {
        if open_error == 1060 { return Ok(None); }
        bail!("cannot inspect installed persistent service");
    }
    let result = (|| -> Result<SERVICE_STATUS_PROCESS> {
        let mut state: SERVICE_STATUS_PROCESS = unsafe { std::mem::zeroed() }; let mut bytes = 0;
        if unsafe { QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO, (&raw mut state).cast(),
            std::mem::size_of_val(&state) as u32, &mut bytes) } == 0 {
            bail!("cannot query installed persistent service");
        }
        // SCM's administrator-controlled account configuration is queryable by
        // the user. Reading a SYSTEM process token is not required or attempted.
        let mut buffer = vec![0usize; 8192 / std::mem::size_of::<usize>()];
        let config = buffer.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
        if unsafe { QueryServiceConfigW(service, config, 8192, &mut bytes) } == 0 {
            bail!("cannot validate service account configuration");
        }
        let account = unsafe { (*config).lpServiceStartName };
        if account.is_null() { bail!("service account is missing"); }
        let mut length = 0;
        while length < 256 && unsafe { *account.add(length) } != 0 { length += 1; }
        let account = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(account,length) });
        if !account.eq_ignore_ascii_case("LocalSystem") { bail!("persistent service must use LocalSystem"); }
        Ok(state)
    })();
    unsafe { CloseServiceHandle(service); }
    result.map(Some)
}
pub(crate) async fn ready_for_desktop(port: u16) -> Result<bool> {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
    let Some(state) = service_state()? else { return Ok(false); };
    if state.dwCurrentState == SERVICE_START_PENDING && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(200)).await;
        continue;
    }
    if state.dwCurrentState != SERVICE_RUNNING || state.dwProcessId == 0 {
        bail!("installed persistent service is not ready; restart it before opening the desktop");
    }
    let (assets, config) = distribution()?;
    let ready: Ready = read_json(&root()?.join("ready.json"))?;
    if ready.schema != 1 || !ready.forwarding_ready || !ready.firewall_ready || ready.relay_port == 0 ||
        ready.service_pid != state.dwProcessId ||
        ready.proxy_port != port || ready.owner_sid != current_sid()? ||
        started(ready.service_pid)? != ready.service_started ||
        !same_path(&image(ready.service_pid)?, &assets.join("codex-proxy-service.exe")) ||
        !same_path(&ready.cli_executable, &std::env::current_exe()?) ||
        !same_path(&image(ready.kernel_pid)?, &assets.join("codex-mihomo.exe")) ||
        started(ready.kernel_pid)? != ready.kernel_started ||
        process_parents()?.get(&ready.kernel_pid) != Some(&ready.service_pid) {
        bail!("persistent service identity or readiness mismatch");
    }
    super::verify(&config.desktop_executable, &config.desktop_sha256)?;
    return Ok(true);
    }
}
