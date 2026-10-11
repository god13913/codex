//! Administrator packet forwarding for an unchanged, installed desktop executable.
//! Credentials stay in the user's protected runtime directory, never in arguments.
mod session;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, FILETIME, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::LibraryLoader::{
    GetProcAddress, LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
    LoadLibraryExW,
};
use windows_sys::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

#[derive(Deserialize)]
struct Distribution {
    schema: u32,
    desktop_executable: PathBuf,
    desktop_sha256: String,
    bridge_sha256: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    session_path: PathBuf,
    lease_id: String,
    owner_pid: u32,
    owner_started: u64,
    kernel_pid: u32,
    kernel_started: u64,
    desktop_pid: u32,
    desktop_started: u64,
    desktop_executable: PathBuf,
    owner_sid: String,
    proxy_port: u16,
    proxy_password: String,
    status_path: PathBuf,
}

pub struct BridgeLease {
    request_path: PathBuf,
}

impl BridgeLease {
    pub fn stop(&self) {
        // Release only this backend. The desktop session owns the administrator helper.
        let _ = std::fs::remove_file(&self.request_path);
    }
}

impl Drop for BridgeLease {
    fn drop(&mut self) {
        self.stop();
    }
}

fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 {
        bail!("desktop bridge file exceeds size limit");
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid desktop bridge configuration"))
}

fn distribution() -> Result<(PathBuf, Distribution)> {
    let executable = std::env::current_exe()?;
    let directory = executable
        .parent()
        .context("missing CLI directory")?
        .to_owned();
    let config: Distribution = read_json(&directory.join("desktop-forwarding.json"))?;
    if config.schema != 1 {
        bail!("unsupported desktop bridge configuration");
    }
    Ok((directory, config))
}

fn image(pid: u32) -> Result<PathBuf> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        bail!("cannot inspect desktop process identity");
    }
    let _handle = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut buffer = vec![0u16; 32768];
    let mut size = buffer.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut size) } == 0 {
        bail!("cannot resolve desktop process image");
    }
    use std::os::windows::ffi::OsStringExt;
    Ok(PathBuf::from(std::ffi::OsString::from_wide(
        &buffer[..size as usize],
    )))
}

fn same_path(left: &Path, right: &Path) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

fn started(pid: u32) -> Result<u64> {
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        bail!("cannot inspect forwarding process creation time");
    }
    let _handle = unsafe { OwnedHandle::from_raw_handle(handle) };
    let mut creation: FILETIME = unsafe { std::mem::zeroed() };
    let mut exit = creation;
    let mut kernel = creation;
    let mut user = creation;
    if unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) } == 0 {
        bail!("cannot inspect forwarding process creation time");
    }
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

fn desktop_ancestor(config: &Distribution, start_pid: u32) -> Result<Option<(u32, PathBuf)>> {
    let parents = process_parents()?;
    let Some(parent) = parents.get(&start_pid).copied() else {
        return Ok(None);
    };
    // Only a backend launched directly by an official Electron process may
    // register an endpoint. Tool/MCP descendants must not replace that endpoint.
    if image(parent)
        .ok()
        .is_none_or(|path| !same_path(&path, &config.desktop_executable))
    {
        return Ok(None);
    }
    let mut pid = start_pid;
    let mut desktop = None;
    // Electron can launch a backend through another child. Share the outermost
    // official desktop ancestor, not an individual renderer/backend process.
    for _ in 0..64 {
        let Some(parent) = parents.get(&pid).copied() else {
            break;
        };
        if parent == 0 || parent == pid {
            break;
        }
        if started(parent)
            .ok()
            .zip(started(pid).ok())
            .is_none_or(|(parent, child)| parent > child)
        {
            break;
        }
        pid = parent;
        if let Ok(path) = image(pid) {
            if same_path(&path, &config.desktop_executable) {
                desktop = Some((pid, path));
            }
        }
    }
    Ok(desktop)
}

fn process_parents() -> Result<HashMap<u32, u32>> {
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snapshot == INVALID_HANDLE_VALUE {
        bail!("cannot inspect desktop process ancestry");
    }
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = std::mem::size_of_val(&entry) as u32;
    let mut parents = HashMap::new();
    let mut available = unsafe { Process32FirstW(snapshot, &mut entry) } != 0;
    while available {
        parents.insert(entry.th32ProcessID, entry.th32ParentProcessID);
        available = unsafe { Process32NextW(snapshot, &mut entry) } != 0;
    }
    unsafe {
        CloseHandle(snapshot);
    }
    Ok(parents)
}

fn verify(path: &Path, expected: &str) -> Result<()> {
    let actual = format!("{:X}", Sha256::digest(std::fs::read(path)?));
    if !actual.eq_ignore_ascii_case(expected) {
        bail!("desktop bridge asset checksum mismatch");
    }
    Ok(())
}

fn current_sid() -> Result<String> {
    process_sid(std::process::id())
}

fn process_sid(pid: u32) -> Result<String> {
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Threading::OpenProcessToken;
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        bail!("cannot inspect forwarding owner");
    }
    let _process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        bail!("cannot inspect forwarding owner token");
    }
    let _token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut length);
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(std::mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        bail!("cannot inspect forwarding owner SID");
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut text = std::ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
        bail!("cannot format forwarding owner SID");
    }
    let mut count = 0;
    unsafe {
        while *text.add(count) != 0 {
            count += 1;
        }
    }
    let sid = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, count) });
    unsafe {
        windows_sys::Win32::Foundation::LocalFree(text.cast());
    }
    Ok(sid)
}

fn as_desktop_user<T>(session: &session::Session, action: impl FnOnce() -> Result<T>) -> Result<T> {
    // Never use administrator filesystem access to write an IPC path supplied by
    // a normal user. Validate the owner and impersonate its original token.
    struct RestoreIdentity;
    impl Drop for RestoreIdentity {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::Security::RevertToSelf();
            }
        }
    }
    let _identity = if unsafe { IsUserAnAdmin() } != 0 {
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{
            GetTokenInformation, ImpersonateLoggedOnUser, TOKEN_DUPLICATE, TOKEN_QUERY, TOKEN_USER,
            TokenUser,
        };
        use windows_sys::Win32::System::Threading::OpenProcessToken;
        if current_sid()? != session.owner_sid
            || started(session.desktop_pid)? != session.desktop_started
            || !same_path(&image(session.desktop_pid)?, &session.desktop_executable)
        {
            bail!("forwarding status owner identity mismatch");
        }
        let process =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, session.desktop_pid) };
        if process.is_null() {
            bail!("cannot open forwarding status owner");
        }
        let _process = unsafe { OwnedHandle::from_raw_handle(process) };
        let mut token = std::ptr::null_mut();
        if unsafe { OpenProcessToken(process, TOKEN_QUERY | TOKEN_DUPLICATE, &mut token) } == 0 {
            bail!("cannot open forwarding status identity");
        }
        let _token = unsafe { OwnedHandle::from_raw_handle(token) };
        let mut required = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut required);
        }
        let mut buffer = vec![0usize; (required as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            bail!("cannot inspect forwarding status identity");
        }
        let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
        let mut sid = std::ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid) } == 0 {
            bail!("cannot inspect forwarding owner SID");
        }
        let mut length = 0;
        unsafe {
            while *sid.add(length) != 0 {
                length += 1;
            }
        }
        let owner_sid =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid, length) });
        unsafe {
            windows_sys::Win32::Foundation::LocalFree(sid.cast());
        }
        if owner_sid != session.owner_sid || unsafe { ImpersonateLoggedOnUser(token) } == 0 {
            bail!("cannot impersonate forwarding status owner");
        }
        Some(RestoreIdentity)
    } else {
        None
    };
    action()
}

fn status(
    session: &session::Session,
    state: &str,
    request: Option<&Request>,
    error: Option<&str>,
) -> Result<()> {
    let bridge_pid = std::process::id();
    let bridge_started = started(bridge_pid)?;
    as_desktop_user(session, || {
        let value = serde_json::json!({"state": state, "forwarding_ready": state == "running",
        "owner_pid": request.map(|r| r.owner_pid), "owner_started": request.map(|r| r.owner_started),
        "desktop_pid": session.desktop_pid, "desktop_started": session.desktop_started,
        "bridge_pid": bridge_pid, "bridge_started": bridge_started,
        "proxy_port": request.map(|r| r.proxy_port), "session_shared": true,
        "tcp_ports": [80, 443], "quic_blocked": state == "running",
        "timestamp": super::storage::now(), "error": error});
        let path = &session.status_path;
        let directory = path.parent().context("missing bridge status directory")?;
        let mut file = tempfile::NamedTempFile::new_in(directory)?;
        use std::io::Write;
        file.write_all(&serde_json::to_vec_pretty(&value)?)?;
        file.persist(path)
            .map_err(|_| anyhow::anyhow!("cannot save desktop bridge status"))?;
        Ok(())
    })
}

pub(super) fn attach(runtime: &super::Runtime) -> Result<Option<BridgeLease>> {
    let executable = std::env::current_exe()?;
    // Ordinary terminal/tool invocations must not create another desktop filter.
    if !std::env::args_os()
        .skip(1)
        .any(|value| value == "app-server")
    {
        return Ok(None);
    }
    let Some(selected_cli) = std::env::var_os("CODEX_CLI_PATH") else {
        return Ok(None);
    };
    if !same_path(&executable, Path::new(&selected_cli)) {
        return Ok(None);
    }
    let (_, config) = distribution()?;
    let Some((desktop_pid, desktop_executable)) = desktop_ancestor(&config, std::process::id())?
    else {
        return Ok(None);
    };
    verify(&desktop_executable, &config.desktop_sha256)?;
    session::attach(runtime, desktop_pid, desktop_executable).map(Some)
}

pub(super) fn run(path: &Path) -> Result<()> {
    session::run_broker(path)
}

pub(super) fn run_session(path: &Path) -> Result<()> {
    session::run_coordinator(path)
}

pub(super) fn refresh_status(value: &mut serde_json::Value) {
    let matches = |pid_field: &str, creation_field: &str| {
        let Some(pid) = value
            .get(pid_field)
            .and_then(serde_json::Value::as_u64)
            .and_then(|pid| u32::try_from(pid).ok())
        else {
            return false;
        };
        super::windows::ParentProcess::open(pid)
            .and_then(|process| process.running())
            .unwrap_or(false)
            && value
                .get(creation_field)
                .and_then(serde_json::Value::as_u64)
                .is_none_or(|creation| started(pid).ok() == Some(creation))
    };
    let desktop_running = matches("desktop_pid", "desktop_started");
    let worker_running = matches("bridge_pid", "bridge_started");
    let owner_running = matches("owner_pid", "owner_started");
    if !desktop_running {
        value["forwarding_ready"] = serde_json::json!(false);
        value["state"] = serde_json::json!("stopped");
    } else if value
        .get("forwarding_ready")
        .and_then(serde_json::Value::as_bool)
        == Some(true)
        && (!worker_running || !owner_running)
    {
        value["forwarding_ready"] = serde_json::json!(false);
        value["state"] = serde_json::json!("waiting-for-backend");
    }
}

pub(super) fn run_worker(path: &Path) -> Result<()> {
    if unsafe { IsUserAnAdmin() } == 0 {
        bail!("administrator privileges are required");
    }
    // The request file is next to a credential-free, validated session descriptor.
    // All user-supplied file access is impersonated, including reading credentials.
    let session_path = path
        .parent()
        .context("missing session directory")?
        .join("session.json");
    let session = session::load(&session_path)?;
    let request = as_desktop_user(&session, || session::read_request(path))?;
    let _owners = session::validate_request(&session, &session_path, &request)?;
    let result = run_inner(path, &request, &session);
    if result.is_err() {
        let _ = status(
            &session,
            "failed",
            Some(&request),
            Some(
                "Administrator forwarding failed. Check asset integrity, process identity and driver availability.",
            ),
        );
    }
    result
}

fn run_inner(path: &Path, request: &Request, session: &session::Session) -> Result<()> {
    if unsafe { IsUserAnAdmin() } == 0 {
        bail!("administrator privileges are required");
    }
    if request.proxy_port == 0
        || request.proxy_password.len() != 64
        || !request.owner_sid.starts_with("S-1-")
    {
        bail!("invalid forwarding owner or endpoint");
    }
    let (directory, config) = distribution()?;
    let owner = super::windows::ParentProcess::open(request.owner_pid)?;
    let desktop = super::windows::ParentProcess::open(request.desktop_pid)?;
    if !same_path(&image(request.owner_pid)?, &std::env::current_exe()?)
        || !same_path(&image(request.desktop_pid)?, &config.desktop_executable)
        || !same_path(&request.desktop_executable, &config.desktop_executable)
        || desktop_ancestor(&config, request.owner_pid)?.map(|v| v.0) != Some(request.desktop_pid)
    {
        bail!("desktop forwarding process identity mismatch");
    }
    verify(&config.desktop_executable, &config.desktop_sha256)?;
    verify(&directory.join("ProxyBridge.dll"), &config.bridge_sha256)?;
    verify(
        &directory.join("WinDivert.dll"),
        "C1E060EE19444A259B2162F8AF0F3FE8C4428A1C6F694DCE20DE194AC8D7D9A2",
    )?;
    verify(
        &directory.join("WinDivert64.sys"),
        "8DA085332782708D8767BCACE5327A6EC7283C17CFB85E40B03CD2323A90DDC2",
    )?;
    let dll = wide(directory.join("ProxyBridge.dll"));
    let module = unsafe {
        LoadLibraryExW(
            dll.as_ptr(),
            std::ptr::null_mut(),
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_DEFAULT_DIRS,
        )
    };
    if module.is_null() {
        bail!("cannot load dedicated packet forwarding library");
    }
    macro_rules! function {
        ($name:literal, $signature:ty) => {{
            let pointer = unsafe { GetProcAddress(module, concat!($name, "\0").as_ptr()) }
                .context("missing packet forwarding entrypoint")?;
            unsafe {
                std::mem::transmute::<unsafe extern "system" fn() -> isize, $signature>(pointer)
            }
        }};
    }
    let set_owner = function!(
        "ProxyBridge_SetOwnerSid",
        unsafe extern "C" fn(*const i8) -> i32
    );
    let add_proxy = function!(
        "ProxyBridge_AddProxyConfig",
        unsafe extern "C" fn(i32, *const i8, u16, *const i8, *const i8, i32) -> u32
    );
    let add_rule = function!(
        "ProxyBridge_AddRule",
        unsafe extern "C" fn(*const i8, *const i8, *const i8, *const i8, i32, i32, u32) -> u32
    );
    let traffic_logging = function!(
        "ProxyBridge_SetTrafficLoggingEnabled",
        unsafe extern "C" fn(i32)
    );
    let start = function!("ProxyBridge_Start", unsafe extern "C" fn() -> i32);
    let stop = function!("ProxyBridge_Stop", unsafe extern "C" fn() -> i32);
    let sid = CString::new(request.owner_sid.as_str())?;
    let process = CString::new(request.desktop_executable.to_string_lossy().as_bytes())?;
    let password = CString::new(request.proxy_password.as_str())?;
    unsafe {
        if set_owner(sid.as_ptr()) == 0 {
            bail!("cannot restrict packet forwarding to its owner");
        }
        traffic_logging(0);
        let proxy = add_proxy(
            0,
            c"127.0.0.1".as_ptr(),
            request.proxy_port,
            c"codex".as_ptr(),
            password.as_ptr(),
            0,
        );
        if proxy == 0
            || add_rule(
                process.as_ptr(),
                c"*".as_ptr(),
                c"80;443".as_ptr(),
                c"".as_ptr(),
                0,
                0,
                proxy,
            ) == 0
            || add_rule(
                process.as_ptr(),
                c"*".as_ptr(),
                c"443".as_ptr(),
                c"".as_ptr(),
                1,
                2,
                proxy,
            ) == 0
        {
            bail!("cannot configure dedicated desktop forwarding rules");
        }
        if start() == 0 {
            bail!("dedicated packet forwarding driver did not start");
        }
    }
    let result = (|| -> Result<()> {
        status(session, "running", Some(request), None)?;
        while owner.running()?
            && desktop.running()?
            && as_desktop_user(session, || Ok(path.is_file()))?
        {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(())
    })();
    unsafe {
        stop();
    }
    let _ = status(session, "waiting-for-backend", None, None);
    result
}
