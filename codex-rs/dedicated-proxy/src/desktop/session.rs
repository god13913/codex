//! One elevation attempt per desktop lifetime, independent of app-server lifetimes.
//!
//! A detached, unelevated coordinator owns the UAC call. The elevated broker stays
//! alive with the desktop and replaces only its own forwarding worker on handoff.
//! The DLL has mutable process-global proxy state, so workers use separate address
//! spaces instead of editing credentials underneath its live network threads.
use super::{
    BridgeLease, Request, as_desktop_user, current_sid, desktop_ancestor, distribution, image,
    process_parents, process_sid, read_json, same_path, started, status, verify, wide,
};
use crate::windows::{Job, ParentProcess};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use windows_sys::Win32::Foundation::{ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION};
use windows_sys::Win32::System::Threading::{CREATE_BREAKAWAY_FROM_JOB, CREATE_NO_WINDOW};
use windows_sys::Win32::UI::Shell::{
    IsUserAnAdmin, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Session {
    schema: u32,
    pub(super) desktop_pid: u32,
    pub(super) desktop_started: u64,
    pub(super) desktop_executable: PathBuf,
    cli_executable: PathBuf,
    pub(super) owner_sid: String,
    pub(super) status_path: PathBuf,
}

fn directory(pid: u32, creation: u64) -> Result<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").context("missing local application directory")?;
    let local = PathBuf::from(local);
    if !local.is_absolute() {
        bail!("invalid local application directory");
    }
    Ok(local
        .join("CodexProxy")
        .join("DesktopSessions")
        .join(format!("{pid}-{creation:016x}")))
}

fn write_once(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file =
        tempfile::NamedTempFile::new_in(path.parent().context("missing session directory")?)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    match file.persist_noclobber(path) {
        Ok(_) => Ok(()),
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(_) => bail!("cannot publish desktop session state"),
    }
}

// Windows sharing restrictions are released by the OS even on process crashes.
// No user-writable PID file is treated as proof that a broker is running.
fn try_lock(path: &Path) -> Result<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .share_mode(0)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(error) if matches!(error.raw_os_error(), Some(code) if code == ERROR_SHARING_VIOLATION as i32 || code == ERROR_LOCK_VIOLATION as i32) => {
            Ok(None)
        }
        Err(_) => bail!("cannot acquire desktop session lock"),
    }
}

pub(super) fn load(path: &Path) -> Result<Session> {
    // Derive the anchor process from the expected directory before reading any
    // user-provided descriptor with administrator privileges.
    let folder = path
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .context("invalid desktop session directory")?;
    let (pid, creation) = folder
        .split_once('-')
        .context("invalid desktop session identity")?;
    let pid: u32 = pid.parse().context("invalid desktop session process")?;
    let creation =
        u64::from_str_radix(creation, 16).context("invalid desktop session creation time")?;
    if !same_path(path, &directory(pid, creation)?.join("session.json")) {
        bail!("unexpected desktop session descriptor path");
    }
    let (_, config) = distribution()?;
    let desktop = ParentProcess::open(pid)?;
    if !desktop.running()?
        || started(pid)? != creation
        || !same_path(&image(pid)?, &config.desktop_executable)
    {
        bail!("desktop session no longer matches the running desktop");
    }
    let anchor = Session {
        schema: 1,
        desktop_pid: pid,
        desktop_started: creation,
        desktop_executable: config.desktop_executable,
        cli_executable: std::env::current_exe()?,
        owner_sid: current_sid()?,
        status_path: PathBuf::new(),
    };
    if process_sid(pid)? != anchor.owner_sid {
        bail!("desktop session belongs to another Windows user");
    }
    let session: Session = as_desktop_user(&anchor, || read_json(path))?;
    if session.schema != 1
        || session.desktop_pid != pid
        || session.desktop_started != creation
        || session.owner_sid != anchor.owner_sid
        || !same_path(&session.desktop_executable, &anchor.desktop_executable)
        || !same_path(&session.cli_executable, &anchor.cli_executable)
        || !session.status_path.is_absolute()
        || session
            .status_path
            .file_name()
            .and_then(|name| name.to_str())
            != Some("desktop-forwarding-status.json")
    {
        bail!("desktop session identity mismatch");
    }
    verify(&session.desktop_executable, &config.desktop_sha256)?;
    Ok(session)
}

pub(super) fn attach(
    runtime: &crate::Runtime,
    desktop_pid: u32,
    desktop_executable: PathBuf,
) -> Result<BridgeLease> {
    let session = Session {
        schema: 1,
        desktop_pid,
        desktop_started: started(desktop_pid)?,
        desktop_executable,
        cli_executable: std::env::current_exe()?,
        owner_sid: current_sid()?,
        status_path: crate::storage::directory(&runtime.home)
            .join("desktop-forwarding-status.json"),
    };
    if process_sid(desktop_pid)? != session.owner_sid {
        bail!("desktop belongs to another Windows user");
    }
    let root = directory(session.desktop_pid, session.desktop_started)?;
    crate::windows::private_directory(&root)?;
    let path = root.join("session.json");
    write_once(&path, &serde_json::to_vec(&session)?)?;
    if read_json::<Session>(&path)? != session {
        bail!(
            "desktop session already uses another CLI or CODEX_HOME; restart the desktop to switch"
        );
    }
    let kernel_pid = runtime
        .child
        .lock()
        .map_err(|_| anyhow::anyhow!("kernel process lock failed"))?
        .id();
    let request = Request {
        session_path: path.clone(),
        lease_id: crate::random_secret(),
        owner_pid: std::process::id(),
        owner_started: started(std::process::id())?,
        kernel_pid,
        kernel_started: started(kernel_pid)?,
        desktop_pid,
        desktop_started: session.desktop_started,
        desktop_executable: session.desktop_executable.clone(),
        owner_sid: session.owner_sid.clone(),
        proxy_port: runtime.proxy_port,
        proxy_password: runtime.password.clone(),
        status_path: session.status_path.clone(),
    };
    let request_path = root.join(format!("endpoint-{}.json", request.lease_id));
    let mut plain = serde_json::to_vec(&request)?;
    let protected = crate::storage::protect(&plain);
    plain.fill(0);
    write_once(&request_path, &protected?)?;
    let lease = BridgeLease { request_path };
    if !root.join("elevation-attempted.json").exists() {
        let mut command = Command::new(&session.cli_executable);
        command
            .args(["proxy", "bridge-session", "--request"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .current_dir(
                session
                    .cli_executable
                    .parent()
                    .context("missing CLI directory")?,
            )
            .creation_flags(CREATE_NO_WINDOW | CREATE_BREAKAWAY_FROM_JOB);
        // Like the daemon launcher, do not fall back to a parent-owned Job. The
        // coordinator must survive backend replacement while the UAC UI is open.
        let _child = command.spawn().context(
            "cannot detach desktop authorization coordinator; the host job must allow breakaway",
        )?;
    }
    Ok(lease)
}

pub(super) fn run_coordinator(path: &Path) -> Result<()> {
    let session = load(path)?;
    let root = path.parent().context("missing session directory")?;
    let Some(_launch) = try_lock(&root.join("launch.lock"))? else {
        return Ok(());
    };
    let attempted = root.join("elevation-attempted.json");
    if attempted.exists() {
        return Ok(());
    }
    // Publish before runas. A denied prompt or a failed helper must not turn a
    // backend restart into another surprise prompt in the same desktop session.
    write_once(&attempted, br#"{"attempted":true}"#)?;
    status(&session, "awaiting-administrator", None, None)?;
    let executable = wide(&session.cli_executable);
    let verb = wide("runas");
    let parameters = wide(format!("proxy bridge --request \"{}\"", path.display()));
    let mut launch: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    launch.cbSize = std::mem::size_of_val(&launch) as u32;
    launch.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
    launch.lpVerb = verb.as_ptr();
    launch.lpFile = executable.as_ptr();
    launch.lpParameters = parameters.as_ptr();
    launch.nShow = SW_HIDE;
    if unsafe { ShellExecuteExW(&mut launch) } == 0 || launch.hProcess.is_null() {
        let _ = status(
            &session,
            "elevation-denied",
            None,
            Some(
                "Desktop forwarding was not authorized. Restart the desktop to request authorization again.",
            ),
        );
        bail!("Windows administrator forwarding was not approved or could not start");
    }
    let _process = unsafe { OwnedHandle::from_raw_handle(launch.hProcess) };
    Ok(())
}

pub(super) fn read_request(path: &Path) -> Result<Request> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(32 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 {
        bail!("desktop endpoint exceeds size limit");
    }
    let envelope: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("invalid protected desktop endpoint"))?;
    if envelope.get("format").and_then(serde_json::Value::as_str) != Some("codex-dpapi-v1") {
        bail!("desktop endpoints must use current-user encryption");
    }
    let mut plain = crate::storage::unprotect(&bytes)?;
    let request =
        serde_json::from_slice(&plain).map_err(|_| anyhow::anyhow!("invalid desktop endpoint"));
    plain.fill(0);
    request
}

pub(super) fn validate_request(
    session: &Session,
    session_path: &Path,
    request: &Request,
) -> Result<[ParentProcess; 3]> {
    if request.desktop_pid != session.desktop_pid
        || request.desktop_started != session.desktop_started
        || request.owner_sid != session.owner_sid
        || !same_path(&request.session_path, session_path)
        || !same_path(&request.desktop_executable, &session.desktop_executable)
        || !same_path(&request.status_path, &session.status_path)
        || request.lease_id.len() != 64
        || !request.lease_id.bytes().all(|b| b.is_ascii_hexdigit())
        || request.proxy_port == 0
        || request.proxy_password.len() != 64
        || !request
            .proxy_password
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        bail!("desktop endpoint identity mismatch");
    }
    let desktop = ParentProcess::open(session.desktop_pid)?;
    let owner = ParentProcess::open(request.owner_pid)?;
    let kernel = ParentProcess::open(request.kernel_pid)?;
    if !desktop.running()?
        || !owner.running()?
        || !kernel.running()?
        || started(session.desktop_pid)? != session.desktop_started
        || started(request.owner_pid)? != request.owner_started
        || started(request.kernel_pid)? != request.kernel_started
        || process_sid(request.owner_pid)? != session.owner_sid
        || process_sid(request.kernel_pid)? != session.owner_sid
        || !same_path(&image(request.owner_pid)?, &session.cli_executable)
        || !same_path(
            &image(request.kernel_pid)?,
            &session.cli_executable.with_file_name("codex-mihomo.exe"),
        )
        || process_parents()?.get(&request.kernel_pid).copied() != Some(request.owner_pid)
    {
        bail!("desktop endpoint process no longer matches its owner");
    }
    let (_, config) = distribution()?;
    if desktop_ancestor(&config, request.owner_pid)?.map(|value| value.0)
        != Some(session.desktop_pid)
    {
        bail!("desktop endpoint is not owned by this desktop session");
    }
    Ok([desktop, owner, kernel])
}

struct Endpoint {
    path: PathBuf,
    request: Request,
    // Keep the checked process objects alive so PID reuse cannot authorize a new process.
    _owners: [ParentProcess; 3],
}

fn select_endpoint(session: &Session, path: &Path) -> Result<Option<Endpoint>> {
    as_desktop_user(session, || {
        let mut candidates = Vec::new();
        for entry in std::fs::read_dir(path.parent().context("missing session directory")?)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("endpoint-") || !name.ends_with(".json") {
                continue;
            }
            let Ok(request) = read_request(&entry.path()) else {
                continue;
            };
            if name != format!("endpoint-{}.json", request.lease_id) {
                continue;
            }
            let Ok(owners) = validate_request(session, path, &request) else {
                continue;
            };
            candidates.push(Endpoint {
                path: entry.path(),
                request,
                _owners: owners,
            });
        }
        // During a graceful replacement both backends may briefly be alive.
        // Prefer the newest one and fall back to a surviving backend if it exits.
        Ok(candidates.into_iter().max_by_key(|endpoint| {
            (
                endpoint.request.owner_started,
                endpoint.request.kernel_started,
            )
        }))
    })
}

struct Worker {
    endpoint: Endpoint,
    child: Child,
    _job: Job,
}

impl Drop for Worker {
    fn drop(&mut self) {
        // This process was created by this broker. Closing its handles removes
        // its WinDivert filters before a replacement worker starts.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_worker(session: &Session, endpoint: Endpoint) -> Result<Worker> {
    status(session, "starting", Some(&endpoint.request), None)?;
    let mut command = Command::new(&session.cli_executable);
    crate::windows::hidden(&mut command);
    command
        .args(["proxy", "bridge-worker", "--request"])
        .arg(&endpoint.path)
        .current_dir(
            session
                .cli_executable
                .parent()
                .context("missing CLI directory")?,
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Inherit the already elevated broker token. There is no runas call here.
    let mut child = command
        .spawn()
        .context("cannot start desktop forwarding worker")?;
    let job = match Job::contain(&child) {
        Ok(job) => job,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error);
        }
    };
    Ok(Worker {
        endpoint,
        child,
        _job: job,
    })
}

pub(super) fn run_broker(path: &Path) -> Result<()> {
    if unsafe { IsUserAnAdmin() } == 0 {
        bail!("administrator privileges are required");
    }
    let session = load(path)?;
    let desktop = ParentProcess::open(session.desktop_pid)?;
    if started(session.desktop_pid)? != session.desktop_started {
        bail!("desktop session ended");
    }
    let root = path.parent().context("missing session directory")?;
    let Some(_broker) = as_desktop_user(&session, || try_lock(&root.join("broker.lock")))? else {
        return Ok(());
    };
    status(&session, "waiting-for-backend", None, None)?;
    let result = broker_loop(&session, path, &desktop);
    if result.is_err() && desktop.running().unwrap_or(false) {
        let _ = status(
            &session,
            "failed",
            None,
            Some(
                "The shared desktop helper stopped. Restart the desktop to request authorization again.",
            ),
        );
    }
    // Session files are ordinary user data. Keep the attempt marker for this
    // desktop lifetime; a new PID/creation-time pair gets a fresh authorization.
    result
}

fn broker_loop(session: &Session, path: &Path, desktop: &ParentProcess) -> Result<()> {
    let mut worker: Option<Worker> = None;
    let mut failed_lease: Option<String> = None;
    while desktop.running()? {
        if let Some(active) = worker.as_mut() {
            if active.child.try_wait()?.is_some() {
                failed_lease = Some(active.endpoint.request.lease_id.clone());
                status(
                    session,
                    "worker-stopped",
                    Some(&active.endpoint.request),
                    Some("The forwarding worker stopped; waiting for a new backend."),
                )?;
                worker = None;
            }
        }
        let next = select_endpoint(session, path)?;
        let current_id = worker
            .as_ref()
            .map(|active| active.endpoint.request.lease_id.as_str());
        let next_id = next
            .as_ref()
            .map(|endpoint| endpoint.request.lease_id.as_str());
        if current_id != next_id {
            // Destroy and wait for our old worker before installing new filters.
            drop(worker.take());
            match next {
                Some(endpoint)
                    if failed_lease.as_deref() != Some(endpoint.request.lease_id.as_str()) =>
                {
                    let lease = endpoint.request.lease_id.clone();
                    match start_worker(session, endpoint) {
                        Ok(next) => {
                            worker = Some(next);
                            failed_lease = None;
                        }
                        Err(_) => {
                            failed_lease = Some(lease);
                            let _ = status(
                                session,
                                "worker-stopped",
                                None,
                                Some(
                                    "Cannot start the forwarding worker; waiting for a new backend.",
                                ),
                            );
                        }
                    }
                }
                Some(_) => {}
                None => {
                    status(session, "waiting-for-backend", None, None)?;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    // Drop kills only our forwarding worker; the desktop process owns this lifetime.
    drop(worker);
    Ok(())
}
