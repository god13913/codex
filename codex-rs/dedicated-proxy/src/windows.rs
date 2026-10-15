use anyhow::{Context, Result, bail};
use std::path::Path;

#[cfg(windows)]
pub fn hidden(command: &mut std::process::Command) {
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x08000000);
}
#[cfg(not(windows))]
pub fn hidden(_command: &mut std::process::Command) {}

pub fn private_directory(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).context("cannot create private proxy directory")?;
    #[cfg(windows)]
    {
        let mut identity = std::process::Command::new("whoami.exe");
        hidden(&mut identity);
        let output = identity
            .args(["/user", "/fo", "csv", "/nh"])
            .output()
            .context("cannot resolve current user SID")?;
        let text = String::from_utf8_lossy(&output.stdout);
        let sid = text
            .trim()
            .split(',')
            .next_back()
            .unwrap_or("")
            .trim_matches('"');
        if !output.status.success() || !sid.starts_with("S-1-") {
            bail!("cannot resolve current user SID");
        }
        let mut acl = std::process::Command::new("icacls.exe");
        hidden(&mut acl);
        let output = acl
            .arg(path)
            .args([
                "/inheritance:r",
                "/grant:r",
                &format!("*{sid}:(OI)(CI)F"),
                "*S-1-5-18:(OI)(CI)F",
            ])
            .output()
            .context("cannot protect proxy directory")?;
        if !output.status.success() {
            bail!("cannot protect proxy directory ACL");
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Shows a modal error dialog telling the operator that the fixed proxy port is
/// already held by another program. Windows only; other platforms ignore the call.
#[cfg(windows)]
pub fn alert_port_in_use(port: u16) {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        MessageBoxW, MB_ICONERROR, MB_OK, MB_SETFOREGROUND, MB_TOPMOST,
    };
    let caption: Vec<u16> = OsStr::new("Codex 专用代理")
        .encode_wide()
        .chain(Some(0))
        .collect();
    let text = format!(
        "专用代理端口 {port} 已被其他程序占用，内核无法启动。\r\n\r\n\
         请关闭占用该端口的程序，或在 settings.json 中修改 proxy_port 后重试。"
    );
    let body: Vec<u16> = OsStr::new(&text).encode_wide().chain(Some(0)).collect();
    unsafe {
        MessageBoxW(
            std::ptr::null_mut(),
            body.as_ptr(),
            caption.as_ptr(),
            MB_OK | MB_ICONERROR | MB_TOPMOST | MB_SETFOREGROUND,
        );
    }
}

#[cfg(not(windows))]
pub fn alert_port_in_use(_port: u16) {}

#[cfg(windows)]
pub struct Job {
    _handle: std::os::windows::io::OwnedHandle,
}
#[cfg(not(windows))]
pub struct Job;

#[cfg(windows)]
pub struct ParentProcess(std::os::windows::io::OwnedHandle);
#[cfg(not(windows))]
pub struct ParentProcess;

impl ParentProcess {
    pub fn open(pid: u32) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::io::{FromRawHandle, OwnedHandle};
            use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE};
            let handle = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, pid) };
            if handle.is_null() {
                bail!("cannot monitor desktop process lifetime");
            }
            Ok(Self(unsafe { OwnedHandle::from_raw_handle(handle) }))
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            bail!("desktop proxy supervisor requires Windows");
        }
    }

    pub fn running(&self) -> Result<bool> {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows_sys::Win32::System::Threading::WaitForSingleObject;
            match unsafe { WaitForSingleObject(self.0.as_raw_handle(), 0) } {
                WAIT_TIMEOUT => Ok(true),
                WAIT_OBJECT_0 => Ok(false),
                _ => bail!("cannot inspect desktop process lifetime"),
            }
        }
        #[cfg(not(windows))]
        {
            Ok(false)
        }
    }
}

impl Job {
    pub fn contain(child: &std::process::Child) -> Result<Self> {
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
            use windows_sys::Win32::System::JobObjects::*;
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                bail!("cannot create Mihomo lifetime job");
            }
            let owned = unsafe { OwnedHandle::from_raw_handle(handle) };
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
                || unsafe { AssignProcessToJobObject(handle, child.as_raw_handle()) } == 0
            {
                bail!("cannot contain Mihomo lifetime");
            }
            Ok(Self { _handle: owned })
        }
        #[cfg(not(windows))]
        {
            let _ = child;
            Ok(Self)
        }
    }
}
