//! A service-owned inbound exception for the actual dual-stack TCP relay port.
//! The fixed PS5.1 script is compiled into the binary. No user script is run as SYSTEM.
use anyhow::{Context, Result, bail};
use base64::Engine;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

const SCRIPT: &str = include_str!("relay_firewall.ps1");

pub(super) struct RelayFirewall {
    port: u16,
    executable: PathBuf,
    powershell: PathBuf,
}

struct ScriptChild(Child);
impl Drop for ScriptChild {
    fn drop(&mut self) {
        // Only our own worker is terminated on timeout/error; no name-based kill.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl RelayFirewall {
    pub(super) fn install(port: u16) -> Result<Self> {
        if port == 0 || super::current_sid()? != "S-1-5-18" {
            bail!("relay firewall setup requires the SYSTEM service and a bound port");
        }
        let mut buffer = [0u16; 32768];
        let count = unsafe { GetSystemDirectoryW(buffer.as_mut_ptr(), buffer.len() as u32) } as usize;
        if count == 0 || count >= buffer.len() { bail!("cannot locate Windows system directory"); }
        let powershell = PathBuf::from(String::from_utf16(&buffer[..count])?)
            .join("WindowsPowerShell").join("v1.0").join("powershell.exe");
        let guard = Self { port, executable: std::env::current_exe()?, powershell };
        // If setup partially succeeds, Drop attempts to remove this exact rule.
        guard.run("Apply")?;
        Ok(guard)
    }

    fn run(&self, action: &str) -> Result<()> {
        let bytes: Vec<u8> = SCRIPT.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let mut command = Command::new(&self.powershell);
        command.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
            .env("CODEX_RELAY_ACTION", action)
            .env("CODEX_RELAY_PORT", self.port.to_string())
            .env("CODEX_RELAY_SERVICE_PID", std::process::id().to_string())
            .env("CODEX_RELAY_PROGRAM", &self.executable)
            // Import only the OS module, never a module from a user's search path.
            .env("PSModulePath", self.powershell.parent().context("missing PowerShell directory")?.join("Modules"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        crate::windows::hidden(&mut command);
        let mut worker = ScriptChild(command.spawn().context("cannot start trusted relay firewall worker")?);
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = worker.0.try_wait()? {
                if !status.success() { bail!("relay firewall {action} failed (exit {})", status.code().unwrap_or(-1)); }
                return Ok(());
            }
            if Instant::now() >= deadline { bail!("relay firewall {action} timed out"); }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for RelayFirewall {
    fn drop(&mut self) {
        // ActiveStore exceptions do not survive reboot. On a normal stop remove
        // ours now; a crashed service's stale rule is replaced on the next start.
        let _ = self.run("Remove");
    }
}
