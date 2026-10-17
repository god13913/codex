//! Let the configured desktop verify service identities across the SYSTEM boundary.
//! This never grants process control, memory access, token access, or filesystem rights.
use super::wide;
use anyhow::{Context, Result, bail};
use std::os::windows::io::{FromRawHandle, OwnedHandle};
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSidToSidW, EXPLICIT_ACCESS_W, GRANT_ACCESS, GetSecurityInfo, NO_MULTIPLE_TRUSTEE,
    SE_KERNEL_OBJECT, SetEntriesInAclW, SetSecurityInfo, TRUSTEE_IS_SID, TRUSTEE_IS_USER,
    TRUSTEE_W,
};
use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, NO_INHERITANCE};
use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};

// Standard access rights READ_CONTROL and WRITE_DAC, only used by the owning service.
const PROCESS_SECURITY_ACCESS: u32 = 0x0002_0000 | 0x0004_0000;
struct LocalAllocation(*mut std::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
fn account_sid(value: &str) -> Result<LocalAllocation> {
    let mut sid = std::ptr::null_mut();
    if unsafe { ConvertStringSidToSidW(wide(value).as_ptr(), &mut sid) } == 0 {
        return Err(std::io::Error::last_os_error()).context("invalid desktop identity SID");
    }
    Ok(LocalAllocation(sid))
}
fn query_entry(sid: &LocalAllocation) -> EXPLICIT_ACCESS_W {
    EXPLICIT_ACCESS_W {
        grfAccessPermissions: PROCESS_QUERY_LIMITED_INFORMATION,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: NO_INHERITANCE,
        Trustee: TRUSTEE_W {
            pMultipleTrustee: std::ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_USER,
            ptstrName: sid.0.cast(),
        },
    }
}
pub(super) fn allow_identity_queries(pid: u32, owner_sid: &str) -> Result<()> {
    let sid = account_sid(owner_sid)?;
    let process = unsafe { OpenProcess(PROCESS_SECURITY_ACCESS, 0, pid) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("cannot open service process identity ACL");
    }
    let _process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut descriptor = std::ptr::null_mut();
    let mut old_acl = std::ptr::null_mut();
    let code = unsafe {
        GetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut old_acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32))
            .context("cannot read service process identity ACL");
    }
    let _descriptor = LocalAllocation(descriptor);
    if old_acl.is_null() {
        bail!("service process identity ACL must not be unrestricted");
    }
    let mut new_acl = std::ptr::null_mut();
    let code = unsafe { SetEntriesInAclW(1, &query_entry(&sid), old_acl, &mut new_acl) };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32))
            .context("cannot build service process identity ACL");
    }
    let _new_acl = LocalAllocation(new_acl.cast());
    let code = unsafe {
        SetSecurityInfo(
            process,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            new_acl,
            std::ptr::null(),
        )
    };
    if code != 0 {
        return Err(std::io::Error::from_raw_os_error(code as i32))
            .context("cannot grant limited service identity queries");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Child, Command, Stdio};
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{
        PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_VM_WRITE,
    };

    struct Fixture(Child);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn fixture() -> Fixture {
        let executable = std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap())
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let mut command = Command::new(executable);
        crate::windows::hidden(&mut command);
        Fixture(
            command
                .args([
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Start-Sleep -Seconds 60",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    }
    fn allowed(pid: u32, access: u32) -> bool {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if handle.is_null() {
            false
        } else {
            unsafe {
                CloseHandle(handle);
            }
            true
        }
    }
    fn restrict_fixture(pid: u32, owner: &str) {
        let owner_sid = account_sid(owner).unwrap();
        let system_sid = account_sid("S-1-5-18").unwrap();
        let mut owner_entry = query_entry(&owner_sid);
        // Keep fixture cleanup/security-management rights but deny identity and memory queries.
        owner_entry.grfAccessPermissions = PROCESS_SECURITY_ACCESS | 0x0010_0000 | 1;
        let mut system_entry = query_entry(&system_sid);
        system_entry.grfAccessPermissions = 0x001f_ffff;
        let entries = [owner_entry, system_entry];
        let mut acl = std::ptr::null_mut();
        assert_eq!(
            unsafe { SetEntriesInAclW(2, entries.as_ptr(), std::ptr::null(), &mut acl) },
            0
        );
        let _acl = LocalAllocation(acl.cast());
        let process = unsafe { OpenProcess(PROCESS_SECURITY_ACCESS, 0, pid) };
        assert!(!process.is_null());
        let _process = unsafe { OwnedHandle::from_raw_handle(process) };
        assert_eq!(
            unsafe {
                SetSecurityInfo(
                    process,
                    SE_KERNEL_OBJECT,
                    DACL_SECURITY_INFORMATION,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    acl,
                    std::ptr::null(),
                )
            },
            0
        );
    }
    #[test]
    fn owner_can_verify_restricted_process_without_memory_or_thread_rights() {
        let child = fixture();
        let pid = child.0.id();
        let owner = super::super::current_sid().unwrap();
        assert_ne!(owner, "S-1-5-18", "run this fixture as the desktop user");
        restrict_fixture(pid, &owner);
        assert!(!allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION));
        allow_identity_queries(pid, &owner).unwrap();
        assert!(allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION));
        assert!(super::super::image(pid).unwrap().is_absolute());
        assert!(super::super::started(pid).unwrap() > 0);
        for access in [PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_CREATE_THREAD] {
            assert!(!allowed(pid, access), "unexpected process access: {access}");
        }
        allow_identity_queries(pid, &owner).unwrap();
        assert!(allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION));
        assert!(!allowed(pid, PROCESS_VM_READ));
    }
    #[test]
    fn granting_queries_preserves_existing_process_access() {
        let child = fixture();
        let pid = child.0.id();
        let owner = super::super::current_sid().unwrap();
        let original = allowed(pid, PROCESS_VM_READ);
        allow_identity_queries(pid, &owner).unwrap();
        assert_eq!(allowed(pid, PROCESS_VM_READ), original);
        assert!(allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION));
    }
    #[test]
    fn malformed_sid_does_not_change_process_permissions() {
        let child = fixture();
        let pid = child.0.id();
        let before = allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION);
        assert!(allow_identity_queries(pid, "not-a-sid").is_err());
        assert_eq!(allowed(pid, PROCESS_QUERY_LIMITED_INFORMATION), before);
    }
}
