//! Process-isolation probe for the elevated backend.
//!
//! The parent test starts a *victim* process at medium integrity whose process
//! DACL models a standard user's default DACL (the user and SYSTEM full
//! control, the logon SID read and execute). It then runs this test binary
//! inside the sandbox with `CODEX_ISOLATION_PROBE_PID` set, and
//! [`isolation_probe_child`] reports which `OpenProcess` rights the sandboxed
//! process obtains on the victim, together with its own token groups.

use crate::token::get_logon_sid_bytes;
use crate::token::token_groups;
use crate::winutil::string_from_sid_bytes;
use crate::winutil::to_wide;
use std::collections::BTreeMap;
use std::ffi::c_void;

pub(super) const PROBE_PID_ENV: &str = "CODEX_ISOLATION_PROBE_PID";
pub(super) const PROBE_TEST_NAME: &str =
    "unified_exec::tests::isolation_probe::isolation_probe_child";

type Handle = *mut c_void;

const PROCESS_TERMINATE: u32 = 0x0001;
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_READ: u32 = 0x0010;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_DUP_HANDLE: u32 = 0x0040;
const PROCESS_CREATE_PROCESS: u32 = 0x0080;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const READ_CONTROL: u32 = 0x0002_0000;
const WRITE_DAC: u32 = 0x0004_0000;
const WRITE_OWNER: u32 = 0x0008_0000;
const TOKEN_DUPLICATE: u32 = 0x0002;
const TOKEN_QUERY: u32 = 0x0008;
const TOKEN_ADJUST_DEFAULT: u32 = 0x0080;
const TOKEN_ASSIGN_PRIMARY: u32 = 0x0001;
const TOKEN_ADJUST_SESSIONID: u32 = 0x0100;
const TOKEN_RESTRICTED_SIDS_CLASS: i32 = 11;
const TOKEN_INTEGRITY_LEVEL_CLASS: i32 = 25;
const TOKEN_USER_CLASS: i32 = 1;
const SECURITY_IMPERSONATION: i32 = 2;
const TOKEN_PRIMARY: i32 = 1;
const SE_GROUP_INTEGRITY: u32 = 0x20;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MEDIUM_INTEGRITY_SID: &str = "S-1-16-8192";

/// Rights whose grant would let the sandbox tamper with, inject into, read or
/// stop the user's process. Each is probed on its own.
pub(super) const PROBED_RIGHTS: &[(&str, u32)] = &[
    (
        "vm_write_operation",
        PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
    ),
    ("create_thread", PROCESS_CREATE_THREAD),
    ("dup_handle", PROCESS_DUP_HANDLE),
    ("create_process", PROCESS_CREATE_PROCESS),
    ("set_information", PROCESS_SET_INFORMATION),
    ("suspend_resume", PROCESS_SUSPEND_RESUME),
    ("write_dac", WRITE_DAC),
    ("write_owner", WRITE_OWNER),
    ("terminate", PROCESS_TERMINATE),
    ("vm_read", PROCESS_VM_READ),
    ("query_information", PROCESS_QUERY_INFORMATION),
    ("read_control", READ_CONTROL),
    ("query_limited", PROCESS_QUERY_LIMITED_INFORMATION),
];

#[repr(C)]
struct SidAndAttributes {
    sid: *mut c_void,
    attributes: u32,
}

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    security_descriptor: *mut c_void,
    inherit_handle: i32,
}

#[repr(C)]
struct StartupInfoW {
    cb: u32,
    reserved: *mut u16,
    desktop: *mut u16,
    title: *mut u16,
    x: u32,
    y: u32,
    x_size: u32,
    y_size: u32,
    x_count_chars: u32,
    y_count_chars: u32,
    fill_attribute: u32,
    flags: u32,
    show_window: u16,
    reserved2_len: u16,
    reserved2: *mut u8,
    std_input: Handle,
    std_output: Handle,
    std_error: Handle,
}

#[repr(C)]
struct ProcessInformation {
    process: Handle,
    thread: Handle,
    process_id: u32,
    thread_id: u32,
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetCurrentProcess() -> Handle;
    fn OpenProcess(desired_access: u32, inherit_handle: i32, process_id: u32) -> Handle;
    fn TerminateProcess(process: Handle, exit_code: u32) -> i32;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(mem: *mut c_void) -> *mut c_void;
}

#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Handle, desired_access: u32, token: *mut Handle) -> i32;
    fn DuplicateTokenEx(
        existing: Handle,
        desired_access: u32,
        attributes: *const SecurityAttributes,
        impersonation_level: i32,
        token_type: i32,
        new_token: *mut Handle,
    ) -> i32;
    fn SetTokenInformation(
        token: Handle,
        class: i32,
        information: *const c_void,
        length: u32,
    ) -> i32;
    fn GetTokenInformation(
        token: Handle,
        class: i32,
        information: *mut c_void,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
    fn ConvertStringSidToSidW(string_sid: *const u16, sid: *mut *mut c_void) -> i32;
    fn ConvertSidToStringSidW(sid: *mut c_void, string_sid: *mut *mut u16) -> i32;
    fn GetLengthSid(sid: *mut c_void) -> u32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string_sd: *const u16,
        revision: u32,
        sd: *mut *mut c_void,
        sd_size: *mut u32,
    ) -> i32;
    fn CreateProcessAsUserW(
        token: Handle,
        application_name: *const u16,
        command_line: *mut u16,
        process_attributes: *const SecurityAttributes,
        thread_attributes: *const SecurityAttributes,
        inherit_handles: i32,
        creation_flags: u32,
        environment: *const c_void,
        current_directory: *const u16,
        startup_info: *const StartupInfoW,
        process_information: *mut ProcessInformation,
    ) -> i32;
}

/// A medium-integrity process owned by the test whose DACL models a standard
/// user's default process DACL. Terminated on drop.
pub(super) struct Victim {
    process: Handle,
    pub(super) pid: u32,
    pub(super) logon_sid: String,
}

impl Drop for Victim {
    fn drop(&mut self) {
        // SAFETY: `process` is a handle this struct owns.
        unsafe {
            TerminateProcess(self.process, 0);
            CloseHandle(self.process);
        }
    }
}

impl Victim {
    pub(super) fn is_running(&self) -> bool {
        const WAIT_TIMEOUT: u32 = 0x102;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn WaitForSingleObject(handle: Handle, milliseconds: u32) -> u32;
        }
        // SAFETY: `process` is a valid handle owned by this struct.
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_TIMEOUT }
    }
}

fn sid_string(sid: *mut c_void) -> String {
    let mut raw: *mut u16 = std::ptr::null_mut();
    // SAFETY: `sid` is a valid SID; `raw` is freed with LocalFree.
    unsafe {
        if ConvertSidToStringSidW(sid, &mut raw) == 0 || raw.is_null() {
            return "<invalid>".to_string();
        }
        let len = (0..).take_while(|&i| *raw.add(i) != 0).count();
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(raw, len));
        LocalFree(raw.cast());
        text
    }
}

/// Starts `ping -n 900 127.0.0.1` as the victim. Its token retains the
/// administrator groups/privileges; token-access results are indicative only.
pub(super) fn spawn_victim() -> Result<Victim, String> {
    // SAFETY: plain Win32 calls on handles and buffers owned by this function;
    // every allocation is released before returning.
    unsafe {
        let mut own_token: Handle = std::ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut own_token,
        ) == 0
        {
            return Err(format!("OpenProcessToken failed: {}", GetLastError()));
        }
        let user_sid = crate::token::get_user_sid_bytes(own_token)
            .map_err(|err| format!("user SID: {err}"))
            .and_then(|sid| string_from_sid_bytes(&sid));
        let logon_sid = get_logon_sid_bytes(own_token)
            .map_err(|err| format!("logon SID: {err}"))
            .and_then(|sid| string_from_sid_bytes(&sid));
        let (user_sid, logon_sid) = match (user_sid, logon_sid) {
            (Ok(user), Ok(logon)) => (user, logon),
            (user, logon) => {
                CloseHandle(own_token);
                return Err(format!("victim SIDs: {user:?} {logon:?}"));
            }
        };
        let mut token: Handle = std::ptr::null_mut();
        let duplicated = DuplicateTokenEx(
            own_token,
            TOKEN_DUPLICATE
                | TOKEN_QUERY
                | TOKEN_ASSIGN_PRIMARY
                | TOKEN_ADJUST_DEFAULT
                | TOKEN_ADJUST_SESSIONID,
            std::ptr::null(),
            SECURITY_IMPERSONATION,
            TOKEN_PRIMARY,
            &mut token,
        );
        CloseHandle(own_token);
        if duplicated == 0 {
            return Err(format!("DuplicateTokenEx failed: {}", GetLastError()));
        }
        // Lower the copy to medium integrity, where the user's own processes
        // run; a high-integrity victim would be shielded by no-read-up alone.
        let mut medium_sid: *mut c_void = std::ptr::null_mut();
        if ConvertStringSidToSidW(to_wide(MEDIUM_INTEGRITY_SID).as_ptr(), &mut medium_sid) == 0 {
            CloseHandle(token);
            return Err(format!("ConvertStringSidToSidW failed: {}", GetLastError()));
        }
        let label = SidAndAttributes {
            sid: medium_sid,
            attributes: SE_GROUP_INTEGRITY,
        };
        let lowered = SetTokenInformation(
            token,
            TOKEN_INTEGRITY_LEVEL_CLASS,
            (&label as *const SidAndAttributes).cast(),
            (std::mem::size_of::<SidAndAttributes>() as u32) + GetLengthSid(medium_sid),
        );
        LocalFree(medium_sid);
        if lowered == 0 {
            CloseHandle(token);
            return Err(format!(
                "SetTokenInformation(IL) failed: {}",
                GetLastError()
            ));
        }
        let sddl = format!("D:(A;;GA;;;{user_sid})(A;;GA;;;SY)(A;;GRGX;;;{logon_sid})");
        let mut sd: *mut c_void = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            to_wide(&sddl).as_ptr(),
            1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            CloseHandle(token);
            return Err(format!("SDDL {sddl} failed: {}", GetLastError()));
        }
        let attributes = SecurityAttributes {
            length: std::mem::size_of::<SecurityAttributes>() as u32,
            security_descriptor: sd,
            inherit_handle: 0,
        };
        let mut startup: StartupInfoW = std::mem::zeroed();
        startup.cb = std::mem::size_of::<StartupInfoW>() as u32;
        let mut info: ProcessInformation = std::mem::zeroed();
        let mut command_line = to_wide(r"C:\Windows\System32\PING.EXE -n 900 127.0.0.1");
        let created = CreateProcessAsUserW(
            token,
            std::ptr::null(),
            command_line.as_mut_ptr(),
            &attributes,
            std::ptr::null(),
            0,
            CREATE_NO_WINDOW,
            std::ptr::null(),
            std::ptr::null(),
            &startup,
            &mut info,
        );
        let error = GetLastError();
        LocalFree(sd);
        CloseHandle(token);
        if created == 0 {
            return Err(format!("CreateProcessAsUserW failed: {error}"));
        }
        CloseHandle(info.thread);
        Ok(Victim {
            process: info.process,
            pid: info.process_id,
            logon_sid,
        })
    }
}

/// Parses complete results, retaining errors so an expired victim cannot pass.
pub(super) fn parse_open_results(stdout: &str) -> BTreeMap<String, (bool, u32)> {
    stdout
        .lines()
        .filter_map(|line| line.trim().strip_prefix("PROBE open "))
        .filter_map(|rest| {
            let mut name = None;
            let mut granted = None;
            let mut error = None;
            for field in rest.split_whitespace() {
                if let Some(value) = field.strip_prefix("name=") {
                    name = Some(value.to_string());
                } else if let Some(value) = field.strip_prefix("granted=") {
                    granted = match value {
                        "0" => Some(false),
                        "1" => Some(true),
                        _ => None,
                    };
                } else if let Some(value) = field.strip_prefix("error=") {
                    error = value.parse::<u32>().ok();
                }
            }
            Some((name?, (granted?, error?)))
        })
        .collect()
}

unsafe fn token_sids(token: Handle, class: i32) -> Vec<(String, u32)> {
    let mut needed = 0u32;
    // SAFETY: size query with a null buffer, then a buffer of that size.
    unsafe {
        GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut needed);
        if needed == 0 {
            return Vec::new();
        }
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return Vec::new();
        }
        let count = std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) as usize;
        let first = buffer
            .as_ptr()
            .add(std::mem::size_of::<usize>())
            .cast::<SidAndAttributes>();
        (0..count)
            .map(|index| {
                let entry = std::ptr::read_unaligned(first.add(index));
                (sid_string(entry.sid), entry.attributes)
            })
            .collect()
    }
}

/// Runs only inside the sandbox, when the parent test sets the victim PID.
#[test]
fn isolation_probe_child() {
    let Some(pid) = std::env::var(PROBE_PID_ENV)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
    else {
        return;
    };
    // SAFETY: plain Win32 queries on handles opened and closed here.
    unsafe {
        let mut own_token: Handle = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut own_token) != 0 {
            let mut user = [0u8; 256];
            let mut needed = 0u32;
            if GetTokenInformation(
                own_token,
                TOKEN_USER_CLASS,
                user.as_mut_ptr().cast(),
                user.len() as u32,
                &mut needed,
            ) != 0
            {
                let entry = std::ptr::read_unaligned(user.as_ptr().cast::<SidAndAttributes>());
                println!("PROBE token user={}", sid_string(entry.sid));
            }
            let mut integrity = [0u8; 256];
            if GetTokenInformation(
                own_token,
                TOKEN_INTEGRITY_LEVEL_CLASS,
                integrity.as_mut_ptr().cast(),
                integrity.len() as u32,
                &mut needed,
            ) != 0
            {
                let entry = std::ptr::read_unaligned(integrity.as_ptr().cast::<SidAndAttributes>());
                println!("PROBE token integrity={}", sid_string(entry.sid));
            }
            match token_groups(own_token, 1 << 20) {
                Ok(groups) => {
                    for group in groups {
                        let sid = string_from_sid_bytes(&group.sid)
                            .unwrap_or_else(|_| "<invalid>".to_string());
                        println!("PROBE group sid={sid} attributes=0x{:x}", group.attributes);
                    }
                }
                Err(err) => println!("PROBE group error={err}"),
            }
            for (sid, attributes) in token_sids(own_token, TOKEN_RESTRICTED_SIDS_CLASS) {
                println!("PROBE restricted sid={sid} attributes=0x{attributes:x}");
            }
            CloseHandle(own_token);
        }
        for (name, mask) in PROBED_RIGHTS {
            let handle = OpenProcess(*mask, 0, pid);
            let error = if handle.is_null() { GetLastError() } else { 0 };
            println!(
                "PROBE open name={name} mask=0x{mask:x} granted={} error={error}",
                u8::from(!handle.is_null())
            );
            if *name == "query_limited" && !handle.is_null() {
                for (token_name, token_mask) in [
                    ("token_query", TOKEN_QUERY),
                    ("token_duplicate", TOKEN_DUPLICATE),
                ] {
                    let mut token: Handle = std::ptr::null_mut();
                    let opened = OpenProcessToken(handle, token_mask, &mut token) != 0;
                    let error = if opened { 0 } else { GetLastError() };
                    println!(
                        "PROBE open name={token_name} mask=0x{token_mask:x} granted={} error={error}",
                        u8::from(opened)
                    );
                    if opened {
                        CloseHandle(token);
                    }
                }
            } else if *name == "query_limited" {
                // Without a process handle the token cannot be opened at all;
                // report both token rights as denied with the open's error.
                for (token_name, token_mask) in [
                    ("token_query", TOKEN_QUERY),
                    ("token_duplicate", TOKEN_DUPLICATE),
                ] {
                    println!(
                        "PROBE open name={token_name} mask=0x{token_mask:x} granted=0 error={error}"
                    );
                }
            }
            if !handle.is_null() {
                CloseHandle(handle);
            }
        }
    }
    println!("PROBE done");
}
