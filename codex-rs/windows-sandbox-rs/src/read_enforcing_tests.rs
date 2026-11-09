use super::*;
use crate::run_windows_sandbox_capture_with_filesystem_overrides;
use codex_protocol::models::PermissionProfile;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;

const SECRET: &str = "READ-ENFORCING-SECRET-7731";
const SIBLING: &str = "READ-ENFORCING-SIBLING-OK";
const READ_ONLY: &str = "READ-ENFORCING-READ-ONLY-OK";

/// Fixture under the user's own temp folder, so it is owned by the test user
/// and inherits the user's ordinary rights, like a real profile secret.
struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn fixture(name: &str) -> Result<Fixture> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);
    let root = PathBuf::from(std::env::var("LOCALAPPDATA")?)
        .join("Temp")
        .join(format!(
            "codex-read-enforcing-{name}-{}-{nanos}",
            std::process::id()
        ));
    std::fs::create_dir_all(root.join("work").join("secret"))?;
    std::fs::create_dir_all(root.join("elsewhere"))?;
    std::fs::create_dir_all(root.join("home"))?;
    std::fs::write(root.join("work").join("secret").join("s.txt"), SECRET)?;
    std::fs::write(root.join("work").join("sibling.txt"), SIBLING)?;
    std::fs::create_dir_all(root.join("work").join("ro"))?;
    std::fs::write(root.join("work").join("ro").join("r.txt"), READ_ONLY)?;
    Ok(Fixture { root })
}

fn approved_root_write_profile(denied: &AbsolutePathBuf) -> PermissionProfile {
    // Shape produced by `FileSystemSandboxPolicy::for_approved_command` for a
    // baseline that carries a denied read: `:root` write plus the retained denial.
    PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Write,
            ),
            FileSystemSandboxEntry::new(denied.clone().into(), FileSystemAccessMode::Deny),
        ]),
        NetworkSandboxPolicy::Restricted,
    )
}

#[test]
fn approved_root_write_capture_keeps_denied_reads() -> Result<()> {
    let fixture = fixture("capture")?;
    let work = fixture.root.join("work");
    let secret_dir = work.join("secret");
    let new_elsewhere = fixture.root.join("elsewhere").join("new.txt");
    let read_only_dir = work.join("ro");
    let denied = AbsolutePathBuf::from_absolute_path(&secret_dir)?;
    let read_only = AbsolutePathBuf::from_absolute_path(&read_only_dir)?;
    let profile = approved_root_write_profile(&denied);

    let result = run_windows_sandbox_capture_with_filesystem_overrides(
        &profile,
        &[AbsolutePathBuf::from_absolute_path(&work)?],
        &fixture.root.join("home"),
        vec![
            "C:\\Windows\\System32\\cmd.exe".to_string(),
            "/D".to_string(),
            "/C".to_string(),
            "type secret\\s.txt & type sibling.txt & type ro\\r.txt & echo written>..\\elsewhere\\new.txt & echo written>secret\\w.txt & echo written>ro\\w.txt & echo READ-ENFORCING-DONE"
                .to_string(),
        ],
        &work,
        HashMap::new(),
        Some(30_000),
        None,
        std::slice::from_ref(&denied),
        std::slice::from_ref(&read_only),
    )?;
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    let output = format!("stdout:\n{stdout}\nstderr:\n{stderr}");
    println!("{output}");

    ensure!(!result.timed_out, "command timed out\n{output}");
    ensure!(
        stdout.contains("READ-ENFORCING-DONE"),
        "command did not finish\n{output}"
    );
    ensure!(!output.contains(SECRET), "denied file was read\n{output}");
    ensure!(
        stdout.contains(SIBLING),
        "sibling of the denied path was not readable\n{output}"
    );
    // A read-only path stays readable: its write deny must not carry the
    // `READ_CONTROL` and `SYNCHRONIZE` bits that ordinary reads request.
    ensure!(
        stdout.contains(READ_ONLY),
        "read-only path was not readable\n{output}"
    );
    ensure!(
        !read_only_dir.join("w.txt").exists(),
        "read-only path was writable\n{output}"
    );
    ensure!(
        new_elsewhere.exists(),
        "approved root write did not reach an untouched user folder\n{output}"
    );
    ensure!(
        !secret_dir.join("w.txt").exists(),
        "denied path was writable\n{output}"
    );
    Ok(())
}

#[test]
fn scoped_write_with_denied_read_still_requires_elevated_backend() -> Result<()> {
    let fixture = fixture("scoped")?;
    let work = fixture.root.join("work");
    let denied = AbsolutePathBuf::from_absolute_path(work.join("secret"))?;
    let workspace = AbsolutePathBuf::from_absolute_path(&work)?;
    let profile = PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(workspace.clone().into(), FileSystemAccessMode::Write),
            FileSystemSandboxEntry::new(denied.clone().into(), FileSystemAccessMode::Deny),
        ]),
        NetworkSandboxPolicy::Restricted,
    );
    let Err(err) = run_windows_sandbox_capture_with_filesystem_overrides(
        &profile,
        std::slice::from_ref(&workspace),
        &fixture.root.join("home"),
        vec![
            "C:\\Windows\\System32\\cmd.exe".to_string(),
            "/D".to_string(),
            "/C".to_string(),
            "echo scoped".to_string(),
        ],
        &work,
        HashMap::new(),
        Some(30_000),
        None,
        std::slice::from_ref(&denied),
        &[],
    ) else {
        anyhow::bail!("scoped write with a denied read must not run in the legacy backend");
    };
    ensure!(
        // Either legacy refusal is correct: the restricted-read check or the
        // deny-read check, whichever runs first.
        err.to_string().contains("elevated Windows sandbox backend"),
        "unexpected error: {err:#}"
    );
    Ok(())
}

/// Records, without asserting, whether a token can open an unrestricted
/// same-user process (this test process) with the rights needed to run code in
/// it. Process isolation is a documented residual of the read-enforcing token;
/// today's `WRITE_RESTRICTED` token is the comparison.
#[test]
fn same_user_process_access_is_measured() -> Result<()> {
    use crate::token::create_workspace_write_token_with_caps_from;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Security::Authorization::GetSecurityInfo;
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
    use windows_sys::Win32::System::Threading::GetCurrentProcess;
    use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::PROCESS_CREATE_THREAD;
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
    use windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION;
    use windows_sys::Win32::System::Threading::PROCESS_VM_READ;
    use windows_sys::Win32::System::Threading::PROCESS_VM_WRITE;

    const SE_KERNEL_OBJECT: i32 = 6;
    const INJECTION_RIGHTS: u32 = PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    let mapping = GENERIC_MAPPING {
        GenericRead: READ_CONTROL | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        GenericWrite: READ_CONTROL | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
        GenericExecute: READ_CONTROL | SYNCHRONIZE,
        GenericAll: PROCESS_ALL_ACCESS,
    };
    let capability = LocalSid::from_string("S-1-5-21-10-20-30-42")?;
    unsafe {
        let base = OwnedHandle::from_raw_handle(get_current_token_for_restriction()? as _);
        let base_raw = base.as_raw_handle() as HANDLE;
        let variant = OwnedHandle::from_raw_handle(
            create_read_enforcing_token_with_caps_and_user_from(base_raw, &[capability.as_ptr()])?
                as _,
        );
        let control = OwnedHandle::from_raw_handle(
            create_workspace_write_token_with_caps_from(base_raw, &[capability.as_ptr()])? as _,
        );
        let variant_imp = ImpersonationToken::duplicate(variant.as_raw_handle() as HANDLE)?;
        let control_imp = ImpersonationToken::duplicate(control.as_raw_handle() as HANDLE)?;
        let mut sd: *mut c_void = std::ptr::null_mut();
        let code = GetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        );
        ensure!(
            code == ERROR_SUCCESS,
            "GetSecurityInfo(process) failed: {code}"
        );
        let read_enforcing = access_check_descriptor(sd, variant_imp.0, INJECTION_RIGHTS, &mapping);
        let write_restricted =
            access_check_descriptor(sd, control_imp.0, INJECTION_RIGHTS, &mapping);
        LocalFree(sd as HLOCAL);
        let read_enforcing = read_enforcing? & INJECTION_RIGHTS;
        let write_restricted = write_restricted? & INJECTION_RIGHTS;
        println!(
            "RESIDUAL same-user process injection rights granted: read-enforcing={read_enforcing:#x} write-restricted={write_restricted:#x} (wanted {INJECTION_RIGHTS:#x})"
        );
    }
    Ok(())
}
