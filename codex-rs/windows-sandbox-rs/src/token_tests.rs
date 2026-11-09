use super::*;
use crate::read_enforcing::file_access_allowed;
use pretty_assertions::assert_eq;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::TokenRestrictedSids;

unsafe fn token_has_restricting_sid(token: HANDLE, expected_sid: *mut c_void) -> Result<bool> {
    let mut needed = 0;
    GetTokenInformation(
        token,
        TokenRestrictedSids,
        std::ptr::null_mut(),
        0,
        &mut needed,
    );
    if needed == 0 {
        return Err(anyhow!(
            "GetTokenInformation(TokenRestrictedSids) size query failed: {}",
            GetLastError()
        ));
    }

    let mut buffer = vec![0_u8; needed as usize];
    if GetTokenInformation(
        token,
        TokenRestrictedSids,
        buffer.as_mut_ptr().cast(),
        needed,
        &mut needed,
    ) == 0
    {
        return Err(anyhow!(
            "GetTokenInformation(TokenRestrictedSids) failed: {}",
            GetLastError()
        ));
    }

    let group_count = std::ptr::read_unaligned(buffer.as_ptr().cast::<u32>()) as usize;
    let after_count = buffer.as_ptr().add(std::mem::size_of::<u32>()) as usize;
    let align = std::mem::align_of::<SID_AND_ATTRIBUTES>();
    let entries_addr = (after_count + (align - 1)) & !(align - 1);
    let restricting_sids =
        std::slice::from_raw_parts(entries_addr as *const SID_AND_ATTRIBUTES, group_count);
    Ok(restricting_sids
        .iter()
        .any(|entry| EqualSid(entry.Sid, expected_sid) != 0))
}

#[test]
fn elevated_token_includes_network_proxy_restricting_sid() -> Result<()> {
    let capability_sid = LocalSid::from_string("S-1-5-21-10-20-30-40")?;
    let network_proxy_sid = LocalSid::from_string("S-1-5-21-50-60-70-80")?;
    let base_token = unsafe { get_current_token_for_restriction()? };
    let restricted_token = unsafe {
        create_readonly_token_with_caps_and_user_from(
            base_token,
            &[capability_sid.as_ptr()],
            &[network_proxy_sid.as_ptr()],
        )?
    };

    let has_network_proxy_sid =
        unsafe { token_has_restricting_sid(restricted_token, network_proxy_sid.as_ptr()) };
    unsafe {
        CloseHandle(restricted_token);
        CloseHandle(base_token);
    }

    assert!(has_network_proxy_sid?);
    Ok(())
}

#[test]
fn default_objects_deny_other_logons_even_with_the_same_owner() -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Security::ACCESS_ALLOWED_ACE;
    use windows_sys::Win32::Security::AccessCheck;
    use windows_sys::Win32::Security::DuplicateToken;
    use windows_sys::Win32::Security::GENERIC_MAPPING;
    use windows_sys::Win32::Security::GetAce;
    use windows_sys::Win32::Security::InitializeSecurityDescriptor;
    use windows_sys::Win32::Security::MapGenericMask;
    use windows_sys::Win32::Security::SECURITY_DESCRIPTOR;
    use windows_sys::Win32::Security::SecurityImpersonation;
    use windows_sys::Win32::Security::SetSecurityDescriptorDacl;
    use windows_sys::Win32::Security::SetSecurityDescriptorGroup;
    use windows_sys::Win32::Security::SetSecurityDescriptorOwner;
    use windows_sys::Win32::Storage::FileSystem::READ_CONTROL;
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
    use windows_sys::Win32::System::Threading::PROCESS_ALL_ACCESS;
    use windows_sys::Win32::System::Threading::PROCESS_CREATE_THREAD;
    use windows_sys::Win32::System::Threading::PROCESS_QUERY_INFORMATION;
    use windows_sys::Win32::System::Threading::PROCESS_TERMINATE;
    use windows_sys::Win32::System::Threading::PROCESS_VM_OPERATION;
    use windows_sys::Win32::System::Threading::PROCESS_VM_READ;
    use windows_sys::Win32::System::Threading::PROCESS_VM_WRITE;

    unsafe {
        let base = OwnedHandle::from_raw_handle(get_current_token_for_restriction()? as _);
        let base_raw = base.as_raw_handle() as HANDLE;
        let capability = LocalSid::from_string("S-1-5-21-10-20-30-40")?;
        let victim =
            OwnedHandle::from_raw_handle(create_workspace_write_token_with_caps_and_user_from(
                base_raw,
                &[capability.as_ptr()],
                &[],
            )? as _);
        let mut needed = 0;
        GetTokenInformation(
            victim.as_raw_handle() as _,
            TokenDefaultDacl,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        let mut buffer = vec![0u8; needed as usize];
        ensure!(
            GetTokenInformation(
                victim.as_raw_handle() as _,
                TokenDefaultDacl,
                buffer.as_mut_ptr().cast(),
                needed,
                &mut needed
            ) != 0,
            "GetTokenInformation(TokenDefaultDacl) failed: {}",
            GetLastError()
        );
        let default_dacl = std::ptr::read_unaligned(buffer.as_ptr().cast::<TokenDefaultDaclInfo>());
        let mapping = GENERIC_MAPPING {
            GenericRead: READ_CONTROL | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            GenericWrite: READ_CONTROL | PROCESS_VM_WRITE | PROCESS_VM_OPERATION,
            GenericExecute: READ_CONTROL,
            GenericAll: PROCESS_ALL_ACCESS,
        };
        // Object creation maps the token default DACL's generic ACE masks to
        // object-specific rights. AccessCheck expects that mapping already done.
        for index in 0..u32::from((*default_dacl.default_dacl).AceCount) {
            let mut ace = std::ptr::null_mut();
            ensure!(GetAce(default_dacl.default_dacl, index, &mut ace) != 0);
            MapGenericMask(&mut (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask, &mapping);
        }
        let mut owner = get_user_sid_bytes(base_raw)?;
        let mut descriptor: SECURITY_DESCRIPTOR = std::mem::zeroed();
        let sd = std::ptr::addr_of_mut!(descriptor).cast();
        ensure!(InitializeSecurityDescriptor(sd, 1) != 0);
        ensure!(SetSecurityDescriptorOwner(sd, owner.as_mut_ptr().cast(), 0) != 0);
        ensure!(SetSecurityDescriptorGroup(sd, owner.as_mut_ptr().cast(), 0) != 0);
        ensure!(SetSecurityDescriptorDacl(sd, 1, default_dacl.default_dacl, 0) != 0);

        // Model another logon of the same account without the victim's logon
        // SID. Build from the base token, retaining the shared user, Everyone,
        // and filesystem capability in the write-restricting SID set.
        let mut logon = get_logon_sid_bytes(base_raw)?;
        let mut everyone = world_sid()?;
        let disabled = SID_AND_ATTRIBUTES {
            Sid: logon.as_mut_ptr().cast(),
            Attributes: 0,
        };
        let restricting = [
            capability.as_ptr(),
            owner.as_mut_ptr().cast(),
            everyone.as_mut_ptr().cast(),
        ]
        .map(|sid| SID_AND_ATTRIBUTES {
            Sid: sid,
            Attributes: 0,
        });
        let mut other = std::ptr::null_mut();
        ensure!(
            CreateRestrictedToken(
                base_raw,
                DISABLE_MAX_PRIVILEGE | LUA_TOKEN | WRITE_RESTRICTED,
                1,
                &disabled,
                0,
                std::ptr::null(),
                restricting.len() as u32,
                restricting.as_ptr(),
                &mut other
            ) != 0,
            "CreateRestrictedToken(other logon) failed: {}",
            GetLastError()
        );
        let other = OwnedHandle::from_raw_handle(other as _);
        for (token, same_logon) in [(&victim, true), (&other, false)] {
            let mut impersonation = std::ptr::null_mut();
            ensure!(
                DuplicateToken(
                    token.as_raw_handle() as _,
                    SecurityImpersonation,
                    &mut impersonation
                ) != 0,
                "DuplicateToken failed: {}",
                GetLastError()
            );
            let impersonation = OwnedHandle::from_raw_handle(impersonation as _);
            for access in [
                PROCESS_VM_READ,
                PROCESS_VM_WRITE,
                PROCESS_VM_OPERATION,
                PROCESS_CREATE_THREAD,
                PROCESS_TERMINATE,
                PROCESS_QUERY_INFORMATION,
                WRITE_DAC,
                0x43a,
            ] {
                let mut privileges = [0u64; 128];
                let mut privilege_bytes = std::mem::size_of_val(&privileges) as u32;
                let mut granted = 0;
                let mut allowed = 0;
                ensure!(
                    AccessCheck(
                        sd,
                        impersonation.as_raw_handle() as _,
                        access,
                        &mapping,
                        privileges.as_mut_ptr().cast(),
                        &mut privilege_bytes,
                        &mut granted,
                        &mut allowed
                    ) != 0,
                    "AccessCheck failed: {}",
                    GetLastError()
                );
                assert_eq!(allowed != 0, same_logon, "access {access:#x}");
            }
        }
    }
    Ok(())
}

/// Fixture for one child run: a denied directory with a secret, a readable
/// sibling, an untouched directory to write into and an output directory.
/// Nothing here receives an allow ACE; the child may only use the user's own
/// existing rights.
struct ReadEnforcingFixture {
    _root: tempfile::TempDir,
    script: std::path::PathBuf,
    secret_dir: std::path::PathBuf,
    secret: std::path::PathBuf,
    sibling: std::path::PathBuf,
    elsewhere: std::path::PathBuf,
    out: std::path::PathBuf,
}

const SECRET_TEXT: &str = "claudeai-spike-secret";
const SIBLING_TEXT: &str = "claudeai-spike-sibling";

// Each probe records its errorlevel in r.txt. The `> file echo` form avoids
// cmd reading a trailing digit as a stream number. The two strip probes try to
// remove the capability deny from the directory and to reset the file DACL.
const SPIKE_SCRIPT: &str = r#"@echo off
> "%OUT%\started.txt" echo started
type "%SECRET%" > "%OUT%\secret_copy.txt" 2> "%OUT%\secret_err.txt"
>> "%OUT%\r.txt" echo secret=%errorlevel%
type "%SIBLING%" > "%OUT%\sibling_copy.txt" 2> "%OUT%\sibling_err.txt"
>> "%OUT%\r.txt" echo sibling=%errorlevel%
copy /b /y "%SystemRoot%\System32\kernel32.dll" "%OUT%\k32.bin" > nul 2> "%OUT%\k32_err.txt"
>> "%OUT%\r.txt" echo kernel32=%errorlevel%
dir /b "%USERPROFILE%" > "%OUT%\profile.txt" 2> "%OUT%\profile_err.txt"
>> "%OUT%\r.txt" echo profile=%errorlevel%
reg query "HKCU\Environment" > "%OUT%\reg.txt" 2> "%OUT%\reg_err.txt"
>> "%OUT%\r.txt" echo hkcu=%errorlevel%
> "%TEMP%\claudeai-spike-%RANDOM%%RANDOM%.txt" echo t
>> "%OUT%\r.txt" echo temp=%errorlevel%
> "%ELSEWHERE%\new.txt" echo hello
>> "%OUT%\r.txt" echo elsewhere=%errorlevel%
icacls "%SECRETDIR%" /remove:d *%CAP% > "%OUT%\strip_dir.txt" 2>&1
>> "%OUT%\r.txt" echo strip_dir=%errorlevel%
icacls "%SECRET%" /reset > "%OUT%\strip_file.txt" 2>&1
>> "%OUT%\r.txt" echo strip_file=%errorlevel%
type "%SECRET%" > "%OUT%\secret_copy2.txt" 2> "%OUT%\secret_err2.txt"
>> "%OUT%\r.txt" echo secret_after=%errorlevel%
exit /b 0
"#;

fn read_enforcing_fixture() -> Result<ReadEnforcingFixture> {
    // The profile's Temp is owned by the signed-in user, like the files a real
    // approved command would touch.
    let local_temp = std::path::PathBuf::from(std::env::var("LOCALAPPDATA")?).join("Temp");
    std::fs::create_dir_all(&local_temp)?;
    let root = tempfile::Builder::new()
        .prefix("claudeai-spike-")
        .tempdir_in(&local_temp)?;
    let base = root.path().to_path_buf();
    let secret_dir = base.join("secret");
    let elsewhere = base.join("elsewhere");
    let out = base.join("out");
    for dir in [&secret_dir, &elsewhere, &out] {
        std::fs::create_dir_all(dir)?;
    }
    let secret = secret_dir.join("secret.txt");
    let sibling = base.join("sibling.txt");
    std::fs::write(&secret, SECRET_TEXT)?;
    std::fs::write(&sibling, SIBLING_TEXT)?;
    let script = base.join("probe.cmd");
    std::fs::write(&script, SPIKE_SCRIPT)?;
    Ok(ReadEnforcingFixture {
        _root: root,
        script,
        secret_dir,
        secret,
        sibling,
        elsewhere,
        out,
    })
}

/// A capability SID unique to this test run, so no persistent ACE from an
/// earlier run or another test can satisfy the checks.
fn unique_capability_sid() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_nanos())
        .unwrap_or(0);
    format!("S-1-5-21-{}-{nanos}-4242-77", std::process::id())
}

/// Runs the probe script in a child created with `token` and returns the
/// recorded errorlevels plus the child exit code.
unsafe fn run_probe(
    token: HANDLE,
    fixture: &ReadEnforcingFixture,
    capability_sid: &str,
) -> Result<(std::collections::HashMap<String, i64>, u32)> {
    use crate::desktop::LaunchDesktop;
    use crate::process::ConsoleMode;
    use crate::process::create_process_as_user;
    use windows_sys::Win32::System::Threading::GetExitCodeProcess;
    use windows_sys::Win32::System::Threading::WaitForSingleObject;

    let mut env: std::collections::HashMap<String, String> = std::env::vars().collect();
    for (key, value) in [
        ("OUT", fixture.out.display().to_string()),
        ("SECRET", fixture.secret.display().to_string()),
        ("SECRETDIR", fixture.secret_dir.display().to_string()),
        ("SIBLING", fixture.sibling.display().to_string()),
        ("ELSEWHERE", fixture.elsewhere.display().to_string()),
        ("CAP", capability_sid.to_string()),
    ] {
        env.insert(key.to_string(), value);
    }
    let comspec =
        std::env::var("ComSpec").unwrap_or_else(|_| r"C:\Windows\System32\cmd.exe".to_string());
    let argv = vec![
        comspec,
        "/d".to_string(),
        "/c".to_string(),
        fixture.script.display().to_string(),
    ];
    let desktop = LaunchDesktop::prepare(None)?;
    let created = create_process_as_user(
        token,
        &argv,
        fixture.out.parent().expect("fixture root"),
        &env,
        None,
        None,
        ConsoleMode::NoWindow,
        desktop,
    )?;
    let wait = WaitForSingleObject(created.process_info.hProcess, 120_000);
    let mut exit_code = 0u32;
    let got_exit = GetExitCodeProcess(created.process_info.hProcess, &mut exit_code) != 0;
    let exit_err = GetLastError();
    CloseHandle(created.process_info.hThread);
    CloseHandle(created.process_info.hProcess);
    ensure!(wait == 0, "probe child did not exit within 120 s (wait {wait})");
    ensure!(got_exit, "GetExitCodeProcess failed: {exit_err}");

    let report = std::fs::read_to_string(fixture.out.join("r.txt")).unwrap_or_default();
    println!("probe exit={exit_code} report:\n{report}");
    for name in [
        "secret_err.txt",
        "secret_err2.txt",
        "strip_dir.txt",
        "strip_file.txt",
        "k32_err.txt",
        "reg_err.txt",
        "profile_err.txt",
    ] {
        if let Ok(text) = std::fs::read_to_string(fixture.out.join(name)) {
            println!("{name}: {}", text.trim());
        }
    }
    let codes = report
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .filter_map(|(key, value)| {
            value
                .trim()
                .parse::<i64>()
                .ok()
                .map(|code| (key.to_string(), code))
        })
        .collect();
    Ok((codes, exit_code))
}

fn probe_code(codes: &std::collections::HashMap<String, i64>, key: &str) -> i64 {
    *codes
        .get(key)
        .unwrap_or_else(|| panic!("probe did not record {key}: {codes:?}"))
}

fn read_trimmed(path: &std::path::Path) -> String {
    std::fs::read_to_string(path)
        .map(|text| text.trim().to_string())
        .unwrap_or_default()
}

#[test]
fn read_enforcing_token_keeps_denied_reads_without_new_allow_aces() -> Result<()> {
    use crate::acl::OWNER_RIGHTS_SID;
    use crate::acl::dacl_has_read_deny_for_sid;
    use crate::acl::fetch_dacl_handle;
    use crate::acl::protect_read_denied_path;
    use crate::acl::revoke_ace;
    use std::os::windows::io::AsRawHandle;
    use std::os::windows::io::FromRawHandle;
    use std::os::windows::io::OwnedHandle;
    use windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA;
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

    let control_fixture = read_enforcing_fixture()?;
    let variant_fixture = read_enforcing_fixture()?;
    let capability_sid_str = unique_capability_sid();
    let capability = LocalSid::from_string(&capability_sid_str)?;
    let owner_rights = LocalSid::from_string(OWNER_RIGHTS_SID)?;

    unsafe {
        for fixture in [&control_fixture, &variant_fixture] {
            protect_read_denied_path(&fixture.secret_dir, capability.as_ptr())?;
            // (h) The parent still reads the secret, and the file carries the
            // inherited deny for the capability SID.
            assert_eq!(read_trimmed(&fixture.secret), SECRET_TEXT);
            let (dacl, sd) = fetch_dacl_handle(&fixture.secret)?;
            let inherited_deny = dacl_has_read_deny_for_sid(dacl, capability.as_ptr());
            LocalFree(sd as HLOCAL);
            assert!(inherited_deny, "secret file did not inherit the deny-read ACE");
        }

        let base = OwnedHandle::from_raw_handle(get_current_token_for_restriction()? as _);
        let base_raw = base.as_raw_handle() as HANDLE;
        // (d) Negative control: today's WRITE_RESTRICTED constructor with the
        // same capability and user SIDs.
        let control = OwnedHandle::from_raw_handle(
            create_workspace_write_token_with_caps_and_user_from(
                base_raw,
                &[capability.as_ptr()],
                &[],
            )? as _,
        );
        let variant = OwnedHandle::from_raw_handle(
            create_read_enforcing_token_with_caps_and_user_from(base_raw, &[capability.as_ptr()])?
                as _,
        );
        let control_raw = control.as_raw_handle() as HANDLE;
        let variant_raw = variant.as_raw_handle() as HANDLE;

        let control_secret_read =
            file_access_allowed(&control_fixture.secret, control_raw, FILE_READ_DATA)?;
        let variant_secret_read =
            file_access_allowed(&variant_fixture.secret, variant_raw, FILE_READ_DATA)?;
        let variant_secret_dac = file_access_allowed(&variant_fixture.secret, variant_raw, WRITE_DAC)?;
        let variant_dir_dac =
            file_access_allowed(&variant_fixture.secret_dir, variant_raw, WRITE_DAC)?;
        let variant_sibling_read =
            file_access_allowed(&variant_fixture.sibling, variant_raw, FILE_READ_DATA)?;
        println!(
            "AccessCheck control_secret_read={control_secret_read} variant_secret_read={variant_secret_read} variant_secret_write_dac={variant_secret_dac} variant_dir_write_dac={variant_dir_dac} variant_sibling_read={variant_sibling_read}"
        );

        println!("--- control child (WRITE_RESTRICTED) ---");
        let control_run = run_probe(control_raw, &control_fixture, &capability_sid_str);
        println!("--- variant child (read-enforcing) ---");
        let variant_run = run_probe(variant_raw, &variant_fixture, &capability_sid_str);

        for fixture in [&control_fixture, &variant_fixture] {
            let _ = revoke_ace(&fixture.secret_dir, capability.as_ptr());
            let _ = revoke_ace(&fixture.secret_dir, owner_rights.as_ptr());
        }
        let (control_codes, control_exit) = control_run?;
        let (codes, exit) = variant_run?;

        // (d) The control child reads the secret: WRITE_RESTRICTED ignores the deny.
        assert!(control_secret_read, "control AccessCheck should allow the read");
        assert_eq!(control_exit, 0, "control child failed to run");
        assert_eq!(probe_code(&control_codes, "secret"), 0, "control should read the secret");
        assert_eq!(
            read_trimmed(&control_fixture.out.join("secret_copy.txt")),
            SECRET_TEXT
        );

        // (i) The variant child starts and finishes.
        assert!(
            variant_fixture.out.join("started.txt").exists(),
            "variant child never started"
        );
        assert_eq!(exit, 0, "variant child exit code");
        // (b)/(h) The read fails with access denied, not file-not-found.
        assert!(!variant_secret_read, "variant AccessCheck allowed the denied read");
        assert_ne!(probe_code(&codes, "secret"), 0, "variant child read the denied secret");
        let secret_err = read_trimmed(&variant_fixture.out.join("secret_err.txt"));
        assert!(
            secret_err.to_ascii_lowercase().contains("access is denied"),
            "denied read failed for another reason: {secret_err}"
        );
        assert!(
            read_trimmed(&variant_fixture.out.join("secret_copy.txt")).is_empty(),
            "secret text leaked"
        );
        // (g) The child cannot remove its deny.
        assert!(
            !variant_secret_dac && !variant_dir_dac,
            "variant may change the denied DACL"
        );
        assert_ne!(
            probe_code(&codes, "strip_dir"),
            0,
            "variant removed the deny ACE from the directory"
        );
        assert_ne!(
            probe_code(&codes, "secret_after"),
            0,
            "secret readable after strip attempts"
        );
        // (e) Path-scoped: the sibling stays readable.
        assert!(variant_sibling_read, "variant AccessCheck denied the sibling");
        assert_eq!(probe_code(&codes, "sibling"), 0, "sibling read failed");
        assert_eq!(
            read_trimmed(&variant_fixture.out.join("sibling_copy.txt")),
            SIBLING_TEXT
        );
        // (c) System files.
        assert_eq!(probe_code(&codes, "kernel32"), 0, "kernel32.dll read failed");
        let system_root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_string());
        assert_eq!(
            std::fs::metadata(variant_fixture.out.join("k32.bin"))?.len(),
            std::fs::metadata(std::path::Path::new(&system_root).join(r"System32\kernel32.dll"))?
                .len()
        );
        // (f) Profile, HKCU and TEMP.
        assert_eq!(probe_code(&codes, "profile"), 0, "profile listing failed");
        assert_eq!(probe_code(&codes, "hkcu"), 0, "HKCU read failed");
        assert_eq!(probe_code(&codes, "temp"), 0, "TEMP write failed");
        // (a) Broad write through the user's own rights, no allow ACE added.
        assert_eq!(
            probe_code(&codes, "elsewhere"),
            0,
            "write outside denied paths failed"
        );
        assert_eq!(read_trimmed(&variant_fixture.elsewhere.join("new.txt")), "hello");
    }
    Ok(())
}
