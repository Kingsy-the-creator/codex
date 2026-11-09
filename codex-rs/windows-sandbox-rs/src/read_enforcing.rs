//! Read-enforcing legacy sessions for approved commands that write from the
//! filesystem root.
//!
//! The unelevated backend normally runs commands under a `WRITE_RESTRICTED`
//! token. Its restricting SIDs are consulted only for writes, so capability-SID
//! deny-read ACEs never apply. When an approved policy already grants write
//! access from the filesystem root and keeps the root readable, capability-SID
//! write confinement adds nothing. For that shape only, the command runs under
//! a token without `WRITE_RESTRICTED` whose restricting SIDs include the user
//! (see `token::create_read_enforcing_token_with_caps_and_user_from`). The
//! user's ordinary access is kept, and deny ACEs for the session capability SID
//! apply to reads as well as writes. No allow ACE is added anywhere.
//!
//! Because the user is a restricting SID, the command would also hold the
//! owner's implicit `READ_CONTROL | WRITE_DAC` on files the user owns and could
//! remove its own deny ACE. Every protected path therefore gets an OWNER RIGHTS
//! ACE first, and its deny ACE also covers DACL and owner changes. Before the
//! command starts, `AccessCheck` with the real child token confirms every
//! entry under each denied path refuses read, write and DACL or owner changes,
//! and every entry under each read-only path refuses write and DACL or owner
//! changes. Any failure refuses the run.
//!
//! Each protection set (root, denied-read paths, read-only paths) has its own
//! capability SID, so concurrent sessions never revoke each other's denies and
//! a deny left by an earlier set never applies to a later token.
//!
//! Residuals:
//! - The user's rights on a protected path's parent still let the command
//!   delete or rename the protected entry. Inherited deny ACEs survive a
//!   same-volume rename, so this does not disclose the contents.
//! - Process isolation is not provided. The user SID also passes the second
//!   access check on the user's other, unrestricted processes, whose default
//!   DACL grants that SID full access, so a deliberately hostile command could
//!   act through one of them. The test
//!   `same_user_process_access_is_measured` records this against today's
//!   `WRITE_RESTRICTED` token. The deny-read paths stop ordinary reads by the
//!   command and its children; they are not a boundary against code written to
//!   escape, which an approved root write already allows by other means (for
//!   example a file the user later runs).

use crate::acl::allow_null_device;
use crate::acl::protect_write_denied_path;
use crate::allow::AllowDenyPaths;
use crate::allow::compute_allow_paths_for_permissions;
use crate::cap::read_enforcing_cap_sid_for_set;
use crate::deny_read_acl::DenyReadAceStyle;
use crate::deny_read_state::sync_persistent_deny_read_acls_with_style;
use crate::path_normalization::canonical_path_key;
use crate::resolved_permissions::ResolvedWindowsSandboxPermissions;
use crate::spawn_prep::LegacySessionSecurity;
use crate::spawn_prep::RootCapabilitySid;
use crate::token::LocalSid;
use crate::token::create_read_enforcing_token_with_caps_and_user_from;
use crate::token::get_current_token_for_restriction;
use crate::token::get_logon_sid_bytes;
use crate::winutil::to_wide;
use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use anyhow::ensure;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::ffi::c_void;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::AccessCheck;
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;
use windows_sys::Win32::Security::DuplicateToken;
use windows_sys::Win32::Security::GENERIC_MAPPING;
use windows_sys::Win32::Security::GROUP_SECURITY_INFORMATION;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Security::SecurityImpersonation;
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows_sys::Win32::Storage::FileSystem::FILE_APPEND_DATA;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_EXECUTE;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_READ;
use windows_sys::Win32::Storage::FileSystem::FILE_GENERIC_WRITE;
use windows_sys::Win32::Storage::FileSystem::FILE_READ_DATA;
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_ATTRIBUTES;
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_DATA;
use windows_sys::Win32::Storage::FileSystem::FILE_WRITE_EA;
use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;
use windows_sys::Win32::Storage::FileSystem::WRITE_OWNER;
use windows_sys::Win32::System::SystemServices::MAXIMUM_ALLOWED;

/// Upper bound on entries checked under each protected path. A larger tree is
/// refused rather than partly checked. Each entry costs one security-descriptor
/// read and one `AccessCheck`.
const MAX_VERIFIED_ENTRIES_PER_PATH: usize = 100_000;

/// Returns the filesystem-root write grant (for example `C:\`) in the
/// resolved allow set, if any.
pub(crate) fn filesystem_root_allow_path(
    permissions: &ResolvedWindowsSandboxPermissions,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
) -> Option<PathBuf> {
    compute_allow_paths_for_permissions(permissions, current_dir, env_map)
        .allow
        .into_iter()
        .find(|path| path.is_absolute() && path.parent().is_none())
}

/// True when this legacy run should use the read-enforcing token: deny-read
/// paths exist, the root stays readable, and writes are already granted from
/// the filesystem root. Scoped write policies would lose their write
/// confinement under this token, so they never qualify.
pub(crate) fn uses_read_enforcing_session(
    permissions: &ResolvedWindowsSandboxPermissions,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    deny_read_paths: &[PathBuf],
) -> bool {
    !deny_read_paths.is_empty()
        && permissions.has_symbolic_root_read_access(current_dir)
        && filesystem_root_allow_path(permissions, current_dir, env_map).is_some()
}

/// Protects denied and read-only paths for the session capability SID, creates
/// the read-enforcing token and verifies it with `AccessCheck`.
pub(crate) fn prepare_read_enforcing_session_security(
    permissions: &ResolvedWindowsSandboxPermissions,
    codex_home: &Path,
    current_dir: &Path,
    env_map: &HashMap<String, String>,
    deny_read_paths: &[PathBuf],
    additional_deny_write_paths: &[PathBuf],
) -> Result<LegacySessionSecurity> {
    let root = filesystem_root_allow_path(permissions, current_dir, env_map)
        .context("read-enforcing session requires a filesystem-root write grant")?;

    let AllowDenyPaths { deny, .. } =
        compute_allow_paths_for_permissions(permissions, current_dir, env_map);
    let mut deny_write_paths: BTreeSet<PathBuf> = deny.into_iter().collect();
    for path in additional_deny_write_paths {
        // Carveouts must exist before the command starts so it cannot create
        // them under a writable parent first.
        if !path.exists() {
            std::fs::create_dir_all(path)
                .with_context(|| format!("create deny-write path {}", path.display()))?;
        }
        deny_write_paths.insert(path.clone());
    }

    // A dedicated capability SID per protection set, which never receives an
    // allow ACE. Concurrent sessions with different sets hold different SIDs,
    // so reconciling one set never revokes a deny another live session needs,
    // and a deny left by an earlier set never applies to a later token.
    let set_key = protection_set_key(&root, deny_read_paths, &deny_write_paths);
    let sid_str = read_enforcing_cap_sid_for_set(codex_home, &set_key)?;
    let sid = LocalSid::from_string(&sid_str)?;

    let applied_read_denies = unsafe {
        sync_persistent_deny_read_acls_with_style(
            codex_home,
            &sid_str,
            deny_read_paths,
            sid.as_ptr(),
            DenyReadAceStyle::ReadAndControl,
        )?
    };
    // A denied path is also not writable.
    deny_write_paths.extend(applied_read_denies.iter().cloned());
    for path in &deny_write_paths {
        unsafe { protect_write_denied_path(path, sid.as_ptr()) }
            .with_context(|| format!("protect read-only path {}", path.display()))?;
    }

    let h_token = unsafe {
        let base = get_current_token_for_restriction()?;
        let token = create_read_enforcing_token_with_caps_and_user_from(base, &[sid.as_ptr()]);
        CloseHandle(base);
        token?
    };
    let verified = verify_protected_paths(h_token, &applied_read_denies, &deny_write_paths);
    if let Err(err) = verified {
        unsafe {
            CloseHandle(h_token);
        }
        return Err(err);
    }

    unsafe {
        allow_null_device(sid.as_ptr());
        let base = get_current_token_for_restriction()?;
        if let Ok(bytes) = get_logon_sid_bytes(base) {
            let mut logon_sid = bytes;
            allow_null_device(logon_sid.as_mut_ptr() as *mut c_void);
        }
        CloseHandle(base);
    }

    Ok(LegacySessionSecurity {
        h_token,
        readonly_sid: None,
        readonly_sid_str: None,
        write_root_sids: vec![RootCapabilitySid { root, sid, sid_str }],
    })
}

/// Stable key for one protection set: the root, then the sorted denied-read
/// and read-only path keys.
fn protection_set_key(
    root: &Path,
    deny_read_paths: &[PathBuf],
    read_only_paths: &BTreeSet<PathBuf>,
) -> String {
    format!(
        "root={}\ndeny-read={}\nread-only={}",
        canonical_path_key(root),
        sorted_path_keys(deny_read_paths),
        sorted_path_keys(read_only_paths)
    )
}

fn sorted_path_keys<'a>(paths: impl IntoIterator<Item = &'a PathBuf>) -> String {
    let keys: BTreeSet<String> = paths
        .into_iter()
        .map(|path| canonical_path_key(path))
        .collect();
    keys.into_iter().collect::<Vec<_>>().join("|")
}

/// Mutation rights every entry under a read-only path must refuse. `DELETE`
/// of the top entry can still come from its parent; see the module residual.
const READ_ONLY_FORBIDDEN_RIGHTS: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER;

/// Rights every entry under a denied path must refuse.
const DENIED_FORBIDDEN_RIGHTS: u32 = FILE_READ_DATA | READ_ONLY_FORBIDDEN_RIGHTS;

/// Refuses the run unless `token` is refused [`DENIED_FORBIDDEN_RIGHTS`] on
/// every entry under each denied path and [`READ_ONLY_FORBIDDEN_RIGHTS`] on
/// every entry under each read-only path. This covers protected-DACL
/// descendants, paths the user cannot change and silent inheritance failures
/// in one check.
fn verify_protected_paths(
    token: HANDLE,
    denied_read_paths: &[PathBuf],
    read_only_paths: &BTreeSet<PathBuf>,
) -> Result<()> {
    let impersonation = unsafe { ImpersonationToken::duplicate(token)? };
    for denied in denied_read_paths {
        verify_tree(&impersonation, denied, DENIED_FORBIDDEN_RIGHTS, "denied")?;
    }
    for path in read_only_paths {
        verify_tree(&impersonation, path, READ_ONLY_FORBIDDEN_RIGHTS, "read-only")?;
    }
    Ok(())
}

fn verify_tree(
    impersonation: &ImpersonationToken,
    path: &Path,
    forbidden: u32,
    kind: &str,
) -> Result<()> {
    for entry in entries_under(path)? {
        let granted =
            unsafe { granted_file_access(&entry, impersonation.0, MAXIMUM_ALLOWED)? } & forbidden;
        ensure!(
            granted == 0,
            "read-enforcing sandbox token still has access {granted:#x} to {kind} path {}; refusing to run",
            entry.display()
        );
    }
    Ok(())
}

/// `path` and its descendants, without following reparse points.
fn entries_under(path: &Path) -> Result<Vec<PathBuf>> {
    let mut entries = Vec::new();
    let mut pending = vec![path.to_path_buf()];
    while let Some(next) = pending.pop() {
        let metadata = match std::fs::symlink_metadata(&next) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(err)
                    .with_context(|| format!("inspect protected path {}", next.display()));
            }
        };
        ensure!(
            entries.len() < MAX_VERIFIED_ENTRIES_PER_PATH,
            "protected path {} has more than {MAX_VERIFIED_ENTRIES_PER_PATH} entries to verify; refusing to run",
            path.display()
        );
        if metadata.is_dir() && !metadata.file_type().is_symlink() {
            let children = std::fs::read_dir(&next)
                .with_context(|| format!("list protected path {}", next.display()))?;
            for child in children {
                pending.push(
                    child
                        .with_context(|| format!("list protected path {}", next.display()))?
                        .path(),
                );
            }
        }
        entries.push(next);
    }
    Ok(entries)
}

/// An impersonation copy of a token, as `AccessCheck` requires.
struct ImpersonationToken(HANDLE);

impl ImpersonationToken {
    /// # Safety
    /// `token` must be a valid token handle with `TOKEN_DUPLICATE` access.
    unsafe fn duplicate(token: HANDLE) -> Result<Self> {
        let mut impersonation: HANDLE = std::ptr::null_mut();
        if unsafe { DuplicateToken(token, SecurityImpersonation, &mut impersonation) } == 0 {
            let err = unsafe { GetLastError() };
            return Err(anyhow!("DuplicateToken failed: {err}"));
        }
        Ok(Self(impersonation))
    }
}

impl Drop for ImpersonationToken {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}

/// `AccessCheck` of `desired` on a file or directory for an impersonation copy
/// of `token`; true only when every requested right is granted.
///
/// # Safety
/// `token` must be a valid token handle with `TOKEN_DUPLICATE` access.
#[cfg(test)]
pub(crate) unsafe fn file_access_allowed(path: &Path, token: HANDLE, desired: u32) -> Result<bool> {
    let impersonation = unsafe { ImpersonationToken::duplicate(token)? };
    let granted = unsafe { granted_file_access(path, impersonation.0, desired)? };
    Ok(desired != 0 && granted & desired == desired)
}

/// Rights `AccessCheck` grants `impersonation` on a file or directory for
/// `desired` (`MAXIMUM_ALLOWED` for everything it would grant); zero when it
/// grants nothing.
///
/// # Safety
/// `impersonation` must be a valid impersonation token handle.
unsafe fn granted_file_access(path: &Path, impersonation: HANDLE, desired: u32) -> Result<u32> {
    let mut sd: *mut c_void = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            to_wide(path).as_ptr(),
            1, // SE_FILE_OBJECT
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    ensure!(
        code == ERROR_SUCCESS,
        "GetNamedSecurityInfoW({}) failed: {code}",
        path.display()
    );
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ,
        GenericWrite: FILE_GENERIC_WRITE,
        GenericExecute: FILE_GENERIC_EXECUTE,
        GenericAll: FILE_ALL_ACCESS,
    };
    let granted = unsafe { access_check_descriptor(sd, impersonation, desired, &mapping) };
    unsafe {
        LocalFree(sd as HLOCAL);
    }
    granted.with_context(|| format!("AccessCheck({})", path.display()))
}

/// Rights `AccessCheck` grants `impersonation` on the object described by `sd`
/// for `desired`; zero when it grants nothing.
///
/// # Safety
/// `sd` must be a valid self-relative security descriptor with owner, group
/// and DACL, and `impersonation` a valid impersonation token handle.
unsafe fn access_check_descriptor(
    sd: *mut c_void,
    impersonation: HANDLE,
    desired: u32,
    mapping: &GENERIC_MAPPING,
) -> Result<u32> {
    let mut privileges = [0u64; 128];
    let mut privilege_bytes = std::mem::size_of_val(&privileges) as u32;
    let mut granted = 0;
    let mut allowed = 0;
    let ok = unsafe {
        AccessCheck(
            sd,
            impersonation,
            desired,
            mapping,
            privileges.as_mut_ptr().cast(),
            &mut privilege_bytes,
            &mut granted,
            &mut allowed,
        )
    };
    ensure!(ok != 0, "AccessCheck failed: {}", unsafe { GetLastError() });
    Ok(if allowed != 0 { granted } else { 0 })
}

#[cfg(test)]
#[path = "read_enforcing_tests.rs"]
mod tests;
