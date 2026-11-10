//! Expands a filesystem-root write root for the elevated (sandbox-account)
//! backend.
//!
//! The elevated backend grants writes by adding an inheritable allow ACE for a
//! per-root capability SID on each writable root, from a setup refresh that
//! runs as the signed-in user. A filesystem root such as `C:\` cannot take that
//! ACE: a standard user cannot open it for `WRITE_DAC`, and an ACE there would
//! rewrite the ACL of the whole volume. An approved command whose policy writes
//! from `:root` therefore replaces that root with the roots the signed-in user
//! controls on the same volume:
//!
//! 1. the user profile, which the existing profile expansion then splits into
//!    its children minus the configured exclusions, `CODEX_HOME` and the
//!    sandbox state folders;
//! 2. each direct child of the filesystem root that is a real directory (not a
//!    reparse point) owned by the signed-in user's own SID.
//!
//! Nothing else is added, and the filesystem root itself never is. Writes the
//! user could otherwise make elsewhere (other volumes, `C:\` itself, folders the
//! user can write but does not own) are refused with "Access is denied". That
//! is a deliberate narrowing: the command keeps running as the separate sandbox
//! account, so the user's own processes stay out of its reach.

use crate::path_normalization::canonical_path_key;
use crate::token::get_current_token_for_restriction;
use crate::token::get_user_sid_bytes;
use crate::winutil::to_wide;
use std::ffi::c_void;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Foundation::CloseHandle;
use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Authorization::GetNamedSecurityInfoW;
use windows_sys::Win32::Security::EqualSid;
use windows_sys::Win32::Security::OWNER_SECURITY_INFORMATION;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

/// True when `path` is a filesystem root (a drive root such as `C:\`, a UNC
/// share root, or `/`).
pub(crate) fn is_filesystem_root(path: &Path) -> bool {
    path.is_absolute() && path.parent().is_none()
}

/// Replaces each filesystem-root write root with the roots the signed-in user
/// controls on that volume. Other roots pass through unchanged.
pub(crate) fn expand_filesystem_root_write_roots(roots: Vec<PathBuf>) -> Vec<PathBuf> {
    if !roots.iter().any(|root| is_filesystem_root(root)) {
        return roots;
    }
    let user_profile = std::env::var_os("USERPROFILE")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from);
    let user_sid = current_user_sid();
    expand_filesystem_root_write_roots_for(roots, user_profile.as_deref(), |path| {
        user_sid
            .as_deref()
            .is_some_and(|sid| path_is_owned_by(path, sid))
    })
}

/// Testable core of [`expand_filesystem_root_write_roots`]. `is_user_owned`
/// decides whether a top-level directory belongs to the signed-in user.
pub(crate) fn expand_filesystem_root_write_roots_for(
    roots: Vec<PathBuf>,
    user_profile: Option<&Path>,
    is_user_owned: impl Fn(&Path) -> bool,
) -> Vec<PathBuf> {
    let mut expanded = Vec::new();
    for root in roots {
        if !is_filesystem_root(&root) {
            expanded.push(root);
            continue;
        }
        let root_key = canonical_path_key(&root);
        if let Some(profile) = user_profile
            && profile
                .ancestors()
                .last()
                .is_some_and(|volume| canonical_path_key(volume) == root_key)
            && !is_filesystem_root(profile)
        {
            expanded.push(profile.to_path_buf());
        }
        expanded.extend(user_owned_top_level_dirs(&root, &is_user_owned));
    }
    expanded.sort_by_key(|root| canonical_path_key(root));
    expanded.dedup_by(|a, b| canonical_path_key(a) == canonical_path_key(b));
    expanded
}

fn user_owned_top_level_dirs(root: &Path, is_user_owned: &impl Fn(&Path) -> bool) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(root) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| {
            // Do not follow junctions or symlinks: their target could be any
            // folder, owned by anyone.
            entry.path().symlink_metadata().is_ok_and(|metadata| {
                metadata.is_dir()
                    && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            })
        })
        .map(|entry| entry.path())
        .filter(|path| is_user_owned(path))
        .collect()
}

fn current_user_sid() -> Option<Vec<u8>> {
    unsafe {
        let token = get_current_token_for_restriction().ok()?;
        let sid = get_user_sid_bytes(token).ok();
        CloseHandle(token);
        sid
    }
}

/// True when the owner of `path` is exactly `user_sid` (never a group such as
/// Administrators, which owns folders an elevated administrator creates).
fn path_is_owned_by(path: &Path, user_sid: &[u8]) -> bool {
    let mut owner: *mut c_void = std::ptr::null_mut();
    let mut sd: *mut c_void = std::ptr::null_mut();
    let code = unsafe {
        GetNamedSecurityInfoW(
            to_wide(path).as_ptr(),
            1, // SE_FILE_OBJECT
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut sd,
        )
    };
    if code != ERROR_SUCCESS {
        return false;
    }
    let owned = !owner.is_null()
        && unsafe { EqualSid(owner, user_sid.as_ptr() as *mut c_void) } != 0;
    unsafe {
        LocalFree(sd as HLOCAL);
    }
    owned
}

#[cfg(test)]
#[path = "root_write_expansion_tests.rs"]
mod tests;
