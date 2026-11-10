//! Expands a filesystem-root write root for the elevated (sandbox-account)
//! backend.
//!
//! The elevated backend grants writes by adding an inheritable allow ACE for a
//! per-root capability SID on each writable root, from a setup refresh that
//! runs as the signed-in user. A filesystem root such as `C:\` cannot take that
//! ACE: a standard user cannot open it for `WRITE_DAC`, and an ACE there would
//! rewrite the ACL of the whole volume. An approved command whose policy writes
//! from `:root` therefore replaces that root with the real directories directly
//! inside the user profile, when the profile is on that volume.
//!
//! Each expanded root is left out when it:
//!
//! - is a file or a reparse point (only real directories are expanded, so
//!   profile files such as shell start-up files are never writable);
//! - is an agent or editor configuration folder that a later process running
//!   as the user would execute from ([`ROOT_WRITE_PROFILE_EXCLUSIONS`]);
//! - is read-denied by the policy, or lies under a read-denied path. The write
//!   grant replaces the sandbox group's entries on the root object itself, and
//!   an explicit allow there would outrank a deny inherited from above, so such
//!   a root would make the denied path readable. A read-denied path strictly
//!   inside a root keeps its own explicit deny ACE, which precedes the
//!   inherited allow, so the root is kept;
//! - is `CODEX_HOME`, a deferred-execution directory, or an ancestor of either.
//!   Ancestors are split into real child directories recursively, so neither
//!   the protected directory nor an ancestor receives a write grant.
//!
//! Nothing else is added, and the filesystem root itself never is. Writes the
//! user could otherwise make elsewhere (other volumes, `C:\` itself, folders
//! outside the profile) are refused with "Access is denied". That is a
//! deliberate narrowing: the command keeps running as the separate sandbox
//! account, so the user's own processes stay out of its reach.
//!
//! The expansion is for the elevated backend only. The unelevated backend's
//! callers use [`crate::setup::effective_legacy_write_roots_for_permissions`],
//! which never expands.

use crate::path_normalization::canonical_path_key;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

/// Profile children never expanded into write roots, in addition to the
/// profile exclusions every write root already gets. Each holds configuration
/// that an agent or editor running as the user loads and acts on later.
pub(crate) const ROOT_WRITE_PROFILE_EXCLUSIONS: &[&str] = &[
    ".agents", ".claude", ".codex", ".cursor", ".gemini", ".vscode",
];

/// Profile-relative folders whose contents Windows or the user's shell runs
/// automatically later. Expansion splits around these even when missing;
/// existing parents also permit materialising a deny-write carveout.
const DEFERRED_EXECUTION_PROFILE_PATHS: &[&str] = &[
    r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
    r"AppData\Local\Microsoft\WindowsApps",
    r"Documents\PowerShell",
    r"Documents\WindowsPowerShell",
    r"OneDrive\Documents\PowerShell",
    r"OneDrive\Documents\WindowsPowerShell",
];

/// How deep a root containing a protected path is split before it is dropped.
const MAX_SPLIT_DEPTH: usize = 8;

/// True when `path` is a filesystem root (a drive root such as `C:\`, a UNC
/// share root, or `/`).
pub(crate) fn is_filesystem_root(path: &Path) -> bool {
    path.is_absolute() && path.parent().is_none()
}

/// Inputs to [`expand_filesystem_root_write_roots`].
pub(crate) struct RootWriteExpansion<'a> {
    /// The signed-in user's profile directory.
    pub(crate) user_profile: Option<&'a Path>,
    /// `CODEX_HOME`, which must never become writable.
    pub(crate) codex_home: &'a Path,
    /// Whether the policy denies reading `path` (true for paths under a
    /// read-denied directory too). Must fail closed.
    pub(crate) is_read_denied: &'a dyn Fn(&Path) -> bool,
}

/// Replaces each filesystem-root write root with the real directories inside
/// the user profile on that volume, minus the exclusions described in the
/// module documentation. Other roots pass through unchanged.
pub(crate) fn expand_filesystem_root_write_roots(
    roots: Vec<PathBuf>,
    expansion: &RootWriteExpansion<'_>,
) -> Vec<PathBuf> {
    if !roots.iter().any(|root| is_filesystem_root(root)) {
        return roots;
    }
    let mut expanded = Vec::new();
    for root in roots {
        if !is_filesystem_root(&root) {
            expanded.push(root);
            continue;
        }
        let Some(profile) = expansion
            .user_profile
            .filter(|profile| profile_is_on_volume(profile, &root))
        else {
            continue;
        };
        let mut from_profile = Vec::new();
        let mut protected_keys: Vec<String> = deferred_execution_candidates(profile)
            .iter()
            .map(|path| canonical_path_key(path))
            .collect();
        protected_keys.push(canonical_path_key(expansion.codex_home));
        for child in real_child_dirs(profile) {
            if is_root_write_profile_exclusion(&child) {
                continue;
            }
            split_around_protected_paths(child, &protected_keys, expansion.is_read_denied, 0, &mut from_profile);
        }
        // Only the roots this expansion adds are filtered here; explicit write
        // roots keep the policy's own precedence rules.
        from_profile.retain(|root| !(expansion.is_read_denied)(root.as_path()));
        expanded.extend(from_profile);
    }
    expanded.sort_by_key(|root| canonical_path_key(root));
    expanded.dedup_by(|a, b| canonical_path_key(a) == canonical_path_key(b));
    expanded
}

/// The deny-write carveouts an expanded profile needs: the folders under the
/// profile (including redirected Documents and Startup folders within it)
/// whose contents run automatically later. Only paths whose parent exists are
/// returned, so a carveout never creates a stray folder tree.
pub(crate) fn deferred_execution_paths(user_profile: &Path) -> Vec<PathBuf> {
    let mut paths = deferred_execution_candidates(user_profile);
    let profile_key = canonical_path_key(user_profile);
    paths.retain(|path| {
        Path::new(&canonical_path_key(path)).starts_with(&profile_key)
            && path.parent().is_some_and(Path::is_dir)
    });
    paths.sort_by_key(|path| canonical_path_key(path));
    paths.dedup_by(|a, b| canonical_path_key(a) == canonical_path_key(b));
    paths
}

fn deferred_execution_candidates(user_profile: &Path) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = DEFERRED_EXECUTION_PROFILE_PATHS
        .iter()
        .map(|relative| user_profile.join(relative))
        .collect();
    if let Some(documents) = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Documents) {
        paths.push(documents.join("PowerShell"));
        paths.push(documents.join("WindowsPowerShell"));
    }
    if let Some(startup) = known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_Startup) {
        paths.push(startup);
    }
    paths
}

fn profile_is_on_volume(profile: &Path, volume: &Path) -> bool {
    !is_filesystem_root(profile)
        && profile
            .ancestors()
            .last()
            .is_some_and(|profile_volume| {
                canonical_path_key(profile_volume) == canonical_path_key(volume)
            })
}

fn is_root_write_profile_exclusion(path: &Path) -> bool {
    path.file_name().is_some_and(|name| {
        let name = name.to_string_lossy();
        ROOT_WRITE_PROFILE_EXCLUSIONS
            .iter()
            .any(|excluded| name.eq_ignore_ascii_case(excluded))
    })
}

/// Pushes `root` unless it overlaps a protected path; ancestors are replaced
/// by their real child directories, recursively, without traversing denials.
fn split_around_protected_paths(
    root: PathBuf,
    protected_keys: &[String],
    is_read_denied: &dyn Fn(&Path) -> bool,
    depth: usize,
    out: &mut Vec<PathBuf>,
) {
    // Check before enumerating descendants, including ancestors of CODEX_HOME.
    if is_read_denied(&root) {
        return;
    }
    let root_key = canonical_path_key(&root);
    if protected_keys.iter().any(|key| Path::new(&root_key).starts_with(key)) {
        return;
    }
    let root_prefix = format!("{}/", root_key.trim_end_matches('/'));
    if !protected_keys.iter().any(|key| key.starts_with(&root_prefix)) {
        out.push(root);
        return;
    }
    if depth >= MAX_SPLIT_DEPTH {
        return;
    }
    for child in real_child_dirs(&root) {
        split_around_protected_paths(child, protected_keys, is_read_denied, depth + 1, out);
    }
}

/// The real directories directly inside `dir`. Junctions and symlinks are
/// skipped: their target could be any folder, including one outside the
/// profile or one the policy denies under another name.
fn real_child_dirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.symlink_metadata().is_ok_and(|metadata| {
                metadata.is_dir() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0
            })
        })
        .collect()
}

fn known_folder(folder_id: &windows_sys::core::GUID) -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::SHGetKnownFolderPath;

    let mut raw: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: `raw` receives a CoTaskMem-allocated, NUL-terminated string that
    // is freed below whether or not the call succeeded.
    let hr = unsafe { SHGetKnownFolderPath(folder_id, 0, std::ptr::null_mut(), &mut raw) };
    let path = if hr >= 0 && !raw.is_null() {
        // SAFETY: on success `raw` is a valid NUL-terminated wide string.
        let len = unsafe { (0..).take_while(|&i| *raw.add(i) != 0).count() };
        // SAFETY: `len` wide characters were just read from `raw`.
        let wide = unsafe { std::slice::from_raw_parts(raw, len) };
        Some(PathBuf::from(std::ffi::OsString::from_wide(wide)))
    } else {
        None
    };
    // SAFETY: CoTaskMemFree accepts null and the pointer SHGetKnownFolderPath returned.
    unsafe { CoTaskMemFree(raw as *const std::ffi::c_void) };
    path
}

#[cfg(test)]
#[path = "root_write_expansion_tests.rs"]
mod tests;
