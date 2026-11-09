//! Windows temp override behavior not covered by a successful child launch.
use super::*;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::NetworkSandboxPolicy;
use pretty_assertions::assert_eq;

#[test]
fn elevated_non_write_temp_never_grants_write_access() {
    let dir = tempfile::TempDir::new().unwrap();
    let cwd = AbsolutePathBuf::from_absolute_path(dir.path().join("work")).unwrap();
    let temp = dir.path().join("temp");
    std::fs::create_dir_all(cwd.as_path()).unwrap();
    std::fs::create_dir_all(&temp).unwrap();
    let env = HashMap::from([("Temp".into(), temp.to_string_lossy().into_owned())]);
    for access in [FileSystemAccessMode::Read, FileSystemAccessMode::Deny] {
        let profile = PermissionProfile::from_runtime_permissions(
            &FileSystemSandboxPolicy::restricted(vec![
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Read,
                ),
                FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Tmpdir,
                    },
                    access,
                ),
            ]),
            NetworkSandboxPolicy::Restricted,
        );
        let overrides = resolve_windows_elevated_filesystem_overrides(
            SandboxType::WindowsRestrictedToken,
            &profile,
            &cwd,
            true,
            &env,
        )
        .unwrap();
        let write_roots = overrides
            .as_ref()
            .and_then(|o| o.write_roots_override.as_ref());
        assert!(write_roots.is_none_or(Vec::is_empty));
        if access == FileSystemAccessMode::Deny {
            assert_eq!(
                overrides.unwrap().additional_deny_read_paths,
                vec![
                    AbsolutePathBuf::from_absolute_path(dunce::canonicalize(&temp).unwrap())
                        .unwrap(),
                ]
            );
        }
    }
}

#[test]
fn elevated_root_write_with_retained_denied_read_is_refused_before_setup() {
    let dir = tempfile::TempDir::new().unwrap();
    let cwd = AbsolutePathBuf::from_absolute_path(dir.path().join("work")).unwrap();
    let private = dir.path().join("private");
    std::fs::create_dir_all(cwd.as_path()).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    let denied = FileSystemSandboxEntry::new(
        AbsolutePathBuf::from_absolute_path(&private)
            .unwrap()
            .into(),
        FileSystemAccessMode::Deny,
    );
    // Shape produced by `FileSystemSandboxPolicy::for_approved_command` for a
    // baseline that carries a denied read: `:root` write plus the retained denial.
    let approved = PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Write,
            ),
            denied.clone(),
        ]),
        NetworkSandboxPolicy::Restricted,
    );
    let err = resolve_windows_elevated_filesystem_overrides(
        SandboxType::WindowsRestrictedToken,
        &approved,
        &cwd,
        true,
        &HashMap::new(),
    )
    .expect_err("root write with a retained denied read must not reach setup");
    assert!(
        err.contains("will not grant write access to filesystem root"),
        "{err}"
    );

    // The same denial with a scoped write root is still accepted.
    let scoped = PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(cwd.clone().into(), FileSystemAccessMode::Write),
            denied,
        ]),
        NetworkSandboxPolicy::Restricted,
    );
    resolve_windows_elevated_filesystem_overrides(
        SandboxType::WindowsRestrictedToken,
        &scoped,
        &cwd,
        true,
        &HashMap::new(),
    )
    .expect("scoped write with a retained denied read is enforceable");
}

#[test]
fn unelevated_root_write_with_retained_denied_read_uses_read_enforcing_route() {
    let dir = tempfile::TempDir::new().unwrap();
    let cwd = AbsolutePathBuf::from_absolute_path(dir.path().join("work")).unwrap();
    let private = dir.path().join("private");
    std::fs::create_dir_all(cwd.as_path()).unwrap();
    std::fs::create_dir_all(&private).unwrap();
    let denied = FileSystemSandboxEntry::new(
        AbsolutePathBuf::from_absolute_path(&private)
            .unwrap()
            .into(),
        FileSystemAccessMode::Deny,
    );
    // Shape produced by `FileSystemSandboxPolicy::for_approved_command` for a
    // baseline that carries a denied read: `:root` write plus the retained denial.
    let approved = PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Write,
            ),
            denied.clone(),
        ]),
        NetworkSandboxPolicy::Restricted,
    );
    let overrides = resolve_windows_restricted_token_filesystem_overrides(
        SandboxType::WindowsRestrictedToken,
        &approved,
        &cwd,
        WindowsSandboxLevel::RestrictedToken,
    )
    .expect("root write with a retained denied read uses the read-enforcing token")
    .expect("the denied read is passed to the backend");
    let private_key = dunce::canonicalize(&private).unwrap();
    assert!(
        overrides.additional_deny_read_paths.iter().any(|path| {
            dunce::canonicalize(path.as_path()).is_ok_and(|path| path == private_key)
        }),
        "{overrides:?}"
    );
    assert_eq!(overrides.read_roots_override, None);
    assert_eq!(overrides.write_roots_override, None);

    // A scoped write root would lose its confinement under that token.
    let scoped = PermissionProfile::from_runtime_permissions(
        &FileSystemSandboxPolicy::restricted(vec![
            FileSystemSandboxEntry::new(
                FileSystemPath::Special {
                    value: FileSystemSpecialPath::Root,
                },
                FileSystemAccessMode::Read,
            ),
            FileSystemSandboxEntry::new(cwd.clone().into(), FileSystemAccessMode::Write),
            denied,
        ]),
        NetworkSandboxPolicy::Restricted,
    );
    let err = resolve_windows_restricted_token_filesystem_overrides(
        SandboxType::WindowsRestrictedToken,
        &scoped,
        &cwd,
        WindowsSandboxLevel::RestrictedToken,
    )
    .expect_err("scoped write with a denied read still needs the elevated backend");
    assert!(
        err.contains("cannot enforce deny-read restrictions directly"),
        "{err}"
    );
}
