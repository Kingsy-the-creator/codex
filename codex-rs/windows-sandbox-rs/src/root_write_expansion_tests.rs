use super::*;
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;

fn keys(paths: &[PathBuf]) -> BTreeSet<String> {
    paths.iter().map(|path| canonical_path_key(path)).collect()
}

fn volume_of(path: &Path) -> PathBuf {
    path.ancestors().last().expect("volume").to_path_buf()
}

fn never_denied(_: &Path) -> bool {
    false
}

fn always_denied(_: &Path) -> bool {
    true
}

/// A fake profile with real directories, a file and a junction.
struct FakeProfile {
    _tmp: tempfile::TempDir,
    profile: PathBuf,
    codex_home: PathBuf,
}

impl FakeProfile {
    fn new(children: &[&str]) -> Self {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let profile = dunce::canonicalize(tmp.path()).expect("canonical tempdir");
        for child in children {
            std::fs::create_dir_all(profile.join(child)).expect("create child");
        }
        let codex_home = profile.join(".codex");
        Self {
            _tmp: tmp,
            profile,
            codex_home,
        }
    }

    fn expand(&self, roots: Vec<PathBuf>, is_read_denied: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
        expand_filesystem_root_write_roots(
            roots,
            &RootWriteExpansion {
                user_profile: Some(&self.profile),
                codex_home: &self.codex_home,
                is_read_denied,
            },
        )
    }

    fn expand_volume(&self, is_read_denied: &dyn Fn(&Path) -> bool) -> Vec<PathBuf> {
        self.expand(vec![volume_of(&self.profile)], is_read_denied)
    }
}

#[test]
fn non_root_write_roots_pass_through_unchanged() {
    let fake = FakeProfile::new(&["work"]);
    let roots = vec![fake.profile.join("work"), fake.profile.join("other")];
    // Explicit roots are not filtered, even when the predicate would deny them.
    let expanded = fake.expand(roots.clone(), &always_denied);
    assert_eq!(keys(&expanded), keys(&roots));
}

#[test]
fn filesystem_root_becomes_real_profile_directories_only() {
    let fake = FakeProfile::new(&["Documents", "AppData", "dev"]);
    std::fs::write(fake.profile.join(".gitconfig"), "x").expect("write profile file");
    let junction = fake.profile.join("linked");
    let junction_made = std::process::Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&junction)
        .arg(fake.profile.join("dev"))
        .output()
        .is_ok_and(|output| output.status.success());
    assert!(junction_made, "test setup: junction was not created");

    let expanded = fake.expand_volume(&never_denied);

    assert!(
        expanded.iter().all(|root| !is_filesystem_root(root)),
        "{expanded:?}"
    );
    assert_eq!(
        keys(&expanded),
        keys(&[
            fake.profile.join("AppData"),
            fake.profile.join("dev"),
            fake.profile.join("Documents"),
        ])
    );
}

#[test]
fn profile_on_another_volume_is_not_added() {
    let fake = FakeProfile::new(&["Documents"]);
    let other_volume_profile = PathBuf::from(r"\\codex-test-server\share\profile");
    let expanded = expand_filesystem_root_write_roots(
        vec![volume_of(&fake.profile)],
        &RootWriteExpansion {
            user_profile: Some(&other_volume_profile),
            codex_home: &fake.codex_home,
            is_read_denied: &never_denied,
        },
    );
    assert_eq!(expanded, Vec::<PathBuf>::new());
}

#[test]
fn missing_profile_expands_to_nothing() {
    let fake = FakeProfile::new(&["Documents"]);
    let expanded = expand_filesystem_root_write_roots(
        vec![volume_of(&fake.profile), fake.profile.join("Documents")],
        &RootWriteExpansion {
            user_profile: None,
            codex_home: &fake.codex_home,
            is_read_denied: &never_denied,
        },
    );
    assert_eq!(keys(&expanded), keys(&[fake.profile.join("Documents")]));
}

#[test]
fn read_denied_children_and_children_under_denied_paths_are_dropped() {
    let fake = FakeProfile::new(&["Documents", "secrets", "vault"]);
    let secrets_key = canonical_path_key(&fake.profile.join("secrets"));
    // `vault` lies under a denied glob or directory in the policy.
    let vault_key = canonical_path_key(&fake.profile.join("vault"));
    let is_read_denied = |path: &Path| {
        let key = canonical_path_key(path);
        key == secrets_key || key == vault_key
    };
    let expanded = fake.expand_volume(&is_read_denied);
    assert_eq!(keys(&expanded), keys(&[fake.profile.join("Documents")]));
}

#[test]
fn agent_configuration_folders_are_never_expanded() {
    let fake = FakeProfile::new(&[
        "Documents",
        ".claude",
        ".Codex",
        ".agents",
        ".vscode",
        ".cursor",
        ".gemini",
    ]);
    let expanded = fake.expand_volume(&never_denied);
    assert_eq!(keys(&expanded), keys(&[fake.profile.join("Documents")]));
}

#[test]
fn root_containing_codex_home_is_split_around_it() {
    let fake = FakeProfile::new(&[
        r"Documents\codex-home\.sandbox",
        r"Documents\notes",
        r"Documents\projects\app",
        "Music",
    ]);
    let codex_home = fake.profile.join(r"Documents\codex-home");
    let expanded = expand_filesystem_root_write_roots(
        vec![volume_of(&fake.profile)],
        &RootWriteExpansion {
            user_profile: Some(&fake.profile),
            codex_home: &codex_home,
            is_read_denied: &never_denied,
        },
    );
    assert_eq!(
        keys(&expanded),
        keys(&[
            fake.profile.join(r"Documents\notes"),
            fake.profile.join(r"Documents\projects"),
            fake.profile.join("Music"),
        ])
    );
}

#[test]
fn deferred_execution_paths_need_an_existing_parent() {
    let fake = FakeProfile::new(&[
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
        "Documents",
    ]);
    let paths = keys(&deferred_execution_paths(&fake.profile));
    for expected in [
        r"AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup",
        r"Documents\PowerShell",
        r"Documents\WindowsPowerShell",
    ] {
        let key = canonical_path_key(&fake.profile.join(expected));
        assert!(paths.contains(&key), "missing {expected}: {paths:?}");
    }
    for absent in [
        r"AppData\Local\Microsoft\WindowsApps",
        r"OneDrive\Documents\PowerShell",
    ] {
        let key = canonical_path_key(&fake.profile.join(absent));
        assert!(!paths.contains(&key), "unexpected {absent}: {paths:?}");
    }
}
