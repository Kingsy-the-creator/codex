use super::*;
use pretty_assertions::assert_eq;
use std::collections::BTreeSet;

fn keys(paths: &[PathBuf]) -> BTreeSet<String> {
    paths.iter().map(|path| canonical_path_key(path)).collect()
}

#[test]
fn non_root_write_roots_pass_through_unchanged() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let roots = vec![tmp.path().join("work"), tmp.path().join("other")];
    let expanded =
        expand_filesystem_root_write_roots_for(roots.clone(), Some(tmp.path()), |_| true);
    assert_eq!(keys(&expanded), keys(&roots));
}

#[test]
fn filesystem_root_is_never_returned() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let volume = tmp.path().ancestors().last().unwrap().to_path_buf();
    let expanded =
        expand_filesystem_root_write_roots_for(vec![volume.clone()], Some(tmp.path()), |_| false);
    assert!(
        expanded.iter().all(|root| !is_filesystem_root(root)),
        "{expanded:?}"
    );
    assert!(
        expanded
            .iter()
            .any(|root| canonical_path_key(root) == canonical_path_key(tmp.path())),
        "the profile on the same volume must be kept: {expanded:?}"
    );
}

#[test]
fn profile_on_another_volume_is_not_added() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    // A profile path whose volume is not the root being expanded.
    let other_volume_profile = PathBuf::from(r"\\codex-test-server\share\profile");
    let volume = tmp.path().ancestors().last().unwrap().to_path_buf();
    let expanded = expand_filesystem_root_write_roots_for(
        vec![volume],
        Some(&other_volume_profile),
        |_| false,
    );
    assert!(
        !expanded
            .iter()
            .any(|root| canonical_path_key(root) == canonical_path_key(&other_volume_profile)),
        "{expanded:?}"
    );
}

#[test]
fn only_user_owned_real_top_level_directories_are_added() {
    // A fake volume: `user_owned_top_level_dirs` lists the children of the
    // root it is given, so the owner predicate and reparse filter can be
    // checked without touching a real drive root.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let root = tmp.path();
    let owned = root.join("owned");
    let foreign = root.join("foreign");
    let file = root.join("owned-file.txt");
    std::fs::create_dir_all(&owned).unwrap();
    std::fs::create_dir_all(&foreign).unwrap();
    std::fs::write(&file, "x").unwrap();
    let junction = root.join("owned-junction");
    let junction_made = std::process::Command::new("cmd")
        .args(["/D", "/C", "mklink", "/J"])
        .arg(&junction)
        .arg(&owned)
        .output()
        .is_ok_and(|output| output.status.success());

    let owned_key = canonical_path_key(&owned);
    let file_key = canonical_path_key(&file);
    let junction_key = canonical_path_key(&junction);
    let predicate = |path: &Path| {
        let key = canonical_path_key(path);
        key == owned_key || key == file_key || key == junction_key
    };
    let dirs = user_owned_top_level_dirs(root, &predicate);
    assert_eq!(keys(&dirs), BTreeSet::from([owned_key]));
    assert!(junction_made, "test setup: junction was not created");
}

#[test]
fn current_user_owns_a_directory_it_creates_unless_elevated() {
    // Folders created by an elevated administrator are owned by the
    // Administrators group, so they are correctly left out; a standard user
    // owns what it creates.
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let dir = tmp.path().join("made-by-me");
    std::fs::create_dir_all(&dir).unwrap();
    let sid = current_user_sid().expect("current user SID");
    let owned = path_is_owned_by(&dir, &sid);
    let elevated = crate::setup::is_elevated().unwrap_or(false);
    println!("PROBE owner-is-user={owned} elevated={elevated}");
    if !elevated {
        assert!(owned, "a standard user must own a directory it creates");
    }
}
