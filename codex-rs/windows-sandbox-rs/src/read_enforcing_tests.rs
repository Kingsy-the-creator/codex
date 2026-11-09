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
    let denied = AbsolutePathBuf::from_absolute_path(&secret_dir)?;
    let profile = approved_root_write_profile(&denied);

    let result = run_windows_sandbox_capture_with_filesystem_overrides(
        &profile,
        &[AbsolutePathBuf::from_absolute_path(&work)?],
        &fixture.root.join("home"),
        vec![
            "C:\\Windows\\System32\\cmd.exe".to_string(),
            "/D".to_string(),
            "/C".to_string(),
            "type secret\\s.txt & type sibling.txt & echo written>..\\elsewhere\\new.txt & echo written>secret\\w.txt & echo READ-ENFORCING-DONE"
                .to_string(),
        ],
        &work,
        HashMap::new(),
        Some(30_000),
        None,
        std::slice::from_ref(&denied),
        &[],
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
