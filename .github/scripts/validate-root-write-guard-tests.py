"""Run from codex-rs on Windows; fail if any expected test is absent."""
import subprocess
import sys

EXPECTED = {
    "codex-windows-sandbox": [
        "refresh_write_root_validation_allows_empty_and_scoped_roots",
        "refresh_write_root_validation_rejects_drive_and_unc_roots",
        "refresh_write_root_validation_uses_computed_roots_with_retained_denial",
    ],
    "codex-sandboxing": [
        "elevated_root_write_with_retained_denied_read_is_refused_before_setup",
    ],
}

def run(args):
    print("+ " + " ".join(args), flush=True)
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, flush=True)
    result.check_returncode()
    return result.stdout

def main():
    if sys.platform != "win32":
        raise SystemExit("These tests are Windows-gated; a Linux run cannot validate them.")
    for crate, expected in EXPECTED.items():
        prefix = ["cargo", "test", "-p", crate, "--lib"]
        listing = run(prefix + ["--", "--list"])
        discovered = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
        for name in expected:
            matches = [full for full in discovered if full == name or full.endswith("::" + name)]
            if len(matches) != 1:
                raise SystemExit(f"Expected exactly one {name}; discovered {len(matches)}. Refusing a zero-test pass.")
            run(prefix + [matches[0], "--", "--exact", "--nocapture"])
    # Pre-existing upstream failure on GitHub-hosted windows-latest, unrelated to the
    # guards: it fails identically on the unpatched base c40729ea (control run
    # https://github.com/Kingsy-the-creator/codex/actions/runs/42611523841). Skipped
    # by exact name so every other test in both crates still has to pass.
    run(["cargo", "test", "-p", "codex-sandboxing", "-p", "codex-windows-sandbox", "--lib", "--",
         "--skip", "manager::tests::transform_for_direct_spawn_windows_materializes_inner_helper"])

if __name__ == "__main__":
    main()
