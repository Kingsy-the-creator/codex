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
        prefix = ["cargo", "test", "--locked", "-p", crate, "--lib"]
        listing = run(prefix + ["--", "--list"])
        discovered = [line.removesuffix(": test") for line in listing.splitlines() if line.endswith(": test")]
        for name in expected:
            matches = [full for full in discovered if full == name or full.endswith("::" + name)]
            if len(matches) != 1:
                raise SystemExit(f"Expected exactly one {name}; discovered {len(matches)}. Refusing a zero-test pass.")
            run(prefix + [matches[0], "--", "--exact", "--nocapture"])
    run(["cargo", "test", "--locked", "-p", "codex-sandboxing", "-p", "codex-windows-sandbox", "--lib"])

if __name__ == "__main__":
    main()
