# Windows sandbox PC validation

Prepared 18 November 2026. This is a fork validation plan, not installation approval or a completed fix. Start with native, non-elevated Windows observations. Preserve existing source changes, managed denials and security controls. Use synthetic secrets only.

## What the evidence establishes

| Track | Immutable revision | Result and limit |
|---|---|---|
| Option D candidate, PR #2 | `eef8136d5e7d3a54d0502e99bd8362eea7dd995e` | Run [43582766382](https://github.com/Kingsy-the-creator/codex/actions/runs/43582766382): 13 expansion tests, the exact elevated boundary test, 8 resolver tests and the existing elevated command test passed. The full library suite was **291 passed, 9 failed, 6 ignored**, reported without failing the workflow. Seven of the nine are knock-ons from the shared legacy test lock being poisoned (`tests.rs:62`), including both tests below, so that run says nothing about them. The primary failures were `legacy_capture_cancellation_terminates_descendants_without_timeout` (cancellation did not end capture before the timeout) and `uninstall_windows::principals::tests::profile_cleanup_preserves_account_until_profile_can_be_deleted` (read owned profile hive: 1018). |
| Option D comparison base | `d18d77d3b10b268ed1925b8bb612249c414587ef` | Use this base for candidate regression comparisons. Its historical guard tests prove early refusal, not restored broad execution. |
| Separate current-main diagnostic | `8703d32bd0ea5cf26768859a3dd476df906ba053` | PR #3 head `bab42a9cae8262bacc006728167b3f8c916b0fd5` changes only its workflow. Run [43791063542](https://github.com/Kingsy-the-creator/codex/actions/runs/43791063542): **267 passed, 8 failed, 5 ignored**. Four failures pass alone; two others respond differently to permission experiments. Two descendant-lifecycle tests remain unexplained. This is not Option D's base. |
| Installer fixture, PR #4 | `91fadced7ba9426a20c2ac9ba3805944d8484262` | Run [43585484218](https://github.com/Kingsy-the-creator/codex/actions/runs/43585484218): candidate 22 tests pass without skips on Ubuntu 24.04 and 26.04. Baseline/unpatched candidate each fail one on 26.04. This fixes a Linux test fixture, not Windows runtime permissions. |

Option D deliberately permits eligible profile directories, not whole-drive writes. Explicit drive-root writes, other volumes and excluded profile paths remain refused. The existing elevated boundary fixture runs as an administrator. It does not establish ordinary-user `WRITE_DAC` behaviour (the right to alter a folder's access rules).

The earlier independent review request covered `5ded5417a1be37eb9d08860d298bd3850ff8e731`. The current candidate changes two Rust files after that revision: canonical root-alias checks in `resolved_permissions.rs` and refresh validation plus a regression test in `setup.rs`. Review the original packet and this [exact delta](https://github.com/Kingsy-the-creator/codex/compare/5ded5417a1be37eb9d08860d298bd3850ff8e731...eef8136d5e7d3a54d0502e99bd8362eea7dd995e), or issue a new frozen packet. An old review cannot clear the newer revision automatically.

## First PC session: collect observations

1. Inspect the PC handoff store and active ownership before touching a checkout. Record the real repository path, branch, full commit and dirty state. The cloud cannot establish current installed binaries or account settings.
2. Use a separate detached worktree for each immutable revision. Keep it outside OneDrive and protected agent configuration folders, on a normal user-owned NTFS directory. Do not stash, reset, clean, switch or overwrite an active owner's checkout. Do not delete a worktree with unexplained changes.
3. Read the preflight script before execution. Run it with native 64-bit PowerShell 7, non-elevated, using an evidence folder outside the repository that does not yet exist:

   ```powershell
   & '<validation-checkout>\scripts\windows-sandbox-pc-preflight.ps1' `
     -Repository '<isolated-target-checkout>' `
     -ExpectedCommit '8703d32bd0ea5cf26768859a3dd476df906ba053' `
     -OutputDirectory '<private-evidence>\main-before'
   ```

4. Read `preflight.json` and `groups.txt`. A zero exit here means observations were collected, **zero tests ran**. Verify the exact `%ProgramFiles%\PowerShell\7\pwsh.exe`, current account, integrity label, actual profile, TEMP/TMP, path aliases and access rules. A PowerShell on PATH is insufficient. Parent FullLanguage does not prove the sandboxed child can use `Add-Type`.
5. Identify the required Rust version from the checkout, installed toolchains, MSVC build tools and Windows SDK. Missing prerequisites are a blocker, not a sandbox failure. Builds can download dependencies and execute build scripts; record the existing installation/download authorisation before starting. Do not install tools or change execution policy merely to make this plan run. `codex-rs/rust-toolchain.toml` pins Rust 1.95.0 with clippy, rustfmt and rust-src, and rustup installs a missing pinned toolchain on the first `cargo` call by default: check `rustup toolchain list` before any cargo command and set `RUSTUP_AUTO_INSTALL=0` in the disposable shell. That variable needs rustup 1.28.1 or newer (`rustup --version`); older rustup ignores it, so there a missing 1.95.0 is a blocker to report before cargo runs. At d18d77d and eef8136 (and control base 4b2f29d) `codex-rs/Cargo.toml` declares workspace version `0.167.0-alpha.3.2` while `Cargo.lock` still records `0.0.0`, so the first cargo command rewrites about 171 version lines and leaves both comparison checkouts dirty; `--locked` fails there. Main 8703d32 is consistent. Retain that expected diff; any other Cargo.lock change needs an explanation. Do not silently discard either.
6. Before test execution, inventory the checkout's existing ACL entries and test-related processes. Record before/after identity and access rules. Tests add capability entries to their workspace and make temporary files/processes. Existing elevated/full-suite tests can create sandbox accounts or perform account cleanup. Review those effects separately; the first two-test session does not run the full suite or any ignored test.

## Run the two unresolved tests, one at a time

These commands are for the isolated main checkout's `codex-rs` directory after preflight and permission for those bounded test effects. Prebuild once with `cargo test -p codex-windows-sandbox --lib --no-run`; keep its log, actual exit and lockfile changes. Discover the exact names with `cargo test -p codex-windows-sandbox --lib -- --list`; a successful build or listing is not a test pass. Build helper binaries only if the selected tests actually require them, and record their source revision and paths.

Set these process-only values in the disposable test shell, recording any prior values: `RUST_BACKTRACE=1`, `RUST_LIB_BACKTRACE=0`, `RUST_MIN_STACK=8388608`, `CARGO_TERM_COLOR=never`, `RUSTUP_AUTO_INSTALL=0`. Do not persist them globally. Avoid launching other sandbox tests concurrently.

```powershell
$PSNativeCommandUseErrorActionPreference = $false # keep nonzero native exits available to record
$test = 'unified_exec::tests::legacy_capture_emits_output_and_preserves_descendant_after_normal_exit'
cargo test -p codex-windows-sandbox --lib $test -- --exact --nocapture --test-threads=1 2>&1 |
    Tee-Object -FilePath '<private-evidence>\capture.log'
$code = $LASTEXITCODE
$code | Set-Content '<private-evidence>\capture.exit.txt'

$test = 'unified_exec::tests::legacy_tty_job_terminates_and_preserves_descendants'
cargo test -p codex-windows-sandbox --lib $test -- --exact --nocapture --test-threads=1 2>&1 |
    Tee-Object -FilePath '<private-evidence>\tty.log'
$code = $LASTEXITCODE
$code | Set-Content '<private-evidence>\tty.exit.txt'
```

Run the first command to completion and inspect it before starting the second. Use separate fresh evidence filenames for retries. A test-only run that has not finished after five minutes is a hang/incomplete result: record the process tree and stop only processes positively identified as belonging to this run, under the approved cleanup scope. Do not kill unrelated cargo, PowerShell or Codex processes. Compilation has a separate budget: a prior hosted cold build took about 11 minutes, not a promise for this PC.

Capture means ordinary command output collection. TTY means a pseudoterminal, Windows ConPTY, used for interactive processes. The TTY test contains **both** terminate and preserve cases. Capture must preserve the descendant after normal parent exit, release it, and see it finish. TTY must terminate descendants on cancellation and preserve them after normal exit until release.

For every run record full commit, source changes, start/end timestamps with timezone, native exit code, timeout/interrupt status, exact command, raw output and preflight evidence. Require exactly one named test and `1 passed; 0 failed; 0 ignored`. Capture must also print `capture pwsh codex_home=`, `exit_code=0` and `timed_out=false`. TTY has no positive body marker: verify the pinned function has only the known missing-PowerShell early return, the exact executable was present and runnable before/after, no skip was printed, and both lifecycle assertions were reached. If body execution remains uncertain, record BODY_UNCONFIRMED rather than certify coverage. The optional classifier treats a TTY pass with no duration, or under 0.25 s, as BODY_UNCONFIRMED: the early return is instant and libtest hides its skip text unless `--nocapture` is used. Temporary diagnostic markers can be a separately recorded identical patch on both comparison revisions; they must not weaken assertions or alter permissions/timings.

Optional local log triage:

```powershell
python '<validation-checkout>\scripts\classify-sandbox-pc-log.py' '<private-evidence>\capture.log' --test capture --exit-code <actual-code>
python '<validation-checkout>\scripts\classify-sandbox-pc-log.py' '<private-evidence>\tty.log' --test tty --exit-code <actual-code>
```

The classifier returns REPORTED_PASS, never a complete-fix verdict. Its exit code is not the test's exit code. Do not pass a whole CI job, several attempts or nested probe output as one test invocation.

## Interpret results without overclaiming

| Observation | Interpretation | Next action |
|---|---|---|
| Main passes on PC, hosted main failed | Environment difference is supported; its cause remains unproved | Preserve the ordinary-user result; compare token, temp rights, child language mode and terminal behaviour. |
| Main fails in the same way on PC | Reproducible beyond that hosted runner | Identify the first failed prerequisite/assertion; it is not automatically an Option D regression. |
| Main differs between attempts | State, timing or flaky-test problem | Repeat only the affected case up to three fresh-process runs; keep all results, then diagnose. |
| Option D base passes, candidate fails under matched conditions | Candidate regression is a serious possibility | Reproduce once with clean state, isolate the differing code and repair before acceptance. |
| Base and candidate fail identically | Existing problem or shared environment limitation is supported | Track separately; check whether it prevents the required user workflow or security guarantees. |
| Candidate passes only after elevation or broadened rights | Required ordinary-user path remains unproved | Diagnose the missing right/setup behaviour; do not adopt blanket permission changes. |
| Missing shell, zero matches, ignored test, helper-only success, build failure or no complete result | No valid feature pass | Correct the prerequisite/harness or leave the case blocked. |

For Option D regression comparisons, use **d18d77d versus eef8136**, each in isolated checkouts with separate target/temp/evidence paths, the same account and matched ACL starting state. Record deliberate differences. Sequential runs can inherit machine accounts, capability grants or profile state; a new process alone is not a clean machine. If those effects cannot be bounded, use a disposable Windows environment rather than claiming an independent control. The separate main result is useful context, not a replacement for this comparison.

## Remaining acceptance cases and pitfalls

These are planned cases, not executed checks. Apply in bounded batches with before/after evidence. Use files and secrets made for the test, never real denied-read targets.

| ID | Case or pitfall | Required observation / response |
|---|---|---|
| P01 | Missing PowerShell, alternate install or x86 shell | Exact expected 64-bit executable exists and runs; reject early-return success. |
| P02 | Elevated account differs from normal user | Record SID, integrity and profile each time; do not substitute an administrator result. |
| P03 | Administrator protection changes the account/profile | Observe the actual context on this PC; do not infer it from historical reports. |
| P04 | Parent FullLanguage, child ConstrainedLanguage | Capture the sandbox child's mode and stderr; do not weaken application control or use policy bypasses. |
| P05 | Wrong revision or dirty tree | Full SHA, diff and source hashes; preserve the original checkout. |
| P06 | Cached helpers from another revision | Separate build outputs; match helper paths/hashes to the tested revision. |
| P07 | Missing SDK/toolchain/dependency | Classify build/precondition failure separately; no silent installs. |
| P08 | Test filter matches zero or several cases | Discover exact name, execute one, require counts and captured native exit. |
| P09 | Ignored child helper run by itself | `retained_handles_child` can return success without its fixture; count its real parent instead. `workload_identity_child` is not a standalone feature test. |
| P10 | MSIX identity absent | Registered-backend test is blocked until its genuine package context exists; do not manufacture a pass. |
| P11 | Nested probe summaries or repeated annotations | Attribute results to the parent invocation; do not add child/annotation counts. |
| P12 | Lock poisoning after another test fails | Diagnose the first failure; fresh-process retry is separate evidence. |
| P13 | Timeout, missing PID marker, truncated log | Preserve first error and process evidence; not success or automatically a runtime defect. |
| P14 | Terminal cancellation vs normal exit | Verify terminate **and** preserve branches, exit status and descendant cleanup. |
| P15 | Antivirus, Controlled Folder Access, OneDrive, Dev Drive | Record actual state/events without disabling protection; these are hypotheses until evidenced. |
| P16 | TEMP/TMP depend on admin-only inherited rights | Compare effective rights in the ordinary token; no `Everyone:Modify` workaround on the PC. |
| P17 | Prior runs leave files, accounts, processes or ACL entries | Compare before/after; clean only identified test-owned state using a reviewed rollback. |
| P18 | Parallel runs or another active agent | Serialise account/ACL tests; preserve ownership and logs. |
| S01 | Symbolic `:root` vs explicit drive root | Only the intended symbolic elevated policy expands; explicit root is refused before setup. |
| S02 | Junction alias of drive root | Current `setup_refresh_rejects_junction_root_aliases_before_setup` must pass; verify no setup directory was created. |
| S03 | TEMP/TMP points to root alias | Both refresh entry points reject before changing ACLs; include symbolic-plus-explicit input. |
| S04 | UNC, extended paths, casing, 8.3 names | Canonicalisation preserves the same deny/root decision; record unsupported aliases as untested. |
| S05 | Profile missing, wrong volume, redirected or reparse ancestor | Fail closed or exclude safely; never expand an unintended user's profile. |
| S06 | Junction/reparse child or path swapped during setup | No grant escapes the intended tree; review race/ancestor behaviour before claims. |
| S07 | Read-denied root or directory ancestor | No expanded grant overwrites or outranks denial. |
| S08 | Denied file/directory inside writable root | Synthetic secret stays unreadable and unchanged; an allowed sibling remains usable. |
| S09 | Protected DACL and unusual inheritance flags | Denial and narrow grants hold without assuming default inheritance. |
| S10 | Excluded agent/editor folders and profile-root files | They remain unwritable; test all configured exclusion names, not just `.claude`. |
| S11 | CODEX_HOME inside an expanded ancestor | Split around it; neither it nor a renameable protected ancestor becomes writable. |
| S12 | Startup, WindowsApps and both PowerShell profile folders | Existing and initially absent paths remain protected, including redirected known folders. |
| S13 | Rename/delete via a parent directory | Protected child cannot be bypassed by moving/removing its ancestor. |
| S14 | Failed WRITE_DAC or partly applied grant | Log the failure; verify actual resulting access, not just that the root was omitted from a list. |
| S15 | Refresh with changed/revoked policy | Retained denials remain effective; stale capability grants do not reopen access. |
| S16 | Repeated setup, interrupted propagation, retry | No widening after partial failure; rollback/retry consequences are explicit. |
| S17 | Large/deep profile, split depth and grant threads | Measure time and failures; the cap of eight threads is not a time limit. |
| S18 | Consumer disagreement | Resolver, setup, spawn preparation, wrapper and token use the same effective roots. |
| S19 | Legacy backend receives retained denials | It remains non-expanding and refuses unsupported deny-read enforcement. |
| S20 | Process and desktop isolation | The real probe runs; dangerous process rights denied, victim survives, clipboard blocked; model limits remain recorded. |
| S21 | Deferred execution outside listed exclusions | Review remaining paths the user's apps might execute later; profile write retains residual risk. |
| S22 | Network permissions | Remain unchanged and enforced as configured; filesystem tests do not establish network isolation. |
| R01 | Installed runtime differs from reviewed source | Record executable resolution/version/hash, helpers, configuration and launch path before any replacement. |
| R02 | Original symptom is outside the profile | Option D does not meet whole-drive access; choose a narrow explicit workspace grant/design, not relaxed denials. |
| R03 | Real workflow differs from the Rust fixture | Reproduce a harmless equivalent through the actual approval path with synthetic denied files. |
| R04 | Rollback or cleanup removes unrelated state | Keep before snapshots and a bounded restoration plan; never recursively reset a profile/root ACL. |
| R05 | Full suite badge is green despite report-only failures | Retain complete counts, all failure names, skipped steps and separate retries. |
| R06 | Original reviewer packet covers older code | Review the frozen packet plus newer delta independently; no aggregate clearance from stale review. |

## Ordinary-user boundary test needs preparation

Do **not** simply run the existing ignored elevated test non-elevated and interpret failure as an Option D defect. It creates `C:\codex-optd-e2e-<pid>` and a root-file sentinel; fixture creation can fail before exercising the feature. It also provisions sandbox state.

Prepare a dedicated, uniquely named user-owned fixture on the intended volume, with a synthetic profile override scoped to the test and restored on every exit. Keep the outside-profile negative target outside that synthetic profile but inside the disposable test area. Preserve the real drive-root negative check without deleting an unrelated pre-existing file. The setup/refresh caller must retain the ordinary user's token; any required account provisioning needs a separately identified setup step and account. Verify the test observes the intended signed-in profile rather than the administrator-protection account. Do not re-ACL the real profile for a fixture.

Before executing that adapted test, review the exact patch, asserted access boundaries and account/ACL cleanup. Run the corresponding administrator control separately. A setup UAC prompt does not establish that every later operation used the correct token. The current fixture is useful evidence; it is not the ready-made ordinary-user test.

## Completion gates

1. **Review:** independent review covers the exact intended candidate, including the two-file delta and material residuals. Missing original packets remain missing, not reconstructed originals.
2. **Regression:** the two legacy tests and the two permission-sensitive cases are classified with matched base/candidate evidence. Existing failures can be tracked separately only with evidence and an explicit effect on the required workflow; a universal green claim requires resolving all applicable failures.
3. **Boundary:** ordinary-user writes to eligible fixtures work while retained denies, explicit-root refusal, protected paths, process isolation and refresh behaviour hold. High-risk untested cases are visible, not silently waived.
4. **Build:** relevant Windows compilation/tests and style/lint checks run at the final SHA. Review PR #4's installer fixture separately; do not merge merely because its focused tests passed. Broad CI failures still need attributable causes or scoped accepted exclusions, never weaker gates. The pre-existing Cargo.lock version mismatch above is one candidate cause to check against the Cargo.lock worktree-mutation failures reported for broad CI run 43380844211.
5. **PC workflow:** with deployment approval, the intended binary and helpers actually reproduce the harmless user workflow in the real launch path; before/after checks show policies and unrelated access unchanged, with a verified rollback.

Until these gates are satisfied, the correct status is **tested candidate; PC validation and independent review incomplete**. The two legacy tests need a defensible classification, but are not automatically blockers specific to Option D. A complete fix is relative to the agreed profile-scoped workflow, not an assertion that every broad command can now write anywhere.
