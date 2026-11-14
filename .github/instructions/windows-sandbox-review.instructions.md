---
applyTo: "codex-rs/windows-sandbox-rs/**,codex-rs/sandboxing/**,.github/workflows/claudeai-option-d.yml"
---

# Review focus: elevated Windows sandbox root write (fork review branch only)

This branch lets the *elevated* Windows sandbox (commands run as a separate local sandbox account) run an approved command whose policy is symbolic `:root` write plus retained deny-read paths. The backend cannot put an ACE on `C:\`, so `root_write_expansion.rs` replaces the filesystem-root write root with the real directories directly inside the user profile (no files, no reparse points, no agent config folders, nothing read-denied or under a read-denied path, split around `CODEX_HOME`). Deferred-execution folders (Startup, `WindowsApps`, PowerShell profile folders) get deny-write carveouts. Review it as security-critical code; prefer a few high-confidence findings over style notes.

Check especially:

1. **Does a denied path become readable?** The write grant uses `SET_ACCESS` for the sandbox group and the root's capability SID (`acl.rs` `ensure_allow_write_aces`), after deny-read ACEs are applied to the sandbox group. A root equal to or under a denied path is dropped; a denied path strictly inside a root relies on its explicit deny preceding the inherited allow. Look for a case where that ordering fails: protected DACLs, inheritance flags, files vs directories, globs, 8.3 or `\\?\` aliases, junctions, a later refresh re-granting.
2. **Does the expansion ever widen access?** It must only apply to the elevated backend (`effective_write_roots_for_permissions`); the unelevated path uses `effective_legacy_write_roots_for_permissions`. The resolver in `sandboxing/src/windows.rs` must accept only the symbolic `:root` write and still refuse an explicit `C:\ = write`.
3. **Token and ACL agreement:** every consumer of the seam (setup refresh, `elevated_impl`, `spawn_prep`, `wrapper`) must see the same roots, so no capability SID is in the token for a root the policy denies.
4. **Deferred execution as the user:** what else under the profile would the user's own processes later run from (beyond the listed folders and the excluded `.claude`, `.codex`, `.agents`, `.vscode`, `.cursor`, `.gemini`)? Distinguish what is fixable here from the inherent residual of granting profile write.
5. **Process isolation:** the sandbox token is `WRITE_RESTRICTED` and shares the caller's logon SID (`CreateProcessWithLogonW`). The e2e test's `OpenProcess` probe measures this; check the probe's victim (medium integrity, modelled standard-user DACL) is a fair model.
6. **Failure handling:** a failed grant on an expanded root is logged and skipped (`best_effort_write_roots`); confirm a skipped root cannot end up writable and that non-expanded roots still fail closed.
7. Unsafe Rust and FFI in `isolation_probe.rs` and `known_folder`: struct layouts, buffer sizes, handle and `LocalFree`/`CoTaskMemFree` pairing, edition 2024 `unsafe` rules.

Known and accepted residuals (do not re-report unless you find a bypass): writes outside the profile (other volumes, `C:\` itself, folders outside the profile) are refused by design; the runner is an elevated administrator, so standard-user `WRITE_DAC` failures are not exercised in CI; propagation cost on large profile folders is bounded by thread count, not by a timeout.

The CI workflow is fork-only validation; do not suggest upstream CI changes. Rust is not built locally, so flag anything that would not compile on Windows with Rust 1.95.
