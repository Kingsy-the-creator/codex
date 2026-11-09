---
applyTo: "codex-rs/windows-sandbox-rs/**,codex-rs/sandboxing/**,.github/workflows/claudeai-token-spike.yml"
---

# Review focus: Windows sandbox read-enforcing token (fork review branch only)

This branch lets the unelevated Windows sandbox run an *approved* command whose policy writes from the filesystem root but keeps deny-read paths. It does so with a restricted token without `WRITE_RESTRICTED`, whose restricting SIDs are a capability SID, the user, Users, Authenticated Users, INTERACTIVE, RESTRICTED, the logon SID and Everyone. Review it as security-critical code. Prefer a few high-confidence findings over style notes.

Check especially:

1. **Can the sandboxed command read a denied path anyway?** Consider implicit owner rights (`READ_CONTROL`/`WRITE_DAC`), the OWNER RIGHTS (S-1-3-4) ACE, inheritance to existing and new children, protected-DACL descendants, hard links, junctions/symlinks, reparse points, alternate data streams, 8.3 short names, case and `\\?\` path forms, rename/delete via the parent's `FILE_DELETE_CHILD`, `SeBackupPrivilege`/`SeChangeNotifyPrivilege` and backup semantics.
2. **Can it write a denied or read-only path,** or remove/alter a deny ACE (`WRITE_DAC`, `WRITE_OWNER`, take ownership)?
3. **Does the routing ever widen access?** The read-enforcing token gives up capability-SID write confinement, so it must only be chosen when the policy already grants root write. Check `sandboxing/src/windows.rs` (`read_enforcing_filesystem_overrides`) and `windows-sandbox-rs/src/read_enforcing.rs` (`uses_read_enforcing_session`) agree, and that scoped write policies still refuse.
4. **The `AccessCheck` sweep** (`verify_protected_paths`): does it check the token the child really gets, the right access masks, every entry (no TOCTOU gap that matters, no skipped error), and fail closed?
5. **Error handling:** every ACL step on this route must be fatal; no `let _ =` on security-relevant calls; handles and `LocalFree` paired.
6. **Persistent state:** deny ACEs go through `sync_persistent_deny_read_acls_with_style`; check stale denies are revoked and nothing leaves a broader ACE behind.
7. Unsafe Rust: pointer lifetimes of `LocalSid`/SID byte buffers passed to Win32, buffer sizes, and `unsafe` blocks in edition 2024.

Known and accepted residuals (do not re-report unless you find a disclosure): delete/rename via the parent directory; workspace `.codex`/`.agents` protection not applied on this route; an OWNER RIGHTS ACE left after a deny is revoked; network enforcement unchanged from the existing legacy backend.

The CI workflow is fork-only validation; do not suggest upstream CI changes. Rust is not built locally, so flag anything that would not compile on Windows with Rust 1.95.
