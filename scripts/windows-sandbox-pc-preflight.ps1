#requires -Version 7.0
<#
Read-only Windows observations, except for a new private evidence directory.
Does not build, run tests, install, elevate, change ACLs or read denied targets.
Exit 0 means the observations meet initial prerequisites, never a test pass.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Repository,
    [Parameter(Mandatory)][ValidatePattern('^[0-9a-fA-F]{40}$')][string]$ExpectedCommit,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
if (-not $IsWindows) { throw 'Native Windows PowerShell 7 is required; do not run under WSL.' }
$git = (Get-Command git -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
$repo = (Resolve-Path -LiteralPath $Repository).Path
if (-not (Test-Path -LiteralPath (Join-Path $repo 'codex-rs/windows-sandbox-rs/src/unified_exec/tests.rs') -PathType Leaf)) {
    throw 'Expected repository source is absent.'
}
if (Test-Path -LiteralPath $OutputDirectory) { throw 'Use a new evidence directory; existing evidence is never overwritten.' }
$out = [IO.Path]::GetFullPath($OutputDirectory)
if ($out.Equals($repo, [StringComparison]::OrdinalIgnoreCase) -or
    $out.StartsWith($repo.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Keep private evidence outside the checkout.'
}
$head = (& $git -C $repo rev-parse HEAD 2>&1 | Out-String).Trim()
if ($LASTEXITCODE -ne 0) { throw "git rev-parse failed: $head" }
$dirty = @(& $git -C $repo status --porcelain=v1 --untracked-files=all 2>&1)
if ($LASTEXITCODE -ne 0) { throw 'git status failed.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
$elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$pwsh = Join-Path $env:ProgramFiles 'PowerShell/7/pwsh.exe'
$pwshExists = Test-Path -LiteralPath $pwsh -PathType Leaf
$probe = $null
$probeCode = $null
if ($pwshExists) {
    $probe = @(& $pwsh -NoLogo -NoProfile -NonInteractive -Command '[pscustomobject]@{version=$PSVersionTable.PSVersion.ToString(); languageMode=$ExecutionContext.SessionState.LanguageMode.ToString(); exe=(Get-Process -Id $PID).Path} | ConvertTo-Json -Compress' 2>&1)
    $probeCode = $LASTEXITCODE
}
$tools = [ordered]@{}
foreach ($tool in @('git', 'cargo', 'rustc', 'rustup', 'cl', 'link')) {
    $found = Get-Command $tool -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    $tools[$tool] = if ($found) { $found.Source } else { $null }
}
# Do not invoke rustup shims: version checks inside a pinned checkout may download a toolchain.
$hashes = [ordered]@{}
foreach ($relative in @('codex-rs/Cargo.lock', 'codex-rs/rust-toolchain.toml', 'codex-rs/windows-sandbox-rs/src/unified_exec/tests.rs')) {
    $path = Join-Path $repo $relative
    if (Test-Path -LiteralPath $path -PathType Leaf) { $hashes[$relative] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }
}
$observations = @()
foreach ($path in @($repo, (Join-Path $repo 'codex-rs'), $env:TEMP, $env:TMP, $env:USERPROFILE) | Select-Object -Unique) {
    if (-not $path) { continue }
    try {
        $item = Get-Item -LiteralPath $path -Force
        $acl = Get-Acl -LiteralPath $path
        $observations += [pscustomobject]@{path=$path; attributes="$($item.Attributes)"; linkType=$item.LinkType; target=$item.Target; owner=$acl.Owner; sddl=$acl.Sddl; error=$null}
    } catch {
        $observations += [pscustomobject]@{path=$path; error=$_.Exception.Message}
    }
}
$blockers = @()
if ($head -ne $ExpectedCommit) { $blockers += 'HEAD does not match the requested immutable revision.' }
if ($dirty.Count -ne 0) { $blockers += 'Checkout is dirty; preserve changes and use an isolated checkout.' }
if ($elevated) { $blockers += 'This is an elevated administrator token; ordinary-user results require a separate non-elevated session.' }
if ([IntPtr]::Size -ne 8) { $blockers += 'Use a 64-bit native shell.' }
if (-not $pwshExists -or $probeCode -ne 0) { $blockers += 'The exact PowerShell 7 executable used by the tests is missing or cannot run.' }
if (-not $tools['cargo'] -or -not $tools['rustc']) { $blockers += 'Rust tools were not found; installation is not authorised by this script.' }
if (@($observations | Where-Object { $_.error }).Count -gt 0) { $blockers += 'One or more path/ACL observations failed; inspect the evidence.' }
$result = [ordered]@{
    schema=1; observed_at_utc=[DateTime]::UtcNow.ToString('o'); kind='preflight_only';
    repository=$repo; expected_commit=$ExpectedCommit; actual_commit=$head; dirty=@($dirty);
    windows_version=[Environment]::OSVersion.VersionString; architecture=[Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString();
    identity=$identity.Name; sid=$identity.User.Value; elevated_administrator=$elevated;
    userprofile=$env:USERPROFILE; temp=$env:TEMP; tmp=$env:TMP;
    cargo_target_dir=$env:CARGO_TARGET_DIR; rustup_toolchain=$env:RUSTUP_TOOLCHAIN;
    parent_language_mode=$ExecutionContext.SessionState.LanguageMode.ToString();
    expected_pwsh=$pwsh; pwsh_exists=$pwshExists; pwsh_probe_exit=$probeCode; pwsh_probe_output=$probe;
    tool_paths=$tools; source_sha256=$hashes; path_observations=$observations;
    child_helper_environment_present=[bool]$env:CODEX_TEST_SETUP_LAUNCH_DIRECTORY;
    blockers=$blockers; tests_run=0;
    limitations=@('Does not validate Rust/SDK installation or cached dependencies.', 'Parent PowerShell language mode does not establish sandboxed-child language mode.', 'No permission changes or PC tests have been performed.')
}
New-Item -ItemType Directory -Path $out -ErrorAction Stop | Out-Null
$result | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $out 'preflight.json') -Encoding utf8
& whoami.exe /groups 2>&1 | Out-File -LiteralPath (Join-Path $out 'groups.txt') -Encoding utf8
$groupCode = $LASTEXITCODE
if ($groupCode -ne 0) { Write-Warning "whoami /groups exited $groupCode; identity evidence is incomplete." }
Write-Output "Saved private preflight evidence to $out. Tests run: 0."
if ($blockers.Count -gt 0 -or $groupCode -ne 0) {
    $blockers | ForEach-Object { Write-Warning $_ }
    exit 2
}
Write-Output 'Initial observations complete. Review the checklist and test side effects before execution.'
exit 0
