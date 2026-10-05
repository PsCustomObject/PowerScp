# Verification

Run from the repository root in Windows PowerShell 5.1 or PowerShell 7. The offline
suite can also run in PowerShell 7 on Linux/macOS; live WinSCP operations require
Windows. Keep the bundled WinSCP executable and assemblies at matching versions.

## Offline regression tests and static analysis

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
Install-Module PSScriptAnalyzer -RequiredVersion 1.24.0 -Scope CurrentUser
Import-Module Pester -RequiredVersion 5.7.1
./scripts/Test-StaticAnalysis.ps1
Invoke-Pester ./tests -CI
```

Static analysis checks the shipping module and manifest and fails on any
unsuppressed diagnostic. Function-scoped exceptions document existing public
plural option names, legacy plaintext credential parameters and in-memory factories.
Use PSCredential and SecurePrivateKeyPassphrase for new code. No security or
ShouldProcess rules are disabled globally.

The Windows workflow runs these checks with Windows PowerShell 5.1 and the
runner's PowerShell 7. The offline session doubles exercise wrapper control flow,
not real transfer protocols or server behavior. Live tests are skipped unless
explicitly configured.

## Live SFTP verification

Use a dedicated writable test root on an SFTP server and an account that supports
upload, download, chmod, rename, delete and remote copying. Some SFTP servers do
not support remote copy; that case must be evaluated for your deployment rather
than silently ignored. Independently verify the SSH host fingerprint.

On Windows, set the following values for your own test server:

```powershell
$env:POWERSCP_LIVE_TESTS = '1'
$env:POWERSCP_SFTP_HOST = 'sftp.example.org'
$env:POWERSCP_SFTP_USER = 'powerscp-test'
$env:POWERSCP_SFTP_KEY = 'C:\keys\test.ppk'
$env:POWERSCP_SFTP_FINGERPRINT = '<verified SSH fingerprint>'
$env:POWERSCP_SFTP_ROOT = '/powerscp-test'
# Optional: $env:POWERSCP_SFTP_PORT = '2222'
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester ./tests/integration -CI -Output Detailed
```

The test key must be usable without an interactive passphrase prompt. Nothing
embeds a password in source or logs. Tests create a unique `powerscp-<GUID>` child
under the configured root and remove only that child on completion. Test cleanup
also disposes the session; inspect leftover test directories after interrupted runs.

These tests perform real uploads, downloads, source deletion, synchronization
comparison, permissions, text writes and remote replacement. Source deletion is
limited to temporary test files. They cover bracket filenames, exact UTF-8/line
ending round trips, recursive directory uploads and WhatIf behavior.

Offline tests cover replacement failures and unsafe restoration without needing
to deliberately break a real server. They cannot prove atomicity or concurrency
safety: forced replacement has no server-wide lock. A target is backed up under a
unique `.powerscp-backup-<GUID>` sibling before replacement. On failure it is
restored only if the destination is absent. Otherwise the backup is retained and
its path is reported. If backup cleanup fails after successful replacement, a
warning reports where the previous file remains. This strategy requires rename
permissions and can fail on servers where copying is allowed but renaming is not.

## Validation of the 1.2.1 changes

PowerShell 7.4.13 on Linux: 61 offline tests passed, zero failed; four live tests
were skipped. PSScriptAnalyzer 1.24.0 reported no unsuppressed diagnostics. Windows 5.1,
Windows PowerShell 7 and real SFTP transfers must still be checked using the
workflow and live suite. A configured workflow is not evidence of a passing run.
