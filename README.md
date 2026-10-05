# PowerScp

PowerScp is a PowerShell module for transferring files and managing them on remote servers. It uses [WinSCP](https://winscp.net/) to handle SFTP, SCP, FTP, FTPS, WebDAV, WebDAVS and S3 connections.

The project started with a simple need: upload files to an SFTP server from PowerShell. It has since grown to cover downloads, directory listings, checksums, synchronization and other tasks that come up when writing transfer scripts.

## What you need

PowerScp supports Windows PowerShell 5.1 and PowerShell 7 on Windows. WinSCP still needs Windows to open connections and transfer files, even if you use PowerShell 7. You can import the module, create transfer options and run the offline tests on macOS or Linux.

WinSCP 6.5.7 is included in the repository. The module loads the .NET Framework assembly in Windows PowerShell and the .NET Standard assembly in PowerShell 7. There is no separate WinSCP installation step when using this checkout.

If you update WinSCP yourself, keep the executable and both assemblies on the same version, then restart PowerShell. The [WinSCP installation documentation](https://winscp.net/eng/docs/library_install) explains the two assembly builds. Details about the bundled files and their licenses are in [bin/README.md](bin/README.md).

## Getting started

Import the module from the project folder:

```powershell
Import-Module ./PowerScp.psd1
```

To connect to an SFTP server, you will need your credentials and the server's SSH host key fingerprint. Ask the server administrator for the fingerprint and verify it before using it in your script.

This example lists remote files, previews an upload, uploads a report and downloads CSV files. Replace the server address, fingerprint and paths with your own values. The local `downloads` folder must already exist.

```powershell
$credential = Get-Credential
$verifiedFingerprint = 'ssh-ed25519 255 <your verified SHA-256 fingerprint>'

$session = New-ScpSession -RemoteHost 'sftp.example.org' -Protocol Sftp `
    -Credentials $credential -SshHostKeyFingerprint $verifiedFingerprint

try {
    Get-ScpChildItem -Session $session -RemotePath '/incoming' -Recurse -FilesOnly

    Send-ScpItem -Session $session -LocalPath './report.csv' -RemotePath '/incoming' -WhatIf
    Send-ScpItem -Session $session -LocalPath './report.csv' -RemotePath '/incoming'

    Receive-ScpItem -Session $session -RemotePath '/outgoing/*.csv' -LocalPath './downloads'
} finally {
    Remove-ScpSession -Session $session
}
```

Closing the session in a `finally` block releases its resources even when an operation fails. A session that has been removed cannot be opened again; create a new one when you need to reconnect.

## Working with files

`Send-ScpItem` takes local file or directory paths and uploads them to a remote directory. It creates the destination directory and any missing parents. Local paths are treated literally, so a filename containing brackets is handled as a filename rather than a wildcard pattern.

Uploading a directory keeps its folder structure. If you use `-TransferFilesOnly`, the module collects files from the entire directory tree and puts them directly into the destination directory. It rejects duplicate filenames before uploading, since flattening those files would cause them to overwrite one another.

`Receive-ScpItem` downloads files into an existing local directory. Its remote paths can use WinSCP file masks, such as `/outgoing/*.csv`.

Uploads and downloads keep the source files by default. Use `-Remove` when you deliberately want to delete each source after a successful transfer.

Commands that change files or directories support `-WhatIf` and `-Confirm`. For uploads, `-WhatIf` also prevents the destination directory from being created. Failed transfers and other operations report errors so your script can handle them.

### Transfer options

You can reuse the same transfer options across several uploads or downloads:

```powershell
$options = New-ScpTransferOptions -TransferMode Binary -Permissions 644 -SpeedLimit 1024

Send-ScpItem -Session $session -LocalPath './data' -RemotePath '/data' `
    -TransferOptions $options
```

`Permissions` uses Unix octal notation, such as `644` or `755`. `SpeedLimit` is measured in KB/s; zero leaves the transfer speed unlimited. Permissions and other options depend on what the server and protocol support.

### Directory listings

Use `Get-ScpChildItem` to list a directory. Add `-Recurse` to include its subdirectories and `-FilesOnly` to leave directories out of the results.

With `-Recurse`, `-Depth 1` includes items up to one subdirectory level below the starting directory. A depth of zero means no limit. WinSCP still searches the full tree before the module filters the results, so setting a depth does not reduce the remote search.

`Get-ScpItem` keeps its original behavior of listing remote items. Use `Receive-ScpItem` when you want to download them.

### Synchronization

Use `Sync-ScpDirectory` to keep a local and remote directory in sync:

```powershell
Sync-ScpDirectory -Session $session -LocalPath './data' -RemotePath '/data' `
    -Mode Remote -WhatIf
```

`Remote` uploads local changes, `Local` downloads remote changes, and `Both` works in both directions. Deleting files requires `-Remove`. The `Remove` and `Mirror` options cannot be used with `Both`.

## Connection settings

`New-ScpSession` accepts either a credential object or a username and password. You can also supply an SSH private key with `-SshKeyPath` and, for an encrypted key, its passphrase with `-SshKeyPassword`. An unencrypted key does not need a passphrase.

SCP remains the default protocol for compatibility with older scripts. Specify `-Protocol Sftp` for SFTP connections. If you leave the port unspecified, WinSCP chooses the protocol's default port.

`Get-HostFingerPrint` can scan SSH host key fingerprints and TLS certificate fingerprints. For a TLS scan, supply the appropriate FTPS or secure WebDAV settings. Verify a scanned fingerprint independently before trusting it. `-TlsHostCertificateFingerprint` lets you supply a trusted TLS certificate fingerprint when opening a connection.

`-NoSshKeyCheck` and `-NoTlsCheck` disable the corresponding identity checks. Passing either switch as `$false` keeps verification enabled.

For settings that do not have a dedicated parameter, including additional S3 configuration, use `-RawSettings` with a hashtable of [WinSCP raw settings](https://winscp.net/eng/docs/rawsettings).

## Available commands

| Task | Commands |
| --- | --- |
| Open, check and close connections | `New-ScpSession`, `Test-ScpSession`, `Remove-ScpSession` |
| Get a server fingerprint | `Get-HostFingerPrint` |
| List and inspect remote files | `Get-ScpChildItem`, `Get-ScpItem`, `Get-ScpItemType`, `Test-ScpPath`, `Get-ScpItemCheckSum` |
| Upload and download files | `Send-ScpItem`, `Receive-ScpItem`, `New-ScpTransferOptions` |
| Create directories, delete, move and copy files | `New-ScpDirectory`, `Remove-ScpItem`, `Move-ScpItem`, `Copy-ScpItem` |
| Synchronize directories | `Sync-ScpDirectory` |
| Run remote commands or open the console | `Invoke-ScpCommand`, `Start-WinScpConsole` |
| Convert backslashes in remote paths to slashes | `Format-StringPath` |

Remote copying and command execution depend on server support. `Remove-ScpItem` treats paths literally, including filenames with wildcard characters. `New-ScpDirectory -SuppressOutput` hides success output; errors are still reported.

For help with a command, run:

```powershell
Get-Help Send-ScpItem
Get-Command Send-ScpItem -Syntax
```

PowerScp focuses on scripting transfers and remote file operations. WinSCP's editor, bookmarks and interactive background queues are outside the module's scope.

## Updating from an older version

Version 1.1 requires PowerShell 5.1 or later. It also changes a few defaults and fixes behavior that older scripts may have worked around:

- WinSCP chooses the connection port unless you specify one.
- SFTP is now available as an explicit protocol choice; SCP remains the default.
- Transfers default to Binary mode. The existing `Text` value maps to WinSCP's `Ascii` mode.
- Checksums default to SHA-256.
- Missing local upload paths and failed operations report errors instead of being silently skipped.
- Internal helpers and module variables are no longer exported.

The [code review notes](docs/REVIEW.md) describe the fixes and the validation that remains.

## Running the tests

The test suite uses Pester 5.7.1:

```powershell
Import-Module Pester -RequiredVersion 5.7.1
Invoke-Pester ./tests/PowerScp.Tests.ps1 -CI
```

The tests check module loading, connection settings, transfer options and operation behavior. They use the real WinSCP assemblies, with simulated sessions for operations that would otherwise need a server. Since WinSCP's session class cannot be mocked directly, those tests use a temporary copy of the module with the session type annotations removed.

The Windows CI workflow runs the tests in Windows PowerShell 5.1 and the runner's installed PowerShell 7. Local verification has been performed on PowerShell 7.6.6 on macOS. Windows CI and live transfers have not yet been verified for this revision, so testing against your own servers is still needed before a production release.
