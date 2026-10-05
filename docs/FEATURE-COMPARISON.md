# Feature comparison

This comparison uses the published [WinSCP 6.3.6.0 Gallery package](https://www.powershellgallery.com/packages/WinSCP/6.3.6.0), including its public scripts, rather than assuming that its command names tell the whole story. The package was downloaded for inspection; it was not installed or imported. PowerScp's additions were implemented independently.

PowerScp 1.2 covers the reference module's everyday transfer and administration operations. It keeps PowerScp's command names and existing listing behavior, so this is a capability comparison, not a promise that scripts written for the other module run unchanged.

## Command mapping

| Gallery command | PowerScp equivalent |
| --- | --- |
| `ConvertTo-WinSCPEscapedString` | `ConvertTo-ScpEscapedString` |
| `Copy-WinSCPItem` | `Copy-ScpItem` |
| `Get-WinSCPChildItem` | `Get-ScpChildItem` |
| `Get-WinSCPItem` | `Get-ScpItemType` or `Get-ScpItem -LiteralPath` |
| `Get-WinSCPItemChecksum` | `Get-ScpItemCheckSum` |
| `Get-WinSCPSession` | `Get-ScpSession` |
| `Get-WinSCPHostKeyFingerprint` | `Get-HostFingerPrint` |
| `Invoke-WinSCPCommand` | `Invoke-ScpCommand` |
| `Move-WinSCPItem` | `Move-ScpItem` |
| `New-WinSCPItem` | `New-ScpItem` or `New-ScpDirectory` |
| `New-WinSCPItemPermission` | `New-ScpItemPermission` |
| `New-WinSCPSessionOption` | `New-ScpSessionOptions` |
| `New-WinSCPSession` | `New-ScpSession` |
| `New-WinSCPTransferOption` | `New-ScpTransferOptions` |
| `New-WinSCPTransferResumeSupport` | `New-ScpTransferResumeSupport` |
| `Receive-WinSCPItem` | `Receive-ScpItem` |
| `Remove-WinSCPItem` | `Remove-ScpItem` |
| `Remove-WinSCPSession` | `Remove-ScpSession` |
| `Rename-WinSCPItem` | `Rename-ScpItem` |
| `Send-WinSCPItem` | `Send-ScpItem` |
| `Start-WinSCPConsole` | `Start-WinScpConsole` |
| `Sync-WinSCPPath` | `Sync-ScpDirectory` |
| `Test-WinSCPPath` | `Test-ScpPath` |

## Additions that help with routine administration

| Addition | Why it is useful |
| --- | --- |
| Reusable connection options | Separate connection configuration from opening a session; reuse it for fingerprint scans and reconnects. |
| Named sessions | Retrieve a connection by name when working with several servers without changing global command defaults. |
| Rename and guarded replacement | Rename a file in its current directory. Move/copy can return metadata and replace an existing file only with `Force`. |
| File creation and content writes | Create empty marker files or publish generated configuration text without manually managing a local staging file. |
| Permissions and resume settings | Reuse Unix permissions and configure temporary uploads so consumers do not see a partly uploaded file. Protocol restrictions still apply. |
| Listing controls | Return directories only, files only or names; inspect a literal file through metadata mode. |
| Explicit transfer renaming | Upload a single file under a different name or download a literal file to a chosen local filename. |
| Synchronization comparison | Inspect actual proposed changes before choosing to synchronize. `WhatIf` alone describes the operation without comparing server contents. |
| Remote text reads | Read SFTP/FTP configuration or log files directly through the assembly's download stream. |
| Reusable close | Close a connection while keeping the session object available for an explicit `Open` call. |

## Protocols

The assembly uses the same transfer methods for SFTP, SCP, FTP/FTPS, WebDAV and S3. Creating a separate upload/download command for each protocol would duplicate the workflow. PowerScp instead adds connection settings and examples where they make setup easier.

For S3, those settings include the bucket/root, region, URL style, temporary session token, and WinSCP's environment/profile credential lookup. TLS is enabled by default for AWS and custom S3 endpoints. `Secure $false` is an explicit option for an endpoint that requires HTTP. Named parameters take precedence over matching `RawSettings` entries. AWS access keys can be supplied as a credential object; a session token uses a SecureString parameter, although WinSCP requires its value as a plaintext raw setting internally.

For FTP/FTPS, active/passive mode, explicit/implicit TLS, trusted certificate fingerprints and client certificates are exposed. FTP-specific settings are rejected on other protocols. The shared send/receive commands support masks, binary/ASCII mode, speed limits and deliberate source removal.

S3 capabilities here concern object transfer and file-style management. Bucket policies, IAM, lifecycle rules, versioning administration and AWS SSO workflows belong in AWS tooling. Unix permissions do not apply to S3 objects. WinSCP's stream methods support SFTP and FTP only, so `Get-ScpContent` has that restriction; file creation and `Set-ScpContent` use ordinary transfers and can work on the other protocols too.

## Deliberate differences

- Existing `Get-ScpItem` calls still list directory contents. Use `Get-ScpItemType` or `Get-ScpItem -LiteralPath` for metadata.
- Local upload paths are literal. Select several paths explicitly or use a transfer file mask for directory contents. Downloads accept remote masks; `LiteralPath` escapes a remote filename.
- Deletion paths are literal by default. Use `UseFileMask` explicitly for patterned cleanup.
- Move/copy refuses an existing destination without `Force`. Force can replace a file, but it will not recursively delete an existing directory. Replacement deletes the target before moving/copying, so it is not atomic.
- Session retrieval uses a module-owned registry. It does not change `$PSDefaultParameterValues`, and session disposal never kills unrelated WinSCP processes. Keep and pass explicit session objects in scripts.
- The wrapper keeps version checking enabled and uses its matched bundled executable. Custom executable arguments, disabling version checks and Framework-only process impersonation are not exposed as routine connection parameters.
- Module reimport resets the session registry. Keep your session reference and dispose it in `finally`, even when using a name.
- Assembly events, `Abort`, `TryGetFileInfo`, direct stream uploads, and specialized single-file methods remain available on the returned WinSCP object. Extra wrapper commands for those methods do not currently improve the documented workflows enough to justify more API surface. The comparison and content commands cover the useful additional workflows selected for this release.

## Validation

Offline tests exercise real option/permission/resume objects and simulated session operations. They cover S3 TLS defaults and raw settings, FTPS URL parsing, conflict validation, named sessions, overwrite guards, temporary-file cleanup, content-stream disposal, literal filenames and WhatIf behavior. Windows CI runs both test files in Windows PowerShell 5.1 and PowerShell 7. This workspace is on macOS; Windows CI and real-server tests remain unverified.

## Assembly references

- [Session methods and protocol support](https://winscp.net/eng/docs/library_session)
- [Connection properties](https://winscp.net/eng/docs/library_sessionoptions)
- [Raw settings](https://winscp.net/eng/docs/rawsettings)
- [S3 options](https://winscp.net/eng/docs/ui_login_s3)
- [S3 setting names in the pinned WinSCP source](https://github.com/winscp/winscp/blob/6.5.7/source/core/SessionData.cpp)
- [Synchronization comparison](https://winscp.net/eng/docs/library_session_comparedirectories)
- [Resume settings](https://winscp.net/eng/docs/library_transferresumesupport)
- [Download streaming and its protocol limits](https://winscp.net/eng/docs/library_session_getfile)
