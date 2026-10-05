# Code review and modernization

## Findings fixed

| Severity | Original defect | Resolution |
| --- | --- | --- |
| Critical | Upload overwrite mode was passed as the `PutFiles` source-removal boolean, risking local deletion | Removal is a separate, explicit switch; overwrite behavior lives in transfer options |
| High | Uploads did nothing without `TransferFilesOnly`; single-file branch used an undefined variable | Unified normal and flattened upload paths |
| High | `SupportsShouldProcess` on uploads did not call `ShouldProcess`, including directory creation | Mutation wrappers gate operations before writing |
| High | Fingerprint scan used undefined password/port variables and omitted protocol; its credential set had no credential parameter | Shared connection-option builder and complete scan parameters |
| High | Checksum used an undefined path instead of ItemName | Normalize and hash the supplied path |
| High | Transfer/deletion failures could be ignored; error handlers referenced the global error list | Check result objects and propagate errors |
| High | Bundled old Framework assembly and legacy CLR requirements prevented proper PowerShell Core support | Matched WinSCP 6.5.7 executable, Framework and Standard assemblies; edition-aware loader |
| Medium | Pipeline sessions were validated in begin before pipeline binding | Validation occurs in process |
| Medium | Protocol, FTP mode/security, timeout/reconnect/debug and WebDAV options were ignored or misapplied | Apply options directly; protocol default ports; WebDAV validation |
| Medium | Host key arrays, explicit false security switches and private-key passphrases behaved incorrectly | Join fingerprints, honor boolean values and allow unencrypted keys |
| Medium | FilesOnly discarded recursion, Depth was ignored, Test-ScpPath was defined twice | Single definitions and working enumeration options/depth filtering |
| Medium | TransferMode was ignored, only one option might apply, permissions dereferenced a null object | Reusable option factory applying all settings, validating octal permissions |
| Medium | Removal interpreted literal names as wildcard masks | Escape literal paths before removal |
| Low | Wildcard exports exposed helper functions and module variables | Explicit public export list |

## Completed feature scope

The abandoned staging upload prototype is implemented in the main module. Added reusable transfer options, downloads, remote move/rename and copy, remote command execution, and directory synchronization. Existing listing, checksum, directory creation, session creation/disposal and fingerprint scanning are repaired. All original public command names are retained.

## Validation limits

Local validation uses PowerShell 7.6.6 on macOS with Pester 5.7.1 and real WinSCP assemblies. Session method tests use simulated sessions because WinSCP requires Windows and its Session class is sealed. Windows 5.1/7 CI is provided but has not been executed in this workspace. No remote credentials or server were provided, so live SFTP, SCP, FTP/FTPS, WebDAV and S3 tests remain required before declaring production compatibility. Recursive Depth limits output, not server traversal. Copy and shell execution depend on server capabilities.

## Upstream references

- [PowerShell support lifecycle](https://learn.microsoft.com/powershell/scripting/install/powershell-support-lifecycle)
- [WinSCP runtime installation and PowerShell Core builds](https://winscp.net/eng/docs/library_install)
- [WinSCP stable downloads](https://winscp.net/eng/downloads.php)
- [WinSCP PutFiles contract](https://winscp.net/eng/docs/library_session_putfiles)
- [WinSCP synchronization contract](https://winscp.net/eng/docs/library_session_synchronizedirectories)
