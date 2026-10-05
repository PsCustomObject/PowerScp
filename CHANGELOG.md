# PowerScp change history

## 1.2.1 - 2026-10-05

- Treat rename destinations as exact names and reject existing directories.
- Preserve forced replacement targets in sibling backups; restore on failure when safe, otherwise report recovery paths.
- Reject directory-over-file replacement and directory sources for download renaming.
- Validate renamed downloads against Windows filename rules.
- Require Binary mode for content writes to preserve exact bytes.
- Dispose tracked sessions when the module is removed or force-reimported.
- Expand command help, regression tests, static analysis and opt-in live SFTP coverage.

## 1.2.0 - 2026-10-05

- Compare practical features against the WinSCP 6.3.6.0 Gallery package and document command mappings and deliberate differences.
- Expose reusable session options, URL parsing, modern SSH host-key policies, secure key passphrases, client certificates and XML/raw session logging options.
- Fix S3 TLS defaults and add bucket, region, temporary token, URL style and environment/profile credential parameters.
- Add session retrieval/close, remote rename/file creation, permission and resume factories, synchronization comparison, and text content read/write commands.
- Extend listing controls, literal metadata lookup, explicit upload/download filenames, move/copy Force and PassThru, command arrays and opt-in deletion masks.
- Guard remote replacements, clean temporary files after failures and dispose downloaded content streams.
- Expand offline regression tests and run the full tests directory in Windows CI.

## 1.1.0 - 2026-10-05

- Support Windows PowerShell 5.1 and PowerShell 7 with matched WinSCP 6.5.7 assemblies.
- Repair upload execution, source-removal behavior, fingerprint scans, checksums, pipeline binding, connection options, recursion and result/error handling.
- Complete abandoned upload implementation; add downloads, transfer-option creation, remote move/copy, command execution and synchronization.
- Apply ShouldProcess to mutations, escape literal paths and make removal opt-in.
- Add regression tests, Windows CI, migration documentation and code review findings.

## Version 0.2.1a (Development build) - 03.08.2020

- Added *-TransferFilesOnly* parameter to *Send-ScpItem* cmdlet
- *Send-ScpItem* will now create remote destination directory if it does not exist
- Cleaned up development comments and staging tree

## Version 0.2.0a (Development build) - 31.07.2020

- Added *Get-ScpItemType* cmdlet
- Added *Test-ScpPath* cmdlet
- Added Send-ScpItemcmdlet
- Added *New-ScpDirectory* cmdlet

## Version 0.1.0a (Development build) - 29.07.2020

- Reorganized module functions into a single file
- Created staging folder for all cmdlets/snippets not yet part of the main module files
