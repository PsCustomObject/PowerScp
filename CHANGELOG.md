# PowerScp change history

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
