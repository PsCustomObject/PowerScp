# Contributing to PowerScp

Thanks for your interest in improving PowerScp.

This project is a PowerShell module built around practical file-transfer automation. Contributions should keep the project focused on secure, readable, and reliable remote file operations without unnecessary scope expansion.

## Project scope

Please keep changes aligned with the module’s purpose:

- PowerShell 5.1 and PowerShell 7 compatibility where appropriate
- WinSCP-backed transfer operations for common remote file workflows
- secure session handling and explicit connection validation
- clear, maintainable scripting behavior that helps automation teams work faster and more safely

Avoid unrelated feature drift or large rewrites that move the project away from its core transfer-focused purpose.

## Repository structure

- `PowerScp.psd1` and `PowerScp.psm1` contain the module manifest and exported functionality.
- `docs/` contains design notes, reviews and testing guidance.
- `bin/` contains bundled WinSCP assets.
- `tests/` contains the project test suite.
- `scripts/` contains repository support scripts.
- `Staging/` contains staged or transitional work.

## Development setup

Requirements:

- PowerShell 5.1 or PowerShell 7
- WinSCP assembly dependencies bundled with the repo
- Pester 5.7.1 or later for test execution

Typical workflow:

```powershell
Import-Module Pester -RequiredVersion 5.7.1
Import-Module ./PowerScp.psd1 -Force -ErrorAction Stop
Invoke-Pester ./tests
```

## Contribution workflow

1. Create a focused branch for the work.
2. Keep changes scoped to one improvement or fix.
3. Preserve existing behavior unless the change intentionally updates documented semantics.
4. Validate the relevant tests and import behavior.
5. Update documentation when usage or compatibility changes.

## Coding expectations

- Prefer explicit, readable PowerShell over clever shortcuts.
- Keep session, connection and transfer behavior easy to reason about.
- Preserve secure defaults and validation-first patterns.
- Avoid silently swallowing operational failures.
- Add comments only when they clarify intent or non-obvious logic.
- Keep public cmdlet behavior predictable and consistent with the rest of the module.

## Testing

Run the project tests before submitting changes:

```powershell
Invoke-Pester ./tests
```

If a change affects transfer logic, session handling, protocol behavior, path validation or security-sensitive workflows, add or update tests wherever practical.

## Pull requests

Keep pull requests focused and specific.

Please include:

- a short summary of the change
- the reason it was needed
- any compatibility or migration impact
- validation performed

## Reporting bugs

When filing an issue, include:

- the command or script that failed
- expected behavior
- actual behavior
- operating system and PowerShell version
- repository commit or branch
- redacted sample input and output if relevant

## Security and sensitive issues

For security-sensitive issues, do not open a public issue. See [SECURITY.md](./SECURITY.md) for the appropriate reporting path.

## Documentation

If a change affects usage, protocol behavior, compatibility, or security assumptions, update the relevant documentation in the repo.

## License

By contributing, you agree that your contributions will be licensed under the project’s MIT license.
