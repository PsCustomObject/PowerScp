# Security Policy

## Reporting a vulnerability

Please do not open a public issue for security-sensitive problems.

Instead, use the project’s private reporting path and provide the following information:

- a clear description of the issue
- the affected command, script, or workflow
- expected and actual behavior
- operating system and PowerShell version
- steps to reproduce
- any relevant redacted sample input or output

If a report includes credentials, secrets, SSH keys, or other sensitive operational data, redact that information before sharing it.

## Supported versions

This project is currently in active development, and support expectations should be reviewed before broad production adoption. Security fixes are prioritized based on impact and maintenance needs.

## Security expectations

- Keep credentials and secrets out of examples and issue reports.
- Verify remote host fingerprints before trusting connections.
- Treat transport, TLS, and SSH configuration as security-sensitive decisions.
- Prefer explicit, reviewable transfer logic over hidden defaults.

## Disclosure guidance

Please allow a reasonable time for a fix to be evaluated and prepared before public disclosure.
