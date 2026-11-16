# Contributing

Aries is a Windows-first developer preview. Contributions should preserve evidence immutability, case isolation, exact evidence references, deterministic parser behavior, and guaranteed partial-report generation.

1. Fork the repository and create a focused branch.
2. Never commit real evidence, case folders, secrets, model usage files, or recovered content.
3. Add or update tests for every behavior change.
4. Run `python -m pytest -q` from the repository root.
5. On Windows, also run `Set-ExecutionPolicy -Scope Process Bypass; .\Test-Aries.ps1` in an installed test workspace.
6. Explain evidence-safety, compatibility, and migration effects in the pull request.

Use synthetic fixtures. A lead is not a finding, a suspicious artifact is not automatically malicious, and absence claims must account for parser coverage.
