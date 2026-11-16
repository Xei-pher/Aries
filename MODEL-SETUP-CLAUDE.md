# Aries v0.3.4 — One-Model Claude Setup

Aries v0.3.4 uses one primary model for the complete investigation. Delegated reviewers are disabled in the default workflow.

## 1. Update Aries

Extract the v0.5.0 ZIP, open PowerShell in the extracted folder, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Update-Aries.ps1
```

The updater preserves `C:\Aries\.venv`, `C:\Aries\cases`, `C:\Aries\config`, and `C:\Tools`.

## 2. Select Claude

```powershell
hermes -p aries model
```

Choose Anthropic and select a current Claude Sonnet model for a strong cost/quality balance. A direct Anthropic API key is usually the most predictable option for long investigations; use another Hermes-supported authentication method if preferred.

Verify the active model:

```powershell
hermes -p aries config get model
```

The Aries web model card should show the same model and `Single-model workflow`.

## 3. Start the console

```powershell
C:\Aries\Start-Aries-Web.ps1
```

Verify `http://127.0.0.1:8787/api/health` reports version `0.5.0-dev`.

## 4. Resume an existing case

Open the case and click **Run investigation**. Completed parsers, hashes, pivots, and timelines are reused. Any old waiting independent-review phase is marked skipped, and Aries continues with evidence assessment and reporting.

The final gate still checks exact evidence references, corroboration, context, temporal linkage, overclaims, and unresolved high-priority leads.
