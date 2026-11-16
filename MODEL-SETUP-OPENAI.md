# Aries v0.3.4 — One-Model OpenAI Setup

Aries v0.3.4 uses one primary model for the complete investigation. Delegated reviewers are disabled in the default workflow.

## 1. Update Aries

Extract the v0.5.0 ZIP, open PowerShell in the extracted folder, and run:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\Update-Aries.ps1
```

The updater preserves `C:\Aries\.venv`, `C:\Aries\cases`, `C:\Aries\config`, and `C:\Tools`.

## 2. Select the model

```powershell
hermes -p aries model
```

Choose OpenAI, authenticate through the option supported by your Hermes build, and select the model you want. A capable mid-tier reasoning model is usually the best cost/quality tradeoff; the workflow no longer doubles cost with reviewer calls.

Verify the active model:

```powershell
hermes -p aries config get model
```

You can also click the model card in the Aries web console. It should show the same model and `Single-model workflow`.

## 3. Start the console

```powershell
C:\Aries\Start-Aries-Web.ps1
```

Verify `http://127.0.0.1:8787/api/health` reports version `0.5.0-dev`.

## 4. Resume an existing case

Open the case and click **Run investigation**. Completed parsers, hashes, pivots, and timelines are reused. Any old waiting independent-review phase is marked skipped, and Aries continues with evidence assessment and reporting.

The final gate still checks exact evidence references, corroboration, context, temporal linkage, overclaims, and unresolved high-priority leads.
