param(
    [string]$Root = "C:\Aries",
    [string]$ToolsRoot = "C:\Tools",
    [string]$Profile = "aries"
)

$ErrorActionPreference = "Stop"
$SourceRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

function Get-HermesProfileHome {
    param([string]$ProfileName)

    try {
        $show = (& hermes profile show $ProfileName 2>&1 | Out-String)
        $match = [regex]::Match($show, '(?mi)^\s*Path:\s*(.+?)\s*$')
        if ($match.Success) {
            $candidate = $match.Groups[1].Value.Trim()
            if ($candidate.StartsWith('~')) {
                $candidate = Join-Path $HOME $candidate.Substring(2)
            }
            if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
        }
    } catch {}

    if ($env:HERMES_HOME) {
        $candidate = Join-Path $env:HERMES_HOME "profiles\$ProfileName"
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    }
    if ($env:LOCALAPPDATA) {
        $candidate = Join-Path $env:LOCALAPPDATA "hermes\profiles\$ProfileName"
        if (Test-Path $candidate) { return (Resolve-Path $candidate).Path }
    }
    $legacy = Join-Path $HOME ".hermes\profiles\$ProfileName"
    if (Test-Path $legacy) { return (Resolve-Path $legacy).Path }
    throw "Could not resolve Hermes profile home for '$ProfileName'."
}

Write-Host "Aries v0.5.0 Windows developer preview in-place update" -ForegroundColor Green

if (-not (Test-Path $Root)) { throw "Aries workspace not found: $Root" }
if (-not (Get-Command hermes -ErrorAction SilentlyContinue)) { throw "hermes command not found" }
& hermes profile show $Profile *> $null
if ($LASTEXITCODE -ne 0) { throw "Hermes profile '$Profile' does not exist" }

# Never update framework files beneath a live investigation. The coordinator is
# a separate process group and would continue using a mixed old/new codebase.
$activeCases = @()
$casesPath = Join-Path $Root "cases"
if (Test-Path $casesPath) {
    Get-ChildItem -LiteralPath $casesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $statePath = Join-Path $_.FullName "web-state.json"
        if (Test-Path $statePath) {
            try {
                $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
                if ($state.status -eq "investigating" -and $state.investigation_pid) {
                    $live = Get-Process -Id ([int]$state.investigation_pid) -ErrorAction SilentlyContinue
                    if ($live) { $activeCases += "$($_.Name) (PID $($state.investigation_pid))" }
                }
            } catch {}
        }
    }
}
if ($activeCases.Count -gt 0) {
    throw "Stop the active Aries investigation(s) before updating: $($activeCases -join ', '). Use the web Stop button, then rerun Update-Aries.ps1."
}

# A previous web server can keep serving old Python modules even after files are
# replaced. Stop only a listener whose command line clearly belongs to this
# Aries workspace; never kill an unrelated service using the same port.
$listeners = @(Get-NetTCPConnection -LocalAddress 127.0.0.1 -LocalPort 8787 -State Listen -ErrorAction SilentlyContinue)
foreach ($pidValue in ($listeners | Select-Object -ExpandProperty OwningProcess -Unique)) {
    $processInfo = Get-CimInstance Win32_Process -Filter "ProcessId = $pidValue" -ErrorAction SilentlyContinue
    $commandLine = [string]$processInfo.CommandLine
    $belongsToAries = $commandLine -match [regex]::Escape($Root) -and $commandLine -match "(?i)uvicorn" -and $commandLine -match "app:app"
    if (-not $belongsToAries) {
        throw "Port 8787 is owned by a non-Aries process (PID $pidValue). Stop it manually before updating."
    }
    Write-Host "Stopping previous Aries web server (PID $pidValue) so the new version can load..." -ForegroundColor Yellow
    Stop-Process -Id $pidValue -Force
}

Write-Host "`n==> Updating Aries project files (preserving .venv, cases, and config)" -ForegroundColor Cyan
$preserve = @('.venv', 'cases', 'config')
Get-ChildItem -LiteralPath $SourceRoot -Force | ForEach-Object {
    if ($_.Name -notin $preserve) {
        Copy-Item -LiteralPath $_.FullName -Destination $Root -Recurse -Force
    }
}

Write-Host "`n==> Repairing Aries profile identity and skill" -ForegroundColor Cyan
$profileHome = Get-HermesProfileHome -ProfileName $Profile
Write-Host "Profile home: $profileHome"
Copy-Item -LiteralPath (Join-Path $Root "profile\SOUL.md") -Destination (Join-Path $profileHome "SOUL.md") -Force
$skillDest = Join-Path $profileHome "skills\aries-dfir"
New-Item -ItemType Directory -Force -Path $skillDest | Out-Null
Copy-Item -LiteralPath (Join-Path $Root "skills\aries-dfir\SKILL.md") -Destination (Join-Path $skillDest "SKILL.md") -Force

Write-Host "`n==> Reasserting Aries terminal settings" -ForegroundColor Cyan
& hermes -p $Profile config set terminal.backend local | Out-Host
& hermes -p $Profile config set terminal.cwd $Root | Out-Host
& hermes -p $Profile config set terminal.timeout 7200 | Out-Host
& hermes -p $Profile config set approvals.mode smart | Out-Host
& hermes -p $Profile config set skills.write_approval true | Out-Host
& hermes -p $Profile config set agent.api_max_retries 0 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Warning "This Hermes build did not accept agent.api_max_retries; configure it manually to avoid repeated billed-provider failures." }
& hermes -p $Profile config set agent.auto_recovery_cycles 0 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Warning "This Hermes build did not accept agent.auto_recovery_cycles; configure it manually to avoid recovery churn." }
& hermes -p $Profile config set agent.max_iterations 18 | Out-Host
if ($LASTEXITCODE -ne 0) { Write-Warning "This Hermes build did not accept agent.max_iterations; the report fallback still prevents an unfinished model response from blocking output." }

$python = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) { throw "Aries Python environment is missing: $python" }
$env:ARIES_ROOT = $Root
$env:Path = "$(Join-Path $Root '.venv\Scripts');$env:Path"

Write-Host "`n==> Installing Aries web-console dependencies" -ForegroundColor Cyan
& $python -m pip install -r (Join-Path $Root "requirements.txt")
if ($LASTEXITCODE -ne 0) { throw "Aries web dependency installation failed" }

$adhoc = Join-Path $Root "run_investigation.py"
if (Test-Path $adhoc) {
    Write-Warning "Found $adhoc from an earlier agent run. It is NOT part of Aries and will not be used. Review/delete it manually after the update."
}

Write-Host "`n==> Refreshing forensic tool inventory" -ForegroundColor Cyan
& $python (Join-Path $Root "scripts\tool_inventory.py") --tools-root $ToolsRoot
if ($LASTEXITCODE -ne 0) { throw "Tool inventory failed" }

Write-Host "`nARIES v0.5.0 WINDOWS DEVELOPER PREVIEW UPDATED" -ForegroundColor Green
Write-Host "Aries now owns routine case creation. Launch Start-Aries-Web.ps1 for the browser console or Start-Aries.ps1 for chat."
Write-Host "`nRunning health check..." -ForegroundColor Cyan
& (Join-Path $Root "Test-Aries.ps1") -Root $Root -Profile $Profile -ToolsRoot $ToolsRoot
exit $LASTEXITCODE
