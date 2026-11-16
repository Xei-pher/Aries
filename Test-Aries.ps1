param(
    [string]$Root = "C:\Aries",
    [string]$Profile = "aries",
    [string]$ToolsRoot = "C:\Tools"
)

$ErrorActionPreference = "Continue"
$failed = 0

function Get-HermesProfileHome {
    param([string]$ProfileName)
    try {
        $show = (& hermes profile show $ProfileName 2>&1 | Out-String)
        $match = [regex]::Match($show, '(?mi)^\s*Path:\s*(.+?)\s*$')
        if ($match.Success) {
            $candidate = $match.Groups[1].Value.Trim()
            if ($candidate.StartsWith('~')) { $candidate = Join-Path $HOME $candidate.Substring(2) }
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

function Check-Item {
    param([string]$Name, [scriptblock]$Test)
    Write-Host -NoNewline ("{0,-38}" -f $Name)
    try {
        $ok = & $Test
        if ($ok) { Write-Host "PASS" -ForegroundColor Green }
        else { Write-Host "FAIL" -ForegroundColor Red; $script:failed++ }
    } catch {
        Write-Host "FAIL" -ForegroundColor Red
        Write-Host "  $($_.Exception.Message)" -ForegroundColor DarkRed
        $script:failed++
    }
}

Write-Host "Aries v0.5.0 Windows developer preview health check" -ForegroundColor Cyan
Write-Host "Root: $Root`n"

Check-Item "Hermes command" { [bool](Get-Command hermes -ErrorAction SilentlyContinue) }
Check-Item "Aries workspace" { Test-Path $Root }
Check-Item "C:\Tools" { Test-Path $ToolsRoot }
Check-Item "Aries Hermes profile" { & hermes profile show $Profile *> $null; $LASTEXITCODE -eq 0 }

$python = Join-Path $Root ".venv\Scripts\python.exe"
$vol = Join-Path $Root ".venv\Scripts\vol.exe"
$tq = Join-Path $Root ".venv\Scripts\target-query.exe"

Check-Item "Aries Python venv" { Test-Path $python }
Check-Item "Volatility 3 CLI" { if (-not (Test-Path $vol)) { return $false }; & $vol -h *> $null; $LASTEXITCODE -eq 0 }
Check-Item "Dissect target-query" { if (-not (Test-Path $tq)) { return $false }; & $tq -h *> $null; $LASTEXITCODE -eq 0 }
Check-Item "Aries DFIR skill" { $profileHome = Get-HermesProfileHome $Profile; Test-Path (Join-Path $profileHome "skills\aries-dfir\SKILL.md") }
Check-Item "Aries AGENTS.md" { Test-Path (Join-Path $Root "AGENTS.md") }
Check-Item "Review bundle exporter" { Test-Path (Join-Path $Root "Export-Aries-Review.ps1") }
Check-Item "Web console launcher" { Test-Path (Join-Path $Root "Start-Aries-Web.ps1") }
Check-Item "Web console application" { Test-Path (Join-Path $Root "web\app.py") }
Check-Item "Claude model setup guide" { Test-Path (Join-Path $Root "MODEL-SETUP-CLAUDE.md") }
Check-Item "OpenAI model setup guide" { Test-Path (Join-Path $Root "MODEL-SETUP-OPENAI.md") }
Check-Item "Resumable coordinator" { Test-Path (Join-Path $Root "scripts\investigate.py") }
Check-Item "Preflight module" { Test-Path (Join-Path $Root "scripts\preflight.py") }
Check-Item "Artifact discovery module" { Test-Path (Join-Path $Root "scripts\artifact_discovery.py") }
Check-Item "Event-log baseline" { Test-Path (Join-Path $Root "scripts\run_ez_baseline.py") }
Check-Item "Event triage module" { Test-Path (Join-Path $Root "scripts\event_triage.py") }
Check-Item "Loose-artifact baseline" { Test-Path (Join-Path $Root "scripts\run_artifact_baseline.py") }
Check-Item "Static/archive analyzer" { Test-Path (Join-Path $Root "scripts\static_artifact.py") }
Check-Item "Loose-artifact triage" { Test-Path (Join-Path $Root "scripts\artifact_triage.py") }
Check-Item "Lead/pivot engine" { Test-Path (Join-Path $Root "scripts\pivot.py") }
Check-Item "Targeted timeline module" { Test-Path (Join-Path $Root "scripts\targeted_timeline.py") }
Check-Item "Optional second-opinion module" {
    $scriptPath = Join-Path $Root "scripts\orchestration.py"
    if (-not (Test-Path $python) -or -not (Test-Path $scriptPath)) { return $false }
    & $python $scriptPath --help *> $null
    $LASTEXITCODE -eq 0
}
Check-Item "Evidence assessment module" { Test-Path (Join-Path $Root "scripts\evidence_assessment.py") }
Check-Item "Case forensic data lake" { Test-Path (Join-Path $Root "scripts\case_datalake.py") }
Check-Item "Deterministic web workflow" { Test-Path (Join-Path $Root "scripts\web_workflow.py") }
Check-Item "Lead/context records module" { Test-Path (Join-Path $Root "scripts\records.py") }
Check-Item "Aries Python syntax" { if (-not (Test-Path $python)) { return $false }; & $python -m compileall -q (Join-Path $Root "scripts") *> $null; $LASTEXITCODE -eq 0 }
Check-Item "FastAPI web runtime" { if (-not (Test-Path $python)) { return $false }; & $python -c "import fastapi, uvicorn" *> $null; $LASTEXITCODE -eq 0 }

if (Test-Path $python) {
    Write-Host "`nRefreshing tool inventory..." -ForegroundColor Cyan
    $env:ARIES_ROOT = $Root
    $env:Path = "$(Join-Path $Root '.venv\Scripts');$env:Path"
    & $python (Join-Path $Root "scripts\tool_inventory.py") --tools-root $ToolsRoot *> $null
    $inventoryPath = Join-Path $Root "config\tools.json"
    if (Test-Path $inventoryPath) {
        $inventory = Get-Content $inventoryPath -Raw | ConvertFrom-Json
        $found = @($inventory.eztools.PSObject.Properties | Where-Object { $_.Value.found } | ForEach-Object { $_.Name })
        Write-Host "EZ Tools discovered: $($found.Count)" -ForegroundColor Cyan
        if ($found.Count -gt 0) { Write-Host ("  " + ($found -join ", ")) }
    }
}

$archiveTool = Get-Command 7z.exe -ErrorAction SilentlyContinue
if (-not $archiveTool) { $archiveTool = Get-Command 7zz.exe -ErrorAction SilentlyContinue }
if (-not $archiveTool) {
    foreach ($candidate in @("$env:ProgramFiles\7-Zip\7z.exe", "${env:ProgramFiles(x86)}\7-Zip\7z.exe")) {
        if ($candidate -and (Test-Path $candidate)) { $archiveTool = Get-Item $candidate; break }
    }
}
if ($archiveTool) {
    $archiveToolPath = if ($archiveTool.Path) { $archiveTool.Path } elseif ($archiveTool.FullName) { $archiveTool.FullName } else { [string]$archiveTool.Source }
    Write-Host "RAR/7z static extraction backend: $archiveToolPath" -ForegroundColor Cyan
} else {
    Write-Warning "7-Zip was not found. ZIP/TAR static analysis works, but RAR/7z evidence requires 7-Zip (7z.exe). Install it with: winget install --id 7zip.7zip -e"
}

Write-Host ""
if ($failed -eq 0) {
    Write-Host "ARIES v0.5.0 WINDOWS DEVELOPER PREVIEW HEALTH CHECK PASSED" -ForegroundColor Green
    exit 0
}
Write-Host "ARIES v0.5.0 WINDOWS DEVELOPER PREVIEW HEALTH CHECK FAILED: $failed check(s)" -ForegroundColor Red
exit 1
