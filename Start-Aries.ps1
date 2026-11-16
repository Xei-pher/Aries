param(
    [string]$Root = "C:\Aries"
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path $Root)) {
    throw "Aries workspace not found: $Root. Run install-aries.ps1 first."
}

$env:ARIES_ROOT = $Root
$venvScripts = Join-Path $Root ".venv\Scripts"
if (Test-Path $venvScripts) {
    $env:Path = "$venvScripts;$env:Path"
}

Set-Location $Root
Write-Host "Starting Aries from $Root" -ForegroundColor Cyan
Write-Host "Profile: aries | v0.3.4 single-model investigation | deterministic evidence gate | Evidence remains read-only" -ForegroundColor DarkGray
& hermes -p aries chat
