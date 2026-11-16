param(
    [string]$Root = "C:\Aries",
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
$python = Join-Path $Root ".venv\Scripts\python.exe"
$app = Join-Path $Root "web\app.py"
$expectedVersion = "0.5.0-dev"

if (-not (Test-Path $python)) { throw "Aries Python environment not found: $python" }
if (-not (Test-Path $app)) { throw "Aries web application not found: $app" }

$listeners = @(Get-NetTCPConnection -LocalAddress $HostAddress -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
if ($listeners.Count -gt 0) {
    $existingVersion = "unknown"
    try {
        $health = Invoke-RestMethod -Uri "http://${HostAddress}:$Port/api/health" -TimeoutSec 3
        if ($health.version) { $existingVersion = [string]$health.version }
    } catch {}
    throw "Port $Port is already serving Aries version $existingVersion. Stop the existing server first; expected $expectedVersion."
}

$env:ARIES_ROOT = $Root
$env:PYTHONPATH = "$(Join-Path $Root 'web');$(Join-Path $Root 'scripts')"

Write-Host "Starting Aries Forensics Console $expectedVersion" -ForegroundColor Cyan
Write-Host "Local URL: http://${HostAddress}:$Port"
Write-Host "Evidence stays on this machine. Press Ctrl+C to stop."

Start-Process "http://${HostAddress}:$Port"
& $python -m uvicorn app:app --app-dir (Join-Path $Root "web") --host $HostAddress --port $Port

