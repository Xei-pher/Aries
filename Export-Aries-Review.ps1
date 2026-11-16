param(
    [Parameter(Mandatory=$true)][string]$Case,
    [string]$Root = "C:\Aries",
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
$caseDir = Join-Path $Root "cases\$Case"
if (-not (Test-Path $caseDir)) { throw "Case not found: $caseDir" }

if (-not $OutputPath) {
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $OutputPath = Join-Path $Root "Aries-$Case-review-$stamp.zip"
}

$temp = Join-Path ([System.IO.Path]::GetTempPath()) ("aries-review-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $temp | Out-Null

try {
    $relativeFiles = @(
        "case.json",
        "evidence_manifest.json",
        "artifact_inventory.json",
        "case_context.json",
        "investigation-brief.json",
        "leads.jsonl",
        "findings.jsonl",
        "iocs.csv",
        "ioc_candidates.csv",
        "notes.md",
        "output\investigation-state.json",
        "output\event_triage.json",
        "output\artifact_triage.json",
        "output\evidence-assessment.json",
        "output\datalake\manifest.json",
        "output\web\assistant-history.jsonl",
        "output\ioc-scan-manifest.json",
        "output\preflight\preflight.json",
        "output\pivots\pivot-summary.json",
        "output\eztools\EvtxECmd-Auto\baseline-manifest.json",
        "output\artifacts\artifact-baseline-manifest.json",
        "output\dissect\run-quick-manifest.json",
        "output\dissect\run-full-manifest.json",
        "output\dissect\run-timeline-manifest.json",
        "output\volatility\run-quick-manifest.json",
        "output\volatility\run-full-manifest.json",
        "timeline\targeted_timeline.csv",
        "timeline\targeted_timeline.md",
        "report\report.md"
    )

    foreach ($rel in $relativeFiles) {
        $src = Join-Path $caseDir $rel
        if (Test-Path $src) {
            $dest = Join-Path $temp $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            Copy-Item -LiteralPath $src -Destination $dest -Force
        }
    }

    # Include each lead's small pivot plan, but not hits.jsonl (which can be large).
    $pivotRoot = Join-Path $caseDir "output\pivots"
    if (Test-Path $pivotRoot) {
        Get-ChildItem -Path $pivotRoot -Directory -Filter "L-*" | ForEach-Object {
            $plan = Join-Path $_.FullName "pivot-plan.json"
            if (Test-Path $plan) {
                $rel = "output\pivots\$($_.Name)\pivot-plan.json"
                $dest = Join-Path $temp $rel
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
                Copy-Item -LiteralPath $plan -Destination $dest -Force
            }
        }
    }

    # Include bounded orchestration snapshots/tasks/reviews/decisions. These are
    # reasoning records only; source evidence and extracted files remain excluded.
    $orchestrationRoot = Join-Path $caseDir "output\orchestration"
    if (Test-Path $orchestrationRoot) {
        Get-ChildItem -Path $orchestrationRoot -Recurse -File | Where-Object { $_.Length -le 25MB } | ForEach-Object {
            $suffix = $_.FullName.Substring($orchestrationRoot.Length).TrimStart('\')
            $rel = Join-Path "output\orchestration" $suffix
            $dest = Join-Path $temp $rel
            New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
            Copy-Item -LiteralPath $_.FullName -Destination $dest -Force
        }
    }

    $metadata = @{
        case = $Case
        exported_utc = (Get-Date).ToUniversalTime().ToString("o")
        source_case = $caseDir
        note = "Review bundle includes the analyst brief, assistant history, data-lake manifest, and bounded legacy review records, but excludes source evidence, extracted binaries, the data-lake database, full parser outputs, and whole-disk timelines."
    } | ConvertTo-Json -Depth 5
    Set-Content -Path (Join-Path $temp "review-bundle.json") -Value $metadata -Encoding UTF8

    if (Test-Path $OutputPath) { Remove-Item -LiteralPath $OutputPath -Force }
    Compress-Archive -Path (Join-Path $temp "*") -DestinationPath $OutputPath -Force
    Write-Host "Aries review bundle created:" -ForegroundColor Green
    Write-Host $OutputPath
    Write-Host "This ZIP contains case metadata/manifests/report only — not source evidence or extracted binaries." -ForegroundColor DarkGray
} finally {
    if (Test-Path $temp) { Remove-Item -LiteralPath $temp -Recurse -Force -ErrorAction SilentlyContinue }
}
