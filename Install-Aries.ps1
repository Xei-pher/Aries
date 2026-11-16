param(
    [string]$Root = "C:\Aries",
    [string]$ToolsRoot = "C:\Tools",
    [string]$Profile = "aries"
)

$ErrorActionPreference = "Stop"
$installer = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "install-aries.ps1"
& $installer -Root $Root -ToolsRoot $ToolsRoot -Profile $Profile
exit $LASTEXITCODE
