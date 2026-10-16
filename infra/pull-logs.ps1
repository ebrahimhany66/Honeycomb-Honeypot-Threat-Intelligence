# Pull the Cowrie log from the honeypot VM into data\raw\ (never committed).
# Usage:
#   powershell -ExecutionPolicy Bypass -File infra\pull-logs.ps1 -VmIp <IP> -AdminPort <PORT> -AdminUser <USER>
param(
    [Parameter(Mandatory = $true)][string]$VmIp,
    [Parameter(Mandatory = $true)][int]$AdminPort,
    [Parameter(Mandatory = $true)][string]$AdminUser
)

$ErrorActionPreference = "Stop"

$outDir = Join-Path $PSScriptRoot "..\data\raw"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $outDir "cowrie-$stamp.json"
$remoteCmd = "docker exec honeycomb-cowrie cat /cowrie/cowrie-git/var/log/cowrie/cowrie.json"

$data = ssh -p $AdminPort "$AdminUser@$VmIp" $remoteCmd
if ($LASTEXITCODE -ne 0) {
    throw "SSH or docker command failed (exit code $LASTEXITCODE). Nothing was saved."
}
if (-not $data) {
    Write-Host "Connected, but there are no events yet. Nothing saved."
    exit 0
}

$data | Set-Content -Path $out -Encoding UTF8
Write-Host "Saved $out"