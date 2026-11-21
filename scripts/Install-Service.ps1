#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Publishes NetSentinel and registers it as a Windows Service.

.DESCRIPTION
  Builds a Release publish of the dashboard, installs it under Program Files by
  default, registers the NetSentinel service, and opens the dashboard TCP port
  and the SNMP trap UDP port. Run from an elevated PowerShell session.

.EXAMPLE
  .\scripts\Install-Service.ps1
  .\scripts\Install-Service.ps1 -DashboardPort 8741 -TrapPort 162 -SelfContained
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "$env:ProgramFiles\NetSentinel",
    [int]$DashboardPort = 8741,
    [int]$TrapPort = 162,
    [switch]$SelfContained
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$project = Join-Path $root "src\NetSentinel.App\NetSentinel.App.csproj"
$stage = Join-Path $env:TEMP ("netsentinel-publish-" + [guid]::NewGuid().ToString("N"))

Write-Host "Publishing NetSentinel..."
$publishArgs = @("publish", $project, "-c", "Release", "-o", $stage)
if ($SelfContained) {
    $publishArgs += @("-r", "win-x64", "--self-contained", "true")
}
& dotnet @publishArgs
if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed." }

$settingsPath = Join-Path $stage "appsettings.json"
$settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
$settings.Urls = "http://0.0.0.0:$DashboardPort"
if (-not $settings.Snmp) {
    $settings | Add-Member -NotePropertyName Snmp -NotePropertyValue ([pscustomobject]@{})
}
$settings.Snmp.TrapPort = $TrapPort
$settings.Snmp.TrapEnabled = $true
$settings | ConvertTo-Json -Depth 8 | Set-Content $settingsPath -Encoding utf8

$existing = Get-Service -Name NetSentinel -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service NetSentinel -Force
    }
    sc.exe delete NetSentinel | Out-Null
    Start-Sleep -Seconds 2
}

if (Test-Path $InstallPath) {
    Remove-Item -Recurse -Force $InstallPath
}
New-Item -ItemType Directory -Path $InstallPath | Out-Null
Copy-Item -Path (Join-Path $stage "*") -Destination $InstallPath -Recurse -Force
Remove-Item -Recurse -Force $stage

$exe = Join-Path $InstallPath "NetSentinel.exe"
if (-not (Test-Path $exe)) { throw "Published executable was not found at $exe." }

New-Service -Name "NetSentinel" `
    -BinaryPathName "`"$exe`"" `
    -DisplayName "NetSentinel" `
    -StartupType Automatic `
    -Description "SNMP network monitoring and the NetSentinel dashboard." | Out-Null
sc.exe failure NetSentinel reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
Start-Service NetSentinel

function Set-FirewallRule {
    param([string]$Name, [string]$Display, [string]$Protocol, [int]$Port)
    $rule = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($rule) { Remove-NetFirewallRule -Name $Name }
    New-NetFirewallRule -Name $Name -DisplayName $Display -Direction Inbound -Action Allow -Protocol $Protocol -LocalPort $Port | Out-Null
}

Set-FirewallRule -Name "NetSentinel-Dashboard" -Display "NetSentinel dashboard" -Protocol TCP -Port $DashboardPort
Set-FirewallRule -Name "NetSentinel-Traps" -Display "NetSentinel SNMP traps" -Protocol UDP -Port $TrapPort

Write-Host ""
Write-Host "NetSentinel service is running."
Write-Host "Dashboard:  http://localhost:$DashboardPort"
Write-Host "Traps:      UDP $TrapPort"
Write-Host "Install:    $InstallPath"
Write-Host "Sign in with the Dashboard credentials in $InstallPath\appsettings.json"
Write-Host "The shipped default is admin / changeme. Change it before exposing the port."
