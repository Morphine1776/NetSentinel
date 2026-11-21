#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Stops and removes the NetSentinel Windows Service.

.EXAMPLE
  .\scripts\Uninstall-Service.ps1
  .\scripts\Uninstall-Service.ps1 -RemoveFiles
#>
[CmdletBinding()]
param(
    [string]$InstallPath = "$env:ProgramFiles\NetSentinel",
    [switch]$RemoveFiles
)

$ErrorActionPreference = "Stop"
$existing = Get-Service -Name NetSentinel -ErrorAction SilentlyContinue
if ($existing) {
    if ($existing.Status -ne "Stopped") {
        Stop-Service NetSentinel -Force
    }
    sc.exe delete NetSentinel | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "Removed the NetSentinel service."
}
else {
    Write-Host "The NetSentinel service is not installed."
}

foreach ($name in @("NetSentinel-Dashboard", "NetSentinel-Traps")) {
    $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($rule) {
        Remove-NetFirewallRule -Name $name
        Write-Host "Removed firewall rule $name."
    }
}

if ($RemoveFiles -and (Test-Path $InstallPath)) {
    Remove-Item -Recurse -Force $InstallPath
    Write-Host "Removed $InstallPath."
}
elseif ($RemoveFiles) {
    Write-Host "No files found at $InstallPath."
}
else {
    Write-Host "Files were left at $InstallPath. Pass -RemoveFiles to delete them."
}
