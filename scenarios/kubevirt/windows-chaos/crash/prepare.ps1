<#
.SYNOPSIS
    Prepares a disposable Windows VM to be used as a krkn guest-crash target.

.DESCRIPTION
    Run once, elevated, inside the fixture VM (or from sysprep) before the
    `windows_guest_crash` scenario is used against it. It:

      * enables OpenSSH Server so `virtctl ssh` can reach the guest
      * gives SSH admin sessions a full (elevated) token, which terminating a
        critical process requires
      * configures a kernel crash dump with automatic reboot and overwrite
      * verifies that C:\chaos holds the scenario scripts

    This script does not crash anything.

.NOTES
    Only run this on a VM labelled chaos.openshift.io/disposable=true.
#>
[CmdletBinding()]
param(
    [string] $ChaosDir = 'C:\chaos',
    [string] $DumpFile = '%SystemRoot%\MEMORY.DMP'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'prepare.ps1 must run elevated.'
}

Write-Output 'Enabling OpenSSH Server...'
$capability = Get-WindowsCapability -Online -Name 'OpenSSH.Server*'
if ($capability.State -ne 'Installed') {
    Add-WindowsCapability -Online -Name $capability.Name | Out-Null
}
Set-Service -Name sshd -StartupType Automatic
Start-Service -Name sshd

# virtctl ssh runs a single command per connection; PowerShell as the default
# shell keeps the in-guest command lines identical to what you would type.
New-ItemProperty -Path 'HKLM:\SOFTWARE\OpenSSH' -Name DefaultShell `
    -Value "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -PropertyType String -Force | Out-Null

# Without this, a local administrator connecting over the network gets a
# filtered token and `taskkill /f` on a critical process fails with access
# denied, which would look like "the crash did not take effect".
New-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' `
    -Name LocalAccountTokenFilterPolicy -Value 1 -PropertyType DWord -Force | Out-Null

Write-Output 'Configuring kernel crash dump...'
$crashControl = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
# 2 = kernel memory dump: enough to identify the faulting component, far
# smaller than a complete dump, and it fits the fixture disk.
Set-ItemProperty -Path $crashControl -Name CrashDumpEnabled -Value 2 -Type DWord
Set-ItemProperty -Path $crashControl -Name DumpFile -Value $DumpFile -Type ExpandString
Set-ItemProperty -Path $crashControl -Name Overwrite -Value 1 -Type DWord
# The scenario measures guest recovery, so the guest has to come back on its own.
Set-ItemProperty -Path $crashControl -Name AutoReboot -Value 1 -Type DWord
Set-ItemProperty -Path $crashControl -Name LogEvent -Value 1 -Type DWord

# A kernel dump is written through the paging file on the boot volume; a
# system-managed page file keeps it large enough as the VM's memory changes.
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
if (-not $computer.AutomaticManagedPagefile) {
    Set-CimInstance -InputObject $computer -Property @{ AutomaticManagedPagefile = $true }
    Write-Output 'Enabled the system-managed page file (reboot required).'
}

foreach ($script in @('crash.ps1', 'collect-dump.ps1', 'check.ps1')) {
    $path = Join-Path $ChaosDir $script
    if (-not (Test-Path $path)) {
        throw "missing $path - copy crash/ and recovery/ into $ChaosDir first."
    }
}

Write-Output "Prepared. Reboot once, then confirm 'virtctl ssh' reaches this guest."
