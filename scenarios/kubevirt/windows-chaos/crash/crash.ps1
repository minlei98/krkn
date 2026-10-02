<#
.SYNOPSIS
    Triggers a Windows guest kernel bugcheck on a disposable chaos VM.

.DESCRIPTION
    Terminates a process the kernel treats as critical. Windows responds with
    bugcheck 0xEF CRITICAL_PROCESS_DIED: it writes the configured crash dump
    and, with AutoReboot enabled by prepare.ps1, restarts.

    This is a guest-kernel crash. The hypervisor, the node and the VMI are
    untouched, which is the whole point of the experiment: it exercises the
    Windows crash/dump/reboot path rather than a VM-level restart.

    This script never returns normally on success - the SSH session dies with
    the guest. krkn treats a dead session as the expected outcome and confirms
    the crash afterwards from the guest's own bugcheck event.

.PARAMETER ProcessName
    The critical process to terminate. services.exe is the default because it
    is critical but, unlike csrss.exe and wininit.exe, not a protected process
    (PPL), so an elevated administrator can terminate it. If a given Windows
    build refuses it, stage a signed crash driver (for example Sysinternals
    NotMyFault) in the image and point crash_command at that instead.

.NOTES
    Only run this on a VM labelled chaos.openshift.io/disposable=true.
#>
[CmdletBinding()]
param(
    [string] $ProcessName = 'services.exe'
)

$ErrorActionPreference = 'Stop'

$identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'crash.ps1 must run elevated; terminating a critical process needs SeDebugPrivilege.'
}

$crashControl = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
if ((Get-ItemProperty -Path $crashControl).CrashDumpEnabled -eq 0) {
    throw 'crash dumps are disabled; run prepare.ps1 first or the bugcheck will leave no evidence.'
}

$target = Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($ProcessName)) -ErrorAction SilentlyContinue
if (-not $target) {
    throw "critical process $ProcessName is not running."
}

Write-Output "Terminating critical process $ProcessName (pid $($target.Id)) to force a bugcheck..."
& taskkill.exe /f /im $ProcessName | Out-Null

# Reached only if the kernel did not bugcheck: report it so the run fails loudly
# instead of waiting out the recovery timeout on a guest that never crashed.
Start-Sleep -Seconds 10
throw "terminating $ProcessName did not bugcheck this Windows build; use a signed crash driver instead."
