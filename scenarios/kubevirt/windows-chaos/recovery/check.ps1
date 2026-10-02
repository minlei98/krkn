<#
.SYNOPSIS
    Application health check for the Windows chaos fixture VM.

.DESCRIPTION
    krkn runs this twice: once before the crash to establish a baseline, and
    once after the guest has rebooted. A non-zero exit fails the scenario, so
    keep it strict about what "healthy" means for the workload under test.

    The default checks are deliberately minimal - the services Windows needs to
    be usable at all. Add the workload's own checks (a port, an HTTP endpoint,
    a service name) for a test that says something about the application.

.PARAMETER ServiceName
    Services that must be running.

.PARAMETER TcpPort
    Optional local TCP port that must be listening.
#>
[CmdletBinding()]
param(
    [string[]] $ServiceName = @('EventLog', 'Winmgmt', 'LanmanServer', 'sshd'),
    [int] $TcpPort = 0
)

$ErrorActionPreference = 'Stop'
$failures = @()

foreach ($name in $ServiceName) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    if (-not $service) {
        $failures += "service $name not found"
    } elseif ($service.Status -ne 'Running') {
        $failures += "service $name is $($service.Status)"
    }
}

# Windows reports the boot as pending until the service control manager has
# finished; a guest that is still mid-boot is not healthy yet.
if ((Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime -gt (Get-Date)) {
    $failures += 'implausible boot time; the guest clock is not settled'
}

if ($TcpPort -gt 0) {
    $listening = Get-NetTCPConnection -State Listen -LocalPort $TcpPort -ErrorAction SilentlyContinue
    if (-not $listening) {
        $failures += "nothing is listening on port $TcpPort"
    }
}

if ($failures.Count -gt 0) {
    Write-Output ("unhealthy: " + ($failures -join '; '))
    exit 1
}

Write-Output 'healthy'
exit 0
