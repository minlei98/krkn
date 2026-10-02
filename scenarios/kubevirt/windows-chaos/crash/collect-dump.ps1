<#
.SYNOPSIS
    Collects Windows bugcheck evidence after a guest crash and prints it as JSON.

.DESCRIPTION
    Run by krkn once the guest is reachable again, before any cleanup. It
    reports the newest bugcheck recorded by the guest, when the guest last
    booted, and where the dump is. krkn uses the bugcheck timestamp to prove
    that this run caused the reboot rather than something else.

    With -IncludeDump the dump is compressed into -StageDir so that krkn can
    pull it out with `virtctl scp`; the staged copy is what cleanup removes.

    stdout is a single compact JSON object - do not add other output.

.PARAMETER StageDir
    Directory inside the guest where the compressed dump is staged.

.PARAMETER IncludeDump
    Stage the dump file itself, not just its metadata.
#>
[CmdletBinding()]
param(
    [string] $StageDir = 'C:\chaos\artifacts',
    [switch] $IncludeDump
)

$ErrorActionPreference = 'Stop'

function ConvertTo-Utc8601 {
    param([datetime] $Value)
    if ($null -eq $Value) { return $null }
    return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss') + 'Z'
}

$evidence = [ordered]@{
    bugCheckCode      = $null
    bugCheckTimeUtc   = $null
    bugCheckMessage   = $null
    lastBootUpTimeUtc = $null
    dumpPath          = $null
    dumpSizeBytes     = $null
    dumpWrittenUtc    = $null
    stagedPath        = $null
    collectedAtUtc    = ConvertTo-Utc8601 (Get-Date)
}

$os = Get-CimInstance -ClassName Win32_OperatingSystem
$evidence.lastBootUpTimeUtc = ConvertTo-Utc8601 $os.LastBootUpTime

# Event 1001 from WER-SystemErrorReporting is the record Windows writes on the
# boot that follows a bugcheck; it carries the bugcheck code and the dump path.
$bugCheck = Get-WinEvent -FilterHashtable @{
    LogName      = 'System'
    ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'
    Id           = 1001
} -MaxEvents 1 -ErrorAction SilentlyContinue

if ($bugCheck) {
    $evidence.bugCheckTimeUtc = ConvertTo-Utc8601 $bugCheck.TimeCreated
    $evidence.bugCheckMessage = ($bugCheck.Message -replace '\s+', ' ').Trim()
    $match = [regex]::Match($evidence.bugCheckMessage, '0x[0-9a-fA-F]{8}')
    if ($match.Success) {
        $evidence.bugCheckCode = $match.Value
    }
}

$crashControl = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$dumpPath = [Environment]::ExpandEnvironmentVariables($crashControl.DumpFile)
if ($dumpPath -and (Test-Path -LiteralPath $dumpPath)) {
    $dump = Get-Item -LiteralPath $dumpPath
    $evidence.dumpPath = $dump.FullName
    $evidence.dumpSizeBytes = $dump.Length
    $evidence.dumpWrittenUtc = ConvertTo-Utc8601 $dump.LastWriteTime

    if ($IncludeDump) {
        if (-not (Test-Path -LiteralPath $StageDir)) {
            New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
        }
        $staged = Join-Path $StageDir ('{0}.zip' -f $dump.BaseName)
        # Copy first: the live dump file can be locked, and compressing a copy
        # keeps the original intact for a second look.
        $working = Join-Path $StageDir $dump.Name
        Copy-Item -LiteralPath $dump.FullName -Destination $working -Force
        Compress-Archive -Path $working -DestinationPath $staged -Force
        Remove-Item -LiteralPath $working -Force
        $evidence.stagedPath = $staged
    }
}

ConvertTo-Json -InputObject $evidence -Compress
