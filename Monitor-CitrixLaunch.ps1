
#requires -Version 5.1
<#
.SYNOPSIS
    Citrix Workspace concurrent session launch diagnostic monitor.

.DESCRIPTION
    Monitors wfica32.exe, wfcrun32.exe and related Workspace processes.
    Samples process, system, memory, network and TCP statistics every
    3 seconds. Captures recent Windows events and a failure snapshot.

    All monitor messages are logged to ConsoleOutput.csv.
    ConsoleTranscript.txt records the PowerShell console transcript.

    Stops on a detected unresponsive wfica32.exe window or Ctrl+C.
    Does not terminate, restart, or modify Citrix processes.

.NOTES
    Run in 64-bit Windows PowerShell 5.1 or later.
    Recommended: run with appropriate permissions for event-log access.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 60)]
    [int]$IntervalSeconds = 3,

    [ValidateRange(1, 20)]
    [int]$HangSamples = 2,

    [ValidateRange(1, 1440)]
    [int]$EventLookbackMinutes = 30,

    [string]$OutputRoot =
        "$env:USERPROFILE\Desktop\CitrixLaunchDiagnostics"
)

$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------
# 1. Output files
# ---------------------------------------------------------------------

$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$OutDir = Join-Path $OutputRoot $runId

New-Item -Path $OutDir -ItemType Directory -Force |
    Out-Null

$ProcessCsv   = Join-Path $OutDir 'ProcessSamples.csv'
$SystemCsv    = Join-Path $OutDir 'SystemSamples.csv'
$NetworkCsv   = Join-Path $OutDir 'NetworkSamples.csv'
$TcpCsv       = Join-Path $OutDir 'TcpSamples.csv'
$EventCsv     = Join-Path $OutDir 'EventsAtFailure.csv'
$ConsoleCsv   = Join-Path $OutDir 'ConsoleOutput.csv'
$Transcript   = Join-Path $OutDir 'ConsoleTranscript.txt'
$MetaFile     = Join-Path $OutDir 'Environment.txt'
$SnapshotFile = Join-Path $OutDir 'FailureSnapshot.txt'

$script:ProcessNames = @(
    'wfica32',
    'wfcrun32',
    'wfcrun',
    'SelfService',
    'AuthManSvr',
    'concentr',
    'Receiver'
)

$script:PreviousCpu = @{}
$script:PreviousSampleTime = $null
$script:ConsecutiveHangSamples = 0
$script:SampleNumber = 0
$script:FailureCaptured = $false
$script:TranscriptStarted = $false
$script:StopReason = 'Monitoring stopped by user or interruption'

# ---------------------------------------------------------------------
# 2. Console + CSV logging
# ---------------------------------------------------------------------

function Write-LoggedConsole {
    param(
        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS')]
        [string]$Level = 'INFO'
    )

    $timestamp = (Get-Date).ToString('o')

    $color = switch ($Level) {
        'WARN'    { 'Yellow' }
        'ERROR'   { 'Red' }
        'SUCCESS' { 'Green' }
        default   { 'Cyan' }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color

    $row = [pscustomobject]@{
        Timestamp = $timestamp
        Level     = $Level
        Message   = $Message
    }

    if (Test-Path -LiteralPath $ConsoleCsv) {
        $row | Export-Csv -LiteralPath $ConsoleCsv `
            -NoTypeInformation -Append
    }
    else {
        $row | Export-Csv -LiteralPath $ConsoleCsv `
            -NoTypeInformation
    }
}

function Write-CsvRow {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Row
    )

    if (Test-Path -LiteralPath $Path) {
        $Row | Export-Csv -LiteralPath $Path `
            -NoTypeInformation -Append
    }
    else {
        $Row | Export-Csv -LiteralPath $Path `
            -NoTypeInformation
    }
}

# ---------------------------------------------------------------------
# 3. Citrix process monitoring
# ---------------------------------------------------------------------

function Get-ProcessSnapshot {

    $now = Get-Date
    $elapsed = $null

    if ($script:PreviousSampleTime) {
        $elapsed = ($now - $script:PreviousSampleTime).TotalSeconds
    }

    $script:PreviousSampleTime = $now

    $procs = @(
        Get-Process -ErrorAction SilentlyContinue |
        Where-Object {
            $script:ProcessNames -contains $_.ProcessName
        }
    )

    $unresponsive = @()
    $currentCpu = @{}

    foreach ($p in $procs) {

        $cpuSeconds = $null
        $cpuDeltaPct = $null
        $path = $null
        $startTime = $null
        $responding = $null
        $windowTitle = $null
        $fileVersion = $null
        $threadCount = $null

        try { $cpuSeconds = [double]$p.CPU } catch {}
        try { $path = $p.Path } catch {}
        try { $startTime = $p.StartTime } catch {}
        try { $windowTitle = $p.MainWindowTitle } catch {}
        try { $threadCount = $p.Threads.Count } catch {}

        # Responsiveness is meaningful only when a main window exists.
        try {
            if ($p.MainWindowHandle -ne 0) {
                $responding = [bool]$p.Responding

                if (
                    $responding -eq $false -and
                    $p.ProcessName -eq 'wfica32'
                ) {
                    $unresponsive += $p.Id
                }
            }
        }
        catch {}

        if ($path) {
            try {
                if (Test-Path -LiteralPath $path) {
                    $fileVersion = (
                        Get-Item -LiteralPath $path
                    ).VersionInfo.FileVersion
                }
            }
            catch {}
        }

        if ($null -ne $cpuSeconds) {
            $key = [string]$p.Id

            if (
                $script:PreviousCpu.ContainsKey($key) -and
                $elapsed -gt 0
            ) {
                $delta = $cpuSeconds - $script:PreviousCpu[$key]

                if ($delta -ge 0) {
                    $cpuDeltaPct = [math]::Round(
                        100 * $delta / $elapsed /
                        [math]::Max(
                            1,
                            [Environment]::ProcessorCount
                        ),
                        2
                    )
                }
            }

            $currentCpu[$key] = $cpuSeconds
        }

        $row = [pscustomobject]@{
            Timestamp          = $now.ToString('o')
            Sample             = $script:SampleNumber
            ProcessName        = $p.ProcessName
            PID                = $p.Id
            SessionId          = $p.SessionId
            StartTime          = $startTime
            ExecutablePath     = $path
            FileVersion        = $fileVersion
            CPUSecondsTotal    = $cpuSeconds
            CPUPercentInterval = $cpuDeltaPct
            WorkingSetMB       = [math]::Round(
                $p.WorkingSet64 / 1MB, 1
            )
            PrivateMemoryMB    = [math]::Round(
                $p.PrivateMemorySize64 / 1MB, 1
            )
            VirtualMemoryMB    = [math]::Round(
                $p.VirtualMemorySize64 / 1MB, 1
            )
            HandleCount        = $p.HandleCount
            ThreadCount        = $threadCount
            Responding         = $responding
            MainWindowTitle    = $windowTitle
        }

        Write-CsvRow -Path $ProcessCsv -Row $row
    }

    $script:PreviousCpu = $currentCpu

    $totalWorkingSet = (
        $procs | Measure-Object WorkingSet64 -Sum
    ).Sum

    $totalPrivate = (
        $procs | Measure-Object PrivateMemorySize64 -Sum
    ).Sum

    $totalHandles = (
        $procs | Measure-Object HandleCount -Sum
    ).Sum

    $totalThreads = 0
    foreach ($p in $procs) {
        try { $totalThreads += $p.Threads.Count } catch {}
    }

    [pscustomobject]@{
        Count             = $procs.Count
        WficaCount        = @($procs | Where-Object {
            $_.ProcessName -eq 'wfica32'
        }).Count
        WfcrunCount       = @($procs | Where-Object {
            $_.ProcessName -in @('wfcrun32', 'wfcrun')
        }).Count
        SelfServiceCount  = @($procs | Where-Object {
            $_.ProcessName -eq 'SelfService'
        }).Count
        UnresponsivePids  = $unresponsive
        TotalWorkingSetMB = [math]::Round(
            [double]$totalWorkingSet / 1MB, 1
        )
        TotalPrivateMB    = [math]::Round(
            [double]$totalPrivate / 1MB, 1
        )
        TotalHandles      = $totalHandles
        TotalThreads      = $totalThreads
    }
}

# ---------------------------------------------------------------------
# 4. Overall system CPU and memory
# ---------------------------------------------------------------------

function Write-SystemSnapshot {

    $now = Get-Date
    $cpu = $null
    $freeMB = $null
    $totalMB = $null
    $commitMB = $null
    $commitLimitMB = $null
    $processCount = $null

    try {
        $cpu = (
            Get-CimInstance Win32_Processor |
            Measure-Object LoadPercentage -Average
        ).Average
    }
    catch {}

    try {
        $os = Get-CimInstance Win32_OperatingSystem

        $freeMB = [math]::Round(
            $os.FreePhysicalMemory / 1024, 1
        )

        $totalMB = [math]::Round(
            $os.TotalVisibleMemorySize / 1024, 1
        )
    }
    catch {}

    try {
        $counters = Get-Counter `
            '\Memory\Committed Bytes',
            '\Memory\Commit Limit' `
            -ErrorAction Stop

        $commitMB = [math]::Round(
            $counters.CounterSamples[0].CookedValue / 1MB, 1
        )

        $commitLimitMB = [math]::Round(
            $counters.CounterSamples[1].CookedValue / 1MB, 1
        )
    }
    catch {}

    try { $processCount = (Get-Process).Count } catch {}

    Write-CsvRow -Path $SystemCsv -Row ([pscustomobject]@{
        Timestamp      = $now.ToString('o')
        Sample         = $script:SampleNumber
        CPUPercent     = $cpu
        FreeMemoryMB   = $freeMB
        TotalMemoryMB  = $totalMB
        CommitUsedMB   = $commitMB
        CommitLimitMB  = $commitLimitMB
        OSProcessCount = $processCount
    })
}

# ---------------------------------------------------------------------
# 5. Network adapter counters
# ---------------------------------------------------------------------

function Write-NetworkSnapshot {

    $now = Get-Date

    try {
        Get-NetAdapterStatistics -ErrorAction Stop |
        ForEach-Object {
            Write-CsvRow -Path $NetworkCsv -Row ([pscustomobject]@{
                Timestamp       = $now.ToString('o')
                Sample          = $script:SampleNumber
                Name            = $_.Name
                ReceivedBytes   = $_.ReceivedBytes
                SentBytes       = $_.SentBytes
                ReceivedUnicast = $_.ReceivedUnicastPackets
                SentUnicast     = $_.SentUnicastPackets
                InErrors        = $_.ReceivedPacketErrors
                OutErrors       = $_.OutboundPacketErrors
                InDiscards      = $_.ReceivedDiscardedPackets
                OutDiscards     = $_.OutboundDiscardedPackets
            })
        }
    }
    catch {
        Write-LoggedConsole `
            "Network counters unavailable: $($_.Exception.Message)" `
            WARN
    }
}

# ---------------------------------------------------------------------
# 6. TCP connection states and Citrix-owned connections
# ---------------------------------------------------------------------

function Write-TcpSnapshot {

    $now = Get-Date

    try {
        $tcp = @(Get-NetTCPConnection -ErrorAction Stop)

        # Summary counts by TCP state
        $tcp | Group-Object State | ForEach-Object {
            Write-CsvRow -Path $TcpCsv -Row ([pscustomobject]@{
                Timestamp  = $now.ToString('o')
                Sample     = $script:SampleNumber
                RecordType = 'StateSummary'
                State      = $_.Name
                Count      = $_.Count
                Local      = $null
                Remote     = $null
                PID        = $null
            })
        }

        $citrixPids = @(
            Get-Process -Name $script:ProcessNames `
                -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty Id
        )

        # Detailed TCP connections owned by monitored processes
        $tcp | Where-Object {
            $_.OwningProcess -in $citrixPids
        } | ForEach-Object {

            Write-CsvRow -Path $TcpCsv -Row ([pscustomobject]@{
                Timestamp  = $now.ToString('o')
                Sample     = $script:SampleNumber
                RecordType = 'CitrixProcessConnection'
                State      = [string]$_.State
                Count      = 1
                Local      = "$($_.LocalAddress):$($_.LocalPort)"
                Remote     = "$($_.RemoteAddress):$($_.RemotePort)"
                PID        = $_.OwningProcess
            })
        }
    }
    catch {
        Write-LoggedConsole `
            "TCP snapshot unavailable: $($_.Exception.Message)" `
            WARN
    }
}

# ---------------------------------------------------------------------
# 7. Environment and failure snapshot
# ---------------------------------------------------------------------

function Save-DiagnosticSnapshot {
    param([string]$Reason)

    if ($script:FailureCaptured) { return }
    $script:FailureCaptured = $true

    $now = Get-Date

    $content = @(
        "Reason: $Reason"
        "Timestamp: $($now.ToString('o'))"
        "Computer: $env:COMPUTERNAME"
        "User: $env:USERDOMAIN\$env:USERNAME"
        "PowerShell: $($PSVersionTable.PSVersion)"
        "64BitOS: $([Environment]::Is64BitOperatingSystem)"
        "64BitProcess: $([Environment]::Is64BitProcess)"
        ""
        "=== Citrix processes ==="
        (
            Get-Process -ErrorAction SilentlyContinue |
            Where-Object {
                $script:ProcessNames -contains $_.ProcessName
            } |
            Format-List * | Out-String -Width 240
        )
        ""
        "=== Installed Workspace versions ==="
        (
            Get-ItemProperty `
                'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
                'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -match 'Citrix Workspace|Citrix Receiver'
            } |
            Select-Object DisplayName, DisplayVersion,
                InstallDate, Publisher |
            Format-Table -AutoSize | Out-String -Width 240
        )
        ""
        "=== Top CPU processes ==="
        (
            Get-Process -ErrorAction SilentlyContinue |
            Sort-Object CPU -Descending |
            Select-Object -First 20 ProcessName, Id, CPU,
                WorkingSet64, PrivateMemorySize64, HandleCount |
            Format-Table -AutoSize | Out-String -Width 240
        )
        ""
        "=== Top memory processes ==="
        (
            Get-Process -ErrorAction SilentlyContinue |
            Sort-Object WorkingSet64 -Descending |
            Select-Object -First 20 ProcessName, Id,
                WorkingSet64, PrivateMemorySize64, HandleCount |
            Format-Table -AutoSize | Out-String -Width 240
        )
    )

    $content | Out-File -LiteralPath $SnapshotFile -Encoding utf8

    $since = $now.AddMinutes(-$EventLookbackMinutes)
    $events = @()

    foreach ($logName in @('Application', 'System')) {
        try {
            $events += @(
                Get-WinEvent -FilterHashtable @{
                    LogName   = $logName
                    StartTime = $since
                } -ErrorAction Stop |
                Where-Object {
                    $_.Level -in 1, 2, 3 -or
                    $_.ProviderName -match
                        'Application Hang|Windows Error Reporting|SideBySide'
                } |
                Select-Object @{
                    Name = 'CapturedAt'
                    Expression = { $now.ToString('o') }
                }, @{
                    Name = 'LogName'
                    Expression = { $logName }
                }, TimeCreated, Id, LevelDisplayName,
                   ProviderName, ProcessId, Message
            )
        }
        catch {
            Write-LoggedConsole `
                "Could not read $logName events: $($_.Exception.Message)" `
                WARN
        }
    }

    if ($events.Count -gt 0) {
        $events |
            Export-Csv -LiteralPath $EventCsv -NoTypeInformation
    }

    Write-LoggedConsole "Diagnostic snapshot saved: $SnapshotFile" SUCCESS
    Write-LoggedConsole "Recent Windows events captured: $($events.Count)" INFO
}

# ---------------------------------------------------------------------
# 8. Start monitoring
# ---------------------------------------------------------------------

@(
    "StartTime=$((Get-Date).ToString('o'))"
    "ComputerName=$env:COMPUTERNAME"
    "User=$env:USERDOMAIN\$env:USERNAME"
    "OS=$([Environment]::OSVersion.VersionString)"
    "PowerShell=$($PSVersionTable.PSVersion)"
    "Is64BitOS=$([Environment]::Is64BitOperatingSystem)"
    "Is64BitPowerShell=$([Environment]::Is64BitProcess)"
    "SampleIntervalSeconds=$IntervalSeconds"
    "HangSamples=$HangSamples"
) | Out-File -LiteralPath $MetaFile -Encoding utf8

try {
    Start-Transcript -Path $Transcript -Force | Out-Null
    $script:TranscriptStarted = $true
}
catch {
    Write-LoggedConsole `
        "Could not start transcript: $($_.Exception.Message)" WARN
}

Write-LoggedConsole "Citrix Workspace launch monitor started" SUCCESS
Write-LoggedConsole "Sampling interval: $IntervalSeconds seconds"
Write-LoggedConsole "Hang threshold: $HangSamples consecutive samples"
Write-LoggedConsole "Output folder: $OutDir"
Write-LoggedConsole "Start your 20-session launch test now"
Write-LoggedConsole "Press Ctrl+C to stop monitoring"

try {
    while ($true) {

        $script:SampleNumber++
        $timestamp = Get-Date

        $stats = Get-ProcessSnapshot

        Write-SystemSnapshot
        Write-NetworkSnapshot
        Write-TcpSnapshot

        if ($stats.UnresponsivePids.Count -gt 0) {
            $script:ConsecutiveHangSamples++
        }
        else {
            $script:ConsecutiveHangSamples = 0
        }

        # Log each summary line to both console and CSV
        $summary = [ordered]@{
            Timestamp         = $timestamp.ToString('o')
            Sample            = $script:SampleNumber
            Wfica32           = $stats.WficaCount
            Wfcrun            = $stats.WfcrunCount
            SelfService       = $stats.SelfServiceCount
            CitrixMemoryMB    = $stats.TotalWorkingSetMB
            CitrixPrivateMB   = $stats.TotalPrivateMB
            CitrixHandles     = $stats.TotalHandles
            CitrixThreads     = $stats.TotalThreads
            UnresponsivePIDs  = $stats.UnresponsivePids -join ';'
        }

        foreach ($key in $summary.Keys) {
            Write-LoggedConsole "$key=$($summary[$key])"
        }

        if ($script:ConsecutiveHangSamples -ge $HangSamples) {
            $script:StopReason = (
                "wfica32.exe unresponsive for " +
                "$HangSamples consecutive samples"
            )

            Write-LoggedConsole $script:StopReason ERROR

            Save-DiagnosticSnapshot -Reason $script:StopReason
            break
        }

        Start-Sleep -Seconds $IntervalSeconds
    }
}
catch {
    $script:StopReason = "Monitor exception: $($_.Exception.Message)"
    Write-LoggedConsole $script:StopReason ERROR
}
finally {

    if (-not $script:FailureCaptured) {
        Save-DiagnosticSnapshot -Reason $script:StopReason
    }

    Write-LoggedConsole "Monitoring ended. Logs: $OutDir" SUCCESS

    if ($script:TranscriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {}
    }
}
