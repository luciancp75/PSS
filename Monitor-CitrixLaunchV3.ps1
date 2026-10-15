
#requires -Version 5.1
<#
.SYNOPSIS
    Monitors Citrix Workspace app processes and system resources during
    automated launches, including destination IPs for each wfica32.exe PID.

.DESCRIPTION
    Sampling interval: 3 seconds by default.
    Detects a nonresponsive wfica32.exe with a visible window.
    Captures a failure snapshot and continues monitoring until stopped.

.OUTPUTS
    ProcessSamples.csv
    SystemSamples.csv
    NetworkSamples.csv
    TcpSamples.csv
    EventsAtFailure.csv
    ConsoleOutput.csv
    ConsoleTranscript.txt
    Environment.txt
    FailureSnapshot.txt

.NOTES
    Run in 64-bit Windows PowerShell 5.1 or PowerShell 7 on Windows.
    TCP destination IPs are collected using Get-NetTCPConnection.
    UDP remote destinations are not exposed by this method.
#>

[CmdletBinding()]
param(
    [ValidateRange(1, 300)]
    [int]$IntervalSeconds = 3,

    [ValidateRange(1, 20)]
    [int]$HangSamples = 2,

    [ValidateRange(1, 1440)]
    [int]$EventLookbackMinutes = 30,

    [string]$OutputRoot = (
        Join-Path ([Environment]::GetFolderPath('Desktop')) 'CitrixLaunchMonitor'
    )
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Continue'

# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

$script:ProcessNames = @(
    'wfica32',
    'wfcrun32',
    'wfcrun',
    'SelfService',
    'AuthManSvr',
    'concentr',
    'Receiver'
)

$script:LastCpuSeconds = @{}
$script:HangCounters = @{}
$script:FailureCaptured = $false
$script:StartTime = Get-Date

if (-not (Test-Path -LiteralPath $OutputRoot)) {
    New-Item -Path $OutputRoot -ItemType Directory -Force | Out-Null
}

$script:ProcessCsv    = Join-Path $OutputRoot 'ProcessSamples.csv'
$script:SystemCsv     = Join-Path $OutputRoot 'SystemSamples.csv'
$script:NetworkCsv    = Join-Path $OutputRoot 'NetworkSamples.csv'
$script:TcpCsv        = Join-Path $OutputRoot 'TcpSamples.csv'
$script:EventsCsv     = Join-Path $OutputRoot 'EventsAtFailure.csv'
$script:ConsoleCsv    = Join-Path $OutputRoot 'ConsoleOutput.csv'
$script:Transcript    = Join-Path $OutputRoot 'ConsoleTranscript.txt'
$script:Environment   = Join-Path $OutputRoot 'Environment.txt'
$script:FailureFile   = Join-Path $OutputRoot 'FailureSnapshot.txt'

# Create empty CSV files with headers so they exist even if no data is captured.
@(
    @{ Path = $script:ProcessCsv; Data = [pscustomobject]@{
        Timestamp=''; ProcessName=''; PID=0; SessionId=0
        CPUSeconds=0; CPUPercent=0; WorkingSetMB=0; PrivateMB=0
        VirtualMB=0; Handles=0; Threads=0; Responding=$true
        MainWindowHandle=''; WindowTitle=''; ExecutablePath=''
        FileVersion=''; StartTime=''; DestinationIP=''
    }},
    @{ Path = $script:SystemCsv; Data = [pscustomobject]@{
        Timestamp=''; CPUPercent=0; TotalRAMGB=0; FreeRAMGB=0
        RAMUsedPercent=0; ProcessCount=0
    }},
    @{ Path = $script:NetworkCsv; Data = [pscustomobject]@{
        Timestamp=''; Interface=''; ReceivedBytes=0; SentBytes=0
        ReceivedUnicastPackets=0; SentUnicastPackets=0
        ReceivedDiscardedPackets=0; OutboundDiscardedPackets=0
        ReceivedErrors=0; OutboundErrors=0
    }},
    @{ Path = $script:TcpCsv; Data = [pscustomobject]@{
        Timestamp=''; TCPState=''; ConnectionCount=0
    }},
    @{ Path = $script:EventsCsv; Data = [pscustomobject]@{
        TimeCreated=''; LogName=''; ProviderName=''; Id=0
        LevelDisplayName=''; Message=''
    }},
    @{ Path = $script:ConsoleCsv; Data = [pscustomobject]@{
        Timestamp=''; Level=''; Message=''
    }}
) | ForEach-Object {
    if (-not (Test-Path -LiteralPath $_.Path)) {
        $_.Data | Export-Csv -LiteralPath $_.Path -NoTypeInformation
    }
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

function Write-LoggedConsole {
    param(
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG')]
        [string]$Level = 'INFO',

        [Parameter(Mandatory)]
        [string]$Message
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "$timestamp [$Level] $Message"

    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }

    [pscustomobject]@{
        Timestamp = $timestamp
        Level     = $Level
        Message   = $Message
    } | Export-Csv -LiteralPath $script:ConsoleCsv `
        -NoTypeInformation -Append -Encoding UTF8
}

function Add-CsvRow {
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][object]$Row
    )

    $Row | Export-Csv -LiteralPath $Path `
        -NoTypeInformation -Append -Encoding UTF8
}

# ---------------------------------------------------------------------------
# Destination IP lookup for a specific process
# ---------------------------------------------------------------------------

function Get-CitrixDestination {
    param(
        [Parameter(Mandatory)]
        [int]$ProcessId
    )

    try {
        $connections = @(
            Get-NetTCPConnection -OwningProcess $ProcessId `
                -ErrorAction SilentlyContinue |
            Where-Object {
                $_.RemoteAddress -and
                $_.RemotePort -gt 0 -and
                $_.RemoteAddress -notin @(
                    '0.0.0.0', '::', '127.0.0.1', '::1'
                )
            }
        )

        if ($connections.Count -eq 0) {
            return 'No active TCP destination'
        }

        # Return unique remote IP addresses and ports.
        $destinations = $connections |
            ForEach-Object {
                '{0}:{1}' -f $_.RemoteAddress, $_.RemotePort
            } |
            Sort-Object -Unique

        return ($destinations -join ';')
    }
    catch {
        return 'Destination unavailable'
    }
}

# ---------------------------------------------------------------------------
# Environment information
# ---------------------------------------------------------------------------

function Save-EnvironmentInfo {
    $lines = [System.Collections.Generic.List[string]]::new()

    $lines.Add("Monitor start: $(Get-Date -Format o)")
    $lines.Add("Computer: $env:COMPUTERNAME")
    $lines.Add("User: $env:USERDOMAIN\$env:USERNAME")
    $lines.Add("PowerShell: $($PSVersionTable.PSVersion)")
    $lines.Add("PowerShell edition: $($PSVersionTable.PSEdition)")
    $lines.Add("64-bit OS: $([Environment]::Is64BitOperatingSystem)")
    $lines.Add("64-bit process: $([Environment]::Is64BitProcess)")
    $lines.Add("Interval seconds: $IntervalSeconds")
    $lines.Add("Hang samples: $HangSamples")
    $lines.Add("Output folder: $OutputRoot")

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $lines.Add("Windows: $($os.Caption)")
        $lines.Add("Windows version: $($os.Version)")
        $lines.Add("OS architecture: $($os.OSArchitecture)")
    }
    catch {
        $lines.Add("OS query failed: $($_.Exception.Message)")
    }

    try {
        $cpu = Get-CimInstance Win32_Processor |
            Select-Object -First 1
        $lines.Add("CPU: $($cpu.Name)")
        $lines.Add("Logical processors: $(
            (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
        )")
    }
    catch {
        $lines.Add("CPU query failed: $($_.Exception.Message)")
    }

    try {
        $versions = Get-ItemProperty `
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.DisplayName -match 'Citrix Workspace|Citrix Receiver'
            } |
            Select-Object DisplayName, DisplayVersion, Publisher

        $lines.Add('')
        $lines.Add('Installed Citrix products:')
        foreach ($v in $versions) {
            $lines.Add("$($v.DisplayName) | $($v.DisplayVersion) | $($v.Publisher)")
        }
    }
    catch {
        $lines.Add("Citrix version query failed: $($_.Exception.Message)")
    }

    $lines | Set-Content -LiteralPath $script:Environment -Encoding UTF8
}

# ---------------------------------------------------------------------------
# System resource sampling
# ---------------------------------------------------------------------------

function Get-SystemSnapshot {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    $cpuPercent = $null
    $totalRAMGB = $null
    $freeRAMGB = $null
    $ramUsedPercent = $null

    try {
        $processors = @(Get-CimInstance Win32_Processor)
        if ($processors.Count -gt 0) {
            $cpuValues = @(
                $processors |
                Where-Object { $null -ne $_.LoadPercentage } |
                ForEach-Object { [double]$_.LoadPercentage }
            )

            if ($cpuValues.Count -gt 0) {
                $cpuPercent = [math]::Round(
                    ($cpuValues | Measure-Object -Average).Average, 2
                )
            }
        }
    }
    catch {
        Write-LoggedConsole -Level WARN -Message (
            "Could not read CPU load: $($_.Exception.Message)"
        )
    }

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $totalRAMGB = [math]::Round(
            ([double]$os.TotalVisibleMemorySize * 1KB) / 1GB, 2
        )
        $freeRAMGB = [math]::Round(
            ([double]$os.FreePhysicalMemory * 1KB) / 1GB, 2
        )

        if ($totalRAMGB -gt 0) {
            $ramUsedPercent = [math]::Round(
                100 * ($totalRAMGB - $freeRAMGB) / $totalRAMGB, 2
            )
        }
    }
    catch {
        Write-LoggedConsole -Level WARN -Message (
            "Could not read memory status: $($_.Exception.Message)"
        )
    }

    $processCount = @(
        Get-Process -ErrorAction SilentlyContinue
    ).Count

    $row = [pscustomobject]@{
        Timestamp       = $timestamp
        CPUPercent      = $cpuPercent
        TotalRAMGB      = $totalRAMGB
        FreeRAMGB       = $freeRAMGB
        RAMUsedPercent  = $ramUsedPercent
        ProcessCount    = $processCount
    }

    Add-CsvRow -Path $script:SystemCsv -Row $row
    return $row
}

# ---------------------------------------------------------------------------
# Network interface counters
# ---------------------------------------------------------------------------

function Save-NetworkSnapshot {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    try {
        $adapters = Get-NetAdapterStatistics -ErrorAction Stop

        foreach ($adapter in $adapters) {
            $row = [pscustomobject]@{
                Timestamp                = $timestamp
                Interface                = $adapter.Name
                ReceivedBytes            = $adapter.ReceivedBytes
                SentBytes                = $adapter.SentBytes
                ReceivedUnicastPackets   = $adapter.ReceivedUnicastPackets
                SentUnicastPackets       = $adapter.SentUnicastPackets
                ReceivedDiscardedPackets = $adapter.ReceivedDiscardedPackets
                OutboundDiscardedPackets = $adapter.OutboundDiscardedPackets
                ReceivedErrors           = $adapter.ReceivedPacketErrors
                OutboundErrors           = $adapter.OutboundPacketErrors
            }

            Add-CsvRow -Path $script:NetworkCsv -Row $row
        }
    }
    catch {
        Write-LoggedConsole -Level WARN -Message (
            "Network adapter statistics unavailable: $($_.Exception.Message)"
        )
    }
}

# ---------------------------------------------------------------------------
# TCP state sampling and connection ownership
# ---------------------------------------------------------------------------

function Save-TcpSnapshot {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    try {
        $connections = @(Get-NetTCPConnection -ErrorAction Stop)

        $connections |
            Group-Object -Property State |
            ForEach-Object {
                Add-CsvRow -Path $script:TcpCsv -Row ([pscustomobject]@{
                    Timestamp      = $timestamp
                    TCPState       = $_.Name
                    ConnectionCount = $_.Count
                })
            }

        # Record individual TCP connections owned by monitored Citrix PIDs.
        $citrixProcesses = @(
            Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -in $script:ProcessNames }
        )

        $pids = @($citrixProcesses | ForEach-Object { $_.Id })

        foreach ($connection in $connections) {
            if ($connection.OwningProcess -in $pids) {
                $message = (
                    'TCP_CONNECTION; PID={0}; State={1}; Local={2}:{3}; Remote={4}:{5}'
                ) -f $connection.OwningProcess,
                    $connection.State,
                    $connection.LocalAddress,
                    $connection.LocalPort,
                    $connection.RemoteAddress,
                    $connection.RemotePort

                Write-LoggedConsole -Level DEBUG -Message $message
            }
        }
    }
    catch {
        Write-LoggedConsole -Level WARN -Message (
            "TCP snapshot failed: $($_.Exception.Message)"
        )
    }
}

# ---------------------------------------------------------------------------
# Per-process snapshot
# ---------------------------------------------------------------------------

function Save-ProcessSnapshot {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $now = Get-Date

    $processes = @(
        Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.ProcessName -in $script:ProcessNames }
    )

    foreach ($proc in $processes) {
        try {
            $cpuSeconds = $null
            $cpuPercent = $null
            $workingSetMB = $null
            $privateMB = $null
            $virtualMB = $null
            $responding = $null
            $windowTitle = ''
            $mainWindowHandle = ''
            $exePath = ''
            $fileVersion = ''
            $processStart = ''

            try {
                $cpuSeconds = [math]::Round([double]$proc.CPU, 3)

                if ($script:LastCpuSeconds.ContainsKey([string]$proc.Id)) {
                    $previous = $script:LastCpuSeconds[[string]$proc.Id]
                    $delta = [math]::Max(0, $cpuSeconds - $previous)
                    $logicalProcessors = [Environment]::ProcessorCount

                    $cpuPercent = [math]::Round(
                        100 * $delta / $IntervalSeconds /
                        [math]::Max(1, $logicalProcessors), 2
                    )
                }

                $script:LastCpuSeconds[[string]$proc.Id] = $cpuSeconds
            }
            catch {}

            try {
                $workingSetMB = [math]::Round(
                    $proc.WorkingSet64 / 1MB, 2
                )
                $privateMB = [math]::Round(
                    $proc.PrivateMemorySize64 / 1MB, 2
                )
                $virtualMB = [math]::Round(
                    $proc.VirtualMemorySize64 / 1MB, 2
                )
            }
            catch {}

            try {
                $responding = $proc.Responding
            }
            catch {}

            try {
                $mainWindowHandle = [string]$proc.MainWindowHandle
                $windowTitle = $proc.MainWindowTitle
            }
            catch {}

            try {
                $exePath = $proc.Path
                if ($exePath -and (Test-Path -LiteralPath $exePath)) {
                    $fileVersion = (
                        Get-Item -LiteralPath $exePath
                    ).VersionInfo.FileVersion
                }
            }
            catch {}

            try {
                $processStart = $proc.StartTime.ToString('o')
            }
            catch {}

            $destination = 'N/A'
            if ($proc.ProcessName -ieq 'wfica32') {
                $destination = Get-CitrixDestination -ProcessId $proc.Id
            }

            $row = [pscustomobject]@{
                Timestamp       = $timestamp
                ProcessName     = $proc.ProcessName
                PID             = $proc.Id
                SessionId       = $proc.SessionId
                CPUSeconds      = $cpuSeconds
                CPUPercent      = $cpuPercent
                WorkingSetMB    = $workingSetMB
                PrivateMB       = $privateMB
                VirtualMB       = $virtualMB
                Handles         = $proc.Handles
                Threads         = $proc.Threads.Count
                Responding      = $responding
                MainWindowHandle = $mainWindowHandle
                WindowTitle     = $windowTitle
                ExecutablePath  = $exePath
                FileVersion     = $fileVersion
                StartTime       = $processStart
                DestinationIP   = $destination
            }

            Add-CsvRow -Path $script:ProcessCsv -Row $row

            # The requested per-PID console output, also written to ConsoleOutput.csv.
            $message = (
                'CITRIX_PROCESS; ProcessName={0}; PID={1}; SessionId={2}; ' +
                'CPUSeconds={3}; CPUPercent={4}; MemoryMB={5}; PrivateMB={6}; ' +
                'Handles={7}; Threads={8}; Responding={9}; DestinationIP={10}; ' +
                'WindowTitle={11}'
            ) -f $proc.ProcessName,
                $proc.Id,
                $proc.SessionId,
                $cpuSeconds,
                $cpuPercent,
                $workingSetMB,
                $privateMB,
                $proc.Handles,
                $proc.Threads.Count,
                $responding,
                $destination,
                $windowTitle

            Write-LoggedConsole -Level INFO -Message $message

            # A visible, nonresponsive wfica32 window is used as a hang indicator.
            if ($proc.ProcessName -ieq 'wfica32' -and
                $proc.MainWindowHandle -ne 0 -and
                $responding -eq $false) {

                $key = [string]$proc.Id

                if (-not $script:HangCounters.ContainsKey($key)) {
                    $script:HangCounters[$key] = 0
                }

                $script:HangCounters[$key]++

                if ($script:HangCounters[$key] -ge $HangSamples -and
                    -not $script:FailureCaptured) {

                    Write-LoggedConsole -Level ERROR -Message (
                        "POSSIBLE_HANG detected: wfica32 PID=$($proc.Id), " +
                        "SessionId=$($proc.SessionId), WindowTitle='$windowTitle'"
                    )

                    Save-FailureSnapshot -Reason (
                        "wfica32 PID $($proc.Id) was nonresponsive for " +
                        "$HangSamples consecutive samples."
                    )
                }
            }
            elseif ($proc.ProcessName -ieq 'wfica32') {
                $script:HangCounters[[string]$proc.Id] = 0
            }
        }
        catch {
            Write-LoggedConsole -Level WARN -Message (
                "Process sampling failed for PID $($proc.Id): " +
                "$($_.Exception.Message)"
            )
        }
    }

    # Remove stale PID tracking entries after processes exit.
    $currentPids = @($processes | ForEach-Object { [string]$_.Id })

    foreach ($key in @($script:LastCpuSeconds.Keys)) {
        if ($key -notin $currentPids) {
            $script:LastCpuSeconds.Remove($key)
        }
    }

    foreach ($key in @($script:HangCounters.Keys)) {
        if ($key -notin $currentPids) {
            $script:HangCounters.Remove($key)
        }
    }

    return $processes.Count
}

# ---------------------------------------------------------------------------
# Failure snapshot and recent Windows events
# ---------------------------------------------------------------------------

function Save-FailureSnapshot {
    param(
        [Parameter(Mandatory)]
        [string]$Reason
    )

    if ($script:FailureCaptured) {
        return
    }

    $script:FailureCaptured = $true
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

    Write-LoggedConsole -Level ERROR -Message (
        "Capturing failure snapshot. Reason: $Reason"
    )

    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Failure snapshot time: $timestamp")
    $lines.Add("Reason: $Reason")
    $lines.Add("Monitor started: $($script:StartTime.ToString('o'))")
    $lines.Add('')

    $lines.Add('=== Citrix processes ===')
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Where-Object { $_.ProcessName -in $script:ProcessNames } |
            Select-Object ProcessName, Id, SessionId, CPU, WorkingSet64,
                PrivateMemorySize64, Handles, Responding, MainWindowTitle |
            Format-Table -AutoSize |
            Out-String -Width 240 |
            ForEach-Object { $lines.Add($_) }
    }
    catch {
        $lines.Add("Citrix process listing failed: $($_.Exception.Message)")
    }

    $lines.Add('')
    $lines.Add('=== Top CPU processes ===')
    try {
        Get-Process -ErrorAction SilentlyContinue |
            Sort-Object CPU -Descending |
            Select-Object -First 15 ProcessName, Id, CPU,
                WorkingSet64, PrivateMemorySize64 |
            Format-Table -AutoSize |
            Out-String -Width 240 |
            ForEach-Object { $lines.Add($_) }
    }
    catch {}

    $lines.Add('')
    $lines.Add('=== Recent Application and System events ===')

    try {
        $since = (Get-Date).AddMinutes(-$EventLookbackMinutes)
        $events = @(
            Get-WinEvent -FilterHashtable @{
                LogName   = @('Application', 'System')
                StartTime = $since
                Level     = @(1, 2, 3)
            } -ErrorAction SilentlyContinue |
            Select-Object -First 250
        )

        foreach ($event in $events) {
            $message = [string]$event.Message
            $message = $message -replace '[\r\n]+', ' '

            Add-CsvRow -Path $script:EventsCsv -Row ([pscustomobject]@{
                TimeCreated      = $event.TimeCreated
                LogName          = $event.LogName
                ProviderName     = $event.ProviderName
                Id               = $event.Id
                LevelDisplayName = $event.LevelDisplayName
                Message          = $message
            })

            $lines.Add(
                ('{0} | {1} | EventID={2} | {3} | {4}' -f
                    $event.TimeCreated,
                    $event.LogName,
                    $event.Id,
                    $event.ProviderName,
                    $message)
            )
        }
    }
    catch {
        $lines.Add("Event query failed: $($_.Exception.Message)")
    }

    $lines | Set-Content -LiteralPath $script:FailureFile -Encoding UTF8

    Write-LoggedConsole -Level ERROR -Message (
        "Failure snapshot saved: $($script:FailureFile)"
    )
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

$transcriptStarted = $false

try {
    Start-Transcript -LiteralPath $script:Transcript -Append | Out-Null
    $transcriptStarted = $true
}
catch {
    Write-Warning "Could not start transcript: $($_.Exception.Message)"
}

try {
    Save-EnvironmentInfo

    Write-LoggedConsole -Level INFO -Message 'Citrix launch monitor started.'
    Write-LoggedConsole -Level INFO -Message "Interval: $IntervalSeconds seconds."
    Write-LoggedConsole -Level INFO -Message "Output folder: $OutputRoot"
    Write-LoggedConsole -Level INFO -Message (
        'Monitoring process names: ' + ($script:ProcessNames -join ', ')
    )
    Write-LoggedConsole -Level INFO -Message (
        'DestinationIP contains remote TCP IP:port pairs for each wfica32 PID.'
    )
    Write-LoggedConsole -Level INFO -Message (
        'Press Ctrl+C to stop the monitor and preserve collected data.'
    )

    while ($true) {
        $sampleTime = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'

        $system = Get-SystemSnapshot
        $processCount = Save-ProcessSnapshot

        Save-NetworkSnapshot
        Save-TcpSnapshot

        Write-LoggedConsole -Level INFO -Message (
            'SAMPLE_SUMMARY; MonitoredProcesses={0}; CPUPercent={1}; ' +
            'RAMUsedPercent={2}; FreeRAMGB={3}; TotalRAMGB={4}'
        ) -f $processCount,
            $system.CPUPercent,
            $system.RAMUsedPercent,
            $system.FreeRAMGB,
            $system.TotalRAMGB

        Start-Sleep -Seconds $IntervalSeconds
    }
}
catch {
    Write-LoggedConsole -Level ERROR -Message (
        "Monitor stopped due to error: $($_.Exception.Message)"
    )
    throw
}
finally {
    Write-LoggedConsole -Level INFO -Message (
        'Monitor stopping. Output files are located at: ' + $OutputRoot
    )

    if ($transcriptStarted) {
        try {
            Stop-Transcript | Out-Null
        }
        catch {}
    }
}
