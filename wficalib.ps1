
#requires -Version 5.1
<#
.SYNOPSIS
    Enumerates Citrix Workspace app Connection Center sessions.

.NOTES
    Designed for Windows PowerShell 5.1.
    Verify WfIcaLib.dll architecture before selecting PowerShell x86/x64.
    Session status is not assumed to be available through GetSessionString().
#>

[CmdletBinding()]
param(
    [string]$OutputCsv = "$env:USERPROFILE\Desktop\Citrix-ConnectionCenter.csv"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ico = $null
$enumHandle = $null
$results = [System.Collections.Generic.List[object]]::new()

try {
    # 1. Architecture check
    $is64BitOS = [Environment]::Is64BitOperatingSystem
    $is64BitProcess = [Environment]::Is64BitProcess

    Write-Host "OS 64-bit: $is64BitOS"
    Write-Host "PowerShell 64-bit: $is64BitProcess"
    Write-Host "PowerShell version: $($PSVersionTable.PSVersion)"

    # 2. Locate the DLL
    $candidates = @(
        "${env:ProgramFiles(x86)}\Citrix\ICA Client\WfIcaLib.dll",
        "$env:ProgramFiles\Citrix\ICA Client\WfIcaLib.dll"
    ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }

    if (-not $candidates) {
        throw "WfIcaLib.dll not found in the default Citrix ICA Client paths."
    }

    $dllPath = $candidates[0]
    $dll = Get-Item -LiteralPath $dllPath
    $signature = Get-AuthenticodeSignature -FilePath $dllPath

    Write-Host "DLL: $dllPath"
    Write-Host "File version: $($dll.VersionInfo.FileVersion)"
    Write-Host "Product version: $($dll.VersionInfo.ProductVersion)"
    Write-Host "Signature status: $($signature.Status)"

    if ($signature.Status -notin @('Valid', 'NotSigned')) {
        throw "DLL signature status is $($signature.Status). Verify the file before loading it."
    }

    # 3. Check COM/.NET API loading
    try {
        Add-Type -Path $dllPath -ErrorAction Stop
    }
    catch {
        throw ("Unable to load WfIcaLib.dll into this PowerShell process. " +
               "Check DLL architecture, dependencies and runtime compatibility. " +
               $_.Exception.Message)
    }

    try {
        $ico = New-Object WFICALib.ICAClientClass
    }
    catch {
        throw ("Unable to create WFICALib.ICAClientClass. " +
               "Check COM registration and Workspace app installation. " +
               $_.Exception.Message)
    }

    # 4. Enumerate sessions
    $enumHandle = $ico.EnumerateCCMSessions()
    if ($null -eq $enumHandle) {
        throw "EnumerateCCMSessions returned a null handle."
    }

    $count = [int]$ico.GetEnumNameCount($enumHandle)
    Write-Host "Sessions enumerated: $count"

    for ($i = 0; $i -lt $count; $i++) {
        $sessionId = $null
        $monitoringStarted = $false
        $server = $null
        $user = $null
        $domain = $null
        $rowStatus = 'Enumerated'
        $errorMessage = $null

        try {
            $sessionId = [string]$ico.GetEnumNameByIndex($enumHandle, $i)

            if ([string]::IsNullOrWhiteSpace($sessionId)) {
                throw "The API returned an empty session ID."
            }

            $null = $ico.StartMonitoringCCMSession($sessionId, $true)
            $monitoringStarted = $true

            # Documented community usage:
            # 0 = server, 1 = username, 2 = domain.
            $server = [string]$ico.GetSessionString(0)
            $user   = [string]$ico.GetSessionString(1)
            $domain = [string]$ico.GetSessionString(2)

            $rowStatus = 'MonitoringStarted'
        }
        catch {
            $rowStatus = 'MonitoringFailed'
            $errorMessage = $_.Exception.Message
        }
        finally {
            if ($monitoringStarted -and $null -ne $sessionId) {
                try {
                    $null = $ico.StopMonitoringCCMSession($sessionId)
                }
                catch {
                    if (-not $errorMessage) {
                        $errorMessage = "Stop monitoring failed: $($_.Exception.Message)"
                    }
                }
            }
        }

        $results.Add([PSCustomObject]@{
            Timestamp       = Get-Date
            SessionId       = $sessionId
            Server          = $server
            User            = $user
            Domain          = $domain
            SessionStatus   = $rowStatus
            ConnectionState = 'NotExposedByThisQuery'
            Error           = $errorMessage
            DllVersion      = $dll.VersionInfo.FileVersion
        })
    }
}
catch {
    Write-Error $_.Exception.Message
}
finally {
    if ($null -ne $enumHandle -and $null -ne $ico) {
        try {
            $null = $ico.CloseEnumHandle($enumHandle)
        }
        catch {
            Write-Warning "Could not close enumeration handle: $($_.Exception.Message)"
        }
    }

    if ($null -ne $ico -and
        [Runtime.InteropServices.Marshal]::IsComObject($ico)) {
        try {
            [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($ico)
        }
        catch {
            Write-Warning "COM object cleanup failed: $($_.Exception.Message)"
        }
    }
}

# 5. Display and export
if ($results.Count -gt 0) {
    $results | Format-Table SessionId, Server, User, Domain,
        SessionStatus, ConnectionState -AutoSize

    try {
        $parent = Split-Path -Parent $OutputCsv
        if ($parent -and -not (Test-Path -LiteralPath $parent)) {
            New-Item -ItemType Directory -Path $parent -Force |
                Out-Null
        }

        $results | Export-Csv -LiteralPath $OutputCsv `
            -NoTypeInformation -Encoding UTF8

        Write-Host "CSV written to: $OutputCsv"
    }
    catch {
        Write-Warning "CSV export failed: $($_.Exception.Message)"
    }
}
else {
    Write-Host "No session records were returned."
}

