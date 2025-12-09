<#
.SYNOPSIS
    Batch reconnaissance for multiple IP addresses.

.DESCRIPTION
    Wrapper script to run Invoke-ServerRecon.ps1 against multiple targets.
    Useful when assessing multiple potentially exposed servers.

.PARAMETER IPList
    Array of IP addresses to scan.

.PARAMETER IPFile
    Path to a text file containing one IP per line.

.PARAMETER OutputDirectory
    Directory for reports. Defaults to current directory.

.PARAMETER ShodanAPIKey
    Optional Shodan API key.

.PARAMETER Parallel
    Number of parallel scans (default 1 for sequential scanning).

.EXAMPLE
    .\Invoke-BatchRecon.ps1 -IPList @("192.168.1.100", "192.168.1.101")

.EXAMPLE
    .\Invoke-BatchRecon.ps1 -IPFile "targets.txt" -OutputDirectory "C:\Reports"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$IPList,

    [Parameter(Mandatory = $false)]
    [string]$IPFile,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ".",

    [Parameter(Mandatory = $false)]
    [string]$ShodanAPIKey = "",

    [Parameter(Mandatory = $false)]
    [int]$Parallel = 1
)

# Validate input
if (-not $IPList -and -not $IPFile) {
    Write-Error "You must provide either -IPList or -IPFile"
    exit 1
}

# Load IPs from file if specified
if ($IPFile) {
    if (-not (Test-Path $IPFile)) {
        Write-Error "IP file not found: $IPFile"
        exit 1
    }
    $IPList = Get-Content $IPFile | Where-Object { $_ -match '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$' }
}

# Create output directory if needed
if (-not (Test-Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Batch Server Reconnaissance" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Targets: $($IPList.Count)" -ForegroundColor White
Write-Host "Output:  $OutputDirectory" -ForegroundColor White
Write-Host "Started: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "========================================`n" -ForegroundColor Cyan

$scriptPath = Join-Path $PSScriptRoot "Invoke-ServerRecon.ps1"

if (-not (Test-Path $scriptPath)) {
    Write-Error "Invoke-ServerRecon.ps1 not found in script directory"
    exit 1
}

$results = @()
$count = 0

foreach ($ip in $IPList) {
    $count++
    Write-Host "`n[$count/$($IPList.Count)] Scanning: $ip" -ForegroundColor Yellow

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeIP = $ip -replace '\.', '-'
    $outputPath = Join-Path $OutputDirectory "recon_${safeIP}_${timestamp}.txt"

    $params = @{
        TargetIP = $ip
        OutputPath = $outputPath
    }

    if ($ShodanAPIKey) {
        $params.ShodanAPIKey = $ShodanAPIKey
    }

    try {
        $result = & $scriptPath @params

        $results += [PSCustomObject]@{
            IP = $ip
            Status = "Completed"
            OpenPorts = $result.OpenPorts -join ", "
            Report = $outputPath
            Duration = $result.Duration
        }
    }
    catch {
        Write-Host "  Error scanning $ip : $($_.Exception.Message)" -ForegroundColor Red
        $results += [PSCustomObject]@{
            IP = $ip
            Status = "Failed"
            OpenPorts = "N/A"
            Report = "N/A"
            Duration = "N/A"
            Error = $_.Exception.Message
        }
    }
}

# Summary report
$summaryPath = Join-Path $OutputDirectory "batch_summary_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  BATCH SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$results | Format-Table -AutoSize | Out-String | Write-Host

# Save summary
$results | Format-Table -AutoSize | Out-File $summaryPath
$results | Export-Csv -Path ($summaryPath -replace '\.txt$', '.csv') -NoTypeInformation

Write-Host "Summary saved to: $summaryPath" -ForegroundColor Green
