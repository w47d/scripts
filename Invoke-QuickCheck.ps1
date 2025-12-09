<#
.SYNOPSIS
    Quick port check and banner grab for rapid triage.

.DESCRIPTION
    Lightweight script for fast initial assessment of a target.
    Use this for quick checks before running the full Invoke-ServerRecon.ps1

.PARAMETER TargetIP
    The IP address to check.

.PARAMETER Ports
    Specific ports to check. Defaults to known exposed ports (22, 139, 445, 3389).

.EXAMPLE
    .\Invoke-QuickCheck.ps1 -TargetIP "192.168.1.100"

.EXAMPLE
    .\Invoke-QuickCheck.ps1 -TargetIP "10.0.0.50" -Ports @(22, 80, 443, 3389)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$TargetIP,

    [Parameter(Mandatory = $false)]
    [int[]]$Ports = @(22, 139, 445, 3389)
)

$ErrorActionPreference = "SilentlyContinue"

Write-Host "`n=== Quick Security Check: $TargetIP ===" -ForegroundColor Cyan
Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n" -ForegroundColor Gray

# Quick DNS check
Write-Host "[DNS Lookup]" -ForegroundColor Yellow
try {
    $dns = [System.Net.Dns]::GetHostEntry($TargetIP)
    Write-Host "  Hostname: $($dns.HostName)" -ForegroundColor Green
}
catch {
    Write-Host "  No PTR record found" -ForegroundColor DarkGray
}

# Port checks
Write-Host "`n[Port Status]" -ForegroundColor Yellow
$openPorts = @()

foreach ($port in $Ports) {
    $tcp = New-Object System.Net.Sockets.TcpClient
    $async = $tcp.BeginConnect($TargetIP, $port, $null, $null)
    $wait = $async.AsyncWaitHandle.WaitOne(2000, $false)

    if ($wait -and $tcp.Connected) {
        $openPorts += $port
        Write-Host "  Port $port : " -NoNewline
        Write-Host "OPEN" -ForegroundColor Green

        # Quick banner grab
        try {
            $tcp.Close()
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.ReceiveTimeout = 3000
            $tcp.Connect($TargetIP, $port)
            $stream = $tcp.GetStream()
            $stream.ReadTimeout = 3000

            # For HTTP, send a request
            if ($port -in @(80, 8080, 8000)) {
                $request = "HEAD / HTTP/1.0`r`nHost: $TargetIP`r`n`r`n"
                $bytes = [Text.Encoding]::ASCII.GetBytes($request)
                $stream.Write($bytes, 0, $bytes.Length)
            }

            Start-Sleep -Milliseconds 1500
            if ($stream.DataAvailable) {
                $buffer = New-Object byte[] 1024
                $read = $stream.Read($buffer, 0, 1024)
                $banner = [Text.Encoding]::ASCII.GetString($buffer, 0, $read).Trim()
                if ($banner.Length -gt 0) {
                    $shortBanner = if ($banner.Length -gt 80) { $banner.Substring(0, 80) + "..." } else { $banner }
                    Write-Host "    Banner: $shortBanner" -ForegroundColor DarkCyan
                }
            }
        }
        catch {}
    }
    else {
        Write-Host "  Port $port : " -NoNewline
        Write-Host "CLOSED/FILTERED" -ForegroundColor DarkGray
    }
    $tcp.Close()
}

# SMB quick check if port 445 is open
if ($openPorts -contains 445) {
    Write-Host "`n[SMB Info]" -ForegroundColor Yellow
    $nbtstat = nbtstat -A $TargetIP 2>&1 | Out-String
    if ($nbtstat -match "(\S+)\s+<00>\s+UNIQUE") {
        Write-Host "  NetBIOS Name: $($Matches[1])" -ForegroundColor Green
    }
    if ($nbtstat -match "(\S+)\s+<00>\s+GROUP") {
        Write-Host "  Domain/Workgroup: $($Matches[1])" -ForegroundColor Green
    }
}

# Quick geo lookup
Write-Host "`n[IP Info]" -ForegroundColor Yellow
try {
    $geo = Invoke-RestMethod -Uri "http://ip-api.com/json/${TargetIP}?fields=isp,org,country,city" -TimeoutSec 5
    Write-Host "  ISP: $($geo.isp)" -ForegroundColor Cyan
    Write-Host "  Org: $($geo.org)" -ForegroundColor Cyan
    Write-Host "  Location: $($geo.city), $($geo.country)" -ForegroundColor Cyan
}
catch {
    Write-Host "  Could not retrieve IP info" -ForegroundColor DarkGray
}

# Summary
Write-Host "`n[Summary]" -ForegroundColor Yellow
Write-Host "  Open ports: $($openPorts -join ', ')" -ForegroundColor $(if ($openPorts.Count -gt 0) { "Red" } else { "Green" })

if ($openPorts.Count -gt 0) {
    Write-Host "`n  Run full scan for detailed analysis:" -ForegroundColor White
    Write-Host "  .\Invoke-ServerRecon.ps1 -TargetIP $TargetIP" -ForegroundColor Gray
}

Write-Host ""
