<#
.SYNOPSIS
    Defensive security reconnaissance script for profiling exposed servers.

.DESCRIPTION
    This script performs comprehensive reconnaissance on a target IP address
    to assess exposure and gather context about a potentially misconfigured
    server belonging to your organization.

    Features:
    - Port scanning (nmap + PowerShell fallback)
    - Banner grabbing on discovered services
    - SMB enumeration (anonymous/null session only)
    - DNS lookups (forward/reverse)
    - WHOIS lookups via web APIs
    - Shodan API queries (optional)
    - Live Sysinternals tools integration
    - RDP/SSH fingerprinting

.PARAMETER TargetIP
    The IP address of the server to assess.

.PARAMETER OutputPath
    Path for the output report file. Defaults to "recon_report_<IP>_<timestamp>.txt"

.PARAMETER ShodanAPIKey
    Optional Shodan API key for additional intelligence gathering.

.PARAMETER SkipNmap
    Skip nmap scanning (use PowerShell-only port scanning).

.PARAMETER CustomPorts
    Additional ports to scan beyond the default list.

.EXAMPLE
    .\Invoke-ServerRecon.ps1 -TargetIP "192.168.1.100"

.EXAMPLE
    .\Invoke-ServerRecon.ps1 -TargetIP "10.0.0.50" -ShodanAPIKey "your_api_key" -OutputPath "C:\Reports\scan.txt"

.EXAMPLE
    .\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50" -CustomPorts @(8443, 9090, 27017)

.NOTES
    Author: Security Team
    Purpose: Defensive assessment of organization-owned infrastructure
    Requires: Windows 11, PowerShell 5.1+, optional nmap installation
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Target IP address to assess")]
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    [string]$TargetIP,

    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "",

    [Parameter(Mandatory = $false)]
    [string]$ShodanAPIKey = "",

    [Parameter(Mandatory = $false)]
    [switch]$SkipNmap,

    [Parameter(Mandatory = $false)]
    [int[]]$CustomPorts = @()
)

#region Configuration
$script:StartTime = Get-Date
$script:Results = [System.Collections.ArrayList]::new()

# Default ports to scan (common services)
$DefaultPorts = @(
    21,    # FTP
    22,    # SSH/SFTP
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    111,   # RPC
    135,   # MSRPC
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    465,   # SMTPS
    587,   # SMTP Submission
    993,   # IMAPS
    995,   # POP3S
    1433,  # MSSQL
    1434,  # MSSQL Browser
    1521,  # Oracle
    2049,  # NFS
    3306,  # MySQL
    3389,  # RDP
    5432,  # PostgreSQL
    5900,  # VNC
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS
    6379,  # Redis
    8080,  # HTTP Proxy
    8443,  # HTTPS Alt
    9200,  # Elasticsearch
    27017  # MongoDB
)

# Merge custom ports
$AllPorts = ($DefaultPorts + $CustomPorts) | Sort-Object -Unique

# Set output path if not specified
if ([string]::IsNullOrEmpty($OutputPath)) {
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $safeIP = $TargetIP -replace '\.', '-'
    $OutputPath = Join-Path $PSScriptRoot "recon_report_${safeIP}_${timestamp}.txt"
}

# Live Sysinternals base URL
$SysinternalsBaseUrl = "https://live.sysinternals.com"

#endregion

#region Helper Functions

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "HEADER", "SUBHEADER")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    switch ($Level) {
        "HEADER" {
            $formatted = "`n{'='*60}`n$Message`n{'='*60}"
            Write-Host $formatted -ForegroundColor Cyan
        }
        "SUBHEADER" {
            $formatted = "`n[+] $Message"
            Write-Host $formatted -ForegroundColor Yellow
        }
        "SUCCESS" {
            $formatted = "    [*] $Message"
            Write-Host $formatted -ForegroundColor Green
        }
        "WARNING" {
            $formatted = "    [!] $Message"
            Write-Host $formatted -ForegroundColor DarkYellow
        }
        "ERROR" {
            $formatted = "    [-] $Message"
            Write-Host $formatted -ForegroundColor Red
        }
        default {
            $formatted = "    $Message"
            Write-Host $formatted
        }
    }

    $null = $script:Results.Add("[$timestamp] $Message")
}

function Write-Banner {
    $banner = @"

  ____                           ____
 / ___|  ___ _ ____   _____ _ __|  _ \ ___  ___ ___  _ __
 \___ \ / _ \ '__\ \ / / _ \ '__| |_) / _ \/ __/ _ \| '_ \
  ___) |  __/ |   \ V /  __/ |  |  _ <  __/ (_| (_) | | | |
 |____/ \___|_|    \_/ \___|_|  |_| \_\___|\___\___/|_| |_|

 Defensive Security Assessment Tool v1.0
 =========================================================
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Log "Defensive Security Assessment Tool v1.0"
    Write-Log "Target: $TargetIP"
    Write-Log "Started: $($script:StartTime)"
    Write-Log "Output: $OutputPath"
}

function Test-PortOpen {
    param(
        [string]$IP,
        [int]$Port,
        [int]$Timeout = 2000
    )

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout, $false)

        if ($wait -and $tcpClient.Connected) {
            $tcpClient.Close()
            return $true
        }
        $tcpClient.Close()
        return $false
    }
    catch {
        return $false
    }
}

function Get-Banner {
    param(
        [string]$IP,
        [int]$Port,
        [int]$Timeout = 5000,
        [string]$SendData = ""
    )

    try {
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.ReceiveTimeout = $Timeout
        $tcpClient.SendTimeout = $Timeout

        $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
        $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout, $false)

        if (!$wait -or !$tcpClient.Connected) {
            $tcpClient.Close()
            return $null
        }

        $tcpClient.EndConnect($asyncResult)
        $stream = $tcpClient.GetStream()
        $stream.ReadTimeout = $Timeout

        # Send data if specified (for HTTP, etc.)
        if ($SendData -ne "") {
            $sendBytes = [System.Text.Encoding]::ASCII.GetBytes($SendData)
            $stream.Write($sendBytes, 0, $sendBytes.Length)
            Start-Sleep -Milliseconds 500
        }

        # Try to read banner
        $buffer = New-Object byte[] 4096
        $banner = ""

        # Wait a moment for data
        Start-Sleep -Milliseconds 1000

        if ($stream.DataAvailable) {
            $bytesRead = $stream.Read($buffer, 0, $buffer.Length)
            if ($bytesRead -gt 0) {
                $banner = [System.Text.Encoding]::ASCII.GetString($buffer, 0, $bytesRead)
            }
        }

        $tcpClient.Close()
        return $banner.Trim()
    }
    catch {
        return $null
    }
}

function Get-HTTPBanner {
    param(
        [string]$IP,
        [int]$Port,
        [bool]$UseSSL = $false
    )

    try {
        $protocol = if ($UseSSL) { "https" } else { "http" }
        $uri = "${protocol}://${IP}:${Port}/"

        # Disable certificate validation for HTTPS
        if ($UseSSL) {
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        }

        $request = [System.Net.HttpWebRequest]::Create($uri)
        $request.Method = "HEAD"
        $request.Timeout = 5000
        $request.AllowAutoRedirect = $false
        $request.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Security-Assessment/1.0"

        $response = $request.GetResponse()

        $result = @{
            StatusCode = [int]$response.StatusCode
            Server = $response.Headers["Server"]
            PoweredBy = $response.Headers["X-Powered-By"]
            AspNetVersion = $response.Headers["X-AspNet-Version"]
            ContentType = $response.ContentType
            Headers = @{}
        }

        foreach ($header in $response.Headers.AllKeys) {
            $result.Headers[$header] = $response.Headers[$header]
        }

        $response.Close()
        return $result
    }
    catch [System.Net.WebException] {
        $response = $_.Exception.Response
        if ($response) {
            return @{
                StatusCode = [int]$response.StatusCode
                Server = $response.Headers["Server"]
                Error = $_.Exception.Message
            }
        }
        return @{ Error = $_.Exception.Message }
    }
    catch {
        return @{ Error = $_.Exception.Message }
    }
}

#endregion

#region Reconnaissance Functions

function Invoke-DNSRecon {
    Write-Log "DNS RECONNAISSANCE" -Level HEADER

    # Reverse DNS lookup
    Write-Log "Performing reverse DNS lookup..." -Level SUBHEADER
    try {
        $dnsResult = [System.Net.Dns]::GetHostEntry($TargetIP)
        Write-Log "Hostname: $($dnsResult.HostName)" -Level SUCCESS

        if ($dnsResult.Aliases.Count -gt 0) {
            Write-Log "Aliases: $($dnsResult.Aliases -join ', ')" -Level SUCCESS
        }

        # Forward lookup on discovered hostname
        if ($dnsResult.HostName) {
            Write-Log "Forward DNS verification..." -Level SUBHEADER
            try {
                $forwardResult = [System.Net.Dns]::GetHostAddresses($dnsResult.HostName)
                foreach ($addr in $forwardResult) {
                    Write-Log "Resolves to: $($addr.IPAddressToString)" -Level INFO
                }
            }
            catch {
                Write-Log "Forward lookup failed: $($_.Exception.Message)" -Level WARNING
            }
        }
    }
    catch {
        Write-Log "Reverse DNS lookup failed - no PTR record found" -Level WARNING
    }

    # Try nslookup for additional records
    Write-Log "Checking for additional DNS records..." -Level SUBHEADER
    try {
        $nslookup = nslookup $TargetIP 2>&1
        foreach ($line in $nslookup) {
            if ($line -match "Name:|Address:|name =") {
                Write-Log $line.Trim() -Level INFO
            }
        }
    }
    catch {
        Write-Log "nslookup failed: $($_.Exception.Message)" -Level WARNING
    }
}

function Invoke-PortScan {
    Write-Log "PORT SCANNING" -Level HEADER

    $openPorts = [System.Collections.ArrayList]::new()

    # Try nmap first if available
    if (-not $SkipNmap) {
        Write-Log "Attempting nmap scan..." -Level SUBHEADER

        $nmapPath = Get-Command nmap -ErrorAction SilentlyContinue
        if ($nmapPath) {
            try {
                Write-Log "Running nmap service scan (this may take a few minutes)..." -Level INFO

                # Run nmap with service detection
                $portList = $AllPorts -join ","
                $nmapArgs = @(
                    "-sT",                    # TCP connect scan (works without admin)
                    "-sV",                    # Service version detection
                    "--version-intensity", "5",
                    "-p", $portList,
                    "-T3",                    # Medium timing
                    "--open",                 # Only show open ports
                    "-oN", "-",               # Output to stdout
                    $TargetIP
                )

                $nmapOutput = & nmap $nmapArgs 2>&1

                Write-Log "Nmap scan results:" -Level SUBHEADER
                foreach ($line in $nmapOutput) {
                    $lineStr = $line.ToString()
                    if ($lineStr -match "^\d+/(tcp|udp)\s+open" -or
                        $lineStr -match "^PORT\s+" -or
                        $lineStr -match "^Nmap scan report" -or
                        $lineStr -match "^MAC Address:" -or
                        $lineStr -match "^Service Info:") {
                        Write-Log $lineStr -Level SUCCESS
                    }

                    # Extract open ports
                    if ($lineStr -match "^(\d+)/(tcp|udp)\s+open") {
                        $null = $openPorts.Add([int]$Matches[1])
                    }
                }

                if ($openPorts.Count -eq 0) {
                    Write-Log "No open ports found via nmap in scanned range" -Level WARNING
                }

                return $openPorts
            }
            catch {
                Write-Log "Nmap scan failed: $($_.Exception.Message)" -Level ERROR
                Write-Log "Falling back to PowerShell port scan..." -Level INFO
            }
        }
        else {
            Write-Log "Nmap not found in PATH, using PowerShell port scanning..." -Level WARNING
        }
    }

    # PowerShell port scan fallback
    Write-Log "PowerShell TCP port scan..." -Level SUBHEADER
    Write-Log "Scanning $($AllPorts.Count) ports..." -Level INFO

    $jobs = @()
    $maxConcurrent = 50

    foreach ($port in $AllPorts) {
        # Throttle concurrent connections
        while ((Get-Job -State Running).Count -ge $maxConcurrent) {
            Start-Sleep -Milliseconds 100
            Get-Job -State Completed | ForEach-Object {
                $result = Receive-Job $_
                if ($result.Open) {
                    $null = $openPorts.Add($result.Port)
                    Write-Log "Port $($result.Port)/tcp OPEN" -Level SUCCESS
                }
                Remove-Job $_
            }
        }

        $jobs += Start-Job -ScriptBlock {
            param($IP, $Port)
            $result = @{ Port = $Port; Open = $false }
            try {
                $tcpClient = New-Object System.Net.Sockets.TcpClient
                $asyncResult = $tcpClient.BeginConnect($IP, $Port, $null, $null)
                $wait = $asyncResult.AsyncWaitHandle.WaitOne(2000, $false)
                if ($wait -and $tcpClient.Connected) {
                    $result.Open = $true
                }
                $tcpClient.Close()
            }
            catch {}
            return $result
        } -ArgumentList $TargetIP, $port
    }

    # Wait for remaining jobs
    $jobs | Wait-Job | ForEach-Object {
        $result = Receive-Job $_
        if ($result.Open) {
            $null = $openPorts.Add($result.Port)
            Write-Log "Port $($result.Port)/tcp OPEN" -Level SUCCESS
        }
        Remove-Job $_
    }

    Write-Log "Found $($openPorts.Count) open port(s)" -Level INFO
    return $openPorts
}

function Invoke-BannerGrab {
    param([System.Collections.ArrayList]$OpenPorts)

    Write-Log "BANNER GRABBING" -Level HEADER

    if ($OpenPorts.Count -eq 0) {
        Write-Log "No open ports to grab banners from" -Level WARNING
        return
    }

    foreach ($port in $OpenPorts) {
        Write-Log "Port $port banner grab..." -Level SUBHEADER

        switch ($port) {
            # SSH/SFTP
            22 {
                $banner = Get-Banner -IP $TargetIP -Port $port
                if ($banner) {
                    Write-Log "SSH Banner: $banner" -Level SUCCESS

                    # Parse SSH version info
                    if ($banner -match "SSH-(\d+\.\d+)-(.+)") {
                        Write-Log "  SSH Protocol: $($Matches[1])" -Level INFO
                        Write-Log "  SSH Software: $($Matches[2])" -Level INFO
                    }
                }
                else {
                    Write-Log "No SSH banner received" -Level WARNING
                }
            }

            # FTP
            21 {
                $banner = Get-Banner -IP $TargetIP -Port $port
                if ($banner) {
                    Write-Log "FTP Banner: $banner" -Level SUCCESS
                }
            }

            # Telnet
            23 {
                $banner = Get-Banner -IP $TargetIP -Port $port
                if ($banner) {
                    Write-Log "Telnet Banner: $banner" -Level SUCCESS
                }
            }

            # SMTP
            {$_ -in @(25, 465, 587)} {
                $banner = Get-Banner -IP $TargetIP -Port $port
                if ($banner) {
                    Write-Log "SMTP Banner: $banner" -Level SUCCESS
                }
            }

            # HTTP
            {$_ -in @(80, 8080, 8000, 8888)} {
                $httpResult = Get-HTTPBanner -IP $TargetIP -Port $port -UseSSL $false
                if ($httpResult.Server) {
                    Write-Log "HTTP Server: $($httpResult.Server)" -Level SUCCESS
                }
                if ($httpResult.PoweredBy) {
                    Write-Log "X-Powered-By: $($httpResult.PoweredBy)" -Level SUCCESS
                }
                if ($httpResult.AspNetVersion) {
                    Write-Log "ASP.NET Version: $($httpResult.AspNetVersion)" -Level SUCCESS
                }
                if ($httpResult.Headers) {
                    Write-Log "HTTP Headers:" -Level INFO
                    foreach ($header in $httpResult.Headers.GetEnumerator()) {
                        Write-Log "  $($header.Key): $($header.Value)" -Level INFO
                    }
                }
                if ($httpResult.Error) {
                    Write-Log "HTTP Error: $($httpResult.Error)" -Level WARNING
                }
            }

            # HTTPS
            {$_ -in @(443, 8443, 9443)} {
                $httpsResult = Get-HTTPBanner -IP $TargetIP -Port $port -UseSSL $true
                if ($httpsResult.Server) {
                    Write-Log "HTTPS Server: $($httpsResult.Server)" -Level SUCCESS
                }
                if ($httpsResult.PoweredBy) {
                    Write-Log "X-Powered-By: $($httpsResult.PoweredBy)" -Level SUCCESS
                }
                if ($httpsResult.Headers) {
                    Write-Log "HTTPS Headers:" -Level INFO
                    foreach ($header in $httpsResult.Headers.GetEnumerator()) {
                        Write-Log "  $($header.Key): $($header.Value)" -Level INFO
                    }
                }

                # Try to get SSL certificate info
                try {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient($TargetIP, $port)
                    $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, { $true })
                    $sslStream.AuthenticateAsClient($TargetIP)
                    $cert = $sslStream.RemoteCertificate

                    if ($cert) {
                        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
                        Write-Log "SSL Certificate Info:" -Level SUCCESS
                        Write-Log "  Subject: $($cert2.Subject)" -Level INFO
                        Write-Log "  Issuer: $($cert2.Issuer)" -Level INFO
                        Write-Log "  Valid From: $($cert2.NotBefore)" -Level INFO
                        Write-Log "  Valid To: $($cert2.NotAfter)" -Level INFO
                        Write-Log "  Thumbprint: $($cert2.Thumbprint)" -Level INFO

                        # Extract SANs if present
                        $sanExt = $cert2.Extensions | Where-Object { $_.Oid.FriendlyName -eq "Subject Alternative Name" }
                        if ($sanExt) {
                            Write-Log "  SANs: $($sanExt.Format($true))" -Level INFO
                        }
                    }

                    $sslStream.Close()
                    $tcpClient.Close()
                }
                catch {
                    Write-Log "SSL cert extraction failed: $($_.Exception.Message)" -Level WARNING
                }
            }

            # RDP
            3389 {
                Write-Log "RDP port detected - attempting fingerprint..." -Level INFO

                # Try to get RDP security info via nmap script if available
                if (Get-Command nmap -ErrorAction SilentlyContinue) {
                    try {
                        $rdpNmap = & nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info $TargetIP 2>&1
                        foreach ($line in $rdpNmap) {
                            $lineStr = $line.ToString()
                            if ($lineStr -match "^\|" -or $lineStr -match "Target_Name:|NetBIOS|DNS|Product") {
                                Write-Log $lineStr.TrimStart('|').Trim() -Level SUCCESS
                            }
                        }
                    }
                    catch {
                        Write-Log "RDP nmap script failed" -Level WARNING
                    }
                }

                # Basic RDP connection attempt
                $banner = Get-Banner -IP $TargetIP -Port $port -Timeout 3000
                if ($banner) {
                    # RDP typically doesn't send a readable banner, but log raw bytes
                    $hexBanner = ($banner.ToCharArray() | ForEach-Object { "{0:X2}" -f [int][char]$_ }) -join " "
                    Write-Log "RDP Raw Response (hex): $hexBanner" -Level INFO
                }
            }

            # MySQL
            3306 {
                $banner = Get-Banner -IP $TargetIP -Port $port
                if ($banner) {
                    Write-Log "MySQL Banner: $banner" -Level SUCCESS
                    if ($banner -match "(\d+\.\d+\.\d+)") {
                        Write-Log "  MySQL Version: $($Matches[1])" -Level INFO
                    }
                }
            }

            # MSSQL
            1433 {
                Write-Log "MSSQL port detected" -Level INFO
                # MSSQL requires TDS protocol, basic banner grab won't work
                # Try nmap script if available
                if (Get-Command nmap -ErrorAction SilentlyContinue) {
                    try {
                        $mssqlNmap = & nmap -p 1433 --script ms-sql-info $TargetIP 2>&1
                        foreach ($line in $mssqlNmap) {
                            $lineStr = $line.ToString()
                            if ($lineStr -match "^\|" -or $lineStr -match "Version:|Instance") {
                                Write-Log $lineStr.TrimStart('|').Trim() -Level SUCCESS
                            }
                        }
                    }
                    catch {
                        Write-Log "MSSQL nmap script failed" -Level WARNING
                    }
                }
            }

            # Default banner grab for other ports
            default {
                $banner = Get-Banner -IP $TargetIP -Port $port -Timeout 3000
                if ($banner -and $banner.Length -gt 0) {
                    # Clean up non-printable characters
                    $cleanBanner = $banner -replace '[^\x20-\x7E\r\n]', '.'
                    if ($cleanBanner.Trim().Length -gt 0) {
                        Write-Log "Banner: $cleanBanner" -Level SUCCESS
                    }
                }
                else {
                    Write-Log "No banner received (service may require protocol-specific probe)" -Level INFO
                }
            }
        }
    }
}

function Invoke-SMBRecon {
    param([System.Collections.ArrayList]$OpenPorts)

    if ($OpenPorts -notcontains 445 -and $OpenPorts -notcontains 139) {
        return
    }

    Write-Log "SMB ENUMERATION (Anonymous)" -Level HEADER

    # Try to get NetBIOS name
    Write-Log "NetBIOS name query..." -Level SUBHEADER
    try {
        $nbtstat = nbtstat -A $TargetIP 2>&1
        $foundInfo = $false
        foreach ($line in $nbtstat) {
            $lineStr = $line.ToString()
            if ($lineStr -match "<00>|<20>|<03>|UNIQUE|GROUP|MAC Address") {
                Write-Log $lineStr.Trim() -Level SUCCESS
                $foundInfo = $true
            }
        }
        if (-not $foundInfo) {
            Write-Log "No NetBIOS information retrieved" -Level WARNING
        }
    }
    catch {
        Write-Log "nbtstat failed: $($_.Exception.Message)" -Level ERROR
    }

    # Try SMB connection with null session
    Write-Log "SMB null session enumeration..." -Level SUBHEADER

    # Try net view
    try {
        $netView = net view \\$TargetIP 2>&1
        $netViewStr = $netView | Out-String
        if ($netViewStr -notmatch "System error|Access is denied") {
            Write-Log "Shared resources:" -Level SUCCESS
            foreach ($line in $netView) {
                Write-Log "  $line" -Level INFO
            }
        }
        else {
            Write-Log "net view: Access denied or no shares visible anonymously" -Level WARNING
        }
    }
    catch {
        Write-Log "net view failed: $($_.Exception.Message)" -Level WARNING
    }

    # Try to enumerate shares using WMI/CIM (may fail without creds)
    Write-Log "Attempting CIM/WMI share enumeration..." -Level SUBHEADER
    try {
        $shares = Get-CimInstance -ClassName Win32_Share -ComputerName $TargetIP -ErrorAction Stop
        Write-Log "Discovered shares:" -Level SUCCESS
        foreach ($share in $shares) {
            Write-Log "  $($share.Name) - $($share.Path) - $($share.Description)" -Level INFO
        }
    }
    catch {
        Write-Log "CIM share enumeration failed (expected without credentials)" -Level INFO
    }

    # Use nmap SMB scripts if available
    if (Get-Command nmap -ErrorAction SilentlyContinue) {
        Write-Log "Running nmap SMB scripts..." -Level SUBHEADER
        try {
            $smbScripts = @(
                "smb-os-discovery",
                "smb-protocols",
                "smb-security-mode",
                "smb2-security-mode"
            )

            $smbNmap = & nmap -p 445 --script ($smbScripts -join ",") $TargetIP 2>&1
            foreach ($line in $smbNmap) {
                $lineStr = $line.ToString()
                if ($lineStr -match "^\|" -or $lineStr -match "OS:|Computer name:|Domain:|Workgroup:|SMBv|signing") {
                    Write-Log $lineStr.TrimStart('|').Trim() -Level SUCCESS
                }
            }
        }
        catch {
            Write-Log "nmap SMB scripts failed: $($_.Exception.Message)" -Level WARNING
        }
    }
}

function Invoke-WHOISLookup {
    Write-Log "WHOIS / IP INTELLIGENCE" -Level HEADER

    # Use ip-api.com for geolocation and basic info
    Write-Log "IP Geolocation and ISP info..." -Level SUBHEADER
    try {
        $geoUrl = "http://ip-api.com/json/${TargetIP}?fields=status,message,continent,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
        $geoResponse = Invoke-RestMethod -Uri $geoUrl -TimeoutSec 10

        if ($geoResponse.status -eq "success") {
            Write-Log "IP: $($geoResponse.query)" -Level SUCCESS
            Write-Log "Reverse DNS: $($geoResponse.reverse)" -Level INFO
            Write-Log "ISP: $($geoResponse.isp)" -Level INFO
            Write-Log "Organization: $($geoResponse.org)" -Level INFO
            Write-Log "AS: $($geoResponse.as)" -Level INFO
            Write-Log "AS Name: $($geoResponse.asname)" -Level INFO
            Write-Log "Location: $($geoResponse.city), $($geoResponse.regionName), $($geoResponse.country)" -Level INFO
            Write-Log "Coordinates: $($geoResponse.lat), $($geoResponse.lon)" -Level INFO
            Write-Log "Timezone: $($geoResponse.timezone)" -Level INFO
        }
        else {
            Write-Log "Geolocation lookup failed: $($geoResponse.message)" -Level WARNING
        }
    }
    catch {
        Write-Log "Geolocation API failed: $($_.Exception.Message)" -Level ERROR
    }

    # Try ipinfo.io as backup
    Write-Log "Additional IP info (ipinfo.io)..." -Level SUBHEADER
    try {
        $ipinfoUrl = "https://ipinfo.io/${TargetIP}/json"
        $ipinfoResponse = Invoke-RestMethod -Uri $ipinfoUrl -TimeoutSec 10

        if ($ipinfoResponse.hostname) {
            Write-Log "Hostname: $($ipinfoResponse.hostname)" -Level SUCCESS
        }
        if ($ipinfoResponse.org) {
            Write-Log "Organization: $($ipinfoResponse.org)" -Level SUCCESS
        }
    }
    catch {
        Write-Log "ipinfo.io lookup failed" -Level WARNING
    }
}

function Invoke-ShodanLookup {
    if ([string]::IsNullOrEmpty($ShodanAPIKey)) {
        Write-Log "SHODAN LOOKUP" -Level HEADER
        Write-Log "Shodan API key not provided - skipping Shodan lookup" -Level WARNING
        Write-Log "To use Shodan, run with: -ShodanAPIKey 'your_api_key'" -Level INFO
        return
    }

    Write-Log "SHODAN INTELLIGENCE" -Level HEADER

    try {
        $shodanUrl = "https://api.shodan.io/shodan/host/${TargetIP}?key=${ShodanAPIKey}"
        $shodanResponse = Invoke-RestMethod -Uri $shodanUrl -TimeoutSec 15

        Write-Log "Shodan data found!" -Level SUCCESS

        if ($shodanResponse.hostnames) {
            Write-Log "Hostnames: $($shodanResponse.hostnames -join ', ')" -Level INFO
        }
        if ($shodanResponse.os) {
            Write-Log "Operating System: $($shodanResponse.os)" -Level INFO
        }
        if ($shodanResponse.org) {
            Write-Log "Organization: $($shodanResponse.org)" -Level INFO
        }
        if ($shodanResponse.isp) {
            Write-Log "ISP: $($shodanResponse.isp)" -Level INFO
        }
        if ($shodanResponse.ports) {
            Write-Log "Open Ports (Shodan): $($shodanResponse.ports -join ', ')" -Level INFO
        }
        if ($shodanResponse.vulns) {
            Write-Log "Potential Vulnerabilities:" -Level WARNING
            foreach ($vuln in $shodanResponse.vulns) {
                Write-Log "  - $vuln" -Level WARNING
            }
        }
        if ($shodanResponse.data) {
            Write-Log "Service banners from Shodan:" -Level SUBHEADER
            foreach ($service in $shodanResponse.data) {
                Write-Log "Port $($service.port):" -Level INFO
                if ($service.product) {
                    Write-Log "  Product: $($service.product)" -Level INFO
                }
                if ($service.version) {
                    Write-Log "  Version: $($service.version)" -Level INFO
                }
                if ($service.banner) {
                    $shortBanner = if ($service.banner.Length -gt 200) { $service.banner.Substring(0, 200) + "..." } else { $service.banner }
                    Write-Log "  Banner: $shortBanner" -Level INFO
                }
            }
        }

        Write-Log "Last Shodan Update: $($shodanResponse.last_update)" -Level INFO
    }
    catch {
        if ($_.Exception.Message -match "404") {
            Write-Log "No Shodan data found for this IP" -Level WARNING
        }
        else {
            Write-Log "Shodan lookup failed: $($_.Exception.Message)" -Level ERROR
        }
    }
}

function Invoke-SysinternalsRecon {
    param([System.Collections.ArrayList]$OpenPorts)

    Write-Log "LIVE SYSINTERNALS TOOLS" -Level HEADER

    # Only attempt if SMB ports are open (remote admin possible)
    if ($OpenPorts -notcontains 445) {
        Write-Log "Port 445 not open - Sysinternals remote tools require SMB" -Level WARNING
        Write-Log "Sysinternals tools work best when run locally on the target" -Level INFO
        return
    }

    Write-Log "Attempting Sysinternals tools via live.sysinternals.com..." -Level SUBHEADER
    Write-Log "Note: These require network access to the target's admin shares" -Level INFO

    # PsInfo - System information
    Write-Log "Trying PsInfo for system information..." -Level SUBHEADER
    try {
        $psinfoPath = "\\live.sysinternals.com\tools\psinfo.exe"

        # Test if we can access live.sysinternals.com
        if (Test-Path $psinfoPath) {
            $psinfoOutput = & $psinfoPath -accepteula \\$TargetIP 2>&1
            foreach ($line in $psinfoOutput) {
                $lineStr = $line.ToString()
                if ($lineStr -match "System information|OS|Processor|Physical Memory|Uptime|Product|Owner|Organization") {
                    Write-Log $lineStr -Level SUCCESS
                }
            }
        }
        else {
            Write-Log "Cannot access live.sysinternals.com - check WebDAV/WebClient service" -Level WARNING
            Write-Log "Try: Start-Service WebClient" -Level INFO
        }
    }
    catch {
        Write-Log "PsInfo failed (expected without admin rights): $($_.Exception.Message)" -Level WARNING
    }

    # PsLoggedOn - Check logged on users
    Write-Log "Trying PsLoggedOn for logged-in users..." -Level SUBHEADER
    try {
        $psloggedonPath = "\\live.sysinternals.com\tools\psloggedon.exe"
        if (Test-Path $psloggedonPath) {
            $psloggedOutput = & $psloggedonPath -accepteula \\$TargetIP 2>&1
            foreach ($line in $psloggedOutput) {
                Write-Log $line.ToString() -Level INFO
            }
        }
    }
    catch {
        Write-Log "PsLoggedOn failed: $($_.Exception.Message)" -Level WARNING
    }
}

function Invoke-AdditionalRecon {
    param([System.Collections.ArrayList]$OpenPorts)

    Write-Log "ADDITIONAL RECONNAISSANCE" -Level HEADER

    # Traceroute
    Write-Log "Network path (traceroute)..." -Level SUBHEADER
    try {
        $tracert = tracert -d -h 15 $TargetIP 2>&1 | Select-Object -First 20
        foreach ($line in $tracert) {
            $lineStr = $line.ToString()
            if ($lineStr -match "\d+\s+(<?\d+ ms|[\*\s]+)" -or $lineStr -match "Tracing route") {
                Write-Log $lineStr -Level INFO
            }
        }
    }
    catch {
        Write-Log "Traceroute failed: $($_.Exception.Message)" -Level WARNING
    }

    # Ping for TTL-based OS guess
    Write-Log "Ping analysis (TTL-based OS detection)..." -Level SUBHEADER
    try {
        $ping = Test-Connection -ComputerName $TargetIP -Count 3 -ErrorAction Stop
        $avgTTL = ($ping | Measure-Object -Property TimeToLive -Average).Average

        Write-Log "Average TTL: $avgTTL" -Level INFO

        # TTL-based OS guessing
        if ($avgTTL -le 64 -and $avgTTL -gt 0) {
            Write-Log "TTL suggests: Linux/Unix (default TTL 64)" -Level INFO
        }
        elseif ($avgTTL -le 128 -and $avgTTL -gt 64) {
            Write-Log "TTL suggests: Windows (default TTL 128)" -Level INFO
        }
        elseif ($avgTTL -le 255 -and $avgTTL -gt 128) {
            Write-Log "TTL suggests: Network device/Solaris (default TTL 255)" -Level INFO
        }

        $avgLatency = ($ping | Measure-Object -Property ResponseTime -Average).Average
        Write-Log "Average latency: $([math]::Round($avgLatency, 2)) ms" -Level INFO
    }
    catch {
        Write-Log "Ping failed (host may block ICMP): $($_.Exception.Message)" -Level WARNING
    }

    # Check for HTTP/HTTPS title if web ports are open
    $webPorts = $OpenPorts | Where-Object { $_ -in @(80, 443, 8080, 8443, 8000, 8888) }
    if ($webPorts.Count -gt 0) {
        Write-Log "Web page title extraction..." -Level SUBHEADER
        foreach ($port in $webPorts) {
            try {
                $protocol = if ($port -in @(443, 8443)) { "https" } else { "http" }
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
                $webClient = New-Object System.Net.WebClient
                $webClient.Headers.Add("User-Agent", "Mozilla/5.0 Security-Assessment/1.0")
                $html = $webClient.DownloadString("${protocol}://${TargetIP}:${port}/")

                if ($html -match "<title>([^<]+)</title>") {
                    Write-Log "Port ${port} Page Title: $($Matches[1])" -Level SUCCESS
                }
            }
            catch {
                Write-Log "Could not extract title from port ${port}" -Level WARNING
            }
        }
    }
}

function Get-SecurityAssessment {
    param([System.Collections.ArrayList]$OpenPorts)

    Write-Log "SECURITY ASSESSMENT SUMMARY" -Level HEADER

    $findings = [System.Collections.ArrayList]::new()

    # Check for risky port exposures
    $riskyPorts = @{
        21 = "FTP (often allows anonymous access, transmits in cleartext)"
        23 = "Telnet (cleartext protocol, should never be exposed)"
        135 = "MSRPC (commonly exploited for lateral movement)"
        139 = "NetBIOS (legacy protocol, information disclosure risk)"
        445 = "SMB (high-value target for attackers, ransomware vector)"
        1433 = "MSSQL (database exposure, credential attacks)"
        1434 = "MSSQL Browser (information disclosure)"
        3306 = "MySQL (database exposure)"
        3389 = "RDP (brute force target, BlueKeep vulnerability)"
        5432 = "PostgreSQL (database exposure)"
        5900 = "VNC (often weak authentication)"
        27017 = "MongoDB (often misconfigured with no auth)"
        6379 = "Redis (often no authentication by default)"
    }

    Write-Log "Risk Assessment:" -Level SUBHEADER
    foreach ($port in $OpenPorts) {
        if ($riskyPorts.ContainsKey($port)) {
            $null = $findings.Add("HIGH RISK: Port $port - $($riskyPorts[$port])")
            Write-Log "HIGH RISK: Port $port - $($riskyPorts[$port])" -Level WARNING
        }
    }

    # Additional security observations
    if ($OpenPorts -contains 445 -and $OpenPorts -contains 3389) {
        Write-Log "CRITICAL: Both SMB (445) and RDP (3389) exposed - high attack surface" -Level ERROR
    }

    if ($OpenPorts -contains 22) {
        Write-Log "INFO: SSH/SFTP exposed - ensure strong authentication and updated software" -Level INFO
    }

    Write-Log "Recommendations:" -Level SUBHEADER
    Write-Log "1. Verify this server should be internet-facing" -Level INFO
    Write-Log "2. Implement firewall rules to restrict access by source IP" -Level INFO
    Write-Log "3. Enable MFA where possible (especially RDP)" -Level INFO
    Write-Log "4. Ensure all services are patched to latest versions" -Level INFO
    Write-Log "5. Review and remove any unnecessary exposed services" -Level INFO
    Write-Log "6. Implement network segmentation if not already in place" -Level INFO
}

#endregion

#region Main Execution

function Invoke-ServerRecon {
    Write-Banner

    Write-Host ""
    Write-Host "Starting reconnaissance against $TargetIP" -ForegroundColor White
    Write-Host "This may take several minutes depending on network conditions..." -ForegroundColor Gray
    Write-Host ""

    # Execute all recon functions
    Invoke-DNSRecon

    $openPorts = Invoke-PortScan

    if ($openPorts.Count -gt 0) {
        Invoke-BannerGrab -OpenPorts $openPorts
        Invoke-SMBRecon -OpenPorts $openPorts
    }

    Invoke-WHOISLookup
    Invoke-ShodanLookup
    Invoke-SysinternalsRecon -OpenPorts $openPorts
    Invoke-AdditionalRecon -OpenPorts $openPorts

    Get-SecurityAssessment -OpenPorts $openPorts

    # Final summary
    $endTime = Get-Date
    $duration = $endTime - $script:StartTime

    Write-Log "SCAN COMPLETE" -Level HEADER
    Write-Log "Duration: $($duration.ToString('hh\:mm\:ss'))" -Level INFO
    Write-Log "Open Ports Found: $($openPorts.Count)" -Level INFO
    Write-Log "Report saved to: $OutputPath" -Level INFO

    # Save results to file
    $script:Results | Out-File -FilePath $OutputPath -Encoding UTF8

    Write-Host ""
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Green
    Write-Host ""

    return @{
        TargetIP = $TargetIP
        OpenPorts = $openPorts
        Duration = $duration
        ReportPath = $OutputPath
    }
}

# Run the main function
Invoke-ServerRecon

#endregion
