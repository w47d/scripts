# Server Reconnaissance Toolkit

Defensive security assessment scripts for profiling exposed servers belonging to your organization.

## Scripts Included

| Script | Purpose |
|--------|---------|
| `Invoke-ServerRecon.ps1` | Full comprehensive reconnaissance |
| `Invoke-QuickCheck.ps1` | Fast initial triage (30 seconds) |
| `Invoke-BatchRecon.ps1` | Scan multiple IPs sequentially |

---

## Quick Start

### Basic Usage

```powershell
# Quick triage check
.\Invoke-QuickCheck.ps1 -TargetIP "203.0.113.50"

# Full reconnaissance
.\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50"

# With Shodan intelligence
.\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50" -ShodanAPIKey "your_api_key"
```

### Batch Scanning

```powershell
# Scan multiple IPs
.\Invoke-BatchRecon.ps1 -IPList @("203.0.113.50", "203.0.113.51", "203.0.113.52")

# Scan from file (one IP per line)
.\Invoke-BatchRecon.ps1 -IPFile "targets.txt" -OutputDirectory "C:\Reports"
```

---

## Invoke-ServerRecon.ps1 Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-TargetIP` | Yes | IP address to assess |
| `-OutputPath` | No | Custom report file path |
| `-ShodanAPIKey` | No | Shodan API key for threat intel |
| `-SkipNmap` | No | Use PowerShell-only port scanning |
| `-CustomPorts` | No | Additional ports to scan |

### Examples

```powershell
# Basic scan
.\Invoke-ServerRecon.ps1 -TargetIP "192.168.1.100"

# Custom output location
.\Invoke-ServerRecon.ps1 -TargetIP "10.0.0.50" -OutputPath "C:\Reports\server_scan.txt"

# Add custom ports to scan
.\Invoke-ServerRecon.ps1 -TargetIP "10.0.0.50" -CustomPorts @(8443, 9090, 27017)

# Full scan with Shodan
.\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50" -ShodanAPIKey "abcd1234..."

# Skip nmap (PowerShell only)
.\Invoke-ServerRecon.ps1 -TargetIP "192.168.1.100" -SkipNmap
```

---

## What Gets Checked

### Network Reconnaissance
- Reverse DNS lookup
- Forward DNS verification
- Network path (traceroute)
- Ping analysis with TTL-based OS detection

### Port Scanning
- 32 common service ports by default
- Custom ports via `-CustomPorts`
- Uses nmap when available (better accuracy)
- Falls back to PowerShell TCP scanning

### Default Ports Scanned
```
21 (FTP), 22 (SSH), 23 (Telnet), 25 (SMTP), 53 (DNS),
80 (HTTP), 110 (POP3), 111 (RPC), 135 (MSRPC), 139 (NetBIOS),
143 (IMAP), 443 (HTTPS), 445 (SMB), 465 (SMTPS), 587 (SMTP),
993 (IMAPS), 995 (POP3S), 1433 (MSSQL), 1434 (MSSQL Browser),
1521 (Oracle), 2049 (NFS), 3306 (MySQL), 3389 (RDP),
5432 (PostgreSQL), 5900 (VNC), 5985 (WinRM), 5986 (WinRM HTTPS),
6379 (Redis), 8080 (HTTP Proxy), 8443 (HTTPS Alt),
9200 (Elasticsearch), 27017 (MongoDB)
```

### Banner Grabbing
- SSH version and software identification
- HTTP/HTTPS server headers
- SSL certificate extraction (subject, issuer, SANs, validity)
- SMTP, FTP, Telnet banners
- MySQL version detection
- RDP fingerprinting via nmap scripts

### SMB Enumeration (Anonymous Only)
- NetBIOS name resolution (nbtstat)
- SMB share enumeration attempt
- OS discovery via nmap scripts
- SMB protocol version detection
- SMB signing status

### IP Intelligence
- Geolocation (ip-api.com)
- ISP and organization info
- AS number lookup
- Shodan historical data (if API key provided)

### Sysinternals Integration
- PsInfo for system information
- PsLoggedOn for user sessions
- Runs from https://live.sysinternals.com (requires WebClient service)

---

## Prerequisites

### Required
- Windows 11 / PowerShell 5.1+
- Network access to target

### Recommended
- nmap installed and in PATH ([download](https://nmap.org/download.html))
- WebClient service running (for Sysinternals): `Start-Service WebClient`
- Shodan API key ([get one free](https://account.shodan.io/register))

### Enable WebClient for Sysinternals
```powershell
# Run as Administrator
Start-Service WebClient
Set-Service WebClient -StartupType Automatic
```

---

## Output

Reports are saved as text files with timestamp:
```
recon_report_203-0-113-50_20241209_143022.txt
```

### Output Sections
1. DNS Reconnaissance
2. Port Scanning Results
3. Banner/Service Information
4. SMB Enumeration
5. WHOIS/IP Intelligence
6. Shodan Data (if API key provided)
7. Sysinternals Results
8. Security Assessment Summary
9. Recommendations

---

## Security Assessment

The script provides a risk assessment for discovered services:

| Risk Level | Ports |
|------------|-------|
| **CRITICAL** | SMB (445) + RDP (3389) exposed together |
| **HIGH** | 21 (FTP), 23 (Telnet), 445 (SMB), 3389 (RDP), 27017 (MongoDB) |
| **MEDIUM** | 139 (NetBIOS), 135 (MSRPC), 1433 (MSSQL), 3306 (MySQL) |

---

## Troubleshooting

### "nmap not found"
Install nmap from https://nmap.org/download.html and add to PATH, or use `-SkipNmap`

### "Cannot access live.sysinternals.com"
```powershell
# Enable WebDAV client
Start-Service WebClient
# Test access
Test-Path \\live.sysinternals.com\tools\
```

### Slow scanning
- Use `-SkipNmap` for faster (but less accurate) scans
- Run `Invoke-QuickCheck.ps1` for initial triage

### Corporate firewall blocking
Run from an assessment machine with unrestricted outbound access, or use a VPN egress point.

---

## Legal Notice

This toolkit is intended for authorized defensive security assessments of infrastructure owned by your organization. Ensure you have proper authorization before scanning any systems. Unauthorized scanning may violate computer crime laws.
