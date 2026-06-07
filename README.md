```
               ░░░░░░░░░
          ░░░░▒▒▒▒▒▒▒▒▒▒▒░░░░
       ░░░▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒░░░
     ░░░▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒░░░
    ░░▒▒▒▒▓▓▓▓███████████▓▓▓▓▒▒▒▒░░
   ░░▒▒▒▓▓▓▓███▒▒▒▒▒▒▒▒▒███▓▓▓▓▒▒▒░░
  ░░▒▒▒▓▓▓███▒▒▒░░░░░░░▒▒▒███▓▓▓▒▒▒░░
 ░░▒▒▒▓▓▓██▒▒▒░░░░▓▓▓░░░░▒▒▒██▓▓▓▒▒▒░░
 ░░▒▒▒▓▓███▒▒░░░▓▓▓◉▓▓▓░░░▒▒███▓▓▒▒▒░░
 ░░▒▒▓▓▓██▒▒▒░░▓▓◉◉◉◉◉▓▓░░▒▒▒██▓▓▓▒▒░░
 ░░▒▒▒▓▓███▒▒░░░▓▓▓◉▓▓▓░░░▒▒███▓▓▒▒▒░░
 ░░▒▒▒▓▓▓██▒▒▒░░░░▓▓▓░░░░▒▒▒██▓▓▓▒▒▒░░
  ░░▒▒▒▓▓▓███▒▒▒░░░░░░░▒▒▒███▓▓▓▒▒▒░░
   ░░▒▒▒▓▓▓▓███▒▒▒▒▒▒▒▒▒███▓▓▓▓▒▒▒░░
    ░░▒▒▒▒▓▓▓▓███████████▓▓▓▓▒▒▒▒░░
     ░░░▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒░░░
       ░░░▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒░░░
          ░░░░▒▒▒▒▒▒▒▒▒▒▒░░░░
               ░░░░░░░░░
```

```
 ┌──(w47d㉿recon)─[~/scripts]
 └─$ ls -la
   drwxr-xr-x  PowerShell defensive recon toolkit
   -rwxr-xr-x  Profile exposed servers. Gather context. Stay legal.
```

---

## > whoami

A small set of **PowerShell reconnaissance scripts** for profiling internet-exposed
servers that belong to *your* organization. Built for defenders who need to answer
"what does this box look like from the outside?" without spinning up a full pentest rig.

```
[+] nmap-backed port scans (with PS fallback)
[+] Banner grabbing on the usual suspects
[+] Anonymous SMB enumeration
[+] DNS / WHOIS / Shodan intel
[+] Sysinternals live tools integration
[+] RDP / SSH fingerprinting
```

---

## > arsenal

| Script | Role | Speed |
|---|---|---|
| [`Invoke-QuickCheck.ps1`](./Invoke-QuickCheck.ps1)     | Fast triage — is this box ugly?         | ~30s    |
| [`Invoke-ServerRecon.ps1`](./Invoke-ServerRecon.ps1)   | Full deep-dive on a single target       | minutes |
| [`Invoke-BatchRecon.ps1`](./Invoke-BatchRecon.ps1)     | Loop a target list through ServerRecon  | varies  |

Full docs and parameter reference: [**README-ServerRecon.md**](./README-ServerRecon.md)

---

## > quickstart

```powershell
# Triage — 30 second sanity check
.\Invoke-QuickCheck.ps1 -TargetIP "203.0.113.50"

# Full recon
.\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50"

# With Shodan intel
.\Invoke-ServerRecon.ps1 -TargetIP "203.0.113.50" -ShodanAPIKey "your_key"

# Batch mode
.\Invoke-BatchRecon.ps1 -IPFile "targets.txt" -OutputDirectory "C:\Reports"
```

---

## > risk matrix

The scanner flags exposed services by severity:

```
  ╔═══════════╦══════════════════════════════════════════════════╗
  ║  CRITICAL ║  SMB (445) + RDP (3389) on the same box          ║
  ║  HIGH     ║  21 / 23 / 445 / 3389 / 27017                    ║
  ║  MEDIUM   ║  139 / 135 / 1433 / 3306                         ║
  ╚═══════════╩══════════════════════════════════════════════════╝
```

---

## > requirements

```
[*] Windows 11 / PowerShell 5.1+
[*] nmap on PATH                 (optional, recommended)
[*] WebClient service running    (for Sysinternals live tools)
[*] Shodan API key               (optional, free tier works)
```

---

## > legal

```
  ┌─────────────────────────────────────────────────────────────┐
  │  Run this only against systems you are authorized to test.  │
  │  Unauthorized scanning may violate computer-crime laws in   │
  │  your jurisdiction. You own the consequences.               │
  └─────────────────────────────────────────────────────────────┘
```

---

```
 [w47d] ──> defensive tooling // built for blue teams that think red
```
