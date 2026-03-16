# Incident Report: LOLBIN Abuse and Domain Controller Compromise

| | |
|---|---|
| **Report Title** | LOLBIN Abuse and Domain Controller Compromise |
| **Date of Report** | 2026-02-15 |
| **Reported By** | David Gilmore |
| **Severity Level** | Critical — Domain Controller compromised, LSASS credentials dumped, domain-wide impact assumed |
| **Alert ID** | `da73aafdef-71a1-4c23-a45c-90bbf57cd5c8_1` |
| **Alert Time** | 2026-01-29 05:27:55 UTC |

---

## Table of Contents

- [Executive Summary](#executive-summary)
- [Findings at a Glance](#findings-at-a-glance)
- [Investigation Timeline](#investigation-timeline)
- [5 W's Breakdown](#5-ws-breakdown)
- [MITRE ATT&CK Techniques](#mitre-attck-techniques)
- [Impact Assessment](#impact-assessment)
- [Recommendations](#recommendations)
- [Indicators of Compromise](#indicators-of-compromise)

---

## Executive Summary

On January 18th, 2026 at 21:14:20 UTC, an external attacker successfully gained unauthorized access to the company domain controller (**mts-dc.mts.local**) through credential access to the **Administrator** account, achieved by exploiting weak credentials and an inadequate password policy. Access originated from IP `70.49.218.98` and initial access to the Administrator account was used to gain foothold across the domain, system, and other valid accounts.

On January 28, 2026 at 23:50:51 UTC, the attacker pivoted to the CEO's account, **zach.balrog**. The attacker downloaded and executed a malicious file (`Project2026 {dpfdngwebys=).exe`) — in actuality `gorelo.dll` — installing Gorelo RMM, a legitimate remote management tool not previously present in the MTS environment. `GoreloRemoteInstaller.exe` spawned a chain of processes that triggered a Microsoft Defender LOLBIN alert via `msiexec.exe` and `rundll32.exe`, ultimately downloading a second Remote Access Tool: **ScreenConnect**, which was used to maintain persistence and evade discovery.

On January 29, 2026 at 21:45:31 UTC, the attacker pivoted to the **Administrator** account on contractor device **mts-contractorpc1**. The attacker ran a network scan to identify systems, users, accounts, groups, and other credentials. In addition, they deleted Microsoft OneDrive backup directories and gained access to browser-based payment information and saved passwords. A known info-stealer, `Wfo8KJM.exe`, was downloaded from a malicious Cloudflare URL and executed, subsequently contacting external Command and Control servers. The attacker logged on and off over two weeks, stealing passwords and credentials from any users who also logged on during this period. The attacker maintained persistence through the first week of February, though no additional malicious activity was observed after that point.

---

## Findings at a Glance

### Victim Hosts

| Host | Role |
|---|---|
| `mts-dc.mts.local` | Domain Controller — primary target |
| `mts-contractorpc1` | Contractor workstation |
| `mts-contractorpc2` | Contractor workstation |
| `mts-honeypot` | Honeypot system |

### Victim Accounts

`administrator` · `system` · `zach.balrog` · `contractor` · `root`

### Initial Access Windows

| Timestamp (UTC) | Event |
|---|---|
| `2026-01-18 21:14:20` | First attacker login |
| `2026-01-28 23:50:51` | Pre-alert return access |

---

## Investigation Timeline

### 2026-01-18

| Time (UTC) | Event |
|---|---|
| `21:14:20` | Login from `70.49.218.98` to **mts-dc.mts.local** on the **administrator** account |

---

### 2026-01-28 — Host: `mts-dc.mts.local` · Account: `zach.balrog`

| Time (UTC) | Event |
|---|---|
| `23:50:51` | Network login from `70.49.218.98` (`DESKTOP-6KVS52N`) to **mts-dc.mts.local** on **zach.balrog** |
| `23:52:01` | `Project2026 {dpfdngwebys=).exe` downloaded via `msedge.exe` from `104.18.21.226` (Cloudflare — 19 VirusTotal reports) |
| `23:52:14` | `svchost.exe -k netsvcs -p -s BITS` launched |
| `23:52:46` | `explorer.exe` executes `Project2026 {dpfdngwebys=).exe` from `zach.balrog\Downloads\` |
| `23:52:54–23:53:51` | PowerShell execution chain — Gorelo RMM installed, 70 DLLs created (see below) |
| `23:54:08` | PowerShell SID enumeration: `$computerName=$env:COMPUTERNAME; foreach SID/` |
| `23:54:11` | VC++ redistributable downloaded from `hxxps://aka[.]ms/vs/17/release/vc_redist.$Architecture.exe` |

**PowerShell Execution Chain (23:52:54–23:53:51)**

```
PowerShell: Get-Package gorelo agent -ErrorAction Ignore
  → 600c23d50c6ee4462ecb200a47f6b627[.]r2[.]cloudflarestorage[.]com

PowerShell: -NoProfile -ExecutionPolicy Unrestricted -File
  C:\Users\zach.balrog\AppData\Local\Temp\installgorelo.ps1

gorelo_rmm_setup.zip extracted → gorelo_rmm_setup.exe executed

File created:
  C:\Program Files\Gorelo\Agent\RMMAgent\Gorelo.RemoteManagement.Agent\
  Gorelo.RemoteManagement.Agent.exe (PID 2596)

PowerShell spawns gorelo.remotemanagement.agent.exe → creates 70 DLLs
```

---

### 2026-01-29 — Host: `mts-dc.mts.local` · Account: `system`

| Time (UTC) | Event |
|---|---|
| `05:27:54` | PowerShell executes Gorelo script, spawns `msiexec.exe` |
| `05:27:55` | `msiexec.exe` contacts Primary C2 — downloads and installs ScreenConnect |
| `05:27:55` | `msiexec.exe` spawns `rundll32.exe` (SysWOW64) and `ScreenConnect.exe` |
| `05:27:55` | `rundll32.exe` executes ScreenConnect installer DLL from `C:\Windows\Installer\MSI53BC.tmp` |
| `05:28:05` | `services.exe` spawns `ScreenConnect.ClientService.exe` — connects to Secondary C2 (`relay[.]gregmayerview[.]online`) |
| `05:30:46` | ScreenConnect launches PowerShell — tampers with power and screen lock settings |

**ScreenConnect Power/Lock Tampering (05:30:46)**

```powershell
powercfg ... SUB_BUTTONS LIDACTION 0         # Disable lid close action
powercfg ... SUB_VIDEO VIDEOIDLE 0           # Disable screen timeout
reg.exe  ... ScreenSaverIsSecure /d 0        # Disable screensaver lock
reg.exe  ... ScreenSaveActive /d 0           # Disable screensaver
```

---

### 2026-01-29 — Host: `mts-contractorpc1` · Account: `administrator`

| Time (UTC) | Event |
|---|---|
| `21:45:31` | `explorer.exe` spawns `cmd.exe` — begins OneDrive backup deletion |
| `21:46:38` | `explorer.exe` creates `Advanced_IP_Scanner_2.5.4594.1.exe` |
| `21:46:58–21:47:40` | IP and port enumeration across `192.168.10.0/24` subnet |
| `21:48:04–21:49:51` | `cmd.exe` executes `net user`, `net1 user`, `net user /domain` — domain account enumeration |
| `21:55:39–21:58:56` | `msedge.exe` accesses browser wallet HTML files: `shopping`, `bnpl`, `mini-wallet`, `tokenized-card`, `wallet-crypto` |
| `21:59:18` | `msedge.exe` downloads `Unconfirmed 647463.crdownload` — renamed to `Wfo8KJM.exe` (known info-stealer) |
| `21:59:39` | `Wfo8KJM.exe` targets browser **Login Data** credential store |
| `21:59:50` | `Wfo8KJM.exe` beacons to `telegram.me`, `kec[.]beznervov[.]com`, `c[.]pki[.]goog`, `ocsp[.]godaddy[.]com` |

**OneDrive Backup Deletion Commands**

```cmd
cmd.exe /q /c del /q "C:\Users\administrator\AppData\Local\Microsoft\OneDrive\Update\OneDriveSetup.exe"
cmd.exe /q /c del /q "C:\Users\administrator\AppData\Local\Microsoft\OneDrive\StandaloneUpdater\OneDriveSetup.exe"
cmd.exe /q /c rmdir /s /q "C:\Users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013\amd64"
cmd.exe /q /c rmdir /s /q "C:\Users\administrator\AppData\Local\Microsoft\OneDrive\19.043.0304.0013"
```

---

### 2026-01-30 – 2026-02-11 — Host: `mts-dc.mts.local` · Account: `system`

| Activity | Detail |
|---|---|
| ScreenConnect persistence | `ScreenConnect.WindowsClient.exe "RunRole" "10a37ba5-1580-47ad-a623-4a6a2691a388" "System"` executes every 20 minutes |
| LSASS access | ScreenConnect accesses `lsass.exe` on Jan 29, Feb 1, Feb 5, Feb 10, Feb 11 |
| Attacker resurfaces | Returns under `DESKTOP-6KVS52N` on Feb 6, 2026 |

---

## 5 W's Breakdown

### Who

| Role | Details |
|---|---|
| **Victim Hosts** | `mts-dc.mts.local`, `mts-contractorpc1`, `mts-contractorpc2`, `mts-honeypot` |
| **Victim Accounts** | `administrator`, `system`, `zach.balrog`, `contractor`, `root` |
| **Attacker IPs** | `70.49.218.98` (Canada — Fixed Line ISP), `185.236.200.246` (USA — VPN) |
| **Attacker Device** | `DESKTOP-6KVS52N` |

### What

- Initial access from a remote IP onto the network due to weak credentials
- Downloaded and executed `Project2026 {dpfdngwebys=).exe`, which installed Gorelo RMM
- Gorelo RMM used the LOLBIN `msiexec.exe` to install a second RMM, ScreenConnect
- Both RMM tools leveraged to conduct ongoing malicious activity across the environment

### When

| Timestamp (UTC) | Event |
|---|---|
| `2026-01-18 21:14:20` | Initial Access |
| `2026-01-28 23:50:51` | Pre-alert return access |
| `2026-01-28 23:52:46` | `Project2026 {dpfdngwebys=).exe` executed |
| `2026-01-29 05:27:55` | `msiexec.exe` downloads and installs ScreenConnect |
| `2026-01-30 – 2026-02-11` | ScreenConnect persistence loop active |

### Where

- **Victim Accounts:** `zach.balrog`, `system`, `administrator`, `contractor`, `root`
- **Victim Hosts:** `mts-dc.mts.local`, `mts-contractorpc1`, `mts-contractorpc2`, `mts-honeypot`
- **Attacker IPs:** `70.49.218.98` (Fixed Line ISP), `185.236.200.246` (VPN)
- **Attacker Host:** `DESKTOP-6KVS52N`

### Why

These key events lead to a high-confidence assessment that the attacker's likely end goal was a ransomware attack:

- The attacker quietly deleted OneDrive directories in an attempt to remove any cloud backups
- The attacker was observed accessing `msedge.exe` HTML files that contain financial information
- The attacker targeted a file named **Login Data**, which stores credentials for Chrome and Microsoft Edge
- Following credential access, the attacker downloaded `Wfo8KJM.exe` — a known info-stealer designed to secretly collect sensitive information from an infected device and exfiltrate it to a remote server controlled by cybercriminals
- The attacker then reached out to several remote servers with no legitimate reason to be present in the MTS environment, one of them (`kec[.]beznervov[.]com`) being confirmed malicious
- Simultaneously, ScreenConnect accessed `lsass.exe` multiple times over a 14-day period on the Domain Controller (`mts-dc.mts.local`) using `system` credentials

### How

1. On January 18th, 2026, the Domain Controller (`mts-dc.mts.local`) was accessed using administrator credentials from unknown IP `70.49.218.98` — initial access achieved via weak credentials
2. Attacker returns on January 28th and logs in via `70.49.218.98` (`DESKTOP-6KVS52N`) as `zach.balrog`
3. Attacker downloads and executes `Project2026 {dpfdngwebys=).exe`, which executes `installgorelo.ps1`
4. Gorelo RMM is installed; it executes `00000000-0000-0000-0000-000000000000-execute.ps1`, which spawns `msiexec.exe`
5. `msiexec.exe` contacts the Primary C2 to retrieve ScreenConnect, and also spawns `rundll32.exe`
6. `services.exe` spawns `ScreenConnect.ClientService.exe`, which connects back to the Secondary C2
7. ScreenConnect accesses `lsass.exe` multiple times between January 29th and February 11th
8. On January 29th at 21:45:31, the attacker conducts hands-on network and user enumeration
9. The attacker deletes OneDrive backup directories
10. The attacker accesses `msedge.exe` HTML files containing financial information
11. `Wfo8KJM.exe` is downloaded and immediately targets the browser `Login Data` credential store
12. `Wfo8KJM.exe` beacons out to attacker infrastructure — likely exfiltrating collected credentials

---

## MITRE ATT&CK Techniques

### Initial Access

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Attacker logged in using weak credentials on the Administrator account |

### Execution

| Technique | ID | Description |
|---|---|---|
| PowerShell | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Executed scripts to install RMM tools (`installgorelo.ps1`, `execute.ps1`) |
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User executed disguised malware (`Project2026 {dpfdngwebys=).exe`) |
| System Binary Proxy: Msiexec | [T1218.007](https://attack.mitre.org/techniques/T1218/007/) | Installed ScreenConnect via `msiexec.exe` |
| System Binary Proxy: Rundll32 | [T1218.011](https://attack.mitre.org/techniques/T1218/011/) | Executed installer DLL via `rundll32.exe` |

### Persistence

| Technique | ID | Description |
|---|---|---|
| Remote Access Software | [T1219](https://attack.mitre.org/techniques/T1219/) | Deployed Gorelo RMM and ScreenConnect for persistent remote access |

### Defense Evasion

| Technique | ID | Description |
|---|---|---|
| Masquerading | [T1036.005](https://attack.mitre.org/techniques/T1036/005/) | `GoreloInstaller.dll` disguised as `Project2026.exe` |
| Modify Registry | [T1112](https://attack.mitre.org/techniques/T1112/) | Disabled screensaver security via registry edits |
| BITS Jobs | [T1197](https://attack.mitre.org/techniques/T1197/) | Used BITS service to download payloads |
| Impair Defenses | [T1562.001](https://attack.mitre.org/techniques/T1562/001/) | Removed screen lock protections |
| Power Settings | [T1653](https://attack.mitre.org/techniques/T1653/) | Disabled sleep and lid close actions via `powercfg` |

### Credential Access

| Technique | ID | Description |
|---|---|---|
| LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | ScreenConnect accessed `lsass.exe` on the Domain Controller 5 times over 14 days |
| Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | `Wfo8KJM.exe` targeted the browser `Login Data` credential store |

### Discovery

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | Scanned `192.168.10.0/24` subnet with Advanced IP Scanner |
| Account Discovery: Domain Account | [T1087.002](https://attack.mitre.org/techniques/T1087/002/) | Enumerated domain accounts via `net user /domain` and `net1 user /domain` |

### Collection

| Technique | ID | Description |
|---|---|---|
| Data from Local System | [T1005](https://attack.mitre.org/techniques/T1005/) | Accessed browser wallet and payment data HTML files via `msedge.exe` |

### Command and Control

| Technique | ID | Description |
|---|---|---|
| Application Layer Protocol | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | C2 communications via `kec[.]beznervov[.]com` |
| Web Service | [T1102](https://attack.mitre.org/techniques/T1102/) | C2 via `telegram.me` |
| Ingress Tool Transfer | [T1105](https://attack.mitre.org/techniques/T1105/) | Downloaded malware and RMM tools via browser |

### Impact

| Technique | ID | Description |
|---|---|---|
| Inhibit System Recovery | [T1490](https://attack.mitre.org/techniques/T1490/) | Deleted OneDrive directories to prevent backup-based recovery |

---

## Impact Assessment

The domain controller and system accounts were compromised, violating the **Confidentiality** and **Integrity** of MTS infrastructure.

### Compromised Data

| Data Type | Source |
|---|---|
| Browser-saved payment information | Edge wallet HTML files (`shopping`, `bnpl`, `tokenized-card`, etc.) |
| Browser-saved login credentials | Browser `Login Data` file |
| Domain credentials | LSASS memory dump on Domain Controller |

Data exfiltration is not directly confirmed; however, it is highly likely based on `Wfo8KJM.exe` contacting attacker infrastructure immediately after accessing credential files.

**This is a Critical level incident. Immediate responsive action is required to prevent further impact.**

---

## Recommendations

1. **Immediately isolate** `mts-dc.mts.local`, `mts-contractorpc1`, and `mts-contractorpc2` from the network
2. **Take forensic snapshots** of compromised device states for deeper analysis, then restore from known-good backups
3. **Perform a full password reset** on all accounts. Review password hygiene and enforce complex password policies with MFA for all users at minimum
4. **Implement the principle of least privilege** — users should only retain access essential to their role. Non-admin accounts should not be able to access the Domain Controller
5. **Block all attacker-related domains** to prevent continued C2 access (see Indicators of Compromise)
6. **Create an application allow list** to ensure only permissible applications can be installed or executed on company systems
7. **Coordinate with Detection Engineering** to create alerts for: `ExecutionPolicy Bypass`, mass DLL creation events, and unauthorized `lsass.exe` access
8. **Inform stakeholders** of potential theft of sensitive information so they can coordinate with GRC to assess exposure and risk
9. **Coordinate with legal and compliance** to determine if regulatory notification is required based on the potential data exposure

---

## Indicators of Compromise

### Attacker Infrastructure

| Type | Value | Notes |
|---|---|---|
| IP | `70.49.218.98` | Canada — Fixed Line ISP |
| IP | `185.236.200.246` | USA — VPN |
| IP | `104.18.21.226` | Cloudflare — payload download (19 VirusTotal reports) |
| Device Name | `DESKTOP-6KVS52N` | Attacker host |

### Malicious Domains and URLs

| Indicator | Notes |
|---|---|
| `hxxps://server[.]gregmayerview[.]online` | Primary C2 — NameCheap registrar, created 2026-01-10, Cloudflare hosted, cert expiry 2026-04-11 |
| `relay[.]gregmayerview[.]online` | Secondary C2 — 1Gservers hosted |
| `600c23d50c6ee4462ecb200a47f6b627[.]r2[.]cloudflarestorage[.]com` | Gorelo payload delivery — created 2026-01-06, cert expiry 2026-04-06 |
| `kec[.]beznervov[.]com` (`104.21.24.39`) | Confirmed malicious C2 — Cloudflare, created 2025-12-14, cert expiry 2026-03-14 |
| `telegram[.]me` | Info-stealer exfiltration channel |

**Associated Legitimate Domains**

| Domain | Purpose |
|---|---|
| `ocsp[.]godaddy[.]com` | Certificate validation |
| `c[.]pki[.]goog` | Certificate validation |

### File Hashes (SHA-256)

| File | Hash |
|---|---|
| `GoreloInstaller.dll` (`Project2026/gorelo.dll`) | `26348f583c4ad9ceb21e53b262f2176bfccd3523aa539aa371a517728ffc2c94` |
| `Gorelo.RemoteManagement.Shell.dll` | `1e2557551bea58e54d7a8c267bcad212a00e8f1356e0fb2057887a65ce6627e3` |
| `shmbf.exe` / `Wfo8KJM.exe` (info-stealer) | `66ad70995be6ac7dad8166d2059ec0d221bc83b5293b06b7c17149c5b9973724` |
| `Advanced_IP_Scanner_2.5.4594.1.exe` | `26d5748ffe6bd95e3fee6ce184d388a1a681006dc23a0f08d53c083c593c193b` |
| `ScreenConnect.exe` | `b80d07610b81bddb3d7f30a207a2e134b559e06b8440598a926f3a9c1d439218` |
| `ScreenConnect.exe` (alt) | `f048400c23add8c75abe189393d33c873c02c74eeaf43d47b950c8d643763b35` |
| `msiexec.exe` (LOLBIN) | `8cd926202f31b6a73b2f4c557d77d2725d25cc68822284845eff893a2c90597` |

---

*Report authored by David Gilmore · 2026-02-15 · Severity: Critical*
