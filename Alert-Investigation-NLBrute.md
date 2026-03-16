# Alert Investigation: NLBrute Hacktool Detected and Active

| | |
|---|---|
| **Alert Name** | 'NLBrute' hacktool was detected and was active |
| **Alert ID** | `da5c5c376e-9ac6-4d62-80bd-3705fbd05c6f_1` |
| **Alert Time** | 2026-02-24 11:28:09 UTC |
| **Host** | `mts-dc.mts.local` |
| **Account** | `MTS\administrator` |
| **Severity** | Critical |

---

## Table of Contents

- [Investigation Summary](#investigation-summary)
- [Findings at a Glance](#findings-at-a-glance)
- [5 W's Breakdown](#5-ws-breakdown)
- [Investigation Timeline](#investigation-timeline)
- [MITRE ATT&CK Techniques](#mitre-attck-techniques)
- [Recommendations](#recommendations)
- [Indicators of Compromise](#indicators-of-compromise)

---

## Investigation Summary

On 2026-02-24 at 11:28:09 UTC, an alert was triggered for 'NLBrute' hacktool detected and active. NLBrute is a tool that combines password dictionaries with credentials leaked through data breaches to perform brute-force attacks against Remote Desktop Protocol (RDP) systems. The attacker logged on to domain controller `mts-dc.mts.local` over the local host IP `192.168.10.8` with administrator access.

The attacker executed `explorer.exe` which created the file `3.exe` (Neshta malware) in the Pictures directory, and that file spawned a second `3.exe` (NLBrute 1.2) in the Local directory. The initial `3.exe` (Neshta malware) acts as a malware dropper to deliver the initial malicious payload. `Explorer.exe` also launched the NLBrute KeyGen, activating the attacker's NLBrute license and serial cracker. The second `3.exe` then launched the NLBrute VPN to execute the NLBrute hacktool.

From here, at 2026-02-24 11:09:42 UTC, the tool initiated 1,991 connections via RDP (port 3389) to 1,991 different IPs from local host `192.168.10.8` over the course of a few minutes. The attacker then executed `explorer.exe` again and created a series of `.lnk` files. The initial `.lnk` filenames were renamed to evade defenses — from `mzw1qpnb.newcfg`, `tmp888E.tmp`, and `копия (2).lnk` to `pass1`, `user.config`, `serverlist.xml`, and `copy.lnk`.

This alert covers initial access on this host, but after additional scoping I found that the C2 IP and attacker IP were both present in the environment as early as February 18th on `mts-contractorpc1`. Additionally, LSASS was accessed and credentials could potentially have been dumped shortly after the RDP brute force, and the attacker still maintains all credentials and access at time of writing.

---

## Findings at a Glance

### Victim Host

| Field | Value |
|---|---|
| **Host** | `mts-dc.mts.local` |
| **Local IP** | `192.168.10.8` |
| **Account** | `administrator` |

### Attacker Infrastructure

| Field | Value |
|---|---|
| **Attacker IP** | `89.188.107.27` — Moscow, Russia (Citytelecom LLC) |
| **Internal IP** | `192.168.30.154` |
| **C2 IP** | `204.76.203.18` — Netherlands |
| **Attacker Device** | `VM-865624` |

---

## 5 W's Breakdown

### Who

The targeted host was `mts-dc.mts.local` (IP `192.168.10.8`). Administrator account credentials were used for initial access via Valid Accounts. The attacker IP was `89.188.107.27` and their device was named `VM-865624`.

### What

A known hacktool, NLBrute, was downloaded and activated to use MTS credentials to launch dictionary attacks against external RDP targets.

### When

| Timestamp (UTC) | Event |
|---|---|
| `2026-02-24 07:12:22` | Initial Access |
| `2026-02-24 10:53:21` | Connection to C2 |
| `2026-02-24 11:08:17` | Payload delivered |
| `2026-02-24 11:09:42` | RDP brute force begins |
| `2026-02-24 11:28:09` | Alert triggered |

### Where

The hacktool was downloaded on the domain controller `mts-dc.mts.local` using administrator credentials. The initial access IP `89.188.107.27` originates from Moscow, Russia via ISP Citytelecom LLC. The C2 server IP `204.76.203.18` is based in the Netherlands with hostname `204[.]76[.]203[.]18[.]ptr[.]pfcloud[.]network`.

### Why

It appears the attacker was taking advantage of weak credentials. Using previously obtained valid account access, the MTS network was leveraged to download and stage attacks against external hosts via RDP (port 3389).

### How

1. Attacker logged in at 07:12:22 UTC using Valid Accounts obtained from a previous password spray attack
2. The attacker quickly logged out and back in via Remote Interactive logon, then created a series of `.lnk` startup files spawned by `explorer.exe`
3. The attacker set up a listener on port 8080 and established a connection to C2 server `204.76.203.18`
4. With administrator access, the attacker created `3.exe` (Neshta Malware) and `NLBrute 1.2 x64 & VPN - KeyGen.exe` via `explorer.exe`, activating the NLBrute licensing
5. `3.exe` spawned a second `3.exe` that launched the NLBrute tool
6. NLBrute initiated over 1,991 RDP connections to 1,991 different IPs from local IP `192.168.10.8`
7. Following the brute force, `taskmgr.exe` was used to access `lsass.exe` via `OpenProcessApiCall` and `ReadProcessMemoryApiCall` — indicating a credential dump attempt
8. `servermanager.exe` created renamed files (`user.config`, `serverlist.xml`) from obfuscated originals to stage persistence artifacts

---

## Investigation Timeline

| Timestamp (UTC) | Host | Account | Event |
|---|---|---|---|
| `2026-02-24 07:12:22` | `mts-dc.mts.local` | `administrator` | Network logon from `89.188.107.27` via NTLM — `VM-865624`; follows up with Remote Interactive logon |
| `2026-02-24 07:12:59` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `banana_v001.lnk` in Startup directory |
| `2026-02-24 07:12:59` | `mts-dc.mts.local` | — | `explorer.exe` spawns `TextIntelHost.exe` |
| `2026-02-24 07:13:00` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `deskt.lnk` in Startup directory |
| `2026-02-24 07:13:02` | `mts-dc.mts.local` | `administrator` | `slhost.exe` creates `deskt.lnk` in `C:\Users\administrator\3D Objects` |
| `2026-02-24 07:13:03` | `mts-dc.mts.local` | `administrator` | `textintelhost.exe` spawns `curl.exe` — beacons to `hxxp://localhost:8080/2025` |
| `2026-02-24 07:13:12` | `mts-dc.mts.local` | `administrator` | `textintelhost.exe` creates `banana_v001.lnk` in `C:\Users\administrator\3D Objects` |
| `2026-02-24 07:13:53` | `mts-dc.mts.local` | `administrator` | `textintelhost.exe` spawns `curl.exe` — beacons to `hxxp://localhost:8080/2024` |
| `2026-02-24 10:53:21` | `mts-dc.mts.local` | N/A | Network event: `192.168.10.8:80` connects outbound to `204.76.203.18:38610` |
| `2026-02-24 11:07:47` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `windowsdefender--threat-.lnk` and `The Internet.lnk` |
| `2026-02-24 11:08:17` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `3.exe` (7,907,328 bytes) |
| `2026-02-24 11:08:30` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `Network - Shortcut.lnk` |
| `2026-02-24 11:08:36` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `NLBrute 1.2 x64 & VPN - KeyGen.exe` (2,624,512 bytes) |
| `2026-02-24 11:08:52` | `mts-dc.mts.local` | `administrator` | `explorer.exe` executes `3.exe` from `C:\Users\administrator\Pictures\3\` — `3.exe` spawns second `3.exe` |
| `2026-02-24 11:08:56` | `mts-dc.mts.local` | `administrator` | Second `3.exe` created at `C:\Users\administrator\AppData\Local\Temp\2\3582-490\3.exe` |
| `2026-02-24 11:09:42` | `mts-dc.mts.local` | `administrator` | `3.exe` initiates 1,991 RDP (port 3389) connection attempts to 1,991 unique IPs from `192.168.10.8` — all failed |
| `2026-02-24 11:09:47` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `admin.lnk` and `3.lnk` |
| `2026-02-24 11:09:51` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `pass1 - vse - i ewe - Copy.lnk` |
| `2026-02-24 11:10:16` | `mts-dc.mts.local` | `administrator` | `explorer.exe` creates `24 02 eu333 — копия (2).lnk` |
| `2026-02-24 11:11:52` | `mts-dc.mts.local` | `administrator` | `explorer.exe` spawns `taskmgr.exe` |
| `2026-02-24 11:11:54` | `mts-dc.mts.local` | `administrator` | `taskmgr.exe` accesses `lsass.exe` — `OpenProcessApiCall` |
| `2026-02-24 11:12:23` | `mts-dc.mts.local` | `system` | `winlogon.exe` spawns `logonui.exe` |
| `2026-02-24 11:12:24` | `mts-dc.mts.local` | `administrator` | `servermanager.exe` creates `user.config` (renamed from `mzw1qpnb.newcfg`) and `serverlist.xml` (renamed from `tmp888E.tmp`) |
| `2026-02-24 11:12:24` | `mts-dc.mts.local` | `system` | `csrss.exe` spawns `slhost.exe` from `C:\Users\administrator\3D Objects` |
| `2026-02-24 11:12:42` | `mts-dc.mts.local` | `administrator` | `taskmgr.exe` accesses `lsass.exe` — `ReadProcessMemoryApiCall` |

---

## MITRE ATT&CK Techniques

### Initial Access

| Technique | ID | Description |
|---|---|---|
| Valid Accounts: Domain Accounts | [T1078.002](https://attack.mitre.org/techniques/T1078/002/) | Attacker authenticated using previously compromised administrator credentials |

### Execution

| Technique | ID | Description |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | Administrator executed `3.exe` (Neshta dropper) via `explorer.exe` |
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Curl used to beacon to localhost port 8080 staging infrastructure |

### Persistence

| Technique | ID | Description |
|---|---|---|
| Boot or Logon Autostart: Startup Folder | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Multiple `.lnk` files created in `\Microsoft\Windows\Start Menu\Programs\Startup\` |

### Defense Evasion

| Technique | ID | Description |
|---|---|---|
| Masquerading: Rename System Utilities | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) | Config files renamed from obfuscated names (`mzw1qpnb.newcfg`, `tmp888E.tmp`) to blend in |
| Indicator Removal | [T1070](https://attack.mitre.org/techniques/T1070/) | `.lnk` filenames disguised to appear as legitimate Windows components (`windowsdefender--threat-.lnk`) |

### Credential Access

| Technique | ID | Description |
|---|---|---|
| LSASS Memory | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | `taskmgr.exe` used to access `lsass.exe` via `OpenProcessApiCall` and `ReadProcessMemoryApiCall` |

### Discovery

| Technique | ID | Description |
|---|---|---|
| Network Service Discovery | [T1046](https://attack.mitre.org/techniques/T1046/) | NLBrute initiated 1,991 RDP connection attempts across 1,991 unique external IPs |

### Command and Control

| Technique | ID | Description |
|---|---|---|
| Application Layer Protocol | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Outbound connection established to C2 `204.76.203.18:38610` |
| Non-Standard Port | [T1571](https://attack.mitre.org/techniques/T1571/) | Localhost listener established on port 8080 for staging |

### Impact

| Technique | ID | Description |
|---|---|---|
| Network Denial of Service / Resource Hijacking | [T1496](https://attack.mitre.org/techniques/T1496/) | MTS network infrastructure used to launch 1,991 external RDP brute force attempts |

---

## Recommendations

1. **Isolate `mts-dc.mts.local` immediately** to prevent further attacker access or lateral movement
2. **Reset KRBTGT twice** and reset credentials for all domain users — LSASS access indicates credentials may have been dumped
3. **Re-image `mts-dc.mts.local`** from a known-good backup
4. **Consider reducing exposed ports** to reduce the overall attack surface
5. **Consider changing the default RDP port** (TCP 3389) via the Windows Registry to reduce automated scanning exposure
6. **Enable secure redirection** for remote desktop sessions
7. **Enforce strong, unique passwords** and multi-factor authentication (MFA) for all accounts
8. **Consider blocking ingress and egress traffic** to the `204.76.203.0/24` IP block
9. **Ensure detection rules are in place** for Neshta malware signatures and NLBrute behavioural indicators

---

## Indicators of Compromise

### Attacker Infrastructure

| Type | Value | Notes |
|---|---|---|
| IP | `89.188.107.27` | Moscow, Russia — Citytelecom LLC (Initial Access) |
| IP | `192.168.30.154` | Internal — Initial Access |
| IP | `204.76.203.18` | Netherlands — C2 server |
| Hostname | `204.76.203.18.ptr.pfcloud.network` | C2 PTR record |
| Device Name | `VM-865624` | Attacker device |

### Malicious URLs

| Indicator | Notes |
|---|---|
| `hxxp://localhost:8080/2024` | Local staging beacon |
| `hxxp://localhost:8080/2025` | Local staging beacon |

### File Hashes (SHA-256)

| File | Hash |
|---|---|
| `Slhost.exe` | `10aa650f708dd5752662ddb796f01c9cd3d5c040e760380ffbf089578a483807` |
| `TextIntelHost.exe` | `642606c78b93ee5292be54cfed2247b79e6db75541ae037bdcab287b19a0d34d` |
| `banana_v001.lnk` | `df9d1c9badc877f2521e9d72e2483e5533bd9e57024de279948205500c1b4134` |
| `deskt.lnk` | `499e866a83efe9b2d43ebfa0ada7f637e99ac62f522937799e89e15542b06365` |
| `3.exe` (Neshta dropper) | `3cb6ceb5db9f3f47112b2352f04bac812ef63d8c9cddf70e5bf975d75918567c` |
| `NLBrute 1.2 x64 & VPN.exe` / `3.exe` (NLBrute) | `6e0dcbb9710aced2a00c8863b2fe295a9e7677a07d6fc4bbb100714d2ddf0d4d` |
| `Neshta` / `._cache_file.exe` / `NLBrute 1.2 x64 & VPN - KeyGen.exe` | `f824fdc666630ccb179d9086b79783e3ede76e4392a5edfdd20d93b7259ae061` |
| `windowsdefender--threat-.lnk` | `42d87813ff5a0c2641274b89ea4012464e497f6c3a54b21658c8ad71c46b2e45` |
| `Network - Shortcut.lnk` | `9a78fab2adc78e8f43f0a8e4b05b7f241d77cf36d03860da2015df9e98b5a1fd` |
| `24 02 eu333 — копия (2).lnk` | `41fc0a3f42b0ed883a71e173fb6a0b90389f6c389d651439a234b15218e84764` |
| `3.lnk` (Variant 1) | `34999c77c7541655a381de60c03455e0c8735a455ede1171a984909c8d54e003` |
| `3.lnk` (Variant 2) | `e48d78331c7e88c791a4a5b8ad4cd6fef71c088b8fdb427183ffeaebb8e3c295` |
| `pass1 - vse - i ewe - Copy.lnk` | `cac14a65a90e6dd9ffb7f8c7a057ca9ac2a5c94d697d662fc83e02f3b37013af` |
| `user.config` (renamed from `mzw1qpnb.newcfg`) | `9a164994c27bd10d02a0d1bb1b989326012c45ff0c458ba331a4d8717a268ba2` |
| `Serverlist.xml` (renamed from `tmp888E.tmp`) | `5157d38b734ee1e2b1f16edf5972bed1985e865edc8df14c940f403649b697f8` |

---

*Report authored by David Gilmore · 2026-02-24 · Severity: Critical*
