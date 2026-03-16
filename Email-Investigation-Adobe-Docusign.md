# Email Investigation: Adobe Partnership Discussion — Trojanized DocuSign Infostealer

| | |
|---|---|
| **Investigation Type** | Email / Endpoint |
| **Date of Report** | 2025-12-15 |
| **Reported By** | David Gilmore |
| **Severity** | High |
| **Host** | `MTS-Contractor-PC2` (`10.21.18.72`) |
| **Timeframe** | 2025-12-14 19:43:17 UTC – 2025-12-15 17:39:25 UTC |

---

## Table of Contents

- [Investigation Summary](#investigation-summary)
- [Email Findings](#email-findings)
- [5 W's Breakdown](#5-ws-breakdown)
- [Investigation Timeline](#investigation-timeline)
- [MITRE ATT&CK Techniques](#mitre-attck-techniques)
- [Recommendations](#recommendations)
- [Indicators of Compromise](#indicators-of-compromise)

---

## Investigation Summary

On December 14, 2025 at 19:43:17 UTC and December 15, 2025 at 09:37:12 UTC, `inquiry@mydfir.com` received two separate malicious emails soliciting an Adobe partnership, likely targeting content creators. The email body contained a fake DocuSign page requesting users to download an application with invitation code `ABEC2-OBJ29`. A trojanized `DocuSign_PackageInstaller.exe` was executed on `MTS-Contractor-PC2`, masquerading as a legitimate installer. Within seconds of execution, the binary staged numerous .NET and WebView2-related DLLs into the user's AppData directory, indicating bulk extraction from an embedded payload.

The first DLL written was `WebView2Loader.dll`, followed immediately by a high-volume burst of framework and runtime libraries — consistent with automated payload staging. A `netcore.ionic.zip` file observed shortly after was identified as a supporting resource for the `Ionic.Zip` library, not the primary payload container.

An unsigned secondary payload (`index.exe.tmp`) was subsequently renamed to `index.exe` and executed. This process injected code into Microsoft Edge, created remote threads, and accessed browser credential storage files (`Login Data`, `Web Data`) to decrypt saved credentials. Microsoft Defender detected the activity based on behavior, even though the initial installer and supporting libraries were not flagged by reputation-based scanning (VirusTotal).

No evidence of persistence mechanisms was observed, indicating the malware operated as a fast, memory-centric infostealer.

---

## Email Findings

### First Email

| Field | Value |
|---|---|
| **Time** | 2025-12-14 19:43:17 UTC |
| **Mail Server** | `mail.kakao.com` (flagged malicious — VirusTotal) |
| **Sender** | `david.adobe@daum.net` |
| **Recipient** | `inquiry@mydfir.com` |
| **Subject** | Adobe partnership discussion |
| **SPF** | Softfail |
| **DKIM** | None |
| **DMARC** | BestGuessPass |

### Second Email

| Field | Value |
|---|---|
| **Time** | 2025-12-15 09:37:12 UTC |
| **Mail Server** | `mail.kakao.com` |
| **Sender** | `david.adobe@daum.net` |
| **Recipient** | `inquiry@mydfir.com` |
| **Subject** | RE: Re: Adobe partnership discussion |
| **SPF** | Softfail |
| **DKIM** | None |
| **DMARC** | BestGuessPass |

### Decoded Email Body — First Email (2025-12-14)

> *"Hope everything's going smoothly. Reaching out on behalf of Adobe. Recently came across your content, and it was genuinely enjoyable. Your videos feel natural, and it's clear that you've created a solid connection with your audience.*
>
> *At Adobe, we enjoy collaborating with creators who value quality. Your channel caught our attention because of your creative direction and the way you engage viewers. It feels like a great fit with how we like to work — authentic and focused on real value.*
>
> *We'd love to talk about a potential collaboration... We're very flexible, and always aim to build partnerships around what feels most authentic for the creator.*"
>
> — Adobe Partnerships Team

### Decoded Email Body — Second Email (2025-12-15)

The follow-up email directed the recipient to download an application from `hxxps://docu[.]signtools[.]app` and enter invitation code `ABEC2-OBJ29` to access a fake partnership agreement. The email instructed the recipient to fill in personal information including a shipping address and digitally sign the agreement through the application.

---

## 5 W's Breakdown

### Who

- **Recipient:** `inquiry@mydfir.com`, `MTS-Contractor-PC2`
- **Sender:** `david.adobe@daum.net` via `mail.kakao.com`

### What

A malicious email campaign posed as an Adobe brand partnership offer targeting content creators. A trojanized installer, `DocuSign_PackageInstaller.exe`, was executed. The installer decompressed 62 .NET and WebView2-related DLLs and launched a secondary payload, `index.exe`, which injected code into Microsoft Edge and targeted browser credential storage.

### When

| Timestamp (UTC) | Event |
|---|---|
| `2025-12-14 19:43:17` | First malicious email received |
| `2025-12-15 09:37:12` | Second malicious email received |
| `2025-12-15 17:37:24` | `DocuSign_PackageInstaller.exe` manually executed on `MTS-Contractor-PC2` |
| `2025-12-15 17:39:25` | Last observed malicious activity |

### Where

The emails were delivered to `inquiry@mydfir.com`. Malicious installer download and execution activity took place on `MTS-Contractor-PC2` (`10.21.18.72`).

### Why

After receiving the malicious email, the installer was executed in a simulated environment to gather telemetry and observe artifacts. The threat actor's objective was credential theft — specifically browser-stored passwords, payment data, and session tokens — consistent with infostealer tradecraft commonly used against content creators.

### How

1. Recipient received two phishing emails posing as Adobe over two consecutive days
2. The second email directed the recipient to download `DocuSign_PackageInstaller.exe` from `hxxps://docu[.]signtools[.]app`
3. Upon execution, the installer staged 62 DLL files to `C:\Users\contractor\AppData\Local\Temp\.net\`
4. `DocuSign_PackageInstaller.exe` launched `msedgewebview2.exe` and established an outbound connection to `136.243.14.123:443`
5. A child process `index.exe.tmp` was spawned and immediately renamed to `index.exe` under `C:\Users\contractor\Jik2Hi5l\`
6. `index.exe` injected into `msedge.exe`, accessed `Login Data` and `Web Data` browser credential files, and attempted to decrypt stored credentials
7. Microsoft Defender detected and alerted on the behavior — the initial installer was not flagged by VirusTotal at time of execution

---

## Investigation Timeline

| Timestamp (UTC) | Event |
|---|---|
| `2025-12-15 17:37:24` | `DocuSign_PackageInstaller.exe` manually executed on `MTS-Contractor-PC2` |
| `2025-12-15 17:37:24` | Installer drops 62 DLL files to `C:\Users\contractor\AppData\Local\Temp\.net\` |
| `2025-12-15 17:37:25` | `netcore,Ionic.Zip` dropped to `C:\ProgramData\Microsoft\NetFramework\BreadcrumbStore\` |
| `2025-12-15 17:37:28` | `DocuSign_PackageInstaller.exe` launches `msedgewebview2.exe` |
| `2025-12-15 17:37:32` | `dbghelp.dll` loaded from `C:\Windows\SysWOW64\` |
| `2025-12-15 17:38:47` | Outbound connection: `136.243.14.123:443` |
| `2025-12-15 17:38:48` | `DocuSign_PackageInstaller.exe` spawns child process `index.exe.tmp` — renamed to `index.exe` under `C:\Users\contractor\Jik2Hi5l\` |
| `2025-12-15 17:38:48` | `Ionic.Zip.dll` loaded from `C:\Users\contractor\AppData\Local\Temp\.net\DocuSign_PackageInstaller\pTL9VOq5vseE\` |
| `2025-12-15 17:39:20` | `index.exe` attempts to decrypt browser credentials — opens 1 credential file |
| `2025-12-15 17:39:22` | `index.exe` creates child process `msedge.exe --profile-directory="Default"` |
| `2025-12-15 17:39:25` | Microsoft Defender detects `DocuSign_PackageInstaller.exe` in `C:\Users\contractor\Downloads` |

---

## MITRE ATT&CK Techniques

### Initial Access

| Technique | ID | Description |
|---|---|---|
| User Execution: Malicious File | [T1204.002](https://attack.mitre.org/techniques/T1204/002/) | User executed trojanized `DocuSign_PackageInstaller.exe` delivered via phishing email |

### Execution

| Technique | ID | Description |
|---|---|---|
| Command and Scripting Interpreter | [T1059](https://attack.mitre.org/techniques/T1059/) | Indirect execution via WebView2 and spawned child processes |
| Shared Modules | [T1129](https://attack.mitre.org/techniques/T1129/) | 62 DLL files staged and loaded by the installer |

### Defense Evasion

| Technique | ID | Description |
|---|---|---|
| System Binary Proxy Execution | [T1218](https://attack.mitre.org/techniques/T1218/) | Legitimate WebView2 runtime used to proxy malicious execution |
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Malware masqueraded as a legitimate DocuSign installer |
| Obfuscated Files or Information | [T1027](https://attack.mitre.org/techniques/T1027/) | Secondary payload staged as `index.exe.tmp` before renaming |
| Process Injection | [T1055](https://attack.mitre.org/techniques/T1055/) | `index.exe` injected into `msedge.exe` via remote thread creation |

### Credential Access

| Technique | ID | Description |
|---|---|---|
| Credentials from Web Browsers | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) | `index.exe` accessed `Login Data` and `Web Data` browser credential stores |
| OS Credential Dumping | [T1003](https://attack.mitre.org/techniques/T1003/) | Attempted decryption of browser-stored credentials |

### Collection

| Technique | ID | Description |
|---|---|---|
| Data from Information Repositories | [T1213](https://attack.mitre.org/techniques/T1213/) | Browser credential and payment data targeted |

### Command and Control

| Technique | ID | Description |
|---|---|---|
| Application Layer Protocol: Web Protocols | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Outbound HTTPS connection to `136.243.14.123:443` |

---

## Recommendations

### Immediate / Containment

1. **Isolate `MTS-Contractor-PC2`** to prevent further data exfiltration or lateral activity
2. **Reset credentials** for the affected user — focus on browser-saved credentials for corporate email, VPN, SSO, and cloud accounts
3. **Force browser sign-out and clear saved credentials** to invalidate stolen session tokens where possible
4. **Block associated file hashes** for `index.exe`, `DocuSign_PackageInstaller.exe`, and related artifacts

### Hardening / Detection

5. **Restrict execution from user-writable paths** — block execution from `%AppData%`, `%LocalAppData%`, and `%Downloads%` via ASR or application control policies
6. **Enable enhanced Defender ASR rules** for: credential theft from browsers, process injection, and unsigned binaries injecting into signed processes
7. **Improve email and web filtering** to detect installer masquerading and brand impersonation (DocuSign, Adobe, etc.)
8. **Create behavioral detections** for: high-volume DLL drops in AppData, unsigned binaries injecting into browsers, and non-browser processes accessing browser credential databases

### Long-Term / Strategic

9. **Move away from browser-stored credentials** — enforce password managers with master password and MFA; disable browser credential storage via policy
10. **Adopt Zero Trust principles** — enforce MFA everywhere, limit credential reuse, and apply conditional access based on device trust

---

## Indicators of Compromise

### Network

| Type | Value | Notes |
|---|---|---|
| Domain | `hxxps://docu[.]signtools[.]app` | Malicious download site |
| IP | `136.243.14.123` | C2 — outbound HTTPS connection |
| IP | `10.21.18.72` | Victim host |

### File Hashes (SHA-256)

| File | Hash |
|---|---|
| `DocuSign_PackageInstaller.exe` | `29df8e05138c6d15217d5eb8e6ad1e82bfe5e1b1da1be32d41086706905b38f6` |
| `index.exe` | `228575c084e767a8c92b3db475212129563e230b6da9b27170ea3bfd3c30cccd` |

---

*Report authored by David Gilmore · 2025-12-15 · Severity: High*
