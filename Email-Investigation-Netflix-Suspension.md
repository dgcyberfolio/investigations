# Email Investigation: Netflix Account Suspension Phishing

| | |
|---|---|
| **Investigation Type** | Email — Static Analysis |
| **Date of Report** | 2025-06-04 |
| **Reported By** | David Gilmore |
| **Severity** | Medium |
| **Recipient** | `inquiry@mydfir.com` |
| **Alert Time** | 2025-06-04 20:55:10 UTC |

---

## Table of Contents

- [Investigation Summary](#investigation-summary)
- [Email Findings](#email-findings)
- [5 W's Breakdown](#5-ws-breakdown)
- [MITRE ATT&CK Techniques](#mitre-attck-techniques)
- [Recommendations](#recommendations)
- [Indicators of Compromise](#indicators-of-compromise)

---

## Investigation Summary

On 2025-06-04 at 20:55:10 UTC, a sender attempted to impersonate Netflix in an email alerting of a possible service suspension. The sender account masqueraded as a legitimate Netflix email through the display name 'Netflix', while the actual sending domain was `lna.io`. The email body reproduced Netflix's logo via a hyperlink to a Wikimedia SVG to add further visual legitimacy.

The sender email and the Return-Path (`postmaster@7fcfc3c467.nxcli.io`) pointed to different domains; further investigation confirmed that both domains belong to the same subnet and ISP (Liquid Web LLC). Both domains returned results in VirusTotal as malicious and are associated with known phishing infrastructure.

Despite this, the email's DKIM was valid while SPF and DMARC were unknown. The social engineering objective was to create urgency around an account suspension and prompt the recipient to click a malicious URL — hyperlinked to resolve to a site with no association to Netflix — likely intended to harvest card details and credentials.

---

## Email Findings

| Field | Value |
|---|---|
| **Time** | 2025-06-04 20:55:10 UTC |
| **Display Name** | Netflix |
| **Sender Address** | `y3sox4wm@lna.io` |
| **Return-Path** | `postmaster@7fcfc3c467.nxcli.io` |
| **Recipient** | `inquiry@mydfir.com` |
| **Subject** | Netflix Account Suspension |
| **Sending Host** | `cloudhost-831045.us-midwest-1.nxcli.net` / Cloudflare |
| **Host IP** | `209.87.159.252` |
| **ISP** | Liquid Web LLC (`liquidweb.com`) |
| **ASN** | AS36444 |
| **IOC Domain** | `lna.io` |
| **DKIM** | Valid |
| **SPF** | Unknown |
| **DMARC** | Unknown |

### Infrastructure Analysis

The sender domain (`lna.io`) and the Return-Path domain (`7fcfc3c467.nxcli.io`) resolve to the same ISP and subnet (Liquid Web LLC, AS36444), indicating coordinated infrastructure despite the use of two different domains. Both domains are flagged as malicious in VirusTotal and associated with known phishing campaigns. Valid DKIM without SPF or DMARC alignment is a common evasion pattern in phishing infrastructure designed to pass basic mail filtering while avoiding stricter authentication checks.

### Malicious URL

The email body contained a hyperlinked call-to-action directing the recipient to the following URL:

```
hxxps://t[.]co/HdNFNdZGEO?id=4273186239133548243-8075
```

This URL does not resolve to any Netflix-affiliated infrastructure and was likely used as a redirect to a credential harvesting or payment phishing page. The Netflix logo was pulled from a legitimate Wikimedia source to bolster visual authenticity without embedding a direct malicious image.

---

## 5 W's Breakdown

### Who

- **Recipient:** `inquiry@mydfir.com`
- **Sender:** `y3sox4wm@lna.io` via `cloudhost-831045.us-midwest-1.nxcli.net`
- **Host IP:** `209.87.159.252`

### What

A Netflix brand impersonation phishing email designed to create urgency around an account suspension. The email contained a malicious URL hyperlinked to appear as a legitimate Netflix payment portal, intended to harvest the recipient's card details and credentials.

### When

The email was received on 2025-06-04 at 20:55:10 UTC. No follow-up activity or user interaction was observed within the scope of this investigation.

### Where

The email was delivered to `inquiry@mydfir.com`. The sending infrastructure (`cloudhost-831045.us-midwest-1.nxcli.net`) is hosted by Liquid Web LLC and masked through Cloudflare.

### Why

The attacker impersonated Netflix and manufactured urgency around account suspension to prompt the recipient to click a malicious URL out of fear of service loss. This is a classic credential harvesting and financial data theft technique targeting consumers with active subscription accounts.

### How

The sender impersonated Netflix through a display name match while using an unrelated freemail domain (`lna.io`) as the actual sending address. The Return-Path was set to a different but infrastructurally related domain. The email body included Netflix branding via a legitimate external image source. A hyperlinked call-to-action directed the recipient to a malicious redirect URL (`hxxps://t[.]co/HdNFNdZGEO?id=...`) that masked the final destination — likely a fake Netflix login or payment page.

---

## MITRE ATT&CK Techniques

### Initial Access

| Technique | ID | Description |
|---|---|---|
| Phishing | [T1566](https://attack.mitre.org/techniques/T1566/) | Email delivered impersonating Netflix with a malicious embedded URL |

### Defense Evasion

| Technique | ID | Description |
|---|---|---|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Display name set to 'Netflix'; legitimate Wikimedia logo embedded for visual authenticity |

### Credential Access

| Technique | ID | Description |
|---|---|---|
| Phishing for Information | [T1598](https://attack.mitre.org/techniques/T1598/) | Malicious URL designed to harvest payment credentials and account login details |

---

## Recommendations

1. **Block the sender address** `y3sox4wm@lna.io` and Return-Path address `postmaster@7fcfc3c467.nxcli.io` from future delivery
2. **Search mail logs** for any prior emails from either address, the `lna.io` domain, the `nxcli.io` domain, or the subject line — block accordingly
3. **Inspect network logs** to determine whether any connection to the URL `hxxps://t[.]co/HdNFNdZGEO?id=4273186239133548243-8075` was established
4. **Block the malicious URL** at the web proxy or email filtering layer
5. **Consider blocking the `209.87.159.252` host** and broader `nxcli.net` infrastructure if correlated phishing activity is confirmed

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Domain | `lna.io` | Sender domain — VirusTotal flagged malicious |
| Domain | `7fcfc3c467.nxcli.io` | Return-Path domain — same subnet as sender |
| Domain | `cloudhost-831045.us-midwest-1.nxcli.net` | Sending host |
| IP | `209.87.159.252` | Sending host IP — Liquid Web LLC (AS36444) |
| Email | `y3sox4wm@lna.io` | Sender address |
| Email | `postmaster@7fcfc3c467.nxcli.io` | Return-Path address |
| URL | `hxxps://t[.]co/HdNFNdZGEO?id=4273186239133548243-8075` | Malicious redirect URL embedded in email body |

---

*Report authored by David Gilmore · 2025-06-04 · Severity: Medium*
