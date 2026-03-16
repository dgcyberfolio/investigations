# Email Investigation: Duolingo Brand Impersonation — "Join Us in Creating Unique Material"

| | |
|---|---|
| **Investigation Type** | Email — Static Analysis |
| **Date of Report** | 2025-07-13 |
| **Reported By** | David Gilmore |
| **Severity** | Medium |
| **Host** | Inquiry mailbox (email artifact only) |
| **Alert Time** | 2025-07-13 15:50:03 UTC |

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

On 2025-07-13 at 15:50:03 UTC, an email was delivered to the inquiry mailbox claiming to be from Duolingo. The message originated from `libero.it`, a freemail provider, while impersonating the Duolingo brand. The Reply-To header directed responses to `duolingo-team.com`, a different domain than the sender.

Header analysis identified brand impersonation, a Reply-To domain mismatch, and a missing Date header. SPF and DKIM authentication passed for `libero.it`, but were not aligned with the impersonated brand domain. The email body was Base64 encoded and contained a generic collaboration proposal. No attachments or hyperlinks were observed.

Based on static analysis of the provided `.eml` file, this activity is consistent with a phishing attempt utilizing brand impersonation for potential social engineering engagement. No evidence of payload delivery or user interaction was available. The scope of this investigation was limited to the provided email artifact.

---

## Email Findings

| Field | Value |
|---|---|
| **Time** | 2025-07-13 15:50:03 UTC |
| **Sender** | `duolingo.ads@libero.it` |
| **Reply-To** | `info@duolingo-team.com` |
| **Subject** | Join Us in Creating Unique Material |
| **Mail Infrastructure** | Italiaonline S.p.A. (shared SMTP relay) |
| **IOC Domain** | `duolingo-team.com` |
| **IOC Domain** | `libero.it` |
| **IOC IP** | `90.160.50.35`, `213.209.10.34` |
| **SPF** | Pass (for `libero.it` — not aligned with impersonated brand) |
| **DKIM** | Pass (for `libero.it` — not aligned with impersonated brand) |
| **DMARC** | Not enforced |
| **Attachments** | None |
| **Hyperlinks** | None observed |

### Authentication Analysis

SPF and DKIM both passed, but only for the sending infrastructure (`libero.it`), not for the impersonated brand domain (Duolingo). This is a key indicator — passing authentication does not mean the email is legitimate when the authenticated domain bears no relationship to the claimed sender identity. The Reply-To mismatch (`duolingo-team.com`) indicates the actor intended to harvest replies or further engagement through a controlled domain while keeping the sending infrastructure separate.

---

## 5 W's Breakdown

### Who

- **External Sender:** `duolingo.ads@libero.it`
- **Recipient:** Inquiry mailbox

### What

A brand impersonation phishing email posing as Duolingo marketing outreach, likely targeting content creators or media-facing accounts. The email was designed to initiate social engineering contact via a Reply-To redirect to a controlled domain.

### When

Delivered on 2025-07-13 at 15:50:03 UTC. No indication activity is ongoing. Scope limited to the static `.eml` artifact — no endpoint telemetry available.

### Where

Delivered to the inquiry mailbox via external SMTP relay infrastructure (Italiaonline S.p.A., a shared freemail relay based in Italy).

### Why

Likely intended to initiate deceptive communication and potentially collect information through redirected replies to `duolingo-team.com`. Brand impersonation of a well-known company targeting a media-facing mailbox is consistent with social engineering for credential harvesting, financial fraud, or follow-on payload delivery.

### How

Sent through shared SMTP infrastructure (Italiaonline S.p.A.) using legitimate freemail authentication, with the sender domain (`libero.it`) passing SPF and DKIM independently of the impersonated brand. The Reply-To header was set to `info@duolingo-team.com` — a separate actor-controlled domain — to redirect any recipient replies away from `libero.it` and into the attacker's inbox.

---

## MITRE ATT&CK Techniques

### Initial Access

| Technique | ID | Description |
|---|---|---|
| Phishing: Spearphishing via Service | [T1566.003](https://attack.mitre.org/techniques/T1566/003/) | Email delivered via legitimate shared SMTP relay impersonating a known brand |

### Defense Evasion

| Technique | ID | Description |
|---|---|---|
| Masquerading | [T1036](https://attack.mitre.org/techniques/T1036/) | Sender identity spoofed to appear as Duolingo brand outreach |

### Collection

| Technique | ID | Description |
|---|---|---|
| Email Collection | [T1114](https://attack.mitre.org/techniques/T1114/) | Reply-To mismatch designed to redirect victim replies to attacker-controlled domain |

---

## Recommendations

1. **Monitor for additional emails** using `duolingo-team.com` or similar brand impersonation patterns targeting this mailbox
2. **Consider blocking `duolingo-team.com`** if recurring activity is observed
3. **Reinforce phishing awareness** regarding emails from freemail domains (`libero.it`, `daum.net`, etc.) claiming corporate affiliation
4. **Ensure anti-impersonation protections are enabled** within the email security platform — specifically DMARC enforcement and Reply-To analysis
5. **Treat SPF/DKIM pass as insufficient validation** in isolation — verify domain alignment against the claimed sender identity

---

## Indicators of Compromise

| Type | Value | Notes |
|---|---|---|
| Domain | `duolingo-team.com` | Reply-To domain — actor-controlled |
| Domain | `libero.it` | Freemail sender domain |
| IP | `90.160.50.35` | Associated sending infrastructure |
| IP | `213.209.10.34` | Associated sending infrastructure |
| Email | `duolingo.ads@libero.it` | Sender address |
| Email | `info@duolingo-team.com` | Reply-To — actor-controlled |

---

*Report authored by David Gilmore · 2025-07-13 · Severity: Medium*
