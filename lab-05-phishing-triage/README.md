# Lab 05 — Phishing Triage (T1566.002)

> Status: Complete

This is an email-phishing triage lab, built on a realistic, multi-source SOC dataset ingested into a
self-hosted Splunk instance. A phishing alert is not a single-log investigation; it is a **correlation
job**, because the answer lives across three separate systems — the email security gateway, the web
proxy, and the identity provider. The aim here is to take the alert end to end the way a Tier-1 analyst
actually does: read and analyse the message, scope who was hit, establish who clicked, check whether any
account was compromised as a result, reach a verdict, and write the whole thing up properly.

| Technique | MITRE ATT&CK | Status |
|-----------|--------------|--------|
| Phishing: Spearphishing Link | T1566.002 (Initial Access) | Under investigation |
| Valid Accounts (downstream) | T1078 (Initial Access / Persistence) | — |

Workflow: pull and analyze the suspicious message (headers, sender authenticity, payload) → scope
delivery across the mail feed → determine click-through in the proxy logs → check the identity logs
for a resulting account compromise → reach a disposition → contain and escalate.

## Lab environment

Modelled on a common MSSP stack — **Proofpoint** (email security), a **Zscaler-style web proxy**,
and **Okta** (identity). All three feeds land in Splunk so the work is real cross-source triage.

| | |
|---|---|
| SIEM | Splunk Enterprise (single GCP VM, `splunk-lab`) |
| Access | Splunk Web over an IAP tunnel to `http://localhost:8000` |
| Email feed | `index=email` (sourcetype `pps:message`) — Proofpoint message events |
| Proxy feed | `index=proxy` (sourcetype `zscaler:web`) — web access logs |
| Identity feed | `index=identity` (sourcetype `okta:system`) — Okta sign-in events |
| Time range | Events span **2026-07-03**. Set the time picker to **All time** or searches return nothing. |

Useful fields (extracted at search time — use them directly in SPL):

- **email** (`index=email`): `sender`, `headerFrom`, `recipient`, `subject`, `spf`, `dkim`, `dmarc`, `threatStatus`, `disposition`, `senderIP`, `url`, `messageID`
- **proxy** (`index=proxy`): `user`, `src`, `method`, `url`, `action`, `urlcategory`, `useragent` (the visited domain is in `url` — you can also search it as a bare term, e.g. `index=proxy some-domain.example`)
- **identity** (`index=identity`): `user`, `src_ip`, `country`, `city`, `result`, `reason`, `user_agent`

## The alert

The following notable lands in the Tier-1 queue:

| Field | Value |
|---|---|
| **Notable ID** | `PHISH-2607030815` |
| **Detection** | `Email - Suspected Credential Phishing Delivered to Multiple Recipients` |
| **Severity / Urgency** | SEV3 / Medium |
| **MITRE ATT&CK** | T1566.002 (Phishing: Spearphishing Link) |
| **Trigger** | The email gateway classified an inbound message as **suspected-phish** but its disposition was **delivered** (it bypassed quarantine) to **8 recipients** in the Finance group. The message contains an external link. Gateway auto-block did not fire, so it needs analyst review. |
| **Entities** | 8 recipient mailboxes (`@soclab.io`), sender domain `micros0ft-verify.com` |
| **Artifact** | Raw message exported for analysis: [`artifacts/suspicious-email.eml`](./artifacts/suspicious-email.eml) |
| **Playbook** | [PB-EMAIL-009](./playbook.md) — follow it |

A Tier-1 analyst picks this up cold and works it per the attached **[playbook](./playbook.md)**: is the
message actually malicious, or a false positive? If malicious — what is it after, who received it, who
**clicked** it, and did anyone's account get **compromised** as a result? What is the blast radius, and
what needs to be contained or escalated?

## Files

| File | Description |
|------|-------------|
| [playbook.md](./playbook.md) | **PB-EMAIL-009** — Tier-1 triage runbook for this detection (procedure, disposition criteria, escalation) |
| [artifacts/suspicious-email.eml](./artifacts/suspicious-email.eml) | The raw phishing message, exported for header/payload analysis |
| [investigation-notes.md](./investigation-notes.md) | Working notes: SPL queries, findings, timeline, IOCs, verdict (filled in live during triage) |
| [incident-report.md](./incident-report.md) | Formal incident report (written after triage) |
| [splunk-queries.md](./splunk-queries.md) | Reusable SPL query library from this lab |
| [evidence/](./evidence/) | Screenshots captured during the investigation |

## Outcome

The alert resolved to a confirmed true positive: credential phishing (T1566.002) that led on to a
valid-account compromise (T1078). A brand-impersonating Microsoft 365 phish, sent from a lookalike domain
(`micros0ft-verify.com`, with SPF, DKIM, and DMARC all failing), was delivered to 8 Finance users and
linked to a credential-harvesting page.

Working the alert across all three feeds resolved the blast radius as a narrowing funnel:
**8 received the message, 3 clicked, 2 submitted their credentials, and 1 account was confirmed
compromised.** The compromised account, `rgarcia`, was accessed roughly 44 minutes after credential
submission, from an external hosting IP in Amsterdam (`45.133.216.78`) using an automated
`python-requests` client. That is credential replay, and it was proven anomalous against the user's own
ordinary browser sign-ins from the office network. `dwilson` had also submitted her credentials, but she
showed no anomalous sign-in, so her account was treated as *credentials exposed, precautionary reset*
rather than a confirmed compromise — a deliberately different disposition for a genuinely different level
of risk.

On that confirmation, the notable was raised from SEV3 to **High** and escalated to Tier 2 / IR as an
active account takeover. The Tier-1 containment was as follows: purge the message from all 8 mailboxes;
block the sender domain, the payload domain, and the sender IP; reset the passwords and **revoke the
active sessions** for `rgarcia` (a password reset on its own would not have evicted the live attacker
session) and for `dwilson`; and block the attacker's sign-in IP.

Two triage lessons stood out, and both are worth carrying forward. The first is that an over-specific
click-through query, pinned to the exact landing URL, initially returned only the `GET`s and produced a
false "no credentials submitted" — re-scoping the search to the phishing *host* is what surfaced the
`POST` submissions. The second is that the containment had to match where the compromise actually lived:
this was an identity and cloud-account takeover launched from external attacker infrastructure, so the
correct response is identity-side (reset, session revocation, IP block), and not endpoint isolation.
