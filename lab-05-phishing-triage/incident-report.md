# SOC Investigation Report — Lab 05: Phishing Triage
**Classification:** Internal / Training
**Analyst:** Uduak
**Date:** 2026-07-05
**Incident ID:** INC-2026-0705-01
**Notable:** PHISH-2607030815 — Suspected Credential Phishing Delivered to Multiple Recipients
**Initial Severity:** SEV3 · **Final Severity:** High

---

## 1. Executive Summary

This report sets out the triage of notable PHISH-2607030815 — a suspected credential-phishing message
that the email gateway delivered rather than blocked — and what the investigation established across the
email, proxy, and identity feeds.

On 2026-07-03, a credential-phishing email impersonating the "Microsoft 365 Security Team" was
**delivered** to 8 Finance users after the email gateway flagged it as *suspected phish* but allowed it
through. The message spoofed a Microsoft security alert from a lookalike domain (`micros0ft-verify.com`)
and linked to a credential-harvesting page (`hxxps://microsoftonline-verify[.]review/session/login`).

Working the alert across three data sources — the email gateway, the web proxy, and the identity
provider — established the blast radius as a narrowing funnel: **8 recipients received the message, 3
clicked the link, 2 submitted their credentials, and 1 account was confirmed compromised.** The
compromised account, **rgarcia**, was successfully accessed roughly 44 minutes after the credentials
were submitted, from an external hosting IP in the Netherlands (`45.133.216.78`) using an automated
`python-requests` client — the signature of credential replay rather than a legitimate sign-in.

On confirmation of the account takeover, the notable was raised from SEV3 to **High** and escalated to
Tier 2 / IR. Email containment, credential resets, session revocation, and IOC blocks were carried out at
Tier 1. The sections that follow lay out the timeline, the evidence behind each conclusion, and the
response taken.

---

## 2. Alert & Trigger

| Field | Detail |
|-------|--------|
| Notable ID | PHISH-2607030815 |
| Detection | Email - Suspected Credential Phishing Delivered to Multiple Recipients |
| Alert time | 2026-07-03 ~08:12 UTC (delivery) |
| Trigger | Gateway classified message as *suspected-phish* but disposition = **delivered** (auto-block threshold not met) to 8 recipients; message contained an external link |
| Initial Severity | SEV3 |
| Final Severity | High |
| MITRE ATT&CK | T1566.002 (Phishing: Spearphishing Link); T1078 (Valid Accounts) |

---

## 3. Investigation Timeline

| Time (UTC 2026-07-03) | Event | Source | Detail |
|----------------------|-------|--------|--------|
| 08:12 | Phishing email delivered to 8 Finance recipients | email (`pps:message`) | SPF/DKIM/DMARC all **fail**; sender `micros0ft-verify.com`; disposition delivered |
| 08:20 | rgarcia loads the phishing page | proxy (`zscaler:web`) | `GET` to `microsoftonline-verify.review` |
| 08:21 | **rgarcia submits credentials** | proxy | `POST` to `/session/login` |
| 08:34 | dwilson loads the phishing page | proxy | `GET` |
| 08:35 | **dwilson submits credentials** | proxy | `POST` to `/session/login` |
| 08:41 | pnguyen loads the phishing page | proxy | `GET` only — **no submission** |
| 09:04 | Failed sign-in as rgarcia from attacker IP | identity (`okta:system`) | `FAILURE` from `45.133.216.78` (Amsterdam, NL), UA `python-requests/2.31` |
| 09:05 | **Successful sign-in as rgarcia — account compromised** | identity | `SUCCESS` from `45.133.216.78`, UA `python-requests/2.31` |

---

## 4. Attack Narrative

**Initial Access (T1566.002).** The attacker sent a credential-phishing email impersonating Microsoft 365
security notifications from a lookalike domain (`micros0ft-verify.com` — a homoglyph of *microsoft* that
substitutes a zero for the letter "o"). The message carried an urgent "unusual sign-in activity — verify
within 24 hours" lure designed to drive recipients to a spoofed Microsoft login page. The gateway
suspected the message but delivered it all the same, placing it in front of 8 Finance users.

**Credential Harvesting.** Three of those recipients went on to visit the phishing page. Two of them —
**rgarcia** and **dwilson** — submitted their credentials, observed as `POST` requests to the harvesting
page's login path roughly one minute after they landed on it. A third recipient, **pnguyen**, viewed the
page but did not submit anything, and the remaining five recipients did not interact with the link at all.

**Valid-Account Compromise (T1078).** Roughly 44 minutes after rgarcia submitted his credentials, the
attacker replayed them. A failed sign-in at 09:04 was followed by a **successful** sign-in at 09:05, both
originating from `45.133.216.78` — a hosting/VPS address in Amsterdam, Netherlands — using an automated
`python-requests` client. This is plainly out of character for rgarcia, whose baseline sign-ins originate
from the Lagos office network in an ordinary browser. Taken together, the foreign location, the automated
user-agent, and the timing immediately after credential submission confirm this as attacker credential
replay: a genuine account takeover, and not a legitimate login. **dwilson**, though she also submitted her
credentials, showed no anomalous sign-in anywhere in the window — her credentials are exposed, but had not
yet been used.

---

## 5. Scope / Blast Radius

| Stage | Count | Users |
|-------|:-----:|-------|
| Received | 8 | aokafor, dwilson, jthompson, klewis, mchen, pnguyen, rgarcia, tbrooks |
| Clicked (GET) | 3 | rgarcia, dwilson, pnguyen |
| Submitted credentials (POST) | 2 | **rgarcia, dwilson** |
| **Confirmed account compromise** | **1** | **rgarcia** |

---

## 6. Evidence Summary

| Evidence | Source | Significance |
|----------|--------|--------------|
| 8× message-delivered, SPF/DKIM/DMARC = fail, sender `micros0ft-verify.com` | email | Confirms delivered, spoofed, brand-impersonating phish |
| Raw `.eml` — `Authentication-Results: spf=fail dkim=fail dmarc=fail`, display-name spoof | email artifact | Independent confirmation of sender inauthenticity |
| `GET`+`POST` to `microsoftonline-verify.review` by rgarcia & dwilson; `GET` only by pnguyen | proxy | Distinguishes viewed vs. credential-submitted |
| rgarcia `SUCCESS` from `45.133.216.78` (Amsterdam), UA `python-requests/2.31` | identity | Confirmed account takeover via credential replay |
| rgarcia baseline sign-ins from Lagos office IPs, normal browser | identity | Establishes the anomaly by contrast |
| dwilson sign-ins normal throughout window | identity | Distinguishes precautionary from confirmed compromise |

---

## 7. Indicators of Compromise (IOCs)

| Type | Value | Context |
|------|-------|---------|
| Sender domain | `micros0ft-verify[.]com` | Lookalike sender domain |
| Sender (envelope) | `bounce@mail.micros0ft-verify[.]com` | Envelope from |
| Header From | `security-alert@micros0ft-verify[.]com` ("Microsoft 365 Security Team") | Display-name spoof |
| Sender IP | `185.220.101.47` | Sending infrastructure |
| Phishing URL | `hxxps://microsoftonline-verify[.]review/session/login` | Credential-harvesting page |
| Phishing domain | `microsoftonline-verify[.]review` | Payload domain |
| Attacker sign-in IP | `45.133.216.78` (Amsterdam, NL; hosting/VPS) | Source of the account takeover |
| Attacker user-agent | `python-requests/2.31` | Automated credential replay client |
| Compromised account | `rgarcia@soclab.io` | Confirmed account takeover |

---

## 8. Findings & Verdict

- **Is this a real incident?** Yes — **true positive**.
- **Classification:** Credential phishing (T1566.002) leading to a valid-account compromise (T1078).
- **Payload type:** Credential harvesting (link to a spoofed login form; no attachment / no malware).
- **Confirmed compromise:** 1 account — `rgarcia@soclab.io` (attacker authenticated successfully).
- **Data accessed / actions taken by the attacker post-login:** Not determined at Tier 1 — handed to
  Tier 2 / IR (out of L1 scope).
- **Final severity:** High — a confirmed account takeover with an attacker actively authenticated,
  contained to a single account/user at the time of triage.

---

## 9. Recommended Response Actions

**rgarcia — confirmed compromise (treat as active intrusion):**
1. Reset password **and revoke all active sessions / tokens** (a password reset alone does not evict the
   existing attacker session).
2. Require re-authentication and re-registration of MFA.
3. Escalate to Tier 2 / IR for intrusion investigation (session activity, inbox rules/forwarding,
   data access, lateral movement) — **out of L1 scope**.

**dwilson — credentials submitted, not yet used (precautionary):**
4. Force password reset and revoke sessions as a precaution.
5. Monitor sign-ins for anomalous activity.

**pnguyen — viewed only, no submission:**
6. Security-awareness note; monitor. No confirmed credential exposure.

**Email containment (all recipients):**
7. Purge the message from all 8 recipient mailboxes.
8. Block the sender domain `micros0ft-verify[.]com`, the payload domain `microsoftonline-verify[.]review`,
   and the sender IP `185.220.101.47` at the gateway / proxy.

**Identity containment:**
9. Block the attacker sign-in IP `45.133.216.78`.

**Other 5 recipients (received, no interaction):**
10. Confirm no click/submission (done); brief awareness. Low risk.

---

## 10. Detection Gaps & Improvements (recommendations for L2)

> Recommendations only — authoring/tuning detections is a Tier-2 activity and is not claimed as work
> performed in this lab.

- **Gateway delivered a suspected-phish.** The message was classified as suspicious but fell below the
  auto-block threshold. Recommend L2 review the gateway policy for lookalike-domain / auth-failure
  (SPF+DKIM+DMARC all fail) handling.
- **Successful credential replay suggests an MFA gap.** The attacker authenticated with a password
  alone from a new country and an automated client. Recommend enforcing MFA and blocking legacy
  authentication / adding conditional-access (impossible-travel, new-country) controls for the
  affected user population.

---

## 11. Lessons Learned

- **Scope to the infrastructure, not to one exact URL.** My initial click-through query pinned the exact
  landing URL, query string and all, and so returned only the `GET`s — which produced a false reading of
  "no credentials submitted." Re-scoping the search to the phishing *host* immediately surfaced the `POST`
  submissions. A phishing ticket can be closed incorrectly on the strength of a filter that is simply too
  specific, and that is a mistake worth guarding against deliberately.
- **Submitting credentials is not the same as being compromised.** Two users submitted their credentials,
  yet only one was confirmed compromised. Checking the identity logs user by user is what separated the
  *confirmed takeover* (reset, revoke, escalate) from the merely *precautionary* case (reset and monitor) —
  a different response for a genuinely different level of risk.
- **Match the containment to where the compromise actually lives.** This was an identity and cloud-account
  takeover launched from external attacker infrastructure, not an endpoint infection. The containment
  therefore belongs on the identity side — password reset, session revocation, and an IP block — rather
  than host isolation.
- **Corroborate every conclusion across sources.** The sender's inauthenticity was confirmed in both the
  raw `.eml` and the gateway logs, and the compromise itself was proven by contrast against the user's own
  sign-in baseline. No single log was asked to carry a conclusion on its own.

---

*Report submitted for review: 2026-07-05*
