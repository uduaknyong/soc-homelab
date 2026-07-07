# Investigation Working Notes — Lab 05 (Phishing Triage)

**Analyst:** Uduak
**Notable:** `PHISH-2607030815` — Suspected Credential Phishing Delivered to Multiple Recipients
**Playbook:** PB-EMAIL-009
**Investigation started:** _____

> Fill this in live as you work the playbook. Every query is yours — paste it, say what you were
> looking for, and record what you found. Defang URLs (`hxxps://`) in your notes.

---

## Alert details
- Notable ID: PHISH-2607030815
- Detection: Email - Suspected Credential Phishing Delivered to Multiple Recipients
- Severity (initial): SEV3 / Medium
- Trigger: gateway marked message suspected-phish but **delivered** to 8 Finance recipients; external link
- Data: `index=email` (pps:message) · `index=proxy` (zscaler:web) · `index=identity` (okta:system) — **All time**

---

## 1 — Message analysis (the .eml)
*(sender display name vs address, sending domain, Authentication-Results, subject, call-to-action, URL)*

sender display name: Microsoft 365 Security Team
Address: security-alert@micros0ft-verify.com
sending domain: micros0ft-verify[.]com
Auth-results: spf, dkim and dmarc all failed
subject: Action Required: Unusual sign-in activity detected on your account
call to action: verify my account
url: hxxps://microsoftonline-verify[.]review/session/login?id=8f3a2b
-

## 2 — Sender authenticity (index=email)
*(spf / dkim / dmarc verdicts; lookalike domain?)*

**Query:**
```
index=email senderIP=185.220.101.47 | stats count by dmarc spf dkim
```
*Looking for:* the counts of spf, dkim and dmarc auth events
*Found:* 8 failed events for all 3 records meaning the sender cannot be validated.

## 3 — Payload assessment
*(what the URL leads to; credential harvesting / malware / benign; defanged IOC)*

- URL "hxxps://microsoftonline-verify[.]review/session/login?id=8f3a2b" leads an error page currently. The payload leads to a login page that requests login details. This is classic credential harvester to steal login info.

## 4 — Delivery scope (index=email)
*(how many recipients, who — the candidate victim list)*

**Query:**
```
index=email senderIP=185.220.101.47 | stats count by recipient
index=email sender=bounce@mail.micros0ft-verify.com | stats count by recipient
```
*Looking for:* I am looking for the recipients this email was sent to, the candidate victim list.
*Found:* The email was sent to 8 different recipients. See recipients below.

aokafor@soclab.io
dwilson@soclab.io
jthompson@soclab.io
klewis@soclab.io
mchen@soclab.io
pnguyen@soclab.io
rgarcia@soclab.io
tbrooks@soclab.io

## 5 — Click-through (index=proxy)
*(did any recipient visit the phishing host? user / time / GET vs POST)*

**Query:**
```
index=proxy url="https://microsoftonline-verify.review*" | table _time user method
```
*Looking for:* Who clicked, when they clicked and if they submitted any login credentials.
*Found:* A couple of users clicked. After the email was delivered. Two users submitted their credentials. See below.


time			user			method
2026-07-03 08:41:00	pnguyen@soclab.io	GET
2026-07-03 08:35:18	dwilson@soclab.io	POST
2026-07-03 08:34:00	dwilson@soclab.io	GET
2026-07-03 08:21:18	rgarcia@soclab.io	POST
2026-07-03 08:20:00	rgarcia@soclab.io	GET


## 6 — Account compromise check (index=identity)
*(for clickers: anomalous successful sign-in? new country / IP / device vs their baseline)*

**Query:**
```
index=identity user IN ("rgarcia@soclab.io", "dwilson@soclab.io") | table _time result city country user user_agent src_ip | sort user _time
```
*Looking for:* Account compromise
*Found:*
rgarcia signed in from Amsterdam with a python user-agent. Baseline is from Lagos and Chrome user agent.
---

## Timeline

| Time (UTC 2026-07-03) | Event | Source | Notes |
|----------------------|-------|--------|-------|
| 08:12 | Phish delivered to 8 Finance recipients | email | SPF/DKIM/DMARC all fail; sender micros0ft-verify.com; delivered (not blocked) |
| 08:20 | rgarcia loads phishing page | proxy | GET |
| 08:21 | **rgarcia submits credentials** | proxy | POST /session/login |
| 08:34 | dwilson loads phishing page | proxy | GET |
| 08:35 | **dwilson submits credentials** | proxy | POST /session/login |
| 08:41 | pnguyen loads phishing page | proxy | GET only — no submission |
| 09:04 | Failed sign-in as rgarcia from attacker IP | identity | FAILURE from 45.133.216.78 (Amsterdam), UA python-requests/2.31 |
| 09:05 | **Successful sign-in as rgarcia — compromised** | identity | SUCCESS from 45.133.216.78, UA python-requests/2.31 |

---

## Key findings
- Delivered, brand-impersonating credential phish (lookalike `micros0ft-verify.com`, all three auth checks fail).
- Payload = credential harvesting (link to a fake M365 login page; no attachment / no malware).
- Blast radius funnel: 8 received → 3 clicked → 2 submitted → 1 confirmed compromise.
- rgarcia compromised: successful sign-in from a Netherlands hosting IP with an automated python-requests client, ~44 min after submitting creds — credential replay, anomalous vs his Lagos/Chrome baseline.
- dwilson submitted creds but no anomalous sign-in — exposed, not (yet) compromised.

## IOCs

| Type | Value | Context |
|------|-------|---------|
| Sender domain | micros0ft-verify[.]com | Lookalike sender domain |
| Sender IP | 185.220.101.47 | Sending infrastructure |
| URL / domain | hxxps://microsoftonline-verify[.]review/session/login | Credential-harvesting page |
| Sign-in IP (attacker) | 45.133.216.78 (Amsterdam, NL; hosting/VPS) | Source of the account takeover |
| Attacker user-agent | python-requests/2.31 | Automated credential-replay client |
| Compromised account | rgarcia@soclab.io | Confirmed account takeover |

---

## Victim breakdown

| User | Received | Clicked (GET) | Submitted (POST) | Compromised sign-in | Action |
|------|:--------:|:-------------:|:----------------:|:-------------------:|--------|
| rgarcia | ✅ | ✅ | ✅ | ✅ **confirmed** | Reset + revoke sessions + re-MFA; block attacker IP; escalate to L2/IR |
| dwilson | ✅ | ✅ | ✅ | ❌ | Precautionary reset + revoke sessions; monitor |
| pnguyen | ✅ | ✅ | ❌ | ❌ | Awareness note; monitor (no creds submitted) |
| 5 others | ✅ | ❌ | ❌ | ❌ | Purge from mailbox; low risk |

---

## Verdict
- Incident or false positive?: **Incident — true positive.**
- Technique / intent: Credential phishing (T1566.002) → valid-account compromise (T1078); intent = credential theft.
- Blast radius (received / clicked / submitted / compromised): **8 / 3 / 2 / 1.**
- Severity (final): **High** (raised from SEV3 on confirmed account takeover).
- Containment actions: purge email from all 8 mailboxes; block sender domain + payload domain + sender IP; reset + revoke sessions for rgarcia (confirmed) and dwilson (precaution); block attacker IP 45.133.216.78.
- Escalate to L2/IR?: **Yes** — rgarcia is an active account takeover; intrusion investigation (session activity, inbox rules, lateral movement, data access) is out of L1 scope.
