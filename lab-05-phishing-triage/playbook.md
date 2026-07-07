# Playbook — Suspected Credential Phishing (Delivered)

> Tier-1 triage runbook attached to the detection that raised this notable. Follow it in order.
> It defines *how* to work the alert and *how* to decide — not what you'll find. Record your work in
> [investigation-notes.md](./investigation-notes.md). You write and run every SPL query yourself.

| | |
|---|---|
| **Playbook ID** | PB-EMAIL-009 |
| **Detection / correlation search** | `Email - Suspected Credential Phishing Delivered to Multiple Recipients` |
| **Notable severity** | SEV3 / Medium |
| **MITRE ATT&CK** | [T1566.002 — Phishing: Spearphishing Link](https://attack.mitre.org/techniques/T1566/002/) (Tactic: Initial Access) |
| **Owner tier** | SOC Tier 1 (escalate to Tier 2 / IR per §7) |
| **Response SLA (SEV3)** | Acknowledge ≤ 30 min · Begin triage ≤ 60 min · Initial disposition ≤ 4 h |
| **Data sources** | `index=email` (`pps:message`) · `index=proxy` (`zscaler:web`) · `index=identity` (`okta:system`). Set the time picker to **All time**. |

---

## Background (why this fires)
Credential phishing lures a user to a fake login page to steal their username and password. The gateway
flagged this message as *suspected* phish but **delivered** it anyway (it did not meet the auto-block
threshold), so it reached user inboxes. The Tier-1 job is to confirm whether it is malicious and, if so,
determine the **impact**: a phishing email only matters to the degree that someone *clicked* it and,
worse, *entered credentials* that were then *used*. That is why this alert cannot be closed from the email
log alone — you must follow the chain **email → proxy → identity**.

The three questions that decide this ticket:
1. **Is the message malicious?** (sender authenticity + payload)
2. **Did anyone act on it?** (click-through, credential submission)
3. **Was an account compromised as a result?** (anomalous sign-in)

---

## Triage checklist

Work these in order. Each step is an **objective + guidance**; you write the SPL.

**1 — Pull and read the message.**
Open [`artifacts/suspicious-email.eml`](./artifacts/suspicious-email.eml). Note the **display name** vs the
**actual sender address** and the **sending domain**. Read the `Authentication-Results` header. Note the
**subject**, the **call to action**, and the **link** the user is being pushed toward. Form a first
impression before you touch Splunk.

**2 — Judge sender authenticity.**
In `index=email`, find the message and examine the authentication verdicts: **`spf`**, **`dkim`**,
**`dmarc`**. Does the sending domain legitimately belong to who the message claims to be from? Is the
domain a **lookalike** of a trusted brand? A brand-impersonating display name on a domain that fails all
three authentication checks is a strong malicious signal — but state it in those terms, not a hunch.

**3 — Assess the payload.**
Identify the **URL(s)** in the message and where they lead. Is this **credential harvesting** (a fake
login page), a malware download, or benign? (Defang URLs in your notes — `hxxps://`.) You are classifying
*intent*: what does the attacker want the user to do?

**4 — Scope delivery.**
In `index=email`, determine **how many recipients** received this message and **who** they are. This is
your candidate victim list — everyone who could have clicked. `... | stats ... by recipient` or a count is
a fair pivot. Don't assume the alert's recipient count is complete; confirm it from the data.

**5 — Determine click-through (the pivot that matters).**
Move to `index=proxy`. Did any recipient actually **visit the phishing URL / domain**? Search the proxy
logs for the malicious host. For anyone who did: note the **user**, the **time** (was it after the email?),
and the **HTTP method** — a `GET` is a *view*; a `POST` to the login path suggests the user **submitted
the form** (entered credentials). Separate "clicked" from "clicked *and* submitted" — they carry different
risk.

**6 — Check for account compromise.**
For each user who clicked (especially those who submitted), pivot to `index=identity`. Look at their
**sign-in events** around and after the click. The signal for a *successful* credential-phish compromise is
an **anomalous successful sign-in**: a new **country / IP / device (user agent)** that is out of character
for that user, shortly after they submitted. Compare against the user's **own baseline** sign-ins. A
success from an unfamiliar location is confirmed compromise; failures from an odd source are attempts.
*Clicking ≠ compromise* — prove it from the sign-in data, don't assume it.

**7 — Disposition, contain, escalate.**
Reach a verdict (true positive / false positive) and, if malicious, act:
- **Contain the email:** block the sender domain and the malicious URL/domain; purge the message from all
  recipient mailboxes.
- **Contain the users:** for anyone who submitted credentials, force a password reset and revoke active
  sessions; for a **confirmed compromised account**, treat it as active intrusion.
- **Escalate to Tier 2 / IR** when there is a confirmed account compromise (a successful anomalous
  sign-in), evidence of post-compromise activity, or blast radius beyond a single mailbox. A phish that was
  delivered but not clicked, or clicked but not submitted with no compromise, is contained and closed at
  Tier 1 with monitoring.

---

## Disposition criteria (quick reference)

| Situation | Disposition |
|---|---|
| Message benign / legitimate sender (FP) | Close — false positive; tune if recurring (note for L2) |
| Malicious, delivered, **no clicks** | True positive — contain email (block + purge), close, monitor |
| Malicious, **clicked, no credential submission, no anomalous sign-in** | True positive — reset as precaution, contain email, monitor |
| Malicious, **credentials submitted, no anomalous sign-in yet** | True positive — force reset + session revoke, contain, monitor closely |
| Malicious, **confirmed compromise** (anomalous successful sign-in) | True positive — **raise severity, escalate to L2/IR**, treat as active intrusion |

## Escalation (§7)
Escalate to Tier 2 / IR with: the confirmed IOCs (sender, domain, URL, sender IP, attacker sign-in IP),
the victim list split by *received / clicked / submitted / compromised*, the timeline, and the containment
actions already taken. State clearly which accounts are **confirmed compromised** vs **precautionary**.
