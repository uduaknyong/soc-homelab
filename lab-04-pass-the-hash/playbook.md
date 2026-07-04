# Playbook — Anomalous NTLM Network Authentication (Suspected Pass-the-Hash)

> Tier-1 triage runbook attached to the detection that raised this notable. Follow it in order.
> It defines *how* to work the alert and *how* to decide — not what you'll find. Record your work in
> [investigation-notes.md](./investigation-notes.md).

| | |
|---|---|
| **Playbook ID** | PB-CRED-014 |
| **Detection / correlation search** | `Windows - Anomalous NTLM Network Logon (Possible Pass-the-Hash)` |
| **Notable severity** | SEV2 / Medium |
| **MITRE ATT&CK** | [T1550.002 — Use Alternate Authentication Material: Pass the Hash](https://attack.mitre.org/techniques/T1550/002/) (Tactic: Lateral Movement) |
| **Owner tier** | SOC Tier 1 (escalate to Tier 2 / IR per §6) |
| **Response SLA (SEV2)** | Acknowledge ≤ 15 min · Begin triage ≤ 30 min · Initial disposition ≤ 60 min |
| **Data source** | Windows Security Event Logs — Splunk `index=passthehash` (`sourcetype=pth:winlog`). Set time picker to **All time**. |

---

## Background (why this fires)
Pass-the-Hash replays a stolen NTLM hash to authenticate **without knowing the plaintext password**.
Because the hash is used directly, the resulting logon authenticates over **NTLM**, produces a **network
logon (Logon Type 3)**, and typically originates from a host or account that would normally use
**Kerberos**. This detection surfaces NTLM network logons that fall outside the Kerberos-first baseline so
an analyst can decide whether they are legitimate NTLM usage or replayed credentials.

Key Windows Security events you will reference:

| Event ID | Meaning | Why it matters here |
|---|---|---|
| 4624 | Successful logon | The logon itself — read `Logon_Type`, `Authentication_Package`, `Logon_Process` |
| 4625 | Failed logon | Failed/attempted replays, spray, wrong target |
| 4648 | Logon using **explicit credentials** | `runas` / PsExec / lateral tooling signature |
| 4672 | Special privileges assigned | Privileged/admin logon session |
| 4776 | NTLM credential validation (DC) | DC-side view of NTLM auth |
| 4634 | Logoff | Session correlation via Logon ID |

---

## Triage checklist

Work these in order. Each step is an **objective + guidance**; you write and run the SPL yourself.

**1 — Validate & scope the notable.**
Confirm the events are real and establish the blast radius: which **hosts**, which **event IDs**, what
**time window**. Don't chase a single event before you know the shape of the data.
`... | stats count by EventCode host` is a fair orientation pivot.

**2 — Isolate the anomalous authentication.**
Narrow to the events the detection cares about: **successful network logons (4624, Logon Type 3)** and
break them down by **`Authentication_Package`**. Where does NTLM sit relative to the Kerberos baseline?

**3 — Identify the principals.**
For each NTLM logon, establish: **which account** (`user` / `Account_Name`), is it **privileged**, is it a
**user vs machine ($) account**; and the **origin** — `Source_Network_Address` (`src`), `Workstation_Name`,
`host`. A named account authenticating over NTLM from an unfamiliar source is the pattern of interest.

**4 — Establish the baseline (the TP/FP hinge).**
Is NTLM expected **for this account, from this source, on this host**? Compare against the surrounding
authentication for the same principals. In a Kerberos-first environment, ask *why NTLM at all* — that
question, not the raw volume, is what separates malicious replay from benign NTLM.

**5 — Hunt corroborating lateral-movement indicators.**
Around the same window/account, look for **explicit-credential logons (4648)**, **special-privilege
assignment (4672)**, **failed logons (4625)** (spray/attempts), and any **remote-execution tooling**
referenced in the events. These turn a lone anomalous logon into an attack chain.

**6 — Correlate across hosts and sessions.**
If the same authentication appears from more than one vantage point (source vs destination host), line them
up. Use **Logon ID** and timestamps to tie logon → activity → logoff.

**7 — Determine success & impact.**
Confirm whether the logon **succeeded** (Audit Success) and what the account could reach. A successful PtH
with a privileged account is a materially different incident from a failed attempt.

---

## Disposition criteria

**Rate as TRUE POSITIVE (Pass-the-Hash) if you observe indicators such as:**
- Successful **NTLM** network logon (Type 3) by a **named/privileged** account where Kerberos is the norm.
- Origin is an **unexpected host / workstation / source IP** for that account.
- Corroborating **4648 explicit-credential** logons and/or **remote-exec tooling** in the same window.
- The account/source has **no legitimate reason** to use NTLM here.

**Rate as FALSE POSITIVE / BENIGN if the NTLM logon is explained by:**
- Access to a resource by **IP literal / hostname alias** (forces NTLM instead of Kerberos).
- **Legacy applications or appliances** that only speak NTLM.
- **Vulnerability scanners / authenticated monitoring** using service accounts from a known scan host.
- **Non-domain or workgroup** systems, or a documented maintenance activity.
- Confirm the source host and account are expected, then clear with justification.

*If evidence is mixed or you cannot rule out replay, treat as suspicious and escalate — do not close.*

---

## §6 — Escalation

**Escalate to Tier 2 / Incident Response immediately if any of the following are true:**
- A **privileged account** (Domain Admin, local admin, service account) is involved.
- You confirm **lateral movement** (explicit-cred logons, remote tooling, multiple targets).
- The logon **succeeded** and cannot be attributed to sanctioned activity.

**Escalation contents:** notable ID, affected accounts/hosts, source, timeline, MITRE technique, the
evidence you relied on, and your recommended containment.
**Path:** SOC Tier 2 on-call → IR duty manager (page for confirmed privileged compromise).

---

## §7 — Recommended containment (Tier-1 recommends; T2/IR executes with approval)
- Preserve evidence (do not log the attacker out / wipe): export the relevant events.
- Recommend **disabling / forcing password reset** on the affected account(s) — and `krbtgt` considerations
  if domain-wide replication is suspected.
- Recommend **isolating the source host** pending investigation, per containment policy.

## §8 — Closure & documentation (required to close)
Ticket must contain: **disposition** (TP/FP/benign) with rationale, **IOCs** (accounts, source IPs/hosts,
times), **timeline**, **MITRE mapping (T1550.002)**, **actions taken / recommended**, and **evidence**
(screenshots / exported events). No SEV2 notable closes without a written verdict.

---

## References
- MITRE ATT&CK [T1550.002 Pass the Hash](https://attack.mitre.org/techniques/T1550/002/)
- Microsoft — [4624](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4624) ·
  [4648](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4648) ·
  [4672](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4672)
- Logon types & authentication packages (Kerberos vs NTLM) reference
