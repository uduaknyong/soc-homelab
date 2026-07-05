# Lab 01 — Password Spray → Credential Compromise

## Scenario

> **[ALERT — SEV3] Unusual Authentication Pattern Detected**  
> **Host:** win-dc-01 | **Trigger:** 5+ failed logon attempts followed by successful logon from same source within 10 minutes

A Tier 1 SOC analyst receives an automated alert during shift handover. No prior investigation has been done. Starting from the alert alone, the task is to determine what happened, who was affected, and what to do next.

---

## Techniques Covered

| Technique | MITRE ATT&CK |
|-----------|-------------|
| Password Spraying | T1110.003 |
| Valid Accounts | T1078 |
| SMB/Network Logon (Type 3) | — |

---

## Key Event IDs

| Event ID | Meaning |
|----------|---------|
| 4625 | Failed logon attempt |
| 4624 | Successful logon |

---

## Attack Summary

- **Source IP:** 10.0.0.5 (attacker VM)
- **Attack type:** Blind password spray across 3 domain accounts
- **Compromised account:** jsmith
- **Access method:** SMB network logon (Logon Type 3)
- **Post-exploitation:** None observed

---

## Files

| File | Description |
|------|-------------|
| [investigation-notes.md](./investigation-notes.md) | Working notes — SPL queries, findings, timeline built during investigation |
| [incident-report.md](./incident-report.md) | Formal incident report submitted after investigation |
| [splunk-queries.md](./splunk-queries.md) | Reusable SPL query library from this lab |

---

## Outcome

**Verdict:** Confirmed incident — Initial Access achieved via credential compromise  
**Severity:** SEV3  
**Response:** Isolate host, rotate jsmith credentials, block source IP, escalate to L2
