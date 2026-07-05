# SOC Investigation Report — Week 1
**Classification:** Internal / Training  
**Analyst:** Uduak  
**Date:** 8th May, 2026  
**Incident ID:** INC-2026-W1-001  
**Severity:** SEV3

---

## 1. Executive Summary

On May 8th, 2026, an alert fired for an unusual authentication pattern on win-dc-01. A blind password spray attack was launched from IP 10.0.0.5 (ubuntu-attacker-01) targeting accounts jsmith, ajonas, and bwilliams. The attacker successfully authenticated to jsmith's account via SMB (Logon Type 3) following 18 failed logon attempts. No post-compromise activity was observed. Recommended actions include isolating the host, rotating jsmith's credentials, blocking the source IP, and escalating to L2 for further investigation.

---

## 2. Alert & Trigger

| Field | Detail |
|-------|--------|
| Alert Name | Unusual Authentication Pattern |
| Alert Time | 2026-05-08 ~06:52 UTC |
| Affected Host | win-dc-01 |
| Affected Account(s) | jsmith (compromised), ajonas (targeted), bwilliams (targeted) |
| Initial Severity | SEV3 |
| Final Severity | SEV3 |

---

## 3. Investigation Timeline

| Time (UTC 2026-05-08) | Event Description | Log Source | Event ID / Detail |
|----------------------|-------------------|------------|-------------------|
| 06:52:00 | Password spray begins — first 4625 observed | wineventlog | EventCode 4625 — jsmith, ajonas, bwilliams targeted evenly |
| 06:55:09 | Last failed logon attempt recorded | wineventlog | EventCode 4625 — NT_STATUS_LOGON_FAILURE |
| 06:55:15 | Successful logon — jsmith account compromised | wineventlog | EventCode 4624 — Logon Type 3 (SMB/Network) |
| 06:55:15 → 07:10:00 | No further activity observed | sysmon | No processes spawned post-logon |

---

## 4. Attack Narrative

On May 8th, 2026, a blind password spray attack was launched from 10.0.0.5 against the domain controller win-dc-01. The attacker systematically tried common passwords against three domain accounts (jsmith, ajonas, bwilliams) with an even distribution across all three, indicating no prior knowledge of which account would be the weakest — consistent with opportunistic credential spraying rather than a targeted attack.

After approximately 18 failed attempts, the attacker successfully authenticated to jsmith's account using a weak or guessable password. No post-compromise activity was detected in either Windows Security logs or Sysmon.

### 4.1 Initial Access
The attacker gained access via SMB network authentication (Logon Type 3) to jsmith's domain account following a password spray. The source was an internal IP (10.0.0.5), suggesting the attacker already had a foothold inside the network perimeter prior to this activity.

### 4.2 Execution / Post-Compromise Activity
No security or Sysmon events were recorded following the successful logon at 06:55:15 UTC. No commands were executed, no accounts were touched, and no files were accessed during the observation window.

### 4.3 Persistence / Lateral Movement
No evidence of persistence mechanisms or lateral movement was observed.

---

## 5. Evidence Summary

| Evidence Item | Source | Significance |
|---------------|--------|--------------|
| 18 x EventCode 4625 from 10.0.0.5 | wineventlog | Confirms password spray activity |
| Even 4625 distribution across jsmith, ajonas, bwilliams | wineventlog | Confirms blind spray — no prior account targeting |
| EventCode 4624, Logon Type 3, Account: jsmith, Source: 10.0.0.5 | wineventlog | Confirms successful SMB credential compromise |
| No Sysmon events post-logon (06:55:15 – 07:10:00 UTC) | sysmon | No post-exploitation activity observed |

---

## 6. Indicators of Compromise (IOCs)

| Type | Value | First Seen | Context |
|------|-------|------------|---------|
| Source IP | 10.0.0.5 | 2026-05-08 06:52 UTC | Attacker machine — source of spray and successful logon |
| Username | jsmith | 2026-05-08 06:55 UTC | Compromised account |
| Username | ajonas | 2026-05-08 06:52 UTC | Targeted in spray — no successful logon |
| Username | bwilliams | 2026-05-08 06:52 UTC | Targeted in spray — no successful logon |

---

## 7. Key SPL Queries

**Query 1:**
```
index="wineventlog" host="win-dc-01" EventCode=4625
```
*What I was looking for:* Failed logons on the host  
*What I found:* ~18 failed logons from source IP 10.0.0.5

---

**Query 2:**
```
index="wineventlog" host="win-dc-01" EventCode=4624 Source_Network_Address="10.0.0.5"
```
*What I was looking for:* Successful logons from the attacker IP  
*What I found:* jsmith successfully authenticated from 10.0.0.5

---

**Query 3:**
```
index="wineventlog" Account_Name=jsmith Source_Network_Address="10.0.0.5"
```
*What I was looking for:* All activity on jsmith's account from the attacker IP  
*What I found:* Confirmed logon events; no other activity

---

**Query 4:**
```
index="wineventlog" Source_Network_Address="10.0.0.5" Account_Name=jsmith Logon_Type=3 EventCode=4624
```
*What I was looking for:* Logon method used by attacker  
*What I found:* Logon Type 3 — network logon via SMB

---

**Query 5:**
```
index="wineventlog" host="win-dc-01" EventCode=4625 Source_Network_Address="10.0.0.5" earliest="05/08/2026:06:50:00" latest="05/08/2026:07:05:00" | stats count by Account_Name
```
*What I was looking for:* Distribution of failed logons per account  
*What I found:* Even distribution — confirms blind spray, not targeted attack

---

**Query 6:**
```
index="sysmon" host="win-dc-01" earliest="05/08/2026:06:55:15" latest="05/08/2026:07:10:00"
```
*What I was looking for:* Post-compromise process activity  
*What I found:* No events — no post-exploitation observed

---

## 8. Findings & Verdict

- **Is this a real incident?** Yes
- **Attack type:** Blind password spray → credential compromise
- **Attack stage reached:** Initial Access (MITRE ATT&CK T1110.003 — Password Spraying)
- **Data accessed or exfiltrated?** No
- **Blast radius:** jsmith account compromised; ajonas and bwilliams targeted but not compromised

---

## 9. Recommended Response Actions

1. Isolate win-dc-01 from the network pending further investigation
2. Disable and rotate jsmith's account credentials immediately
3. Block source IP 10.0.0.5 at the NSG/firewall level
4. Review ajonas and bwilliams accounts for any successful logons from other sources
5. Review jsmith's account for privilege changes, group membership additions, or new scheduled tasks
6. Escalate to L2/IR team for deeper forensic investigation
7. Implement account lockout policy (e.g. lock after 5 failed attempts) to prevent future sprays

---

## 10. Detection Gaps & Improvements

- **No account lockout policy** — 18 failed attempts succeeded with no automated lockout. A lockout threshold of 5 attempts would have stopped this attack before it succeeded.
- **No alerting on Logon Type 3 from non-domain hosts** — SMB logons from a Linux machine to a DC should trigger an alert. This would have flagged the activity in real time.
- **No network segmentation** — the attacker VM (10.0.0.5) could directly reach the DC (10.0.0.4) on port 445. In a hardened environment, these would be in separate VLANs with firewall rules restricting SMB access.
- **No MFA on domain accounts** — multi-factor authentication would have prevented account access even after the password was compromised.

---

## 11. Lessons Learned

- Thinking through the whole process was more difficult than expected — didn't know where to start. Calming down and starting with the simplest, most obvious query (failed logons) and pivoting from there was the right move.
- Still building intuition for what's critical to check on each alert type. For authentication alerts: 4625 count and source → 4624 confirmation → Logon Type → post-compromise Sysmon check. That's the core playbook for this scenario.

---

*Report submitted for review: 2026-05-08*
