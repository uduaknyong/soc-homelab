# Week 1 — Investigation Working Notes
**Analyst:** Uduak  
**Alert:** Unusual Authentication Pattern — win-dc-01  
**Investigation started:** 2026-05-08 ~07:00 UTC

---

## Alert Details
- Alert fired: Saturday ~02:14 UTC *(scenario time — actual simulated events occurred 2026-05-08 ~06:52 UTC)*
- Trigger: 5+ failed logons → successful logon from same source
- Host in scope: win-dc-01

> **Date note:** The brief's "Saturday" is the fictional scenario date. The lab simulation ran on 2026-05-08. All Splunk timestamps reflect May 8, 2026. Use actual Splunk timestamps in your report.

---

## Timeline (fill this in as you investigate)

| Time UTC (2026-05-08) | Event | Source IP | Notes |
|----------------------|-------|-----------|-------|
| 06:52 | Password spray begins | 10.0.0.5 | Multiple 4625s across jsmith, ajonas, bwilliams |
| 06:55:09 | 4625 — Failed logon | 10.0.0.5 | Failed attempt on targeted account |
| 06:55:15 | 4624 — Successful logon | 10.0.0.5 | jsmith account compromised |

---

## SPL Queries Used

> Paste your queries here as you go — this builds your query library.

**Query 1:**
```
index="wineventlog" host="win-dc-01" EventCode=4625
```
*What I was looking for:* 
Failed logons on that host
 
*What I found:*
About 18 failed logons on that host from the IP "10.0.0.5
---

**Query 2:**
```
index="wineventlog" host="win-dc-01" EventCode=4624 Source_Network_Address="10.0.0.5"
```
*What I was looking for:*  
Succesful logons on the host machine

*What I found:*
The attacker was able to logon to jsmith's account
---

**Query 3:**
```
index="wineventlog" Account_Name=jsmith Source_Network_Address="10.0.0.5"
```
*What I was looking for:*  
All activities done by this ip address on jsmith account

*What I found:*
The attacker was able to logon to jsmith's account

**Query 4:**
```
index="wineventlog" Source_Network_Address="10.0.0.5" Account_Name=jsmith Logon_Type=3 EventCode=4624
```
*What I was looking for:*  
How the attacker logged in

*What I found:*
It was a network logon (Type 3)


*Query 5:**
```
index="sysmon"  host="win-dc-01" earliest="05/08/2026:06:55:15" latest="05/08/2026:07:10:00"
```
*What I was looking for:*  
Activities/processes spawned by the attacker

*What I found:*
Nil


*Query 6:**
```
index=wineventlog host="win-dc-01" EventCode=4625 Source_Network_Address="10.0.0.5" earliest="05/08/2026:06:50:00" latest="05/08/2026:07:05:00" | stats count by Account_Name
```
*What I was looking for:*  
This was to confirm if this was a blind spray or an account was targeted

*What I found:*
It was a blind spray.
---

## Key Findings

*(Fill in as you discover things)*

- Targeted accounts where jsmith, ajonas, bwilliams
- No logged activities carried out by attacker after access. no process spawned at that particular time.
- Logon Type: 3
- no specific account was targeted.

---

## IOCs (Indicators of Compromise)

| Type | Value | Context |
|------|-------|---------|
| IP Address | 10.0.0.5 | Source of spray and successful logon (ubuntu-attacker-01) |
| Username | jsmith | Compromised account |
| Username | ajonas | Targeted (spray) |
| Username | bwilliams | Targeted (spray) |
| Process | | |
| File | | |

---

## Questions / Dead Ends

*(Track things you tried that didn't work, or questions you need to answer)*

- 
- 

---

## Preliminary Verdict

*(Your working theory — update as you go)* 
- Incident or false positive?: - This is an incident.
- Attack stage reached: The attacker has been able to breach an account on our environment.
- Affected accounts: jsmith
- Recommended immediate action: host machine should be pulled from the network. affected account logins should be rotated. incident should be escalated to level 2 for further investigation.
