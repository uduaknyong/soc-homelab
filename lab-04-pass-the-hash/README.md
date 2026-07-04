# Lab 04 — Pass-the-Hash Detection (T1550.002)

> Status: Complete

An investigation lab built on real Windows attack telemetry from the
[splunk/attack_data](https://github.com/splunk/attack_data) project, ingested into a self-hosted
Splunk instance. The goal is to take a SOC alert end to end: triage it in Splunk, confirm or deny it,
scope the activity, reach a verdict, and write it up as a formal incident report mapped to MITRE ATT&CK.

| Technique | MITRE ATT&CK | Status |
|-----------|--------------|--------|
| Pass-the-Hash | T1550.002 (Lateral Movement — Use Alternate Authentication Material) | Confirmed true positive |

Workflow: orient on the dataset, run down the alert with SPL, separate the malicious authentication
from the legitimate baseline, build the timeline and IOCs, reach a verdict, map to ATT&CK, and write
the incident report.

## Lab environment

| | |
|---|---|
| SIEM | Splunk Enterprise 10.2.5 (single GCP VM, `splunk-lab`) |
| Access | Splunk Web over an IAP tunnel to `http://localhost:8000` |
| Index | `passthehash` (sourcetype `pth:winlog`) |
| Data | Windows Security event logs from several hosts (Event IDs 4624 / 4625 / 4634 / 4648 / 4672 / 4769 …) |
| Time range | Events span **2019-01-09 → 01-10** and **2020-10-15**. Set the time picker to **All time** or the search returns nothing. |

Fields extracted at search time (use them directly in SPL): `EventCode`, `Logon_Type`,
`Authentication_Package`, `Logon_Process`, `Account_Name` (alias `user`), `Source_Network_Address`
(alias `src`), `Workstation_Name`, `Account_Domain`, `host`.

## The alert

The following notable event lands in the Tier-1 queue:

| Field | Value |
|---|---|
| **Notable ID** | `NTLM-ANOM-2607031042` |
| **Detection** | `Windows - Anomalous NTLM Network Logon (Possible Pass-the-Hash)` |
| **Severity / Urgency** | SEV2 / Medium |
| **MITRE ATT&CK** | T1550.002 (Lateral Movement — Use Alternate Authentication Material) |
| **Trigger** | Successful **NTLM** network logons (Logon Type 3) observed in an environment where authentication is otherwise **Kerberos-first**. NTLM for privileged/interactive access here falls outside baseline and is a common footprint of a credential being *replayed* rather than typed. |
| **Entities** | Multiple hosts in scope across the retained Windows security-log data |
| **Playbook** | [PB-CRED-014](./playbook.md) — follow it |

A Tier-1 analyst picks this up cold and works it per the attached **[playbook](./playbook.md)**: true
positive or benign noise? If malicious — what technique and goal, which account(s) and host(s), where did
it originate, and did it succeed? What separates the suspicious authentication from the legitimate baseline?

## Files

| File | Description |
|------|-------------|
| [playbook.md](./playbook.md) | **PB-CRED-014** — Tier-1 triage runbook for this detection (procedure, disposition criteria, escalation) |
| [investigation-notes.md](./investigation-notes.md) | Working notes: SPL queries, findings, timeline, IOCs, verdict (filled in live during triage) |
| incident-report.md | Formal incident report (written after triage) |
| splunk-queries.md | Reusable SPL query library from this lab |
| LEARN-resources.md | Curated reading to go deeper on Pass-the-Hash & NTLM authentication |
| evidence/ | Screenshots captured during the investigation |

## Outcome

Confirmed true positive: Pass-the-Hash (T1550.002). The alert flagged anomalous NTLM logons in a
Kerberos-first environment. Triage resolved it to a single successful authentication: the account
`userA` logged on over **NTLM** (Event 4624, Logon Type 3) from an unrecognized workstation named
`SZUFS` at 2019-01-09 09:20:30. The same logon was recorded by two independent hosts — the destination
(`destDeviceA`) and an observer (`observerDeviceA`) — so it was corroborated, not a logging artifact.

The proof was in the baseline. `userA` authenticates with Kerberos essentially always (216 Kerberos to
2 NTLM, and those 2 are this one event seen twice), so NTLM is firmly out of character. NTLM that is
replayed rather than typed, from a machine name that does not belong to the estate, is the signature of
Pass-the-Hash. The logon succeeded, so this is a foothold with lateral-movement capability. I raised it
from SEV2 to **High** and escalated to L2/IR — High rather than Critical because the confirmed scope is
one account on one host and `userA`'s privilege level is not yet established.

A second, unrelated cluster of NTLM activity in the same index (three failed logons on `win-dc-800`
from an external IP, 21 months later) was scoped, enriched (source IP clean on VirusTotal and
AbuseIPDB), and cleared as failed opportunistic attempts. Unrelated explicit-credential activity on that
host was flagged to L2 rather than investigated — that is threat-hunting, outside the Tier-1 mandate.

One thing worth noting: the source IP on the malicious logon was blank, which is normal for NTLM. The
move that cracked it was not chasing the missing IP but pivoting to the workstation name and measuring
the user's own protocol baseline. The signal was *how* the account authenticated, not *where from*.
